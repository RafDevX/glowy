use std::borrow::Cow;

use parser::{
    Location, Span,
    ast::{
        AmbiguousBracketAccessNode, ExprNode, IndexingNode, SelectionNode, SlicingNode, TypeNode,
        UnaryOpKind,
    },
};

use crate::{
    Pinned,
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{Label, LabelBacktrace, LabelBacktraceKind},
    symbols::{QualifiedSymbolResolutionResult, SymbolRef},
    taint::{exprs, funcs},
    types::{PromotedField, StructFieldInfo, TypeInfo, TypeKind},
    values::{
        BacktraceContainer, Mergeable, SelfAwareBacktraceContainer, SimpleConstValue, ValueRef,
    },
};

type MutationResult<'a> = Option<(ValueRef<'a>, Option<SimpleConstValue>)>;

pub trait LeftValue<'a> {
    #[expect(clippy::too_many_arguments, reason = "No obvious arg aggregation")]
    fn assign(
        &self,
        ctx: &mut AnalysisContext<'a>,
        backtrace_kind: LabelBacktraceKind, // usually Assignment, unless...
        rhs: ValueRef<'a>,
        known_const: Option<SimpleConstValue>,
        simple: bool,
        explicit_backtrace: Option<&LabelBacktrace<'a>>, // from annotation
        // from revocation annotation
        subtract: &Label<'a>,
        location: &Location,
    );

    fn root_operand(&self) -> Option<Span<'a>>;

    // lower level primitive; should not really be used outside this module
    fn mutate_target(
        &self,
        ctx: &mut AnalysisContext<'a>,
        assignment_location: &Location,
        mutator: &dyn Fn(&mut AnalysisContext<'a>, ValueRef<'a>) -> MutationResult<'a>,
    );

    // high-level helper to use in alternative to `assign` when it is necessary
    // to transform a value in-place, instead of a visit + assign pattern which
    // would lead the expression to be visited twice (unsound for side-effects)
    fn assign_with(
        &self,
        ctx: &mut AnalysisContext<'a>,
        backtrace_kind: LabelBacktraceKind,
        location: &Location,
        transformer: &dyn Fn(&mut AnalysisContext<'a>, ValueRef<'a>) -> Option<ValueRef<'a>>,
    ) {
        #[expect(
            clippy::shadow_unrelated,
            reason = "Same context, just threaded through closures"
        )]
        self.mutate_target(ctx, location, &|ctx, target| {
            let new_value = transformer(ctx, target)?;
            let pinned = ctx.pin(location.clone());

            Some((
                new_value.nest_backtrace(
                    backtrace_kind,
                    None,
                    pinned,
                    ctx.branch_backtrace().cloned(),
                ),
                None,
            ))
        });
    }

    // lower level primitive; should not really be used outside this module
    #[must_use]
    fn should_override(&self, ctx: &mut AnalysisContext<'a>, simple_assignment: bool) -> bool {
        // for complex assignments like `x += y` we need to keep x's
        // label, but for simple assignments like `x = y` we can usually
        // overwrite it and drop the previous x label, except if we are
        // currently inside a control-flow split region and x was declared
        // outside it, in which case we have to be conservative and disallow
        // any overriding
        // FIXME: try to improve symtab alt branch support to avoid this
        if !simple_assignment {
            return false;
        }

        let Some(root) = self.root_operand() else {
            return false;
        };

        // a root operand that names a package qualifier (not shadowed by a
        // local symbol) is necessarily a write to a cross-package symbol,
        // which by construction was *not* declared inside our active split.
        // resolve_operand_name would emit a spurious UnknownSymbol here, so
        // short-circuit silently with the safe (non-override) answer
        if ctx.symtab().qualifier_exists(root.content())
            && ctx.symtab().get_symbol(root.content()).is_none()
        {
            return false;
        }

        let Some(symbol) = exprs::resolve_operand_name(ctx, root, None) else {
            return false;
        };

        ctx.was_symbol_declared_within_active_split(&symbol)
            .unwrap_or(true)
    }
}

fn as_valid_left_value<'a, 'b>(
    expr: &'b ExprNode<'a>,
    ctx: Option<&mut AnalysisContext<'a>>,
) -> Option<&'b dyn LeftValue<'a>> {
    if matches!(expr, ExprNode::Slicing(_)) {
        // slicing expressions are valid mutation targets (e.g., for `copy`),
        // but they cannot be directly assigned to

        if let Some(ctx) = ctx {
            ctx.report_error(AnalysisErrorKind::InvalidLeftValue {
                location: expr.location().into_owned(),
            });
        }

        return None;
    }

    as_mutation_target(expr, ctx)
}

fn as_mutation_target<'a, 'b>(
    expr: &'b ExprNode<'a>,
    ctx: Option<&mut AnalysisContext<'a>>,
) -> Option<&'b dyn LeftValue<'a>> {
    let inner: &'b dyn LeftValue = match expr {
        ExprNode::Name(name) => name,
        ExprNode::Indexing(indexing) => indexing,
        ExprNode::AmbiguousBracketAccess(ambiguous) => ambiguous,
        ExprNode::Selection(selection) => selection,
        ExprNode::Slicing(slicing) => slicing,

        // Glowy does not model heap addresses, so `&x` and `*p` are treated as
        // transparent over their operand (mirroring the read-side transparency
        // in `taint::exprs::visit_expr`). this is somehow sound because any
        // taint flowing through the pointer view also flows through the operand
        // view, but evidently *it is not fully sound* since we lose
        // pointer-identity precision, as two distinct pointers aliasing the
        // same cell are not connected (e.g. if `p == q`, changing `*p` will
        // reflect on `p` but not on `q`).
        // nevertheless, this present approximation is already very useful as
        // it enables (at least partially) some constructs such as `*p = ...`,
        // `(*p).field = ...`, and `(&arr[i]).field = ...` to be left-values
        ExprNode::UnaryOp {
            kind: UnaryOpKind::Deref | UnaryOpKind::Address,
            operand,
            ..
        } => return as_valid_left_value(operand, ctx),

        // not using wildcard to force revisiting this implementation if a new
        // kind of expression is ever added (need to decide whether to implement
        // LeftValue for it or not)
        ExprNode::Literal(_)
        | ExprNode::Call(_)
        | ExprNode::Make(_)
        | ExprNode::Conversion(_)
        | ExprNode::TypeAssertion(_)
        | ExprNode::TypeInstantiation(_)
        | ExprNode::UnaryOp { .. }
        | ExprNode::BinaryOp { .. } => {
            if let Some(ctx) = ctx {
                ctx.report_error(AnalysisErrorKind::InvalidLeftValue {
                    location: expr.location().into_owned(),
                });
            }

            return None;
        }
    };

    Some(inner)
}

// maybe it sends the wrong message for this to be implemented for ExprNode even
// though not all of its variants are actually supported, but this is the
// easiest way to accomplish simple dispatching
impl<'a> LeftValue<'a> for ExprNode<'a> {
    fn assign(
        &self,
        ctx: &mut AnalysisContext<'a>,
        backtrace_kind: LabelBacktraceKind,
        rhs: ValueRef<'a>,
        known_const: Option<SimpleConstValue>,
        simple: bool,
        explicit_backtrace: Option<&LabelBacktrace<'a>>,
        subtract: &Label<'a>,
        location: &Location,
    ) {
        let Some(inner) = as_valid_left_value(self, Some(ctx)) else {
            // error already reported
            return;
        };

        inner.assign(
            ctx,
            backtrace_kind,
            rhs,
            known_const,
            simple,
            explicit_backtrace,
            subtract,
            location,
        );
    }

    fn root_operand(&self) -> Option<Span<'a>> {
        as_mutation_target(self, None)?.root_operand()
    }

    fn mutate_target(
        &self,
        ctx: &mut AnalysisContext<'a>,
        assignment_location: &Location,
        mutator: &dyn Fn(&mut AnalysisContext<'a>, ValueRef<'a>) -> MutationResult<'a>,
    ) {
        let Some(inner) = as_mutation_target(self, Some(ctx)) else {
            // error already reported
            return;
        };

        inner.mutate_target(ctx, assignment_location, mutator);
    }
}

// for use only in the context of an operand name! not just any Span
impl<'a> LeftValue<'a> for Span<'a> {
    fn assign(
        &self,
        ctx: &mut AnalysisContext<'a>,
        backtrace_kind: LabelBacktraceKind,
        rhs: ValueRef<'a>,
        known_const: Option<SimpleConstValue>,
        simple: bool,
        explicit_backtrace: Option<&LabelBacktrace<'a>>,
        subtract: &Label<'a>,
        location: &Location,
    ) {
        if simple && self.content() == "_" {
            // blank identifier, so we just ignore this
            return;
        }

        #[expect(
            clippy::shadow_unrelated,
            reason = "Same context, just threaded through closures"
        )]
        self.mutate_target(ctx, location, &|ctx, target| {
            let should_override = self.should_override(ctx, simple)
                || (rhs.is_function() && !target.is_function() && target.is_bottom());
            // ^ a zero-valued (non-initialized) function variable has no
            // callable body state to retain, so keeping that Bottom placeholder
            // as the merge base in the function-specific branch below would
            // discard the rhs function's outcome and captures

            let pinned_location = ctx.pin(location.clone());

            let mut mutated = if should_override {
                rhs.nest_backtrace(
                    backtrace_kind,
                    Some(self.content()),
                    pinned_location.clone(),
                    explicit_backtrace
                        .into_iter()
                        .chain(ctx.branch_backtrace())
                        .cloned(),
                )
            } else if target.is_function() || rhs.is_function() {
                // Mergeable intentionally does not handle (Function, Function),
                // this is instead deferred to the body-derived analysis results
                // absorption mechanism below

                // note that the `is_function` usage in this branch's condition
                // is essential: `as_function` would upgrade a Simple into a
                // blackbox Function, which would corrupt the actual intention
                // behind the value in most cases

                target.nest_backtrace(
                    backtrace_kind,
                    Some(self.content()),
                    pinned_location.clone(),
                    explicit_backtrace
                        .cloned()
                        .into_iter()
                        .chain(rhs.backtrace())
                        .chain(ctx.branch_backtrace().cloned()),
                )
            } else {
                // neither side is a function, so we can perform a
                // shape-preserving merge via Mergeable so that e.g. a struct
                // can keep its shape past a control-flow split if possible

                target
                    .merge_with(&rhs, backtrace_kind, Cow::Borrowed(&pinned_location))
                    .nest_backtrace(
                        backtrace_kind,
                        Some(self.content()),
                        pinned_location.clone(),
                        explicit_backtrace
                            .cloned()
                            .into_iter()
                            .chain(ctx.branch_backtrace().cloned()),
                    )
            };

            // apply revocation
            mutated.subtract_label(subtract);

            // for non-override assignments, `mutated` so far carries only
            // rhs's *label*, not its body-derived state. that's fine for
            // ordinary values, but for function values any deferred
            // enforcement checks would be silently discarded (unsound!) so
            // we explicitly absorb that body-derived analysis results state
            // here when both sides are functions. the `rhs.is_function()` peek
            // prevents the following `as_*` calls from coercing unshaped Simple
            // operands into a blackbox Function (and corrupting their aliases)
            // in the (very common) case where the assignment has nothing
            // to do with functions in the first place
            if !should_override
                && rhs.is_function()
                && let Some(rhs_func) = rhs.as_function()
                && let Some(mut lhs_func) = mutated.as_function_mut()
            {
                let absorbed = lhs_func.try_absorb_body_state_from(&rhs_func);

                if !absorbed {
                    // if the absorption is refused as unsafe (e.g., closure
                    // captures from one lambda cannot be coherently rebound
                    // onto another's), we cannot proceed soundly and must
                    // surface the limitation instead of silently pretending the
                    // analysis is complete when it actually failed
                    ctx.report_error(AnalysisErrorKind::UnsoundFunctionMergingAssignment {
                        location: location.clone(),
                    });
                }
            }

            let known_const = if should_override {
                known_const.clone()
            } else {
                None
            };

            Some((mutated, known_const))
        });
    }

    fn root_operand(&self) -> Option<Self> {
        Some(*self)
    }

    fn mutate_target(
        &self,
        ctx: &mut AnalysisContext<'a>,
        assignment_location: &Location,
        mutator: &dyn Fn(&mut AnalysisContext<'a>, ValueRef<'a>) -> MutationResult<'a>,
    ) {
        let Some(symbol) = exprs::resolve_operand_name(ctx, *self, None) else {
            // no symbol found, but error already reported
            return;
        };

        mutate_through_symbol(ctx, &symbol, *self, assignment_location, mutator);
    }
}

fn mutate_through_symbol<'a>(
    ctx: &mut AnalysisContext<'a>,
    symbol: &SymbolRef<'a>,
    name: Span<'a>,
    assignment_location: &Location,
    mutator: &dyn Fn(&mut AnalysisContext<'a>, ValueRef<'a>) -> MutationResult<'a>,
) {
    if !symbol.borrow().mutable() {
        ctx.report_error(AnalysisErrorKind::ImmutableLeftValue { symbol: name });

        return;
    }

    // we need to clone_inner to ensure compliance with the AssumedImmutable
    // restrictions (cannot directly mutate a Symbol's value)
    let value = symbol.borrow().value().get().clone_inner();

    let Some((mutated, known_const)) = mutator(ctx, value) else {
        return;
    };

    record_active_function_capture_mutation(
        ctx,
        symbol,
        &mutated,
        &ctx.pin(assignment_location.clone()),
    );

    symbol.borrow_mut().set_value(mutated, known_const);

    ctx.record_per_iteration_value(symbol);
}

pub fn record_active_function_capture_mutation<'a>(
    ctx: &AnalysisContext<'a>,
    symbol: &SymbolRef<'a>,
    mutated: &ValueRef<'a>,
    location: &Pinned<'a, Location>,
) {
    let Some(mutation_backtrace) = mutated.backtrace() else {
        // we don't need to record anything if the new backtrace is Bottom,
        // since the pre-mutation value is already necessarily more conservative
        return;
    };

    // the mutated symbol may be a fake capture-local owned by any enclosing
    // function, not just the innermost function currently being visited, so we
    // have to find the right one by traversing all active functions from
    // innermost to outermost until one of them has a registered capture
    // matching this symbol (if any), so we can record the mutation there
    for mut active_function in ctx.active_functions() {
        let Some(mut func) = active_function.as_function_mut() else {
            return;
        };

        if func.record_capture_mutation(symbol, &mutation_backtrace, Cow::Borrowed(location)) {
            // this function matched, so we can stop here
            break;
        }
    }
}

impl<'a> LeftValue<'a> for IndexingNode<'a> {
    fn assign(
        &self,
        ctx: &mut AnalysisContext<'a>,
        backtrace_kind: LabelBacktraceKind,
        rhs: ValueRef<'a>,
        known_const: Option<SimpleConstValue>,
        simple: bool,
        explicit_backtrace: Option<&LabelBacktrace<'a>>,
        subtract: &Label<'a>,
        location: &Location,
    ) {
        #[expect(
            clippy::shadow_unrelated,
            reason = "Same context, just threaded through closures"
        )]
        self.mutate_target(ctx, location, &|ctx, target| {
            let should_override = self.should_override(ctx, simple);

            let new_value = rhs.nest_backtrace(
                backtrace_kind,
                None,
                ctx.pin(location.clone()),
                explicit_backtrace
                    .cloned()
                    .into_iter()
                    .chain(ctx.branch_backtrace().cloned()),
            );

            let mut mutated = merge_assigned_target_value(
                &target,
                &new_value,
                should_override,
                backtrace_kind,
                &ctx.pin(location.clone()),
            );

            // apply revocation
            mutated.subtract_label(subtract);

            let known_const = if should_override {
                known_const.clone()
            } else {
                None
            };

            Some((mutated, known_const))
        });
    }

    fn root_operand(&self) -> Option<Span<'a>> {
        self.base.root_operand()
    }

    fn mutate_target(
        &self,
        ctx: &mut AnalysisContext<'a>,
        assignment_location: &Location,
        mutator: &dyn Fn(&mut AnalysisContext<'a>, ValueRef<'a>) -> MutationResult<'a>,
    ) {
        // evaluate index before base to trigger side-effects in order
        #[rustfmt::skip]
        let (index_backtrace, index_const) = exprs::get_expr_backtrace_and_untainted_const(
            ctx,
            &self.index
        );

        #[expect(
            clippy::shadow_unrelated,
            reason = "Same context, just threaded through closures"
        )]
        self.base
            .mutate_target(ctx, assignment_location, &|ctx, mut target| {
                let target_is_map = target.is_map();

                let Some(mut composite) = target.as_composite_mut() else {
                    ctx.report_error(AnalysisErrorKind::InvalidIndexingBase {
                        location: self.base.location().into_owned(),
                    });

                    return None;
                };

                let child = composite.get_at_key(
                    index_const.as_ref(), // use const key if available
                    ctx.pin(self.location.clone()),
                );

                let (child, _) = mutator(ctx, child)?;

                composite.set_at_key(
                    index_const.clone(), // use const key if available
                    child,
                    index_backtrace.clone(),
                    ctx.pin(assignment_location.clone()),
                );

                if target_is_map {
                    composite.record_key_backtrace(
                        ctx.branch_backtrace().cloned(),
                        ctx.pin(assignment_location.clone()),
                    );
                }

                drop(composite);
                Some((target, None))
            });
    }
}

// an AmbiguousBracketAccessNode used as a left-value can only ever be an
// indexing, since type instantiation is not a valid left-value, so this impl
// just forwards everything to IndexingNode's own implementation
impl<'a> LeftValue<'a> for AmbiguousBracketAccessNode<'a> {
    fn assign(
        &self,
        ctx: &mut AnalysisContext<'a>,
        backtrace_kind: LabelBacktraceKind,
        rhs: ValueRef<'a>,
        known_const: Option<SimpleConstValue>,
        simple: bool,
        explicit_backtrace: Option<&LabelBacktrace<'a>>,
        subtract: &Label<'a>,
        location: &Location,
    ) {
        let indexing = IndexingNode::from(self.clone());

        indexing.assign(
            ctx,
            backtrace_kind,
            rhs,
            known_const,
            simple,
            explicit_backtrace,
            subtract,
            location,
        );
    }

    fn root_operand(&self) -> Option<Span<'a>> {
        let indexing = IndexingNode::from(self.clone());

        indexing.root_operand()
    }

    fn mutate_target(
        &self,
        ctx: &mut AnalysisContext<'a>,
        assignment_location: &Location,
        mutator: &dyn Fn(&mut AnalysisContext<'a>, ValueRef<'a>) -> MutationResult<'a>,
    ) {
        let indexing = IndexingNode::from(self.clone());

        indexing.mutate_target(ctx, assignment_location, mutator);
    }
}

impl<'a> LeftValue<'a> for SlicingNode<'a> {
    fn assign(
        &self,
        ctx: &mut AnalysisContext<'a>,
        _backtrace_kind: LabelBacktraceKind,
        _rhs: ValueRef<'a>,
        _known_const: Option<SimpleConstValue>,
        _simple: bool,
        _explicit_backtrace: Option<&LabelBacktrace<'a>>,
        _subtract: &Label<'a>,
        _location: &Location,
    ) {
        // a slicing expression is not directly assignable in Go, even though it
        // is a valid mutation target for some builtins uch as copy and clear

        ctx.report_error(AnalysisErrorKind::InvalidLeftValue {
            location: self.location.clone(),
        });
    }

    fn root_operand(&self) -> Option<Span<'a>> {
        self.base.root_operand()
    }

    fn mutate_target(
        &self,
        ctx: &mut AnalysisContext<'a>,
        assignment_location: &Location,
        mutator: &dyn Fn(&mut AnalysisContext<'a>, ValueRef<'a>) -> MutationResult<'a>,
    ) {
        if self.base.root_operand().is_none() {
            // slice-valued expressions need not be assignable to expose mutable
            // backing storage (for example, `copy(make([]int, 1)[:], src)`).
            let target = exprs::visit_single_expr(ctx, &self.clone().into());

            let _ = mutator(ctx, target);

            return;
        }

        #[expect(
            clippy::shadow_unrelated,
            reason = "Same context, just threaded through closures"
        )]
        self.base
            .mutate_target(ctx, assignment_location, &|ctx, target| {
                // re-slicing creates a descriptor view over the same backing
                // storage, so keep the base descriptor itself unchanged while
                // the mutator updates storage through that view

                let view = exprs::visit_slicing_with_base(ctx, self, &target);

                mutator(ctx, view)?;

                Some((target, None))
            });
    }
}

impl<'a> LeftValue<'a> for SelectionNode<'a> {
    fn assign(
        &self,
        ctx: &mut AnalysisContext<'a>,
        backtrace_kind: LabelBacktraceKind,
        rhs: ValueRef<'a>,
        known_const: Option<SimpleConstValue>,
        simple: bool,
        explicit_backtrace: Option<&LabelBacktrace<'a>>,
        subtract: &Label<'a>,
        location: &Location,
    ) {
        #[expect(
            clippy::shadow_unrelated,
            reason = "Same context, just threaded through closures"
        )]
        self.mutate_target(ctx, location, &|ctx, target| {
            let should_override = self.should_override(ctx, simple);
            let pinned_location = ctx.pin(location.clone());

            let new_value = rhs.nest_backtrace(
                backtrace_kind,
                None,
                pinned_location.clone(),
                explicit_backtrace
                    .cloned()
                    .into_iter()
                    .chain(ctx.branch_backtrace().cloned()),
            );

            let mut mutated = merge_assigned_target_value(
                &target,
                &new_value,
                should_override,
                backtrace_kind,
                &pinned_location,
            );

            // apply revocation
            mutated.subtract_label(subtract);

            let known_const = if should_override {
                known_const.clone()
            } else {
                None
            };

            Some((mutated, known_const))
        });
    }

    fn root_operand(&self) -> Option<Span<'a>> {
        self.base.root_operand()
    }

    fn mutate_target(
        &self,
        ctx: &mut AnalysisContext<'a>,
        assignment_location: &Location,
        mutator: &dyn Fn(&mut AnalysisContext<'a>, ValueRef<'a>) -> MutationResult<'a>,
    ) {
        // while in most cases mutating a selection means changing some field in
        // some struct, technically it is possible that this is actually the
        // mutation of an exported binding in another package, since qualified
        // operand names are parsed as selections too, and `pkg.X = ...` is not
        // distinguishable from `obj.X = ...` without additional checks.
        // in particular, we need to know if the base is a known qualifier that
        // has not been shadowed by any local symbol
        if let ExprNode::Name(qualifier) = &*self.base
            && ctx.symtab().qualifier_exists(qualifier.content())
            && ctx.symtab().get_symbol(qualifier.content()).is_none()
        {
            match ctx
                .symtab()
                .get_qualified_symbol(qualifier.content(), self.selector.content())
            {
                QualifiedSymbolResolutionResult::Success(symbol) => {
                    let symbol = funcs::resolve_accessed_capture(ctx, &symbol);

                    mutate_through_symbol(
                        ctx,
                        &symbol,
                        self.selector,
                        assignment_location,
                        mutator,
                    );
                }
                // package source is unavailable (blackbox) or has not yet been
                // analyzed in this pass -- the write target is invisible to us,
                // so we silently drop the write. rhs side effects and
                // sink/assert annotations are handled at the assignment site,
                // before `mutate_target` runs, so soundness is preserved
                // (mirrors the read-side softening in `resolve_operand_name`)
                QualifiedSymbolResolutionResult::PendingAnalysis => {}
                // we already checked above with `qualifier_exists`
                QualifiedSymbolResolutionResult::UnknownQualifier => unreachable!(),
                QualifiedSymbolResolutionResult::UnknownSymbol => {
                    // the package *is* analyzed and has no such symbol

                    ctx.report_error(AnalysisErrorKind::UnknownSymbol {
                        found: self.selector,
                    });
                }
            }

            return;
        }

        #[expect(
            clippy::shadow_unrelated,
            reason = "Same context, just threaded through closures"
        )]
        self.base
            .mutate_target(ctx, assignment_location, &|ctx, target| {
                let selector = self.selector.content().to_owned();

                // resolve the field's static metadata (shape hint + tag) before
                // `as_struct_mut` has the chance to upgrade `target`
                let field = target
                    .declared_type()
                    .and_then(|r#type| r#type.lookup_promoted_field(&selector));

                let field_hint = field
                    .as_ref()
                    .map(PromotedField::field_info)
                    .and_then(FieldShapeHint::for_field);

                let field_tag_backtrace = field
                    .as_ref()
                    .map(PromotedField::field_info)
                    .and_then(StructFieldInfo::tag_backtrace)
                    .cloned();

                let Some(mut r#struct) = target.as_struct_mut() else {
                    ctx.report_error(AnalysisErrorKind::InvalidSelectionBase {
                        location: self.location.clone(),
                    });

                    return None;
                };

                let child = r#struct.get_const(&selector, ctx.pin(self.location.clone()));

                if let Some(hint) = field_hint {
                    hint.try_apply(&child);
                }

                // fold in the field-tag backtrace (if any) at the access site
                // so complex assignments (which read `child` before merging)
                // propagate the label declared by the struct field tag
                let child = match field_tag_backtrace {
                    Some(tag) => child.nest_backtrace(
                        LabelBacktraceKind::Expression,
                        None,
                        ctx.pin(self.location.clone()),
                        [tag],
                    ),
                    None => child,
                };

                let (child, _) = mutator(ctx, child)?;

                r#struct.set_const(selector, child);

                drop(r#struct);
                Some((target, None))
            });
    }
}

// coarse-grained hint about the shape a struct field's declared type imposes
#[derive(Clone, Copy)]
enum FieldShapeHint {
    Channel,
    Array,
    Slice,
    Struct,
}

impl FieldShapeHint {
    fn for_field(field: &StructFieldInfo<'_>) -> Option<Self> {
        // prefer the resolved TypeInfo (for named types), and fall back to the
        // syntactic TypeNode for anonymous field types that never enter the
        // type registry (such as `chan struct{}` or `map[k]v`)
        field
            .resolved_type()
            .as_ref()
            .and_then(|info| Self::from_type_info(info))
            .or_else(|| Self::from_type_node(field.declared_type_node()))
    }

    fn from_type_info(info: &TypeInfo<'_>) -> Option<Self> {
        // Map/Function upgrades need `&mut ValueRef` which the mutator
        // doesn't hold; Opaque/Interface don't map to an aggregate shape
        match info.strip_pointers().underlying()? {
            TypeKind::Channel => Some(Self::Channel),
            TypeKind::Array => Some(Self::Array),
            TypeKind::Slice => Some(Self::Slice),
            TypeKind::Struct { .. } => Some(Self::Struct),
            // Map/Function upgrades need more context than what is present here
            // and Opaque/Interface cannot be mapped to a specific shape, so it
            // is not possible for us to provide a hint
            TypeKind::Map
            | TypeKind::Function
            | TypeKind::Opaque
            | TypeKind::Interface
            | TypeKind::Pointer(_) => None,
        }
    }

    fn from_type_node(node: &TypeNode<'_>) -> Option<Self> {
        let base = node.strip_pointers();

        match base {
            TypeNode::Channel { .. } => Some(Self::Channel),
            TypeNode::Array { .. } => Some(Self::Array),
            TypeNode::Slice { .. } => Some(Self::Slice),
            TypeNode::Struct { .. } => Some(Self::Struct),
            // Name is only possible here when its resolved TypeInfo was absent
            // or when it reported an underlying type kind we do not provide
            // hints for; the rest are shapes we intentionally skip
            TypeNode::Name(_)
            | TypeNode::Map { .. }
            | TypeNode::Function { .. }
            | TypeNode::Interface { .. }
            | TypeNode::Pointer { .. } => None,
        }
    }

    fn try_apply(self, value: &ValueRef<'_>) {
        match self {
            Self::Channel => value.try_upgrade_to_channel(),
            Self::Array => value.try_upgrade_to_array(),
            Self::Slice => value.try_upgrade_to_slice(),
            Self::Struct => value.try_upgrade_to_struct(),
        }
    }
}

fn merge_assigned_target_value<'a>(
    current: &ValueRef<'a>,
    assigned: &ValueRef<'a>,
    overwrite: bool,
    backtrace_kind: LabelBacktraceKind,
    merge_location: &Pinned<'a, Location>,
) -> ValueRef<'a> {
    if overwrite {
        // nothing to merge
        return assigned.clone();
    }

    // `merge_with` below would collapse (Function, Function) to Simple, which
    // which would erase the function shape. to prevent that, we make use of
    // `nest_backtrace` in that case, mirroring Span's LeftValue impl.
    // we use `is_function` (vs. `as_function`) so an unrelated Simple is not
    // accidentally upgraded to a blackbox function
    if current.is_function() || assigned.is_function() {
        return assigned.nest_backtrace(
            backtrace_kind,
            None,
            merge_location.clone(),
            current.backtrace(),
        );
    }

    // preserve value shape when possible
    current.merge_with(assigned, backtrace_kind, Cow::Borrowed(merge_location))
}
