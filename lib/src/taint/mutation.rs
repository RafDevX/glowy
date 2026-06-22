use std::borrow::Cow;

use parser::{
    Location, Span,
    ast::{ExprNode, IndexingNode, SelectionNode},
};

use crate::{
    Pinned,
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{Label, LabelBacktrace, LabelBacktraceKind},
    taint::exprs,
    values::{
        BacktraceContainer, Mergeable, SelfAwareBacktraceContainer, SimpleConstValue, ValueRef,
    },
};

pub trait LeftValue<'a> {
    #[expect(clippy::too_many_arguments, reason = "No obvious arg aggregation")]
    fn assign(
        &self,
        ctx: &mut AnalysisContext<'a>,
        backtrace_kind: LabelBacktraceKind, // usually Assignment, unless...
        rhs: ValueRef<'a>,
        simple: bool,
        explicit_backtrace: Option<&LabelBacktrace<'a>>, // from annotation
        // from declassification annotation
        subtract: &Label<'a>,
        location: &Location,
    );

    fn root_operand(&self) -> Option<Span<'a>>;

    fn mutate_target(
        &self,
        ctx: &mut AnalysisContext<'a>,
        assignment_location: &Location,
        mutator: &dyn Fn(&mut AnalysisContext<'a>, ValueRef<'a>) -> Option<ValueRef<'a>>,
    );

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
    let inner: &'b dyn LeftValue = match expr {
        ExprNode::Name(name) => name,
        ExprNode::Indexing(indexing) => indexing,
        ExprNode::Selection(selection) => selection,

        // not using wildcard to force revisiting this implementation if a new
        // kind of expression is ever added (need to decide whether to implement
        // LeftValue for it or not)
        ExprNode::Literal(_)
        | ExprNode::Call(_)
        | ExprNode::Make(_)
        | ExprNode::Slicing(_)
        | ExprNode::Conversion(_)
        | ExprNode::TypeAssertion(_)
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
            simple,
            explicit_backtrace,
            subtract,
            location,
        );
    }

    fn root_operand(&self) -> Option<Span<'a>> {
        as_valid_left_value(self, None)?.root_operand()
    }

    fn mutate_target(
        &self,
        ctx: &mut AnalysisContext<'a>,
        assignment_location: &Location,
        mutator: &dyn Fn(&mut AnalysisContext<'a>, ValueRef<'a>) -> Option<ValueRef<'a>>,
    ) {
        let Some(inner) = as_valid_left_value(self, Some(ctx)) else {
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
            let should_override = self.should_override(ctx, simple);
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

            // apply declassification
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

            Some(mutated)
        });
    }

    fn root_operand(&self) -> Option<Self> {
        Some(*self)
    }

    fn mutate_target(
        &self,
        ctx: &mut AnalysisContext<'a>,
        _assignment_location: &Location,
        mutator: &dyn Fn(&mut AnalysisContext<'a>, ValueRef<'a>) -> Option<ValueRef<'a>>,
    ) {
        let Some(symbol) = exprs::resolve_operand_name(ctx, *self, None) else {
            // no symbol found, but error already reported
            return;
        };

        if !symbol.borrow().mutable() {
            ctx.report_error(AnalysisErrorKind::ImmutableLeftValue { symbol: *self });

            return;
        }

        // we need to clone_inner to ensure compliance with the AssumedImmutable
        // restrictions (cannot directly mutate a Symbol's value)
        // See: Symbol::value
        let value = symbol.borrow().value().get().clone_inner();

        let Some(mutated) = mutator(ctx, value) else {
            return;
        };

        symbol.borrow_mut().set_value(mutated);
    }
}

impl<'a> LeftValue<'a> for IndexingNode<'a> {
    fn assign(
        &self,
        ctx: &mut AnalysisContext<'a>,
        backtrace_kind: LabelBacktraceKind,
        rhs: ValueRef<'a>,
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
                self.should_override(ctx, simple),
                backtrace_kind,
                &ctx.pin(location.clone()),
            );

            // apply declassification
            mutated.subtract_label(subtract);

            Some(mutated)
        });
    }

    fn root_operand(&self) -> Option<Span<'a>> {
        self.base.root_operand()
    }

    fn mutate_target(
        &self,
        ctx: &mut AnalysisContext<'a>,
        assignment_location: &Location,
        mutator: &dyn Fn(&mut AnalysisContext<'a>, ValueRef<'a>) -> Option<ValueRef<'a>>,
    ) {
        exprs::visit_single_expr(ctx, &self.index); // trigger side effects

        #[expect(
            clippy::shadow_unrelated,
            reason = "Same context, just threaded through closures"
        )]
        self.base
            .mutate_target(ctx, assignment_location, &|ctx, mut target| {
                let Some(mut composite) = target.as_composite_mut() else {
                    ctx.report_error(AnalysisErrorKind::InvalidIndexingBase {
                        location: self.location.clone(),
                    });

                    return None;
                };

                let index = SimpleConstValue::try_resolve_from_expr(&self.index);

                let child = composite.get_at_key(index.as_ref(), ctx.pin(self.location.clone()));

                let child = mutator(ctx, child)?;

                composite.set_at_key(index, child, ctx.pin(assignment_location.clone()));

                drop(composite);
                Some(target)
            });
    }
}

impl<'a> LeftValue<'a> for SelectionNode<'a> {
    fn assign(
        &self,
        ctx: &mut AnalysisContext<'a>,
        backtrace_kind: LabelBacktraceKind,
        rhs: ValueRef<'a>,
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
                self.should_override(ctx, simple),
                backtrace_kind,
                &pinned_location,
            );

            // apply declassification
            mutated.subtract_label(subtract);

            Some(mutated)
        });
    }

    fn root_operand(&self) -> Option<Span<'a>> {
        self.base.root_operand()
    }

    fn mutate_target(
        &self,
        ctx: &mut AnalysisContext<'a>,
        assignment_location: &Location,
        mutator: &dyn Fn(&mut AnalysisContext<'a>, ValueRef<'a>) -> Option<ValueRef<'a>>,
    ) {
        #[expect(
            clippy::shadow_unrelated,
            reason = "Same context, just threaded through closures"
        )]
        self.base
            .mutate_target(ctx, assignment_location, &|ctx, target| {
                let selector = self.selector.content().to_owned();

                let Some(mut r#struct) = target.as_struct_mut() else {
                    ctx.report_error(AnalysisErrorKind::InvalidSelectionBase {
                        location: self.location.clone(),
                    });

                    return None;
                };

                let child = r#struct.get_const(&selector, ctx.pin(self.location.clone()));

                let child = mutator(ctx, child)?;

                r#struct.set_const(selector, child);

                drop(r#struct);
                Some(target)
            });
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
        assigned.clone()
    } else {
        assigned.nest_backtrace(
            backtrace_kind,
            None,
            merge_location.clone(),
            current.backtrace(),
        )
    }
}
