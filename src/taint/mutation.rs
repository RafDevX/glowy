use parser::{
    Location, Span,
    ast::{ExprNode, IndexingNode, SelectionNode},
};

use crate::{
    Pinned,
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{LabelBacktrace, LabelBacktraceKind},
    taint::exprs,
    values::{SelfAwareBacktraceContainer, SimpleConstValue, ValueRef},
};

pub trait LeftValue<'a> {
    fn assign(
        &self,
        ctx: &mut AnalysisContext<'a>,
        backtrace_kind: LabelBacktraceKind, // usually Assignment, unless...
        rhs: ValueRef<'a>,
        simple: bool,
        explicit_backtrace: Option<&LabelBacktrace<'a>>, // from annotation
        location: &Location,
    );

    #[must_use]
    fn root_operand(&self, ctx: &mut AnalysisContext<'a>) -> Option<Span<'a>>;

    fn mutate_target(
        &self,
        ctx: &mut AnalysisContext<'a>,
        assignment_location: &Location,
        mutator: &dyn Fn(&mut AnalysisContext<'a>, ValueRef<'a>) -> Option<ValueRef<'a>>,
    );

    #[must_use]
    fn is_root_in_current_scope(&self, ctx: &mut AnalysisContext<'a>) -> bool {
        let Some(root) = self.root_operand(ctx) else {
            return false;
        };

        if let Some(symbol) = exprs::resolve_operand_name(ctx, root, None) {
            ctx.symtab().is_symbol_in_current_scope(&symbol)
        } else {
            false
        }
    }

    #[must_use]
    fn should_override(&self, ctx: &mut AnalysisContext<'a>, simple_assignment: bool) -> bool {
        // for complex assignments like `x += y` we need to keep x's
        // label, but for simple assignments like `x = y` we can usually
        // overwrite it and drop the previous x label, except if x was
        // not declared in the current scope, in which case we
        // (heuristically) have to conservatively assume that this is
        // e.g. an if branch and so the other branch might not have a
        // simple assignment, so we can't forget x's previous label
        // FIXME: try to improve symtab alt branch support to avoid this
        simple_assignment && self.is_root_in_current_scope(ctx)
    }
}

fn as_valid_left_value<'a, 'b>(
    ctx: &mut AnalysisContext<'a>,
    expr: &'b ExprNode<'a>,
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
            ctx.report_error(AnalysisErrorKind::InvalidLeftValue {
                location: exprs::get_expr_location(expr),
            });

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
        location: &Location,
    ) {
        let Some(inner) = as_valid_left_value(ctx, self) else {
            // error already reported
            return;
        };

        inner.assign(
            ctx,
            backtrace_kind,
            rhs,
            simple,
            explicit_backtrace,
            location,
        );
    }

    fn root_operand(&self, ctx: &mut AnalysisContext<'a>) -> Option<Span<'a>> {
        as_valid_left_value(ctx, self)?.root_operand(ctx)
    }

    fn mutate_target(
        &self,
        ctx: &mut AnalysisContext<'a>,
        assignment_location: &Location,
        mutator: &dyn Fn(&mut AnalysisContext<'a>, ValueRef<'a>) -> Option<ValueRef<'a>>,
    ) {
        let Some(inner) = as_valid_left_value(ctx, self) else {
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
            let mutated = if self.should_override(ctx, simple) {
                // for complex assignments like `x += y` we need to keep x's
                // label, but for simple assignments like `x = y` we can usually
                // overwrite it and drop the previous x label, except if x was
                // not declared in the current scope, in which case we
                // (heuristically) have to conservatively assume that this is
                // e.g. an if branch and so the other branch might not have a
                // simple assignment, so we can't forget x's previous label
                // FIXME: try to improve symtab alt branch support to avoid this

                rhs.nest_backtrace(
                    backtrace_kind,
                    Some(self.content()),
                    ctx.pin(location.clone()),
                    explicit_backtrace
                        .into_iter()
                        .chain(ctx.branch_backtrace())
                        .cloned(),
                )
            } else {
                target.nest_backtrace(
                    backtrace_kind,
                    Some(self.content()),
                    ctx.pin(location.clone()),
                    explicit_backtrace
                        .cloned()
                        .into_iter()
                        .chain(rhs.backtrace())
                        .chain(ctx.branch_backtrace().cloned()),
                )
            };

            Some(mutated)
        });
    }

    fn root_operand(&self, _ctx: &mut AnalysisContext<'a>) -> Option<Self> {
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

            let mutated = merge_assigned_target_value(
                &target,
                &new_value,
                self.should_override(ctx, simple),
                backtrace_kind,
                &ctx.pin(location.clone()),
            );

            Some(mutated)
        });
    }

    fn root_operand(&self, ctx: &mut AnalysisContext<'a>) -> Option<Span<'a>> {
        self.base.root_operand(ctx)
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

            let mutated = merge_assigned_target_value(
                &target,
                &new_value,
                self.should_override(ctx, simple),
                backtrace_kind,
                &pinned_location,
            );

            Some(mutated)
        });
    }

    fn root_operand(&self, ctx: &mut AnalysisContext<'a>) -> Option<Span<'a>> {
        self.base.root_operand(ctx)
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
    merge_location: &Pinned<Location>,
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
