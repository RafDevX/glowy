use std::{borrow::Cow, cmp, rc::Rc};

use parser::{
    Annotation, Location, Span,
    ast::{
        AssignmentKind, AssignmentNode, BindingDeclSpecNode, ExprNode, IndexingNode, LiteralNode,
        SelectionNode, ShortVarDeclNode,
    },
};

use super::exprs;
use crate::{
    Pinned,
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{Label, LabelBacktrace, LabelBacktraceKind},
    symbols::Symbol,
    taint::{SinkDescriptor, SinkKind, enforcement},
    values::{SelfAwareBacktraceContainer, SimpleConstValue, ValueRef},
};

pub fn visit_binding_decl<'a>(
    ctx: &mut AnalysisContext<'a>,
    specs: &[BindingDeclSpecNode<'a>],
    mutable: bool,
    location: &Location,
    annotation: Option<&Annotation<'a>>,
) {
    for spec in specs {
        visit_binding_decl_spec(ctx, spec, mutable, false, location, annotation);
    }
}

fn visit_binding_decl_spec<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &BindingDeclSpecNode<'a>,
    mutable: bool,
    short: bool, // allows redeclaration in some circumstances
    location: &Location,
    annotation: Option<&Annotation<'a>>,
) {
    if node.exprs.is_empty() && node.r#type.is_some() && !short {
        // no initialization expression; zero-value is used;
        // for our purposes, we just need to remember the decl exists
        // (branch label is irrelevant in this case)

        for name in &node.ids {
            let pinned = ctx.pin(*name);
            let value = ValueRef::new_bottom(pinned.pinned_location());

            let symbol = Symbol::new_ref(pinned, mutable, value);

            ctx.declare_new_symbol(symbol);
        }

        return;
    }

    let mut rhs_values = exprs::visit_multi_exprs(ctx, &node.exprs);

    let mut expanded = None;
    if node.ids.len() > 1 {
        if let [single] = rhs_values.as_slice() {
            if let Some(expandable) = single.as_expandable() {
                // cannot assign directly to rhs_values here because the borrow
                // checker is very cool and awesome and does not allow it while
                // rhs_values is borrowed from the if-let, so we do this instead
                expanded = Some(expandable.expand());
            } else if let Some(mobius) = single.as_mobius() {
                expanded = Some(mobius.expand_to(node.ids.len()));
            }
        }
    }

    if let Some(expanded) = expanded {
        rhs_values = expanded;
    }

    visit_raw_binding_decl_spec(
        ctx,
        &node.ids,
        rhs_values.into_iter(),
        mutable,
        short,
        location,
        annotation,
    );
}

// for declaration-like cases more generic than an actual declaration node
pub fn visit_raw_binding_decl_spec<'a>(
    ctx: &mut AnalysisContext<'a>,
    ids: &[Span<'a>],
    rhs_values: impl ExactSizeIterator<Item = ValueRef<'a>>,
    mutable: bool,
    short: bool, // allows redeclaration in some circumstances
    location: &Location,
    annotation: Option<&Annotation<'a>>,
) {
    if ids.len() != rhs_values.len() {
        ctx.report_error(AnalysisErrorKind::UnevenBindingDeclSpec {
            location: location.clone(),
            left: ids.len(),
            right: rhs_values.len(),
        });

        return;
    }

    let mut redeclarations = vec![];
    let mut any_new = false;

    for (name, rhs) in ids.iter().copied().zip(rhs_values) {
        if name.content() == "_" {
            // blank identifier, so we don't really need to do anything else
            // except visiting the expression to process e.g. function calls
            // (needed to detect insecure flows wrt integrity, for example),
            // but this was necessarily already done or we wouldn't have the
            // corresponding value

            continue;
        }

        let mut explicit_backtrace = None;

        if let Some(annotation) = annotation {
            match annotation.directive {
                "label" => {
                    explicit_backtrace = Some(LabelBacktrace::new_root(
                        LabelBacktraceKind::ExplicitAnnotation,
                        Label::from_tags(&annotation.tags),
                        Some(name.content()),
                        ctx.pin(location.clone()),
                    ));
                }
                "sink" => {
                    let sink = SinkDescriptor::new(
                        SinkKind::Declaration,
                        &annotation.tags,
                        location.clone(), // spec, not annotation
                    );

                    enforcement::trigger_sink(ctx, Cow::Owned(sink), rhs.backtrace());
                }
                "assert" => {
                    enforcement::trigger_assertion(
                        ctx,
                        &Label::sequence_from_tags(&annotation.tags),
                        rhs.backtrace(),
                        location.clone(),
                    );
                }
                _ => ctx.report_error(AnalysisErrorKind::UnknownAnnotationDirective {
                    directive: annotation.directive,
                    location: annotation.location.clone(),
                }),
            }
        }

        let symbol = Symbol::new_ref(
            ctx.pin(name),
            true, // we initially always set the symbol as mutable
            ValueRef::new_bottom(ctx.pin(location.clone())),
        );
        let symbol2 = Rc::clone(&symbol); // for later use if needed

        if short {
            // declare manually to hold errors until we're sure
            if let Some(existing) = ctx.symtab_mut().declare_new_symbol(name.content(), symbol) {
                let borrowed = existing.borrow();

                if matches!(
                    ctx.pin(name)
                        .pinned_location()
                        .partial_cmp(&borrowed.declared_name().pinned_location()),
                    None | Some(cmp::Ordering::Greater)
                ) {
                    redeclarations.push(AnalysisErrorKind::IllegalRedeclaration {
                        previous: borrowed.declared_name().clone(),
                        found: name,
                    });

                    continue;
                }
            }

            any_new = true;
        } else {
            // just report any errors
            ctx.declare_new_symbol(symbol);
        }

        // now that symbol is declared, we can assign a value to it

        name.assign(
            ctx,
            LabelBacktraceKind::DeclarationInitialization,
            rhs,
            true,
            explicit_backtrace.as_ref(),
            location,
        );

        // now, after assigning, we can set the symbol to immutable if that was
        // the case (before we created it as mutable to allow the assignment)
        if !mutable {
            symbol2.borrow_mut().mark_immutable();
        }
    }

    if !redeclarations.is_empty() && !any_new {
        // does not meet criteria for valid redeclaration
        // (at least 1 non-blank identifier must be new)
        for error in redeclarations {
            ctx.report_error(error);
        }
    }
}

pub fn visit_short_var_decl<'a>(ctx: &mut AnalysisContext<'a>, node: &ShortVarDeclNode<'a>) {
    // for simplicity, we treat this as if it was a binding decl spec

    visit_binding_decl_spec(
        ctx,
        &BindingDeclSpecNode {
            ids: node.ids.clone(),
            exprs: node.exprs.clone(),
            r#type: None,
        },
        true,
        true,
        &node.location,
        node.annotation.as_deref(),
    );
}

pub fn visit_assignment<'a>(ctx: &mut AnalysisContext<'a>, node: &AssignmentNode<'a>) {
    if node.kind != AssignmentKind::Simple && node.lhs.len() != 1 {
        ctx.report_error(AnalysisErrorKind::MultiComplexAssignment {
            location: node.location.clone(),
            num: node.lhs.len(),
        });

        return;
    }

    let mut rhs_values = exprs::visit_multi_exprs(ctx, &node.rhs);

    let mut expanded = None;
    if node.lhs.len() > 1 {
        if let [single] = rhs_values.as_slice() {
            if let Some(expandable) = single.as_expandable() {
                // cannot assign directly to rhs_values here because the borrow
                // checker is very cool and awesome and does not allow it while
                // rhs_values is borrowed from the if-let, so we do this instead
                expanded = Some(expandable.expand());
            } else if let Some(mobius) = single.as_mobius() {
                expanded = Some(mobius.expand_to(node.lhs.len()));
            }
        }
    }

    if let Some(expanded) = expanded {
        rhs_values = expanded;
    }

    visit_raw_assignment(
        ctx,
        node.kind,
        node.lhs.iter(),
        rhs_values.into_iter(),
        None, // TODO: support annotations in assignments
        &node.location,
    );
}

// for assignment-like cases more generic than an actual assignment node
pub fn visit_raw_assignment<'a: 'b, 'b>(
    ctx: &mut AnalysisContext<'a>,
    kind: AssignmentKind,
    lhs_exprs: impl ExactSizeIterator<Item = &'b ExprNode<'a>>,
    rhs_values: impl ExactSizeIterator<Item = ValueRef<'a>>,
    explicit_backtrace: Option<&LabelBacktrace<'a>>, // from annotation
    location: &Location,
) {
    if lhs_exprs.len() != rhs_values.len() {
        ctx.report_error(AnalysisErrorKind::UnevenAssignment {
            location: location.clone(),
            left: lhs_exprs.len(),
            right: rhs_values.len(),
        });

        return;
    }

    for (lhs, rhs) in lhs_exprs.zip(rhs_values) {
        lhs.assign(
            ctx,
            LabelBacktraceKind::Assignment,
            rhs,
            kind == AssignmentKind::Simple,
            explicit_backtrace,
            location,
        );
    }
}

pub fn visit_incdec<'a>(
    ctx: &mut AnalysisContext<'a>,
    operand: &ExprNode<'a>,
    location: &Location,
) {
    // for simplicity, we treat this as syntactic sugar for an assignment

    visit_assignment(
        ctx,
        &AssignmentNode {
            kind: AssignmentKind::Sum, // can be anything except Simple
            lhs: vec![operand.clone()],
            rhs: vec![ExprNode::Literal(LiteralNode::Int {
                value: 1,
                location: location.clone(),
            })],
            location: location.clone(),
        },
    );
}

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

        let index = SimpleConstValue::try_resolve_from_expr(&self.index);

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

                let child = if let Some(index) = &index {
                    composite.get_at_known_key(index, ctx.pin(self.location.clone()))
                } else {
                    composite.get_at_unknown_key(ctx.pin(self.location.clone()))
                };

                let child = mutator(ctx, child)?;

                if let Some(index) = &index {
                    composite.set_at_known_key(
                        index.clone(),
                        child,
                        true,
                        ctx.pin(assignment_location.clone()),
                    );
                } else {
                    composite.set_at_unknown_key(&child, ctx.pin(assignment_location.clone()));
                }

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

                r#struct.set_const(selector, child, true, ctx.pin(assignment_location.clone()));

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
