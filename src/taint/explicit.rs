use std::cmp;

use parser::{
    Annotation, Location, Span,
    ast::{
        AssignmentKind, AssignmentNode, BindingDeclSpecNode, ExprNode, IndexingNode, LiteralNode,
        SelectionNode, ShortVarDeclNode,
    },
};

use super::exprs;
use crate::{
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{Label, LabelBacktrace, LabelBacktraceKind},
    symbols::Symbol,
    values::{BacktraceContainer, SelfAwareBacktraceContainer, SimpleConstValue, ValueRef},
};

pub fn visit_binding_decl<'a>(
    ctx: &mut AnalysisContext<'a>,
    specs: &[BindingDeclSpecNode<'a>],
    mutable: bool,
    location: &Location,
    annotation: &Option<Box<Annotation<'a>>>,
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
    annotation: &Option<Box<Annotation<'a>>>,
) {
    if node.exprs.is_empty() && node.r#type.is_some() && !short {
        // no initialization expression; zero-value is used;
        // for our purposes, we just need to remember the decl exists
        // (branch label is irrelevant in this case)

        for name in &node.ids {
            let value = ValueRef::uninitialized_from_type(node.r#type.as_ref());

            let symbol = Symbol::new_ref(ctx.pin(*name), mutable, value);

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
                expanded = Some(mobius.expand_to(node.ids.len()))
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
    annotation: &Option<Box<Annotation<'a>>>,
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
            if annotation.scope == "label" {
                explicit_backtrace = Some(LabelBacktrace::new_root(
                    LabelBacktraceKind::ExplicitAnnotation,
                    Label::from_tags(&annotation.tags),
                    name.content(),
                    ctx.pin(location.clone()),
                ));
            }

            // TODO: `match` other scopes
        };

        let symbol = Symbol::new_ref(ctx.pin(name), mutable, ValueRef::from(None));
        // ^ we don't need to use ValueRef::uninitialized_from_type here, since
        // we know an initialization expression does exist

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
        &node.annotation,
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
                expanded = Some(mobius.expand_to(node.lhs.len()))
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
        let inner: &dyn LeftValue = match self {
            ExprNode::Name(name) => name,
            ExprNode::Indexing(indexing) => indexing,
            ExprNode::Selection(selection) => selection,
            _ => {
                ctx.report_error(AnalysisErrorKind::InvalidLeftValue {
                    location: exprs::get_expr_location(self),
                });

                return;
            }
        };

        inner.assign(
            ctx,
            backtrace_kind,
            rhs,
            simple,
            explicit_backtrace,
            location,
        )
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
        let Some(symbol) = exprs::resolve_operand_name(ctx, *self, None) else {
            // no symbol found, but error already reported
            return;
        };

        if !symbol.borrow().mutable() {
            ctx.report_error(AnalysisErrorKind::ImmutableLeftValue { symbol: *self });

            return;
        }

        let in_current_scope = ctx.symtab().is_symbol_in_current_scope(symbol.clone());

        let mut borrowed = symbol.borrow_mut();

        let value = if simple && in_current_scope {
            // for complex assignments like `x += y` we need to keep x's label,
            // but for simple assignments like `x = y` we can usually overwrite
            // it and drop the previous x label, except if x was not declared in
            // the current scope, in which case we (heuristically) have to
            // conservatively assume that this is e.g. an if branch and so the
            // other branch might not have a simple assignment, so we can't
            // forget x's previous label either
            // FIXME: try to improve symtab alt branch support to avoid this

            rhs.nest_backtrace(
                backtrace_kind,
                Some(self.content()), // symbol.declared_name()?
                ctx.pin(location.clone()),
                explicit_backtrace
                    .into_iter()
                    .chain(ctx.branch_backtrace())
                    .cloned(),
            )
        } else {
            let rhs_backtrace = rhs.backtrace_at_location(ctx.pin(location.clone()));

            borrowed.value().nest_backtrace(
                backtrace_kind,
                Some(self.content()), // symbol.declared_name()?
                ctx.pin(location.clone()),
                explicit_backtrace
                    .into_iter()
                    .cloned()
                    .chain(rhs_backtrace)
                    .chain(ctx.branch_backtrace().cloned()),
            )
        };

        borrowed.set_value(value);
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
        let mut base = exprs::visit_single_expr(ctx, &self.base);

        let Some(mut composite) = base.as_composite_mut() else {
            ctx.report_error(AnalysisErrorKind::InvalidIndexingBase {
                location: self.location.clone(),
            });

            return;
        };

        let value = rhs.nest_backtrace(
            backtrace_kind,
            None,
            ctx.pin(location.clone()),
            explicit_backtrace
                .cloned()
                .into_iter()
                .chain(ctx.branch_backtrace().cloned()),
        );

        exprs::visit_single_expr(ctx, &self.index); // trigger side effects

        let index = SimpleConstValue::try_resolve_from_expr(&self.index);

        let overwrite = simple && root_indexing_in_current_scope(ctx, self);

        if let Some(index) = index {
            composite.set_const(index, value, overwrite, ctx.pin(location.clone()));
        } else {
            composite.set_dyn(value, ctx.pin(location.clone()));
        }
    }
}

fn root_indexing_in_current_scope<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &IndexingNode<'a>,
) -> bool {
    match &*node.base {
        ExprNode::Name(operand) => {
            if let Some(symbol) = exprs::resolve_operand_name(ctx, *operand, None) {
                ctx.symtab().is_symbol_in_current_scope(symbol)
            } else {
                false
            }
        }
        ExprNode::Indexing(inner) => root_indexing_in_current_scope(ctx, inner),
        _ => false, // too complex to determine; err on the side of caution
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
        let base = exprs::visit_single_expr(ctx, &self.base);

        let Some(mut r#struct) = base.as_struct_mut() else {
            ctx.report_error(AnalysisErrorKind::InvalidSelectionBase {
                location: self.location.clone(),
            });

            return;
        };

        let value = rhs.nest_backtrace(
            backtrace_kind,
            None,
            ctx.pin(location.clone()),
            explicit_backtrace
                .cloned()
                .into_iter()
                .chain(ctx.branch_backtrace().cloned()),
        );

        let overwrite = if simple {
            if let ExprNode::Name(operand) = &*self.base {
                if let Some(symbol) = exprs::resolve_operand_name(ctx, *operand, None) {
                    ctx.symtab().is_symbol_in_current_scope(symbol)
                } else {
                    false
                }
            } else {
                // too complex to determine; err on the side of caution
                false
            }
        } else {
            false
        };

        r#struct.set_const(
            self.selector.content().to_owned(),
            value,
            overwrite,
            ctx.pin(location.clone()),
        );
    }
}
