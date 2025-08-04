use std::cmp;

use parser::{
    ast::{
        AssignmentKind, AssignmentNode, BindingDeclSpecNode, ExprNode, IndexingNode, LiteralNode,
        OperandNameNode, ShortVarDeclNode,
    },
    Annotation, Location, Span,
};

use super::exprs;
use crate::{
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{Label, LabelBacktrace, LabelBacktraceKind},
    symbols::Symbol,
    taint::funcs,
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
            let symbol = Symbol::new_ref(ctx.pin(name.clone()), mutable, None);

            ctx.declare_new_symbol(symbol);
        }

        return;
    }

    let backtraces = match node.exprs.as_slice() {
        // vvv case where `var a, b = f()` with `f` returning multiple values
        // (note: `const` cannot do this - we check `mutable` as a heuristic)
        [ExprNode::Call(call)] if node.ids.len() > 1 && mutable => funcs::visit_call(ctx, call),
        _ => node
            .exprs
            .iter()
            .map(|expr| exprs::visit_single_expr(ctx, expr))
            .collect(),
    };

    visit_raw_binding_decl_spec(
        ctx,
        &node.ids,
        &backtraces,
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
    backtraces: &[Option<LabelBacktrace<'a>>],
    mutable: bool,
    short: bool, // allows redeclaration in some circumstances
    location: &Location,
    annotation: &Option<Box<Annotation<'a>>>,
) {
    if ids.len() != backtraces.len() {
        ctx.report_error(AnalysisErrorKind::UnevenBindingDeclSpec {
            location: location.clone(),
            left: ids.len(),
            right: backtraces.len(),
        });

        return;
    }

    let mut redeclarations = vec![];
    let mut any_new = false;

    for (name, expr_backtrace) in ids.iter().zip(backtraces.iter()) {
        if name.content() == "_" {
            // blank identifier, so we don't really need to do anything else
            // except visiting the expression to process e.g. function calls
            // (needed to detect insecure flows wrt integrity, for example),
            // but this was necessarily already done or we wouldn't have the
            // corresponding `expr_backtrace`

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

        let backtrace = LabelBacktrace::fold(
            [
                explicit_backtrace.as_ref(),
                expr_backtrace.as_ref(),
                ctx.branch_backtrace(),
            ]
            .into_iter()
            .flatten(),
            LabelBacktraceKind::Assignment,
            Some(name.content()),
            ctx.pin(location.clone()),
        );

        let symbol = Symbol::new_ref(ctx.pin(name.clone()), mutable, backtrace);

        if short {
            // declare manually to hold errors until we're sure
            if let Some(existing) = ctx.symtab_mut().declare_new_symbol(name.content(), symbol) {
                let borrowed = existing.borrow();

                if matches!(
                    ctx.pin(name.clone())
                        .pinned_location()
                        .partial_cmp(&borrowed.declared_name().pinned_location()),
                    None | Some(cmp::Ordering::Greater)
                ) {
                    redeclarations.push(AnalysisErrorKind::IllegalRedeclaration {
                        previous: borrowed.declared_name().clone(),
                        found: name.clone(),
                    });

                    continue;
                }
            }

            any_new = true;
        } else {
            // just report any errors
            ctx.declare_new_symbol(symbol);
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

    let rhs_backtraces = match node.rhs.as_slice() {
        // vvv case where `a, b = f()` with `f` returning multiple values
        [ExprNode::Call(call)] if node.lhs.len() > 1 => funcs::visit_call(ctx, call),
        _ => node
            .rhs
            .iter()
            .map(|expr| exprs::visit_single_expr(ctx, expr))
            .collect(),
    };

    visit_raw_assignment(ctx, node.kind, &node.lhs, &rhs_backtraces, &node.location);
}

// for assignment-like cases more generic than an actual assignment node
pub fn visit_raw_assignment<'a>(
    ctx: &mut AnalysisContext<'a>,
    kind: AssignmentKind,
    lhs_exprs: &[ExprNode<'a>],
    rhs_backtraces: &[Option<LabelBacktrace<'a>>],
    location: &Location,
) {
    if lhs_exprs.len() != rhs_backtraces.len() {
        ctx.report_error(AnalysisErrorKind::UnevenAssignment {
            location: location.clone(),
            left: lhs_exprs.len(),
            right: rhs_backtraces.len(),
        });

        return;
    }

    for (lhs, rhs_backtrace) in lhs_exprs.iter().zip(rhs_backtraces.iter()) {
        lhs.assign(
            ctx,
            rhs_backtrace.as_ref(),
            kind == AssignmentKind::Simple,
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

trait LeftValue<'a> {
    fn assign(
        &self,
        ctx: &mut AnalysisContext<'a>,
        rhs: Option<&LabelBacktrace<'a>>,
        simple: bool,
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
        rhs: Option<&LabelBacktrace<'a>>,
        simple: bool,
        location: &Location,
    ) {
        let inner: &dyn LeftValue = match self {
            ExprNode::Name(name) => name,
            ExprNode::Indexing(indexing) => indexing,
            _ => {
                ctx.report_error(AnalysisErrorKind::InvalidLeftValue {
                    location: exprs::get_expr_location(self),
                });

                return;
            }
        };

        inner.assign(ctx, rhs, simple, location)
    }
}

impl<'a> LeftValue<'a> for OperandNameNode<'a> {
    fn assign(
        &self,
        ctx: &mut AnalysisContext<'a>,
        rhs: Option<&LabelBacktrace<'a>>,
        simple: bool,
        location: &Location,
    ) {
        let Some(symbol) = exprs::resolve_operand_name(ctx, self) else {
            // no symbol found, but error already reported
            return;
        };

        if !symbol.borrow().mutable() {
            ctx.report_error(AnalysisErrorKind::ImmutableLeftValue {
                symbol: self.id.clone(),
            });

            return;
        }

        let mut children = vec![rhs, ctx.branch_backtrace()];

        let in_current_scope = ctx.symtab().is_symbol_in_current_scope(symbol.clone());

        let mut borrowed = symbol.borrow_mut();

        if !simple || !in_current_scope {
            // for complex assignments like `x += y` we need to keep x's label,
            // but for simple assignments like `x = y` we can usually overwrite
            // it and drop the previous x label, except if x was not declared in
            // the current scope, in which case we (heuristically) have to
            // conservatively assume that this is e.g. an if branch and so the
            // other branch might not have a simple assignment, so we can't
            // forget x's previous label either
            // FIXME: try to improve symtab alt branch support to avoid this

            children.push(borrowed.label_backtrace());
        }

        let backtrace = LabelBacktrace::fold(
            children.into_iter().flatten(),
            LabelBacktraceKind::Assignment,
            Some(self.id.content()), // symbol.declared_name()?
            ctx.pin(location.clone()),
        );

        borrowed.set_label_backtrace(backtrace);
    }
}

impl<'a> LeftValue<'a> for IndexingNode<'a> {
    fn assign(
        &self,
        ctx: &mut AnalysisContext<'a>,
        rhs: Option<&LabelBacktrace<'a>>,
        _simple: bool,
        location: &Location,
    ) {
        // TODO: more fine-grained labeling of arrays; for example, if all
        // accesses are constant (~ literals, e.g. arr[2]), then remember a
        // mapping index-label. otherwise, for every assignment like arr[x]
        // (where we can't know x at compile-time), save in the array's symbol
        // label that label, and then on read union that general/overall label
        // with the one from the mapping (assuming it's a constant, otherwise
        // union all the possible mapped values)

        // never simple because we never want to override the entire array based
        // on just one entry
        self.expr.assign(ctx, rhs, false, location);
    }
}
