use std::cmp;

use parser::{
    ast::{
        AssignmentKind, AssignmentNode, BindingDeclSpecNode, ExprNode, LiteralNode,
        ShortVarDeclNode,
    },
    Annotation, Location,
};

use crate::{
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{Label, LabelBacktrace, LabelBacktraceKind},
    symbols::Symbol,
    taint::funcs,
};

use super::exprs;

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

    if node.ids.len() != backtraces.len() {
        ctx.report_error(AnalysisErrorKind::UnevenBindingDeclSpec {
            location: location.clone(),
            left: node.ids.len(),
            right: backtraces.len(),
        });

        return;
    }

    let mut redeclarations = vec![];
    let mut any_new = false;

    for (name, expr_backtrace) in node.ids.iter().zip(backtraces.iter()) {
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

        // TODO: branch backtrace

        let backtrace = LabelBacktrace::fold(
            [
                explicit_backtrace.as_ref(),
                expr_backtrace.as_ref(),
                /*, branch_backtrace */
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

    if node.lhs.len() != rhs_backtraces.len() {
        ctx.report_error(AnalysisErrorKind::UnevenAssignment {
            location: node.location.clone(),
            left: node.lhs.len(),
            right: rhs_backtraces.len(),
        });

        return;
    }

    // TODO: branch backtrace

    for (lhs, rhs_backtrace) in node.lhs.iter().zip(rhs_backtraces.iter()) {
        // TODO: support more kinds of left-values, e.g. indexing
        // (maybe have a module for complex data-types like arrays and structs
        //  which defines a trait that we can use to set values like we do for
        //  raw symbols here?)

        let ExprNode::Name(name) = lhs else {
            let location = exprs::get_expr_location(lhs).unwrap_or_else(|| node.location.clone());

            ctx.report_error(AnalysisErrorKind::InvalidLeftValue { location });

            return;
        };

        let Some(symbol) = exprs::resolve_operand_name(ctx, name) else {
            // error already reported
            return;
        };

        if !symbol.borrow().mutable() {
            ctx.report_error(AnalysisErrorKind::ImmutableLeftValue {
                symbol: name.id.clone(),
            });

            return;
        }

        let mut children = vec![rhs_backtrace.as_ref() /*, branch_backtrace */];

        let in_current_scope = ctx.symtab().is_symbol_in_current_scope(symbol.clone());

        let mut borrowed = symbol.borrow_mut();

        if node.kind != AssignmentKind::Simple || !in_current_scope {
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
            Some(name.id.content()), // symbol.declared_name()?
            ctx.pin(node.location.clone()),
        );

        borrowed.set_label_backtrace(backtrace);
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
            rhs: vec![ExprNode::Literal(LiteralNode::Int(1))],
            location: location.clone(),
        },
    );
}
