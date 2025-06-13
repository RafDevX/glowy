use std::cmp;

use parser::{
    ast::{BindingDeclSpecNode, ShortVarDeclNode},
    Annotation, Location,
};

use crate::{
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{Label, LabelBacktrace, LabelBacktraceKind},
    symbols::Symbol,
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
    // TODO: handle case where `var x, y = f()`;
    // i.e., use visit_expr instead of visit_single_expr

    let mut redeclarations = vec![];
    let mut any_new = false;

    for (name, expr) in &node.mapping {
        if name.content() == "_" {
            // blank identifier, so we don't really need to do anything else
            // except visiting the expression to process e.g. function calls
            // (needed to detect insecure flows wrt integrity, for example).
            exprs::visit_single_expr(ctx, expr);

            continue;
        }

        let mut label = Label::Bottom;
        let mut children_backtraces = vec![]; // order matters

        if let Some(annotation) = annotation {
            if annotation.scope == "label" {
                let annotation_label = Label::from_tags(&annotation.tags);
                label = label.union(&annotation_label);

                let explicit = LabelBacktrace::new_root(
                    LabelBacktraceKind::ExplicitAnnotation,
                    annotation_label,
                    name.content(),
                    ctx.pin(location.clone()),
                );

                children_backtraces.push(explicit);
            }

            // TODO: `match` other scopes
        };

        if let Some(expr_backtrace) = exprs::visit_single_expr(ctx, expr) {
            label = label.union(expr_backtrace.label());
            children_backtraces.push(expr_backtrace);
        }

        // TODO: branch backtrace

        let backtrace = LabelBacktrace::new(
            LabelBacktraceKind::Assignment,
            label,
            Some(name.content()),
            ctx.pin(location.clone()),
            &children_backtraces,
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

    if node.ids.len() != node.exprs.len() {
        ctx.report_error(AnalysisErrorKind::UnevenShortVarDecl {
            location: node.location.clone(),
            left: node.ids.len(),
            right: node.exprs.len(),
        });

        return;
    }

    visit_binding_decl_spec(
        ctx,
        &BindingDeclSpecNode {
            mapping: node
                .ids
                .iter()
                .cloned()
                .zip(node.exprs.iter().cloned())
                .collect(),
            r#type: None,
        },
        true,
        true,
        &node.location,
        &node.annotation,
    );
}
