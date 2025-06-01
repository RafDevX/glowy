use parser::{ast::BindingDeclSpecNode, Annotation, Location};

use crate::{
    context::AnalysisContext,
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
        visit_binding_decl_spec(ctx, spec, mutable, location, annotation);
    }
}

fn visit_binding_decl_spec<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &BindingDeclSpecNode<'a>,
    mutable: bool,
    location: &Location,
    annotation: &Option<Box<Annotation<'a>>>,
) {
    for (name, expr) in &node.mapping {
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

        if let Some(expr_backtrace) = exprs::visit_expr(ctx, expr) {
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

        ctx.declare_new_symbol(symbol);
    }
}
