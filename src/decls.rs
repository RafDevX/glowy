//! Used exclusively for Stage 1: RecordDeclarations
//! (visit top-level declarations)

use parser::ast::{BindingDeclSpecNode, DeclNode, FunctionDeclNode, SourceFileNode};

use crate::{
    context::AnalysisContext, errors::AnalysisErrorKind, symbols::Symbol, FullPackagePath,
};

pub fn visit_source_file<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &SourceFileNode<'a>,
    package_path: FullPackagePath,
) {
    // note that Go doesn't require the package name to match the directory
    // name, it's just a convention, so we must extract the package name from
    // the first file's package clause (and enforce for all other files to use
    // the same name)

    let package_name = ctx.pin(node.package_clause.id.clone());

    let original_name = ctx
        .symtab_mut()
        .enter_package(package_name, package_path.clone());

    if original_name.content() != node.package_clause.id.content() {
        // the scope already had a different native identifier, meaning that
        // another file has previously declared a different package name for
        // the same package path (which is invalid, so we report the error)

        let previous = original_name.clone();

        ctx.report_error(AnalysisErrorKind::DistinctPackageName {
            previous,
            found: node.package_clause.id.clone(),
        });

        return; // skip the file
    }

    for decl in &node.top_level_decls {
        visit_decl(ctx, decl);
    }

    // there should be no package progress to save in the symtab, since
    // we didn't create any sub-package scopes
}

fn visit_decl<'a>(ctx: &mut AnalysisContext<'a>, node: &DeclNode<'a>) {
    match node {
        DeclNode::Const { specs, .. } => visit_binding_decl(ctx, specs, false),
        DeclNode::Var { specs, .. } => visit_binding_decl(ctx, specs, true),
        DeclNode::Function(func_node) => visit_function_decl(ctx, func_node),
    }
}

fn visit_binding_decl<'a>(
    ctx: &mut AnalysisContext<'a>,
    specs: &[BindingDeclSpecNode<'a>],
    mutable: bool,
) {
    for spec in specs {
        visit_binding_decl_spec(ctx, spec, mutable);
    }
}

fn visit_binding_decl_spec<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &BindingDeclSpecNode<'a>,
    mutable: bool,
) {
    for id in &node.ids {
        let symbol = Symbol::new_ref(ctx.pin(id.clone()), mutable, None);

        ctx.declare_new_symbol(symbol);
    }
}

fn visit_function_decl<'a>(ctx: &mut AnalysisContext<'a>, node: &FunctionDeclNode<'a>) {
    if node.name.content() == "init" {
        // init functions are not actually declared (and there may be multiple
        // defined, even in the same file). note that this only applies for
        // top-level declarations (i.e., package scope), not anywhere else
        return;
    }

    let symbol = Symbol::new_ref(ctx.pin(node.name.clone()), false, None);

    ctx.declare_new_symbol(symbol);
}
