use parser::ast::{DeclNode, SourceFileNode};

use crate::{context::AnalysisContext, FullPackagePath};

macro_rules! select_scope_iter {
    ($ctx:expr, $item:ident in $items:expr => $body:block) => {
        let mut iter = $items.iter().peekable();

        if iter.peek().is_some() {
            $ctx.symtab_mut().select_first_child_scope();

            while let Some($item) = iter.next() {
                $body

                if iter.peek().is_some() {
                    $ctx.symtab_mut().select_next_sibling_scope();
                }
            }

            $ctx.symtab_mut().select_parent_scope();
        }
    };
}

pub fn visit_source_file<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &SourceFileNode<'a>,
    package_path: FullPackagePath,
) {
    let package_name = ctx.scope_span(node.package_clause.id.clone());

    let original_name = ctx.symtab_mut().enter_package(package_name, package_path);

    if original_name.content() != node.package_clause.id.content() {
        // error was already reported in Stage 1 -- [`decls::visit_source_file`]

        return; // skip the file
    }

    select_scope_iter!(ctx, decl in node.top_level_decls => {
        visit_decl(ctx, decl);
    });
}

fn visit_decl<'a>(ctx: &mut AnalysisContext<'a>, node: &DeclNode<'a>) {
    dbg!(&node);

    match node {
        DeclNode::Const { specs, .. } => {}
        DeclNode::Var { specs, .. } => {}
        DeclNode::Function(func_node) => {}
    }
}
