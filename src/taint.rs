use parser::ast::{DeclNode, SourceFileNode};

use crate::{context::AnalysisContext, FullPackagePath};

mod channels;
mod explicit;
mod exprs;

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
    let package_name = ctx.pin(node.package_clause.id.clone());

    let original_name = ctx
        .symtab_mut()
        .enter_package(package_name, package_path.clone());
    // ^ automatically primes symtab for children

    if original_name.content() != node.package_clause.id.content() {
        // error was already reported in Stage 1 -- [`decls::visit_source_file`]

        return; // skip the file
    }

    for decl in &node.top_level_decls {
        visit_decl(ctx, decl);
    }

    ctx.symtab_mut().save_package_progress(&package_path);
}

fn visit_decl<'a>(ctx: &mut AnalysisContext<'a>, node: &DeclNode<'a>) {
    match node {
        DeclNode::Const {
            specs,
            location,
            annotation,
        } => {
            explicit::visit_binding_decl(ctx, specs, false, location, annotation);
        }
        DeclNode::Var {
            specs,
            location,
            annotation,
        } => {
            explicit::visit_binding_decl(ctx, specs, true, location, annotation);
        }
        DeclNode::Function(func_node) => {
            ctx.symtab_mut().select_next_sibling_scope();

            // TODO: ...
        }
    }
}
