use parser::{
    ast::{DeclNode, ImportSpecNode, SourceFileNode, StatementNode},
    Span,
};

use crate::{context::AnalysisContext, errors::AnalysisErrorKind, FullPackagePath};

mod channels;
mod explicit;
mod exprs;
mod funcs;

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

    for import in &node.imports {
        for spec in &import.specs {
            visit_import_spec(ctx, spec);
        }
    }

    for decl in &node.top_level_decls {
        visit_decl(ctx, decl);
    }

    ctx.symtab_mut().save_package_progress(&package_path);
}

fn visit_import_spec<'a>(ctx: &mut AnalysisContext<'a>, node: &ImportSpecNode<'a>) {
    match ctx.symtab_mut().register_import_spec(
        node.identifier
            .as_ref()
            .map(Span::content)
            .map(str::to_owned),
        node.path.clone(),
    ) {
        None => ctx.report_error(AnalysisErrorKind::UnresolvableUnqualifiedImport {
            location: node.location.clone(),
        }),
        Some(true) => ctx.report_error(AnalysisErrorKind::DuplicateImportQualifier {
            location: node.location.clone(),
        }),
        Some(false) => {} // all good
    }
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
        DeclNode::Function(func_node) => funcs::visit_function_decl(ctx, func_node),
    }
}

fn visit_statements<'a>(ctx: &mut AnalysisContext<'a>, statements: &[StatementNode<'a>]) {
    for statement in statements {
        if ctx.returning() && *statement != StatementNode::Empty {
            // FIXME: don't have any location information at this point (from
            // parser) to pass to ErrorKind::Unreachable, which makes it pretty
            // opaque and thus very broad error messages (file-granularity)
            ctx.report_error(AnalysisErrorKind::Unreachable);

            break;
        }

        visit_statement(ctx, statement);
    }
}

fn visit_statement<'a>(ctx: &mut AnalysisContext<'a>, node: &StatementNode<'a>) {
    match node {
        StatementNode::Empty => {}
        StatementNode::Expr(expr) => {
            exprs::visit_expr(ctx, expr);
        }
        StatementNode::Send(send) => todo!(),
        StatementNode::Inc { operand, location } | StatementNode::Dec { operand, location } => {
            todo!()
        }
        StatementNode::Assignment(assignment) => todo!(),
        StatementNode::ShortVarDecl(decl) => explicit::visit_short_var_decl(ctx, decl),
        StatementNode::Decl(decl) => visit_decl(ctx, decl),
        StatementNode::If(r#if) => todo!(),
        StatementNode::Block(statements) => {
            ctx.symtab_mut().select_next_child_scope(); // push

            visit_statements(ctx, statements);

            ctx.symtab_mut().select_parent_scope(); // pop
        }
        StatementNode::Return { exprs, location } => funcs::visit_return(ctx, exprs, location),
        StatementNode::Go(expr) => todo!(),
    }
}
