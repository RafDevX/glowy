use parser::{
    ast::{
        AssignmentNode, BlockNode, DeclNode, ExprNode, ForNode, FunctionDeclNode, IfNode,
        ImportSpecNode, SendNode, ShortVarDeclNode, SourceFileNode, StatementNode,
    },
    Location, Span,
};

use crate::{context::AnalysisContext, errors::AnalysisErrorKind, FullPackagePath};

mod channels;
mod explicit;
mod exprs;
mod funcs;
mod implicit;

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
        // init functions are not actually declared (and there may be multiple
        // defined, even in the same file). note that this only applies for
        // top-level declarations (i.e., package scope), not anywhere else
        if let DeclNode::Function(func) = decl {
            if func.name.content() == "init" {
                // this will create a new scope, which is intended
                visit_block(ctx, &func.body);

                continue;
            }
        }

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

fn visit_block<'a>(ctx: &mut AnalysisContext<'a>, node: &BlockNode<'a>) {
    ctx.symtab_mut().select_next_child_scope(); // push

    // (BlockNode is just a type alias for Vec, so we can pass it directly)
    visit_statements(ctx, node);

    ctx.symtab_mut().select_parent_scope(); // pop
}

fn visit_statements<'a>(ctx: &mut AnalysisContext<'a>, statements: &[StatementNode<'a>]) {
    let mut disallow_further = false;

    for statement in statements {
        if disallow_further {
            ctx.report_error(AnalysisErrorKind::Unreachable {
                location: get_statement_location(statement),
            });

            break;
        }

        visit_statement(ctx, statement);

        if disallows_subsequent_statements(statement) {
            disallow_further = true;
        }
    }
}

fn visit_statement<'a>(ctx: &mut AnalysisContext<'a>, node: &StatementNode<'a>) {
    match node {
        StatementNode::Empty { .. } => {}
        StatementNode::Expr(expr) => {
            exprs::visit_expr(ctx, expr);
        }
        StatementNode::Send(send) => channels::visit_send(ctx, send),
        StatementNode::Inc { operand, location } | StatementNode::Dec { operand, location } => {
            explicit::visit_incdec(ctx, operand, location);
        }
        StatementNode::Assignment(assignment) => explicit::visit_assignment(ctx, assignment),
        StatementNode::ShortVarDecl(decl) => explicit::visit_short_var_decl(ctx, decl),
        StatementNode::Block(block) => visit_block(ctx, block),
        StatementNode::Decl(decl) => visit_decl(ctx, decl),
        StatementNode::If(r#if) => implicit::visit_if(ctx, r#if),
        StatementNode::For(r#for) => implicit::visit_for(ctx, r#for),
        StatementNode::Continue { label, location } | StatementNode::Break { label, location } => {
            implicit::visit_continue_break(ctx, label.as_ref(), location)
        }
        StatementNode::Return { exprs, location } => funcs::visit_return(ctx, exprs, location),
        StatementNode::Go { expr, location } => match expr {
            ExprNode::Call(call) => {
                // for our purposes, a `go` statement is functionally equivalent to a function call
                funcs::visit_call(ctx, call);
            }
            _ => {
                ctx.report_error(AnalysisErrorKind::GoNotCall {
                    location: location.clone(),
                });
            }
        },
    }
}

fn get_statement_location(node: &StatementNode) -> Location {
    let location = match node {
        StatementNode::Empty { location }
        | StatementNode::Send(SendNode { location, .. })
        | StatementNode::Inc { location, .. }
        | StatementNode::Dec { location, .. }
        | StatementNode::Assignment(AssignmentNode { location, .. })
        | StatementNode::ShortVarDecl(ShortVarDeclNode { location, .. })
        | StatementNode::Decl(
            DeclNode::Const { location, .. }
            | DeclNode::Var { location, .. }
            | DeclNode::Function(FunctionDeclNode { location, .. }),
        )
        | StatementNode::If(IfNode { location, .. })
        | StatementNode::For(ForNode { location, .. })
        | StatementNode::Continue { location, .. }
        | StatementNode::Break { location, .. }
        | StatementNode::Return { location, .. }
        | StatementNode::Go { location, .. } => location,
        StatementNode::Expr(expr) => return exprs::get_expr_location(expr),
        StatementNode::Block(stmts) => {
            if let Some(first) = stmts.first() {
                if let Some(last) = stmts.last() {
                    let first = get_statement_location(first);
                    let last = get_statement_location(last);

                    return first.start..last.end;
                }
            }

            return 0..usize::MAX;
            // FIXME: ^ can't have location information for an empty block
        }
    };

    location.clone()
    // it would be preferable if this function could return &'a Location, but
    // this doesn't work for expressions, since get_expr_location returns a
    // Location and we can't a reference to it (since this function owns it).
    // in addition, block needs to create a new location altogether
}

fn disallows_subsequent_statements(node: &StatementNode<'_>) -> bool {
    match node {
        StatementNode::Continue { .. }
        | StatementNode::Break { .. }
        | StatementNode::Return { .. } => true,
        StatementNode::Block(statements) => statements
            .last()
            .map(|last| disallows_subsequent_statements(last))
            .unwrap_or(false),
        _ => false,
    }
}
