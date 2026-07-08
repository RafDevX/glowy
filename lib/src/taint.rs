//! Module for Go taint analysis and security policy enforcement.
//!
//! Glowy's principal pipeline processes a Go source file's Abstract Syntax Tree
//! (AST) by visiting each descendent node exactly once and propagating defined
//! taints to later enforcement checks configured to verify certain aspects of
//! an overarching security policy. This module implements that core
//! functionality.

use parser::{
    Span,
    ast::{BlockNode, DeclNode, ExprNode, ImportSpecNode, SourceFileNode, StatementNode},
};

use crate::{
    FullPackagePath,
    context::{AnalysisContext, DeferTarget},
    errors::AnalysisErrorKind,
    labels::Label,
    values::BacktraceContainer,
};

mod annotations;
mod channels;
mod enforcement;
mod explicit;
mod exprs;
mod funcs;
mod goto;
mod implicit;
mod mutation;
mod types;

pub use funcs::ResolvedCall;
pub use goto::GotoConvergenceState;

#[expect(
    clippy::needless_pass_by_value,
    reason = "Signature consistency between top-level visitors"
)]
pub fn visit_source_file<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &SourceFileNode<'a>,
    package_path: FullPackagePath,
) {
    let package_name = ctx.pin(node.package_clause.id);

    let original_name = ctx.enter_package(package_name, package_path.clone());

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
        if let DeclNode::Function(func) = decl
            && func.name.content() == "init"
            && let Some(body) = &func.body
        {
            // this will create a new scope, which is intended
            visit_block(ctx, body);

            continue;
        }

        visit_decl(ctx, decl);
    }

    ctx.symtab_mut().save_package_progress(&package_path);
}

fn visit_import_spec<'a>(ctx: &mut AnalysisContext<'a>, node: &ImportSpecNode<'a>) {
    let first_stage = ctx.stage().is_first();

    match ctx.register_import_spec(
        node.identifier
            .as_ref()
            .map(Span::content)
            .map(str::to_owned),
        node.path.clone(),
        !first_stage,
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
            explicit::visit_binding_decl(ctx, specs, false, location, annotation.as_deref());
        }
        DeclNode::Var {
            specs,
            location,
            annotation,
        } => {
            explicit::visit_binding_decl(ctx, specs, true, location, annotation.as_deref());
        }
        DeclNode::Type { .. } => {} // we just ignore these
        DeclNode::Function(func_node) => funcs::visit_function_decl(ctx, func_node),
    }
}

fn visit_block<'a>(ctx: &mut AnalysisContext<'a>, node: &BlockNode<'a>) {
    visit_scoped_statements(ctx, &node.stmts);
}

fn visit_scoped_statements<'a>(ctx: &mut AnalysisContext<'a>, statements: &[StatementNode<'a>]) {
    ctx.symtab_mut().select_next_child_scope(); // push

    visit_statements(ctx, statements);

    ctx.symtab_mut().select_parent_scope(); // pop
}

fn visit_statements<'a>(ctx: &mut AnalysisContext<'a>, statements: &[StatementNode<'a>]) {
    let mut disallow_further = false;
    let mut already_reported_unreachable = false; // prevent duplicates

    for statement in statements {
        if let StatementNode::Labeled { label, .. } = statement
            && goto::is_label_targeted(ctx, label.content())
        {
            // a labeled statement that is targeted by a `goto` statement is
            // always reachable, so reset the unreachable reporting state
            disallow_further = false;
            already_reported_unreachable = false;
        }

        if disallow_further && !already_reported_unreachable {
            ctx.report_error(AnalysisErrorKind::Unreachable {
                location: statement.location().into_owned(),
            });

            already_reported_unreachable = true;

            continue;
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
        StatementNode::Expr { expr, annotation } => {
            let values = exprs::visit_expr(ctx, expr);

            if let Some(annotation) = annotation
                && annotations::parse_supported_directive(ctx, annotation)
                    == Some(annotations::ExprDirective::Assert)
            {
                let location = expr.location().into_owned();

                if values.is_empty() {
                    ctx.report_error(AnalysisErrorKind::UnexpectedVoidExpression { location });
                    return;
                }

                let sequence = Label::sequence_from_tags(&annotation.tags);
                let location = ctx.pin(location);

                for value in values {
                    enforcement::trigger_assertion(
                        ctx,
                        &sequence,
                        value.backtrace_at_location(location.clone()),
                        location.inner().clone(),
                    );
                }
            }
        }
        StatementNode::Send(send) => channels::visit_send(ctx, send),
        StatementNode::Inc { operand, location } | StatementNode::Dec { operand, location } => {
            explicit::visit_incdec(ctx, operand, location);
        }
        StatementNode::Assignment(assignment) => explicit::visit_assignment(ctx, assignment),
        StatementNode::ShortVarDecl(decl) => explicit::visit_short_var_decl(ctx, decl),
        StatementNode::Labeled { label, inner } => {
            // handle the case where we know a `goto` stmt targets this label
            goto::visit_label_in_goto_context(ctx, *label);

            visit_statement(ctx, inner);

            if let StatementNode::For(_) = inner.as_ref() {
                ctx.trigger_defer_target(DeferTarget::LabeledLoop(label.content()));
            }
        }
        StatementNode::Block(block) => visit_block(ctx, block),
        StatementNode::Decl(decl) => visit_decl(ctx, decl),
        StatementNode::If(r#if) => implicit::visit_if(ctx, r#if),
        StatementNode::For(r#for) => implicit::visit_for(ctx, r#for),
        StatementNode::Select(select) => channels::visit_select(ctx, select),
        StatementNode::Switch(switch) => implicit::visit_switch(ctx, switch),
        StatementNode::Fallthrough { location } => {
            // if we reached it in visit_statement, it's not supposed to be here
            // (switch visitor collects any legitimate fallthrough statements)
            ctx.report_error(AnalysisErrorKind::UnexpectedFallthrough {
                location: location.clone(),
            });
        }
        StatementNode::Continue { label, location } | StatementNode::Break { label, location } => {
            implicit::visit_continue_break(ctx, *label, location);
        }
        StatementNode::Return { exprs, location } => funcs::visit_return(ctx, exprs, location),
        StatementNode::Goto { label, location } => goto::visit_goto(ctx, *label, location),
        StatementNode::Go { expr, location } => {
            if let ExprNode::Call(call) = expr {
                // for our purposes, a `go` statement is functionally equivalent
                // to a function call
                funcs::visit_call(ctx, call);
            } else {
                ctx.report_error(AnalysisErrorKind::GoNotCall {
                    location: location.clone(),
                });
            }
        }
        StatementNode::Defer { expr, location } => funcs::visit_defer(ctx, expr, location),
    }
}

fn disallows_subsequent_statements(node: &StatementNode<'_>) -> bool {
    match node {
        StatementNode::Continue { .. }
        | StatementNode::Break { .. }
        | StatementNode::Return { .. }
        | StatementNode::Goto { .. } => true,
        StatementNode::Block(block) => block
            .stmts
            .last()
            .is_some_and(disallows_subsequent_statements),

        // not using wildcard to force reconsidering this implementation if
        // new statements are added (need to decide what this fn should return)
        StatementNode::Empty { .. }
        | StatementNode::Expr { .. }
        | StatementNode::Send(_)
        | StatementNode::Inc { .. }
        | StatementNode::Dec { .. }
        | StatementNode::Assignment(_)
        | StatementNode::ShortVarDecl(_)
        | StatementNode::Labeled { .. }
        | StatementNode::Decl { .. }
        | StatementNode::If(_)
        | StatementNode::For(_)
        | StatementNode::Switch(_)
        | StatementNode::Select(_)
        | StatementNode::Fallthrough { .. }
        | StatementNode::Go { .. }
        | StatementNode::Defer { .. } => false,
    }
}
