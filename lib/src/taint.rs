use parser::{
    Location, Span,
    ast::{BlockNode, DeclNode, ExprNode, ImportSpecNode, SourceFileNode, StatementNode},
};

use crate::{
    FullPackagePath,
    context::{AnalysisContext, DeferTarget},
    errors::AnalysisErrorKind,
    labels::Label,
    snapshots::SnapshotAware,
    values::BacktraceContainer,
};

mod channels;
mod enforcement;
mod explicit;
mod exprs;
mod funcs;
mod implicit;
mod mutation;

/// Structured information representing a declared sink.
///
/// This is a lightweight descriptor capturing the essential details of an
/// information flow sink as declared by the security policy in effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SinkDescriptor<'a> {
    /// The type of sink in question.
    pub kind: SinkKind,
    /// The sink's declared expected information label.
    pub label: Label<'a>,
    /// Where the sink was found.
    pub location: Location,
}

impl<'a> SinkDescriptor<'a> {
    fn new(kind: SinkKind, tags: &[&'a str], location: Location) -> Self {
        let label = Label::from_tags(tags);

        Self {
            kind,
            label,
            location,
        }
    }
}

impl SnapshotAware for SinkDescriptor<'_> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        self == other
    }
}

/// Represents a specific type of information flow sinks.
///
/// This is useful to know, for example, to provide more personalized error
/// messages when a sink's information flow invariant is violated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SinkKind {
    /// A variable/constant declaration.
    Declaration,
    /// An assignment to an existing symbol.
    Assignment,
    /// A function call.
    Call,
    /// A send statement.
    Send,
}

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
        if let DeclNode::Function(func) = decl
            && func.name.content() == "init"
        {
            // this will create a new scope, which is intended
            visit_block(ctx, &func.body);

            continue;
        }

        visit_decl(ctx, decl);
    }

    ctx.symtab_mut().save_package_progress(&package_path);
}

fn visit_import_spec<'a>(ctx: &mut AnalysisContext<'a>, node: &ImportSpecNode<'a>) {
    let first_stage = ctx.stage().is_first();

    match ctx.symtab_mut().register_import_spec(
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
                location: statement.location().into_owned(),
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
        StatementNode::Expr { expr, annotation } => {
            let values = exprs::visit_expr(ctx, expr);

            if let Some(annotation) = annotation {
                match annotation.directive {
                    "assert" => {
                        let location = expr.location().into_owned();

                        if values.is_empty() {
                            ctx.report_error(AnalysisErrorKind::UnexpectedVoidExpression {
                                location,
                            });
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
                    _ => ctx.report_error(AnalysisErrorKind::UnknownAnnotationDirective {
                        directive: annotation.directive,
                        location: annotation.location.clone(),
                    }),
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
        StatementNode::Goto { location, .. } => {
            // FIXME: goto statements are currently not supported since they can
            // almost completely break the control flow and are extremely rare
            // in real-life Go programs (hopefully)
            ctx.report_error(AnalysisErrorKind::GotoNotSupported {
                location: location.clone(),
            });
        }
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
        StatementNode::Defer { expr, location } => {
            // FIXME: defer statements are currently not supported (the
            // expression is just visited normally instead of later), since
            // there is currently a very tight coupling between 'pre-processing'
            // a call (e.g., visiting function value and arguments, checking if
            // everything is valid, determining when a built-in was called) and
            // actually committing the call (realizing the outcome according to
            // the provided arguments)
            ctx.report_error(AnalysisErrorKind::DeferNotDeferred {
                location: location.clone(),
            });

            exprs::visit_expr(ctx, expr);
        }
    }
}

fn disallows_subsequent_statements(node: &StatementNode<'_>) -> bool {
    match node {
        StatementNode::Continue { .. }
        | StatementNode::Break { .. }
        | StatementNode::Return { .. } => true,
        StatementNode::Block(statements) => statements
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
        | StatementNode::Goto { .. }
        | StatementNode::Go { .. }
        | StatementNode::Defer { .. } => false,
    }
}
