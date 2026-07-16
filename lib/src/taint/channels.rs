use std::{borrow::Cow, cell::Cell};

use parser::{
    Location,
    ast::{
        AssignmentNode, ExprNode, SelectNode, SendNode, ShortVarDeclNode, StatementNode,
        UnaryOpKind,
    },
};

use super::exprs;
use crate::{
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{Label, LabelBacktrace, LabelBacktraceKind},
    policy::{SinkDescriptor, SinkKind},
    taint::{annotations, enforcement, mutation::LeftValue},
    values::ValueRef,
};

pub fn visit_receive<'a>(
    ctx: &mut AnalysisContext<'a>,
    operand: &ExprNode<'a>,
    location: &Location,
) -> ValueRef<'a> {
    let pinned = ctx.pin(location.clone());

    // a receive inside a secret-dependent branch is externally observable:
    // any other holder of the same channel can determine that the receive
    // happened by observing subsequent channel state, so we need to fold the
    // current branch backtrace into the channel's own label. this is only
    // relevant when the operand is a mutable channel that we can reach through
    // a symbol; for example, a temporary value like `<-foo()` has no visible
    // aliases to leak through, so the plain-receive path below is enough
    if ctx.branch_backtrace().is_some() && operand.root_operand().is_some() {
        let received = Cell::new(None);

        #[expect(
            clippy::shadow_unrelated,
            reason = "Same context, just threaded through the transformer"
        )]
        operand.assign_with(
            ctx,
            LabelBacktraceKind::Receive,
            location,
            &|ctx, operand| {
                let Some(channel) = operand.as_channel() else {
                    ctx.report_error(AnalysisErrorKind::InvalidReceiveOperand {
                        location: location.clone(),
                    });

                    return None; // abort mutation
                };

                received.set(Some(channel.receive(pinned.clone())));

                drop(channel);

                // note that we don't actually have to change operand (besides
                // perhaps upgrading it to a channel), since what we actually
                // care about is the boilerplate handled by `assign_with` which
                // folds the current branch backtrace into the value
                Some(operand)
            },
        );

        return received
            .into_inner()
            .unwrap_or_else(|| ValueRef::new_bottom(pinned, None));
    }

    let value = exprs::visit_single_expr(ctx, operand);

    let Some(channel) = value.as_channel() else {
        ctx.report_error(AnalysisErrorKind::InvalidReceiveOperand {
            location: location.clone(),
        });

        return ValueRef::new_bottom(pinned, None);
    };

    channel.receive(pinned)
}

pub fn visit_send<'a>(ctx: &mut AnalysisContext<'a>, node: &SendNode<'a>) {
    let base = exprs::visit_single_expr(ctx, &node.expr);

    let mut explicit_backtrace = None;
    let mut subtract = Label::Bottom;

    if let Some(annotation) = &node.annotation
        && let Some(directive) = annotations::parse_supported_directive(ctx, annotation)
    {
        match directive {
            annotations::SendDirective::Label => {
                explicit_backtrace = LabelBacktrace::new_root(
                    LabelBacktraceKind::ExplicitAnnotation,
                    Label::from_tags(&annotation.tags),
                    None,
                    ctx.pin(node.location.clone()),
                );
            }
            annotations::SendDirective::Revoke => {
                if let Some(label) = annotations::resolve_revocation_label(ctx, annotation) {
                    subtract = label;
                }
            }
            annotations::SendDirective::AllowSink | annotations::SendDirective::DenySink => {
                let sink = SinkDescriptor::new(
                    SinkKind::Send,
                    directive == annotations::SendDirective::AllowSink,
                    &annotation.tags,
                    node.location.clone(), // statement, not annotation
                );

                if let Some(sink) = sink {
                    let backtrace = base.backtrace();

                    enforcement::trigger_sink(ctx, Cow::Owned(sink), backtrace);
                } else {
                    ctx.report_error(AnalysisErrorKind::InvalidDenySinkSemantics {
                        location: annotation.location.clone(),
                    });
                }
            }
            annotations::SendDirective::Assert => {
                let sequence = Label::sequence_from_tags(&annotation.tags);
                let backtrace = base.backtrace();

                enforcement::trigger_assertion(ctx, &sequence, backtrace, node.location.clone());
            }
        }
    }

    // we take send as syntactic sugar for a complex assignment
    node.channel.assign(
        ctx,
        LabelBacktraceKind::Send,
        base,
        None,
        false, // don't overwrite ever
        explicit_backtrace.as_ref(),
        &subtract,
        &node.location,
    );
}

pub fn visit_select<'a>(ctx: &mut AnalysisContext<'a>, node: &SelectNode<'a>) {
    // technically, for each case, the left-hand and right-hand sides of case
    // statement should be considered to evaluate at different points in time,
    // but for simplicity we assume that's not the case (and very rarely will
    // left-value evaluation result in noteworthy side-effects)

    let mut default = None;
    let mut to_push = vec![];

    for clause in &node.clauses {
        let Some(case) = &clause.case else {
            default = Some(clause);

            continue;
        };

        let Some(channel) = extract_select_case_channel(case) else {
            ctx.report_error(AnalysisErrorKind::IllegalSelectCase {
                location: case.location().into_owned(),
            });

            continue;
        };

        // remember backtrace for a potential `default` case
        to_push.extend(exprs::get_expr_backtrace(ctx, channel));

        // since this is not a `default` case (handled below), we need to
        // actually visit the clause (inside a dedicated scope)
        ctx.symtab_mut().select_next_child_scope(); // push

        super::visit_statement(ctx, case);
        super::visit_statements(ctx, &clause.body);

        ctx.symtab_mut().select_parent_scope(); // pop
    }

    // if the `default` case runs, it can be inferred that none of the other
    // communications can proceed, so we need to set appropriate branch
    // backtraces dependant on each of the involved channels.
    // note that this only matters for the `default` case, since order does not
    // matter in a select statement, and so later clauses are not only activated
    // when the earlier ones cannot (i.e., no information can be inferred) -- it
    // is different from an if/else because here there might be random selection
    let Some(default) = default else {
        return;
    };

    let to_pop = to_push.len();
    for backtrace in to_push {
        ctx.push_branch_backtrace(backtrace);
    }

    super::visit_statements(ctx, &default.body);

    for _ in 0..to_pop {
        ctx.pop_branch_backtrace();
    }
}

fn extract_select_case_channel<'a, 'b>(node: &'b StatementNode<'a>) -> Option<&'b ExprNode<'a>> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "We explicitly want to detect only these variants (per Go spec)"
    )]
    match node {
        StatementNode::Send(send) => Some(&send.channel),
        StatementNode::Expr {
            expr:
                ExprNode::UnaryOp {
                    kind: UnaryOpKind::Receive,
                    operand,
                    ..
                },
            ..
        } => Some(operand),
        StatementNode::Assignment(AssignmentNode { rhs, .. })
        | StatementNode::ShortVarDecl(ShortVarDeclNode { exprs: rhs, .. })
            if rhs.len() == 1 =>
        {
            rhs.first()
        }
        _ => None,
    }
}
