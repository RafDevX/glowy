use std::borrow::Cow;

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
    taint::{SinkDescriptor, SinkKind, enforcement, explicit::LeftValue},
    values::{SelfAwareBacktraceContainer, ValueRef},
};

pub fn visit_receive<'a>(
    ctx: &mut AnalysisContext<'a>,
    operand: &ExprNode<'a>,
    location: &Location,
) -> ValueRef<'a> {
    // TODO: must update channel's label to match branch label, because
    // otherwise "has a value been read" or "has the channel been depleted" can
    // be used to exfiltrate information

    exprs::visit_single_expr(ctx, operand).nest_backtrace(
        LabelBacktraceKind::Receive,
        None,
        ctx.pin(location.clone()),
        vec![],
    )
}

pub fn visit_send<'a>(ctx: &mut AnalysisContext<'a>, node: &SendNode<'a>) {
    let base = exprs::visit_single_expr(ctx, &node.expr);

    let mut explicit_backtrace = None;

    if let Some(annotation) = &node.annotation {
        match annotation.directive {
            "label" => {
                explicit_backtrace = Some(LabelBacktrace::new_root(
                    LabelBacktraceKind::ExplicitAnnotation,
                    Label::from_tags(&annotation.tags),
                    None,
                    ctx.pin(node.location.clone()),
                ));
            }
            "sink" => {
                let sink = SinkDescriptor::new(
                    SinkKind::Send,
                    &annotation.tags,
                    node.location.clone(), // statement, not annotation
                );

                let backtrace = base.backtrace();

                enforcement::trigger_sink(ctx, Cow::Owned(sink), backtrace);
            }
            "assert" => {
                let sequence = Label::sequence_from_tags(&annotation.tags);
                let backtrace = base.backtrace();

                enforcement::trigger_assertion(ctx, &sequence, backtrace, node.location.clone());
            }
            _ => ctx.report_error(AnalysisErrorKind::UnknownAnnotationDirective {
                directive: annotation.directive,
                location: annotation.location.clone(),
            }),
        }
    }

    // we take send as syntactic sugar for a complex assignment
    node.channel.assign(
        ctx,
        LabelBacktraceKind::Send,
        base,
        false, // don't overwrite ever
        explicit_backtrace.as_ref(),
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
                location: super::get_statement_location(case),
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
