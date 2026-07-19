use parser::{
    Location,
    ast::{
        AssignmentNode, ExprNode, SelectClauseNode, SelectNode, SendNode, ShortVarDeclNode,
        StatementNode, UnaryOpKind,
    },
};

use crate::{
    context::{AnalysisContext, SplitControlFlowArm},
    errors::AnalysisErrorKind,
    labels::{LabelBacktrace, LabelBacktraceKind},
    taint::{self, explicit, exprs},
    values::ValueRef,
};

pub fn visit_select<'a>(ctx: &mut AnalysisContext<'a>, node: &SelectNode<'a>) {
    // all channel operands and send rhs expressions are evaluated exactly once,
    // in source order, upon entering the select. receive lhs expressions are
    // intentionally absent here as they are only evaluated after a case wins
    let evaluated: Vec<_> = node
        .clauses
        .iter()
        .filter_map(|clause| EvaluatedSelectClause::new(ctx, clause))
        .collect();

    // any readiness fact can affect which communication is selected. apply
    // the union to every arm (including default), but exclude payload labels:
    // payload contents do not determine whether a communication can proceed.
    let readiness_dependencies: Vec<_> = evaluated
        .iter()
        .filter_map(|clause| clause.readiness_backtrace(ctx))
        .collect();

    let readiness = LabelBacktrace::fold(
        readiness_dependencies.iter(),
        LabelBacktraceKind::Branch,
        None,
        ctx.pin(node.location.clone()),
    );

    ctx.push_split_control_flow(node.location.clone());

    let pushed_readiness = if let Some(backtrace) = readiness {
        ctx.push_branch_backtrace(backtrace);

        true
    } else {
        false
    };

    for (index, clause) in evaluated.iter().enumerate() {
        ctx.set_current_split_arm(Some(SplitControlFlowArm::SelectClause(index)));

        ctx.symtab_mut().select_next_child_scope();

        clause.visit_selected(ctx);

        taint::visit_statements(ctx, &clause.clause.body);

        ctx.symtab_mut().select_parent_scope();
    }

    ctx.set_current_split_arm(None);

    if pushed_readiness {
        ctx.pop_branch_backtrace();
    }

    ctx.pop_split_control_flow();
}

struct EvaluatedSelectClause<'a, 'clause> {
    clause: &'clause SelectClauseNode<'a>,
    communication: EvaluatedSelectCommunication<'a, 'clause>,
}

impl<'a, 'clause> EvaluatedSelectClause<'a, 'clause> {
    fn new(ctx: &mut AnalysisContext<'a>, clause: &'clause SelectClauseNode<'a>) -> Option<Self> {
        let communication = match clause.case.as_ref() {
            None => EvaluatedSelectCommunication::Default,
            Some(StatementNode::Send(node)) => EvaluatedSelectCommunication::Send {
                node,
                channel: exprs::visit_single_expr(ctx, &node.channel),
                payload: exprs::visit_single_expr(ctx, &node.expr),
            },
            Some(node) => {
                if let Some((operand, location, target)) = extract_select_receive(node) {
                    EvaluatedSelectCommunication::Receive {
                        target,
                        channel: exprs::visit_single_expr(ctx, operand),
                        location,
                    }
                } else {
                    ctx.report_error(AnalysisErrorKind::IllegalSelectCase {
                        location: node.location().into_owned(),
                    });

                    return None;
                }
            }
        };

        Some(Self {
            clause,
            communication,
        })
    }

    fn readiness_backtrace(&self, ctx: &AnalysisContext<'a>) -> Option<LabelBacktrace<'a>> {
        let channel = match &self.communication {
            EvaluatedSelectCommunication::Send { channel, .. }
            | EvaluatedSelectCommunication::Receive { channel, .. } => channel,
            EvaluatedSelectCommunication::Default => {
                return None;
            }
        };

        let channel = channel.as_channel()?;

        channel.readiness_backtrace(ctx.pin(self.clause.case.as_ref()?.location().into_owned()))
    }

    fn visit_selected(&self, ctx: &mut AnalysisContext<'a>) {
        match &self.communication {
            EvaluatedSelectCommunication::Default => {}
            EvaluatedSelectCommunication::Send {
                node,
                channel,
                payload,
            } => {
                let mut channel = channel.clone();

                super::send_through_channel_with(ctx, node, &mut channel, payload);
            }
            EvaluatedSelectCommunication::Receive {
                target,
                channel,
                location,
            } => {
                let pinned = ctx.pin((*location).clone());

                let mut channel = channel.clone();

                let received = super::receive_from_channel(ctx, &mut channel, location, &pinned)
                    .unwrap_or_else(|| ValueRef::new_bottom(pinned, None));

                target.assign(ctx, received);
            }
        }
    }
}

enum EvaluatedSelectCommunication<'a, 'clause> {
    Default,
    Send {
        node: &'clause SendNode<'a>,
        channel: ValueRef<'a>,
        payload: ValueRef<'a>,
    },
    Receive {
        target: SelectReceiveTarget<'a, 'clause>,
        channel: ValueRef<'a>,
        location: &'clause Location,
    },
}

enum SelectReceiveTarget<'a, 'clause> {
    Discard,
    Assignment(&'clause AssignmentNode<'a>),
    ShortDeclaration(&'clause ShortVarDeclNode<'a>),
}

impl<'a> SelectReceiveTarget<'a, '_> {
    fn assign(&self, ctx: &mut AnalysisContext<'a>, received: ValueRef<'a>) {
        match self {
            Self::Discard => {}
            Self::Assignment(node) => {
                explicit::visit_assignment_with(ctx, node, vec![(received, None)]);
            }
            Self::ShortDeclaration(node) => {
                explicit::visit_short_var_decl_with(ctx, node, vec![(received, None)]);
            }
        }
    }
}

fn extract_select_receive<'a, 'clause>(
    node: &'clause StatementNode<'a>,
) -> Option<(
    &'clause ExprNode<'a>,
    &'clause Location,
    SelectReceiveTarget<'a, 'clause>,
)> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "We explicitly want to detect only these variants (per Go spec)"
    )]
    match node {
        StatementNode::Expr {
            expr:
                ExprNode::UnaryOp {
                    kind: UnaryOpKind::Receive,
                    operand,
                    location,
                },
            ..
        } => Some((operand, location, SelectReceiveTarget::Discard)),
        StatementNode::Assignment(assignment) => {
            extract_receive_expr(&assignment.rhs).map(|(operand, location)| {
                (
                    operand,
                    location,
                    SelectReceiveTarget::Assignment(assignment),
                )
            })
        }
        StatementNode::ShortVarDecl(declaration) => {
            extract_receive_expr(&declaration.exprs).map(|(operand, location)| {
                (
                    operand,
                    location,
                    SelectReceiveTarget::ShortDeclaration(declaration),
                )
            })
        }
        _ => None,
    }
}

fn extract_receive_expr<'a, 'clause>(
    exprs: &'clause [ExprNode<'a>],
) -> Option<(&'clause ExprNode<'a>, &'clause Location)> {
    match exprs {
        [
            ExprNode::UnaryOp {
                kind: UnaryOpKind::Receive,
                operand,
                location,
            },
        ] => Some((operand, location)),
        _ => None,
    }
}
