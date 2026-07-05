use self::{
    concur::{parse_defer_statement, parse_go_statement, parse_select_statement},
    flow::{
        parse_break_statement, parse_continue_statement, parse_for_statement, parse_goto_statement,
        parse_if_statement, parse_return_statement, parse_switch_statement,
    },
};
use super::{
    PResult,
    decls::{
        bindings::{parse_const_decl, parse_var_decl},
        types::parse_type_decl,
    },
    expect,
    exprs::{parse_expression, parse_expressions_list, parse_expressions_list_while},
};
use crate::{
    Annotation, ParsingError, TokenStream,
    ast::{
        AssignmentKind, AssignmentNode, BlockNode, CallNode, ExprNode, SendNode, ShortVarDeclNode,
        StatementNode,
    },
    parser::{BacktrackingContext, of_kind},
    token::{Token, TokenKind},
};

mod concur;
mod flow;

// continue from the right-hand side
fn resume_parsing_assignment_rhs<'a>(
    s: &mut TokenStream<'a>,
    lhs: Vec<ExprNode<'a>>,
    kind: AssignmentKind,
    annotation: Option<Box<Annotation<'a>>>,
) -> PResult<'a, StatementNode<'a>> {
    if let Some(rhs) = parse_expressions_list_while(s, |t| !terminal_token(&t.kind), true)? {
        let location = s.location_starting_at(lhs.first().unwrap().location().start);

        Ok(StatementNode::Assignment(AssignmentNode {
            kind,
            lhs,
            rhs,
            location,
            annotation,
        }))
    } else {
        // reached end-of-file...
        expect(s, TokenKind::SemiColon, Some("assignment"))?;
        // ^^ this will error
        unreachable!()
    }
}

// continue from the left-hand side
fn resume_parsing_assignment_lhs<'a>(
    s: &mut TokenStream<'a>,
    mut lhs: Vec<ExprNode<'a>>,
) -> PResult<'a, StatementNode<'a>> {
    // collect the rest of the expressions, if any
    if let Some((rest, kind)) =
        parse_expressions_list(s, |t| AssignmentKind::try_from(t.kind), true)?
    {
        s.next(); // step over operator

        lhs.extend(rest);

        let annotation = s.take_last_annotation();

        resume_parsing_assignment_rhs(s, lhs, kind, annotation)
    } else {
        // reached end-of-file and found no assignment operator...
        Err(ParsingError::UnexpectedConstruct {
            expected: "an assignment statement",
            found: None, // if we got here, this must mean end-of-file
        })
    }
}

// statements that start with an expression and then diverge wrt operator
fn parse_expression_first_stmt<'a>(s: &mut TokenStream<'a>) -> PResult<'a, StatementNode<'a>> {
    let lhs = parse_expression(s, true)?;

    // this needs to be separate so we don't consume the semicolon, as well as
    // to avoid using peek on the match (would require .next in every branch)
    if let Some(Ok(of_kind!(kind))) = s.peek()
        && terminal_token(kind)
    {
        let annotation = s.take_last_annotation();

        let annotation = if let Some(stmt_annotation) = &annotation
            && let ExprNode::Call(CallNode {
                annotation: Some(call_annotation),
                ..
            }) = &lhs
            && stmt_annotation == call_annotation
        {
            // don't use the same annotation twice
            None
        } else {
            annotation
        };

        let stmt = StatementNode::Expr {
            expr: lhs,
            annotation,
        };

        return Ok(stmt);
    }

    // necessary to make the borrow checker happy (lhs passed before location)
    let lhs_location = lhs.location().into_owned();

    let node = match s.next().transpose()? {
        Some(of_kind!(TokenKind::LtMinus)) => StatementNode::Send(SendNode {
            channel: lhs,
            expr: parse_expression(s, true)?,
            location: s.location_starting_at(lhs_location.start),
            annotation: s.take_last_annotation(),
        }),
        Some(of_kind!(TokenKind::PlusPlus)) => StatementNode::Inc {
            operand: lhs,
            location: s.location_starting_at(lhs_location.start),
        },
        Some(of_kind!(TokenKind::MinusMinus)) => StatementNode::Dec {
            operand: lhs,
            location: s.location_starting_at(lhs_location.start),
        },
        Some(of_kind!(TokenKind::Comma)) => resume_parsing_assignment_lhs(s, vec![lhs])?,
        found => {
            if let Some(token) = found.clone()
                && let Ok(kind) = AssignmentKind::try_from(token.kind)
            {
                let annotation = s.take_last_annotation();

                return resume_parsing_assignment_rhs(s, vec![lhs], kind, annotation);
            }

            return Err(ParsingError::UnexpectedTokenKind {
                expected: TokenKind::SemiColon,
                found,
                context: Some("statement"),
            });
        }
    };

    Ok(node)
}

fn parse_identifier_first_stmt<'a>(s: &mut TokenStream<'a>) -> PResult<'a, StatementNode<'a>> {
    let mut context = BacktrackingContext::new(s);
    let b = context.stream();

    let first = expect(b, TokenKind::Ident, Some("statement"))?;

    if let Some(Ok(of_kind!(TokenKind::Colon))) = b.peek() {
        // labeled statement
        b.next(); // take colon
        context.commit()?; // we're sure, so we'll use the main stream now

        return Ok(StatementNode::Labeled {
            label: first.span,
            inner: Box::new(parse_statement(s, true)?),
        });
    }

    // assume it's a short var decl and that we're collecting ids (vs expressions)
    let mut ids = vec![first.span];

    let mut was_comma = false; // whether the last token was a comma

    loop {
        match b.peek().cloned().transpose()? {
            Some(of_kind!(TokenKind::Ident)) => {
                if was_comma {
                    ids.push(b.next().unwrap()?.span);
                    was_comma = false;
                } else {
                    // 2 identifiers in a row
                    expect(b, TokenKind::Comma, Some("statement"))?;
                    // ^^ this will error
                }
            }
            found @ Some(of_kind!(TokenKind::Comma)) => {
                if was_comma {
                    // 2 commas in a row
                    return Err(ParsingError::UnexpectedConstruct {
                        expected: "an identifier or an expression",
                        found,
                    });
                }

                b.next(); // advance
                was_comma = true;
            }
            Some(of_kind!(TokenKind::ColonAssign)) if !was_comma => break, // short var decl!

            // we got it wrong... they're expressions
            _ => return parse_expression_first_stmt(s), // backtrack
        }
    }

    b.next().unwrap()?; // step over operator that caused break
    context.commit()?; // we're sure it's a short var decl so we can go back to the main stream now
    let annotation = s.take_last_annotation();

    if let Some(exprs) = parse_expressions_list_while(s, |t| !terminal_token(&t.kind), true)? {
        Ok(StatementNode::ShortVarDecl(ShortVarDeclNode {
            ids,
            exprs,
            location: s.location_since(&first),
            annotation,
        }))
    } else {
        // reached end-of-file...
        expect(s, TokenKind::SemiColon, Some("short variable declaration"))?;
        // ^^ this will error
        unreachable!()
    }
}

fn parse_statement<'a>(
    s: &mut TokenStream<'a>,
    allow_non_simple: bool,
) -> PResult<'a, StatementNode<'a>> {
    let node = match s.peek().cloned().transpose()? {
        Some(t @ of_kind!(TokenKind::SemiColon)) => StatementNode::Empty {
            location: t.span.location(),
        },
        Some(of_kind!(TokenKind::CurlyL)) if allow_non_simple => {
            StatementNode::Block(parse_block(s)?)
        }
        Some(of_kind!(TokenKind::If)) if allow_non_simple => parse_if_statement(s)?.into(),
        Some(of_kind!(TokenKind::For)) if allow_non_simple => parse_for_statement(s)?.into(),
        Some(of_kind!(TokenKind::Select)) if allow_non_simple => parse_select_statement(s)?.into(),
        Some(of_kind!(TokenKind::Switch)) if allow_non_simple => parse_switch_statement(s)?.into(),
        Some(t @ of_kind!(TokenKind::Fallthrough)) if allow_non_simple => {
            s.next(); // advance

            StatementNode::Fallthrough {
                location: t.span.location(),
            }
        }
        Some(of_kind!(TokenKind::Continue)) if allow_non_simple => parse_continue_statement(s)?,
        Some(of_kind!(TokenKind::Break)) if allow_non_simple => parse_break_statement(s)?,
        Some(of_kind!(TokenKind::Return)) if allow_non_simple => parse_return_statement(s)?,
        Some(of_kind!(TokenKind::Goto)) if allow_non_simple => parse_goto_statement(s)?,
        Some(of_kind!(TokenKind::Go)) if allow_non_simple => parse_go_statement(s)?,
        Some(of_kind!(TokenKind::Defer)) if allow_non_simple => parse_defer_statement(s)?,

        // declarations (sadly cannot be abstracted, indistinguishable if not for keywords)
        Some(of_kind!(TokenKind::Const)) if allow_non_simple => parse_const_decl(s)?.into(),
        Some(of_kind!(TokenKind::Var)) if allow_non_simple => parse_var_decl(s)?.into(),
        Some(of_kind!(TokenKind::Type)) if allow_non_simple => parse_type_decl(s)?.into(),

        Some(of_kind!(TokenKind::Ident)) => parse_identifier_first_stmt(s)?,
        _ => parse_expression_first_stmt(s)?,
    };

    Ok(node)
}

pub fn parse_statements_until<'a>(
    s: &mut TokenStream<'a>,
    stop: impl Fn(&Token) -> bool,
) -> PResult<'a, Vec<StatementNode<'a>>> {
    let mut stmts = vec![];

    while !s.peek().cloned().transpose()?.as_ref().is_none_or(&stop) {
        stmts.push(parse_statement(s, true)?);

        // spec allows omitting semicolon before closing } and )
        if let Some(Ok(t @ of_kind!(TokenKind::CurlyR | TokenKind::ParenR))) = s.peek()
            && stop(t)
        {
            break;
        }

        expect(s, TokenKind::SemiColon, Some("statements list"))?;
    }

    Ok(stmts)
}

pub fn parse_block<'a>(s: &mut TokenStream<'a>) -> PResult<'a, BlockNode<'a>> {
    let opening = expect(s, TokenKind::CurlyL, Some("block"))?;

    let stmts = parse_statements_until(s, |t| t.kind == TokenKind::CurlyR)?;

    expect(s, TokenKind::CurlyR, Some("block"))?;

    let location = s.location_since(&opening);

    Ok(BlockNode { stmts, location })
}

// may terminate a statement
pub fn terminal_token(kind: &TokenKind) -> bool {
    matches!(
        kind,
        TokenKind::SemiColon // i++; <---
        | TokenKind::CurlyL // for ...; i++ { <---
        | TokenKind::CurlyR // { ...; i++ } <---
        | TokenKind::Colon // select { case x = <-c: <---
    )
}

pub struct UnknownAssignmentKind;

impl TryFrom<TokenKind> for AssignmentKind {
    type Error = UnknownAssignmentKind;

    #[inline]
    fn try_from(kind: TokenKind) -> Result<Self, Self::Error> {
        let res = match kind {
            TokenKind::Assign => Self::Simple,
            TokenKind::PlusAssign => Self::Sum,
            TokenKind::MinusAssign => Self::Diff,
            TokenKind::StarAssign => Self::Product,
            TokenKind::SlashAssign => Self::Quotient,
            TokenKind::PercentAssign => Self::Remainder,
            TokenKind::DoubleLtAssign => Self::ShiftLeft,
            TokenKind::DoubleGtAssign => Self::ShiftRight,
            TokenKind::PipeAssign => Self::BitwiseOr,
            TokenKind::AmpAssign => Self::BitwiseAnd,
            TokenKind::CaretAssign => Self::BitwiseXor,
            TokenKind::AmpCaretAssign => Self::BitClear,
            _ => return Err(UnknownAssignmentKind),
        };

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Span,
        ast::{BinaryOpKind, LiteralNode, UnaryOpKind},
        lexer::Lexer,
    };

    fn parse(input: &str) -> PResult<'_, Vec<StatementNode<'_>>> {
        let mut stream = TokenStream::new(Lexer::new(input));

        Ok(parse_block(&mut stream)?.stmts)
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn block() {
        assert_eq!(
            vec![
                StatementNode::Expr {
                    expr: ExprNode::BinaryOp {
                        kind: BinaryOpKind::Sum,
                        left: Box::new(ExprNode::Literal(LiteralNode::Int {
                            value: 2,
                            location: 39..40
                        })),
                        right: Box::new(ExprNode::Literal(LiteralNode::Int {
                            value: 7,
                            location: 43..44
                        })),
                        location: 39..44,
                    },
                    annotation: None,
                },
                StatementNode::Empty { location: 66..67 },
                StatementNode::Assignment(AssignmentNode {
                    kind: AssignmentKind::Simple,
                    lhs: vec![
                        ExprNode::Name(Span::new("a", 88, 5)),
                        ExprNode::Name(Span::new("b", 91, 5))
                    ],
                    rhs: vec![
                        ExprNode::Name(Span::new("c", 95, 5)),
                        ExprNode::Name(Span::new("d", 98, 5))
                    ],
                    location: 88..99,
                    annotation: None,
                }),
                StatementNode::Assignment(AssignmentNode {
                    kind: AssignmentKind::Simple,
                    lhs: vec![
                        ExprNode::UnaryOp {
                            kind: UnaryOpKind::Negation,
                            operand: Box::new(ExprNode::Literal(LiteralNode::Int {
                                value: 4,
                                location: 122..123
                            })),
                            location: 121..123,
                        },
                        ExprNode::Name(Span::new("x", 125, 6)),
                        ExprNode::Name(Span::new("k", 129, 6))
                    ],
                    rhs: vec![
                        ExprNode::BinaryOp {
                            kind: BinaryOpKind::Product,
                            left: Box::new(ExprNode::Literal(LiteralNode::Int {
                                value: 4,
                                location: 134..135
                            })),
                            right: Box::new(ExprNode::Literal(LiteralNode::Int {
                                value: 2,
                                location: 138..139
                            })),
                            location: 134..139,
                        },
                        ExprNode::BinaryOp {
                            kind: BinaryOpKind::Sum,
                            left: Box::new(ExprNode::Literal(LiteralNode::Int {
                                value: 5,
                                location: 141..142
                            })),
                            right: Box::new(ExprNode::Literal(LiteralNode::Int {
                                value: 2,
                                location: 145..146
                            })),
                            location: 141..146,
                        },
                        ExprNode::Name(Span::new("x", 148, 6))
                    ],
                    location: 121..149,
                    annotation: None,
                }),
                StatementNode::ShortVarDecl(ShortVarDeclNode {
                    ids: vec![
                        Span::new("k", 171, 7),
                        Span::new("r", 174, 7),
                        Span::new("v", 177, 7)
                    ],
                    exprs: vec![
                        ExprNode::Name(Span::new("m", 182, 7)),
                        ExprNode::Name(Span::new("n", 185, 7)),
                        ExprNode::Name(Span::new("o", 188, 7))
                    ],
                    location: 171..189,
                    annotation: None,
                }),
                StatementNode::Assignment(AssignmentNode {
                    kind: AssignmentKind::Simple,
                    lhs: vec![ExprNode::Name(Span::new("a", 263, 10))],
                    rhs: vec![ExprNode::Name(Span::new("b", 267, 10))],
                    location: 263..268,
                    annotation: Some(Box::new(Annotation {
                        directive: "directive",
                        tags: vec!["a", "b", "c"],
                        location: 215..242,
                    })),
                }),
                StatementNode::ShortVarDecl(ShortVarDeclNode {
                    ids: vec![Span::new("c", 290, 11)],
                    exprs: vec![ExprNode::Name(Span::new("d", 295, 11))],
                    location: 290..296,
                    annotation: None
                })
            ],
            parse(
                "
                {
                    2 + 7;
                    ;
                    a, b = c, d;
                    -4, x, (k) = 4 * 2, 5 + 2, x;
                    k, r, v := m, n, o;

                    // glowy::directive::{a, b, c}
                    a = b;
                    c := d;
                }
            "
            )
            .unwrap()
        );
    }
}
