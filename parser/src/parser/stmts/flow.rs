use crate::{
    ParsingError, TokenStream,
    ast::{
        ElseNode, ExprSwitchCaseClause, ExprSwitchNode, ForClauseNode, ForHeaderNode, ForNode,
        ForRangeNode, IfNode, StatementNode, SwitchNode, TypeNode, TypeSwitchCaseClause,
        TypeSwitchNode,
    },
    parser::{
        BacktrackingContext, PResult, expect,
        exprs::{parse_expression, parse_expressions_list_while, parse_primary_expression},
        of_kind,
        stmts::{parse_block, parse_statement, parse_statements_until, terminal_token},
        types::parse_types_until,
    },
    token::TokenKind,
};

pub fn parse_if_statement<'a>(s: &mut TokenStream<'a>) -> PResult<'a, IfNode<'a>> {
    let beginning = expect(s, TokenKind::If, Some("if statement"))?;

    // try to read a statement
    let mut context = BacktrackingContext::new(s);
    let b = context.stream();

    let stmt = if let Ok(stmt) = parse_statement(b, false)
        && let Some(Ok(of_kind!(TokenKind::SemiColon))) = b.next()
    {
        // got it, we can continue with the main stream from now on
        context.commit()?;

        Some(Box::new(stmt))
    } else {
        // nope, rollback
        None
    };

    let cond = parse_expression(s, false)?;
    let then = parse_block(s)?;

    let otherwise = if let Some(Ok(of_kind!(TokenKind::Else))) = s.peek() {
        s.next(); // advance

        let node = if let Some(Ok(of_kind!(TokenKind::If))) = s.peek() {
            ElseNode::If(Box::new(parse_if_statement(s)?))
        } else {
            ElseNode::Block(parse_block(s)?)
        };

        Some(node)
    } else {
        None
    };

    let location = s.location_since(&beginning);

    Ok(IfNode {
        stmt,
        cond,
        then,
        otherwise,
        location,
    })
}

#[allow(clippy::too_many_lines)]
pub fn parse_for_statement<'a>(s: &mut TokenStream<'a>) -> PResult<'a, ForNode<'a>> {
    let beginning = expect(s, TokenKind::For, Some("for loop"))?;

    let header = match s.peek().cloned().transpose()? {
        Some(of_kind!(TokenKind::CurlyL)) => {
            // for { }

            ForHeaderNode::Clause(ForClauseNode {
                init: None,
                cond: None,
                post: None,
            })
        }
        Some(of_kind!(TokenKind::SemiColon)) => {
            // for ; cond? ; post? { }

            s.next(); // advance

            let cond = if let Some(Ok(of_kind!(TokenKind::SemiColon))) = s.peek() {
                None
            } else {
                Some(parse_expression(s, false)?)
            };

            expect(s, TokenKind::SemiColon, Some("for clause"))?;

            let post = if let Some(Ok(of_kind!(TokenKind::CurlyL))) = s.peek() {
                None
            } else {
                Some(Box::new(parse_statement(s, false)?))
            };

            ForHeaderNode::Clause(ForClauseNode {
                init: None,
                cond,
                post,
            })
        }
        Some(of_kind!(TokenKind::Range)) => {
            // for range expr { }

            s.next(); // advance

            let range_expr = parse_expression(s, false)?;

            ForHeaderNode::Range(ForRangeNode::None { range_expr })
        }
        _ => {
            // possibilities of what we can find at this point
            enum ForKind {
                SingleCondition, // for one_bare_condition { }
                ClauseWithInit,  // for init; cond?; post? { }
                RangeDecl,       // for a, b := range expr { }
                RangeAssignment, // for a, b  = range expr { }
            }

            // we assume it's the simplest for, unless we find proof otherwise
            let mut kind = ForKind::SingleCondition;

            // if we find a "range" token, it confirms this kind
            let mut range_kind_hint = None;

            // no point in using BacktrackingContext if we'll never commit
            for future in s.clone() {
                match future?.kind {
                    TokenKind::CurlyL => break, // was actually SingleCondition
                    TokenKind::SemiColon => {
                        // can no longer be a single condition; must have init
                        kind = ForKind::ClauseWithInit;
                        break;
                    }
                    TokenKind::ColonAssign if range_kind_hint.is_none() => {
                        // it might be a `for a := range expr`, but it might
                        // also just be a normal `for i := 0; i < 5; i++`, so
                        // we need to also find a "range" keyword to confirm
                        range_kind_hint = Some(ForKind::RangeDecl);
                    }
                    TokenKind::Assign if range_kind_hint.is_none() => {
                        range_kind_hint = Some(ForKind::RangeAssignment);
                    }
                    TokenKind::Range => {
                        if let Some(hint) = range_kind_hint {
                            // confirmed
                            kind = hint;
                        }
                        // else: range without preceding := or = must be wrong,
                        // but we'll let it error further down the line within
                        // non-for-range parsing so we have more surrounding
                        // context information for the error

                        break;
                    }
                    _ => {}
                }
            }

            match kind {
                ForKind::SingleCondition => {
                    let cond = parse_expression(s, false)?;

                    ForHeaderNode::Clause(ForClauseNode {
                        init: None,
                        cond: Some(cond),
                        post: None,
                    })
                }
                ForKind::ClauseWithInit => {
                    let init = Some(Box::new(parse_statement(s, false)?));

                    expect(s, TokenKind::SemiColon, Some("for clause"))?;

                    let cond = if let Some(Ok(of_kind!(TokenKind::SemiColon))) = s.peek() {
                        None
                    } else {
                        Some(parse_expression(s, false)?)
                    };

                    expect(s, TokenKind::SemiColon, Some("for clause"))?;

                    let post = if let Some(Ok(of_kind!(TokenKind::CurlyL))) = s.peek() {
                        None
                    } else {
                        Some(Box::new(parse_statement(s, false)?))
                    };

                    ForHeaderNode::Clause(ForClauseNode { init, cond, post })
                }
                ForKind::RangeDecl => {
                    let mut lhs = vec![];
                    let mut expect_comma = false;

                    loop {
                        match s.next().transpose()? {
                            Some(token @ of_kind!(TokenKind::Ident)) if !expect_comma => {
                                lhs.push(token.span);
                                expect_comma = true;
                            }
                            Some(of_kind!(TokenKind::Comma)) if expect_comma => {
                                expect_comma = false;
                            }
                            Some(of_kind!(TokenKind::ColonAssign)) if !lhs.is_empty() => break,
                            found => {
                                let expected = if lhs.is_empty() {
                                    TokenKind::Ident
                                } else {
                                    TokenKind::ColonAssign
                                };

                                return Err(ParsingError::UnexpectedTokenKind {
                                    expected,
                                    found,
                                    context: Some("for range clause"),
                                });
                            }
                        }
                    }

                    expect(s, TokenKind::Range, Some("for range clause"))?;

                    let range_expr = parse_expression(s, false)?;

                    ForHeaderNode::Range(ForRangeNode::Decl { lhs, range_expr })
                }
                ForKind::RangeAssignment => {
                    let lhs = parse_expressions_list_while(
                        s,
                        |token| token.kind != TokenKind::Assign,
                        false,
                    )?
                    .unwrap_or_else(Vec::new); // got end-of-file but that's equivalent to empty expressions list

                    if lhs.is_empty() {
                        return Err(ParsingError::UnexpectedConstruct {
                            expected: "a list of expressions",
                            found: s.next().transpose()?,
                        });
                    }

                    expect(s, TokenKind::Assign, Some("for range clause"))?;
                    expect(s, TokenKind::Range, Some("for range clause"))?;

                    let range_expr = parse_expression(s, false)?;

                    ForHeaderNode::Range(ForRangeNode::Assignment { lhs, range_expr })
                }
            }
        }
    };

    let header_location = s.location_since(&beginning);

    let body = parse_block(s)?;

    let location = s.location_since(&beginning);

    Ok(ForNode {
        header,
        header_location,
        body,
        location,
    })
}

pub fn parse_switch_statement<'a>(s: &mut TokenStream<'a>) -> PResult<'a, SwitchNode<'a>> {
    // check if it's a type switch by looking for a "type" keyword ahead
    // (No need for BacktrackingContext if we'll never commit)
    for future in s.clone() {
        match future?.kind {
            TokenKind::CurlyL => break, // we didn't find any
            TokenKind::Type => {
                // found it, we can go back to the original stream s
                return parse_type_switch_statement(s).map(Into::into);
            }
            _ => {}
        }
    }

    // if we got here, it's an expr type switch (and we go back to original s)
    parse_expr_switch_statement(s).map(Into::into)
}

fn parse_expr_switch_statement<'a>(s: &mut TokenStream<'a>) -> PResult<'a, ExprSwitchNode<'a>> {
    let beginning = expect(s, TokenKind::Switch, Some("switch statement"))?;

    let mut stmt = None;
    for future in s.clone() {
        match future?.kind {
            TokenKind::CurlyL => break, // didn't find any semicolon
            TokenKind::SemiColon => {
                // we now know there's a simple statement we need to parse
                // before the switch expression
                stmt = Some(Box::new(parse_statement(s, false)?));

                expect(s, TokenKind::SemiColon, Some("switch statement"))?;

                break;
            }
            _ => {}
        }
    }

    let expr = if let Some(Ok(of_kind!(TokenKind::CurlyL))) = s.peek() {
        // no switch expression (equivalent to true)
        None
    } else {
        Some(parse_expression(s, false)?)
    };

    expect(s, TokenKind::CurlyL, Some("switch statement"))?;

    let mut clauses = vec![];
    while !matches!(s.peek(), Some(Ok(of_kind!(TokenKind::CurlyR)))) {
        clauses.push(parse_expr_switch_case_clause(s)?);
    }

    expect(s, TokenKind::CurlyR, Some("switch statement"))?;

    Ok(ExprSwitchNode {
        stmt,
        expr,
        clauses,
        location: s.location_since(&beginning),
    })
}

fn parse_expr_switch_case_clause<'a>(
    s: &mut TokenStream<'a>,
) -> PResult<'a, ExprSwitchCaseClause<'a>> {
    let exprs = if let Some(Ok(of_kind!(TokenKind::Default))) = s.peek() {
        s.next(); // advance

        Vec::new()
    } else {
        expect(s, TokenKind::Case, Some("switch case clause"))?;

        parse_expressions_list_while(s, |token| token.kind != TokenKind::Colon, true)?
            .unwrap_or_else(Vec::new) // no colon found; ok, we'll error after
    };

    expect(s, TokenKind::Colon, Some("switch case clause"))?;

    let body = parse_statements_until(s, |token| {
        matches!(
            token.kind,
            TokenKind::Case | TokenKind::Default | TokenKind::CurlyR
        )
    })?;

    Ok(ExprSwitchCaseClause { exprs, body })
}

fn parse_type_switch_statement<'a>(s: &mut TokenStream<'a>) -> PResult<'a, TypeSwitchNode<'a>> {
    let beginning = expect(s, TokenKind::Switch, Some("switch statement"))?;

    let mut stmt = None;
    for future in s.clone() {
        match future?.kind {
            TokenKind::CurlyL => break, // didn't find any ;
            TokenKind::SemiColon => {
                // we now know there's a simple statement we need to parse
                // before the switch expression
                stmt = Some(Box::new(parse_statement(s, false)?));

                expect(s, TokenKind::SemiColon, Some("switch statement"))?;

                break;
            }
            _ => {}
        }
    }

    // this can't be merged with the lookup above because first we need to
    // know if there's a semicolon before attempting to search for a :=,
    // otherwise in `switch z := 9; x` the := will trigger early when it's not
    // actually a type switch declaration (just part of the statement)
    let mut decl = None;
    for future in s.clone() {
        match future?.kind {
            TokenKind::CurlyL => break, // didn't find any :=
            TokenKind::ColonAssign => {
                let ident = expect(s, TokenKind::Ident, Some("switch declaration"))?;

                decl = Some(ident.span);

                expect(s, TokenKind::ColonAssign, Some("switch statement"))?;

                break;
            }
            _ => {}
        }
    }

    let expr = parse_primary_expression(s, false)?;

    expect(s, TokenKind::Period, Some("type switch"))?;
    expect(s, TokenKind::ParenL, Some("type switch"))?;
    expect(s, TokenKind::Type, Some("type switch"))?;
    expect(s, TokenKind::ParenR, Some("type switch"))?;

    expect(s, TokenKind::CurlyL, Some("switch statement"))?;

    let mut clauses = vec![];
    while !matches!(s.peek(), Some(Ok(of_kind!(TokenKind::CurlyR)))) {
        clauses.push(parse_type_switch_case_clause(s)?);
    }

    expect(s, TokenKind::CurlyR, Some("switch statement"))?;

    Ok(TypeSwitchNode {
        stmt,
        decl,
        expr,
        clauses,
        location: s.location_since(&beginning),
    })
}

fn parse_type_switch_case_clause<'a>(
    s: &mut TokenStream<'a>,
) -> PResult<'a, TypeSwitchCaseClause<'a>> {
    let types = if let Some(Ok(of_kind!(TokenKind::Default))) = s.peek() {
        s.next(); // advance

        Vec::new()
    } else {
        expect(s, TokenKind::Case, Some("switch case clause"))?;

        parse_types_until(s, |token| token.kind == TokenKind::Colon)?
            .into_iter()
            .map(|r#type| {
                if let TypeNode::Name {
                    package: None,
                    id,
                    args,
                } = &r#type
                    && id.content() == "nil"
                    && args.is_empty()
                {
                    // Go spec: "Instead of a type, a case may use the
                    // predeclared identifier nil; that case is selected when
                    // the expression in the TypeSwitchGuard is a nil interface
                    // value. There may be at most one nil case."
                    // (here we don't check how many nil cases there are;
                    // consuming code can do that)

                    None
                } else {
                    Some(r#type)
                }
            })
            .collect()
    };

    expect(s, TokenKind::Colon, Some("switch case clause"))?;

    let body = parse_statements_until(s, |token| {
        matches!(
            token.kind,
            TokenKind::Case | TokenKind::Default | TokenKind::CurlyR
        )
    })?;

    Ok(TypeSwitchCaseClause { types, body })
}

pub fn parse_continue_statement<'a>(s: &mut TokenStream<'a>) -> PResult<'a, StatementNode<'a>> {
    let beginning = expect(s, TokenKind::Continue, Some("continue statement"))?;

    let label = if s
        .peek()
        .cloned()
        .transpose()?
        .is_none_or(|t| terminal_token(&t.kind))
    // ^ eof is arguably terminal
    {
        None
    } else {
        Some(expect(s, TokenKind::Ident, Some("continue label"))?.span)
    };

    let location = s.location_since(&beginning);

    Ok(StatementNode::Continue { label, location })
}

pub fn parse_break_statement<'a>(s: &mut TokenStream<'a>) -> PResult<'a, StatementNode<'a>> {
    let beginning = expect(s, TokenKind::Break, Some("break statement"))?;

    let label = if s
        .peek()
        .cloned()
        .transpose()?
        .is_none_or(|t| terminal_token(&t.kind))
    // ^ eof is arguably terminal
    {
        None
    } else {
        Some(expect(s, TokenKind::Ident, Some("break label"))?.span)
    };

    let location = s.location_since(&beginning);

    Ok(StatementNode::Break { label, location })
}

pub fn parse_return_statement<'a>(s: &mut TokenStream<'a>) -> PResult<'a, StatementNode<'a>> {
    let beginning = expect(s, TokenKind::Return, Some("return statement"))?;

    let exprs = parse_expressions_list_while(s, |token| !terminal_token(&token.kind), true)?
        .unwrap_or_else(Vec::new); // a potentially better error will be thrown higher up the chain

    Ok(StatementNode::Return {
        exprs,
        location: s.location_since(&beginning),
    })
}

pub fn parse_goto_statement<'a>(s: &mut TokenStream<'a>) -> PResult<'a, StatementNode<'a>> {
    let beginning = expect(s, TokenKind::Goto, Some("goto statement"))?;

    let label = expect(s, TokenKind::Ident, Some("goto statement"))?.span;

    Ok(StatementNode::Goto {
        label,
        location: s.location_since(&beginning),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Span,
        ast::{
            AssignmentKind, AssignmentNode, BinaryOpKind, BlockNode, CallNode, ExprNode,
            LiteralNode, OrderedF64, SelectionNode, ShortVarDeclNode, StatementNode, TypeNode,
            TypeSwitchCaseClause, UnaryOpKind,
        },
        lexer::Lexer,
        parser::stmts::parse_block,
    };

    fn parse(input: &str) -> PResult<'_, BlockNode<'_>> {
        let mut stream = TokenStream::new(Lexer::new(input));

        parse_block(&mut stream)
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn if_chain() {
        assert_eq!(
            vec![StatementNode::If(IfNode {
                stmt: None,
                cond: ExprNode::BinaryOp {
                    kind: BinaryOpKind::Greater,
                    left: Box::new(ExprNode::BinaryOp {
                        kind: BinaryOpKind::Sum,
                        left: Box::new(ExprNode::Name(Span::new("a", 50, 3))),
                        right: Box::new(ExprNode::Literal(LiteralNode::Int {
                            value: 3,
                            location: 54..55
                        })),
                        location: 50..55,
                    }),
                    right: Box::new(ExprNode::Literal(LiteralNode::Int {
                        value: 4,
                        location: 58..59
                    })),
                    location: 50..59,
                },
                then: vec![
                    StatementNode::Empty { location: 90..91 },
                    StatementNode::Assignment(AssignmentNode {
                        kind: AssignmentKind::Simple,
                        lhs: vec![ExprNode::Name(Span::new("a", 120, 5))],
                        rhs: vec![ExprNode::Literal(LiteralNode::Int {
                            value: 4,
                            location: 124..125
                        })],
                        location: 120..125,
                        annotation: None,
                    })
                ],
                otherwise: Some(ElseNode::If(Box::new(IfNode {
                    stmt: None,
                    cond: ExprNode::UnaryOp {
                        kind: UnaryOpKind::Negation,
                        operand: Box::new(ExprNode::UnaryOp {
                            kind: UnaryOpKind::Negation,
                            operand: Box::new(ExprNode::Literal(LiteralNode::Int {
                                value: 9,
                                location: 164..165
                            })),
                            location: 163..165,
                        }),
                        location: 161..166,
                    },
                    then: vec![StatementNode::ShortVarDecl(ShortVarDeclNode {
                        ids: vec![Span::new("k", 197, 7)],
                        exprs: vec![ExprNode::Literal(LiteralNode::Int {
                            value: 3,
                            location: 202..203
                        })],
                        location: 197..203,
                        annotation: None
                    })],
                    otherwise: Some(ElseNode::Block(vec![
                        StatementNode::Block(vec![]),
                        StatementNode::Dec {
                            operand: ExprNode::Name(Span::new("m", 298, 10),),
                            location: 298..301,
                        },
                        StatementNode::Assignment(AssignmentNode {
                            kind: AssignmentKind::BitClear,
                            lhs: vec![
                                ExprNode::Name(Span::new("k", 331, 11)),
                                ExprNode::Selection(SelectionNode {
                                    base: Box::new(ExprNode::Name(Span::new("m", 334, 11))),
                                    selector: Span::new("r", 336, 11),
                                    location: 334..337
                                }),
                            ],
                            rhs: vec![
                                ExprNode::Literal(LiteralNode::Int {
                                    value: 3,
                                    location: 342..343
                                }),
                                ExprNode::Literal(LiteralNode::Int {
                                    value: 2,
                                    location: 345..346
                                }),
                            ],
                            location: 331..346,
                            annotation: None,
                        })
                    ])),
                    location: 158..373,
                }))),
                location: 47..373,
            })],
            parse(
                "
                    {
                        if a + 3 > 4 {
                            ;
                            a = 4;
                        } else if -(-9) {
                            k := 3;
                        } else {
                            {};
                            m--;
                            k, m.r &^= 3, 2;
                        };
                    }
                ",
            )
            .unwrap(),
        );
    }

    #[test]
    fn if_with_prep_statement() {
        assert_eq!(
            vec![StatementNode::If(IfNode {
                stmt: Some(Box::new(StatementNode::ShortVarDecl(ShortVarDeclNode {
                    ids: vec![Span::new("x", 50, 3)],
                    exprs: vec![ExprNode::Literal(LiteralNode::Int {
                        value: 4,
                        location: 55..56
                    })],
                    location: 50..56,
                    annotation: None
                }))),
                cond: ExprNode::BinaryOp {
                    kind: BinaryOpKind::Less,
                    left: Box::new(ExprNode::Name(Span::new("x", 58, 3))),
                    right: Box::new(ExprNode::Literal(LiteralNode::Int {
                        value: 3,
                        location: 62..63
                    })),
                    location: 58..63
                },
                then: vec![StatementNode::Empty { location: 94..95 }],
                otherwise: Some(ElseNode::If(Box::new(IfNode {
                    stmt: None,
                    cond: ExprNode::Name(Span::new("false", 130, 5)),
                    then: vec![StatementNode::Empty { location: 166..167 }],
                    otherwise: Some(ElseNode::If(Box::new(IfNode {
                        stmt: Some(Box::new(StatementNode::Expr {
                            expr: ExprNode::Call(CallNode {
                                func: Box::new(ExprNode::Name(Span::new("y", 202, 7))),
                                type_arg: None,
                                args: vec![],
                                variadic: false,
                                location: 202..205,
                                annotation: None
                            }),
                            annotation: None
                        })),
                        cond: ExprNode::Name(Span::new("true", 207, 7)),
                        then: vec![StatementNode::Block(vec![])],
                        otherwise: None,
                        location: 199..270
                    }))),
                    location: 127..270
                }))),
                location: 47..270
            })],
            parse(
                "
                    {
                        if x := 4; x < 3 {
                            ;
                        } else if false {
                            ;
                        } else if y(); true {
                            {}
                        };
                    }
                ",
            )
            .unwrap(),
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn switch_expr() {
        assert_eq!(
            vec![
                StatementNode::Switch(SwitchNode::Expr(ExprSwitchNode {
                    stmt: None,
                    expr: Some(ExprNode::Name(Span::new("tag", 54, 3))),
                    clauses: vec![
                        ExprSwitchCaseClause {
                            exprs: vec![],
                            body: vec![StatementNode::Expr {
                                expr: ExprNode::Literal(LiteralNode::Int {
                                    value: 3,
                                    location: 97..98
                                }),
                                annotation: None
                            }]
                        },
                        ExprSwitchCaseClause {
                            exprs: vec![
                                ExprNode::Literal(LiteralNode::Int {
                                    value: 0,
                                    location: 132..133
                                }),
                                ExprNode::Literal(LiteralNode::Int {
                                    value: 1,
                                    location: 135..136
                                }),
                                ExprNode::Literal(LiteralNode::Int {
                                    value: 2,
                                    location: 138..139
                                }),
                            ],
                            body: vec![StatementNode::Expr {
                                expr: ExprNode::Call(CallNode {
                                    func: Box::new(ExprNode::Name(Span::new("f", 141, 5))),
                                    type_arg: None,
                                    args: vec![],
                                    variadic: false,
                                    location: 141..144,
                                    annotation: None
                                }),
                                annotation: None
                            }]
                        },
                        ExprSwitchCaseClause {
                            exprs: vec![
                                ExprNode::Literal(LiteralNode::Int {
                                    value: 3,
                                    location: 178..179
                                }),
                                ExprNode::Literal(LiteralNode::Int {
                                    value: 4,
                                    location: 181..182
                                }),
                                ExprNode::Literal(LiteralNode::Int {
                                    value: 5,
                                    location: 184..185
                                }),
                            ],
                            body: vec![StatementNode::Expr {
                                expr: ExprNode::Call(CallNode {
                                    func: Box::new(ExprNode::Name(Span::new("g", 187, 6))),
                                    type_arg: None,
                                    args: vec![],
                                    variadic: false,
                                    location: 187..190,
                                    annotation: None
                                }),
                                annotation: None
                            }]
                        }
                    ],
                    location: 47..216
                })),
                StatementNode::Switch(SwitchNode::Expr(ExprSwitchNode {
                    stmt: Some(Box::new(StatementNode::ShortVarDecl(ShortVarDeclNode {
                        ids: vec![Span::new("x", 249, 9)],
                        exprs: vec![ExprNode::Call(CallNode {
                            func: Box::new(ExprNode::Name(Span::new("f", 254, 9))),
                            type_arg: None,
                            args: vec![],
                            variadic: false,
                            location: 254..257,
                            annotation: None
                        })],
                        location: 249..257,
                        annotation: None
                    }))),
                    expr: None,
                    clauses: vec![
                        ExprSwitchCaseClause {
                            exprs: vec![ExprNode::BinaryOp {
                                kind: BinaryOpKind::Less,
                                left: Box::new(ExprNode::Name(Span::new("x", 294, 10))),
                                right: Box::new(ExprNode::Literal(LiteralNode::Int {
                                    value: 0,
                                    location: 298..299
                                })),
                                location: 294..299
                            }],
                            body: vec![StatementNode::Return {
                                exprs: vec![ExprNode::UnaryOp {
                                    kind: UnaryOpKind::Negation,
                                    operand: Box::new(ExprNode::Name(Span::new("x", 309, 10))),
                                    location: 308..310
                                }],
                                location: 301..310
                            }]
                        },
                        ExprSwitchCaseClause {
                            exprs: vec![],
                            body: vec![StatementNode::Return {
                                exprs: vec![ExprNode::Name(Span::new("x", 355, 11))],
                                location: 348..356
                            }]
                        }
                    ],
                    location: 242..382
                })),
                StatementNode::Switch(SwitchNode::Expr(ExprSwitchNode {
                    stmt: None,
                    expr: None,
                    clauses: vec![
                        ExprSwitchCaseClause {
                            exprs: vec![ExprNode::BinaryOp {
                                kind: BinaryOpKind::Less,
                                left: Box::new(ExprNode::Name(Span::new("x", 450, 15))),
                                right: Box::new(ExprNode::Name(Span::new("y", 454, 15))),
                                location: 450..455
                            }],
                            body: vec![
                                StatementNode::Expr {
                                    expr: ExprNode::Call(CallNode {
                                        func: Box::new(ExprNode::Name(Span::new("f", 489, 16))),
                                        type_arg: None,
                                        args: vec![],
                                        variadic: false,
                                        location: 489..492,
                                        annotation: None
                                    }),
                                    annotation: None
                                },
                                StatementNode::Assignment(AssignmentNode {
                                    kind: AssignmentKind::Simple,
                                    lhs: vec![ExprNode::Name(Span::new("z", 525, 17))],
                                    rhs: vec![ExprNode::Literal(LiteralNode::Int {
                                        value: 3,
                                        location: 529..530
                                    })],
                                    location: 525..530,
                                    annotation: None,
                                }),
                                StatementNode::Fallthrough { location: 563..574 }
                            ]
                        },
                        ExprSwitchCaseClause {
                            exprs: vec![],
                            body: vec![StatementNode::Expr {
                                expr: ExprNode::Call(CallNode {
                                    func: Box::new(ExprNode::Name(Span::new("g", 644, 20))),
                                    type_arg: None,
                                    args: vec![],
                                    variadic: false,
                                    location: 644..647,
                                    annotation: None
                                }),
                                annotation: None
                            }]
                        }
                    ],
                    location: 408..673
                }))
            ],
            parse(
                "
                    {
                        switch tag {
                            default: 3
                            case 0, 1, 2: f()
                            case 3, 4, 5: g()
                        }

                        switch x := f(); {
                            case x < 0: return -x
                            default: return x
                        }

                        switch {
                            case x < y:
                                f()
                                z = 3
                                fallthrough
                            default:
                                g()
                        }
                    }
        "
            )
            .unwrap()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn switch_type() {
        assert_eq!(
            vec![
                StatementNode::Switch(SwitchNode::Type(TypeSwitchNode {
                    stmt: None,
                    decl: Some(Span::new("i", 54, 3)),
                    expr: ExprNode::Name(Span::new("x", 59, 3)),
                    clauses: vec![
                        TypeSwitchCaseClause {
                            types: vec![None],
                            body: vec![]
                        },
                        TypeSwitchCaseClause {
                            types: vec![
                                Some(TypeNode::Name {
                                    package: None,
                                    id: Span::new("int", 141, 5),
                                    args: vec![]
                                }),
                                Some(TypeNode::Name {
                                    package: None,
                                    id: Span::new("float64", 146, 5),
                                    args: vec![]
                                })
                            ],
                            body: vec![StatementNode::Assignment(AssignmentNode {
                                kind: AssignmentKind::Simple,
                                lhs: vec![ExprNode::Name(Span::new("isEven", 155, 5))],
                                rhs: vec![ExprNode::BinaryOp {
                                    kind: BinaryOpKind::Eq,
                                    left: Box::new(ExprNode::BinaryOp {
                                        kind: BinaryOpKind::Remainder,
                                        left: Box::new(ExprNode::Name(Span::new("i", 164, 5))),
                                        right: Box::new(ExprNode::Literal(LiteralNode::Int {
                                            value: 2,
                                            location: 168..169
                                        })),
                                        location: 164..169
                                    }),
                                    right: Box::new(ExprNode::Literal(LiteralNode::Int {
                                        value: 0,
                                        location: 173..174
                                    })),
                                    location: 164..174
                                }],
                                location: 155..174,
                                annotation: None,
                            })]
                        },
                        TypeSwitchCaseClause {
                            types: vec![],
                            body: vec![
                                StatementNode::Expr {
                                    expr: ExprNode::Call(CallNode {
                                        func: Box::new(ExprNode::Name(Span::new("f", 244, 7))),
                                        type_arg: None,
                                        args: vec![],
                                        variadic: false,
                                        location: 244..247,
                                        annotation: None
                                    }),
                                    annotation: None
                                },
                                StatementNode::Return {
                                    exprs: vec![ExprNode::Literal(LiteralNode::Float {
                                        value: OrderedF64(12.1),
                                        location: 287..291
                                    })],
                                    location: 280..291
                                }
                            ]
                        }
                    ],
                    location: 47..317
                })),
                StatementNode::Switch(SwitchNode::Type(TypeSwitchNode {
                    stmt: Some(Box::new(StatementNode::ShortVarDecl(ShortVarDeclNode {
                        ids: vec![Span::new("z", 350, 11)],
                        exprs: vec![ExprNode::Literal(LiteralNode::Int {
                            value: 9,
                            location: 355..356
                        })],
                        location: 350..356,
                        annotation: None
                    }))),
                    decl: None,
                    expr: ExprNode::Call(CallNode {
                        func: Box::new(ExprNode::Name(Span::new("f", 358, 11))),
                        type_arg: None,
                        args: vec![ExprNode::Literal(LiteralNode::Int {
                            value: 7,
                            location: 360..361
                        })],
                        variadic: false,
                        location: 358..362,
                        annotation: None
                    }),
                    clauses: vec![TypeSwitchCaseClause {
                        types: vec![Some(TypeNode::Name {
                            package: None,
                            id: Span::new("float64", 405, 12),
                            args: vec![]
                        })],
                        body: vec![StatementNode::Expr {
                            expr: ExprNode::Call(CallNode {
                                func: Box::new(ExprNode::Name(Span::new("g", 414, 12))),
                                type_arg: None,
                                args: vec![ExprNode::Name(Span::new("z", 416, 12))],
                                variadic: false,
                                location: 414..418,
                                annotation: None
                            }),
                            annotation: None
                        }]
                    }],
                    location: 343..444
                }))
            ],
            parse(
                "
                    {
                        switch i := x.(type) {
                            case nil:
                            case int, float64: isEven = i % 2 == 0
                            default:
                                f()
                                return 12.1
                        }

                        switch z := 9; f(7).(type) {
                            case float64: g(z)
                        }
                    }
                ",
            )
            .unwrap(),
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn for_clause() {
        assert_eq!(
            vec![
                StatementNode::For(ForNode {
                    header: ForHeaderNode::Clause(ForClauseNode {
                        init: Some(Box::new(StatementNode::ShortVarDecl(ShortVarDeclNode {
                            ids: vec![Span::new("i", 51, 3)],
                            exprs: vec![ExprNode::Literal(LiteralNode::Int {
                                value: 0,
                                location: 56..57
                            })],
                            location: 51..57,
                            annotation: None
                        }))),
                        cond: Some(ExprNode::BinaryOp {
                            kind: BinaryOpKind::Less,
                            left: Box::new(ExprNode::Name(Span::new("i", 59, 3))),
                            right: Box::new(ExprNode::Literal(LiteralNode::Int {
                                value: 5,
                                location: 63..64
                            })),
                            location: 59..64
                        }),
                        post: Some(Box::new(StatementNode::Inc {
                            operand: ExprNode::Name(Span::new("i", 66, 3)),
                            location: 66..69
                        }))
                    }),
                    header_location: 47..69,
                    body: vec![StatementNode::Empty { location: 100..101 }],
                    location: 47..127
                }),
                StatementNode::For(ForNode {
                    header: ForHeaderNode::Clause(ForClauseNode {
                        init: None,
                        cond: Some(ExprNode::BinaryOp {
                            kind: BinaryOpKind::LessEq,
                            left: Box::new(ExprNode::Literal(LiteralNode::Int {
                                value: 1,
                                location: 159..160
                            })),
                            right: Box::new(ExprNode::Literal(LiteralNode::Int {
                                value: 2,
                                location: 164..165
                            })),
                            location: 159..165
                        }),
                        post: Some(Box::new(StatementNode::Expr {
                            expr: ExprNode::Literal(LiteralNode::Int {
                                value: 4,
                                location: 168..169
                            }),
                            annotation: None
                        }))
                    }),
                    header_location: 153..169,
                    body: vec![StatementNode::Empty { location: 200..201 }],
                    location: 153..227,
                }),
                StatementNode::For(ForNode {
                    header: ForHeaderNode::Clause(ForClauseNode {
                        init: None,
                        cond: Some(ExprNode::BinaryOp {
                            kind: BinaryOpKind::Greater,
                            left: Box::new(ExprNode::Literal(LiteralNode::Int {
                                value: 10,
                                location: 257..259
                            })),
                            right: Box::new(ExprNode::Literal(LiteralNode::Int {
                                value: 2,
                                location: 262..263
                            })),
                            location: 257..263
                        }),
                        post: None
                    }),
                    header_location: 253..263,
                    body: vec![StatementNode::Empty { location: 294..295 }],
                    location: 253..321,
                }),
                StatementNode::For(ForNode {
                    header: ForHeaderNode::Clause(ForClauseNode {
                        init: None,
                        cond: None,
                        post: None
                    }),
                    header_location: 347..350,
                    body: vec![],
                    location: 347..354,
                })
            ],
            parse(
                "
                    {
                        for i := 0; i < 5; i++ {
                            ;
                        }

                        for ; 1 <= 2 ; 4 {
                            ;
                        }

                        for 10 > 2 {
                            ;
                        }

                        for { }
                    }
        "
            )
            .unwrap()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn for_range() {
        assert_eq!(
            vec![
                StatementNode::For(ForNode {
                    header: ForHeaderNode::Range(ForRangeNode::Decl {
                        lhs: vec![Span::new("i", 51, 3), Span::new("item", 54, 3)],
                        range_expr: ExprNode::Name(Span::new("arr", 68, 3))
                    }),
                    header_location: 47..71,
                    body: vec![StatementNode::Empty { location: 102..103 }],
                    location: 47..129,
                }),
                StatementNode::For(ForNode {
                    header: ForHeaderNode::Range(ForRangeNode::Assignment {
                        lhs: vec![ExprNode::Name(Span::new("x", 159, 7))],
                        range_expr: ExprNode::Name(Span::new("arr", 169, 7))
                    }),
                    header_location: 155..172,
                    body: vec![StatementNode::Empty { location: 203..204 }],
                    location: 155..230,
                }),
                StatementNode::For(ForNode {
                    header: ForHeaderNode::Range(ForRangeNode::None {
                        range_expr: ExprNode::Name(Span::new("ch", 266, 11))
                    }),
                    header_location: 256..268,
                    body: vec![],
                    location: 256..271,
                })
            ],
            parse(
                "
                    {
                        for i, item := range arr {
                            ;
                        }

                        for x = range arr {
                            ;
                        }

                        for range ch {}
                    }
        "
            )
            .unwrap()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn for_continue_break() {
        assert_eq!(
            vec![StatementNode::Labeled {
                label: Span::new("Label", 47, 3),
                inner: Box::new(StatementNode::For(ForNode {
                    header: ForHeaderNode::Range(ForRangeNode::Decl {
                        lhs: vec![Span::new("i", 58, 3), Span::new("item", 61, 3)],
                        range_expr: ExprNode::Name(Span::new("arr", 75, 3))
                    }),
                    header_location: 54..78,
                    body: vec![StatementNode::If(IfNode {
                        stmt: None,
                        cond: ExprNode::BinaryOp {
                            kind: BinaryOpKind::Eq,
                            left: Box::new(ExprNode::BinaryOp {
                                kind: BinaryOpKind::Remainder,
                                left: Box::new(ExprNode::Name(Span::new("i", 112, 4))),
                                right: Box::new(ExprNode::Literal(LiteralNode::Int {
                                    value: 2,
                                    location: 116..117
                                })),
                                location: 112..117
                            }),
                            right: Box::new(ExprNode::Literal(LiteralNode::Int {
                                value: 0,
                                location: 121..122
                            })),
                            location: 112..122
                        },
                        then: vec![StatementNode::Continue {
                            label: None,
                            location: 157..165
                        }],
                        otherwise: Some(ElseNode::If(Box::new(IfNode {
                            stmt: None,
                            cond: ExprNode::BinaryOp {
                                kind: BinaryOpKind::Eq,
                                left: Box::new(ExprNode::BinaryOp {
                                    kind: BinaryOpKind::Remainder,
                                    left: Box::new(ExprNode::Name(Span::new("i", 204, 6))),
                                    right: Box::new(ExprNode::Literal(LiteralNode::Int {
                                        value: 3,
                                        location: 208..209
                                    })),
                                    location: 204..209
                                }),
                                right: Box::new(ExprNode::Literal(LiteralNode::Int {
                                    value: 0,
                                    location: 213..214
                                })),
                                location: 204..214
                            },
                            then: vec![StatementNode::Continue {
                                label: Some(Span::new("Label", 258, 7)),
                                location: 249..263
                            }],
                            otherwise: Some(ElseNode::If(Box::new(IfNode {
                                stmt: None,
                                cond: ExprNode::BinaryOp {
                                    kind: BinaryOpKind::Eq,
                                    left: Box::new(ExprNode::BinaryOp {
                                        kind: BinaryOpKind::Remainder,
                                        left: Box::new(ExprNode::Name(Span::new("i", 302, 8))),
                                        right: Box::new(ExprNode::Literal(LiteralNode::Int {
                                            value: 5,
                                            location: 306..307
                                        })),
                                        location: 302..307
                                    }),
                                    right: Box::new(ExprNode::Literal(LiteralNode::Int {
                                        value: 0,
                                        location: 311..312
                                    })),
                                    location: 302..312
                                },
                                then: vec![StatementNode::Break {
                                    label: Some(Span::new("Label", 353, 9)),
                                    location: 347..358
                                }],
                                otherwise: Some(ElseNode::Block(vec![StatementNode::Break {
                                    label: None,
                                    location: 428..433
                                }])),
                                location: 299..463,
                            }))),
                            location: 201..463,
                        }))),
                        location: 109..463,
                    })],
                    location: 54..489,
                }))
            }],
            parse(
                "
                    {
                        Label: for i, item := range arr {
                            if i % 2 == 0 {
                                continue
                            } else if i % 3 == 0 {
                                continue Label
                            } else if i % 5 == 0 {
                                break Label
                            } else {
                                break
                            }
                        }
                    }
        "
            )
            .unwrap()
        );
    }
}
