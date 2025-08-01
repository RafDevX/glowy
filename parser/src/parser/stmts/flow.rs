use crate::{
    ast::{ElseNode, ForClauseNode, ForHeaderNode, ForNode, ForRangeNode, IfNode, StatementNode},
    parser::{
        expect,
        exprs::{parse_expression, parse_expressions_list_while},
        of_kind,
        stmts::{parse_block, parse_statement, terminal_token},
        PResult,
    },
    token::{Token, TokenKind},
    ParsingError, TokenStream,
};

pub fn parse_if_statement<'a>(s: &mut TokenStream<'a>) -> PResult<'a, IfNode<'a>> {
    let beginning = expect(s, TokenKind::If, Some("if statement"))?;

    let mut stmt = None;

    // no point in using BacktrackingContext if we'll never commit
    for future in s.clone() {
        match future?.kind {
            TokenKind::CurlyL => break, // reached block & no semi was found
            TokenKind::SemiColon => {
                // ok, there's a simple statement we need to parse before
                // the actual condition (note we use the actual stream again
                // now, the clone was just to look for a semicolon)

                stmt = Some(Box::new(parse_statement(s, false)?));

                expect(s, TokenKind::SemiColon, Some("if statement"))?;

                break;
            }
            _ => {}
        }
    }

    let cond = parse_expression(s)?;
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
                Some(parse_expression(s)?)
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

            let range_expr = parse_expression(s)?;

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
                    let cond = parse_expression(s)?;

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
                        Some(parse_expression(s)?)
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
                                expect_comma = false
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

                    let range_expr = parse_expression(s)?;

                    ForHeaderNode::Range(ForRangeNode::Decl { lhs, range_expr })
                }
                ForKind::RangeAssignment => {
                    let lhs =
                        parse_expressions_list_while(s, |token| token.kind != TokenKind::Assign)?
                            .unwrap_or_else(Vec::new); // got end-of-file but that's equivalent to empty expressions list

                    if lhs.is_empty() {
                        return Err(ParsingError::UnexpectedConstruct {
                            expected: "a list of expressions",
                            found: s.next().transpose()?,
                        });
                    }

                    expect(s, TokenKind::Assign, Some("for range clause"))?;
                    expect(s, TokenKind::Range, Some("for range clause"))?;

                    let range_expr = parse_expression(s)?;

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

pub fn parse_continue_statement<'a>(s: &mut TokenStream<'a>) -> PResult<'a, StatementNode<'a>> {
    let beginning = expect(s, TokenKind::Continue, Some("continue statement"))?;

    let label = if s
        .peek()
        .cloned()
        .transpose()?
        .map(|t| terminal_token(&t.kind))
        .unwrap_or(true)
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
        .map(|t| terminal_token(&t.kind))
        .unwrap_or(true)
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
    let token = expect(s, TokenKind::Return, Some("return statement"))?;

    let exprs = parse_expressions_list_while(s, |token| !terminal_token(&token.kind))?
        .unwrap_or_else(Vec::new); // a potentially better error will be thrown higher up the chain

    Ok(StatementNode::Return {
        exprs,
        location: s.location_since(&token),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ast::{
            AssignmentKind, AssignmentNode, BinaryOpKind, BlockNode, CallNode, ExprNode,
            LiteralNode, OperandNameNode, ShortVarDeclNode, StatementNode, UnaryOpKind,
        },
        lexer::Lexer,
        parser::stmts::parse_block,
        Span,
    };

    fn parse(input: &str) -> PResult<'_, BlockNode<'_>> {
        let mut stream = TokenStream::new(Lexer::new(input));

        parse_block(&mut stream)
    }

    #[test]
    fn if_chain() {
        assert_eq!(
            vec![StatementNode::If(IfNode {
                stmt: None,
                cond: ExprNode::BinaryOp {
                    kind: BinaryOpKind::Greater,
                    left: Box::new(ExprNode::BinaryOp {
                        kind: BinaryOpKind::Sum,
                        left: Box::new(ExprNode::Name(OperandNameNode {
                            package: None,
                            id: Span::new("a", 50, 3)
                        })),
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
                        lhs: vec![ExprNode::Name(OperandNameNode {
                            package: None,
                            id: Span::new("a", 120, 5)
                        })],
                        rhs: vec![ExprNode::Literal(LiteralNode::Int {
                            value: 4,
                            location: 124..125
                        })],
                        location: 120..125,
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
                            operand: ExprNode::Name(OperandNameNode {
                                package: None,
                                id: Span::new("m", 298, 10),
                            }),
                            location: 298..301,
                        },
                        StatementNode::Assignment(AssignmentNode {
                            kind: AssignmentKind::BitClear,
                            lhs: vec![
                                ExprNode::Name(OperandNameNode {
                                    package: None,
                                    id: Span::new("k", 331, 11)
                                }),
                                ExprNode::Name(OperandNameNode {
                                    package: Some(Span::new("m", 334, 11)),
                                    id: Span::new("r", 336, 11)
                                })
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
        )
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
                    left: Box::new(ExprNode::Name(OperandNameNode {
                        package: None,
                        id: Span::new("x", 58, 3)
                    })),
                    right: Box::new(ExprNode::Literal(LiteralNode::Int {
                        value: 3,
                        location: 62..63
                    })),
                    location: 58..63
                },
                then: vec![StatementNode::Empty { location: 94..95 }],
                otherwise: Some(ElseNode::If(Box::new(IfNode {
                    stmt: None,
                    cond: ExprNode::Name(OperandNameNode {
                        package: None,
                        id: Span::new("false", 130, 5)
                    }),
                    then: vec![StatementNode::Empty { location: 166..167 }],
                    otherwise: Some(ElseNode::If(Box::new(IfNode {
                        stmt: Some(Box::new(StatementNode::Expr(ExprNode::Call(CallNode {
                            func: Box::new(ExprNode::Name(OperandNameNode {
                                package: None,
                                id: Span::new("y", 202, 7)
                            })),
                            type_arg: None,
                            args: vec![],
                            variadic: false,
                            location: 203..205,
                            annotation: None
                        })))),
                        cond: ExprNode::Name(OperandNameNode {
                            package: None,
                            id: Span::new("true", 207, 7)
                        }),
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
        )
    }

    #[test]
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
                            left: Box::new(ExprNode::Name(OperandNameNode {
                                package: None,
                                id: Span::new("i", 59, 3)
                            })),
                            right: Box::new(ExprNode::Literal(LiteralNode::Int {
                                value: 5,
                                location: 63..64
                            })),
                            location: 59..64
                        }),
                        post: Some(Box::new(StatementNode::Inc {
                            operand: ExprNode::Name(OperandNameNode {
                                package: None,
                                id: Span::new("i", 66, 3)
                            }),
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
                        post: Some(Box::new(StatementNode::Expr(ExprNode::Literal(
                            LiteralNode::Int {
                                value: 4,
                                location: 168..169
                            }
                        ))))
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
        )
    }

    #[test]
    fn for_range() {
        assert_eq!(
            vec![
                StatementNode::For(ForNode {
                    header: ForHeaderNode::Range(ForRangeNode::Decl {
                        lhs: vec![Span::new("i", 51, 3), Span::new("item", 54, 3)],
                        range_expr: ExprNode::Name(OperandNameNode {
                            package: None,
                            id: Span::new("arr", 68, 3)
                        })
                    }),
                    header_location: 47..71,
                    body: vec![StatementNode::Empty { location: 102..103 }],
                    location: 47..129,
                }),
                StatementNode::For(ForNode {
                    header: ForHeaderNode::Range(ForRangeNode::Assignment {
                        lhs: vec![ExprNode::Name(OperandNameNode {
                            package: None,
                            id: Span::new("x", 159, 7)
                        })],
                        range_expr: ExprNode::Name(OperandNameNode {
                            package: None,
                            id: Span::new("arr", 169, 7)
                        })
                    }),
                    header_location: 155..172,
                    body: vec![StatementNode::Empty { location: 203..204 }],
                    location: 155..230,
                }),
                StatementNode::For(ForNode {
                    header: ForHeaderNode::Range(ForRangeNode::None {
                        range_expr: ExprNode::Name(OperandNameNode {
                            package: None,
                            id: Span::new("ch", 266, 11)
                        })
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
        )
    }

    #[test]
    fn for_continue_break() {
        assert_eq!(
            vec![StatementNode::Labeled {
                label: Span::new("Label", 47, 3),
                inner: Box::new(StatementNode::For(ForNode {
                    header: ForHeaderNode::Range(ForRangeNode::Decl {
                        lhs: vec![Span::new("i", 58, 3), Span::new("item", 61, 3)],
                        range_expr: ExprNode::Name(OperandNameNode {
                            package: None,
                            id: Span::new("arr", 75, 3)
                        })
                    }),
                    header_location: 54..78,
                    body: vec![StatementNode::If(IfNode {
                        stmt: None,
                        cond: ExprNode::BinaryOp {
                            kind: BinaryOpKind::Eq,
                            left: Box::new(ExprNode::BinaryOp {
                                kind: BinaryOpKind::Remainder,
                                left: Box::new(ExprNode::Name(OperandNameNode {
                                    package: None,
                                    id: Span::new("i", 112, 4)
                                })),
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
                                    left: Box::new(ExprNode::Name(OperandNameNode {
                                        package: None,
                                        id: Span::new("i", 204, 6)
                                    })),
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
                                        left: Box::new(ExprNode::Name(OperandNameNode {
                                            package: None,
                                            id: Span::new("i", 302, 8)
                                        })),
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
        )
    }
}
