use super::{PResult, expect, exprs::parse_expression, of_kind};
use crate::{
    ParsingError, TokenStream,
    ast::{ChannelDirection, TypeNode},
    parser::decls,
    token::{Token, TokenKind},
};

fn parse_type_args<'a>(s: &mut TokenStream<'a>) -> PResult<'a, Vec<TypeNode<'a>>> {
    let mut args = vec![];

    if !matches!(s.peek(), Some(Ok(of_kind!(TokenKind::SquareL)))) {
        return Ok(args);
    }

    s.next(); // advance

    loop {
        if !args.is_empty() {
            expect(s, TokenKind::Comma, Some("list of type arguments"))?;

            // if what we just read was actually an optional trailing comma
            // and now the list is over, abort reading a new type
            if let Some(Ok(of_kind!(TokenKind::SquareR))) = s.peek() {
                s.next(); // advance
                break;
            }
        }

        args.push(parse_type(s)?);

        if !matches!(s.peek(), Some(Ok(of_kind!(TokenKind::Comma)))) {
            break;
        }
    }

    expect(s, TokenKind::SquareR, Some("type arguments"))?;

    Ok(args)
}

fn parse_type_name<'a>(s: &mut TokenStream<'a>) -> PResult<'a, TypeNode<'a>> {
    let token = expect(s, TokenKind::Ident, Some("type name"))?;

    if let Some(Ok(of_kind!(TokenKind::Period))) = s.peek() {
        s.next(); // advance

        Ok(TypeNode::Name {
            package: Some(token.span),
            id: expect(s, TokenKind::Ident, Some("type name"))?.span,
            args: parse_type_args(s)?,
        })
    } else {
        Ok(TypeNode::Name {
            package: None,
            id: token.span,
            args: parse_type_args(s)?,
        })
    }
}

pub fn parse_channel_type<'a>(s: &mut TokenStream<'a>) -> PResult<'a, TypeNode<'a>> {
    let receive = if let Some(Ok(of_kind!(TokenKind::LtMinus))) = s.peek() {
        s.next(); // advance

        true
    } else {
        false
    };

    expect(s, TokenKind::Chan, Some("channel type"))?;

    let direction = if receive {
        Some(ChannelDirection::Receive)
    } else if let Some(Ok(of_kind!(TokenKind::LtMinus))) = s.peek() {
        s.next(); // advance

        Some(ChannelDirection::Send)
    } else {
        None
    };

    let r#type = Box::new(parse_type(s)?);

    Ok(TypeNode::Channel { r#type, direction })
}

fn parse_array_or_slice_type<'a>(s: &mut TokenStream<'a>) -> PResult<'a, TypeNode<'a>> {
    expect(s, TokenKind::SquareL, Some("arrays/slice type"))?;

    let length = if let Some(Ok(of_kind!(TokenKind::SquareR))) = s.peek() {
        // slice
        None
    } else {
        Some(Box::new(parse_expression(s)?))
    };

    expect(s, TokenKind::SquareR, Some("array/slice type"))?;

    let element = Box::new(parse_type(s)?);

    if let Some(length) = length {
        Ok(TypeNode::Array { length, element })
    } else {
        Ok(TypeNode::Slice { element })
    }
}

fn parse_function_type<'a>(s: &mut TokenStream<'a>) -> PResult<'a, TypeNode<'a>> {
    expect(s, TokenKind::Func, Some("function type"))?;

    let signature = Box::new(decls::funcs::parse_signature(s)?);

    Ok(TypeNode::Function { signature })
}

pub fn parse_type<'a>(s: &mut TokenStream<'a>) -> PResult<'a, TypeNode<'a>> {
    match s.peek().cloned().transpose()? {
        Some(of_kind!(TokenKind::ParenL)) => {
            s.next(); // advance
            let inner = parse_type(s)?;
            expect(s, TokenKind::ParenR, Some("parenthesized type"))?;
            Ok(inner)
        }
        Some(of_kind!(TokenKind::Func)) => parse_function_type(s),
        Some(of_kind!(TokenKind::SquareL)) => parse_array_or_slice_type(s),
        Some(of_kind!(TokenKind::Chan | TokenKind::LtMinus)) => parse_channel_type(s),
        Some(of_kind!(TokenKind::Ident)) => parse_type_name(s),
        found => Err(ParsingError::UnexpectedConstruct {
            expected: "a type",
            found,
        }),
    }
}

pub fn parse_types_until<'a>(
    s: &mut TokenStream<'a>,
    stop: impl Fn(&Token) -> bool,
) -> PResult<'a, Vec<TypeNode<'a>>> {
    let mut types = vec![];

    let mut first = true;
    while !s.peek().cloned().transpose()?.as_ref().is_none_or(&stop) {
        if first {
            first = false;
        } else {
            expect(s, TokenKind::Comma, Some("types list"))?;
        }

        types.push(parse_type(s)?);
    }

    Ok(types)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Span,
        ast::{
            BinaryOpKind, ExprNode, FunctionParamDeclNode, FunctionResultNode,
            FunctionSignatureNode, LiteralNode, OperandNameNode,
        },
        lexer::Lexer,
    };

    fn parse(input: &str) -> PResult<'_, TypeNode<'_>> {
        let mut stream = TokenStream::new(Lexer::new(input));

        parse_type(&mut stream)
    }

    #[test]
    fn channels() {
        assert_eq!(
            TypeNode::Channel {
                r#type: Box::new(TypeNode::Channel {
                    r#type: Box::new(TypeNode::Channel {
                        r#type: Box::new(TypeNode::Name {
                            package: Some(Span::new("pkg", 21, 1)),
                            id: Span::new("member", 25, 1),
                            args: vec![
                                TypeNode::Channel {
                                    r#type: Box::new(TypeNode::Name {
                                        package: None,
                                        id: Span::new("T", 37, 1),
                                        args: vec![]
                                    }),
                                    direction: None
                                },
                                TypeNode::Name {
                                    package: None,
                                    id: Span::new("K", 40, 1),
                                    args: vec![]
                                }
                            ]
                        }),
                        direction: Some(ChannelDirection::Send)
                    }),
                    direction: Some(ChannelDirection::Receive)
                }),
                direction: None
            },
            parse("chan (<-chan (chan<- pkg.member[chan T, K]))").unwrap()
        )
    }

    #[test]
    fn arrays() {
        assert_eq!(
            TypeNode::Array {
                length: Box::new(ExprNode::Literal(LiteralNode::Int {
                    value: 3,
                    location: 1..2
                })),
                element: Box::new(TypeNode::Array {
                    length: Box::new(ExprNode::Literal(LiteralNode::Int {
                        value: 4,
                        location: 4..5
                    })),
                    element: Box::new(TypeNode::Array {
                        length: Box::new(ExprNode::BinaryOp {
                            kind: BinaryOpKind::Sum,
                            left: Box::new(ExprNode::BinaryOp {
                                kind: BinaryOpKind::Product,
                                left: Box::new(ExprNode::Literal(LiteralNode::Int {
                                    value: 2,
                                    location: 7..8
                                })),
                                right: Box::new(ExprNode::Name(OperandNameNode {
                                    package: None,
                                    id: Span::new("N", 11, 1)
                                })),
                                location: 7..12
                            }),
                            right: Box::new(ExprNode::Literal(LiteralNode::Int {
                                value: 1,
                                location: 15..16
                            })),
                            location: 7..16
                        }),
                        element: Box::new(TypeNode::Name {
                            package: Some(Span::new("pkg", 17, 1)),
                            id: Span::new("member", 21, 1),
                            args: vec![TypeNode::Name {
                                package: None,
                                id: Span::new("T", 28, 1),
                                args: vec![]
                            }]
                        })
                    })
                })
            },
            parse("[3][4][2 * N + 1]pkg.member[T]").unwrap()
        )
    }

    #[test]
    fn functions() {
        assert_eq!(
            TypeNode::Function {
                signature: Box::new(FunctionSignatureNode {
                    params: vec![
                        FunctionParamDeclNode {
                            ids: vec![Span::new("a", 5, 1)],
                            variadic: false,
                            r#type: TypeNode::Name {
                                package: None,
                                id: Span::new("int", 7, 1),
                                args: vec![]
                            }
                        },
                        FunctionParamDeclNode {
                            ids: vec![Span::new("f", 12, 1), Span::new("g", 15, 1)],
                            variadic: false,
                            r#type: TypeNode::Function {
                                signature: Box::new(FunctionSignatureNode {
                                    params: vec![],
                                    result: Some(FunctionResultNode::Params(vec![
                                        FunctionParamDeclNode {
                                            ids: vec![Span::new("x", 25, 1)],
                                            variadic: false,
                                            r#type: TypeNode::Name {
                                                package: None,
                                                id: Span::new("int", 27, 1),
                                                args: vec![]
                                            }
                                        },
                                        FunctionParamDeclNode {
                                            ids: vec![Span::new("y", 32, 1)],
                                            variadic: false,
                                            r#type: TypeNode::Name {
                                                package: Some(Span::new("p", 34, 1)),
                                                id: Span::new("A", 36, 1),
                                                args: vec![TypeNode::Name {
                                                    package: None,
                                                    id: Span::new("T", 38, 1),
                                                    args: vec![]
                                                }]
                                            }
                                        },
                                    ]))
                                })
                            }
                        },
                        FunctionParamDeclNode {
                            ids: vec![],
                            variadic: true,
                            r#type: TypeNode::Function {
                                signature: Box::new(FunctionSignatureNode {
                                    params: vec![FunctionParamDeclNode {
                                        ids: vec![Span::new("x", 51, 1)],
                                        variadic: false,
                                        r#type: TypeNode::Name {
                                            package: None,
                                            id: Span::new("float32", 53, 1),
                                            args: vec![]
                                        }
                                    }],
                                    result: Some(FunctionResultNode::Single(TypeNode::Name {
                                        package: None,
                                        id: Span::new("bool", 62, 1),
                                        args: vec![]
                                    }))
                                })
                            }
                        }
                    ],
                    result: Some(FunctionResultNode::Single(TypeNode::Function {
                        signature: Box::new(FunctionSignatureNode {
                            params: vec![FunctionParamDeclNode {
                                ids: vec![Span::new("result", 73, 1)],
                                variadic: false,
                                r#type: TypeNode::Name {
                                    package: None,
                                    id: Span::new("int", 80, 1),
                                    args: vec![]
                                }
                            }],
                            result: None,
                        })
                    }))
                })
            },
            parse("func(a int, f, g func() (x int, y p.A[T]), ...func(x float32) bool) func(result int)")
                .unwrap()
        )
    }
}
