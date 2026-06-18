use super::{PResult, expect, exprs::parse_expression, of_kind};
use crate::{
    ParsingError, TokenStream,
    ast::{
        ChannelDirection, FieldDeclNode, InterfaceElementNode, InterfaceTypeTermNode,
        TypeNameNode, TypeNode, TypeParam,
    },
    parser::{BacktrackingContext, decls},
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

fn parse_type_name<'a>(s: &mut TokenStream<'a>) -> PResult<'a, TypeNameNode<'a>> {
    let token = expect(s, TokenKind::Ident, Some("type name"))?;

    let node = if let Some(Ok(of_kind!(TokenKind::Period))) = s.peek() {
        s.next(); // advance

        TypeNameNode {
            package: Some(token.span),
            id: expect(s, TokenKind::Ident, Some("type name"))?.span,
            args: parse_type_args(s)?,
        }
    } else {
        TypeNameNode {
            package: None,
            id: token.span,
            args: parse_type_args(s)?,
        }
    };

    Ok(node)
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
        Some(Box::new(parse_expression(s, true)?))
    };

    expect(s, TokenKind::SquareR, Some("array/slice type"))?;

    let element = Box::new(parse_type(s)?);

    if let Some(length) = length {
        Ok(TypeNode::Array { length, element })
    } else {
        Ok(TypeNode::Slice { element })
    }
}

fn parse_map_type<'a>(s: &mut TokenStream<'a>) -> PResult<'a, TypeNode<'a>> {
    expect(s, TokenKind::Map, Some("map type"))?;

    expect(s, TokenKind::SquareL, Some("map type"))?;

    let key = Box::new(parse_type(s)?);

    expect(s, TokenKind::SquareR, Some("map type"))?;

    let element = Box::new(parse_type(s)?);

    Ok(TypeNode::Map { key, element })
}

fn parse_struct_type_field<'a>(s: &mut TokenStream<'a>) -> PResult<'a, FieldDeclNode<'a>> {
    let mut ids = vec![];

    loop {
        let ident = expect(s, TokenKind::Ident, Some("struct type field"))?;

        if ident.span.content() == "_" {
            ids.push(None);
        } else {
            ids.push(Some(ident.span));
        }

        if let Some(Ok(of_kind!(TokenKind::Comma))) = s.peek() {
            s.next(); // advance
        } else {
            break; // since there's no comma, next must be type
        }
    }

    let r#type = parse_type(s)?;

    let tag = if let Some(Ok(of_kind!(TokenKind::String(tag)))) = s.peek() {
        let tag = tag.clone(); // clone before mutating s (tag is a ref)
        s.next(); // advance

        Some(tag)
    } else {
        None
    };

    Ok(FieldDeclNode { ids, r#type, tag })
}

fn parse_struct_type<'a>(s: &mut TokenStream<'a>) -> PResult<'a, TypeNode<'a>> {
    expect(s, TokenKind::Struct, Some("struct type"))?;

    expect(s, TokenKind::CurlyL, Some("struct type"))?;

    let mut fields = vec![];

    while !matches!(
        s.peek().cloned().transpose()?,
        None | Some(of_kind!(TokenKind::CurlyR))
    ) {
        fields.push(parse_struct_type_field(s)?);

        // spec: "To allow complex statements to occupy a single line, a
        // semicolon may be omitted before a closing (...) `}`"
        if let Some(Ok(of_kind!(TokenKind::CurlyR))) = s.peek() {
            // don't require semicolon even though while cond would then trigger
            break;
        }

        expect(s, TokenKind::SemiColon, Some("struct type fields list"))?;
    }

    expect(s, TokenKind::CurlyR, Some("struct type"))?;

    Ok(TypeNode::Struct { fields })
}

fn parse_interface_method_element<'a>(
    s: &mut TokenStream<'a>,
) -> PResult<'a, InterfaceElementNode<'a>> {
    let name = expect(s, TokenKind::Ident, Some("interface method element"))?.span;

    let signature = decls::funcs::parse_signature(s)?;

    Ok(InterfaceElementNode::Method { name, signature })
}

fn parse_interface_type_union_element<'a>(
    s: &mut TokenStream<'a>,
) -> PResult<'a, InterfaceElementNode<'a>> {
    let mut terms = vec![];

    loop {
        let builder = if let Some(Ok(of_kind!(TokenKind::Tilde))) = s.peek() {
            s.next(); // advance

            InterfaceTypeTermNode::Underlying
        } else {
            InterfaceTypeTermNode::Simple
        };

        let r#type = parse_type(s)?;

        terms.push(builder(r#type));

        if let Some(Ok(of_kind!(TokenKind::Pipe))) = s.peek() {
            s.next(); // advance
        } else {
            break;
        }
    }

    Ok(InterfaceElementNode::TypeUnion(terms))
}

fn parse_interface_type<'a>(s: &mut TokenStream<'a>) -> PResult<'a, TypeNode<'a>> {
    expect(s, TokenKind::Interface, Some("interface type"))?;

    expect(s, TokenKind::CurlyL, Some("interface type"))?;

    let mut elements = vec![];

    while !matches!(s.peek(), Some(Ok(of_kind!(TokenKind::CurlyR)))) {
        let mut context = BacktrackingContext::new(s);
        let b = context.stream();

        match parse_interface_method_element(b) {
            Ok(method) => {
                context.commit()?;
                elements.push(method);
            }
            Err(_) => elements.push(parse_interface_type_union_element(s)?),
        }

        if let Some(Ok(of_kind!(TokenKind::CurlyR))) = s.peek() {
            break;
        }

        expect(s, TokenKind::SemiColon, Some("interface type"))?;
    }

    expect(s, TokenKind::CurlyR, Some("interface type"))?;

    Ok(TypeNode::Interface { elements })
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
        Some(of_kind!(TokenKind::Star)) => {
            s.next(); // advance
            let base = Box::new(parse_type(s)?);

            Ok(TypeNode::Pointer { base })
        }
        Some(of_kind!(TokenKind::Func)) => parse_function_type(s),
        Some(of_kind!(TokenKind::SquareL)) => parse_array_or_slice_type(s),
        Some(of_kind!(TokenKind::Map)) => parse_map_type(s),
        Some(of_kind!(TokenKind::Struct)) => parse_struct_type(s),
        Some(of_kind!(TokenKind::Interface)) => parse_interface_type(s),
        Some(of_kind!(TokenKind::Chan | TokenKind::LtMinus)) => parse_channel_type(s),
        Some(of_kind!(TokenKind::Ident)) => parse_type_name(s).map(Into::into),
        found => Err(ParsingError::UnexpectedConstruct {
            expected: "a type",
            found,
        }),
    }
}

pub fn parse_type_params<'a>(s: &mut TokenStream<'a>) -> PResult<'a, Vec<TypeParam<'a>>> {
    expect(s, TokenKind::SquareL, Some("type parameters"))?;

    let mut params = vec![];

    loop {
        params.push(parse_type_param(s)?);

        if let Some(Ok(of_kind!(TokenKind::Comma))) = s.peek() {
            s.next(); // advance

            // check if this was an optional trailing comma before ]
            if let Some(Ok(of_kind!(TokenKind::SquareR))) = s.peek() {
                s.next(); // advance

                break;
            }
        } else {
            expect(s, TokenKind::SquareR, Some("type parameters"))?;

            break;
        }
    }

    Ok(params)
}

fn parse_type_param<'a>(s: &mut TokenStream<'a>) -> PResult<'a, TypeParam<'a>> {
    let mut ids = vec![];

    loop {
        let id = expect(s, TokenKind::Ident, Some("type parameter identifier"))?;

        ids.push(id.span);

        if !matches!(s.peek(), Some(Ok(of_kind!(TokenKind::Comma)))) {
            break;
        }

        s.next(); // advance comma
    }

    let InterfaceElementNode::TypeUnion(constraint) = parse_interface_type_union_element(s)? else {
        unreachable!()
    };

    Ok(TypeParam { ids, constraint })
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
            FunctionSignatureNode, LiteralNode,
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
                        r#type: Box::new(TypeNode::Name(TypeNameNode {
                            package: Some(Span::new("pkg", 21, 1)),
                            id: Span::new("member", 25, 1),
                            args: vec![
                                TypeNode::Channel {
                                    r#type: Box::new(TypeNode::Name(TypeNameNode {
                                        package: None,
                                        id: Span::new("T", 37, 1),
                                        args: vec![]
                                    })),
                                    direction: None
                                },
                                TypeNode::Name(TypeNameNode {
                                    package: None,
                                    id: Span::new("K", 40, 1),
                                    args: vec![]
                                })
                            ]
                        })),
                        direction: Some(ChannelDirection::Send)
                    }),
                    direction: Some(ChannelDirection::Receive)
                }),
                direction: None
            },
            parse("chan (<-chan (chan<- pkg.member[chan T, K]))").unwrap()
        );
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
                                right: Box::new(ExprNode::Name(Span::new("N", 11, 1))),
                                location: 7..12
                            }),
                            right: Box::new(ExprNode::Literal(LiteralNode::Int {
                                value: 1,
                                location: 15..16
                            })),
                            location: 7..16
                        }),
                        element: Box::new(TypeNode::Name(TypeNameNode {
                            package: Some(Span::new("pkg", 17, 1)),
                            id: Span::new("member", 21, 1),
                            args: vec![TypeNode::Name(TypeNameNode {
                                package: None,
                                id: Span::new("T", 28, 1),
                                args: vec![]
                            })]
                        }))
                    })
                })
            },
            parse("[3][4][2 * N + 1]pkg.member[T]").unwrap()
        );
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
                            r#type: TypeNode::Name(TypeNameNode {
                                package: None,
                                id: Span::new("int", 7, 1),
                                args: vec![]
                            })
                        },
                        FunctionParamDeclNode {
                            ids: vec![Span::new("f", 12, 1), Span::new("g", 15, 1)],
                            variadic: false,
                            r#type: TypeNode::Function {
                                signature: Box::new(FunctionSignatureNode {
                                    params: vec![],
                                    result: FunctionResultNode::Params(vec![
                                        FunctionParamDeclNode {
                                            ids: vec![Span::new("x", 25, 1)],
                                            variadic: false,
                                            r#type: TypeNode::Name(TypeNameNode {
                                                package: None,
                                                id: Span::new("int", 27, 1),
                                                args: vec![]
                                            })
                                        },
                                        FunctionParamDeclNode {
                                            ids: vec![Span::new("y", 32, 1)],
                                            variadic: false,
                                            r#type: TypeNode::Name(TypeNameNode {
                                                package: Some(Span::new("p", 34, 1)),
                                                id: Span::new("A", 36, 1),
                                                args: vec![TypeNode::Name(TypeNameNode {
                                                    package: None,
                                                    id: Span::new("T", 38, 1),
                                                    args: vec![]
                                                })]
                                            })
                                        },
                                    ])
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
                                        r#type: TypeNode::Name(TypeNameNode {
                                            package: None,
                                            id: Span::new("float32", 53, 1),
                                            args: vec![]
                                        })
                                    }],
                                    result: FunctionResultNode::Single(TypeNode::Name(
                                        TypeNameNode {
                                            package: None,
                                            id: Span::new("bool", 62, 1),
                                            args: vec![]
                                        }
                                    ))
                                })
                            }
                        }
                    ],
                    result: FunctionResultNode::Single(TypeNode::Function {
                        signature: Box::new(FunctionSignatureNode {
                            params: vec![FunctionParamDeclNode {
                                ids: vec![Span::new("result", 73, 1)],
                                variadic: false,
                                r#type: TypeNode::Name(TypeNameNode {
                                    package: None,
                                    id: Span::new("int", 80, 1),
                                    args: vec![]
                                })
                            }],
                            result: FunctionResultNode::None,
                        })
                    })
                })
            },
            parse(
                "func(a int, f, g func() (x int, y p.A[T]), ...func(x float32) bool) func(result \
                 int)"
            )
            .unwrap()
        );
    }
}
