use super::{parse_expression, parse_expressions_list_while};
use crate::{
    ParsingError, TokenStream,
    ast::{
        AmbiguousBracketAccessNode, CallNode, ExprNode, IndexingNode, MakeNode, NewArgNode,
        NewNode, SelectionNode, SlicingNode, TypeAssertionNode, TypeInstantiationNode, TypeNode,
    },
    parser::{BacktrackingContext, PResult, expect, of_kind, types::parse_type},
    token::TokenKind,
};

fn parse_call<'a>(s: &mut TokenStream<'a>, func: ExprNode<'a>) -> PResult<'a, ExprNode<'a>> {
    if let ExprNode::Name(id) = &func {
        // make(T, ...) and new(T) are treated specially, not as a function call
        match id.content() {
            "make" => return Ok(parse_make(s, id.location().start)?.into()),
            "new" => {
                let start = id.location().start;

                return parse_new(s, func, start);
            }
            _ => {}
        }
    }

    parse_regular_call(s, func)
}

fn parse_regular_call<'a>(
    s: &mut TokenStream<'a>,
    func: ExprNode<'a>,
) -> PResult<'a, ExprNode<'a>> {
    expect(s, TokenKind::ParenL, Some("function call"))?;
    let annotation = s.take_last_annotation();

    // note that this will already allow for a trailing comma, BUT that also
    // means that it'll allow e.g. `f(1, arr, ...)`, which is wrong but not so
    // big of a problem (parses the same as `f(1, arr...)`)
    let args = parse_expressions_list_while(
        s,
        |token| !matches!(token.kind, TokenKind::Ellipsis | TokenKind::ParenR),
        true,
    )?
    .unwrap_or_else(Vec::new); // got end-of-file, but it's fine because the upcoming expect will fail

    let variadic = if let Some(Ok(of_kind!(TokenKind::Ellipsis))) = s.peek() {
        s.next(); // advance

        // an optional trailing comma is allowed after the ellipsis
        if let Some(Ok(of_kind!(TokenKind::Comma))) = s.peek() {
            s.next(); // advance
        }

        true
    } else {
        false
    };

    expect(s, TokenKind::ParenR, Some("function call"))?;

    let location = s.location_starting_at(func.location().start);

    let call = CallNode {
        func: Box::new(func),
        args,
        variadic,
        location,
        annotation,
    };

    Ok(call.into())
}

fn parse_make<'a>(s: &mut TokenStream<'a>, start: usize) -> PResult<'a, MakeNode<'a>> {
    expect(s, TokenKind::ParenL, Some("make call"))?;

    macro_rules! parse_opt_param {
        () => {
            if let Some(Ok(of_kind!(TokenKind::ParenR))) = s.peek() {
                None
            } else {
                expect(s, TokenKind::Comma, Some("make call parameter list"))?;

                if let Some(Ok(of_kind!(TokenKind::ParenR))) = s.peek() {
                    // was just a trailing comma
                    None
                } else {
                    Some(Box::new(parse_expression(s, true)?))
                }
            }
        };
    }

    let r#type = parse_type(s)?;
    let n = parse_opt_param!();
    let m = parse_opt_param!();

    if let Some(Ok(of_kind!(TokenKind::Comma))) = s.peek() {
        s.next(); // advance trailing comma
    }

    expect(s, TokenKind::ParenR, Some("make call"))?;

    let location = s.location_starting_at(start);

    Ok(MakeNode {
        r#type,
        n,
        m,
        location,
    })
}

fn parse_new<'a>(
    s: &mut TokenStream<'a>,
    func: ExprNode<'a>,
    start: usize,
) -> PResult<'a, ExprNode<'a>> {
    let mut context = BacktrackingContext::new(s);
    let b = context.stream();

    let new = parse_builtin_new(b, start);

    if let Ok(new) = new {
        context.commit()?;

        Ok(new.into())
    } else {
        // a call with zero or multiple arguments cannot be the predeclared
        // new(T), but is valid when the identifier `new` is shadowed
        parse_regular_call(s, func)
    }
}

fn parse_builtin_new<'a>(s: &mut TokenStream<'a>, start: usize) -> PResult<'a, NewNode<'a>> {
    expect(s, TokenKind::ParenL, Some("new call"))?;

    let mut type_probe = s.clone();

    let mut context = BacktrackingContext::new(s);
    let b = context.stream();

    let expr = parse_expression(b, true).ok().filter(|_| {
        if matches!(b.peek(), Some(Ok(of_kind!(TokenKind::Comma)))) {
            b.next();
        }

        matches!(b.peek(), Some(Ok(of_kind!(TokenKind::ParenR))))
    });

    let arg = if let Some(expr) = expr {
        context.commit()?;

        let closing = expect(s, TokenKind::ParenR, Some("new call"))?;

        let r#type = parse_type(&mut type_probe).ok().filter(|_| {
            if matches!(type_probe.peek(), Some(Ok(of_kind!(TokenKind::Comma)))) {
                type_probe.next();
            }

            type_probe.peek() == Some(&Ok(closing.clone()))
        });

        match r#type {
            Some(r#type) => NewArgNode::Ambiguous {
                if_type: r#type,
                if_expr: Box::new(expr),
            },
            None => NewArgNode::Expr(Box::new(expr)),
        }
    } else {
        let r#type = parse_type(s)?;

        expect(s, TokenKind::ParenR, Some("new call"))?;

        NewArgNode::Type(r#type)
    };

    let location = s.location_starting_at(start);

    Ok(NewNode { arg, location })
}

fn parse_selection<'a>(
    s: &mut TokenStream<'a>,
    base: ExprNode<'a>,
) -> PResult<'a, SelectionNode<'a>> {
    expect(s, TokenKind::Period, Some("selection expression"))?;

    let selector = expect(s, TokenKind::Ident, Some("selector"))?.span;

    let location = s.location_starting_at(base.location().start);

    Ok(SelectionNode {
        base: Box::new(base),
        selector,
        location,
    })
}

fn parse_slicing<'a>(
    s: &mut TokenStream<'a>,
    base: ExprNode<'a>,
    low: Option<ExprNode<'a>>,
) -> PResult<'a, SlicingNode<'a>> {
    expect(s, TokenKind::Colon, Some("slicing expression"))?;

    let (high, max) = if let Some(Ok(of_kind!(TokenKind::SquareR))) = s.peek() {
        // slicing of the form a[low:] (or a[:] is low is None)
        (None, None)
    } else {
        let high = parse_expression(s, true)?;

        if let Some(Ok(of_kind!(TokenKind::SquareR))) = s.peek() {
            // a[low:high] or a[:high]
            (Some(high), None)
        } else {
            // a[low:high:max] or a[:high:max]
            expect(s, TokenKind::Colon, Some("full slicing expression"))?;

            let max = parse_expression(s, true)?;

            (Some(high), Some(max))
        }
    };

    expect(s, TokenKind::SquareR, Some("slicing expression"))?;

    let location = s.location_starting_at(base.location().start);

    Ok(SlicingNode {
        base: Box::new(base),
        low: low.map(Box::new),
        high: high.map(Box::new),
        max: max.map(Box::new),
        location,
    })
}

// indexing, slicing, or type instantiation (or ambiguous bracket access)
fn parse_bracket_expr<'a>(
    s: &mut TokenStream<'a>,
    base: ExprNode<'a>,
) -> PResult<'a, ExprNode<'a>> {
    expect(s, TokenKind::SquareL, Some("bracket expression"))?;

    if let Some(Ok(of_kind!(TokenKind::Colon))) = s.peek() {
        return parse_slicing(s, base, None).map(Into::into);
    }

    let mut type_probe = s.clone(); // needed for later

    // try to parse an expression (either index or the first part of slicing)
    let mut context = BacktrackingContext::new(s);
    let b = context.stream();

    let disposition = match parse_expression(b, true) {
        Ok(expr) => match b.peek().cloned().transpose()? {
            Some(of_kind!(TokenKind::Colon)) => BracketExprDisposition::Slicing(expr),
            Some(of_kind!(TokenKind::SquareR)) => BracketExprDisposition::Indexable(expr),
            Some(of_kind!(TokenKind::Comma))
                if b.next().is_some() // advance
                    && matches!(b.peek(), Some(Ok(of_kind!(TokenKind::SquareR)))) =>
            {
                // just a trailing comma after the single expression

                BracketExprDisposition::Indexable(expr)
            }
            // this was probably not actually an expression, just part of a type
            // that resembles an expression but would then be followed by trash
            _ => BracketExprDisposition::TypeInstantiation,
        },
        // we couldn't parse an expression, so it must be a type
        Err(_) => BracketExprDisposition::TypeInstantiation,
    };

    let node = match disposition {
        BracketExprDisposition::Indexable(index) => {
            // we got it right
            context.commit()?;

            let closing = expect(s, TokenKind::SquareR, Some("bracket expression"))?;

            let location = s.location_starting_at(base.location().start);

            // this is probably an indexing expression, but it could also still
            // be a type instantiation with a single argument shaped so that it
            // parses both as a type and as an expression (e.g., `f[int]` is not
            // syntactically distinguishable from `arr[i]` at parse-time), so we
            // need to check if we have such ambiguity by trying to parse the
            // same tokens as a type and checking for `]` in the same place
            let type_arg = parse_type_instantiation_args(&mut type_probe)
                .ok()
                .filter(|_| type_probe.peek() == Some(&Ok(closing)))
                .filter(|args| args.len() == 1)
                .map(Vec::into_iter)
                .as_mut()
                .and_then(Iterator::next);

            if let Some(type_arg_if_instantiation) = type_arg {
                AmbiguousBracketAccessNode {
                    base: Box::new(base),
                    index_if_indexing: Box::new(index),
                    type_arg_if_instantiation,
                    location,
                }
                .into()
            } else {
                IndexingNode {
                    base: Box::new(base),
                    index: Box::new(index),
                    location,
                }
                .into()
            }
        }
        BracketExprDisposition::Slicing(first) => {
            context.commit()?; // we got it right

            parse_slicing(s, base, Some(first))?.into()
        }
        BracketExprDisposition::TypeInstantiation => {
            // we need to rollback, since any "expression" we may have parsed is
            // not actually correct and needs to be re-parsed as a type

            let type_args = parse_type_instantiation_args(s)?;

            expect(s, TokenKind::SquareR, Some("type instantiation"))?;

            let location = s.location_starting_at(base.location().start);

            TypeInstantiationNode {
                base: Box::new(base),
                type_args,
                location,
            }
            .into()
        }
    };

    Ok(node)
}

enum BracketExprDisposition<'a> {
    Indexable(ExprNode<'a>),
    Slicing(ExprNode<'a>),
    TypeInstantiation,
}

fn parse_type_instantiation_args<'a>(s: &mut TokenStream<'a>) -> PResult<'a, Vec<TypeNode<'a>>> {
    let mut args = vec![parse_type(s)?];

    while let Some(Ok(of_kind!(TokenKind::Comma))) = s.peek() {
        s.next(); // advance

        if matches!(s.peek(), Some(Ok(of_kind!(TokenKind::SquareR)))) {
            // this was actually just an optional trailing comma
            break;
        }

        args.push(parse_type(s)?);
    }

    Ok(args)
}

fn parse_type_assertion<'a>(
    s: &mut TokenStream<'a>,
    base: ExprNode<'a>,
) -> PResult<'a, TypeAssertionNode<'a>> {
    expect(s, TokenKind::Period, Some("type assertion"))?;

    expect(s, TokenKind::ParenL, Some("type assertion"))?;

    let r#type = parse_type(s)?;
    // ^^ this will intentionally fail if the next token is a `type` keyword
    // (in which case this is not actually a type assertion)

    expect(s, TokenKind::ParenR, Some("type assertion"))?;

    let location = s.location_starting_at(base.location().start);

    Ok(TypeAssertionNode {
        expr: Box::new(base),
        r#type,
        location,
    })
}

pub fn parse_postfix_if_exists<'a>(
    s: &mut TokenStream<'a>,
    operand: ExprNode<'a>,
) -> PResult<'a, ExprNode<'a>> {
    let expr = match s.peek().cloned().transpose()? {
        Some(of_kind!(TokenKind::ParenL)) => parse_call(s, operand)?,
        Some(of_kind!(TokenKind::SquareL)) => parse_bracket_expr(s, operand)?,
        Some(of_kind!(TokenKind::Period)) => {
            // this might be a postfix (selection/type assertion), but we cannot
            // know for sure at this point since it depends on the token(s)
            // after the period -- otherwise it might be something else, such as
            // the `.(type)` in a type switch, and in that case we need to leave
            // that part alone to be parsed later

            let mut context = BacktrackingContext::new(s);
            let b = context.stream();

            match parse_selection(b, operand.clone()) {
                Ok(selection) => {
                    // all good, this is really a selection
                    context.commit()?;

                    selection.into()
                }
                Err(ParsingError::UnexpectedTokenKind {
                    expected: TokenKind::Ident,
                    ..
                }) => {
                    // ok, it wasn't a selection, let's try a type assertion
                    let mut context2 = BacktrackingContext::new(s);
                    let b2 = context2.stream();

                    match parse_type_assertion(b2, operand.clone()) {
                        Ok(assertion) => {
                            // all right, it was a type assertion
                            context2.commit()?;

                            assertion.into()
                        }
                        Err(_) => return Ok(operand), // just return what we had before
                    }
                }
                Err(err) => return Err(err),
            }
        }
        _ => return Ok(operand), // nothing found, stop the recursion
    };

    parse_postfix_if_exists(s, expr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Span,
        ast::{BinaryOpKind, LiteralNode, TypeNameNode, UnaryOpKind},
        lexer::Lexer,
        parser::exprs::parse_expression,
    };

    fn parse(input: &str) -> PResult<'_, ExprNode<'_>> {
        let mut stream = TokenStream::new(Lexer::new(input));

        parse_expression(&mut stream, true)
    }

    #[test]
    fn call() {
        assert_eq!(
            ExprNode::Call(CallNode {
                func: Box::new(ExprNode::Call(CallNode {
                    func: Box::new(ExprNode::BinaryOp {
                        kind: BinaryOpKind::Sum,
                        left: Box::new(ExprNode::Selection(SelectionNode {
                            base: Box::new(ExprNode::Name(Span::new("abc", 1))),
                            selector: Span::new("def", 5),
                            location: 1..8
                        })),
                        right: Box::new(ExprNode::Literal(LiteralNode::Int {
                            value: 14,
                            location: 11..13
                        })),
                        location: 1..13,
                    }),
                    args: vec![
                        ExprNode::BinaryOp {
                            kind: BinaryOpKind::Sum,
                            left: Box::new(ExprNode::Literal(LiteralNode::Int {
                                value: 21,
                                location: 15..17
                            })),
                            right: Box::new(ExprNode::BinaryOp {
                                kind: BinaryOpKind::Product,
                                left: Box::new(ExprNode::Literal(LiteralNode::Int {
                                    value: 7,
                                    location: 20..21
                                })),
                                right: Box::new(ExprNode::UnaryOp {
                                    kind: UnaryOpKind::Negation,
                                    operand: Box::new(ExprNode::Literal(LiteralNode::Int {
                                        value: 9,
                                        location: 25..26
                                    })),
                                    location: 24..26,
                                }),
                                location: 20..26,
                            }),
                            location: 15..26,
                        },
                        ExprNode::Literal(LiteralNode::Rune {
                            value: 'a',
                            location: 28..31
                        })
                    ],
                    variadic: true,
                    location: 1..35,
                    annotation: None,
                })),
                args: vec![],
                variadic: false,
                location: 1..37,
                annotation: None
            }),
            parse("(abc.def + 14)(21 + 7 * -9, 'a'...)()").unwrap()
        );
    }

    #[test]
    fn call_index() {
        assert_eq!(
            ExprNode::Call(CallNode {
                func: Box::new(ExprNode::Indexing(IndexingNode {
                    base: Box::new(ExprNode::BinaryOp {
                        kind: BinaryOpKind::Sum,
                        left: Box::new(ExprNode::Selection(SelectionNode {
                            base: Box::new(ExprNode::Name(Span::new("abc", 1))),
                            selector: Span::new("def", 5),
                            location: 1..8
                        })),
                        right: Box::new(ExprNode::Literal(LiteralNode::Int {
                            value: 14,
                            location: 11..13
                        })),
                        location: 1..13,
                    }),
                    index: Box::new(ExprNode::BinaryOp {
                        kind: BinaryOpKind::Sum,
                        left: Box::new(ExprNode::Name(Span::new("k", 15))),
                        right: Box::new(ExprNode::Literal(LiteralNode::Int {
                            value: 2,
                            location: 19..20
                        })),
                        location: 15..20,
                    }),
                    location: 1..22,
                })),
                args: vec![],
                variadic: false,
                location: 1..24,
                annotation: None
            }),
            parse("(abc.def + 14)[k + 2,]()").unwrap()
        );
    }

    #[test]
    fn new_with_type_arg() {
        assert_eq!(
            ExprNode::New(NewNode {
                arg: NewArgNode::Type(TypeNode::Slice {
                    element: Box::new(TypeNode::Name(TypeNameNode {
                        package: None,
                        id: Span::new("int", 6),
                        args: vec![],
                    })),
                }),
                location: 0..10,
            }),
            parse("new([]int)").unwrap()
        );
    }

    #[test]
    fn new_with_expr_arg() {
        assert_eq!(
            ExprNode::New(NewNode {
                arg: NewArgNode::Expr(Box::new(ExprNode::BinaryOp {
                    kind: BinaryOpKind::Sum,
                    left: Box::new(ExprNode::Name(Span::new("x", 4))),
                    right: Box::new(ExprNode::Literal(LiteralNode::Int {
                        value: 1,
                        location: 8..9,
                    })),
                    location: 4..9,
                })),
                location: 0..10,
            }),
            parse("new(x + 1)").unwrap()
        );
    }

    #[test]
    fn new_with_ambiguous_arg() {
        assert_eq!(
            ExprNode::New(NewNode {
                arg: NewArgNode::Ambiguous {
                    if_type: TypeNode::Name(TypeNameNode {
                        package: None,
                        id: Span::new("T", 4),
                        args: vec![],
                    }),
                    if_expr: Box::new(ExprNode::Name(Span::new("T", 4))),
                },
                location: 0..6,
            }),
            parse("new(T)").unwrap()
        );
    }
}
