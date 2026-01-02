use self::postfix::parse_postfix_if_exists;
use super::{PResult, expect};
use crate::{
    ParsingError, TokenStream,
    ast::{
        CompositeLiteralElementListNode, CompositeLiteralElementNode, ConversionNode, ExprNode,
        LiteralNode, OrderedF64, StructLiteralFieldsNode,
    },
    parser::{BacktrackingContext, decls, of_kind, stmts, types::parse_type},
    token::{Token, TokenKind},
};

mod ops;
mod postfix;

fn parse_identifier_first_expr<'a>(s: &mut TokenStream<'a>) -> PResult<'a, ExprNode<'a>> {
    // technically we don't really need a BacktrackingContext because we could
    // try to manually convert an incorrect operand-name into a type-name, but
    // then there's other complexity (like type args) that we would have to keep
    // track of and essentially rely on being able to "jump in" into the middle
    // of lower-level parsing implementations -- it's more sustainable to just
    // backtrack if it wasn't actually an operand name expression

    let mut context = BacktrackingContext::new(s);
    let b = context.stream();

    let operand = expect(b, TokenKind::Ident, Some("identifier first expression"))?;

    let expr = if !matches!(b.peek(), Some(Ok(of_kind!(TokenKind::CurlyL)))) {
        // ok, we got it right, this was for sure an operand name
        context.commit()?;

        ExprNode::Name(operand.span)
    } else {
        // now we know there's a trailing {, but we don't know if that is
        // because of a composite literal (`x { ... }`) or completely unrelated
        // (`if x {`), so we need to try parsing a composite literal but be
        // ready to backtrack (must use the original stream since if correct
        // then `operand` is wrong)
        let mut context2 = BacktrackingContext::new(s);
        let b2 = context2.stream();

        // we default to assume any type is a struct
        if let Ok(lit) = parse_struct_literal(b2) {
            // ok, confirmed, everything worked out
            context2.commit()?;

            lit.into()
        } else {
            // nope, if we got this far then our first guess was correct and it
            // truly is an operand name with an innocent unrelated { after it

            let operand = expect(s, TokenKind::Ident, Some("operand name"))?;
            // ^^^ note, cannot just re-use the `operand` variable because then
            // the main stream would not be at the right position, and cannot
            // use `context.commit()` to fix it because we can only construct
            // `context2` (&mut s) if the previous `context` (also &mut s) has
            // already been dropped (way before this point)

            ExprNode::Name(operand.span)
        }
    };

    Ok(expr)
}

fn parse_function_literal<'a>(s: &mut TokenStream<'a>) -> PResult<'a, LiteralNode<'a>> {
    let beginning = expect(s, TokenKind::Func, Some("function literal"))?;

    // func literals don't support type parameters, per spec

    let signature = decls::funcs::parse_signature(s)?;

    let body = stmts::parse_block(s)?;

    let location = s.location_since(&beginning);

    Ok(LiteralNode::Function {
        signature,
        body,
        location,
    })
}

fn parse_array_or_slice_literal<'a>(s: &mut TokenStream<'a>) -> PResult<'a, LiteralNode<'a>> {
    let beginning = expect(s, TokenKind::SquareL, Some("array/slice literal"))?;

    let (slice, length) = match s.peek().cloned().transpose()? {
        Some(of_kind!(TokenKind::Ellipsis)) => {
            s.next(); // advance

            (false, None)
        }
        Some(of_kind!(TokenKind::SquareR)) => (true, None),
        _ => (false, Some(Box::new(parse_expression(s)?))),
    };

    expect(s, TokenKind::SquareR, Some("array/slice literal"))?;

    let element = parse_type(s)?;

    let values = parse_composite_literal_element_list(s, true)?;

    let location = s.location_since(&beginning);

    let literal = if slice {
        LiteralNode::Slice {
            element,
            values,
            location,
        }
    } else {
        LiteralNode::Array {
            length,
            element,
            values,
            location,
        }
    };

    Ok(literal)
}

fn parse_map_literal<'a>(s: &mut TokenStream<'a>) -> PResult<'a, LiteralNode<'a>> {
    let beginning = expect(s, TokenKind::Map, Some("map literal"))?;
    expect(s, TokenKind::SquareL, Some("map literal"))?;

    let key = parse_type(s)?;

    expect(s, TokenKind::SquareR, Some("map literal"))?;

    let element = parse_type(s)?;

    let values = parse_composite_literal_element_list(s, false)?;

    let location = s.location_since(&beginning);

    Ok(LiteralNode::Map {
        key,
        element,
        values,
        location,
    })
}

fn parse_struct_literal<'a>(s: &mut TokenStream<'a>) -> PResult<'a, LiteralNode<'a>> {
    let Some(beginning) = s.peek().cloned().transpose()? else {
        return Err(ParsingError::UnexpectedConstruct {
            expected: "a struct literal",
            found: None,
        });
    };

    let r#type = parse_type(s)?;

    let list = parse_composite_literal_element_list(s, true)?;

    let fields = if list.iter().any(|(k, _)| k.is_some()) {
        // if any element has a key, all elements must have a key

        let mut pairs = vec![];

        for (key, value) in list {
            let Some(key_expr) = key else {
                return Err(ParsingError::UnexpectedConstruct {
                    expected: "all-keyed struct literal",
                    found: None, // FIXME: report actual location instead of EOF
                });
            };

            if let ExprNode::Name(id) = key_expr {
                // this is not actually an operand name, it's just parsed as
                // such: in reality it's an identifier corresponding to a field
                // name, so now we get rid of that (misconstrued) expression and
                // just extract the inner identifier

                pairs.push((id, value));
            } else {
                return Err(ParsingError::UnexpectedConstruct {
                    expected: "a field name identifier",
                    found: None, // FIXME: report actual location instead of EOF
                });
            }
        }

        StructLiteralFieldsNode::Keyed(pairs)
    } else {
        // otherwise, all fields are exhaustively listed in order without keys
        // (if omitted, the appropriate zero-value is used)

        let values = list.into_iter().map(|(_, v)| v).collect();

        StructLiteralFieldsNode::Exhaustive(values)
    };

    let location = s.location_since(&beginning);

    Ok(LiteralNode::Struct {
        r#type,
        fields,
        location,
    })
}

fn parse_composite_literal_element_list<'a>(
    s: &mut TokenStream<'a>,
    optional_keys: bool,
) -> PResult<'a, CompositeLiteralElementListNode<'a>> {
    expect(s, TokenKind::CurlyL, Some("composite literal"))?;

    let mut values = vec![];

    let mut first = true;
    while !matches!(s.peek(), Some(Ok(of_kind!(TokenKind::CurlyR)))) {
        if first {
            first = false;
        } else {
            expect(s, TokenKind::Comma, Some("element list"))?;

            // if this was just a trailing comma, we need to bail
            if let Some(Ok(of_kind!(TokenKind::CurlyR))) = s.peek() {
                break;
            }
        }

        if optional_keys {
            if let Some(Ok(of_kind!(TokenKind::CurlyL))) = s.peek() {
                // no key, just nested
                let value = parse_composite_literal_element_list(s, optional_keys)?;

                values.push((None, CompositeLiteralElementNode::Nested(value)));

                continue;
            }
        }

        // take an expression, initially assumed as a value candidate
        let value = parse_expression(s)?;

        let (key, value) = if let Some(Ok(of_kind!(TokenKind::Colon))) = s.peek() {
            // nope, it wasn't a value -- it was a key!
            let key = value;

            // advance
            s.next();

            // parse the actual value
            let value = if let Some(Ok(of_kind!(TokenKind::CurlyL))) = s.peek() {
                CompositeLiteralElementNode::Nested(parse_composite_literal_element_list(
                    s,
                    optional_keys,
                )?)
            } else {
                CompositeLiteralElementNode::Expr(parse_expression(s)?)
            };

            (Some(key), value)
        } else {
            // confirmed! it was actually the value, there's no key

            if !optional_keys {
                // but this case isn't actually allowed, so we need to error...
                expect(s, TokenKind::Colon, Some("composite literal"))?;
                // ^ this will intentionally error
            }

            (None, CompositeLiteralElementNode::Expr(value))
        };

        values.push((key, value));
    }

    expect(s, TokenKind::CurlyR, Some("composite literal"))?;

    Ok(values)
}

fn parse_conversion<'a>(s: &mut TokenStream<'a>) -> PResult<'a, ConversionNode<'a>> {
    let start = s.peek().map(Result::as_ref).and_then(Result::ok).cloned();

    let r#type = parse_type(s)?;

    expect(s, TokenKind::ParenL, Some("explicit conversion"))?;

    let expr = Box::new(parse_expression(s)?);

    expect(s, TokenKind::ParenR, Some("explicit conversion"))?;

    let location = s.location_since(&start.unwrap());
    // ^ unwrap is safe since next token definitely exists
    // (otherwise we would not have gotten this far; `expect` would have failed)

    Ok(ConversionNode {
        r#type,
        expr,
        location,
    })
}

pub fn parse_primary_expression<'a>(s: &mut TokenStream<'a>) -> PResult<'a, ExprNode<'a>> {
    macro_rules! with_conversion_fallback {
        ($main:path) => {{
            let mut context = BacktrackingContext::new(s);
            let b = context.stream();

            if let Ok(ret) = $main(b).map(Into::into) {
                context.commit()?;

                ret
            } else {
                // rollback; try parsing a conversion

                parse_conversion(s)?.into()
            }
        }};
    }

    let expr = match s.peek().cloned().transpose()? {
        Some(of_kind!(TokenKind::Ident)) => parse_identifier_first_expr(s)?,
        Some(token @ of_kind!(TokenKind::Int(value))) => {
            s.next(); // advance

            LiteralNode::Int {
                value,
                location: token.span.location(),
            }
            .into()
        }
        Some(token @ of_kind!(TokenKind::Float(value))) => {
            s.next(); // advance

            LiteralNode::Float {
                value: OrderedF64(value),
                location: token.span.location(),
            }
            .into()
        }
        Some(token @ of_kind!(TokenKind::Rune(value))) => {
            s.next(); // advance

            LiteralNode::Rune {
                value,
                location: token.span.location(),
            }
            .into()
        }
        Some(ref token @ of_kind!(TokenKind::String(ref value))) => {
            s.next(); // advance

            LiteralNode::String {
                value: value.clone(),
                location: token.span.location(),
            }
            .into()
        }
        Some(of_kind!(TokenKind::Func)) => parse_function_literal(s)?.into(),
        Some(of_kind!(TokenKind::SquareL)) => {
            with_conversion_fallback!(parse_array_or_slice_literal)
        }
        Some(of_kind!(TokenKind::Map)) => with_conversion_fallback!(parse_map_literal),
        Some(of_kind!(TokenKind::Struct)) => with_conversion_fallback!(parse_struct_literal),
        Some(of_kind!(TokenKind::ParenL)) => {
            s.next(); // advance
            let inner = parse_expression(s)?;
            expect(s, TokenKind::ParenR, Some("parenthesized expression"))?;

            inner
        }
        found => {
            if let Ok(conversion) = parse_conversion(s) {
                // this was a conversion to a weird type like `->int`, which
                // starts with a strange token (didn't match above)

                conversion.into()
            } else {
                // if conversion fails to parse, this was probably not a
                // conversion at all to begin with, so it's better to show a
                // more generic error message

                return Err(ParsingError::UnexpectedConstruct {
                    expected: "a primary expression",
                    found,
                });
            }
        }
    };

    parse_postfix_if_exists(s, expr)
}

pub fn parse_expression<'a>(s: &mut TokenStream<'a>) -> PResult<'a, ExprNode<'a>> {
    ops::parse_expression_bp(s, 0)
}

pub fn parse_expressions_list<'a, F, R, E>(
    s: &mut TokenStream<'a>,
    stop_cond: F,
) -> PResult<'a, Option<(Vec<ExprNode<'a>>, R)>>
where
    F: Fn(Token<'a>) -> Result<R, E>,
{
    let mut exprs = vec![];

    let mut over = false;

    while let Some(Ok(token)) = s.peek().cloned() {
        if let Ok(res) = stop_cond(token) {
            return Ok(Some((exprs, res)));
        }

        if over {
            // 2 non-comma-separated expressions in a row are not allowed
            expect(s, TokenKind::Comma, Some("expressions list"))?;
            // (^^ we know this will error, that's the point)
        }

        exprs.push(parse_expression(s)?);

        if let Some(Ok(of_kind!(TokenKind::Comma))) = s.peek() {
            s.next(); // advance
        } else {
            // the next token must be an assignment operator,
            // otherwise something's wrong -- this will be checked
            // at the beginning of the next loop iteration
            over = true;
        }
    }

    Ok(None)
}

pub fn parse_expressions_list_while<'a, F>(
    s: &mut TokenStream<'a>,
    cond: F,
) -> PResult<'a, Option<Vec<ExprNode<'a>>>>
where
    F: Fn(Token<'a>) -> bool,
{
    Ok(
        parse_expressions_list(s, |token| (!cond(token)).then_some(()).ok_or(()))?
            .map(|(exprs, _)| exprs),
    )
}
