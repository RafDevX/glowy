use self::postfix::parse_postfix_if_exists;
use super::{expect, PResult};
use crate::{
    ast::{
        CompositeLiteralElementListNode, CompositeLiteralElementNode, ExprNode, LiteralNode,
        OperandNameNode,
    },
    parser::{of_kind, types::parse_type, BacktrackingContext},
    token::{Token, TokenKind},
    ParsingError, TokenStream,
};

mod ops;
mod postfix;

fn parse_operand_name<'a>(s: &mut TokenStream<'a>) -> PResult<'a, OperandNameNode<'a>> {
    let token = expect(s, TokenKind::Ident, Some("operand name"))?;

    if let Some(Ok(of_kind!(TokenKind::Period))) = s.peek() {
        // make sure that it's actually `pkg.sym` and not e.g. `x.(type)` in
        // a type switch statement (in which case the `.` shouldn't be touched)
        if let Some(Ok(of_kind!(TokenKind::Ident))) = s.clone().nth(1) {
            s.next(); // advance period

            return Ok(OperandNameNode {
                package: Some(token.span),
                id: expect(s, TokenKind::Ident, Some("operand name"))?.span,
            });
        }
    }

    Ok(OperandNameNode {
        package: None,
        id: token.span,
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

    let values = parse_composite_literal_element_list(s)?;

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

fn parse_composite_literal_element_list<'a>(
    s: &mut TokenStream<'a>,
) -> PResult<'a, CompositeLiteralElementListNode<'a, usize>> {
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

        // elements can be either alone or with an integer literal key, but we
        // don't know unless we see an Int followed by a Colon - since we cannot
        // peek 2 tokens ahead, we use a BacktrackingContext
        let mut context = BacktrackingContext::new(s);
        let b = context.stream();

        let key = if let Some(Ok(of_kind!(TokenKind::Int(candidate)))) = b.next() {
            // might be a key, but only if followed by :
            if let Some(Ok(of_kind!(TokenKind::Colon))) = b.next() {
                // confirmed! we can commit and go back to the main stream s
                context.commit()?;

                Some(usize::try_from(candidate).ok().unwrap_or(usize::MAX))
            } else {
                // nope, there's no key
                // (we cannot re-use `candidate` as the value, we need to parse
                // again, because it might be a more complex expression like
                // the `2` in `2 + 3`)
                None
            }
        } else {
            None
        };

        let value = if let Some(Ok(of_kind!(TokenKind::CurlyL))) = s.peek() {
            CompositeLiteralElementNode::Nested(parse_composite_literal_element_list(s)?)
        } else {
            CompositeLiteralElementNode::Expr(parse_expression(s)?)
        };

        values.push((key, value));
    }

    expect(s, TokenKind::CurlyR, Some("composite literal"))?;

    Ok(values)
}

pub fn parse_primary_expression<'a>(s: &mut TokenStream<'a>) -> PResult<'a, ExprNode<'a>> {
    let expr = match s.peek().cloned().transpose()? {
        Some(of_kind!(TokenKind::Ident)) => parse_operand_name(s)?.into(),
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
                value,
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
        Some(of_kind!(TokenKind::SquareL)) => parse_array_or_slice_literal(s)?.into(),
        Some(of_kind!(TokenKind::ParenL)) => {
            s.next(); // advance
            let inner = parse_expression(s)?;
            expect(s, TokenKind::ParenR, Some("parenthesized expression"))?;

            inner
        }
        found => {
            return Err(ParsingError::UnexpectedConstruct {
                expected: "a primary expression",
                found,
            })
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
