use std::{iter::Peekable, vec::IntoIter};

use finl_unicode::categories::CharacterCategories;

use crate::{
    Diagnostics, ErrorDiagnosticInfo, Span,
    ast::{BuildConstraintExprNode, BuildConstraintNode},
    parser::PResult,
    stream::TokenStream,
};

pub fn try_parse_build_constraint<'a>(
    s: &mut TokenStream<'a>,
) -> PResult<'a, Option<BuildConstraintNode<'a>>> {
    // modern `//go:build` constraints take priority over legacy `// +build`

    if let Some(span) = s.get_build_constraint() {
        let tokens = tokenize_build_constraint(span)?;

        let expr = parse_build_constraint_expr(tokens, span)?;

        return Ok(Some(BuildConstraintNode {
            expr,
            location: span.location(),
        }));
    }

    let Some(legacy) = s.get_legacy_build_constraints() else {
        // neither modern nor legacy constraints were found
        return Ok(None);
    };

    let expr = parse_legacy_build_constraints(legacy.lines())?;

    Ok(Some(BuildConstraintNode {
        expr,
        location: legacy.location().clone(),
    }))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BuildConstraintParsingError<'a> {
    UnexpectedChar {
        expected: char,
        found: Option<Span<'a>>,
    },
    IllegalChar {
        found: Span<'a>,
    },
    ExpectedExpression {
        location: Span<'a>,
    },
    UnclosedParen {
        location: Span<'a>,
    },
    TrailingTokens {
        location: Span<'a>,
    },
}

impl<'a> Diagnostics<'a> for BuildConstraintParsingError<'a> {
    #[inline]
    fn diagnostics(&self) -> ErrorDiagnosticInfo<'a> {
        macro_rules! s {
            ($lit:expr) => {
                $lit.to_owned()
            };
        }

        match self {
            Self::UnexpectedChar { expected, found } => ErrorDiagnosticInfo {
                code: s!("B001"),
                overview: s!("unexpected character in build constraint"),
                details: format!(
                    "expected character {:?}, but found {}",
                    expected,
                    found
                        .as_ref()
                        .map(Span::content)
                        .map_or_else(|| s!("end-of-file"), str::to_owned)
                ),
                context: *found,
            },
            Self::IllegalChar { found } => ErrorDiagnosticInfo {
                code: s!("B002"),
                overview: s!("illegal character in build constraint"),
                details: format!(
                    "character {:?} is not valid in a build constraint expression",
                    found.content()
                ),
                context: Some(*found),
            },
            Self::ExpectedExpression { location } => ErrorDiagnosticInfo {
                code: s!("B003"),
                overview: s!("expected expression in build constraint"),
                details: s!("expected a build tag, `!`, or `(`"),
                context: Some(*location),
            },
            Self::UnclosedParen { location } => ErrorDiagnosticInfo {
                code: s!("B004"),
                overview: s!("unclosed parenthesis in build constraint"),
                details: s!("expected `)` to close a parenthesized sub-expression"),
                context: Some(*location),
            },
            Self::TrailingTokens { location } => ErrorDiagnosticInfo {
                code: s!("B005"),
                overview: s!("trailing tokens in build constraint"),
                details: s!("expected `&&`, `||`, or end of expression"),
                context: Some(*location),
            },
        }
    }
}

#[derive(Clone, Debug)]
enum BuildConstraintToken<'a> {
    Tag(&'a str),
    Not,
    And,
    Or,
    ParenL,
    ParenR,
}

fn tokenize_build_constraint(
    span: Span<'_>,
) -> Result<Vec<BuildConstraintToken<'_>>, BuildConstraintParsingError<'_>> {
    let content = span.content();
    let mut tokens = Vec::new();
    let mut chars = content.char_indices().peekable();

    while let Some(&(pos, ch)) = chars.peek() {
        if ch.is_whitespace() {
            chars.next();

            continue;
        }

        macro_rules! single {
            ($tok:expr) => {{
                chars.next(); // advance

                $tok
            }};
        }

        macro_rules! double {
            ($expect:expr, $tok:expr) => {{
                chars.next(); // advance

                match chars.peek().copied() {
                    Some((_, ch)) if ch == $expect => {
                        chars.next(); // advance

                        $tok
                    }
                    found => {
                        let found_span =
                            found.map(|(pos, ch)| span.subspan(pos..(pos + ch.len_utf8())));

                        let err = BuildConstraintParsingError::UnexpectedChar {
                            expected: $expect,
                            found: found_span,
                        };

                        return Err(err.into());
                    }
                }
            }};
        }

        let token = match ch {
            '!' => single!(BuildConstraintToken::Not),
            '(' => single!(BuildConstraintToken::ParenL),
            ')' => single!(BuildConstraintToken::ParenR),
            '&' => double!('&', BuildConstraintToken::And),
            '|' => double!('|', BuildConstraintToken::Or),
            first if is_tag_start_char(first) => {
                chars.next(); // advance

                let end = loop {
                    match chars.peek().copied() {
                        Some((pos, ch)) if !is_tag_char(ch) => break pos,
                        Some(_) => {
                            chars.next();
                        }
                        None => break content.len(),
                    }
                };

                let tag = &content[pos..end];

                BuildConstraintToken::Tag(tag)
            }
            _ => {
                let end = pos + ch.len_utf8();

                return Err(BuildConstraintParsingError::IllegalChar {
                    found: span.subspan(pos..end),
                });
            }
        };

        tokens.push(token);
    }

    Ok(tokens)
}

fn is_tag_start_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn is_tag_char(ch: char) -> bool {
    is_tag_start_char(ch) || ch == '.'
}

fn collapse_and(mut clauses: Vec<BuildConstraintExprNode<'_>>) -> BuildConstraintExprNode<'_> {
    if clauses.len() == 1 {
        clauses.pop().unwrap()
    } else {
        BuildConstraintExprNode::And(clauses)
    }
}

fn collapse_or(mut clauses: Vec<BuildConstraintExprNode<'_>>) -> BuildConstraintExprNode<'_> {
    if clauses.len() == 1 {
        clauses.pop().unwrap()
    } else {
        BuildConstraintExprNode::Or(clauses)
    }
}

fn parse_build_constraint_expr<'a>(
    tokens: Vec<BuildConstraintToken<'a>>,
    location: Span<'a>,
) -> Result<BuildConstraintExprNode<'a>, BuildConstraintParsingError<'a>> {
    let mut tokens = tokens.into_iter().peekable();
    let expr = parse_or_expr(&mut tokens, location)?;

    if tokens.peek().is_some() {
        return Err(BuildConstraintParsingError::TrailingTokens { location });
    }

    Ok(expr)
}

type TokenIter<'a> = Peekable<IntoIter<BuildConstraintToken<'a>>>;

fn parse_or_expr<'a>(
    tokens: &mut TokenIter<'a>,
    location: Span<'a>,
) -> Result<BuildConstraintExprNode<'a>, BuildConstraintParsingError<'a>> {
    let first = parse_and_expr(tokens, location)?;
    let mut clauses = vec![first];

    while matches!(tokens.peek(), Some(BuildConstraintToken::Or)) {
        tokens.next(); // advance

        clauses.push(parse_and_expr(tokens, location)?);
    }

    Ok(collapse_or(clauses))
}

fn parse_and_expr<'a>(
    tokens: &mut TokenIter<'a>,
    location: Span<'a>,
) -> Result<BuildConstraintExprNode<'a>, BuildConstraintParsingError<'a>> {
    let first = parse_unary_expr(tokens, location)?;
    let mut clauses = vec![first];

    while matches!(tokens.peek(), Some(BuildConstraintToken::And)) {
        tokens.next(); // advance

        clauses.push(parse_unary_expr(tokens, location)?);
    }

    Ok(collapse_and(clauses))
}

fn parse_unary_expr<'a>(
    tokens: &mut TokenIter<'a>,
    location: Span<'a>,
) -> Result<BuildConstraintExprNode<'a>, BuildConstraintParsingError<'a>> {
    if matches!(tokens.peek(), Some(BuildConstraintToken::Not)) {
        tokens.next(); // advance

        let inner = parse_unary_expr(tokens, location)?;

        return Ok(BuildConstraintExprNode::Not(Box::new(inner)));
    }

    parse_primary_expr(tokens, location)
}

fn parse_primary_expr<'a>(
    tokens: &mut TokenIter<'a>,
    location: Span<'a>,
) -> Result<BuildConstraintExprNode<'a>, BuildConstraintParsingError<'a>> {
    match tokens.next() {
        Some(BuildConstraintToken::Tag(name)) => Ok(BuildConstraintExprNode::Tag(name)),
        Some(BuildConstraintToken::ParenL) => {
            let inner = parse_or_expr(tokens, location)?;

            match tokens.next() {
                Some(BuildConstraintToken::ParenR) => Ok(inner),
                _ => Err(BuildConstraintParsingError::UnclosedParen { location }),
            }
        }
        _ => Err(BuildConstraintParsingError::ExpectedExpression { location }),
    }
}

fn parse_legacy_build_constraints<'a>(
    lines: &[Span<'a>],
) -> Result<BuildConstraintExprNode<'a>, BuildConstraintParsingError<'a>> {
    let mut parsed = Vec::with_capacity(lines.len());

    for line in lines {
        let expr = parse_legacy_build_constraint_expression(*line)?;

        parsed.push(expr);
    }

    Ok(collapse_and(parsed))
}

fn parse_legacy_build_constraint_expression(
    span: Span<'_>,
) -> Result<BuildConstraintExprNode<'_>, BuildConstraintParsingError<'_>> {
    let mut options = Vec::new();
    let mut chars = span.content().char_indices().peekable();

    while let Some(&(start, ch)) = chars.peek() {
        if ch.is_whitespace() {
            chars.next();
            continue;
        }

        chars.next();
        let end = loop {
            match chars.peek().copied() {
                Some((position, ch)) if ch.is_whitespace() => break position,
                Some(_) => {
                    chars.next();
                }
                None => break span.content().len(),
            }
        };

        let option_span = span.subspan(start..end);
        options.push(parse_legacy_build_constraint_option(option_span)?);
    }

    if options.is_empty() {
        return Err(BuildConstraintParsingError::ExpectedExpression { location: span });
    }

    Ok(collapse_or(options))
}

fn parse_legacy_build_constraint_option(
    span: Span<'_>,
) -> Result<BuildConstraintExprNode<'_>, BuildConstraintParsingError<'_>> {
    let mut terms = Vec::new();
    let mut start = 0;

    for part in span.content().split(',') {
        let part_span = span.subspan(start..(start + part.len()));
        terms.push(parse_legacy_build_constraint_term(part_span)?);
        start += part.len() + 1;
    }

    Ok(collapse_and(terms))
}

fn parse_legacy_build_constraint_term(
    span: Span<'_>,
) -> Result<BuildConstraintExprNode<'_>, BuildConstraintParsingError<'_>> {
    let (negated, tag_span) = if span.content().starts_with('!') {
        (true, span.subspan(1..span.content().len()))
    } else {
        (false, span)
    };

    if tag_span.content().is_empty() {
        return Err(BuildConstraintParsingError::ExpectedExpression { location: span });
    }

    if let Some((position, ch)) = tag_span
        .content()
        .char_indices()
        .find(|(_, ch)| !is_legacy_tag_char(*ch))
    {
        return Err(BuildConstraintParsingError::IllegalChar {
            found: tag_span.subspan(position..(position + ch.len_utf8())),
        });
    }

    let tag = BuildConstraintExprNode::Tag(tag_span.content());

    if negated {
        Ok(BuildConstraintExprNode::Not(Box::new(tag)))
    } else {
        Ok(tag)
    }
}

fn is_legacy_tag_char(ch: char) -> bool {
    ch.is_letter() || ch.is_number_decimal() || matches!(ch, '_' | '.')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(source: &str) -> PResult<'_, Option<BuildConstraintNode<'_>>> {
        crate::parse(source).map(|file| file.build_constraint)
    }

    #[test]
    fn parses_legacy_constraints() {
        assert_eq!(
            Some(BuildConstraintNode {
                expr: BuildConstraintExprNode::And(vec![
                    BuildConstraintExprNode::Or(vec![
                        BuildConstraintExprNode::And(vec![
                            BuildConstraintExprNode::Tag("linux"),
                            BuildConstraintExprNode::Tag("amd64"),
                        ]),
                        BuildConstraintExprNode::And(vec![
                            BuildConstraintExprNode::Tag("darwin"),
                            BuildConstraintExprNode::Not(Box::new(BuildConstraintExprNode::Tag(
                                "cgo"
                            ))),
                        ]),
                    ]),
                    BuildConstraintExprNode::And(vec![
                        BuildConstraintExprNode::Tag("gc"),
                        BuildConstraintExprNode::Tag("计划"),
                    ]),
                ]),
                location: 21..93
            }),
            parse(
                "
                    // +build linux,amd64 darwin,!cgo
                    //+build gc,计划

                    package p
                "
            )
            .unwrap()
        );
    }

    #[test]
    fn modern_constraint_takes_precedence() {
        assert_eq!(
            Some(BuildConstraintNode {
                expr: BuildConstraintExprNode::Tag("linux"),
                location: 70..75
            }),
            parse(
                "
                    // +build windows
                    //go:build linux

                    package p
                "
            )
            .unwrap()
        );
    }

    #[test]
    fn rejects_malformed_legacy_constraints() {
        for source in [
            "// +build linux\npackage p\n",
            "// +builder \n\npackage p\n",
        ] {
            assert_eq!(None, parse(source).unwrap());
        }
    }

    #[test]
    fn whitespace_only_line_terminates_legacy_constraints() {
        assert_eq!(
            Some(BuildConstraintNode {
                expr: BuildConstraintExprNode::Tag("linux"),
                location: 21..36
            }),
            parse(
                "
                    // +build linux\r
                    \t\r
                    package p\r
                "
            )
            .unwrap()
        );
    }
}
