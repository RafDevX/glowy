use crate::{
    TokenStream,
    ast::{BinaryOpKind, ExprNode, UnaryOpKind},
    parser::PResult,
    token::TokenKind,
};

// adapted from https://matklad.github.io/2020/04/13/simple-but-powerful-pratt-parsing.html

fn infix_binding_power(op: &BinaryOpKind) -> (u8, u8) {
    // (low, high) means left-to-right associativity
    match op {
        BinaryOpKind::LogicalOr => (1, 2),
        BinaryOpKind::LogicalAnd => (3, 4),
        BinaryOpKind::Eq
        | BinaryOpKind::NotEq
        | BinaryOpKind::Less
        | BinaryOpKind::LessEq
        | BinaryOpKind::Greater
        | BinaryOpKind::GreaterEq => (5, 6),
        BinaryOpKind::Sum
        | BinaryOpKind::Diff
        | BinaryOpKind::BitwiseOr
        | BinaryOpKind::BitwiseXor => (7, 8),
        BinaryOpKind::Product
        | BinaryOpKind::Quotient
        | BinaryOpKind::Remainder
        | BinaryOpKind::ShiftLeft
        | BinaryOpKind::ShiftRight
        | BinaryOpKind::BitwiseAnd
        | BinaryOpKind::BitClear => (9, 10),
    }
}

fn parse_unary<'a>(s: &mut TokenStream<'a>) -> PResult<'a, ExprNode<'a>> {
    if let Some(Ok(token)) = s.peek().cloned() {
        if let Ok(op) = token.kind.clone().try_into() {
            s.next(); // advance

            return Ok(ExprNode::UnaryOp {
                kind: op,
                operand: Box::new(parse_unary(s)?),
                location: s.location_since(&token),
            });
        }
    }

    super::parse_primary_expression(s)
}

pub fn parse_expression_bp<'a>(s: &mut TokenStream<'a>, min_bp: u8) -> PResult<'a, ExprNode<'a>> {
    let peeked = s.peek().cloned(); // need to remember location
    let mut lhs = parse_unary(s)?;

    while let Some(token) = s.peek().cloned().transpose()? {
        let op = match token.kind.try_into() {
            Ok(kind) => kind,
            Err(_) => break,
        };

        let (l_bp, r_bp) = infix_binding_power(&op);
        if l_bp < min_bp {
            // operator to the left of this one is stronger than us,
            // so we need to let the lhs go to be with them...
            break;
        }

        s.next(); // step past operator token
        let rhs = parse_expression_bp(s, r_bp)?;

        lhs = ExprNode::BinaryOp {
            kind: op,
            left: Box::new(lhs),
            right: Box::new(rhs),
            location: s.location_since(&peeked.clone().unwrap().unwrap()),
        }
    }

    Ok(lhs)
}

pub struct UnknownOpKind;

impl TryFrom<TokenKind> for UnaryOpKind {
    type Error = UnknownOpKind;

    fn try_from(kind: TokenKind) -> Result<Self, Self::Error> {
        let op = match kind {
            TokenKind::Plus => Self::Identity,
            TokenKind::Minus => Self::Negation,
            TokenKind::Caret => Self::Complement,
            TokenKind::Excl => Self::Not,
            TokenKind::Star => Self::Deref,
            TokenKind::Amp => Self::Address,
            TokenKind::LtMinus => Self::Receive,
            _ => return Err(UnknownOpKind),
        };

        Ok(op)
    }
}

impl TryFrom<TokenKind> for BinaryOpKind {
    type Error = UnknownOpKind;

    fn try_from(kind: TokenKind) -> Result<Self, Self::Error> {
        let op = match kind {
            TokenKind::DoubleEq => Self::Eq,
            TokenKind::NotEq => Self::NotEq,
            TokenKind::Lt => Self::Less,
            TokenKind::LtEq => Self::LessEq,
            TokenKind::Gt => Self::Greater,
            TokenKind::GtEq => Self::GreaterEq,
            TokenKind::Plus => Self::Sum,
            TokenKind::Minus => Self::Diff,
            TokenKind::Star => Self::Product,
            TokenKind::Slash => Self::Quotient,
            TokenKind::Percent => Self::Remainder,
            TokenKind::DoubleLt => Self::ShiftLeft,
            TokenKind::DoubleGt => Self::ShiftRight,
            TokenKind::Pipe => Self::BitwiseOr,
            TokenKind::Amp => Self::BitwiseAnd,
            TokenKind::Caret => Self::BitwiseXor,
            TokenKind::AmpCaret => Self::BitClear,
            TokenKind::DoubleAmp => Self::LogicalAnd,
            TokenKind::DoublePipe => Self::LogicalOr,
            _ => return Err(UnknownOpKind),
        };

        Ok(op)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Span,
        ast::{LiteralNode, SelectionNode},
        lexer::Lexer,
    };

    fn parse(input: &str) -> PResult<'_, ExprNode<'_>> {
        let mut stream = TokenStream::new(Lexer::new(input));

        parse_expression_bp(&mut stream, 0)
    }

    #[test]
    fn precedence() {
        assert_eq!(
            ExprNode::BinaryOp {
                kind: BinaryOpKind::LogicalOr,
                left: Box::new(ExprNode::BinaryOp {
                    kind: BinaryOpKind::Sum,
                    left: Box::new(ExprNode::Literal(LiteralNode::Int {
                        value: 42,
                        location: 0..2
                    })),
                    right: Box::new(ExprNode::BinaryOp {
                        kind: BinaryOpKind::Product,
                        left: Box::new(ExprNode::UnaryOp {
                            kind: UnaryOpKind::Negation,
                            operand: Box::new(ExprNode::Name(Span::new("a", 6, 1))),
                            location: 5..7
                        }),
                        right: Box::new(ExprNode::Literal(LiteralNode::Int {
                            value: 3,
                            location: 10..11
                        })),
                        location: 5..11
                    }),
                    location: 0..11
                }),
                right: Box::new(ExprNode::BinaryOp {
                    kind: BinaryOpKind::LogicalAnd,
                    left: Box::new(ExprNode::Name(Span::new("b", 15, 1))),
                    right: Box::new(ExprNode::BinaryOp {
                        kind: BinaryOpKind::Eq,
                        left: Box::new(ExprNode::BinaryOp {
                            kind: BinaryOpKind::Eq,
                            left: Box::new(ExprNode::UnaryOp {
                                kind: UnaryOpKind::Identity,
                                operand: Box::new(ExprNode::Literal(LiteralNode::Int {
                                    value: 2,
                                    location: 21..22
                                })),
                                location: 20..22
                            }),
                            right: Box::new(ExprNode::Literal(LiteralNode::Int {
                                value: 4,
                                location: 26..27
                            })),
                            location: 20..27
                        }),
                        right: Box::new(ExprNode::BinaryOp {
                            kind: BinaryOpKind::BitwiseXor,
                            left: Box::new(ExprNode::UnaryOp {
                                kind: UnaryOpKind::Receive,
                                operand: Box::new(ExprNode::Literal(LiteralNode::Int {
                                    value: 9,
                                    location: 33..34
                                })),
                                location: 31..34
                            }),
                            right: Box::new(ExprNode::BinaryOp {
                                kind: BinaryOpKind::ShiftLeft,
                                left: Box::new(ExprNode::Literal(LiteralNode::Int {
                                    value: 2,
                                    location: 37..38
                                })),
                                right: Box::new(ExprNode::Name(Span::new("abc", 42, 1))),
                                location: 37..45
                            }),
                            location: 31..45
                        }),
                        location: 20..45
                    }),
                    location: 15..45
                }),
                location: 0..45
            },
            parse("42 + -a * 3 || b && +2 == 4 == <-9 ^ 2 << abc").unwrap()
        );
    }

    #[test]
    fn parens() {
        assert_eq!(
            ExprNode::BinaryOp {
                kind: BinaryOpKind::Product,
                left: Box::new(ExprNode::Literal(LiteralNode::Int {
                    value: 2,
                    location: 0..1
                })),
                right: Box::new(ExprNode::BinaryOp {
                    kind: BinaryOpKind::Diff,
                    left: Box::new(ExprNode::Literal(LiteralNode::Int {
                        value: 3,
                        location: 7..8
                    })),
                    right: Box::new(ExprNode::UnaryOp {
                        kind: UnaryOpKind::Address,
                        operand: Box::new(ExprNode::Selection(SelectionNode {
                            base: Box::new(ExprNode::Name(Span::new("ab", 13, 2))),
                            selector: Span::new("cd", 16, 2),
                            location: 15..18
                        })),
                        location: 11..18
                    }),
                    location: 7..18
                }),
                location: 0..19
            },
            parse("2 * \n (3 - &\tab.cd)").unwrap()
        );
    }
}
