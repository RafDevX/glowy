use crate::{
    TokenStream,
    ast::{SelectClauseNode, SelectNode, StatementNode},
    parser::{PResult, expect, exprs::parse_expression, of_kind},
    token::TokenKind,
};

pub fn parse_go_statement<'a>(s: &mut TokenStream<'a>) -> PResult<'a, StatementNode<'a>> {
    let token = expect(s, TokenKind::Go, Some("go statement"))?;

    // alas, it would be difficult to get a CallNode directly because we'd need
    // to hook into the expression parsing internal postfix logic, so it's
    // easier to just let the AST consumer deal with potentially illegal
    // (non-call) expressions later down the line
    let expr = parse_expression(s)?;
    // ^ technically parenthesized expressions are illegal here, but yeah...

    Ok(StatementNode::Go {
        expr,
        location: s.location_since(&token),
    })
}

// this is considered concurrency-adjacent because it is often most useful to
// defer unlocking shared-access locks, in conjunction with go statements
pub fn parse_defer_statement<'a>(s: &mut TokenStream<'a>) -> PResult<'a, StatementNode<'a>> {
    let token = expect(s, TokenKind::Defer, Some("defer statement"))?;

    // alas, it would be difficult to get a CallNode directly because we'd need
    // to hook into the expression parsing internal postfix logic, so it's
    // easier to just let the AST consumer deal with potentially illegal
    // (non-call) expressions later down the line
    let expr = parse_expression(s)?;
    // ^ technically parenthesized expressions are illegal here, but yeah...

    Ok(StatementNode::Defer {
        expr,
        location: s.location_since(&token),
    })
}

pub fn parse_select_statement<'a>(s: &mut TokenStream<'a>) -> PResult<'a, SelectNode<'a>> {
    let start = expect(s, TokenKind::Select, Some("select statement"))?;

    expect(s, TokenKind::CurlyL, Some("select statement"))?;

    let mut clauses = vec![];

    loop {
        let case = match s.peek().cloned().transpose()? {
            Some(of_kind!(TokenKind::CurlyR)) => break,
            Some(of_kind!(TokenKind::Default)) => {
                s.next(); // advance

                None
            }
            _ => {
                expect(s, TokenKind::Case, Some("select clause"))?;

                // technically we should only allow send or receive statements
                // here, but it would be much more awkward to actually worry
                // about that, so we'll leave any validation to the invoker
                Some(super::parse_statement(s, false)?)
            }
        };

        expect(s, TokenKind::Colon, Some("select clause"))?;

        let body = super::parse_statements_until(s, |t| {
            matches!(
                t.kind,
                TokenKind::CurlyR | TokenKind::Case | TokenKind::Default
            )
        })?;

        clauses.push(SelectClauseNode { case, body })
    }

    expect(s, TokenKind::CurlyR, Some("select statement"))?;

    Ok(SelectNode {
        clauses,
        location: s.location_since(&start),
    })
}
