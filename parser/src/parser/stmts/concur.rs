use crate::{
    TokenStream,
    ast::StatementNode,
    parser::{PResult, expect, exprs::parse_expression},
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
