use crate::{
    ast::{DeclNode, TypeDeclSpecNode},
    parser::{
        BacktrackingContext, PResult, expect, of_kind,
        types::{parse_type, parse_type_params},
    },
    stream::TokenStream,
    token::TokenKind,
};

fn parse_type_spec<'a>(s: &mut TokenStream<'a>) -> PResult<'a, TypeDeclSpecNode<'a>> {
    let id = expect(s, TokenKind::Ident, Some("type decl spec"))?.span;

    // we need to be careful here as it is difficult to distinguish type params
    // like `type newType[K comparable] map[K]bool` from square brackets that
    // are already the start of the type like `type newType [string]bool`.
    // the best we can do is try to parse type parameters, and rollback if it
    // fails to successfully parse exactly

    let mut context = BacktrackingContext::new(s);
    let b = context.stream();

    let params = if let Some(Ok(of_kind!(TokenKind::SquareL))) = b.peek()
        && let Ok(params) = parse_type_params(b)
    {
        context.commit()?;

        params
    } else {
        // rollback, ignore `b` and continue using `s` from now on

        Vec::new()
    };

    let alias = if let Some(Ok(of_kind!(TokenKind::Assign))) = s.peek() {
        s.next(); // advance

        true
    } else {
        false
    };

    let r#type = parse_type(s)?;

    Ok(TypeDeclSpecNode {
        alias,
        id,
        params,
        r#type,
    })
}

pub fn parse_type_decl<'a>(s: &mut TokenStream<'a>) -> PResult<'a, DeclNode<'a>> {
    let beginning = expect(s, TokenKind::Type, Some("type declaration"))?;

    let mut specs = vec![];

    if let Some(Ok(of_kind!(TokenKind::ParenL))) = s.peek() {
        // multiple specs

        s.next(); // advance

        loop {
            // need to check for ) again after ; as well as right at the start
            // of the loop (spec allows empty type declaration)
            if let Some(Ok(of_kind!(TokenKind::ParenR))) = s.peek() {
                s.next(); // advance
                break;
            }

            specs.push(parse_type_spec(s)?);

            if let Some(Ok(of_kind!(TokenKind::ParenR))) = s.peek() {
                s.next(); // advance
                break;
            }

            expect(s, TokenKind::SemiColon, Some("type declaration specs list"))?;
        }
    } else {
        // one spec

        specs.push(parse_type_spec(s)?);
    }

    let location = s.location_since(&beginning);

    Ok(DeclNode::Type { specs, location })
}
