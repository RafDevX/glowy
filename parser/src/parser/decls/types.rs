use crate::{
    ast::{DeclNode, TypeDeclSpecNode},
    parser::{PResult, expect, of_kind, types::parse_type},
    stream::TokenStream,
    token::TokenKind,
};

fn parse_type_spec<'a>(s: &mut TokenStream<'a>) -> PResult<'a, TypeDeclSpecNode<'a>> {
    let id = expect(s, TokenKind::Ident, Some("type decl spec"))?.span;

    let alias = if let Some(Ok(of_kind!(TokenKind::Assign))) = s.peek() {
        s.next(); // advance

        true
    } else {
        false
    };

    let r#type = parse_type(s)?;

    Ok(TypeDeclSpecNode { alias, id, r#type })
}

pub fn parse_type_decl<'a>(s: &mut TokenStream<'a>) -> PResult<'a, DeclNode<'a>> {
    let beginning = expect(s, TokenKind::Type, Some("type declaration"))?;

    let mut specs = vec![];

    if let Some(Ok(of_kind!(TokenKind::ParenL))) = s.peek() {
        // multiple specs

        s.next(); // advance

        loop {
            specs.push(parse_type_spec(s)?);

            if let Some(Ok(of_kind!(TokenKind::ParenR))) = s.peek() {
                s.next(); // advance
                break;
            } else {
                expect(s, TokenKind::SemiColon, Some("type declaration specs list"))?;
            }

            // need to check for ) again after ;
            if let Some(Ok(of_kind!(TokenKind::ParenR))) = s.peek() {
                s.next(); // advance
                break;
            }
        }
    } else {
        // one spec

        specs.push(parse_type_spec(s)?);
    }

    let location = s.location_since(&beginning);

    Ok(DeclNode::Type { specs, location })
}
