use crate::{
    ParsingError, TokenStream,
    ast::{FunctionDeclNode, FunctionParamDeclNode, FunctionResultNode, FunctionSignatureNode},
    parser::{
        BacktrackingContext, PResult, expect, of_kind,
        stmts::{self, parse_block},
        types::parse_type,
    },
    token::TokenKind,
};

fn parse_type_only_param_decl<'a>(
    s: &mut TokenStream<'a>,
) -> PResult<'a, FunctionParamDeclNode<'a>> {
    // each declaration is just one type, so this is easy

    // note: no need to take a `single: bool` parameter because type-only
    // declarations are always single anyway

    let variadic = if let Some(Ok(of_kind!(TokenKind::Ellipsis))) = s.peek() {
        s.next(); // advance

        true
    } else {
        false
    };

    let r#type = parse_type(s)?;

    Ok(FunctionParamDeclNode {
        ids: vec![],
        variadic,
        r#type,
    })
}

fn parse_identifiers_list_param_decl<'a>(
    s: &mut TokenStream<'a>,
    single: bool,
) -> PResult<'a, FunctionParamDeclNode<'a>> {
    let mut ids = vec![];

    loop {
        let ident = expect(s, TokenKind::Ident, Some("parameter declaration"))?;

        ids.push(ident.span);

        if single {
            // we only support one identifier, not a list, so we stop right away
            break;
        }

        // check the next token
        if let Some(Ok(of_kind!(TokenKind::Comma))) = s.peek() {
            s.next(); // advance

            // read another identifier
            continue;
        }

        // next element is a type
        break;
    }

    let variadic = if let Some(Ok(of_kind!(TokenKind::Ellipsis))) = s.peek() {
        s.next(); // advance

        true
    } else {
        false
    };

    let r#type = parse_type(s)?;

    Ok(FunctionParamDeclNode {
        ids,
        variadic,
        r#type,
    })
}

fn parse_param_decl<'a>(
    s: &mut TokenStream<'a>,
    single: bool,
) -> PResult<'a, FunctionParamDeclNode<'a>> {
    // Go in practice supports two different flavors of parameter declarations:
    // either just with types, such as `f(int, int, float32)`, or more commonly
    // with identifiers, like `f(a, b int, z float32)` -- the latter obviously
    // being much more difficult to parse

    // We have no way of knowing which flavor is being used until we actually
    // try it out, so here we just do trial-and-error: we first try parsing the
    // most common identifiers-list flavor, and if that fails then we try
    // parsing the simpler type-only version

    // Note we could not do this the other way around, since parsing the flavor
    // with identifiers is guaranteed to fail immediately for the first
    // declaration if we made an incorrect assumption, but parsing the type-only
    // flavor would not necessarily fail right away even if we got it wrong,
    // since an identifier can always be erroneously parsed as a type -- meaning
    // that if we later discovered that this parameter list was actually using
    // identifiers, we would need to re-parse all previous parameter
    // declarations under this new flavor. In any case, the identifiers-list
    // version _should_ occur more regularly, and it's nice not having to
    // backtrack most of the time

    let mut context = BacktrackingContext::new(s);
    let b = context.stream();

    if let Ok(decl) = parse_identifiers_list_param_decl(b, single) {
        context.commit()?;

        Ok(decl)
    } else {
        parse_type_only_param_decl(s)
    }
}

fn parse_params<'a>(s: &mut TokenStream<'a>) -> PResult<'a, Vec<FunctionParamDeclNode<'a>>> {
    expect(s, TokenKind::ParenL, Some("function parameters"))?;

    let mut params = vec![];

    loop {
        // this should be a while but it's not easy to express the condition
        if let Some(Ok(of_kind!(TokenKind::ParenR))) = s.peek() {
            break;
        }

        params.push(parse_param_decl(s, false)?);

        // need to check again in case there isn't an (optional) trailing comma
        if let Some(Ok(of_kind!(TokenKind::ParenR))) = s.peek() {
            break;
        }

        expect(s, TokenKind::Comma, Some("parameter list"))?;
    }

    expect(s, TokenKind::ParenR, Some("function parameters"))?;

    Ok(params)
}

pub fn parse_signature<'a>(s: &mut TokenStream<'a>) -> PResult<'a, FunctionSignatureNode<'a>> {
    let params = parse_params(s)?;

    let result = match s.peek().cloned().transpose()? {
        None => FunctionResultNode::None,
        Some(of_kind!(kind)) if stmts::terminal_token(&kind) => FunctionResultNode::None,
        Some(of_kind!(TokenKind::ParenL)) => FunctionResultNode::Params(parse_params(s)?),
        _ => FunctionResultNode::Single(parse_type(s)?),
    };

    Ok(FunctionSignatureNode { params, result })
}

// for the purposes of this parser, methods are special functions (w/ receiver)
pub fn parse_function_decl<'a>(s: &mut TokenStream<'a>) -> PResult<'a, FunctionDeclNode<'a>> {
    let annotation = s.take_last_annotation();

    let beginning = expect(s, TokenKind::Func, Some("function declaration"))?;

    let receiver = if let Some(Ok(of_kind!(TokenKind::ParenL))) = s.peek() {
        s.next(); // advance

        let param = parse_param_decl(s, true)?;

        expect(s, TokenKind::ParenR, Some("method receiver"))?;

        Some(param)
    } else {
        None
    };

    let name = expect(s, TokenKind::Ident, Some("function name"))?.span;

    if let Some(Ok(of_kind!(TokenKind::SquareL))) = s.peek() {
        // TODO: support type parameters
        return Err(ParsingError::UnexpectedConstruct {
            expected: "function signature",
            found: s.next().transpose()?,
        });
    }

    let signature = parse_signature(s)?;

    let body = parse_block(s)?;

    let location = s.location_since(&beginning);

    Ok(FunctionDeclNode {
        receiver,
        name,
        signature,
        body,
        location,
        annotation,
    })
}
