use crate::{
    Location, ParsingError, TokenStream,
    ast::{BindingDeclSpecNode, DeclNode},
    parser::{PResult, expect, exprs::parse_expressions_list_while, of_kind, types::parse_type},
    token::{Annotation, TokenKind},
};

// bindings is our term for constants and variables,
// since their declarations look the same, allowing code reuse
#[derive(Clone, Copy, PartialEq, Eq)]
enum BindingKind {
    Const,
    Var,
}

impl BindingKind {
    fn keyword(self) -> TokenKind {
        match self {
            Self::Const => TokenKind::Const,
            Self::Var => TokenKind::Var,
        }
    }

    fn decl_context(self) -> &'static str {
        match self {
            Self::Const => "constant declaration",
            Self::Var => "variable declaration",
        }
    }

    fn spec_construct(self) -> &'static str {
        match self {
            Self::Const => "a constant specification",
            Self::Var => "a variable specification",
        }
    }

    fn spec_context(self) -> &'static str {
        match self {
            Self::Const => "constant specification",
            Self::Var => "variable specification",
        }
    }

    fn build_node<'a>(
        self,
        specs: Vec<BindingDeclSpecNode<'a>>,
        location: Location,
        annotation: Option<Box<Annotation<'a>>>,
    ) -> DeclNode<'a> {
        match self {
            Self::Const => DeclNode::Const {
                specs,
                location,
                annotation,
            },
            Self::Var => DeclNode::Var {
                specs,
                location,
                annotation,
            },
        }
    }
}

fn parse_spec<'a>(
    s: &mut TokenStream<'a>,
    kind: BindingKind,
) -> PResult<'a, BindingDeclSpecNode<'a>> {
    let mut ids = vec![];
    let mut r#type = None;

    loop {
        let token = expect(s, TokenKind::Ident, Some("list of identifiers"))?;
        ids.push(token.span);

        match s.peek().cloned().transpose()? {
            Some(of_kind!(TokenKind::Comma)) => {
                s.next(); // advance
                continue;
            }
            Some(of_kind!(TokenKind::Assign)) => {
                s.next(); // advance
            }
            Some(of_kind!(TokenKind::SemiColon | TokenKind::ParenR))
                if kind == BindingKind::Const =>
            {
                // implicit repetition: identifier list only, with no type and
                // no expressions, meaning that type and value are taken from
                // the previous spec in this const block. nothing else to parse
                break;
            }
            Some(_) => {
                r#type = Some(parse_type(s)?);

                if let Some(Ok(next)) = s.peek()
                    && matches!(next.kind, TokenKind::SemiColon | TokenKind::ParenR)
                {
                    // empty expressions list (sometimes allowed)
                    break;
                }

                // otherwise, it's either an = or illegal
                expect(s, TokenKind::Assign, Some(kind.spec_context()))?;
            }
            None => {
                return Err(ParsingError::UnexpectedTokenKind {
                    expected: TokenKind::Comma,
                    found: None,
                    context: Some("list of identifiers"),
                });
            }
        }

        break;
    }

    let exprs = parse_expressions_list_while(s, |t| {
        !matches!(t.kind, TokenKind::SemiColon | TokenKind::ParenR)
    })?
    .unwrap_or_else(Vec::new); // got end-of-file but that's fine, same as empty expressions list

    Ok(BindingDeclSpecNode { ids, exprs, r#type })
}

fn parse_specs_list<'a>(
    s: &mut TokenStream<'a>,
    kind: BindingKind,
) -> PResult<'a, Vec<BindingDeclSpecNode<'a>>> {
    expect(s, TokenKind::ParenL, Some(kind.decl_context()))?;

    // could be simplified, but spec allows for an empty list... `const ();`

    let mut specs = vec![];
    loop {
        match s.peek().cloned().transpose()? {
            Some(of_kind!(TokenKind::ParenR)) => break,
            Some(of_kind!(TokenKind::Ident)) => {
                specs.push(parse_spec(s, kind)?);

                // spec allows omitting semicolon before closing (
                if let Some(Ok(of_kind!(TokenKind::ParenR))) = s.peek() {
                    break;
                }

                expect(s, TokenKind::SemiColon, Some(kind.spec_context()))?;
            }
            found => {
                return Err(ParsingError::UnexpectedConstruct {
                    expected: kind.spec_construct(),
                    found,
                });
            }
        }
    }

    s.next(); // consume )

    Ok(specs)
}

fn parse_binding_decl<'a>(s: &mut TokenStream<'a>, kind: BindingKind) -> PResult<'a, DeclNode<'a>> {
    let beginning = expect(s, kind.keyword(), Some(kind.decl_context()))?;
    let annotation = s.take_last_annotation();

    let specs = match s.peek().cloned().transpose()? {
        Some(of_kind!(TokenKind::Ident)) => vec![parse_spec(s, kind)?],
        Some(of_kind!(TokenKind::ParenL)) => parse_specs_list(s, kind)?,
        found => {
            return Err(ParsingError::UnexpectedConstruct {
                expected: kind.spec_construct(),
                found,
            });
        }
    };

    Ok(kind.build_node(specs, s.location_since(&beginning), annotation))
}

pub fn parse_const_decl<'a>(s: &mut TokenStream<'a>) -> PResult<'a, DeclNode<'a>> {
    parse_binding_decl(s, BindingKind::Const)
}

pub fn parse_var_decl<'a>(s: &mut TokenStream<'a>) -> PResult<'a, DeclNode<'a>> {
    parse_binding_decl(s, BindingKind::Var)
}
