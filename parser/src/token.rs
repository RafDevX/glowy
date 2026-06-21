use std::{hash, mem};

use crate::{Location, Span};

#[derive(Clone, Debug)]
pub enum TokenKind {
    SemiColon, // ;

    Comma,    // ,
    Period,   // .
    Colon,    // :
    Ellipsis, // ...

    ParenL,  // (
    ParenR,  // )
    SquareL, // [
    SquareR, // ]
    CurlyL,  // {
    CurlyR,  // }

    Plus,    // +
    Minus,   // -
    Star,    //_*
    Slash,   // /
    Percent, // %
    Caret,   // ^
    Excl,    //_!
    Tilde,   // ~

    Amp,        // &
    Pipe,       // |
    DoubleAmp,  // &&
    DoublePipe, // ||
    AmpCaret,   // &^

    DoubleEq, // ==
    NotEq,    //_!=
    Lt,       // <
    Gt,       // >
    LtEq,     // <=
    GtEq,     // >=
    DoubleLt, // <<
    DoubleGt, // >>
    LtMinus,  // <-

    PlusPlus,   // ++
    MinusMinus, // --

    Assign,         // =
    ColonAssign,    // :=
    PlusAssign,     // +=
    MinusAssign,    // -=
    StarAssign,     //_*=
    SlashAssign,    // /=
    PercentAssign,  // %=
    CaretAssign,    // ^=
    AmpAssign,      // &=
    PipeAssign,     // |=
    DoubleLtAssign, // <<=
    DoubleGtAssign, // >>=
    AmpCaretAssign, // &^=

    Int(u64),       // 3
    Float(f64),     // 3.14
    Rune(char),     // 'a'
    String(String), // "hello world"

    Ident,

    // keywords
    Break,
    Case,
    Chan,
    Const,
    Continue,
    Default,
    Defer,
    Else,
    Fallthrough,
    For,
    Func,
    Go,
    Goto,
    If,
    Import,
    Interface,
    Map,
    Package,
    Range,
    Return,
    Select,
    Struct,
    Switch,
    Type,
    Var,
}

impl TokenKind {
    pub(crate) fn allows_implicit_semicolon(&self) -> bool {
        matches!(
            self,
            Self::Ident
                | Self::Int(_)
                | Self::Float(_)
                | Self::Rune(_)
                | Self::String(_)
                | Self::Break
                | Self::Continue
                | Self::Fallthrough
                | Self::Return
                | Self::PlusPlus
                | Self::MinusMinus
                | Self::ParenR
                | Self::SquareR
                | Self::CurlyR
        )
    }
}

// manual PartialEq/Eq/Hash implementation is necessary to handle f64 specially
impl PartialEq for TokenKind {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Int(left), Self::Int(right)) => left == right,
            // bit comparison preserves semantics like 0.0 != -0.0
            (Self::Float(left), Self::Float(right)) => left.to_bits() == right.to_bits(),
            (Self::Rune(left), Self::Rune(right)) => left == right,
            (Self::String(left), Self::String(right)) => left == right,
            _ => mem::discriminant(self) == mem::discriminant(other),
        }
    }
}

impl Eq for TokenKind {}

impl hash::Hash for TokenKind {
    #[inline]
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        mem::discriminant(self).hash(state);

        match self {
            Self::Int(inner) => inner.hash(state),
            Self::Float(inner) => inner.to_bits().hash(state),
            Self::Rune(inner) => inner.hash(state),
            Self::String(inner) => inner.hash(state),
            _ => {}
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Token<'a> {
    pub kind: TokenKind,
    pub span: Span<'a>,
}

impl<'a> Token<'a> {
    pub(crate) fn new(kind: TokenKind, span: Span<'a>) -> Self {
        Self { kind, span }
    }

    pub(crate) fn from_identifier_or_keyword(span: Span<'a>) -> Self {
        let kind = match span.content {
            "break" => TokenKind::Break,
            "case" => TokenKind::Case,
            "chan" => TokenKind::Chan,
            "const" => TokenKind::Const,
            "continue" => TokenKind::Continue,
            "default" => TokenKind::Default,
            "defer" => TokenKind::Defer,
            "else" => TokenKind::Else,
            "fallthrough" => TokenKind::Fallthrough,
            "for" => TokenKind::For,
            "func" => TokenKind::Func,
            "go" => TokenKind::Go,
            "goto" => TokenKind::Goto,
            "if" => TokenKind::If,
            "import" => TokenKind::Import,
            "interface" => TokenKind::Interface,
            "map" => TokenKind::Map,
            "package" => TokenKind::Package,
            "range" => TokenKind::Range,
            "return" => TokenKind::Return,
            "select" => TokenKind::Select,
            "struct" => TokenKind::Struct,
            "switch" => TokenKind::Switch,
            "type" => TokenKind::Type,
            "var" => TokenKind::Var,
            _ => TokenKind::Ident,
        };

        Self::new(kind, span)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Annotation<'a> {
    pub directive: &'a str,
    pub tags: Vec<&'a str>,
    pub location: Location,
}
