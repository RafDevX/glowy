use crate::Span;

#[derive(Clone, Debug, PartialEq)]
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
    Else,
    Fallthrough,
    For,
    Func,
    Go,
    If,
    Import,
    Package,
    Range,
    Return,
    Switch,
    Type,
    Var,
}

impl TokenKind {
    pub fn allows_implicit_semicolon(&self) -> bool {
        matches!(
            self,
            TokenKind::Ident
                | TokenKind::Int(_)
                | TokenKind::Float(_)
                | TokenKind::Rune(_)
                | TokenKind::String(_)
                | TokenKind::Break
                | TokenKind::Continue
                | TokenKind::Fallthrough
                | TokenKind::Return
                | TokenKind::PlusPlus
                | TokenKind::MinusMinus
                | TokenKind::ParenR
                | TokenKind::SquareR
                | TokenKind::CurlyR
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Token<'a> {
    pub kind: TokenKind,
    pub span: Span<'a>,
}

impl<'a> Token<'a> {
    pub fn new(kind: TokenKind, span: Span<'a>) -> Self {
        Self { kind, span }
    }

    pub fn from_identifier_or_keyword(span: Span<'a>) -> Self {
        let kind = match span.content {
            "break" => TokenKind::Break,
            "case" => TokenKind::Case,
            "chan" => TokenKind::Chan,
            "const" => TokenKind::Const,
            "continue" => TokenKind::Continue,
            "default" => TokenKind::Default,
            "else" => TokenKind::Else,
            "fallthrough" => TokenKind::Fallthrough,
            "for" => TokenKind::For,
            "func" => TokenKind::Func,
            "go" => TokenKind::Go,
            "if" => TokenKind::If,
            "import" => TokenKind::Import,
            "package" => TokenKind::Package,
            "range" => TokenKind::Range,
            "return" => TokenKind::Return,
            "switch" => TokenKind::Switch,
            "type" => TokenKind::Type,
            "var" => TokenKind::Var,
            _ => TokenKind::Ident,
        };

        Self::new(kind, span)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Annotation<'a> {
    pub scope: &'a str,
    pub tags: Vec<&'a str>,
}
