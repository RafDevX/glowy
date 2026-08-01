use std::{
    collections::VecDeque,
    hash, mem,
    num::{ParseFloatError, ParseIntError},
    ops::Range,
    str::{Chars, FromStr},
    sync::LazyLock,
};

use finl_unicode::categories::CharacterCategories;
use regex::Regex;

use crate::{
    Location, Span,
    errors::{Diagnostics, ErrorDiagnosticInfo},
    token::{Annotation, Token, TokenKind},
};

const BUILD_CONSTRAINT_MARKER: &str = "//go:build";

static ANNOTATION_REGEX: LazyLock<Regex> = {
    LazyLock::new(|| {
        Regex::new(
            // glowy::directive::{tags}
            r"glowy::(?P<directive>\w+)::\{(?P<tags>[^}]*)\}",
        )
        .unwrap()
    })
};

#[derive(Clone, Debug)]
pub enum LexingError<'a> {
    UnknownChar(Span<'a>),
    InvalidNumberLiteralChar(Span<'a>),
    IntParseFailure(Span<'a>, ParseIntError),
    FloatParseFailure(Span<'a>, ParseFloatError),
    NumberTrailingUnderscore(Span<'a>),
    MultipleCharactersInRune(Span<'a>),
    EmptyRune(Span<'a>),
    LineBreakInString(Span<'a>),
    InvalidStringEscapeSequence(Span<'a>),
    UnclosedString,
    UnclosedComment,
}

// manual implementation of PartialEq/Eq/Hash is necessary to ignore
// ParseIntError and ParseFloatError, as they are not Hash
impl PartialEq for LexingError<'_> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::UnknownChar(left), Self::UnknownChar(right))
            | (Self::InvalidNumberLiteralChar(left), Self::InvalidNumberLiteralChar(right))
            | (Self::IntParseFailure(left, _), Self::IntParseFailure(right, _))
            | (Self::FloatParseFailure(left, _), Self::FloatParseFailure(right, _))
            | (Self::NumberTrailingUnderscore(left), Self::NumberTrailingUnderscore(right))
            | (Self::MultipleCharactersInRune(left), Self::MultipleCharactersInRune(right))
            | (Self::EmptyRune(left), Self::EmptyRune(right))
            | (Self::LineBreakInString(left), Self::LineBreakInString(right))
            | (Self::InvalidStringEscapeSequence(left), Self::InvalidStringEscapeSequence(right)) => {
                left == right
            }
            _ => mem::discriminant(self) == mem::discriminant(other),
        }
    }
}

impl Eq for LexingError<'_> {}

impl hash::Hash for LexingError<'_> {
    #[inline]
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        mem::discriminant(self).hash(state);

        let span = match self {
            LexingError::UnknownChar(span)
            | LexingError::InvalidNumberLiteralChar(span)
            | LexingError::IntParseFailure(span, _)
            | LexingError::FloatParseFailure(span, _)
            | LexingError::NumberTrailingUnderscore(span)
            | LexingError::MultipleCharactersInRune(span)
            | LexingError::EmptyRune(span)
            | LexingError::LineBreakInString(span)
            | LexingError::InvalidStringEscapeSequence(span) => span,
            LexingError::UnclosedString | LexingError::UnclosedComment => return,
        };

        span.hash(state);
    }
}

impl<'a> Diagnostics<'a> for LexingError<'a> {
    #[inline]
    fn diagnostics(&self) -> ErrorDiagnosticInfo<'a> {
        macro_rules! s {
            ($lit:expr) => {
                $lit.to_owned()
            };
        }

        match self {
            Self::UnknownChar(context) => ErrorDiagnosticInfo {
                code: s!("L001"),
                overview: s!("failed to process unknown character"),
                details: s!("this character is invalid in Go or unsupported"),
                context: Some(*context),
            },
            Self::InvalidNumberLiteralChar(context) => ErrorDiagnosticInfo {
                code: s!("L002"),
                overview: s!("failed to process unknown number literal character"),
                details: s!("this character is not valid for the given literal mode"),
                context: Some(*context),
            },
            Self::IntParseFailure(context, err) => ErrorDiagnosticInfo {
                code: s!("L003"),
                overview: s!("failed to parse integer literal"),
                details: err.to_string(),
                context: Some(*context),
            },
            Self::FloatParseFailure(context, err) => ErrorDiagnosticInfo {
                code: s!("L004"),
                overview: s!("failed to parse float literal"),
                details: err.to_string(),
                context: Some(*context),
            },
            Self::NumberTrailingUnderscore(context) => ErrorDiagnosticInfo {
                code: s!("L005"),
                overview: s!("illegal trailing underscore in number literal"),
                details: s!("underscores are only allowed between consecutive digits"),
                context: Some(*context),
            },
            Self::MultipleCharactersInRune(context) => ErrorDiagnosticInfo {
                code: s!("L006"),
                overview: s!("multiple characters in rune"),
                details: s!("found more than one character in the given rune"),
                context: Some(*context),
            },
            Self::EmptyRune(context) => ErrorDiagnosticInfo {
                code: s!("L007"),
                overview: s!("empty rune"),
                details: s!("found no characters in the given rune"),
                context: Some(*context),
            },
            Self::LineBreakInString(context) => ErrorDiagnosticInfo {
                code: s!("L008"),
                overview: s!("line break in string"),
                details: s!("the newline character (\\n) is not allowed in string literals"),
                context: Some(*context),
            },
            Self::InvalidStringEscapeSequence(context) => ErrorDiagnosticInfo {
                code: s!("L009"),
                overview: s!("invalid escape sequence"),
                details: s!("escape sequence in string is invalid"),
                context: Some(*context),
            },
            Self::UnclosedString => ErrorDiagnosticInfo {
                code: s!("L010"),
                overview: s!("unclosed string"),
                details: s!("reached EOF before finding a closing string delimiter"),
                context: None,
            },
            Self::UnclosedComment => ErrorDiagnosticInfo {
                code: s!("L011"),
                overview: s!("unclosed comment"),
                details: s!("reached EOF before finding a closing block comment delimiter"),
                context: None,
            },
        }
    }
}

#[derive(Clone)]
pub struct Lexer<'a> {
    src: Chars<'a>, // cannot use Peekable<Chars> as it doesn't support .as_str()

    offset: usize, // 0-indexed, from start of src (*not* start of line)

    last_token_kind: Option<TokenKind>,
    queue: VecDeque<Token<'a>>,

    last_annotation: Option<Annotation<'a>>, // prevent clearing by whitespace

    enable_implicit_semicolon: bool, // whether to enable implicit semicolon insertion

    build_constraint: Option<Span<'a>>, // from `//go:build ...` at the beginning
    legacy_build_constraints: Option<LegacyBuildConstraints<'a>>,
}

type LResult<'a> = Result<Token<'a>, LexingError<'a>>;

impl<'a> Lexer<'a> {
    pub fn new(src: &'a str) -> Self {
        Self {
            src: src.chars(),

            offset: 0,

            last_token_kind: None,
            queue: VecDeque::new(),

            last_annotation: None,

            enable_implicit_semicolon: true,

            build_constraint: None,
            legacy_build_constraints: None,
        }
    }

    pub fn take_last_annotation(&mut self) -> Option<Box<Annotation<'a>>> {
        self.last_annotation.take().map(Box::new)
    }

    pub fn get_build_constraint(&self) -> Option<Span<'a>> {
        self.build_constraint
    }

    pub fn get_legacy_build_constraints(&self) -> Option<&LegacyBuildConstraints<'a>> {
        self.legacy_build_constraints.as_ref()
    }

    fn peek_char(&mut self) -> Option<char> {
        // cloning Chars<'_> is cheap
        self.src.clone().next()
    }

    fn read_char(&mut self) -> Option<char> {
        let view = self.src.as_str();
        let original_offset = self.offset;

        if let Some(ch) = self.src.next() {
            self.offset += ch.len_utf8();

            if ch == '\n'
                && self.enable_implicit_semicolon
                && self
                    .last_token_kind
                    .as_ref()
                    .is_some_and(TokenKind::allows_implicit_semicolon)
                && self
                    .queue
                    .back()
                    .is_none_or(|token| token.kind != TokenKind::SemiColon)
            {
                // newline is guaranteed single-byte, no panic
                let span = Span::new(&view[..1], original_offset);
                self.queue.push_back(Token::new(TokenKind::SemiColon, span));
            }

            Some(ch)
        } else {
            None
        }
    }

    fn read_span(&mut self) -> Option<Span<'a>> {
        let original_offset = self.offset;

        let view = self.src.as_str();

        if let Some(ch) = self.read_char() {
            let n = ch.len_utf8();
            Some(Span::new(&view[..n], original_offset))
        } else {
            None
        }
    }

    fn accumulate_while<F, S>(&mut self, initial: S, mut func: F) -> (Span<'a>, S)
    where
        F: FnMut(char, &mut S, &mut Self) -> bool,
    {
        let original_offset = self.offset;

        let view = self.src.as_str();
        let mut len = 0;
        let mut state = initial;
        while let Some(ch) = self.peek_char() {
            if !func(ch, &mut state, self) {
                break;
            }
            len += ch.len_utf8();
            self.read_char(); // advance iterator
        }

        let span = Span::new(&view[..len], original_offset);

        (span, state)
    }

    fn read_while<F>(&mut self, mut cond: F) -> Span<'a>
    where
        F: FnMut(char) -> bool,
    {
        self.accumulate_while((), |ch, (), _| cond(ch)).0
    }

    fn read_n(&mut self, n: usize) -> Span<'a> {
        let (span, _) = self.accumulate_while(0, |_, count, _| {
            if *count < n {
                *count += 1;
                true
            } else {
                false
            }
        });

        span
    }

    fn skip_comments(&mut self) -> Result<(), LexingError<'a>> {
        // cloned so we can peek freely
        let mut it = self.src.clone();

        if it.next() == Some('/') {
            match it.next() {
                Some('/') => {
                    // line comment

                    self.read_n(2); // step over //

                    let start = self.offset;

                    let text = self.read_while(|ch| ch != '\n').content;

                    if let Some(captures) = ANNOTATION_REGEX.captures(text) {
                        let directive = captures.name("directive").unwrap().as_str();

                        let tags = captures
                            .name("tags")
                            .unwrap()
                            .as_str()
                            .split(',')
                            .map(str::trim)
                            .filter(|tag| !tag.is_empty())
                            .collect();

                        let location = captures.get(0).unwrap().range();
                        let location = (start + location.start)..(start + location.end);

                        self.last_annotation = Some(Annotation {
                            directive,
                            tags,
                            location,
                        });
                    }
                }
                Some('*') => {
                    // general comment

                    self.read_n(2); // step over /*
                    loop {
                        match self.read_char() {
                            Some('*') if self.peek_char() == Some('/') => {
                                self.read_char(); // step over /
                                break;
                            }
                            Some(_) => {}
                            None => return Err(LexingError::UnclosedComment),
                        }
                    }
                }
                _ => {} // not a comment
            }
        }

        Ok(())
    }

    fn try_extract_build_constraint(&mut self) {
        if self.build_constraint.is_some() || self.last_token_kind.is_some() {
            // nothing to do: either we already have a build constraint (and
            // only the first one is allowed), or we've already returned some
            // token (not a comment nor a blank) so no more build constraints
            // are allowed for this file
            return;
        }

        let view = self.src.as_str();
        let line_end = view.find('\n').unwrap_or(view.len());
        let line = &view[..line_end];

        let Some(expression_range) = build_constraint_expression_range(line) else {
            return;
        };

        let offset = self.offset + expression_range.start;

        self.build_constraint = Some(Span::new(&line[expression_range], offset));

        self.read_n(line.chars().count());
    }

    fn try_extract_legacy_build_constraints(&mut self) {
        if self.build_constraint.is_some()
            || self.legacy_build_constraints.is_some()
            || self.last_token_kind.is_some()
        {
            return;
        }

        let view = self.src.as_str();
        let Some(first_line_end) = view.find('\n') else {
            return;
        };

        if legacy_build_constraint_expression_range(view[..first_line_end].trim_start()).is_none() {
            return;
        }

        let mut lines = Vec::new();
        let mut location_start = None;
        let mut location_end = 0;
        let mut cursor = 0;

        let consumed_bytes = loop {
            let remaining = &view[cursor..];

            let Some(line_end) = remaining.find('\n') else {
                return;
            };

            let line = remaining[..line_end]
                .strip_suffix('\r')
                .unwrap_or(&remaining[..line_end]);

            let comment_offset = line.len() - line.trim_start().len();
            let comment = &line[comment_offset..];

            if line.trim().is_empty() {
                break cursor + line_end + 1;
            }

            // a modern `//go:build` directive is authoritative, so we just
            // advance to it for the regular extractor to handle it
            if build_constraint_expression_range(comment).is_some() {
                let consumed_chars = view[..(cursor + comment_offset)].chars().count();

                self.read_n(consumed_chars);

                return;
            }

            if !comment.starts_with("//") {
                return;
            }

            if let Some(expression_range) = legacy_build_constraint_expression_range(comment) {
                let line = Span::new(comment, self.offset + cursor + comment_offset);
                let line_location = line.location();

                location_start.get_or_insert(line_location.start);
                location_end = line_location.end;

                lines.push(line.subspan(expression_range));
            }

            cursor += line_end + 1;
        };

        let consumed_chars = view[..consumed_bytes].chars().count();
        self.read_n(consumed_chars);

        self.legacy_build_constraints = Some(LegacyBuildConstraints {
            lines,
            location: location_start.unwrap()..location_end,
        });
    }

    fn identifier_or_keyword(&mut self) -> Token<'a> {
        let ident = self.read_while(|ch| is_letter(ch) || is_unicode_digit(ch));

        Token::from_identifier_or_keyword(ident)
    }

    #[allow(clippy::too_many_lines)]
    fn number_literal(&mut self) -> LResult<'a> {
        enum NumberLexMode {
            Unknown,
            Set,
            Decimal,
            Binary,
            Octal,
            Hex,
        }

        #[allow(clippy::struct_excessive_bools)]
        struct NumberLexState<'a> {
            mode: NumberLexMode,
            seen_digits: bool, // whether any real digit has been read yet
            seen_period: bool, // the . in 3.14
            seen_exp: bool,    // the e in 2e6, or the p in 0x2p4
            exp_has_digits: bool,
            last_was_digit: bool,
            imaginary: bool,
            err: Option<LexingError<'a>>,
        }

        let (span, state) = self.accumulate_while(
            NumberLexState {
                mode: NumberLexMode::Unknown,
                seen_digits: false,
                seen_period: false,
                seen_exp: false,
                exp_has_digits: false,
                last_was_digit: false,
                imaginary: false,
                err: None,
            },
            |ch, state, lexer| {
                macro_rules! invalid {
                    ($state:expr, $lexer:expr) => {{
                        // if had already read something, unknown char might be another token
                        if !$state.seen_digits {
                            // haven't read anything yet, this is officially an error
                            let span = $lexer.read_span().unwrap();
                            $state.err = Some(LexingError::InvalidNumberLiteralChar(span));
                        }

                        return false;
                    }};
                }

                if state.imaginary {
                    return false;
                }

                if ch == 'i' {
                    let number_is_complete = (state.seen_digits
                        || matches!(state.mode, NumberLexMode::Set))
                        && (!state.seen_exp || state.exp_has_digits)
                        && state.last_was_digit;

                    if number_is_complete {
                        state.imaginary = true;
                        return true;
                    }

                    invalid!(state, lexer);
                }

                if ch == '_' {
                    // Go allows separating underscores, only one at a time and
                    // only between consecutive digits (e.g. 2_45_6 is ok, but
                    // 2._5 or 1__2 is invalid)
                    if state.last_was_digit {
                        state.last_was_digit = false;
                        return true; // continue to next character
                    }

                    invalid!(state, lexer);
                } else if ch.is_ascii_digit()
                    || (matches!(state.mode, NumberLexMode::Hex)
                        && !state.seen_exp
                        && ch.is_ascii_hexdigit())
                {
                    state.last_was_digit = true;
                }

                match state.mode {
                    NumberLexMode::Unknown if ch == '0' => state.mode = NumberLexMode::Set,
                    NumberLexMode::Set => {
                        state.mode = match ch.to_ascii_lowercase() {
                            'b' => NumberLexMode::Binary,
                            'o' => NumberLexMode::Octal,
                            'x' => NumberLexMode::Hex,
                            '0'..='9' => {
                                state.seen_digits = true;

                                NumberLexMode::Decimal
                            }
                            '.' => {
                                state.seen_digits = true; // first 0 counts as real
                                state.seen_period = true;

                                NumberLexMode::Decimal
                            }
                            'e' => {
                                state.seen_digits = true; // first 0 counts as real
                                state.seen_exp = true;

                                NumberLexMode::Decimal
                            }
                            _ => return false, // this is probably another token
                        }
                    }
                    NumberLexMode::Unknown | NumberLexMode::Decimal => {
                        match ch {
                            '0'..='9' => {
                                state.mode = NumberLexMode::Decimal;
                                if state.seen_exp {
                                    state.exp_has_digits = true;
                                } else {
                                    state.seen_digits = true;
                                }
                            }
                            '.' if !state.seen_period && !state.seen_exp => {
                                state.mode = NumberLexMode::Decimal;
                                state.seen_period = true;
                            }
                            'e' | 'E' if state.seen_digits && !state.seen_exp => {
                                state.seen_exp = true;
                            }
                            '+' | '-' if state.seen_exp && !state.exp_has_digits => {} // allow
                            _ => invalid!(state, lexer),
                        }
                    }
                    NumberLexMode::Binary if ch == '0' || ch == '1' => state.seen_digits = true,
                    NumberLexMode::Octal if ch.is_digit(8) => state.seen_digits = true,
                    NumberLexMode::Hex => match ch {
                        '.' if !state.seen_period && !state.seen_exp => {
                            state.seen_period = true;
                        }
                        'p' | 'P' if state.seen_digits && !state.seen_exp => {
                            state.seen_exp = true;
                        }
                        '+' | '-' if state.seen_exp && !state.exp_has_digits => {} // allow
                        digit if digit.is_ascii_hexdigit() => {
                            if state.seen_exp {
                                state.exp_has_digits = true;
                            } else {
                                state.seen_digits = true;
                            }
                        }
                        _ => invalid!(state, lexer),
                    },
                    _ => invalid!(state, lexer),
                }

                true
            },
        );

        if let Some(err) = state.err {
            return Err(err);
        }

        if span.content().ends_with('_') {
            // this is the only case not caught while reading: if the number
            // ends and the last thing read was an underscore, which is illegal,
            // since underscores are only allowed between digits
            return Err(LexingError::NumberTrailingUnderscore(span));
        }

        let number = span.content().strip_suffix('i').unwrap_or(span.content());

        let (radix, start) = match state.mode {
            NumberLexMode::Unknown => unreachable!("invoker did not peek first! ran out of tokens"),
            NumberLexMode::Set | NumberLexMode::Decimal => (10, number),
            NumberLexMode::Binary => (2, &number[2..]),
            NumberLexMode::Octal => (8, &number[2..]),
            NumberLexMode::Hex => (16, &number[2..]),
        };

        let num_str = start.replace('_', "");

        if state.seen_period || state.seen_exp {
            // float

            let result = if radix == 10 {
                f64::from_str(&num_str)
            } else if radix == 16 {
                // hexadecimal floats are valid Go and accepted by the lexer up
                // to this point, but sadly they cannot be easily parsed by Rust
                // (std) into an f64, since 10 years ago f64::from_str_radix was
                // deprecated, and even before then it was reportedly wildly
                // inaccurate for base 16;
                // https://internals.rust-lang.org/t/deprecate-f-32-64-from-str-radix/2405

                // we thus implement a ridiculous frankenstein conversion
                // ourselves, under the hope that it shall never be used
                Ok(parse_hexadecimal_float(&num_str))
            } else {
                unreachable!("unexpected base-{radix} float")
            };

            match result {
                Ok(float) => {
                    let kind = if state.imaginary {
                        TokenKind::Imaginary(float)
                    } else {
                        TokenKind::Float(float)
                    };

                    Ok(Token::new(kind, span))
                }
                Err(err) => Err(LexingError::FloatParseFailure(span, err)),
            }
        } else {
            // int

            match u64::from_str_radix(&num_str, radix) {
                Ok(int) => {
                    let kind = if state.imaginary {
                        #[allow(clippy::cast_precision_loss)]
                        let value = int as f64;

                        TokenKind::Imaginary(value)
                    } else {
                        TokenKind::Int(int)
                    };

                    Ok(Token::new(kind, span))
                }
                Err(err) => Err(LexingError::IntParseFailure(span, err)),
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn string_like_literal(&mut self) -> LResult<'a> {
        enum StringLexMode {
            Unknown,
            Rune,              // unicode character ('a')
            InterpretedString, // "hello\nworld"
            RawString,         // `hello world`
        }

        enum StringLexEscapeMode {
            Normal,
            Backslash,
            EscapedUnicode {
                value: u32,
                read_count: u8,
                radix: u32,
                expected_count: u8,
                max_value: u32,
            },
        }

        struct StringLexState<'a> {
            mode: StringLexMode,
            escape_mode: StringLexEscapeMode,
            last_char: Option<char>,
            string: String,
            finished: bool, // whether closing delimiter has been read
            err: Option<LexingError<'a>>,
        }

        macro_rules! push_char {
            ($state:expr, $char:expr) => {{
                if let Some(c) = $state.last_char {
                    $state.string.push(c);
                }
                $state.last_char = Some($char);
                $state.escape_mode = StringLexEscapeMode::Normal;
            }};
        }

        let prev_implicit_semicolon = self.enable_implicit_semicolon;
        self.enable_implicit_semicolon = false;

        let (span, state) = self.accumulate_while(
            StringLexState {
                mode: StringLexMode::Unknown,
                escape_mode: StringLexEscapeMode::Normal,
                last_char: None,
                string: String::new(),
                finished: false,
                err: None,
            },
            |ch, state, lexer| {
                if state.finished {
                    return false;
                }
                match &mut state.escape_mode {
                    StringLexEscapeMode::Normal => match (ch, &state.mode) {
                        ('\'', StringLexMode::Unknown) => state.mode = StringLexMode::Rune,
                        ('"', StringLexMode::Unknown) => {
                            state.mode = StringLexMode::InterpretedString;
                        }
                        ('`', StringLexMode::Unknown) => state.mode = StringLexMode::RawString,
                        (_, StringLexMode::Unknown) => unreachable!(
                            "function string_like_literal called on non-string boundary"
                        ),

                        ('\'', StringLexMode::Rune) => {
                            // end rune
                            state.finished = true;
                        }
                        (_, StringLexMode::Rune) if state.last_char.is_some() => {
                            // rune already has character, but closing quote not found
                            let span = lexer.read_span().unwrap();
                            state.err = Some(LexingError::MultipleCharactersInRune(span));
                            return false;
                        }
                        ('`', StringLexMode::RawString)
                        | ('"', StringLexMode::InterpretedString) => {
                            // end raw and interpreted string
                            if let Some(c) = state.last_char {
                                state.string.push(c);
                                state.last_char = None;
                            }
                            state.finished = true;
                        }
                        ('\\', StringLexMode::Rune | StringLexMode::InterpretedString) => {
                            state.escape_mode = StringLexEscapeMode::Backslash;
                        }
                        ('\n', StringLexMode::Rune | StringLexMode::InterpretedString) => {
                            let span = lexer.read_span().unwrap();
                            state.err = Some(LexingError::LineBreakInString(span));
                            return false;
                        }
                        ('\r', StringLexMode::RawString) => {} // carriage returns are discarded
                        // in raw strings
                        _ => push_char!(state, ch),
                    },
                    StringLexEscapeMode::Backslash => {
                        match (ch, &state.mode) {
                            ('a', _) => push_char!(state, '\u{0007}'),
                            ('b', _) => push_char!(state, '\u{0008}'),
                            ('f', _) => push_char!(state, '\u{000c}'),
                            ('n', _) => push_char!(state, '\n'),
                            ('r', _) => push_char!(state, '\r'),
                            ('t', _) => push_char!(state, '\u{0009}'),
                            ('v', _) => push_char!(state, '\u{000b}'),
                            ('\\', _) => push_char!(state, '\\'),
                            ('\'', StringLexMode::Rune) => push_char!(state, '\''),
                            ('"', StringLexMode::InterpretedString) => push_char!(state, '"'),

                            ('0'..='7', _) => {
                                state.escape_mode = StringLexEscapeMode::EscapedUnicode {
                                    value: ch.to_digit(8).expect("char to be a valid octal digit"),
                                    read_count: 1,
                                    radix: 8,
                                    expected_count: 3,
                                    max_value: u32::from(u8::MAX),
                                }
                            }
                            ('x', _) => {
                                state.escape_mode = StringLexEscapeMode::EscapedUnicode {
                                    value: 0,
                                    read_count: 0,
                                    radix: 16,
                                    expected_count: 2,
                                    max_value: u32::from(u8::MAX),
                                }
                            }
                            ('u', _) => {
                                state.escape_mode = StringLexEscapeMode::EscapedUnicode {
                                    value: 0,
                                    read_count: 0,
                                    radix: 16,
                                    expected_count: 4,
                                    max_value: u32::MAX,
                                }
                            }
                            ('U', _) => {
                                state.escape_mode = StringLexEscapeMode::EscapedUnicode {
                                    value: 0,
                                    read_count: 0,
                                    radix: 16,
                                    expected_count: 8,
                                    max_value: u32::MAX,
                                }
                            }

                            (_, _) => {
                                // error: invalid char after backslash
                                let span = lexer.read_span().unwrap();
                                state.err = Some(LexingError::InvalidStringEscapeSequence(span));
                                return false;
                            }
                        }
                    }
                    StringLexEscapeMode::EscapedUnicode {
                        value,
                        read_count,
                        radix,
                        expected_count,
                        max_value,
                    } => {
                        if let Some((new_value, c)) = ch
                            .to_digit(*radix)
                            .and_then(|digit| value.checked_mul(*radix)?.checked_add(digit))
                            .filter(|v| v <= max_value)
                            .and_then(|v| char::from_u32(v).map(|c| (v, c)))
                        {
                            *value = new_value;
                            *read_count += 1;
                            if read_count >= expected_count {
                                push_char!(state, c);
                            }
                        } else {
                            // error: invalid digit
                            let span = lexer.read_span().unwrap();
                            state.err = Some(LexingError::InvalidStringEscapeSequence(span));
                            return false;
                        }
                    }
                }

                true
            },
        );

        self.enable_implicit_semicolon = prev_implicit_semicolon;

        if let Some(err) = state.err {
            return Err(err);
        }

        if !state.finished {
            // reached EOF before closing delimiter
            return Err(LexingError::UnclosedString);
        }

        match &state.mode {
            StringLexMode::Rune => match state.last_char {
                Some(c) => Ok(Token::new(TokenKind::Rune(c), span)),
                None => Err(LexingError::EmptyRune(span)),
            },
            StringLexMode::InterpretedString | StringLexMode::RawString => {
                Ok(Token::new(TokenKind::String(state.string), span))
            }
            StringLexMode::Unknown => {
                unreachable!("function string_like_literal called on non-string boundary")
            }
        }
    }

    fn period_or_ellipsis(&mut self) -> LResult<'a> {
        // cannot use greedy since ".." is not a valid token..

        // we can't use &view[..3] == "..." because ..3 might fall
        // outside char boundaries, e.g. "..ü" would panic
        let upcoming: Vec<_> = self.src.clone().take(3).collect();

        let token = if upcoming.len() == 3 && upcoming.iter().all(|x| *x == '.') {
            Token::new(TokenKind::Ellipsis, self.read_n(3))
        } else if upcoming.first() == Some(&'.') {
            if upcoming.get(1).is_some_and(char::is_ascii_digit) {
                // float literal with elided integer part, such as .25 == 0.25
                return self.number_literal();
            }

            // just a normal period
            Token::new(TokenKind::Period, self.read_span().unwrap())
        } else {
            unreachable!("invoker code did not check for a period!")
        };

        Ok(token)
    }

    fn greedy(&mut self, tree: &TokenOptionsTree<'static>) -> Token<'a> {
        // cannot pass tree directly as initial state since the first
        // iteration needs to take place before any checking so that
        // the first char (already peeked) is included in the final span

        let (span, node) = self.accumulate_while(None, move |ch, state, _| {
            if let &mut Some(&TokenOptionsTree { options, .. }) = state {
                for (key, branch) in options {
                    if ch == *key {
                        *state = Some(branch);
                        return true;
                    }
                }

                false
            } else {
                *state = Some(tree);

                true
            }
        });

        Token::new(node.unwrap().base.clone(), span)
    }
}

struct TokenOptionsTree<'a> {
    base: TokenKind,
    options: &'a [(char, TokenOptionsTree<'a>)],
}

impl<'a> Iterator for Lexer<'a> {
    type Item = LResult<'a>;

    #[allow(clippy::too_many_lines)]
    fn next(&mut self) -> Option<Self::Item> {
        macro_rules! single_char_token {
            ($kind:expr) => {
                Token::new($kind, self.read_span().unwrap())
            };
        }

        macro_rules! tree {
            ($base:expr, $options:expr) => {
                TokenOptionsTree {
                    base: $base,
                    options: $options,
                }
            };
        }

        macro_rules! single_or_eq {
            ($single:expr, $eq:expr) => {
                self.greedy(&tree!($single, &[('=', tree!($eq, &[]))]))
            };
        }

        macro_rules! double_or_eq {
            ($ch:expr, $single:expr, $double:expr, $eq:expr) => {
                self.greedy(&tree!(
                    $single,
                    &[($ch, tree!($double, &[])), ('=', tree!($eq, &[])),]
                ))
            };
        }

        if let Some(queued) = self.queue.pop_front() {
            if self.last_token_kind == Some(TokenKind::SemiColon) {
                self.last_annotation.take(); // clear
            }
            // ^ we check last token kind instead of the new `queued`'s kind
            // since otherwise .peek()'ing on a SemiColon would trigger an
            // annotation flush; this should defer the clearing until after
            // any potential annotation has had time to be extracted

            self.last_token_kind = Some(queued.kind.clone());

            return Some(Ok(queued));
        }

        self.try_extract_build_constraint();
        self.try_extract_legacy_build_constraints();
        // legacy extraction may advance directly to a modern directive, so we
        // try it again now from the new position
        self.try_extract_build_constraint();

        if let Err(err) = self.skip_comments() {
            return Some(Err(err));
        }

        let token = match self.peek_char() {
            Some(';') => single_char_token!(TokenKind::SemiColon),
            Some(',') => single_char_token!(TokenKind::Comma),
            Some('(') => single_char_token!(TokenKind::ParenL),
            Some(')') => single_char_token!(TokenKind::ParenR),
            Some('[') => single_char_token!(TokenKind::SquareL),
            Some(']') => single_char_token!(TokenKind::SquareR),
            Some('{') => single_char_token!(TokenKind::CurlyL),
            Some('}') => single_char_token!(TokenKind::CurlyR),
            Some('~') => single_char_token!(TokenKind::Tilde),

            Some(':') => single_or_eq!(TokenKind::Colon, TokenKind::ColonAssign),
            Some('*') => single_or_eq!(TokenKind::Star, TokenKind::StarAssign),
            Some('/') => single_or_eq!(TokenKind::Slash, TokenKind::SlashAssign),
            Some('%') => single_or_eq!(TokenKind::Percent, TokenKind::PercentAssign),
            Some('^') => single_or_eq!(TokenKind::Caret, TokenKind::CaretAssign),
            Some('!') => single_or_eq!(TokenKind::Excl, TokenKind::NotEq),
            Some('=') => single_or_eq!(TokenKind::Assign, TokenKind::DoubleEq),

            Some('+') => double_or_eq!(
                '+',
                TokenKind::Plus,
                TokenKind::PlusPlus,
                TokenKind::PlusAssign
            ),
            Some('-') => double_or_eq!(
                '-',
                TokenKind::Minus,
                TokenKind::MinusMinus,
                TokenKind::MinusAssign
            ),
            Some('|') => double_or_eq!(
                '|',
                TokenKind::Pipe,
                TokenKind::DoublePipe,
                TokenKind::PipeAssign
            ),

            Some('.') => match self.period_or_ellipsis() {
                Ok(token) => token,
                err @ Err(_) => return Some(err),
            },

            Some('&') => self.greedy(&tree!(
                TokenKind::Amp,
                &[
                    ('&', tree!(TokenKind::DoubleAmp, &[])),
                    ('=', tree!(TokenKind::AmpAssign, &[])),
                    (
                        '^',
                        tree!(
                            TokenKind::AmpCaret,
                            &[('=', tree!(TokenKind::AmpCaretAssign, &[]))]
                        )
                    ),
                ]
            )),
            Some('<') => self.greedy(&tree!(
                TokenKind::Lt,
                &[
                    ('=', tree!(TokenKind::LtEq, &[])),
                    ('-', tree!(TokenKind::LtMinus, &[])),
                    (
                        '<',
                        tree!(
                            TokenKind::DoubleLt,
                            &[('=', tree!(TokenKind::DoubleLtAssign, &[]))]
                        )
                    )
                ]
            )),
            Some('>') => self.greedy(&tree!(
                TokenKind::Gt,
                &[
                    ('=', tree!(TokenKind::GtEq, &[])),
                    (
                        '>',
                        tree!(
                            TokenKind::DoubleGt,
                            &[('=', tree!(TokenKind::DoubleGtAssign, &[]))]
                        )
                    )
                ]
            )),

            Some(ch) if ch.is_ascii_digit() => match self.number_literal() {
                Ok(token) => token,
                err @ Err(_) => return Some(err),
            },
            Some('\'' | '"' | '`') => match self.string_like_literal() {
                Ok(token) => token,
                err @ Err(_) => return Some(err),
            },

            Some(ch) if is_letter(ch) => self.identifier_or_keyword(),
            Some(ch) if is_whitespace(ch) => {
                self.read_char(); // advance iterator
                return self.next();
            }
            Some(_) => return Some(Err(LexingError::UnknownChar(self.read_span().unwrap()))),
            None => {
                if self
                    .last_token_kind
                    .as_ref()
                    .is_some_and(TokenKind::allows_implicit_semicolon)
                {
                    let token = Token::new(
                        TokenKind::SemiColon,
                        Span::new(self.src.as_str(), self.offset),
                    );

                    self.last_token_kind = Some(TokenKind::SemiColon);
                    self.last_annotation.take();

                    return Some(Ok(token));
                }

                return None;
            }
        };

        self.last_token_kind = Some(token.kind.clone());

        if matches!(token.kind, TokenKind::SemiColon | TokenKind::CurlyR) {
            self.last_annotation.take(); // clear
        }

        Some(Ok(token))
    }
}

// character utility functions, as defined by Go spec

fn is_letter(ch: char) -> bool {
    ch.is_letter() || ch == '_'
}

fn is_unicode_digit(ch: char) -> bool {
    ch.is_number_decimal()
}

fn is_whitespace(ch: char) -> bool {
    matches!(ch, ' ' | '\t' | '\r' | '\n')
}

fn build_constraint_expression_range(line: &str) -> Option<Range<usize>> {
    let after_marker = line.strip_prefix(BUILD_CONSTRAINT_MARKER)?;

    if after_marker
        .chars()
        .next()
        .is_some_and(|ch| !ch.is_whitespace())
    {
        return None;
    }

    let expression = after_marker.trim();
    let start = BUILD_CONSTRAINT_MARKER.len()
        + (
            // skip whitespace between `//go:build` and the expression
            after_marker.len() - after_marker.trim_start().len()
        );

    Some(start..(start + expression.len()))
}

#[derive(Clone)]
pub struct LegacyBuildConstraints<'a> {
    lines: Vec<Span<'a>>,
    location: Location,
}

impl<'a> LegacyBuildConstraints<'a> {
    pub fn lines(&self) -> &[Span<'a>] {
        &self.lines
    }

    pub fn location(&self) -> &Location {
        &self.location
    }
}

fn legacy_build_constraint_expression_range(line: &str) -> Option<Range<usize>> {
    let comment = line.strip_prefix("//")?;
    let prefix_whitespace = comment.len() - comment.trim_start().len();
    let after_prefix = comment.trim_start().strip_prefix("+build")?;

    if after_prefix
        .chars()
        .next()
        .is_some_and(|ch| !ch.is_whitespace())
    {
        return None;
    }

    let expression = after_prefix.trim();
    let start = 2
        + prefix_whitespace
        + "+build".len()
        + (after_prefix.len() - after_prefix.trim_start().len());

    Some(start..(start + expression.len()))
}

// truly a sign of decaying times; see invoker for more context
fn parse_hexadecimal_float(s: &str) -> f64 {
    // we (perhaps foolishly) assume that the string is structurally correct
    // (i.e., resembles a float in shape), and thus unwrap away -- in theory
    // this should be fine since we manually created the string inside the lexer
    // ourselves and already validated most conditions and edge cases
    // (note: no 0x prefix is expected; this is removed before invocation)

    let (mantissa_str, exp) = match s.split_once(['p', 'P']) {
        Some((m, e)) => (m, Some(e.parse().unwrap())), // exponent is i32 for f64
        None => (s, None),
        // ^ technically it's not valid Go to omit the exponent in a hexadecimal
        // float, but we have no easy way to propagate this error since we can't
        // construct a ParseFloatError, so we just deal with it
    };

    let (int_part, frac_part) = match mantissa_str.split_once('.') {
        Some((i, f)) => (i, f),
        None => (mantissa_str, ""),
    };

    let mut mantissa = 0.0_f64;

    #[allow(clippy::cast_precision_loss)]
    if !int_part.is_empty() {
        mantissa += u64::from_str_radix(int_part, 16).unwrap() as f64;
    }

    if !frac_part.is_empty() {
        for (i, ch) in frac_part.chars().enumerate() {
            let digit = ch.to_digit(16).unwrap();

            // `i` will never be huge (max = # of digits), so unwrap is safe
            mantissa += f64::from(digit) / 16_f64.powi(i32::try_from(i + 1).unwrap());
        }
    }

    mantissa * exp.map_or(1.0, |e| 2_f64.powi(e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::TokenKind;

    fn lex(src: &str) -> Result<Vec<Token<'_>>, LexingError<'_>> {
        Lexer::new(src).collect::<Result<Vec<_>, _>>()
    }

    #[test]
    fn package() {
        assert_eq!(
            vec![
                Token::new(TokenKind::Package, Span::new("package", 2)),
                Token::new(TokenKind::Ident, Span::new("hello", 16)),
                Token::new(TokenKind::SemiColon, Span::new("", 21)),
            ],
            lex("  package    \t\n\nhello").unwrap(),
        );
    }

    #[test]
    fn int_lits() {
        assert_eq!(
            vec![
                Token::new(TokenKind::Int(3), Span::new("3", 2)),
                Token::new(TokenKind::Int(50), Span::new("50", 4)),
                Token::new(TokenKind::Int(29), Span::new("0b11101", 7)),
                Token::new(TokenKind::Int(505), Span::new("0o771", 15)),
                Token::new(TokenKind::Int(3909), Span::new("0xf45", 21)),
                Token::new(TokenKind::SemiColon, Span::new("\n", 26)),
                Token::new(TokenKind::Int(123), Span::new("0123", 28)),
                Token::new(TokenKind::Int(0), Span::new("0", 33)),
                Token::new(TokenKind::SemiColon, Span::new("", 34)),
            ],
            lex("\t 3 50 0b11101 0o771 0xf45\n 0123 0").unwrap()
        );
    }

    #[test]
    fn float_lits() {
        assert_eq!(
            vec![
                Token::new(TokenKind::Float(0.0), Span::new("0.", 2)),
                Token::new(TokenKind::Float(72.4), Span::new("72.40", 5)),
                Token::new(TokenKind::Float(72.4), Span::new("072.40", 11)),
                #[allow(clippy::approx_constant)]
                Token::new(TokenKind::Float(2.71828), Span::new("2.71828", 18)),
                Token::new(TokenKind::Float(1.0), Span::new("1.e+0", 26)),
                Token::new(TokenKind::SemiColon, Span::new("\n", 31)),
                Token::new(TokenKind::Float(6.6742e-11), Span::new("6.6742e-11", 33)),
                Token::new(TokenKind::Float(1_000_000.0), Span::new("1E6", 44)),
                Token::new(TokenKind::Float(0.25), Span::new(".25", 48)),
                Token::new(TokenKind::Float(12345.0), Span::new(".12345E+5", 52)),
                Token::new(TokenKind::Float(15.0), Span::new("15.", 62)),
                Token::new(TokenKind::Float(15.0), Span::new("0.15e+02", 66)),
                Token::new(TokenKind::Float(0.25), Span::new("0x1p-2", 76)),
                Token::new(TokenKind::Float(2048.0), Span::new("0x2.p10", 83)),
                Token::new(TokenKind::Float(1.9375), Span::new("0x1.Fp+0", 91)),
                Token::new(TokenKind::Float(0.5), Span::new("0X.8p-0", 100)),
                Token::new(
                    TokenKind::Float(0.124_984_741_210_937_5),
                    Span::new("0X1FFFP-16", 108)
                ),
                Token::new(TokenKind::SemiColon, Span::new("", 118)),
            ],
            lex(concat!(
                "\t 0. 72.40 072.40 2.71828 1.e+0\n 6.6742e-11 1E6 .25 .12345E+5 15. 0.15e+02",
                "\t 0x1p-2 0x2.p10 0x1.Fp+0 0X.8p-0 0X1FFFP-16"
            ))
            .unwrap()
        );
    }

    #[test]
    fn underscores() {
        assert_eq!(
            vec![
                Token::new(TokenKind::Int(42), Span::new("4_2", 2)),
                Token::new(TokenKind::Int(600), Span::new("0_600", 6)),
                Token::new(TokenKind::Int(195_951_310), Span::new("0xBad_Face", 12)),
                Token::new(
                    TokenKind::Int(170_141_183_460_469),
                    Span::new("170_141183_460469", 23)
                ),
                Token::new(TokenKind::SemiColon, Span::new("\n", 40)),
                Token::new(TokenKind::Float(15.0), Span::new("1_5.", 41)),
                Token::new(TokenKind::Float(15.0), Span::new("0.15e+0_2", 46)),
                Token::new(
                    TokenKind::Float(0.124_984_741_210_937_5),
                    Span::new("0X_1FFFP-16", 56)
                ),
                Token::new(TokenKind::SemiColon, Span::new("", 67)),
            ],
            lex(concat!(
                "\t 4_2 0_600 0xBad_Face 170_141183_460469\n",
                "1_5. 0.15e+0_2 0X_1FFFP-16"
            ))
            .unwrap()
        );
    }

    #[test]
    fn rune_lits() {
        assert_eq!(
            vec![
                Token::new(TokenKind::Rune('a'), Span::new("'a'", 2)),
                Token::new(TokenKind::Rune('\u{0007}'), Span::new("'\\a'", 6)),
                Token::new(TokenKind::Rune('\n'), Span::new("'\\n'", 11)),
                Token::new(TokenKind::SemiColon, Span::new("\n", 15)),
                Token::new(TokenKind::Rune('\''), Span::new("'\\''", 17)),
                Token::new(TokenKind::Rune('ä'), Span::new("'ä'", 22)),
                Token::new(TokenKind::Rune('本'), Span::new("'本'", 27)),
                Token::new(TokenKind::Rune('\t'), Span::new("'\\t'", 33)),
                Token::new(TokenKind::Rune('\t'), Span::new("'\t'", 38)),
                Token::new(TokenKind::Rune('\0'), Span::new("'\\000'", 42)),
                Token::new(TokenKind::Rune('\x07'), Span::new("'\\007'", 49)),
                Token::new(TokenKind::Rune('\u{ff}'), Span::new("'\\377'", 56)),
                Token::new(TokenKind::Rune('\u{07}'), Span::new("'\\x07'", 63)),
                Token::new(TokenKind::Rune('\u{ff}'), Span::new("'\\xff'", 70)),
                Token::new(TokenKind::Rune('\u{12e4}'), Span::new("'\\u12e4'", 77)),
                Token::new(
                    TokenKind::Rune('\u{101234}'),
                    Span::new("'\\U00101234'", 86)
                ),
                Token::new(TokenKind::SemiColon, Span::new("", 100)),
            ],
            lex(
                "\t 'a' '\\a' '\\n'\n '\\'' 'ä' '本' '\\t' '\t' '\\000' '\\007' '\\377' '\\x07' \
                 '\\xff' '\\u12e4' '\\U00101234'  "
            )
            .unwrap()
        );

        assert_eq!(
            Err(LexingError::MultipleCharactersInRune(Span::new("a", 2))),
            lex("'aa'")
        );
        assert_eq!(
            Err(LexingError::InvalidStringEscapeSequence(Span::new("k", 2))),
            lex("'\\k'")
        );
        assert_eq!(
            Err(LexingError::InvalidStringEscapeSequence(Span::new("'", 4))),
            lex("'\\xa'")
        );
        assert_eq!(
            Err(LexingError::InvalidStringEscapeSequence(Span::new("'", 3))),
            lex("'\\0'")
        );
        assert_eq!(
            Err(LexingError::InvalidStringEscapeSequence(Span::new("0", 4))),
            lex("'\\400'")
        );
        assert_eq!(
            Err(LexingError::InvalidStringEscapeSequence(Span::new("F", 6))),
            lex("'\\uDFFF'")
        );
        assert_eq!(
            Err(LexingError::InvalidStringEscapeSequence(Span::new("0", 10))),
            lex("'\\U00110000'")
        );
        assert_eq!(
            Err(LexingError::InvalidStringEscapeSequence(Span::new("\"", 2))),
            lex("'\\\"'")
        );
        assert_eq!(Err(LexingError::EmptyRune(Span::new("''", 0))), lex("''"));
        assert_eq!(Err(LexingError::UnclosedString), lex("'"));
    }

    #[test]
    fn string_lits() {
        macro_rules! s {
            ($lit:expr) => {
                $lit.to_owned()
            };
        }

        assert_eq!(
            vec![
                Token::new(TokenKind::String(s!("abc")), Span::new("`abc`", 4)),
                Token::new(
                    TokenKind::String(s!("\\n\n\\n")),
                    Span::new("`\\n\n\\n`", 10)
                ),
                Token::new(TokenKind::String(s!("\n")), Span::new("\"\\n\"", 18)),
                Token::new(TokenKind::String(s!("\"")), Span::new("\"\\\"\"", 23)),
                Token::new(TokenKind::SemiColon, Span::new("\n", 27)),
                Token::new(
                    TokenKind::String(s!("Hello, world!\n")),
                    Span::new("\"Hello, world!\\n\"", 29)
                ),
                Token::new(TokenKind::String(s!("日本語")), Span::new("\"日本語\"", 47)),
                Token::new(
                    TokenKind::String(s!("\u{65e5}本\u{008a9e}")),
                    Span::new("\"\\u65e5本\\U00008a9e\"", 59)
                ),
                Token::new(
                    TokenKind::String(s!("\u{ff}\u{00FF}")),
                    Span::new("\"\\xff\\u00FF\"", 81)
                ),
                Token::new(TokenKind::String(s!("a\nb")), Span::new("`a\n\rb`", 94)),
                Token::new(TokenKind::String(s!("")), Span::new("\"\"", 101)),
                Token::new(TokenKind::String(s!("")), Span::new("``", 104)),
                Token::new(TokenKind::SemiColon, Span::new("", 108)),
            ],
            lex(
                "  \t `abc` `\\n\n\\n` \"\\n\" \"\\\"\"\n \"Hello, world!\\n\" \"日本語\" \
                 \"\\u65e5本\\U00008a9e\" \"\\xff\\u00FF\" `a\n\rb` \"\" ``  "
            )
            .unwrap()
        );

        assert_eq!(
            Err(LexingError::InvalidStringEscapeSequence(Span::new("0", 6))),
            lex("\"\\uD800\"")
        );
        assert_eq!(
            Err(LexingError::InvalidStringEscapeSequence(Span::new("0", 10))),
            lex("\"\\U00110000\"")
        );
        assert_eq!(
            Err(LexingError::LineBreakInString(Span::new("\n", 2))),
            lex("\"a\nb\"")
        );
        assert_eq!(
            Err(LexingError::LineBreakInString(Span::new("\n", 2))),
            lex("\"a\nb\"")
        );
        assert_eq!(
            Err(LexingError::InvalidStringEscapeSequence(Span::new("'", 2))),
            lex("\"\\'\"")
        );
        assert_eq!(Err(LexingError::UnclosedString), lex("\"aa"));
    }

    #[test]
    fn greedy() {
        assert_eq!(
            vec![
                Token::new(TokenKind::Gt, Span::new(">", 0)),
                Token::new(TokenKind::Excl, Span::new("!", 2)),
                Token::new(TokenKind::DoubleEq, Span::new("==", 4)),
                Token::new(TokenKind::NotEq, Span::new("!=", 7)),
                Token::new(TokenKind::AmpCaret, Span::new("&^", 10)),
                Token::new(TokenKind::AmpCaretAssign, Span::new("&^=", 13)),
                Token::new(TokenKind::Comma, Span::new(",", 17)),
                Token::new(TokenKind::DoubleGt, Span::new(">>", 19)),
                Token::new(TokenKind::Gt, Span::new(">", 21))
            ],
            lex("> ! == != &^ &^= , >>>").unwrap()
        );
    }
}
