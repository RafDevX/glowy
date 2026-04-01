// Clippy lint configuration
#![warn(clippy::all, clippy::pedantic, clippy::missing_inline_in_public_items)]
#![allow(clippy::option_option, clippy::missing_errors_doc)]

use std::ops::Range;

use ast::SourceFileNode;
pub use errors::{Diagnostics, ErrorDiagnosticInfo, ParsingError};
use lexer::Lexer;
pub use lexer::LexingError;
use stream::TokenStream;
pub use token::{Annotation, Token, TokenKind};

use crate::parser::parse_source_file;

pub mod ast;
mod errors;
mod lexer;
mod parser;
mod stream;
mod token;

// this should be scoped by file, or only used in contexts
// where the file referred to is obvious
pub type Location = Range<usize>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span<'a> {
    content: &'a str,
    offset: usize,
    line: usize,
}

impl<'a> Span<'a> {
    #[must_use]
    #[inline]
    pub fn new(content: &'a str, offset: usize, line: usize) -> Self {
        Self {
            content,
            offset,
            line,
        }
    }

    #[must_use]
    #[inline]
    pub fn content(&self) -> &'a str {
        self.content
    }

    #[must_use]
    #[inline]
    pub fn location(&self) -> Range<usize> {
        self.offset..(self.offset + self.content.len())
    }
}

#[allow(clippy::missing_inline_in_public_items)]
pub fn parse(input: &str) -> Result<SourceFileNode<'_>, ParsingError<'_>> {
    let mut stream = TokenStream::new(Lexer::new(input));

    parse_source_file(&mut stream)
}
