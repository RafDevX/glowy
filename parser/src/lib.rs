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

/// Byte range locating a substring within a source file's contents.
///
/// This allows locating a specific substring within a file by referencing the
/// start and end byte indices (0-indexed). The actual substring is not
/// available without access to the original source, but such a use case is
/// provided by the closely-tied [`Span`].
///
/// Note that [`Location`] should always be scoped by file, or otherwise only be
/// used in contexts where the file to which it refers is obvious, as no source
/// file identifier is intrinsically stored (it is merely a relative reference).
pub type Location = Range<usize>;

/// Source file content snippet bound to a specific location.
///
/// This represents a reference to a concrete substring of a file's contents,
/// annotated with metadata allowing the snippet to be located within the file
/// (i.e., a [`Location`] instance can be derived via [`Span::location`]).
///
/// Note, however, that no information is stored regarding *which* file the
/// snippet was found in, as file identification and referencing is considered
/// to be a higher-level mechanism that should be accomplished somehow else.
///
/// [`Span`] implements [`Copy`] for maximum convenience, which is possible
/// since it mostly holds a reference to source file contents it does not own
/// (as indicated by the exposed lifetime `'a`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Span<'a> {
    content: &'a str,
    offset: usize,
    line: usize,
}

impl<'a> Span<'a> {
    /// Constructs a new localized source file snippet reference.
    #[must_use]
    #[inline]
    pub fn new(content: &'a str, offset: usize, line: usize) -> Self {
        Self {
            content,
            offset,
            line,
        }
    }

    /// Returns a reference to the underlying source code snippet.
    #[must_use]
    #[inline]
    pub fn content(&self) -> &'a str {
        self.content
    }

    /// Returns the calculated byte range where the snippet was found.
    #[must_use]
    #[inline]
    pub fn location(&self) -> Location {
        self.offset..(self.offset + self.content.len())
    }
}

#[allow(clippy::missing_inline_in_public_items)]
pub fn parse(input: &str) -> Result<SourceFileNode<'_>, ParsingError<'_>> {
    let mut stream = TokenStream::new(Lexer::new(input));

    parse_source_file(&mut stream)
}
