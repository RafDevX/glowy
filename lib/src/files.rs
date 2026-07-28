use std::{
    fs, io,
    path::{Path, PathBuf},
};

/// Represents a file containing Go source code.
///
/// This struct encapsulates a source file's contents and metadata so that it
/// may be used in analysis by an instance of [`Analyzer`](crate::Analyzer).
///
/// # Example Usage
///
/// ```no_run
/// let mut analyzer = glowy::Analyzer::new("example.com/company-name/proj");
/// let file = glowy::SourceFile::read_from_disk("/main.go", "./proj/main.go")?;
/// analyzer.add_file(file);
///
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SourceFile {
    virtual_path: PathBuf, // relative to module base
    contents: String,
}

impl SourceFile {
    /// Constructs a new [`SourceFile`].
    ///
    /// The `virtual_path` argument must be absolute, with the root
    /// corresponding to the module base, and include a filename with extension
    /// `.go`.
    ///
    /// # Panics
    ///
    /// This method may panic if `virtual_path` has no root or does not
    /// reference a Go filename.
    ///
    /// # Example Usage
    ///
    /// ```
    /// let file1 = glowy::SourceFile::new("/main.go", "package something;");
    /// let file2 = glowy::SourceFile::new("/auth/oidc.go", "package auth;");
    /// ```
    ///
    /// # See Also
    ///
    /// In many cases, the file content is read dynamically from disk at
    /// runtime. In such cases, the [`SourceFile::read_from_disk`] utility will
    /// likely prove more useful than using this method directly.
    #[inline]
    pub fn new<P: Into<PathBuf>, C: Into<String>>(virtual_path: P, contents: C) -> Self {
        let virtual_path = virtual_path.into();

        assert!(
            virtual_path.has_root() && virtual_path.extension().is_some_and(|e| e == "go"),
            "Glowy: could not instantiate SourceFile with invalid virtual_path `{}`",
            virtual_path.display()
        );

        Self {
            virtual_path,
            contents: contents.into(),
        }
    }

    /// Constructs a new [`SourceFile`], extracting contents from a real file.
    ///
    /// This method is a wrapper around [`SourceFile::new`] that reads its
    /// `contents` parameter (raw Go source code, as a String) from a real file
    /// on disk.
    ///
    /// # Panics
    ///
    /// The underlying [`SourceFile::new`] method may panic if an incorrect
    /// `virtual_path` parameter is passed. See its documentation to learn the
    /// conditions under which this may happen.
    ///
    /// # Errors
    ///
    /// If any error occurs while opening or reading the file residing at
    /// `real_path` (such as if it does not exist or is not valid UTF-8), the
    /// underlying [`std::io::Error`] will be propagated.
    ///
    /// # Example usage
    ///
    /// ```no_run
    /// let file = glowy::SourceFile::read_from_disk(
    ///     "/auth/oidc.go",       // virtual path (relative to module base)
    ///     "./proj/auth/oidc.go", // real path on disk (relative to cwd)
    /// )?;
    ///
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[inline]
    pub fn read_from_disk<V: Into<PathBuf>, R: AsRef<Path>>(
        virtual_path: V,
        real_path: R,
    ) -> io::Result<Self> {
        let contents = fs::read_to_string(&real_path)?;

        Ok(Self::new(virtual_path.into(), contents))
    }

    /// Returns the source file's virtual path.
    ///
    /// This virtual path is always rooted and bound to the Go module base.
    /// For example, `/auth/oidc.go` or `/main.go` correspond to specific Go
    /// files within the module hierarchy, but do not (necessarily) match the
    /// files' real paths on disk.
    #[must_use]
    #[inline]
    pub fn virtual_path(&self) -> &Path {
        &self.virtual_path
    }

    /// Returns the file's contents (Go source code).
    ///
    /// Note that each file is only read from the filesystem at most one time
    /// (if ever), so any changes to some underlying real file on disk will not
    /// be reflected here.
    #[must_use]
    #[inline]
    pub fn contents(&self) -> &str {
        &self.contents
    }
}
