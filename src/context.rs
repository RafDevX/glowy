use std::{fmt, path::Path};

use crate::{
    errors::{AnalysisError, AnalysisErrorKind},
    symbols::{SymbolRef, SymbolTable},
    Pinned,
};

pub struct AnalysisContext<'a> {
    /// Current step of the analysis
    stage: AnalysisStage,
    /// Global symbol manager, including all scope logic
    symbol_table: SymbolTable<'a>,
    /// Current file under analysis (absolute path, where root = module base)
    current_file: Option<&'a Path>,
    /// Errors emitted during analysis
    errors: Vec<AnalysisError<'a>>,
}

impl<'a> AnalysisContext<'a> {
    pub fn new() -> Self {
        AnalysisContext {
            stage: AnalysisStage::default(),
            symbol_table: SymbolTable::new(),
            current_file: None,
            errors: Vec::new(),
        }
    }

    pub fn symtab(&self) -> &SymbolTable<'a> {
        &self.symbol_table
    }

    pub fn symtab_mut(&mut self) -> &mut SymbolTable<'a> {
        &mut self.symbol_table
    }

    pub fn set_stage(&mut self, stage: AnalysisStage) {
        self.stage = stage;
    }

    pub fn set_current_file(&mut self, virtual_path: &'a Path) {
        self.current_file = Some(virtual_path);
    }

    pub fn report_error(&mut self, kind: AnalysisErrorKind<'a>) {
        if let Some(file) = self.current_file {
            if self.stage.admits_errors() {
                self.errors.push(AnalysisError { file, kind });
            }
        }
    }

    pub fn pin<T: Clone + fmt::Debug + PartialEq>(&self, inner: T) -> Pinned<T> {
        let file = self
            .current_file
            .expect("some file should be under analysis")
            .to_owned();

        Pinned::new(file, inner)
    }

    /// Shorthand to declare a new symbol in the [`SymbolTable`] and report
    /// an error if the current scope already had it defined.
    ///
    /// This method should not be used if redeclarations are allowed (i.e., in
    /// some multi-variable short declarations, under some circumstances, as
    /// defined in the Go spec).
    pub fn declare_new_symbol(&mut self, symbol: SymbolRef<'a>) {
        let name = symbol.borrow().declared_name().clone();

        if let Some(existing) = self.symbol_table.declare_new_symbol(name.content(), symbol) {
            if *existing.borrow().declared_name() == name {
                // we do multiple passes over the source code, so it's not an
                // error if a previous declaration is at the same location as
                // this "new" one (i.e., if they're actually the same)
                return;
            }

            self.report_error(AnalysisErrorKind::IllegalRedeclaration {
                previous: existing.borrow().declared_name().clone(),
                found: name.inner().clone(),
            });
        }
    }
}

impl Default for AnalysisContext<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> From<AnalysisContext<'a>> for Result<(), Vec<AnalysisError<'a>>> {
    fn from(ctx: AnalysisContext<'a>) -> Self {
        if ctx.errors.is_empty() {
            Ok(())
        } else {
            Err(ctx.errors)
        }
    }
}

#[derive(Default)]
pub enum AnalysisStage {
    /// Scan all files for top-level declarations and record them
    #[default]
    RecordDeclarations,
    StabilizeLabels,
    EnforceSecurityPolicies,
}

impl AnalysisStage {
    #[inline]
    fn admits_errors(&self) -> bool {
        matches!(
            self,
            Self::RecordDeclarations | Self::EnforceSecurityPolicies
        )
    }
}
