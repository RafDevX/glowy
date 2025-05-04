use std::path::Path;

use crate::{
    errors::{AnalysisError, AnalysisErrorKind},
    symbols::SymbolTable,
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
