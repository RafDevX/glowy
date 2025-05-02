use crate::symbols::SymbolTable;

pub struct AnalysisContext<'a> {
    /// Current step of the analysis
    stage: AnalysisStage,
    /// Global symbol manager, including all scope logic
    symbol_table: SymbolTable<'a>,
}

impl AnalysisContext<'_> {
    pub fn new() -> Self {
        AnalysisContext {
            stage: AnalysisStage::default(),
            symbol_table: SymbolTable::new(),
        }
    }

    pub fn set_stage(&mut self, stage: AnalysisStage) {
        self.stage = stage;
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
