pub struct AnalysisContext {
    stage: AnalysisStage,
}

impl AnalysisContext {
    pub fn new() -> Self {
        AnalysisContext {
            stage: AnalysisStage::default(),
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
