use std::{fmt, path::Path};

use parser::Location;

use crate::{
    Pinned, SinkDescriptor,
    errors::{AnalysisError, AnalysisErrorKind},
    labels::{Label, LabelBacktrace, LabelBacktraceKind},
    symbols::{SymbolRef, SymbolTable},
    values::{FunctionRef, SelfAwareBacktraceContainer, ValueRef},
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

    /// Current stack of functions being declared
    funcs: Vec<ValueRef<'a>>,

    /// Stack of (independent but always a child of previous) branch backtraces
    branch_backtraces: Vec<LabelBacktrace<'a>>,
    /// Branch backtraces that are out of scope but are still in effect.
    ///
    /// This happens as a result of flow-altering statements like `return`,
    /// `continue`, and `break`. For example:
    /// ```go
    /// if cond {
    ///     return
    /// }
    ///
    /// something // label backtrace from cond must remain in effect here
    /// ```
    deferred_branch_backtraces: Vec<DeferredBranchBacktrace<'a>>,
    /// Composition of the last branch backtraces with all the deferred.
    current_calculated_branch_backtrace: Option<LabelBacktrace<'a>>,
    /// How many levels deep analysis currently is within loops/functions.
    ///
    /// Keeping track of this is necessary to correctly support
    /// [`Self::deferred_branch_backtraces`] so that nested structures (such as
    /// loops or functions) can be analyzed properly. For example:
    /// ```go
    /// for {
    ///     if cond {
    ///         break // cond backtrace is deferred to boundary of InnermostLoop
    ///     }
    ///
    ///     for {
    ///         break
    ///         // without a notion of depth at time of defer, the end of this
    ///         // inner loop would lead to the deferred cond backtrace to be
    ///         // popped here, even though it should remain until the end of
    ///         // the outer loop
    ///     }
    /// }
    /// ```
    current_branch_scope_depth: u8,
}

impl<'a> AnalysisContext<'a> {
    pub fn new() -> Self {
        AnalysisContext {
            stage: AnalysisStage::default(),
            symbol_table: SymbolTable::new(),
            current_file: None,
            errors: Vec::new(),
            funcs: Vec::new(),
            branch_backtraces: Vec::new(),
            deferred_branch_backtraces: Vec::new(),
            current_calculated_branch_backtrace: None,
            current_branch_scope_depth: 0,
        }
    }

    pub fn symtab(&self) -> &SymbolTable<'a> {
        &self.symbol_table
    }

    pub fn symtab_mut(&mut self) -> &mut SymbolTable<'a> {
        &mut self.symbol_table
    }

    pub fn stage(&self) -> &AnalysisStage {
        &self.stage
    }

    pub fn set_stage(&mut self, stage: AnalysisStage) {
        self.stage = stage;
    }

    pub fn current_file(&self) -> Option<&'a Path> {
        self.current_file
    }

    pub fn set_current_file(&mut self, virtual_path: &'a Path) {
        self.current_file = Some(virtual_path);
    }

    pub fn current_function(&self) -> Option<ValueRef<'a>> {
        // FIXME: ideally, would .and_then(|v| v.as_function()) here so that we
        // could return Option<Ref<FunctionValue<'a>>>, but borrow checker hates
        // that because we'd return a reference to a temporary value (v) -- it
        // cannot tell that all values are stored in symbols anyway so it's ok,
        // meaning that we must offload this function-checking to the invoker

        self.funcs.last().cloned()
    }

    pub fn push_function(&mut self, func: ValueRef<'a>) {
        self.funcs.push(func);
    }

    pub fn pop_function(&mut self) {
        self.funcs.pop();
    }

    pub fn branch_backtrace(&self) -> Option<&LabelBacktrace<'a>> {
        self.current_calculated_branch_backtrace
            .as_ref()
            .or(self.branch_backtraces.last())
    }

    pub fn push_branch_backtrace(&mut self, backtrace: LabelBacktrace<'a>) {
        // merge with existing branch label so that the new one can be used
        // everywhere on its own without having to worry about the old ones
        let composite = if let Some(existing) = self.branch_backtrace() {
            backtrace.with_child(existing)
        } else {
            backtrace
        };

        self.branch_backtraces.push(composite);

        self.calculate_composite_branch_backtrace();
    }

    pub fn pop_branch_backtrace(&mut self) {
        self.branch_backtraces.pop();

        self.calculate_composite_branch_backtrace();
    }

    pub fn defer_branch_backtrace(&mut self, until: DeferTarget<'a>, location: Location) {
        let Some(backtrace) = self.branch_backtrace().cloned() else {
            // nothing to do
            return;
        };

        let deferred = DeferredBranchBacktrace {
            backtrace,
            until,
            at_depth: self.current_branch_scope_depth,
            because: self.pin(location),
        };

        self.deferred_branch_backtraces.push(deferred);

        self.calculate_composite_branch_backtrace();
    }

    pub fn trigger_defer_target(&mut self, target: DeferTarget<'a>) {
        self.deferred_branch_backtraces.retain(|deferred| {
            deferred.until != target && deferred.at_depth < self.current_branch_scope_depth
        });

        self.calculate_composite_branch_backtrace();
    }

    fn calculate_composite_branch_backtrace(&mut self) {
        self.current_calculated_branch_backtrace = if self.deferred_branch_backtraces.is_empty() {
            // avoid cloning self.branch_backtraces.last():
            // it'll be read in the getter instead of cloned here
            None
        } else {
            LabelBacktrace::fold(
                self.branch_backtraces.last().into_iter().chain(
                    self.deferred_branch_backtraces
                        .iter()
                        .map(|deferred| &deferred.backtrace),
                ),
                LabelBacktraceKind::Branch,
                None,
                self.deferred_branch_backtraces
                    .last()
                    .map(|deferred| &deferred.because)
                    .cloned()
                    .unwrap(), // deferred is never empty; we checked
            )
        }
    }

    pub fn increase_branch_scope_depth(&mut self) {
        self.current_branch_scope_depth += 1;
    }

    pub fn decrease_branch_scope_depth(&mut self) {
        self.current_branch_scope_depth -= 1;
    }

    pub fn defer_enforcement_check(&mut self, check: DeferredEnforcementCheck<'a>) {
        let mut value = self.current_function().unwrap();
        // ^ should be safe if this method is used correctly (only within a fn)

        value.as_function_mut().unwrap().defer_check(check);
    }

    pub fn report_error_at(&mut self, file: &'a Path, kind: AnalysisErrorKind<'a>) {
        if self.stage.admits_errors() {
            self.errors.push(AnalysisError { file, kind });
        }
    }

    pub fn report_error(&mut self, kind: AnalysisErrorKind<'a>) {
        if let Some(file) = self.current_file {
            self.report_error_at(file, kind);
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

            if existing.borrow().declared_name().pinned_location() > name.pinned_location() {
                // the "existing" is actually a redeclaration of this
                // declaration, so we shouldn't report an error either
                return;
            }

            self.report_error(AnalysisErrorKind::IllegalRedeclaration {
                previous: existing.borrow().declared_name().clone(),
                found: *name.inner(),
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

    /// This returns whether the present stage if the first stage of analysis.
    ///
    /// If a value of false is returned, the invoker may assume that all input
    /// files have already been reviewed at least one (meaning that, for
    /// example, package clause and import spec registration should be complete)
    pub fn is_first(&self) -> bool {
        matches!(self, Self::RecordDeclarations)
    }
}

struct DeferredBranchBacktrace<'a> {
    backtrace: LabelBacktrace<'a>,
    until: DeferTarget<'a>,
    at_depth: u8,
    because: Pinned<Location>,
}

#[derive(Clone, Copy, PartialEq)]
pub enum DeferTarget<'a> {
    Function,
    InnermostLoop,
    LabeledLoop(&'a str),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DeferredEnforcementCheck<'a> {
    Sink {
        sink: SinkDescriptor<'a>,
        found: LabelBacktrace<'a>,
        file: &'a Path, // cannot use Pinned since lifetimes are important
    },
    Assertion {
        expected_sequence: Vec<Label<'a>>,
        found: Option<LabelBacktrace<'a>>,
        file: &'a Path, // cannot use Pinned since lifetimes are important
        location: Location,
    },
}

impl<'a> DeferredEnforcementCheck<'a> {
    // might return None if a sink enforcement check no longer makes sense
    // (`found` is now Bottom, so the check would always pass)
    pub fn realize(
        &self,
        from_func: &FunctionRef<'a>,
        from_index: Option<usize>, // None for receiver
        concrete: Option<&LabelBacktrace<'a>>,
    ) -> Option<Self> {
        let realized = match self {
            Self::Sink { sink, found, file } => Self::Sink {
                sink: sink.clone(),
                found: found.realize(from_func, from_index, concrete)?,
                file,
            },
            Self::Assertion {
                expected_sequence,
                found,
                file,
                location,
            } => Self::Assertion {
                expected_sequence: expected_sequence.clone(),
                found: found.realize(from_func, from_index, concrete),
                file,
                location: location.clone(),
            },
        };

        Some(realized)
    }
}
