use std::{fmt, mem, path::Path};

use parser::{
    Location, Span,
    ast::{CallNode, FunctionParamDeclNode},
};

use crate::{
    FullPackagePath, Pinned, SinkDescriptor,
    decls::receiver_base_type_name,
    errors::{AnalysisError, AnalysisErrorKind},
    labels::{Label, LabelBacktrace, LabelBacktraceKind, SyntheticSlot},
    snapshots::SnapshotAware,
    symbols::{SymbolRef, SymbolTable},
    taint::{BlanketDirective, BlanketDirectives, GotoConvergenceState, ResolvedCall},
    types::TypeRegistry,
    values::{FunctionRef, SelfAwareBacktraceContainer, ValueRef},
};

pub struct AnalysisContext<'a> {
    /// Current step of the analysis.
    stage: AnalysisStage,
    /// Global symbol manager, including all scope logic.
    symbol_table: SymbolTable<'a>,
    /// Global registry of named types.
    type_registry: TypeRegistry<'a>,
    /// Current file under analysis (absolute path, where root = module base).
    current_file: Option<&'a Path>,
    /// Errors emitted during analysis.
    errors: Vec<AnalysisError<'a>>,

    /// Current stack of functions being declared.
    funcs: Vec<ValueRef<'a>>,
    // Current stack of stacks awaiting deferred execution (from `defer`).
    deferred_calls: Vec<Vec<DeferredCall<'a>>>,

    /// Stack of (independent but always a child of previous) branch backtraces.
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
    /// How many levels deep analysis will currently suppress reporting errors.
    ///
    /// While this is non-zero, [`Self::report_error_at`] (and any caller that
    /// goes through it, like [`Self::report_error`]) becomes a no-op. This is
    /// used by passes that must speculatively (re-)visit some piece of code
    /// for soundness reasons (e.g., the inner fix-point over a `for range`
    /// body) without producing duplicate diagnostics for assertions/sinks.
    error_suppression_depth: u8,
    /// Stack of per-function `goto` convergence loop context state.
    goto_states: Vec<GotoConvergenceState<'a>>,
    /// Locations of currently active split control-flow regions.
    split_control_flow_regions: Vec<Pinned<'a, Location>>,

    /// Universally-applicable directives registered for specific functions.
    blanket_directives: &'a BlanketDirectives,
}

impl<'a> AnalysisContext<'a> {
    pub fn new(blanket_directives: &'a BlanketDirectives) -> Self {
        AnalysisContext {
            stage: AnalysisStage::default(),
            symbol_table: SymbolTable::new(),
            type_registry: TypeRegistry::new(),
            current_file: None,
            errors: Vec::new(),
            funcs: Vec::new(),
            deferred_calls: Vec::new(),
            branch_backtraces: Vec::new(),
            deferred_branch_backtraces: Vec::new(),
            current_calculated_branch_backtrace: None,
            current_branch_scope_depth: 0,
            error_suppression_depth: 0,
            split_control_flow_regions: Vec::new(),
            goto_states: Vec::new(),
            blanket_directives,
        }
    }

    pub fn symtab(&self) -> &SymbolTable<'a> {
        &self.symbol_table
    }

    pub fn symtab_mut(&mut self) -> &mut SymbolTable<'a> {
        &mut self.symbol_table
    }

    pub fn types(&self) -> &TypeRegistry<'a> {
        &self.type_registry
    }

    pub fn types_mut(&mut self) -> &mut TypeRegistry<'a> {
        &mut self.type_registry
    }

    // make borrow checker happy (&mut + & to self)
    pub fn types_mut_with_symtab(&mut self) -> (&mut TypeRegistry<'a>, &SymbolTable<'a>) {
        (&mut self.type_registry, &self.symbol_table)
    }

    pub fn enter_package(
        &mut self,
        name: Pinned<'a, parser::Span<'a>>,
        path: FullPackagePath,
    ) -> Pinned<'a, parser::Span<'a>> {
        self.type_registry.invalidate_imports_snapshot();

        self.symbol_table.enter_package(name, path)
    }

    pub fn register_import_spec(
        &mut self,
        qualifier: Option<String>,
        path: FullPackagePath,
        infer_from_path: bool,
    ) -> Option<bool> {
        self.type_registry.invalidate_imports_snapshot();

        self.symbol_table
            .register_import_spec(qualifier, path, infer_from_path)
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

        self.deferred_calls.push(Vec::new());
    }

    pub fn pop_function(&mut self) {
        self.funcs.pop();

        // supposedly all already handled before `pop_function` is called
        self.deferred_calls.pop();
    }

    pub fn register_deferred_call(&mut self, node: CallNode<'a>, resolved: ResolvedCall<'a>) {
        // capture before the mutable borrow below; cheap if there's no backtrace
        let captured_branch_backtrace = self.branch_backtrace().cloned();

        let Some(top) = self.deferred_calls.last_mut() else {
            return;
        };

        top.push(DeferredCall {
            node,
            resolved,
            captured_branch_backtrace,
        });
    }

    pub fn take_deferred_calls(&mut self) -> Vec<DeferredCall<'a>> {
        self.deferred_calls
            .last_mut()
            .map(mem::take)
            .unwrap_or_default()
    }

    pub fn is_function_in_call_stack(&self, r#ref: &FunctionRef<'a>) -> bool {
        self.funcs.iter().any(|value| {
            value
                .as_function()
                .as_deref()
                .is_some_and(|func| func.r#ref() == r#ref)
        })
    }

    pub fn branch_backtrace(&self) -> Option<&LabelBacktrace<'a>> {
        self.current_calculated_branch_backtrace
            .as_ref()
            .or_else(|| self.branch_backtraces.last())
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

    pub fn checkpoint_deferred_state(&self) -> DeferredBranchBacktraceCheckpoint<'a> {
        DeferredBranchBacktraceCheckpoint {
            deferred: self.deferred_branch_backtraces.clone(),
            composite: self.current_calculated_branch_backtrace.clone(),
        }
    }

    pub fn restore_deferred_state(&mut self, checkpoint: DeferredBranchBacktraceCheckpoint<'a>) {
        self.deferred_branch_backtraces = checkpoint.deferred;
        self.current_calculated_branch_backtrace = checkpoint.composite;
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

    pub fn push_error_suppression(&mut self) {
        self.error_suppression_depth += 1;
    }

    pub fn pop_error_suppression(&mut self) {
        self.error_suppression_depth -= 1;
    }

    pub fn push_goto_context(&mut self, state: GotoConvergenceState<'a>) {
        self.goto_states.push(state);
    }

    pub fn pop_goto_context(&mut self) -> Option<GotoConvergenceState<'a>> {
        self.goto_states.pop()
    }

    pub fn current_goto_context(&self) -> Option<&GotoConvergenceState<'a>> {
        self.goto_states.last()
    }

    pub fn current_goto_context_mut(&mut self) -> Option<&mut GotoConvergenceState<'a>> {
        self.goto_states.last_mut()
    }

    pub fn push_split_control_flow(&mut self, location: Location) {
        self.split_control_flow_regions.push(self.pin(location));
    }

    pub fn pop_split_control_flow(&mut self) {
        self.split_control_flow_regions.pop();
    }

    pub fn was_symbol_declared_within_active_split(&self, symbol: &SymbolRef<'a>) -> Option<bool> {
        if self.split_control_flow_regions.is_empty() {
            // no active split
            return None;
        }

        let declaration = symbol.borrow().declared_name().pinned_location();

        let within = self
            .split_control_flow_regions
            .iter()
            .any(|region| declaration.contained_in(region));

        Some(within)
    }

    pub fn defer_enforcement_check(&mut self, check: DeferredEnforcementCheck<'a>) {
        let mut value = self.current_function().unwrap();
        // ^ should be safe if this method is used correctly (only within a fn)

        let mut func = value.as_function_mut().unwrap();

        assert!(
            !func.r#ref().is_main(),
            concat!(
                "attempt to defer an enforcement check within the main entrypoint",
                " (this is a bug: synthetics must not escape their respective function)",
                " [check = {:?}]"
            ),
            &check
        );

        func.defer_check(check);
    }

    pub fn blanket_directives_for(&self, func_path: &str) -> &'a [BlanketDirective] {
        self.blanket_directives
            .get(func_path)
            .map_or(&[], Vec::as_slice)
    }

    pub fn report_error_at(&mut self, file: &'a Path, kind: AnalysisErrorKind<'a>) {
        if self.stage.admits_errors() && self.error_suppression_depth == 0 {
            self.errors.push(AnalysisError { file, kind });
        }
    }

    pub fn report_error(&mut self, kind: AnalysisErrorKind<'a>) {
        if let Some(file) = self.current_file {
            self.report_error_at(file, kind);
        }
    }

    pub fn pin<T: Clone + fmt::Debug + PartialEq>(&self, inner: T) -> Pinned<'a, T> {
        let file = self
            .current_file
            .expect("some file should be under analysis");

        Pinned::new(file, inner)
    }

    /// Shorthand to declare a new symbol in the [`SymbolTable`] and report
    /// an error if the current scope already had it defined.
    ///
    /// This method should not be used if redeclarations are allowed (i.e., in
    /// some multi-variable short declarations, under some circumstances, as
    /// defined in the Go spec).
    pub fn declare_new_symbol(&mut self, symbol: SymbolRef<'a>) {
        let name = symbol.borrow().declared_name();
        let existing = self.symbol_table.declare_new_symbol(name.content(), symbol);

        self.report_if_real_redeclaration(name, existing);
    }

    /// Method-specific alternative to [`AnalysisContext::declare_new_symbol`].
    pub fn declare_new_method_symbol(&mut self, receiver_type: &'a str, symbol: SymbolRef<'a>) {
        let name = symbol.borrow().declared_name();

        let existing = self
            .symbol_table
            .declare_new_method(receiver_type, name.content(), symbol);

        self.report_if_real_redeclaration(name, existing);
    }

    /// Dispatcher for [`AnalysisContext::declare_new_symbol`] and
    /// [`AnalysisContext::declare_new_method_symbol`].
    pub fn declare_function_or_method(
        &mut self,
        receiver: Option<&FunctionParamDeclNode<'a>>,
        symbol: SymbolRef<'a>,
    ) {
        match receiver.and_then(|rcv| receiver_base_type_name(&rcv.r#type)) {
            Some(receiver_type) => self.declare_new_method_symbol(receiver_type, symbol),
            None => self.declare_new_symbol(symbol),
        }
    }

    fn report_if_real_redeclaration(
        &mut self,
        name: Pinned<'a, Span<'a>>,
        existing: Option<SymbolRef<'a>>,
    ) {
        let Some(existing) = existing else { return };
        let previous = existing.borrow().declared_name();

        // identical location == same declaration re-visited (Stage 2/3 re-runs)
        // (we do multiple passes over the source code, so it's not an error if
        // a previous declaration is at the same location as this "new" one,
        // i.e. they're actually the same declaration, so all is good)
        if previous == name {
            return;
        }

        // we already saw a *later* declaration in a previous pass; this call
        // is the *earlier* one, so the later one was the redeclaration and was
        // reported (or skipped) at the time
        if previous.pinned_location() > name.pinned_location() {
            return;
        }

        self.report_error(AnalysisErrorKind::IllegalRedeclaration {
            previous,
            found: *name.inner(),
        });
    }
}

impl<'a> From<AnalysisContext<'a>> for Result<(), Vec<AnalysisError<'a>>> {
    #[inline]
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
    /// Scan all files for top-level declarations and record them.
    #[default]
    RecordDeclarations,
    /// Repeatedly visit symbols until all security labels stabilize.
    StabilizeLabels,
    /// Find and report data flow violations based on stable security labels.
    EnforceSecurityPolicies,
}

impl AnalysisStage {
    fn admits_errors(&self) -> bool {
        matches!(
            self,
            Self::RecordDeclarations | Self::EnforceSecurityPolicies
        )
    }

    /// Returns whether the present stage if the first stage of analysis.
    ///
    /// If a value of false is returned, the invoker may assume that all input
    /// files have already been reviewed at least once (meaning that, for
    /// example, package clause and import spec registration should be fully
    /// complete).
    pub fn is_first(&self) -> bool {
        matches!(self, Self::RecordDeclarations)
    }
}

pub struct DeferredCall<'a> {
    pub node: CallNode<'a>,
    pub resolved: ResolvedCall<'a>,
    pub captured_branch_backtrace: Option<LabelBacktrace<'a>>,
}

#[derive(Clone)]
struct DeferredBranchBacktrace<'a> {
    backtrace: LabelBacktrace<'a>,
    until: DeferTarget<'a>,
    at_depth: u8,
    because: Pinned<'a, Location>,
}

#[derive(Clone)]
pub struct DeferredBranchBacktraceCheckpoint<'a> {
    deferred: Vec<DeferredBranchBacktrace<'a>>,
    composite: Option<LabelBacktrace<'a>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
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
        from_slot: SyntheticSlot,
        concrete: Option<&LabelBacktrace<'a>>,
    ) -> Option<Self> {
        let realized = match self {
            Self::Sink { sink, found, file } => Self::Sink {
                sink: sink.clone(),
                found: found.realize(from_func, from_slot, concrete)?,
                file,
            },
            Self::Assertion {
                expected_sequence,
                found,
                file,
                location,
            } => Self::Assertion {
                expected_sequence: expected_sequence.clone(),
                found: found.realize(from_func, from_slot, concrete),
                file,
                location: location.clone(),
            },
        };

        Some(realized)
    }

    pub fn rebind_synthetic_func(
        &self,
        from_func: &FunctionRef<'a>,
        to_func: &FunctionRef<'a>,
    ) -> Self {
        match self {
            Self::Sink { sink, found, file } => Self::Sink {
                sink: sink.clone(),
                found: found.rebind_synthetic_func(from_func, to_func),
                file,
            },
            Self::Assertion {
                expected_sequence,
                found,
                file,
                location,
            } => Self::Assertion {
                expected_sequence: expected_sequence.clone(),
                found: found
                    .as_ref()
                    .map(|bt| bt.rebind_synthetic_func(from_func, to_func)),
                file,
                location: location.clone(),
            },
        }
    }
}

impl SnapshotAware for DeferredEnforcementCheck<'_> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        match (self, other) {
            #[expect(clippy::suspicious_operation_groupings, reason = "False positive")]
            (
                Self::Sink {
                    sink: sink_a,
                    found: found_a,
                    file: file_a,
                },
                Self::Sink {
                    sink: sink_b,
                    found: found_b,
                    file: file_b,
                },
            ) => {
                sink_a.snapshot_aware_eq(sink_b)
                    && found_a.snapshot_aware_eq(found_b)
                    && file_a == file_b
            }
            (
                Self::Assertion {
                    expected_sequence: expected_sequence_a,
                    found: found_a,
                    file: file_a,
                    location: location_a,
                },
                Self::Assertion {
                    expected_sequence: expected_sequence_b,
                    found: found_b,
                    file: file_b,
                    location: location_b,
                },
            ) => {
                expected_sequence_a == expected_sequence_b
                    && found_a.snapshot_aware_eq(found_b)
                    && file_a == file_b
                    && location_a == location_b
            }

            // no wildcard _ so we rely on exhaustiveness for maintainability
            // (compiler will error if a new variant is added and this method
            // is not updated to reflect that)
            (Self::Sink { .. } | Self::Assertion { .. }, _) => false,
        }
    }
}
