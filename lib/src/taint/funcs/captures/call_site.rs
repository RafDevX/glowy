use std::{borrow::Cow, collections::BTreeMap, iter};

use crate::{
    Location, Pinned,
    context::AnalysisContext,
    labels::{FunctionRef, Label, LabelBacktrace, LabelBacktraceKind, SyntheticSlot},
    snapshots::SnapshotAware,
    taint::{
        funcs::{self, call_application, captures::realization::CaptureEnvSnapshot},
        mutation,
    },
    values::{FunctionValue, Mergeable, SelfAwareBacktraceContainer, UnifiedRealization, ValueRef},
};

type CaptureConcretes<'a> = BTreeMap<usize, Option<LabelBacktrace<'a>>>;

pub struct CallCaptureConcretes<'a> {
    // call-entry values for realizing flow-sensitive enforcement checks
    pub at_entry: CaptureConcretes<'a>,
    // values suitable for realizing the function's summarized outcome
    pub for_outcome: CaptureConcretes<'a>,
}

impl<'a> CallCaptureConcretes<'a> {
    pub fn from_stable_environment(ctx: &AnalysisContext<'a>, func: &FunctionValue<'a>) -> Self {
        let captures = derive_stable_capture_concretes(ctx, func);

        Self {
            at_entry: captures.clone(),
            for_outcome: captures,
        }
    }

    pub fn realize_at_entry(&self, func: &FunctionValue<'a>) -> FunctionValue<'a> {
        let substitutions: Vec<_> = self
            .at_entry
            .iter()
            .map(|(index, concrete)| (SyntheticSlot::Capture(*index), concrete.as_ref()))
            .collect();

        let mut realization = UnifiedRealization::multiple(func.r#ref(), &substitutions);

        func.realize_unified(&mut realization)
    }
}

#[expect(clippy::option_option, reason = "Represent receiver absent vs Bottom")]
struct CallSiteConcretes<'a> {
    params: Vec<Option<LabelBacktrace<'a>>>,
    receiver: Option<Option<LabelBacktrace<'a>>>,
    branch: Option<LabelBacktrace<'a>>,
}

impl<'a> CallSiteConcretes<'a> {
    #[expect(clippy::option_option, reason = "Represent receiver absent vs Bottom")]
    fn new(
        ctx: &AnalysisContext<'a>,
        func: &FunctionValue<'a>,
        receiver: Option<Option<&LabelBacktrace<'a>>>,
        args: &[(ValueRef<'a>, Option<&LabelBacktrace<'a>>)],
        location: &Pinned<'a, Location>,
    ) -> Self {
        // calculate the concrete call-site backtrace for each real parameter,
        // which is later needed to realize capture labels after a function call
        // with the actual argument values; this is necessary because a capture
        // may indirectly depend on any argument, so we must resolve each
        // capture against each parameter position

        let params = if let Some(signature) = func.signature() {
            funcs::collect_parameter_slots(signature)
                .into_iter()
                .enumerate()
                .map(|(index, (id, variadic, r#type))| {
                    call_application::calculate_concrete_backtrace(
                        ctx,
                        index,
                        id,
                        variadic,
                        r#type,
                        args,
                        Cow::Borrowed(location),
                    )
                })
                .collect()
        } else {
            Vec::new()
        };

        let receiver = receiver.map(Option::<&_>::cloned);

        let branch = funcs::calc_effective_call_site_branch_backtrace_for(ctx, func, location);

        Self {
            params,
            receiver,
            branch,
        }
    }

    fn realize_backtrace_for_params(
        &self,
        func: &FunctionRef<'a>,
        initial: Option<LabelBacktrace<'a>>,
    ) -> Option<LabelBacktrace<'a>> {
        let substitutions: Vec<_> = self
            .params
            .iter()
            .enumerate()
            .map(|(index, concrete)| (SyntheticSlot::Param(index), concrete.as_ref()))
            .chain(iter::once((
                SyntheticSlot::CallSiteBranch,
                self.branch.as_ref(),
            )))
            .chain(iter::once((SyntheticSlot::YieldFeedback, None)))
            .collect();

        initial?.realize_all(func, &substitutions)
    }
}

#[expect(clippy::option_option, reason = "Represent receiver absent vs Bottom")]
pub fn apply_capture_mutations_and_derive_concretes<'a>(
    ctx: &mut AnalysisContext<'a>,
    func: &FunctionValue<'a>,
    receiver: Option<Option<&LabelBacktrace<'a>>>,
    args: &[(ValueRef<'a>, Option<&LabelBacktrace<'a>>)],
    location: &Pinned<'a, Location>,
) -> CallCaptureConcretes<'a> {
    let call_site = CallSiteConcretes::new(ctx, func, receiver, args, location);

    let has_direct_capture_mutations = func
        .captures()
        .any(|(_, binding)| binding.mutation_backtrace().is_some());

    let at_entry = if func.deferred_checks().is_empty() && !has_direct_capture_mutations {
        BTreeMap::new()
    } else {
        derive_capture_backtraces_at_entry(ctx, func, &call_site)
    };

    let before_write_back = derive_best_backtraces_for_captures(ctx, func, &call_site);

    apply_capture_write_backs_with(ctx, func, &call_site, &before_write_back, location);

    // some capture dependencies become visible only after write-back; for
    // example, a closure may mutate `x` and then read it through another
    // captured closure whose outcome transitively depends on `x`
    let after_write_back = derive_best_backtraces_for_captures(ctx, func, &call_site);

    let mut for_outcome = merge_capture_concretes(before_write_back, after_write_back, location);

    restore_entry_concretes_for_directly_mutated_captures(func, &at_entry, &mut for_outcome);

    CallCaptureConcretes {
        at_entry,
        for_outcome,
    }
}

fn merge_capture_concretes<'a>(
    mut before_write_back: CaptureConcretes<'a>,
    after_write_back: CaptureConcretes<'a>,
    location: &Pinned<'a, Location>,
) -> CaptureConcretes<'a> {
    for (index, after) in after_write_back {
        let Some(before) = before_write_back.remove(&index) else {
            // this index was not in the map, so there is no `before` concrete,
            // meaning there is nothing to merge -- we just insert `after`'s
            before_write_back.insert(index, after);

            continue;
        };

        let merged = merge_capture_backtraces(before, after, location);

        before_write_back.insert(index, merged);
    }

    before_write_back
}

fn restore_entry_concretes_for_directly_mutated_captures<'a>(
    func: &FunctionValue<'a>,
    at_entry: &CaptureConcretes<'a>,
    for_outcome: &mut CaptureConcretes<'a>,
) {
    // a capture-local's own writes are already represented in the symbolic
    // outcome. any occurrence of its original `Capture(i)` slot that remains
    // therefore denotes a call-entry value, such as a local snapshot saved
    // before the write

    for (_, binding) in func
        .captures()
        .filter(|(_, binding)| binding.mutation_backtrace().is_some())
    {
        let index = binding.index();

        let entry = at_entry
            .get(&index)
            .expect("directly mutated captures must have an entry concrete");

        for_outcome.insert(index, entry.clone());
    }
}

fn merge_capture_backtraces<'a>(
    before: Option<LabelBacktrace<'a>>,
    after: Option<LabelBacktrace<'a>>,
    location: &Pinned<'a, Location>,
) -> Option<LabelBacktrace<'a>> {
    if before == after {
        return before;
    }

    LabelBacktrace::combine_options(
        before,
        after,
        LabelBacktraceKind::ClosureCaptureBinding,
        Cow::Borrowed(location),
    )
}

#[expect(clippy::option_option, reason = "Represent receiver absent vs Bottom")]
pub fn apply_capture_write_backs<'a>(
    ctx: &mut AnalysisContext<'a>,
    func: &FunctionValue<'a>,
    receiver: Option<Option<&LabelBacktrace<'a>>>,
    args: &[(ValueRef<'a>, Option<&LabelBacktrace<'a>>)],
    location: &Pinned<'a, Location>,
) {
    let call_site_concretes = CallSiteConcretes::new(ctx, func, receiver, args, location);

    let capture_backtraces = derive_best_backtraces_for_captures(ctx, func, &call_site_concretes);

    apply_capture_write_backs_with(
        ctx,
        func,
        &call_site_concretes,
        &capture_backtraces,
        location,
    );
}

fn apply_capture_write_backs_with<'a>(
    ctx: &mut AnalysisContext<'a>,
    func: &FunctionValue<'a>,
    call_site_concretes: &CallSiteConcretes<'a>,
    capture_backtraces: &CaptureConcretes<'a>,
    call_location: &Pinned<'a, Location>,
) {
    for (outer_decl, binding) in func.captures() {
        let local_symbol = binding.local_symbol();

        let (local_value, local_known_const) = {
            let borrowed = local_symbol.borrow();

            (borrowed.value().get(), borrowed.known_const().cloned())
        };

        if local_value
            .backtrace()
            .as_ref()
            .map_or(&Label::Bottom, LabelBacktrace::label)
            .is_synthetic_representation(func.r#ref(), SyntheticSlot::Capture(binding.index()))
        {
            // the fake local symbol still matches original fake declaration,
            // meaning no significant mutation occurred and so there is no need
            // to propagate this to the real outer symbol
            continue;
        }

        let outer_symbol = super::resolve_capture_runtime_symbol(ctx, outer_decl, binding);

        if !outer_symbol.borrow().mutable() {
            continue;
        }

        let substitutions_before: Vec<_> = call_site_concretes
            .params
            .iter()
            .enumerate()
            .map(|(index, concrete)| (SyntheticSlot::Param(index), concrete.as_ref()))
            .chain(iter::once((SyntheticSlot::YieldFeedback, None)))
            .chain(
                capture_backtraces
                    .range(..binding.index())
                    .map(|(index, concrete)| (SyntheticSlot::Capture(*index), concrete.as_ref())),
            )
            .collect();

        let mut realized = local_value.realize_all(func.r#ref(), &substitutions_before);

        let (outer_value, outer_known_const) = {
            let borrowed = outer_symbol.borrow();

            (borrowed.value().get(), borrowed.known_const().cloned())
        };

        // preserve the current capture's shape instead of substituting its
        // flattened backtrace; this is the sole substitution which cannot be
        // represented by the ordinary batched realization API via realize_all
        realized = realized.realize_with_shape_preservation(
            func.r#ref(),
            SyntheticSlot::Capture(binding.index()),
            &outer_value,
            outer_value.location().clone(),
        );

        let substitutions_after: Vec<_> = capture_backtraces
            .range((binding.index() + 1)..) // continue from where we left off
            .map(|(index, concrete)| (SyntheticSlot::Capture(*index), concrete.as_ref()))
            .chain(
                call_site_concretes
                    .receiver
                    .as_ref()
                    .map(|concrete| (SyntheticSlot::Receiver, concrete.as_ref())),
            )
            .chain(iter::once((
                SyntheticSlot::CallSiteBranch,
                call_site_concretes.branch.as_ref(),
            )))
            .collect();

        realized = realized.realize_all(func.r#ref(), &substitutions_after);

        if realized == local_value {
            // no realization happened; ensure compliance with AssumedImmutable
            realized = local_value.clone_inner();
        }

        if realized.snapshot_aware_eq(&outer_value) && local_known_const == outer_known_const {
            // avoid unbounded growth of the outer symbol's backtrace tree
            // across repeated closure calls, as otherwise later backtrace
            // comparisons (e.g., the == at derive_best_backtraces_for_captures)
            // would suffer monumental performance penalties, and memory usage
            // would grow substantially, overall affecting efficiency by several
            // orders of magnitude; nesting this would essentially lead to
            // virtual non-termination of the analysis process
            continue;
        }

        let (final_value, final_known_const) =
            if ctx.was_symbol_declared_within_active_split(&outer_symbol) == Some(false) {
                // outer was declared outside the active split, so its prior
                // state must survive the closure call alongside whatever the
                // closure produced. merging via Mergeable preserves per-key
                // labels on composites (vs. flattening them all into r#dyn,
                // which feeding outer_value.backtrace() into `extra_children`
                // would do)

                let merged = outer_value
                    .merge_with(
                        &realized,
                        LabelBacktraceKind::Assignment,
                        Cow::Borrowed(outer_value.location()),
                    )
                    .nest_backtrace(
                        LabelBacktraceKind::Assignment,
                        Some(outer_decl.content()),
                        outer_value.location().clone(),
                        [],
                    );

                (merged, None)
            } else {
                (realized, local_known_const)
            };

        mutation::record_active_function_capture_mutation(
            ctx,
            &outer_symbol,
            &final_value,
            call_location,
        );

        outer_symbol
            .borrow_mut()
            .set_value(final_value, final_known_const);

        ctx.record_iteration_cell_value(&outer_symbol);
    }
}

fn derive_best_backtraces_for_captures<'a>(
    ctx: &AnalysisContext<'a>,
    func: &FunctionValue<'a>,
    call_site_concretes: &CallSiteConcretes<'a>,
) -> CaptureConcretes<'a> {
    realize_capture_backtraces_for_call_site(
        derive_stable_capture_concretes(ctx, func),
        func,
        call_site_concretes,
    )
}

fn derive_capture_backtraces_at_entry<'a>(
    ctx: &AnalysisContext<'a>,
    func: &FunctionValue<'a>,
    call_site_concretes: &CallSiteConcretes<'a>,
) -> CaptureConcretes<'a> {
    let snapshot = CaptureEnvSnapshot::derive_new_at_entry(ctx, func);

    realize_capture_backtraces_for_call_site(
        capture_concretes_from_snapshot(func, &snapshot),
        func,
        call_site_concretes,
    )
}

fn realize_capture_backtraces_for_call_site<'a>(
    mut concretes: CaptureConcretes<'a>,
    func: &FunctionValue<'a>,
    call_site_concretes: &CallSiteConcretes<'a>,
) -> CaptureConcretes<'a> {
    // we need to realize the captures' backtraces to get rid of any references
    // coming from function params, since we have each param's concrete already
    // calculated at this point
    for concrete in concretes.values_mut() {
        *concrete = call_site_concretes.realize_backtrace_for_params(func.r#ref(), concrete.take());
    }

    concretes
}

pub fn realize_stable_captures<'a>(
    ctx: &AnalysisContext<'a>,
    func: &FunctionValue<'a>,
) -> FunctionValue<'a> {
    CallCaptureConcretes::from_stable_environment(ctx, func).realize_at_entry(func)
}

fn derive_stable_capture_concretes<'a>(
    ctx: &AnalysisContext<'a>,
    func: &FunctionValue<'a>,
) -> CaptureConcretes<'a> {
    let capture_env_snapshot = CaptureEnvSnapshot::derive_new_stable(ctx, func);

    capture_concretes_from_snapshot(func, &capture_env_snapshot)
}

fn capture_concretes_from_snapshot<'a>(
    func: &FunctionValue<'a>,
    capture_env_snapshot: &CaptureEnvSnapshot<'a>,
) -> CaptureConcretes<'a> {
    func.captures()
        .map(|(outer_decl, binding)| {
            (
                binding.index(),
                capture_env_snapshot
                    .get(&outer_decl)
                    .cloned()
                    .expect("capture snapshot must contain every registered capture"),
            )
        })
        .collect()
}
