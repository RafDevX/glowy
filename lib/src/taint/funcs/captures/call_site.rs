use std::{borrow::Cow, collections::BTreeMap};

use parser::Location;

use crate::{
    Pinned,
    context::AnalysisContext,
    labels::{FunctionRef, Label, LabelBacktrace, LabelBacktraceKind, SyntheticSlot},
    snapshots::SnapshotAware,
    taint::{
        funcs::{self, call_application, captures::realization::CaptureEnvSnapshot},
        mutation,
    },
    values::{FunctionValue, Mergeable, SelfAwareBacktraceContainer, ValueRef},
};

type CaptureConcretes<'a> = Vec<(usize, Option<LabelBacktrace<'a>>)>;

pub struct CallCaptureConcretes<'a> {
    // call-entry values for realizing flow-sensitive enforcement checks
    pub at_entry: CaptureConcretes<'a>,
    // conservative union of values observable throughout the function body
    pub for_outcome: CaptureConcretes<'a>,
}

struct CallSiteConcretes<'a> {
    params: Vec<Option<LabelBacktrace<'a>>>,
    branch: Option<LabelBacktrace<'a>>,
}

impl<'a> CallSiteConcretes<'a> {
    fn new(
        ctx: &AnalysisContext<'a>,
        func: &FunctionValue<'a>,
        args: &[(ValueRef<'a>, Option<&LabelBacktrace<'a>>)],
        location: &Pinned<'a, Location>,
    ) -> Self {
        // calculate the concrete call-site backtrace for each real parameter,
        // which is later needed to realize capture labels after a function call
        // with the actual argument values; this is necessary because a capture
        // may indirectly depend on any argument, so we must resolve each
        // capture against each parameter position

        let params = if let Some(signature) = func.signature() {
            signature
                .params
                .iter()
                .enumerate()
                .map(|(index, param)| {
                    call_application::calculate_concrete_backtrace(
                        ctx,
                        index,
                        param.ids.first(),
                        param.variadic,
                        &param.r#type,
                        args,
                        Cow::Borrowed(location),
                    )
                })
                .collect()
        } else {
            Vec::new()
        };

        let branch = funcs::calc_effective_call_site_branch_backtrace_for(ctx, func, location);

        Self { params, branch }
    }

    fn realize_backtrace_for_params(
        &self,
        func: &FunctionRef<'a>,
        initial: Option<LabelBacktrace<'a>>,
    ) -> Option<LabelBacktrace<'a>> {
        let Some(mut current) = initial else {
            // nothing to realize
            return None;
        };

        for (param_index, concrete) in self.params.iter().enumerate() {
            if let Some(realized) =
                current.realize(func, SyntheticSlot::Param(param_index), concrete.as_ref())
            {
                current = realized;
            } else {
                // nothing left to realize
                return None;
            }
        }

        current.realize(func, SyntheticSlot::CallSiteBranch, self.branch.as_ref())
    }
}

pub fn apply_capture_mutations_and_derive_concretes<'a>(
    ctx: &AnalysisContext<'a>,
    func: &FunctionValue<'a>,
    args: &[(ValueRef<'a>, Option<&LabelBacktrace<'a>>)],
    location: &Pinned<'a, Location>,
) -> CallCaptureConcretes<'a> {
    // each captured variable has only one assigned synthetic slot, which means
    // that different reads of the same captured variable are indistinguishable
    // during realization: all <0> become {concrete}, and there is nothing else
    // that can be done. however, if a closure mutates a captured variable
    // between reads, those 2 reads are supposed to yield different labels, but
    // our model does not support it since both are <0> and so both will become
    // {concrete} (which concrete? probably the one at the end of the function
    // body, post-mutations)

    // to solve this, we conservatively merge all possible read results by
    // merging the calculated concretes for the captured variable as determined
    // for the start and for the end of the closure body (i.e., before and after
    // capture mutations are applied), so as to obtain sound concretes for
    // realization that actually are representative of all the capture's reads

    // if there are multiple read+mutation+read gadgets, intermediate mutation
    // backtraces would not be represented in either the start nor the end value
    // of the capture's local fake symbol, but we already keep track of
    // mutations in CaptureBinding and merge them into the concrete at the end
    // of `derive_concrete_backtrace_or_fallback`, so nothing is lost

    let call_site = CallSiteConcretes::new(ctx, func, args, location);

    let at_entry = if func.deferred_checks().is_empty() {
        Vec::new()
    } else {
        derive_capture_backtraces_at_entry(ctx, func, &call_site)
    };

    let before_mutation = derive_best_backtraces_for_captures(ctx, func, &call_site);

    apply_capture_mutations_with(ctx, func, &call_site, &before_mutation, location);

    let after_mutation = derive_best_backtraces_for_captures(ctx, func, &call_site);

    let for_outcome = merge_capture_backtrace_snapshots(before_mutation, after_mutation, location);

    CallCaptureConcretes {
        at_entry,
        for_outcome,
    }
}

fn merge_capture_backtrace_snapshots<'a>(
    before: Vec<(usize, Option<LabelBacktrace<'a>>)>,
    after: Vec<(usize, Option<LabelBacktrace<'a>>)>,
    location: &Pinned<'a, Location>,
) -> Vec<(usize, Option<LabelBacktrace<'a>>)> {
    let mut by_capture_index: BTreeMap<_, _> = before.into_iter().collect();

    for (index, after_bt) in after {
        let Some(before_bt) = by_capture_index.remove(&index) else {
            // this index was not in the map, so there is no `before` backtrace,
            // meaning there is nothing to merge - we just insert `after`'s
            by_capture_index.insert(index, after_bt);

            continue;
        };

        let merged = merge_capture_binding_backtraces(before_bt, after_bt, location);

        by_capture_index.insert(index, merged);
    }

    by_capture_index.into_iter().collect()
}

fn merge_capture_binding_backtraces<'a>(
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

pub fn apply_capture_mutations<'a>(
    ctx: &AnalysisContext<'a>,
    func: &FunctionValue<'a>,
    args: &[(ValueRef<'a>, Option<&LabelBacktrace<'a>>)],
    location: &Pinned<'a, Location>,
) {
    let call_site_concretes = CallSiteConcretes::new(ctx, func, args, location);

    let capture_backtraces = derive_best_backtraces_for_captures(ctx, func, &call_site_concretes);

    apply_capture_mutations_with(
        ctx,
        func,
        &call_site_concretes,
        &capture_backtraces,
        location,
    );
}

fn apply_capture_mutations_with<'a>(
    ctx: &AnalysisContext<'a>,
    func: &FunctionValue<'a>,
    call_site_concretes: &CallSiteConcretes<'a>,
    capture_backtraces: &[(usize, Option<LabelBacktrace<'a>>)],
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

        let outer_symbol = super::resolve_capture_symbol(ctx, outer_decl);

        if !outer_symbol.borrow().mutable() {
            continue;
        }

        let mut realized = Cow::Borrowed(&local_value);

        for (index, concrete) in call_site_concretes.params.iter().enumerate() {
            realized = Cow::Owned(realized.realize(
                func.r#ref(),
                SyntheticSlot::Param(index),
                concrete.as_ref(),
            ));
        }

        let (outer_value, outer_known_const) = {
            let borrowed = outer_symbol.borrow();

            (borrowed.value().get(), borrowed.known_const().cloned())
        };

        for (index, backtrace) in capture_backtraces {
            realized = Cow::Owned(if *index == binding.index() {
                // try to avoid using `backtrace` (flattened value)
                realized.realize_with_shape_preservation(
                    func.r#ref(),
                    SyntheticSlot::Capture(*index),
                    &outer_value,
                    outer_value.location().clone(),
                )
            } else {
                realized.realize(
                    func.r#ref(),
                    SyntheticSlot::Capture(*index),
                    backtrace.as_ref(),
                )
            });
        }

        realized = Cow::Owned(realized.realize(
            func.r#ref(),
            SyntheticSlot::CallSiteBranch,
            call_site_concretes.branch.as_ref(),
        ));

        if *realized == local_value {
            // no realization happened; ensure compliance with AssumedImmutable
            realized = Cow::Owned(local_value.clone_inner());
        }

        if (*realized).snapshot_aware_eq(&outer_value) && local_known_const == outer_known_const {
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
                (realized.into_owned(), local_known_const)
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
    for (_, concrete) in &mut concretes {
        *concrete = call_site_concretes.realize_backtrace_for_params(func.r#ref(), concrete.take());
    }

    concretes
}

pub fn derive_stable_capture_concretes<'a>(
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
    let mut concretes: CaptureConcretes<'a> = func
        .captures()
        .map(|(outer_decl, binding)| {
            (
                binding.index(),
                capture_env_snapshot
                    .get(&outer_decl)
                    .cloned()
                    .expect("capture snapshot must contain every registered capture"),
            )
        })
        .collect();

    // for determinism
    concretes.sort_by_key(|(index, _)| *index);

    concretes
}
