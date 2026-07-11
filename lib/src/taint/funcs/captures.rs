use std::{borrow::Cow, collections::BTreeMap};

use parser::{
    Location, Span,
    ast::{BlockNode, FunctionParamDeclNode, FunctionSignatureNode},
};

use crate::{
    Pinned,
    context::AnalysisContext,
    labels::{Label, LabelBacktrace, LabelBacktraceKind, LabelTag, SyntheticSlot},
    snapshots::SnapshotAware,
    symbols::{Symbol, SymbolRef},
    values::{
        CaptureBinding, FunctionRef, FunctionValue, Mergeable, SelfAwareBacktraceContainer,
        ValueRef,
    },
};

mod collector;

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
                    super::calculate_concrete_backtrace(
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

        let branch = super::calc_effective_call_site_branch_backtrace_for(ctx, func, location);

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

pub fn register_closure_captures<'a>(
    ctx: &mut AnalysisContext<'a>,
    r#ref: &FunctionRef<'a>,
    signature: &FunctionSignatureNode<'a>,
    receiver: Option<&FunctionParamDeclNode<'a>>,
    body: &BlockNode<'a>,
    value: &mut ValueRef<'a>,
) {
    let FunctionRef::Anonymous(closure_location) = r#ref else {
        return;
    };

    let mut captures: Vec<_> = collector::collect_captured_symbols(signature, receiver, body)
        .into_iter()
        .collect();

    captures.sort_unstable();

    for capture in captures {
        let Some(symbol) = ctx.symtab().get_symbol_above_current_scope(capture) else {
            continue;
        };

        let (outer_decl, outer_value) = {
            let borrowed = symbol.borrow();

            if !borrowed.mutable() {
                // we don't need to worry about immutable symbols because their
                // value will remain constant forever, meaning that it's fine to
                // evaluate them within the function definition and we will
                // never be able to overwrite them from within the closure
                continue;
            }

            (borrowed.declared_name(), borrowed.value())
        };

        let Some(mut func) = value.as_function_mut() else {
            continue;
        };

        // Span offset matters: we cannot hardcode to 0 or anything else because
        // otherwise any other captures with the same name registered for other
        // closures in the chain would clash (would have the same key)
        let local_decl = ctx.pin(Span::new(capture, closure_location.inner().start, 1));

        let index = func.register_capture(outer_decl, local_decl);

        drop(func);

        let synthetic = LabelTag::Synthetic {
            func: r#ref.clone(),
            slot: SyntheticSlot::Capture(index),
            identifier: Some(*local_decl.inner()),
        };

        let capture_backtrace = LabelBacktrace::new_root(
            LabelBacktraceKind::ClosureCapture,
            Label::from_single(synthetic),
            Some(capture),
            value.location().clone(),
        )
        .unwrap(); // safe because we know label is not Bottom

        // mirror the outer's top-level shape so that shape-discriminating
        // operations inside the closure body (e.g. `m[k] = v`, `ch <- v`,
        // `delete(m, k)`) see the correct shape instead of coercing into an
        // arbitrary default, but retain the synthetic as the sole backtrace
        let local_value = outer_value.get().copy_shape(capture_backtrace);

        ctx.declare_new_symbol(Symbol::new_ref(local_decl, true, local_value));
    }
}

pub fn record_closure_capture_fallbacks<'a>(ctx: &AnalysisContext<'a>, value: &mut ValueRef<'a>) {
    let Some(mut func) = value.as_function_mut() else {
        return;
    };

    for (outer_decl, binding) in func.captures_mut() {
        let Some(outer_symbol) = ctx.symtab().get_symbol_by_declaration(outer_decl) else {
            continue;
        };

        let hybrid = derive_hybrid_symbol_backtrace(ctx, &outer_symbol, &[]);
        binding.set_hybrid_fallback(hybrid);
    }
}

pub fn apply_capture_mutations<'a>(
    ctx: &AnalysisContext<'a>,
    func: &FunctionValue<'a>,
    args: &[(ValueRef<'a>, Option<&LabelBacktrace<'a>>)],
    location: &Pinned<'a, Location>,
) {
    let call_site_concretes = CallSiteConcretes::new(ctx, func, args, location);

    let capture_backtraces = derive_best_backtraces_for_captures(ctx, func, &call_site_concretes);

    apply_capture_mutations_with(ctx, func, &call_site_concretes, &capture_backtraces);
}

fn apply_capture_mutations_with<'a>(
    ctx: &AnalysisContext<'a>,
    func: &FunctionValue<'a>,
    call_site_concretes: &CallSiteConcretes<'a>,
    capture_backtraces: &[(usize, Option<LabelBacktrace<'a>>)],
) {
    for (outer_decl, binding) in func.captures() {
        let local_symbol = ctx
            .symtab()
            .get_symbol_by_declaration(binding.local_decl())
            .unwrap();

        let local_value = local_symbol.borrow().value().get();

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

        let outer_symbol = ctx.symtab().get_symbol_by_declaration(outer_decl).unwrap();

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

        for (index, backtrace) in capture_backtraces {
            realized = Cow::Owned(realized.realize(
                func.r#ref(),
                SyntheticSlot::Capture(*index),
                backtrace.as_ref(),
            ));
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

        let outer_value = outer_symbol.borrow().value().get();

        if (*realized).snapshot_aware_eq(&outer_value) {
            // avoid unbounded growth of the outer symbol's backtrace tree
            // across repeated closure calls, as otherwise later backtrace
            // comparisons (e.g., the == at derive_best_backtraces_for_captures)
            // would suffer monumental performance penalties, and memory usage
            // would grow substantially, overall affecting efficiency by several
            // orders of magnitude; nesting this would essentially lead to
            // virtual non-termination of the analysis process
            continue;
        }

        let final_value =
            if ctx.was_symbol_declared_within_active_split(&outer_symbol) == Some(false) {
                // outer was declared outside the active split, so its prior
                // state must survive the closure call alongside whatever the
                // closure produced. merging via Mergeable preserves per-key
                // labels on composites (vs. flattening them all into r#dyn,
                // which feeding outer_value.backtrace() into `extra_children`
                // would do)

                outer_value
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
                    )
            } else {
                realized.into_owned()
            };

        outer_symbol.borrow_mut().set_value(final_value);
    }
}

pub fn apply_capture_mutations_and_merge_capture_backtraces<'a>(
    ctx: &AnalysisContext<'a>,
    func: &FunctionValue<'a>,
    args: &[(ValueRef<'a>, Option<&LabelBacktrace<'a>>)],
    location: &Pinned<'a, Location>,
) -> Vec<(usize, Option<LabelBacktrace<'a>>)> {
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

    let before_mutation = derive_best_backtraces_for_captures(ctx, func, &call_site);

    apply_capture_mutations_with(ctx, func, &call_site, &before_mutation);

    let after_mutation = derive_best_backtraces_for_captures(ctx, func, &call_site);

    merge_capture_backtrace_snapshots(before_mutation, after_mutation, location)
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

fn derive_best_backtraces_for_captures<'a>(
    ctx: &AnalysisContext<'a>,
    func: &FunctionValue<'a>,
    call_site_concretes: &CallSiteConcretes<'a>,
) -> Vec<(usize, Option<LabelBacktrace<'a>>)> {
    // bootstrap a stable view of the closure's own captures before deriving
    // them again; nested closure values can then realize sibling capture
    // synthetics from this snapshot instead of rereading the mutable outer
    // symbol table and preserving stale synthetics
    let capture_env_snapshot: Vec<_> = func
        .captures()
        .map(|(outer_decl, binding)| {
            (
                outer_decl,
                derive_concrete_backtrace_or_fallback(ctx, func.r#ref(), outer_decl, binding, &[]),
            )
        })
        .collect();

    let mut concretes: Vec<_> = func
        .captures()
        .map(|(outer_decl, binding)| {
            (
                binding.index(),
                derive_concrete_backtrace_or_fallback(
                    ctx,
                    func.r#ref(),
                    outer_decl,
                    binding,
                    &capture_env_snapshot,
                ),
            )
        })
        .collect();

    // for determinism
    concretes.sort_by_key(|(index, _)| *index);

    // loop until nothing changes
    loop {
        let previous = concretes.clone();

        // realize each capture's current best backtrace by that of every other
        // capture, in case they depend on each other.
        // for example, if we found out mapping <a> => {secret} and another
        // capture <b> => {confidential, <a>}, then we can resolve <b> to just
        // be {confidential, secret}.
        // we use the previous concretes for realization to maintain stability

        'realization: for (_, concrete) in &mut concretes {
            let mut realized = if let Some(bt) = concrete.as_ref() {
                Cow::Borrowed(bt)
            } else {
                // nothing to realize; already Bottom
                continue;
            };

            for (prev_index, prev_concrete) in &previous {
                let step = realized.realize(
                    func.r#ref(),
                    SyntheticSlot::Capture(*prev_index),
                    prev_concrete.as_ref(),
                );

                if let Some(next) = step {
                    realized = Cow::Owned(next);
                } else {
                    // we'll never evolve from Bottom, stop realizing
                    *concrete = None;
                    continue 'realization;
                }
            }

            *concrete = Some(realized.into_owned());
        }

        if concretes == previous {
            break;
        }
    }

    // finally, we need to realize the captures' backtraces to get rid of any
    // references coming from function params, since we have each param's
    // concrete already calculated
    for (_, concrete) in &mut concretes {
        *concrete = call_site_concretes.realize_backtrace_for_params(func.r#ref(), concrete.take());
    }

    concretes
}

fn derive_concrete_backtrace_or_fallback<'a>(
    ctx: &AnalysisContext<'a>,
    func: &FunctionRef<'a>,
    outer_decl: Pinned<'a, Span<'a>>,
    binding: &CaptureBinding<'a>,
    capture_env_snapshot: &[(Pinned<'a, Span<'a>>, Option<LabelBacktrace<'a>>)],
) -> Option<LabelBacktrace<'a>> {
    let symbol = ctx.symtab().get_symbol_by_declaration(outer_decl).unwrap();

    let value_location = symbol.borrow().value().get().location().clone();

    let hybrid = derive_hybrid_symbol_backtrace(ctx, &symbol, capture_env_snapshot);

    // we should prefer the hybrid even when not fully concrete when its
    // synthetics refer to functions still in the call stack (meaning that they
    // will be realized later), as the fallback would be less useful here, so we
    // only need to check whether there are *inactive* synthetics
    let concrete = if hybrid
        .as_ref()
        .map(LabelBacktrace::label)
        .is_some_and(|label| has_inactive_synthetics(ctx, label, func))
        && let Some(fallback) = binding.hybrid_fallback()
    {
        fallback.cloned()
    } else {
        hybrid
    };

    // finally, we need to merge the concrete with all other intermediate
    // possible values for the capture, based on whatever mutations took place
    // during the function body so that we can properly support read+mutate+read
    // gadgets; see `apply_capture_mutations_and_merge_capture_backtraces`
    LabelBacktrace::combine_options(
        concrete,
        binding.mutation_backtrace().cloned(),
        LabelBacktraceKind::ClosureCaptureBinding,
        Cow::Borrowed(&value_location),
    )
}

fn has_inactive_synthetics<'a>(
    ctx: &AnalysisContext<'a>,
    label: &Label<'a>,
    realizable_func: &FunctionRef<'a>,
) -> bool {
    label.tags().any(|tag| {
        if let LabelTag::Synthetic { func, .. } = tag {
            // `func == realizable_func` means that the function is realizable
            // here, which is not necessarily covered by the other check
            // (`ctx.is_function_in_call_stack`) since `apply_call` can be
            // invoked from outside the function's body (and usually is)

            // `ctx.is_function_in_call_stack` means that the synthetic is
            // realizable later, since we are inside the function body

            func != realizable_func && !ctx.is_function_in_call_stack(func)
        } else {
            false
        }
    })
}

// as much as possible is made concrete, but some synthetics might persist
fn derive_hybrid_symbol_backtrace<'a>(
    ctx: &AnalysisContext<'a>,
    symbol: &SymbolRef<'a>,
    capture_env_snapshot: &[(Pinned<'a, Span<'a>>, Option<LabelBacktrace<'a>>)],
) -> Option<LabelBacktrace<'a>> {
    let borrowed = symbol.borrow();
    let declared_name = borrowed.declared_name();
    let value = borrowed.value().get();
    drop(borrowed);

    derive_hybrid_value_backtrace_in_capture_environment(
        ctx,
        &value,
        None,
        capture_env_snapshot,
        Some(declared_name.content()),
        declared_name.pinned_location(),
    )
}

// as much as possible is made concrete, but some synthetics might persist
#[expect(
    clippy::option_option,
    reason = "Conveniently represent a backtrace's presence/absence"
)]
pub(super) fn derive_hybrid_value_backtrace<'a>(
    ctx: &AnalysisContext<'a>,
    value: &ValueRef<'a>,
    cached_backtrace: Option<Option<LabelBacktrace<'a>>>,
    symbol: Option<&'a str>,
    location: Pinned<'a, Location>,
) -> Option<LabelBacktrace<'a>> {
    derive_hybrid_value_backtrace_in_capture_environment(
        ctx,
        value,
        cached_backtrace,
        &[],
        symbol,
        location,
    )
}

#[expect(
    clippy::option_option,
    reason = "Conveniently represent a backtrace's presence/absence"
)]
fn derive_hybrid_value_backtrace_in_capture_environment<'a>(
    ctx: &AnalysisContext<'a>,
    value: &ValueRef<'a>,
    cached_backtrace: Option<Option<LabelBacktrace<'a>>>,
    capture_env_snapshot: &[(Pinned<'a, Span<'a>>, Option<LabelBacktrace<'a>>)],
    symbol: Option<&'a str>,
    location: Pinned<'a, Location>,
) -> Option<LabelBacktrace<'a>> {
    let cached_backtrace = cached_backtrace.unwrap_or_else(|| value.backtrace());

    // peek before `as_function`: outer captures often arrive as `Value::Simple`
    // (e.g. a fresh function parameter), and the lazy upgrade in `as_function`
    // would coerce them into a blackbox `Value::Function`, irreversibly
    // corrupting every alias. for non-function captures the cached backtrace
    // is the best information we have to offer anyway.
    if !value.is_function() {
        return cached_backtrace;
    }

    let Some(func) = value.as_function() else {
        // should never happen, we checked above, but still
        return cached_backtrace;
    };

    let mut hybrid = derive_hybrid_function_outcome_backtrace(&func, symbol, location);

    for (outer_decl, binding) in func.captures() {
        let Some(backtrace) = hybrid else {
            // no point in continuing to realize if hybrid is already Bottom
            break;
        };

        let capture_concrete = if let Some(r#override) = capture_env_snapshot
            .iter()
            .find(|(override_decl, _)| *override_decl == outer_decl)
            .map(|(_, r#override)| r#override)
        {
            // this function's outcome may contain synthetics for captures that
            // also belong to the closure whose captures we are currently
            // realizing (i.e., sibling captures). we use that closure's stable
            // per-capture snapshot instead of rereading the mutable symbol
            // table, otherwise sibling capture synthetics can survive this
            // inner function realization
            r#override.as_ref().map(Cow::Borrowed)
        } else {
            let live_concrete = ctx
                .symtab()
                .get_symbol_by_declaration(outer_decl)
                .and_then(|sym| sym.borrow().value().get().backtrace());

            if live_concrete
                .as_ref()
                .is_some_and(|bt| bt.label().has_any_synthetic())
            {
                // up-to-date outer symbol value is labeled with synthetic
                // tags, so we cannot use it in LabelBacktrace::realize, or
                // otherwise the synthetics will never be realized and
                // eventually escape their respective function -- so we must
                // use the fallback, which might be unsound if it has become
                // stale

                binding.hybrid_fallback().unwrap().map(Cow::Borrowed)
            } else {
                // up-to-date outer symbol value is fully concrete, so we can
                // use it

                live_concrete.map(Cow::Owned)
            }
        };

        hybrid = backtrace.realize(
            func.r#ref(),
            SyntheticSlot::Capture(binding.index()),
            capture_concrete.as_deref(),
        );
    }

    LabelBacktrace::combine_options(
        hybrid,
        cached_backtrace,
        LabelBacktraceKind::Expression,
        Cow::Borrowed(value.location()),
    )
}

// returned backtrace is stripped of param/receiver/implicit-branch synthetics
// (i.e., what would only be available for realization at each call site), but
// preserves concrete tags as well as capture-related synthetics
fn derive_hybrid_function_outcome_backtrace<'a>(
    func: &FunctionValue<'a>,
    symbol: Option<&'a str>,
    location: Pinned<'a, Location>,
) -> Option<LabelBacktrace<'a>> {
    let children: Vec<_> = func
        .outcome()?
        .iter()
        .filter_map(ValueRef::backtrace)
        .collect();

    #[rustfmt::skip]
    let concrete = LabelBacktrace::fold(
        &children,
        LabelBacktraceKind::Expression,
        symbol,
        location,
    )?;

    realize_function_parameter_synthetics(func, concrete)
}

fn realize_function_parameter_synthetics<'a>(
    func: &FunctionValue<'a>,
    mut concrete: LabelBacktrace<'a>,
) -> Option<LabelBacktrace<'a>> {
    // note that this does not realize for captured variables

    for index in 0..func.parameter_count().unwrap_or(0) {
        concrete = concrete.realize(func.r#ref(), SyntheticSlot::Param(index), None)?;
    }

    concrete = concrete.realize(func.r#ref(), SyntheticSlot::Receiver, None)?;

    concrete = concrete.realize(func.r#ref(), SyntheticSlot::CallSiteBranch, None)?;

    Some(concrete)
}
