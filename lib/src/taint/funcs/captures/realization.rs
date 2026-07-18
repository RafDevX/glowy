use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
};

use parser::{Location, Span};

use crate::{
    Pinned,
    context::AnalysisContext,
    labels::{FunctionRef, Label, LabelBacktrace, LabelBacktraceKind, LabelTag, SyntheticSlot},
    snapshots::SnapshotAware,
    symbols::SymbolRef,
    values::{CaptureBinding, FunctionValue, ValueRef},
};

pub(super) struct CaptureEnvSnapshot<'a>(HashMap<Pinned<'a, Span<'a>>, Option<LabelBacktrace<'a>>>);

impl<'a> CaptureEnvSnapshot<'a> {
    pub fn empty() -> Self {
        // HashMap does not allocate until first inserted into
        Self(HashMap::new())
    }

    pub fn derive_new_stable(ctx: &AnalysisContext<'a>, func: &FunctionValue<'a>) -> Self {
        Self::derive_new(ctx, func, true)
    }

    pub fn derive_new_at_entry(ctx: &AnalysisContext<'a>, func: &FunctionValue<'a>) -> Self {
        Self::derive_new(ctx, func, false)
    }

    fn derive_new(
        ctx: &AnalysisContext<'a>,
        func: &FunctionValue<'a>,
        include_body_mutations: bool,
    ) -> Self {
        let mut current = Self::empty();

        loop {
            let next = current.derive_next_step(ctx, func, include_body_mutations);

            if next.snapshot_aware_eq(&current) {
                return current; // stabilization achieved
            }

            current = next;
        }
    }

    fn derive_next_step(
        &self,
        ctx: &AnalysisContext<'a>,
        func: &FunctionValue<'a>,
        include_body_mutations: bool,
    ) -> Self {
        let mut captures: Vec<_> = func.captures().collect();

        // for determinism
        captures.sort_by_key(|(_, binding)| binding.index());

        let map = captures
            .iter()
            .map(|(outer_decl, binding)| {
                let mut backtrace = derive_concrete_backtrace_or_fallback(
                    ctx,
                    func.r#ref(),
                    *outer_decl,
                    binding,
                    self,
                    include_body_mutations,
                );

                // capture mutations can introduce mutual dependencies (e.g.,
                // `x` is mutated under a branch on `y`, while a deferred reset
                // of `y` executes under a return path that depends on `x`).
                // initially, the empty starting snapshot supplies Bottom for
                // each dependency, and then subsequent steps substitute the
                // previous approximation. by deriving `backtrace` again each
                // derivation step, this computes the least fixed point instead
                // of repeatedly expanding a cycle
                for (dependency_outer_decl, dependency_binding) in &captures {
                    let dependency = self.get(dependency_outer_decl).and_then(Option::as_ref);

                    backtrace = backtrace.and_then(|current| {
                        current.realize(
                            func.r#ref(),
                            SyntheticSlot::Capture(dependency_binding.index()),
                            dependency,
                        )
                    });
                }

                (*outer_decl, backtrace)
            })
            .collect();

        Self(map)
    }

    pub fn get(&self, outer_decl: &Pinned<'a, Span<'a>>) -> Option<&Option<LabelBacktrace<'a>>> {
        self.0.get(outer_decl)
    }
}

impl SnapshotAware for CaptureEnvSnapshot<'_> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        self.0.snapshot_aware_eq(&other.0)
    }
}

fn derive_concrete_backtrace_or_fallback<'a>(
    ctx: &AnalysisContext<'a>,
    func: &FunctionRef<'a>,
    outer_decl: Pinned<'a, Span<'a>>,
    binding: &CaptureBinding<'a>,
    capture_env_snapshot: &CaptureEnvSnapshot<'a>,
    include_body_mutations: bool,
) -> Option<LabelBacktrace<'a>> {
    let symbol = super::resolve_capture_symbol(ctx, outer_decl);

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

    if include_body_mutations {
        // we need to merge the concrete with all other intermediate possible
        // values for the capture, based on whatever mutations took place during
        // the function body so that we can properly support read+mutate+read
        // gadgets; see `apply_capture_mutations_and_merge_capture_backtraces`

        LabelBacktrace::combine_options(
            concrete,
            binding.mutation_backtrace().cloned(),
            LabelBacktraceKind::ClosureCaptureBinding,
            Cow::Borrowed(&value_location),
        )
    } else {
        // the union above is not suitable for enforcement checks, since their
        // stored backtraces already encode mutations preceding the check

        concrete
    }
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
pub(super) fn derive_hybrid_symbol_backtrace<'a>(
    ctx: &AnalysisContext<'a>,
    symbol: &SymbolRef<'a>,
    capture_env_snapshot: &CaptureEnvSnapshot<'a>,
) -> Option<LabelBacktrace<'a>> {
    derive_hybrid_symbol_backtrace_with_active(
        ctx,
        symbol,
        capture_env_snapshot,
        &mut HashSet::new(),
    )
}

// as much as possible is made concrete, but some synthetics might persist
fn derive_hybrid_symbol_backtrace_with_active<'a>(
    ctx: &AnalysisContext<'a>,
    symbol: &SymbolRef<'a>,
    capture_env_snapshot: &CaptureEnvSnapshot<'a>,
    active_symbols: &mut HashSet<Pinned<'a, Span<'a>>>,
) -> Option<LabelBacktrace<'a>> {
    let borrowed = symbol.borrow();
    let declared_name = borrowed.declared_name();
    let value = borrowed.value().get();
    drop(borrowed);

    if !active_symbols.insert(declared_name) {
        // function-valued captures can form cycles (such as a closure capturing
        // the variable to which it is assigned), so we need to prevent infinite
        // recursion by returning an approximation if re-queried
        return value.backtrace();
    }

    let result = derive_hybrid_value_backtrace_in_capture_environment(
        ctx,
        &value,
        None,
        capture_env_snapshot,
        Some(declared_name.content()),
        declared_name.pinned_location(),
        active_symbols,
    );

    active_symbols.remove(&declared_name);

    result
}

// as much as possible is made concrete, but some synthetics might persist
#[expect(
    clippy::option_option,
    reason = "Conveniently represent a backtrace's presence/absence"
)]
pub fn derive_hybrid_value_backtrace<'a>(
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
        &CaptureEnvSnapshot::empty(),
        symbol,
        location,
        &mut HashSet::new(),
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
    capture_env_snapshot: &CaptureEnvSnapshot<'a>,
    symbol: Option<&'a str>,
    location: Pinned<'a, Location>,
    active_symbols: &mut HashSet<Pinned<'a, Span<'a>>>,
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

        let capture_concrete = if let Some(r#override) = capture_env_snapshot.get(&outer_decl) {
            // this function's outcome may contain synthetics for captures that
            // also belong to the closure whose captures we are currently
            // realizing (i.e., sibling captures). we use that closure's stable
            // per-capture snapshot instead of rereading the mutable symbol
            // table, otherwise sibling capture synthetics can survive this
            // inner function realization
            r#override.as_ref().map(Cow::Borrowed)
        } else {
            let live_concrete =
                ctx.symtab()
                    .get_symbol_by_declaration(outer_decl)
                    .and_then(|sym| {
                        // take into account transitive captures
                        derive_hybrid_symbol_backtrace_with_active(
                            ctx,
                            &sym,
                            capture_env_snapshot,
                            active_symbols,
                        )
                    });

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
