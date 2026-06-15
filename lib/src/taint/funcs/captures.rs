use std::borrow::Cow;

use parser::{
    Location, Span,
    ast::{BlockNode, FunctionParamDeclNode, FunctionSignatureNode},
};

use crate::{
    Pinned,
    context::AnalysisContext,
    labels::{Label, LabelBacktrace, LabelBacktraceKind, LabelTag, SyntheticSlot},
    symbols::{Symbol, SymbolRef},
    values::{CaptureBinding, FunctionRef, FunctionValue, SelfAwareBacktraceContainer, ValueRef},
};

mod collector;

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

        let outer_decl = {
            let borrowed = symbol.borrow();

            if !borrowed.mutable() {
                // we don't need to worry about immutable symbols because their
                // value will remain constant forever, meaning that it's fine to
                // evaluate them within the function definition and we will
                // never be able to overwrite them from within the closure
                continue;
            }

            borrowed.declared_name()
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
        );

        ctx.declare_new_symbol(Symbol::new_ref(
            local_decl,
            true,
            ValueRef::from(capture_backtrace),
        ));
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

        let hybrid = derive_hybrid_symbol_backtrace(ctx, &outer_symbol);
        binding.set_hybrid_fallback(hybrid);
    }
}

pub fn apply_capture_mutations<'a>(
    ctx: &mut AnalysisContext<'a>,
    func: &FunctionValue<'a>,
    args: &[(ValueRef<'a>, Option<&LabelBacktrace<'a>>)],
    location: &Location,
) {
    let capture_backtraces = derive_best_backtraces_for_captures(ctx, func);

    // calculate the concrete call-site backtrace for each real parameter, which
    // is later needed to realize capture labels after a function call with the
    // actual argument values; this is necessary because a capture may
    // indirectly depend on any argument, so we must resolve each capture
    // against each parameter position
    let arg_concretes = if let Some(signature) = func.signature() {
        signature
            .params
            .iter()
            .enumerate()
            .map(|(index, param)| {
                (
                    index,
                    super::calculate_concrete_backtrace(
                        ctx,
                        index,
                        param.ids.first(),
                        param.variadic,
                        &param.r#type,
                        args,
                        location,
                    ),
                )
            })
            .collect::<Vec<_>>()
    } else {
        vec![]
    };

    let call_branch = super::calculate_effective_call_site_branch_backtrace_for(
        ctx,
        func,
        ctx.pin(location.clone()),
    );

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

        for (index, concrete) in &arg_concretes {
            realized = Cow::Owned(realized.realize(
                func.r#ref(),
                SyntheticSlot::Param(*index),
                concrete.as_ref(),
            ));
        }

        for (index, backtrace) in &capture_backtraces {
            realized = Cow::Owned(realized.realize(
                func.r#ref(),
                SyntheticSlot::Capture(*index),
                backtrace.as_ref(),
            ));
        }

        // block to force correct formatting
        {
            realized = Cow::Owned(realized.realize(
                func.r#ref(),
                SyntheticSlot::CallSiteBranch,
                call_branch.as_ref(),
            ));
        };

        if *realized == local_value {
            // no realization happened; ensure compliance with AssumedImmutable
            realized = Cow::Owned(local_value.clone_inner());
        }

        if ctx.was_symbol_declared_within_active_split(&outer_symbol) == Some(false) {
            let outer_value = outer_symbol.borrow().value().get();

            realized = Cow::Owned(realized.nest_backtrace(
                LabelBacktraceKind::Assignment,
                Some(outer_decl.content()),
                outer_value.location().clone(),
                outer_value.backtrace(),
            ));
        }

        outer_symbol.borrow_mut().set_value(realized.into_owned());
    }
}

pub fn derive_best_backtraces_for_captures<'a>(
    ctx: &AnalysisContext<'a>,
    func: &FunctionValue<'a>,
) -> Vec<(usize, Option<LabelBacktrace<'a>>)> {
    let mut concretes: Vec<_> = func
        .captures()
        .map(|(outer_decl, binding)| {
            (
                binding.index(),
                derive_concrete_backtrace_or_fallback(ctx, outer_decl, binding),
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

    concretes
}

fn derive_concrete_backtrace_or_fallback<'a>(
    ctx: &AnalysisContext<'a>,
    outer_decl: Pinned<'a, Span<'a>>,
    binding: &CaptureBinding<'a>,
) -> Option<LabelBacktrace<'a>> {
    let symbol = ctx.symtab().get_symbol_by_declaration(outer_decl).unwrap();

    let hybrid = derive_hybrid_symbol_backtrace(ctx, &symbol);

    if hybrid
        .as_ref()
        .map(LabelBacktrace::label)
        .is_some_and(Label::has_any_synthetic)
        && let Some(fallback) = binding.hybrid_fallback()
    {
        return fallback.cloned();
    }

    hybrid
}

// as much as possible is made concrete, but some synthetics might persist
fn derive_hybrid_symbol_backtrace<'a>(
    ctx: &AnalysisContext<'a>,
    symbol: &SymbolRef<'a>,
) -> Option<LabelBacktrace<'a>> {
    let borrowed = symbol.borrow();
    let declared_name = borrowed.declared_name();
    let value = borrowed.value().get();
    drop(borrowed);

    derive_hybrid_value_backtrace(
        ctx,
        &value,
        None,
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
    let cached_backtrace = cached_backtrace.unwrap_or_else(|| value.backtrace());

    let Some(func) = value.as_function() else {
        // not a function, just a normal value, so this is all we can do
        // (there are no other treatment options available to us)
        return cached_backtrace;
    };

    let mut hybrid = derive_hybrid_function_outcome_backtrace(&func, symbol, location);

    for (outer_decl, binding) in func.captures() {
        let Some(backtrace) = hybrid else {
            // no point in continuing to realize if hybrid is already Bottom
            break;
        };

        let live_concrete = ctx
            .symtab()
            .get_symbol_by_declaration(outer_decl)
            .and_then(|sym| sym.borrow().value().get().backtrace());

        let capture_concrete = if live_concrete
            .as_ref()
            .is_some_and(|bt| bt.label().has_any_synthetic())
        {
            // up-to-date outer symbol value is labeled with synthetic tags,
            // so we cannot use it in LabelBacktrace::realize, or otherwise the
            // synthetics will never be realized and eventually escape their
            // respective function -- so we must use the fallback, which might
            // be unsound if it has become stale

            binding.hybrid_fallback().unwrap()
        } else {
            // up-to-date outer symbol value is fully concrete, so we can use it

            live_concrete.as_ref()
        };

        hybrid = backtrace.realize(
            func.r#ref(),
            SyntheticSlot::Capture(binding.index()),
            capture_concrete,
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
