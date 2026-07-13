use std::{borrow::Cow, iter, rc::Rc};

use parser::{
    Location, Span,
    ast::{CallNode, ExprNode, FunctionSignatureNode, TypeNode},
};

use crate::{
    Pinned,
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{Label, LabelBacktrace, LabelBacktraceKind, SyntheticSlot},
    policy::{SinkDescriptor, SinkKind},
    taint::{
        annotations, enforcement,
        funcs::{ResolvedCall, captures},
    },
    values::{
        BacktraceContainer, FunctionValue, InherentSourceOrRevocation, MobiusValue,
        SelfAwareBacktraceContainer, Value, ValueRef,
    },
};

#[expect(clippy::option_option, reason = "Represent receiver absent vs Bottom")]
struct CallRealization<'call, 'a> {
    receiver: Option<Option<&'call LabelBacktrace<'a>>>,
    ids: &'call [(Option<&'call Span<'a>>, bool, &'call TypeNode<'a>)],
    args: &'call [(ValueRef<'a>, Option<&'call LabelBacktrace<'a>>)],
    capture_concretes: &'call [(usize, Option<LabelBacktrace<'a>>)],
    location: &'call Pinned<'a, Location>,
}

#[expect(
    clippy::too_many_lines,
    reason = "Tight coupling between the sub-stages would make further splitting more confusing"
)]
pub fn apply_call<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &CallNode<'a>,
    resolved: ResolvedCall<'a>,
) -> Vec<ValueRef<'a>> {
    let ResolvedCall {
        callee: mut value,
        blackbox_replacement,
        method_receiver_value,
        arg_values,
    } = resolved;

    // re-borrow the callee's FunctionValue; `resolve_call` already validated
    // that this returns `Some` (and produced an error otherwise), so the
    // expect upholds that invariant
    let value_func = value
        .as_function()
        .expect("resolve_call ensures callee is a function value");

    // reconstruct now that we have callee borrowed again
    let func: &FunctionValue<'a> = blackbox_replacement.as_deref().unwrap_or(&value_func);

    let ids = func.signature().map(collect_param_id_slots);

    let with_backtraces: Vec<_> = arg_values.iter().map(|v| (v, v.backtrace())).collect();

    // reshape this as a ref more friendly for calling downstream functions
    let with_backtraces_ref: Vec<_> = with_backtraces
        .iter()
        .map(|(v, bt)| ((*v).clone(), bt.as_ref()))
        .collect();

    // detect calls to the current function's yield parameter (Go's
    // range-over-func: an iterator function `func(yield func(...) bool)`
    // produces values by invoking yield, and we propagate those values'
    // labels back to `for x := range <fn>` via the outer FunctionValue)
    let yield_target = if let ExprNode::Name(id) = &*node.func {
        ctx.current_function()
            .as_ref()
            .and_then(ValueRef::as_function)
            .as_deref()
            .and_then(FunctionValue::yield_param)
            .copied()
            .filter(|decl| {
                ctx.symtab()
                    .get_symbol(id.content())
                    .is_some_and(|sym| sym.borrow().declared_name() == *decl)
            })
    } else {
        None
    };

    if yield_target.is_some()
        && let Some(mut current) = ctx.current_function()
        && let Some(mut current_mut) = current.as_function_mut()
    {
        let arg_bts: Vec<_> = with_backtraces.iter().map(|(_, bt)| bt.as_ref()).collect();

        current_mut.record_yield_call(
            &arg_bts,
            ctx.branch_backtrace(),
            &ctx.pin(node.location.clone()),
        );
    }

    if let Some(annotation) = &node.annotation
        && let Some(directive) = annotations::parse_supported_directive(ctx, annotation)
    {
        match directive {
            annotations::CallDirective::AllowSink | annotations::CallDirective::DenySink => {
                let sink = SinkDescriptor::new(
                    SinkKind::Call,
                    directive == annotations::CallDirective::AllowSink,
                    &annotation.tags,
                    node.location.clone(), // call, not annotation
                );

                if let Some(sink) = sink {
                    for (_, arg_bt) in &with_backtraces {
                        enforcement::trigger_sink(ctx, Cow::Borrowed(&sink), arg_bt.clone());
                    }
                } else {
                    ctx.report_error(AnalysisErrorKind::InvalidDenySinkSemantics {
                        location: annotation.location.clone(),
                    });
                }
            }
            annotations::CallDirective::Assert => {
                let sequence = Label::sequence_from_tags(&annotation.tags);

                for (_, arg_bt) in &with_backtraces {
                    enforcement::trigger_assertion(
                        ctx,
                        &sequence,
                        arg_bt.clone(),
                        node.location.clone(),
                    );
                }
            }
        }
    }

    let call_location = ctx.pin(node.location.clone());

    for sink in func.sinks() {
        let descriptor = sink.as_descriptor_at(node.location.clone());

        for (index, (_, arg_bt)) in with_backtraces.iter().enumerate() {
            if !sink.applies_to_arg(index) {
                // this sink is scoped to a specific arg position and the
                // current one doesn't match, so skip triggering it here
                continue;
            }

            enforcement::trigger_sink(ctx, Cow::Borrowed(&descriptor), arg_bt.clone());
        }
    }

    let Some(outcome) = func.outcome() else {
        // we don't have a known implementation of this function, so we must
        // treat it as a blackbox and assume the label of all its outputs is the
        // union of the label of all its inputs; we can't do anything fancy

        let mut result = visit_blackbox_call(
            ctx,
            func,
            &with_backtraces_ref,
            &call_location,
            func.signature(),
        );

        apply_call_blanket_sources(func, &node.args, &call_location, &mut result);
        apply_call_blanket_revocations(func, &node.args, &mut result);

        return result;
    };

    // by this point, we know `func.outcome()` is `Some`, which means we have
    // an implementation for it (i.e., we have access to the function's source
    // code and we have analyzed it) -- given this information, there should be
    // no possibility that we don't have the function's declaration, so we
    // must know its signature, meaning that `ids` will be Some, and this unwrap
    // will never panic if all assumptions hold
    let ids = ids.unwrap();

    let receiver = match &method_receiver_value {
        // method-form call: reuse the receiver value we already evaluated up
        // top, taint and all
        Some(base) => Some(base.backtrace()),
        // this is a method called via a non-selection expression (e.g. in the
        // form `f := obj.M; f()`); we don't have a `selection.base` to read the
        // bound receiver from here, but its taint was already nested into
        // `func.backtrace()` at the binding site in `visit_selection`, and
        // *that* backtrace gets nested into the result below -- so the
        // receiver's labels still reach the call result.
        // nevertheless, we MUST still realize SyntheticSlot::Receiver (with no
        // concrete backtrace) to cancel the synthetic; otherwise it would
        // escape this function and eventually reach `main` (breaking invariant)
        None if func.has_receiver() => Some(None),
        // not a method call at all, there is no receiver backtrace
        None => None,
    };

    let capture_concretes =
        captures::call_site::apply_capture_mutations_and_merge_capture_backtraces(
            ctx,
            func,
            &with_backtraces_ref,
            &call_location,
        );

    let call_realization = CallRealization {
        receiver: receiver.as_ref().map(Option::as_ref),
        ids: &ids,
        args: &with_backtraces_ref,
        capture_concretes: &capture_concretes,
        location: &call_location,
    };

    handle_deferred_checks(ctx, func, &call_realization);

    let mut result = calculate_call_result(ctx, func, outcome, &call_realization);

    apply_call_blanket_sources(func, &node.args, &call_location, &mut result);

    // need to nest the function's backtrace into the result because the
    // function itself was accessed
    if let Some(bt) = func.backtrace() {
        for realized in &mut result {
            *realized = realized.nest_backtrace(
                LabelBacktraceKind::Expression,
                None,
                call_location.clone(),
                [bt.clone()],
            );
        }
    }

    apply_call_blanket_revocations(func, &node.args, &mut result);

    for realized in &mut result {
        *realized = realized.with_location(call_location.clone());
    }

    // the result's static type is necessarily what the signature declares, not
    // what was passed to `return`, per Go semantics, so we should override
    tag_results_with_declared_types(func, &mut result);

    // re-borrow as mutable
    drop(value_func);

    if blackbox_replacement.is_none()
        && let Some(mut func_mut) = value.as_function_mut()
    {
        func_mut.record_call();
    }

    result
}

fn collect_param_id_slots<'sig, 'a>(
    signature: &'sig FunctionSignatureNode<'a>,
) -> Vec<(Option<&'sig Span<'a>>, bool, &'sig TypeNode<'a>)> {
    let mut ids = vec![];

    for param in &signature.params {
        if param.ids.is_empty() {
            ids.push((None, param.variadic, &param.r#type));
        } else {
            let iter = param
                .ids
                .iter()
                .map(|id| (Some(id), param.variadic, &param.r#type));

            ids.extend(iter);
        }
    }

    ids
}

fn visit_blackbox_call<'a>(
    ctx: &mut AnalysisContext<'a>,
    func: &FunctionValue<'a>,
    args: &[(ValueRef<'a>, Option<&LabelBacktrace<'a>>)],
    call_location: &Pinned<'a, Location>,
    signature_hint: Option<&FunctionSignatureNode<'a>>,
) -> Vec<ValueRef<'a>> {
    // note that this case is still possible even if func is a closure, since
    // e.g. closures can be assigned to previously declared (but not
    // initialized) variables in an effort to make them self-recursive, as the
    // whole point of closure capturing is that outer symbols are only really
    // "evaluated" when the closure is invoked
    captures::call_site::apply_capture_mutations(ctx, func, args, call_location);

    let bt = LabelBacktrace::fold(
        args.iter()
            .filter_map(|(_, bt)| *bt)
            .chain(func.backtrace()),
        LabelBacktraceKind::BlackboxCall,
        None,
        call_location.clone(),
    );

    let mut result = if let Some(signature) = signature_hint {
        // we have a signature, so we know exactly how many values it returns
        // and so can use that known cardinality here

        iter::repeat_with(|| {
            ValueRef::from_backtrace_or_bottom_at(
                bt.clone(), // clone makes borrow checker happy
                || call_location.clone(),
            )
        })
        .take(signature.result.len())
        .collect()
    } else {
        // we have no way to know how many values this call returns, so the best
        // we can do is return a Möbius value that can be expanded to however
        // many values the invoker expects

        let inner = ValueRef::from_backtrace_or_bottom_at(bt, || call_location.clone());

        vec![ValueRef::new(
            Value::Mobius(MobiusValue::new(inner)),
            call_location.clone(),
            None,
        )]
    };

    // even if we don't have an implementation, we might have a signature
    tag_results_with_declared_types(func, &mut result);

    result
}

fn apply_call_blanket_sources<'a>(
    func: &FunctionValue<'a>,
    args: &[ExprNode<'a>],
    call_location: &Pinned<'a, Location>,
    result: &mut [ValueRef<'a>],
) {
    let sources: Vec<_> = func
        .sources()
        .iter()
        .filter(|source| !source.label().is_bottom())
        .filter(|source| source.applies_to_args(args))
        .collect();

    if sources.is_empty() {
        return;
    }

    let new_source_backtrace = |label| {
        LabelBacktrace::new_root(
            LabelBacktraceKind::BlanketSource,
            label,
            None,
            call_location.clone(),
        )
    };

    // handle Möbius/Expandable specially
    if let [single] = result
        && single.supports_overriding_expand_indices()
    {
        for source in sources {
            let Some(backtrace) = new_source_backtrace(source.label().clone()) else {
                continue;
            };

            *single = if source.result_selector().is_empty() {
                single.nest_backtrace(
                    LabelBacktraceKind::Expression,
                    None,
                    call_location.clone(),
                    [backtrace],
                )
            } else {
                single
                    .try_nest_override_expand_indices(
                        source.result_selector().iter().copied(),
                        LabelBacktraceKind::Expression,
                        None,
                        call_location,
                        &[backtrace],
                    )
                    .unwrap()
            };
        }

        return;
    }

    for (index, value) in result.iter_mut().enumerate() {
        let blanket_label: Label<'_> = sources
            .iter()
            .filter(|source| source.applies_to_result(index))
            .copied()
            .map(InherentSourceOrRevocation::label)
            .sum();

        let Some(backtrace) = new_source_backtrace(blanket_label) else {
            continue;
        };

        *value = value.nest_backtrace(
            LabelBacktraceKind::Expression,
            None,
            call_location.clone(),
            [backtrace],
        );
    }
}

fn apply_call_blanket_revocations<'a>(
    func: &FunctionValue<'a>,
    args: &[ExprNode<'a>],
    result: &mut [ValueRef<'a>],
) {
    let revocations: Vec<_> = func
        .revocations()
        .iter()
        .filter(|revocation| !revocation.label().is_bottom())
        .filter(|revocation| revocation.applies_to_args(args))
        .collect();

    if revocations.is_empty() {
        return;
    }

    if let [single] = result
        && single.supports_overriding_expand_indices()
    {
        for revocation in revocations {
            if revocation.result_selector().is_empty() {
                single.subtract_label(revocation.label());
            } else {
                *single = single
                    .try_subtract_override_expand_indices(
                        revocation.result_selector().iter().copied(),
                        revocation.label(),
                    )
                    .unwrap();
            }
        }

        return;
    }

    for (index, value) in result.iter_mut().enumerate() {
        let blanket_label: Label<'_> = revocations
            .iter()
            .filter(|revocation| revocation.applies_to_result(index))
            .copied()
            .map(InherentSourceOrRevocation::label)
            .sum();

        value.subtract_label(&blanket_label);
    }
}

fn handle_deferred_checks<'a>(
    ctx: &mut AnalysisContext<'a>,
    func: &FunctionValue<'a>,
    call: &CallRealization<'_, 'a>,
) {
    let mut deferred_checks = Vec::from(func.deferred_checks());

    if let Some(receiver) = call.receiver {
        deferred_checks = deferred_checks
            .iter()
            .filter_map(|check| check.realize(func.r#ref(), SyntheticSlot::Receiver, receiver))
            .collect();
    }

    for (index, (id, variadic, r#type)) in call.ids.iter().copied().enumerate() {
        #[rustfmt::skip]
        let concrete = calculate_concrete_backtrace(
            ctx,
            index,
            id,
            variadic,
            r#type,
            call.args,
            Cow::Borrowed(call.location),
        );

        deferred_checks = deferred_checks
            .iter()
            .filter_map(|check| {
                check.realize(func.r#ref(), SyntheticSlot::Param(index), concrete.as_ref())
            })
            .collect();
    }

    for (index, concrete) in call.capture_concretes {
        deferred_checks = deferred_checks
            .iter()
            .filter_map(|check| {
                check.realize(
                    func.r#ref(),
                    SyntheticSlot::Capture(*index),
                    concrete.as_ref(),
                )
            })
            .collect();
    }

    #[rustfmt::skip]
    let call_branch = super::calc_effective_call_site_branch_backtrace_for(
        ctx,
        func,
        call.location
    );

    deferred_checks = deferred_checks
        .iter()
        .filter_map(|check| {
            check.realize(
                func.r#ref(),
                SyntheticSlot::CallSiteBranch,
                call_branch.as_ref(),
            )
        })
        .collect();

    // we don't need to -1 because this value is before the call count has been
    // incremented for the current call, so it already corresponds to a 0-index
    let call_index = func.call_count();

    for check in deferred_checks {
        let triggered = enforcement::try_trigger_deferred_check(ctx, &check, call_index);

        if !triggered {
            // propagate further
            ctx.defer_enforcement_check(check);
        }
    }
}

fn calculate_call_result<'a>(
    ctx: &AnalysisContext<'a>,
    func: &FunctionValue<'a>,
    outcome: &Vec<ValueRef<'a>>,
    call: &CallRealization<'_, 'a>,
) -> Vec<ValueRef<'a>> {
    let mut result = vec![];

    'components: for component in outcome {
        let mut realized = component.clone();

        if let Some(receiver) = call.receiver {
            realized = realized.realize(func.r#ref(), SyntheticSlot::Receiver, receiver);
        }

        // vvv cannot actually do this because if/else would have diff types,
        // vvv so we must create it manually instead...
        //
        // let iter = params
        //     .iter()
        //     .flat_map(|param| {
        //         if param.ids.is_empty() {
        //             iter::once((param.variadic, None))
        //         } else {
        //             param.ids.iter().map(|id| (param.variadic, Some(id)))
        //         }
        //     })
        //     .enumerate();

        for (index, (id, variadic, r#type)) in call.ids.iter().copied().enumerate() {
            if realized.is_bottom() && realized.allows_lossless_downgrade() {
                // no sense in continuing, we'll never evolve from this state

                result.push(realized);

                continue 'components;
            }

            #[rustfmt::skip]
            let concrete = calculate_concrete_backtrace(
                ctx,
                index,
                id,
                variadic,
                r#type,
                call.args,
                Cow::Borrowed(call.location)
            );

            #[rustfmt::skip]
            {
                realized = realized.realize(
                    func.r#ref(),
                    SyntheticSlot::Param(index),
                    concrete.as_ref()
                );
            };
        }

        for (index, concrete) in call.capture_concretes {
            if realized.is_bottom() && realized.allows_lossless_downgrade() {
                // no sense in continuing, we'll never evolve from this state

                result.push(realized);

                continue 'components;
            }

            realized = realized.realize(
                func.r#ref(),
                SyntheticSlot::Capture(*index),
                concrete.as_ref(),
            );
        }

        realized = realized.realize(
            func.r#ref(),
            SyntheticSlot::CallSiteBranch,
            ctx.branch_backtrace(),
        );

        result.push(realized);
    }

    // if this is a sanitizer, apply revocation
    if !func.sanitizer().is_bottom() {
        for realized in &mut result {
            realized.subtract_label(func.sanitizer());
        }
    }

    result
}

fn tag_results_with_declared_types<'a>(func: &FunctionValue<'a>, results: &mut [ValueRef<'a>]) {
    // we already pre-resolved the results' declared types at definition-time,
    // since they may rely on contextual information only present at that time
    // and no longer available here at call-time, especially for unqualified
    // types used in functions defined in a different file than its invokers

    // note that if FunctionValue::declared_result_types is not set (i.e., empty
    // Vec), this just comes a no-op as intended, since zip will yield nothing

    for (result, declared_type) in results.iter_mut().zip(func.declared_result_types()) {
        if let Some(r#type) = declared_type {
            result.set_declared_type(Rc::clone(r#type));
        }
    }
}

pub fn calculate_concrete_backtrace<'a>(
    ctx: &AnalysisContext<'a>,
    index: usize,
    id: Option<&Span<'a>>,
    variadic: bool,
    r#type: &TypeNode<'a>,
    args: &[(ValueRef<'a>, Option<&LabelBacktrace<'a>>)],
    location: Cow<Pinned<'a, Location>>,
) -> Option<LabelBacktrace<'a>> {
    if variadic {
        LabelBacktrace::fold(
            args[index..].iter().flat_map(|(_, bt)| bt).copied(),
            LabelBacktraceKind::FunctionVariadicAggregation,
            id.map(Span::content),
            location.into_owned(),
        )
    } else {
        let (value, cached_backtrace) = &args[index];

        // for args bound to function-typed params, used the arg's hybrid
        // backtrace, as it takes into account the function's outcome rather
        // than just its intrinsic access backtrace (vs. cached_backtrace)

        // this check is needed here even if derive_hybrid_value_backtrace
        // implements similar branching, because it uses as_function and that
        // could trigger an upgrade even when we know the param type is not a
        // function, leading to incorrect behavior
        if matches!(r#type, TypeNode::Function { .. }) {
            captures::realization::derive_hybrid_value_backtrace(
                ctx,
                value,
                Some(cached_backtrace.cloned()),
                id.map(Span::content),
                value.location().clone(),
            )
        } else {
            cached_backtrace.cloned()
        }
    }
}
