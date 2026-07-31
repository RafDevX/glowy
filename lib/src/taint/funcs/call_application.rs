use std::{borrow::Cow, iter, rc::Rc};

use parser::{
    Location, Span,
    ast::{CallNode, ExprNode, TypeNode},
};

use crate::{
    Pinned,
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{Label, LabelBacktrace, LabelBacktraceKind, LabelTag, SyntheticSlot},
    policy::{SinkDescriptor, SinkKind},
    taint::{
        annotations, enforcement,
        funcs::{
            ResolvedCall,
            captures::{self, call_site::CallCaptureConcretes},
        },
    },
    types::TypeKind,
    values::{
        BacktraceContainer, FunctionRef, FunctionValue, InherentSourceOrRevocation, MobiusValue,
        SelfAwareBacktraceContainer, SimpleConstValue, UnifiedRealization, Value, ValueRef,
    },
};

#[expect(clippy::option_option, reason = "Represent receiver absent vs Bottom")]
struct CallRealization<'call, 'a> {
    receiver: Option<Option<&'call LabelBacktrace<'a>>>,
    ids: &'call [(Option<&'call Span<'a>>, bool, &'call TypeNode<'a>)],
    args: &'call [(ValueRef<'a>, Option<&'call LabelBacktrace<'a>>)],
    capture_concretes: &'call CallCaptureConcretes<'a>,
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
        method_receiver_value,
        arg_values,
        arg_consts,
    } = resolved;

    // re-borrow the callee's FunctionValue; `resolve_call` already validated
    // that this returns `Some` (and produced an error otherwise), so the
    // expect upholds that invariant
    let value_func = value
        .as_function()
        .expect("resolve_call ensures callee is a function value");

    let func: &FunctionValue<'a> = &value_func;

    let ids = func.signature().map(super::collect_parameter_slots);

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
    let yield_owner = resolve_current_yield_owner(ctx, node);
    // ^^^ "owner" as in the iterator func which receives yield as parameter

    if yield_owner.is_some()
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

    let capture_concretes = if func.signature().is_some() {
        Some(
            captures::call_site::apply_capture_mutations_and_derive_concretes(
                ctx,
                func,
                receiver.as_ref().map(Option::as_ref),
                &with_backtraces_ref,
                &call_location,
            ),
        )
    } else {
        None
    };

    let call_realization =
        if let Some((ids, capture_concretes)) = ids.as_ref().zip(capture_concretes.as_ref()) {
            let call_realization = CallRealization {
                receiver: receiver.as_ref().map(Option::as_ref),
                ids,
                args: &with_backtraces_ref,
                capture_concretes,
                location: &call_location,
            };

            #[rustfmt::skip]
            let call_branch = super::calc_effective_call_site_branch_backtrace_for(
                ctx,
                func,
                &call_location
            );

            handle_deferred_checks(ctx, func, &call_realization, call_branch.as_ref(), None);

            Some(call_realization)
        } else {
            // a completely unknown blackbox has no synthetic slots to realize,
            // but it may still be a recursively initialized closure with
            // relevant capture state
            captures::call_site::apply_capture_write_backs(
                ctx,
                func,
                receiver.as_ref().map(Option::as_ref),
                &with_backtraces_ref,
                &call_location,
            );

            None
        };

    let Some((outcome, call_realization)) = func.outcome().zip(call_realization) else {
        // we have no known implementation for this function (or at least one
        // possible implementation is unknown), so we must treat it as a
        // blackbox and assume the label of all its outputs is the union of the
        // label of all its inputs
        //
        // any known alternatives' summarized side effects and deferred checks
        // were still applied above

        let mut result = visit_blackbox_call(func, &with_backtraces_ref, &call_location);

        add_yield_feedback(yield_owner.as_ref(), &call_location, &mut result);
        apply_call_blanket_sources(func, &arg_consts, &call_location, &mut result);
        apply_call_blanket_revocations(func, &arg_consts, &mut result);

        let should_record_call = !func.deferred_checks().is_empty();
        drop(value_func);

        if should_record_call && let Some(mut func_mut) = value.as_function_mut() {
            func_mut.record_call();
        }

        return result;
    };

    let mut result = calculate_call_result(ctx, func, outcome, &call_realization);

    apply_call_blanket_sources(func, &arg_consts, &call_location, &mut result);

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

    apply_call_blanket_revocations(func, &arg_consts, &mut result);

    for realized in &mut result {
        *realized = realized.with_location(call_location.clone());
    }

    // the result's static type is necessarily what the signature declares, not
    // what was passed to `return`, per Go semantics, so we should override
    tag_results_with_declared_types(func, &mut result);

    // re-borrow as mutable
    drop(value_func);

    if let Some(mut func_mut) = value.as_function_mut() {
        func_mut.record_call();
    }

    result
}

fn visit_blackbox_call<'a>(
    func: &FunctionValue<'a>,
    args: &[(ValueRef<'a>, Option<&LabelBacktrace<'a>>)],
    call_location: &Pinned<'a, Location>,
) -> Vec<ValueRef<'a>> {
    let bt = LabelBacktrace::fold(
        args.iter()
            .filter_map(|(_, bt)| *bt)
            .chain(func.backtrace()),
        LabelBacktraceKind::BlackboxCall,
        None,
        call_location.clone(),
    );

    let mut result = if let Some(signature) = func.signature() {
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

fn resolve_current_yield_owner<'a>(
    ctx: &AnalysisContext<'a>,
    node: &CallNode<'a>,
) -> Option<FunctionRef<'a>> {
    let ExprNode::Name(id) = &*node.func else {
        return None;
    };

    let current = ctx.current_function()?;
    let func = current.as_function()?;
    let yield_param = func.yield_param()?;
    let symbol = ctx.symtab().get_symbol(id.content())?;

    (symbol.borrow().declared_name() == *yield_param).then(|| func.r#ref().clone())
}

fn add_yield_feedback<'a>(
    owner: Option<&FunctionRef<'a>>,
    location: &Pinned<'a, Location>,
    result: &mut [ValueRef<'a>],
) {
    let Some(owner) = owner else {
        return;
    };

    let synthetic = LabelTag::Synthetic {
        func: owner.clone(),
        slot: SyntheticSlot::YieldFeedback,
        identifier: None,
    };

    let feedback = LabelBacktrace::new_root(
        LabelBacktraceKind::FunctionParameter,
        Label::from_single(synthetic),
        None,
        location.clone(),
    )
    .unwrap();

    for value in result {
        *value = value.nest_backtrace(
            LabelBacktraceKind::Expression,
            None,
            location.clone(),
            [feedback.clone()],
        );
    }
}

fn apply_call_blanket_sources<'a>(
    func: &FunctionValue<'a>,
    arg_consts: &[Option<SimpleConstValue>],
    call_location: &Pinned<'a, Location>,
    result: &mut [ValueRef<'a>],
) {
    let sources: Vec<_> = func
        .sources()
        .iter()
        .filter(|source| !source.label().is_bottom())
        .filter(|source| source.applies_to_args(arg_consts))
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

pub(super) fn apply_call_blanket_revocations<'a>(
    func: &FunctionValue<'a>,
    arg_consts: &[Option<SimpleConstValue>],
    result: &mut [ValueRef<'a>],
) {
    let revocations: Vec<_> = func
        .revocations()
        .iter()
        .filter(|revocation| !revocation.label().is_bottom())
        .filter(|revocation| revocation.applies_to_args(arg_consts))
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
    call_branch: Option<&LabelBacktrace<'a>>,
    yield_feedback: Option<&LabelBacktrace<'a>>,
) {
    let parameter_concretes: Vec<_> = call
        .ids
        .iter()
        .copied()
        .enumerate()
        .map(|(index, (id, variadic, r#type))| {
            calculate_concrete_backtrace(
                ctx,
                index,
                id,
                variadic,
                r#type,
                call.args,
                Cow::Borrowed(call.location),
            )
        })
        .collect();

    let substitutions: Vec<_> = parameter_concretes
        .iter()
        .enumerate()
        .map(|(index, concrete)| (SyntheticSlot::Param(index), concrete.as_ref()))
        .chain(
            call.receiver
                .map(|concrete| (SyntheticSlot::Receiver, concrete)),
        )
        .chain(iter::once((SyntheticSlot::CallSiteBranch, call_branch)))
        .chain(iter::once((SyntheticSlot::YieldFeedback, yield_feedback)))
        // a deferred check's backtrace already represents mutations that
        // happened before that check in the function body. realizing it against
        // the entry snapshot preserves that ordering; a mutation-enriched
        // environment used for outcomes could incorrectly make later capture
        // mutations flow backwards in time
        .chain(
            call.capture_concretes
                .at_entry
                .iter()
                .map(|(index, concrete)| (SyntheticSlot::Capture(*index), concrete.as_ref())),
        )
        .collect();

    let mut realization = if ctx.stage().has_stable_labels() {
        // normal realization produces and preserves flattened aggregate roots
        // to keep recursive synthetics compact, but now everything is stable so
        // we can expand them here if this is a non-recursive call boundary;
        // i.e., genuinely recursive substitutions remain compact
        UnifiedRealization::enforcement(func.r#ref(), &substitutions)
    } else {
        UnifiedRealization::multiple(func.r#ref(), &substitutions)
    };

    let deferred_checks: Vec<_> = func
        .deferred_checks()
        .iter()
        .filter_map(|check| check.realize_unified(&mut realization))
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

pub struct IterableFunctionCall<'a> {
    args: Vec<ValueRef<'a>>,
    capture_concretes: CallCaptureConcretes<'a>,
    call_branch: Option<LabelBacktrace<'a>>,
}

impl<'a> IterableFunctionCall<'a> {
    pub fn new(
        ctx: &mut AnalysisContext<'a>,
        value: &ValueRef<'a>,
        location: &Pinned<'a, Location>,
    ) -> Self {
        let func = value
            .as_function()
            .expect("range-function operand must be a function");

        let signature = func
            .signature()
            .expect("range-function operand must have a signature");

        let ids = super::collect_parameter_slots(signature);

        // per the Go spec, ranging over an iterator function invokes it with a
        // compiler-synthesized yield callback. the callback value itself
        // carries no source-level taint; dependencies of its bool result are
        // modeled separately from the argument passed to the iterator
        let args: Vec<_> = ids
            .iter()
            .map(|_| ValueRef::new_bottom(location.clone(), None))
            .collect();

        let args_with_backtraces: Vec<_> = args.iter().cloned().map(|arg| (arg, None)).collect();

        let capture_concretes = CallCaptureConcretes::from_stable_environment(ctx, &func);

        let capture_realized = capture_concretes.realize_at_entry(&func);

        captures::call_site::apply_capture_mutations_and_derive_concretes(
            ctx,
            &capture_realized,
            func.has_receiver().then_some(None),
            &args_with_backtraces,
            location,
        );

        let call_branch =
            super::calc_effective_call_site_branch_backtrace_for(ctx, &func, location);

        Self {
            args,
            capture_concretes,
            call_branch,
        }
    }

    pub fn apply(
        self,
        ctx: &mut AnalysisContext<'a>,
        value: &mut ValueRef<'a>,
        location: &Pinned<'a, Location>,
        yield_feedback: Option<&LabelBacktrace<'a>>,
    ) {
        let func = value
            .as_function()
            .expect("range operand must remain a function during its loop");

        let signature = func
            .signature()
            .expect("range-function operand must retain its signature");

        let ids = super::collect_parameter_slots(signature);

        let args_with_backtraces: Vec<_> =
            self.args.iter().cloned().map(|arg| (arg, None)).collect();

        // the first application at range-expr evaluation handles effects that
        // that precede a yield. re-applying monotonically here adds
        // dependencies from code guarded by yield(false) now that caller
        // feedback is known, after we've seen the loop body
        let capture_realized = super::realize_stable_captures(ctx, &func);

        let feedback_realized = capture_realized.realize(
            capture_realized.r#ref(),
            SyntheticSlot::YieldFeedback,
            yield_feedback,
        );

        captures::call_site::apply_capture_mutations_and_derive_concretes(
            ctx,
            &feedback_realized,
            func.has_receiver().then_some(None),
            &args_with_backtraces,
            location,
        );

        let realization = CallRealization {
            receiver: None,
            ids: &ids,
            args: &args_with_backtraces,
            capture_concretes: &self.capture_concretes,
            location,
        };

        handle_deferred_checks(
            ctx,
            &func,
            &realization,
            self.call_branch.as_ref(),
            yield_feedback,
        );

        let has_known_implementation = func.outcome().is_some();

        drop(func);

        if has_known_implementation && let Some(mut func_mut) = value.as_function_mut() {
            func_mut.record_call();
        }
    }
}

fn calculate_call_result<'a>(
    ctx: &AnalysisContext<'a>,
    func: &FunctionValue<'a>,
    outcome: &[ValueRef<'a>],
    call: &CallRealization<'_, 'a>,
) -> Vec<ValueRef<'a>> {
    let parameter_concretes: Vec<_> = call
        .ids
        .iter()
        .copied()
        .enumerate()
        .map(|(index, (id, variadic, r#type))| {
            calculate_concrete_backtrace(
                ctx,
                index,
                id,
                variadic,
                r#type,
                call.args,
                Cow::Borrowed(call.location),
            )
        })
        .collect();

    let substitutions: Vec<_> = parameter_concretes
        .iter()
        .enumerate()
        .map(|(index, concrete)| (SyntheticSlot::Param(index), concrete.as_ref()))
        .chain(
            call.receiver
                .map(|concrete| (SyntheticSlot::Receiver, concrete)),
        )
        .chain(iter::once((
            SyntheticSlot::CallSiteBranch,
            ctx.branch_backtrace(),
        )))
        // yield feedback can never taint a normal call's result, since it is
        // only present when a function is used as an iterable in a for-range
        // loop, but in that case its return value is never seen
        .chain(iter::once((SyntheticSlot::YieldFeedback, None)))
        .chain(
            call.capture_concretes
                .for_outcome
                .iter()
                .map(|(index, concrete)| (SyntheticSlot::Capture(*index), concrete.as_ref())),
        )
        .collect();

    // sharing this across components means that a joint cache is used, which
    // allows aliases between results to be preserved. for example, this allows
    // for `ch, alias := pair(); ch <- secret; use(<-alias)`
    let mut realization = UnifiedRealization::multiple(func.r#ref(), &substitutions);

    outcome
        .iter()
        .map(|component| component.realize_unified(&mut realization))
        .collect()
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
            if matches!(
                r#type.strip_pointers().underlying(),
                Some(TypeKind::Interface)
            ) {
                // an interface hides its concrete representation, so retaining
                // that representation here can make recursive interface values
                // unfold (unbounded) across convergence passes. we thus
                // downgrade the result into its aggregate taint
                *result = result.downgrade(|| result.location().clone());
            }

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
