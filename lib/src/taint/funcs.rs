use std::{borrow::Cow, iter, path::Path, rc::Rc};

use parser::{
    Annotation, Location, Span,
    ast::{
        BlockNode, CallNode, ExprNode, FunctionDeclNode, FunctionParamDeclNode, FunctionResultNode,
        FunctionSignatureNode, SelectionNode, TypeNameNode, TypeNode,
    },
};

use crate::{
    Pinned,
    context::{AnalysisContext, DeferTarget, DeferredCall},
    errors::AnalysisErrorKind,
    labels::{Label, LabelBacktrace, LabelBacktraceKind, LabelTag, SyntheticSlot},
    symbols::Symbol,
    taint::{
        BlanketDirective, BlanketDirectiveKind, SinkDescriptor, SinkKind, annotations, enforcement,
        exprs, goto,
    },
    types::{TypeInfo, TypeKind},
    values::{
        BacktraceContainer, FunctionRef, FunctionValue, Mergeable, MobiusValue,
        SelfAwareBacktraceContainer, Value, ValueRef,
    },
};

pub mod builtins;
mod captures;

#[expect(
    clippy::too_many_lines,
    reason = "Very tight coupling means it would become more confusing if split up"
)]
fn visit_function_def<'a>(
    ctx: &mut AnalysisContext<'a>,
    r#ref: &FunctionRef<'a>,
    decl_symbol: Option<Pinned<'a, Span<'a>>>,
    signature: &FunctionSignatureNode<'a>,
    receiver: Option<&FunctionParamDeclNode<'a>>,
    body: Option<&BlockNode<'a>>,
    annotation: Option<&Annotation<'a>>,
) -> ValueRef<'a> {
    let value_location = match r#ref {
        FunctionRef::Named(name) => name.pinned_location(),
        FunctionRef::Anonymous(location) => location.clone(),
        FunctionRef::BuiltIn(_) | FunctionRef::BlackboxInference(_) => {
            decl_symbol.as_ref().map_or_else(
                // FIXME: fake location
                || Pinned::new(Path::new(""), 0..1),
                Pinned::pinned_location,
            )
        }
    };

    let func_val = build_function_value(
        ctx,
        r#ref,
        signature,
        receiver.is_some(),
        annotation,
        &value_location,
    );

    let mut value = ValueRef::new(
        Value::Function(Box::new(func_val)),
        value_location.clone(),
        None,
    );

    if let Some(name) = decl_symbol {
        if let Some(existing) = ctx.symtab().get_symbol_by_declaration(name) {
            // this was already declared by a previous analysis iteration/phase,
            // so we should mutate the entry in place rather than allocate a
            // fresh Symbol so that existing SymbolRef owners (i.e., other
            // structures holding an Rc, such as TypeInfo::methods) can observe
            // the body through the same handle, otherwise e.g. typed dispatch
            // would keep dereferencing the stale Bottom-valued symbol

            existing.borrow_mut().set_value(value.clone());
        } else {
            let symbol = Symbol::new_ref(name, false, value.clone());

            ctx.declare_function_or_method(receiver, symbol);
        }
    }

    let Some(body) = body else {
        // no body provided -> no known implementation, nothing else to do here
        return value;
    };

    ctx.symtab_mut().select_next_child_scope(); // push

    macro_rules! declare_param {
        ($id:expr, $slot:expr, $declared_type:expr) => {
            let synthetic = LabelTag::Synthetic {
                func: r#ref.clone(),
                slot: $slot,
                identifier: Some($id),
            };

            let param_backtrace = LabelBacktrace::new_root(
                LabelBacktraceKind::FunctionParameter,
                Label::from_single(synthetic),
                Some($id.content()),
                ctx.pin($id.location()),
            )
            .unwrap(); // safe because we know label is not Bottom

            let mut param_value = ValueRef::from(param_backtrace);
            if let Some(r#type) = $declared_type {
                param_value.set_declared_type(r#type);
            }

            ctx.declare_new_symbol(Symbol::new_ref(ctx.pin($id), true, param_value));
        };
    }

    if let Some(receiver) = receiver
        && let [id] = receiver.ids.as_slice()
        && id.content() != "_"
    {
        let receiver_type = ctx.types().resolve(ctx.symtab(), &receiver.r#type);

        declare_param!(*id, SyntheticSlot::Receiver, receiver_type);
    }

    let mut param_index = 0;

    for param in &signature.params {
        let param_type = if param.variadic {
            // variadic `...T` params bind a `[]T` slice when used as a single
            // param, and that slice has no named representation in the registry

            None
        } else {
            ctx.types().resolve(ctx.symtab(), &param.r#type)
        };

        for &id in &param.ids {
            // only ignore if blank identifier
            if id.content() != "_" {
                declare_param!(id, SyntheticSlot::Param(param_index), param_type.clone());
            }

            param_index += 1;
        }

        if param.ids.is_empty() {
            // did not actually loop above, so an anonymous parameter is being
            // declared (e.g. `f(...int)` or `g([]int)` or `h(int)`)
            // [note that `h(int)` is currently not supported by the parser]
            param_index += 1;

            // we don't actually need to register any new symbol because by
            // definition these parameters have no name and so cannot be used
            // anywhere in the function
        }
    }

    bind_named_result_locals(ctx, &signature.result);

    captures::register_closure_captures(ctx, r#ref, signature, receiver, body, &mut value);

    // it is necessary for sinks and other enforcement mechanisms inside this
    // function body to take into account the external branch backtrace at the
    // time the function in invoked, as otherwise information could be leaked
    // from whether the function is invoked at all (if done conditionally, e.g.
    // only if secret > 0) --- however, call-site branch backtrace is obviously
    // not known at this point of the analysis, so instead we inject a synthetic
    // implicit branch backtrace that will later be realized into the actual,
    // real, concrete branch backtrace each time that this function ins invoked
    let inject_implicit_branch = !r#ref.is_main();
    if inject_implicit_branch {
        let synthetic = LabelTag::Synthetic {
            func: r#ref.clone(),
            slot: SyntheticSlot::CallSiteBranch,
            identifier: None,
        };

        let bt = LabelBacktrace::new_root(
            LabelBacktraceKind::Branch,
            Label::from_single(synthetic),
            None,
            value_location,
        )
        .unwrap(); // safe because we know label is not Bottom

        ctx.push_branch_backtrace(bt);
    }

    ctx.push_function(value.clone());
    ctx.increase_branch_scope_depth();

    visit_function_body(ctx, body);

    apply_deferred_calls(ctx); // from `defer` statements

    captures::record_closure_capture_fallbacks(ctx, &mut value);

    ctx.decrease_branch_scope_depth();
    ctx.trigger_defer_target(DeferTarget::Function);
    ctx.pop_function();

    if inject_implicit_branch {
        ctx.pop_branch_backtrace();
    }

    ctx.symtab_mut().select_parent_scope(); // pop

    value
}

fn build_function_value<'a>(
    ctx: &mut AnalysisContext<'a>,
    r#ref: &FunctionRef<'a>,
    signature: &FunctionSignatureNode<'a>,
    has_receiver: bool,
    annotation: Option<&Annotation<'a>>,
    value_location: &Pinned<'a, Location>,
) -> FunctionValue<'a> {
    let mut explicit_backtrace = None;
    let mut sanitizer = Label::Bottom;
    let mut sink = None;

    if let Some(annotation) = annotation
        && let Some(directive) = annotations::parse_supported_directive(ctx, annotation)
    {
        match directive {
            annotations::FunctionDirective::Label => {
                explicit_backtrace = LabelBacktrace::new_root(
                    LabelBacktraceKind::ExplicitAnnotation,
                    Label::from_tags(&annotation.tags),
                    None,
                    value_location.clone(),
                );
            }
            annotations::FunctionDirective::Sanitizer => {
                let label = annotations::resolve_revocation_label(ctx, annotation, false);

                if let Some(label) = label {
                    sanitizer = label;
                }
            }
            annotations::FunctionDirective::AllowSink
            | annotations::FunctionDirective::DenySink => {
                sink = Some(SinkDescriptor::new(
                    SinkKind::Function,
                    directive == annotations::FunctionDirective::AllowSink,
                    &annotation.tags,
                    value_location.inner().clone(),
                ));
            }
        }
    }

    let mut func_val = FunctionValue::new(
        r#ref.clone(),
        Some(signature.clone()),
        has_receiver,
        explicit_backtrace,
        sanitizer,
        sink,
    );

    // cannot use `vec![ValueRef::new_bottom(); signature.result.len()]`, since
    // the vec! macro would clone the ValueRef (and so they'd all point to the
    // same value, which is not what we want; they should be independent)
    let bottom_outcome = iter::repeat_with(|| ValueRef::new_bottom(value_location.clone(), None))
        .take(signature.result.len())
        .collect();

    // since we know that this function has an implementation, we set a bottom
    // value as outcome (with the right cardinality), to distinguish from a
    // blackbox function without implementation (which would have unset outcome)
    func_val.set_outcome(bottom_outcome);

    // detect Go's range-over-func iterator shape: first param is typed as a
    // function returning a bool. recognizing it lets us track yield(args)
    // calls in the body and propagate their labels to `for ... := range <fn>`
    if let Some(first_param) = signature.params.first()
        && let [yield_id] = first_param.ids.as_slice()
        && let TypeNode::Function {
            signature: yield_sig,
        } = &first_param.r#type
        && let FunctionResultNode::Single(TypeNode::Name(TypeNameNode {
            package: None,
            id: yield_result,
            ..
        })) = &yield_sig.result
        && yield_result.content() == "bool"
    {
        func_val.mark_range_iter_shaped(ctx.pin(*yield_id), yield_sig.count_inputs());
    }

    // function value is now fully constructed, so just return it
    func_val
}

// sets up plumbing to allow for naked returns
fn bind_named_result_locals<'a>(ctx: &mut AnalysisContext<'a>, result: &FunctionResultNode<'a>) {
    let FunctionResultNode::Params(params) = result else {
        // FunctionResultNode::Single is always unnamed; None has no results
        return;
    };

    for param in params {
        let r#type = ctx.types().resolve(ctx.symtab(), &param.r#type);

        for &id in &param.ids {
            if id.content() == "_" {
                // blank identifier
                continue;
            }

            let pinned = ctx.pin(id);
            let value = ValueRef::new_bottom(pinned.pinned_location(), r#type.clone());

            ctx.declare_new_symbol(Symbol::new_ref(pinned, true, value));
        }
    }
}

fn visit_function_body<'a>(ctx: &mut AnalysisContext<'a>, body: &BlockNode<'a>) {
    if !goto::block_contains_goto(body) {
        // this matches the vast majority of functions and collapses into simply
        // visiting the statement block as normal

        super::visit_statements(ctx, &body.stmts);

        return;
    }

    // otherwise, we know there are one or more `goto` statements in this
    // function's body, so we need to run repeated speculative visits with error
    // reporting suppressed until everything converges, since `goto` statements
    // might point to past statements (labels we have already seen but did not
    // know at the same the full taint context implied from the `goto` location)

    goto::push_goto_convergence_context(ctx);

    // checkpoint the function scope's child-scope cursor and deferred state so
    // each speculative iteration re-enters the same child scopes (rather than
    // sibling scopes) and starts from a clean deferred-backtrace baseline
    let initial_cursor = ctx.symtab().current_child_scope_cursor();
    let pre_body_deferred = ctx.checkpoint_deferred_state();

    // termination: labels form a finite lattice and per-label state only ever
    // grows monotonically across iterations (taint can be added, but never
    // removed), so convergence is guaranteed to be eventually reached
    let mut stable = false;
    while !stable {
        ctx.push_error_suppression(); // this is a speculative visit

        super::visit_statements(ctx, &body.stmts);

        ctx.pop_error_suppression();

        goto::pop_goto_branch_backtraces(ctx);

        stable = goto::advance_goto_convergence_iteration(ctx);

        // restore state from checkpoint, since this was a speculative visit
        ctx.symtab_mut().set_child_scope_cursor(initial_cursor);
        ctx.restore_deferred_state(pre_body_deferred.clone());
    }

    // final pass with errors enabled, now that the state is stable
    super::visit_statements(ctx, &body.stmts);

    goto::pop_goto_branch_backtraces(ctx);

    goto::pop_goto_convergence_context(ctx);
}

pub fn visit_function_decl<'a>(ctx: &mut AnalysisContext<'a>, node: &FunctionDeclNode<'a>) {
    let func_name = ctx.pin(node.name);

    visit_function_def(
        ctx,
        &FunctionRef::Named(func_name),
        Some(func_name),
        &node.signature,
        node.receiver.as_ref(),
        node.body.as_ref(),
        node.annotation.as_deref(),
    );
}

pub fn visit_function_literal<'a>(
    ctx: &mut AnalysisContext<'a>,
    signature: &FunctionSignatureNode<'a>,
    body: &BlockNode<'a>,
    location: &Location,
    annotation: Option<&Annotation<'a>>,
) -> ValueRef<'a> {
    let r#ref = FunctionRef::Anonymous(ctx.pin(location.clone()));

    visit_function_def(ctx, &r#ref, None, signature, None, Some(body), annotation)
}

pub fn visit_defer<'a>(ctx: &mut AnalysisContext<'a>, expr: &ExprNode<'a>, location: &Location) {
    if ctx.current_function().is_none() {
        // there is no active function, probably because we are inside an `init`
        // function, so just fallback to evaluating immediately (we still want
        // to trigger side effects and enforcement checks inside the function)

        ctx.report_error(AnalysisErrorKind::DeferInInitNotDeferred {
            location: location.clone(),
        });

        exprs::visit_expr(ctx, expr);

        return;
    }

    let ExprNode::Call(call) = expr else {
        // invalid Go, but visit the expression anyway for side effects

        ctx.report_error(AnalysisErrorKind::DeferNotCall {
            location: location.clone(),
        });

        exprs::visit_expr(ctx, expr);

        return;
    };

    match resolve_call(ctx, call) {
        CallResolution::Final(_) => {} // nothing left to do
        CallResolution::PendingApply(resolved) => {
            ctx.register_deferred_call(call.clone(), resolved);
        }
    }
}

fn apply_deferred_calls(ctx: &mut AnalysisContext<'_>) {
    // taking ownership detaches from `ctx` so we can re-borrow it mutably for
    // each replay (and naturally handles nested `defer` inside a deferred
    // function literal, since its own deferred calls live on the inner frame)

    // deferred calls are applied in reverse order of registration, hence `rev`

    for pending in ctx.take_deferred_calls().into_iter().rev() {
        let DeferredCall {
            node,
            resolved,
            captured_branch_backtrace,
        } = pending;

        let installed = captured_branch_backtrace.is_some();
        if let Some(bt) = captured_branch_backtrace {
            ctx.push_branch_backtrace(bt);
        }

        apply_call(ctx, &node, resolved);

        if installed {
            ctx.pop_branch_backtrace();
        }
    }
}

pub fn visit_return<'a>(
    ctx: &mut AnalysisContext<'a>,
    exprs: &[ExprNode<'a>],
    location: &Location,
) {
    let Some(mut value) = ctx.current_function() else {
        ctx.report_error(AnalysisErrorKind::UnexpectedReturn {
            location: location.clone(),
        });

        return;
    };

    let Some(func) = value.as_function() else {
        ctx.report_error(AnalysisErrorKind::UnexpectedReturn {
            location: location.clone(),
        });

        return;
    };

    // unfortunately we need to do this as otherwise we'd get a runtime borrow
    // error since calculate_outcome must be able to borrow func as mutable, and
    // that's not possible if we're still holding a ref to it
    let signature = func.signature().cloned();
    let existing_outcome = func.outcome().cloned();
    drop(func);

    let outcome = calculate_outcome(ctx, signature.as_ref(), exprs, location);

    // merge with existing outcome, if any
    // (this allows for multiple return statements within the same function)
    let outcome = if let Some(existing) = existing_outcome.as_deref() {
        merge_outcomes(ctx, existing, outcome, location)
    } else {
        outcome
    };

    let Some(mut func_mut) = value.as_function_mut() else {
        ctx.report_error(AnalysisErrorKind::UnexpectedReturn {
            location: location.clone(),
        });

        return;
    };

    func_mut.set_outcome(outcome);

    ctx.defer_branch_backtrace(DeferTarget::Function, location.clone());
}

fn calculate_outcome<'a>(
    ctx: &mut AnalysisContext<'a>,
    signature: Option<&FunctionSignatureNode<'a>>,
    exprs: &[ExprNode<'a>],
    location: &Location,
) -> Vec<ValueRef<'a>> {
    // if there's a single expression with a single function call, then nothing
    // below applies and that function call's outcome is the final outcome
    // (case 2 from https://go.dev/ref/spec#Return_statements)
    if let [ExprNode::Call(call)] = exprs {
        let raw = visit_call(ctx, call);

        return if let Some(sig) = signature
            && let [single] = raw.as_slice()
            && single.is_mobius()
        {
            // expand Möbius to the correct cardinality expected for a call to
            // this current outer function, adapting what the inner one returned
            single.try_expand_to(sig.result.len()).unwrap_or(raw)
        } else {
            raw
        };
    }

    let raw_values: Vec<ValueRef<'a>> = if exprs.is_empty()
        && let Some(sig) = signature
        && let FunctionResultNode::Params(result) = &sig.result
    {
        // naked returns

        result
            .iter()
            .flat_map(|param| &param.ids)
            .map(|id| {
                if id.content() == "_" {
                    // still takes up a position, we can't just skip it
                    ValueRef::new_bottom(ctx.pin(id.location()), None)
                } else {
                    exprs::visit_single_expr(ctx, &ExprNode::Name(*id))
                }
            })
            .collect()
    } else {
        exprs
            .iter()
            .map(|expr| exprs::visit_single_expr(ctx, expr))
            .collect()
    };

    let pinned_location = ctx.pin(location.clone());
    let branch_backtrace = ctx.branch_backtrace();

    raw_values
        .into_iter()
        .map(|value| {
            value.nest_backtrace(
                LabelBacktraceKind::Return,
                None,
                pinned_location.clone(),
                branch_backtrace.cloned(),
            )
        })
        .collect()
}

fn merge_outcomes<'a>(
    ctx: &mut AnalysisContext<'a>,
    existing: &[ValueRef<'a>],
    new: Vec<ValueRef<'a>>,
    location: &Location,
) -> Vec<ValueRef<'a>> {
    if new.len() != existing.len() {
        ctx.report_error(AnalysisErrorKind::MismatchingReturnCardinality {
            expected: existing.len(),
            found: new.len(),
            location: location.clone(),
        });
    }

    let pinned = ctx.pin(location.clone());
    let mut merged = Vec::with_capacity(new.len());

    #[expect(clippy::shadow_unrelated, reason = "False positive")]
    for (existing, new) in existing.iter().zip(new) {
        merged.push(new.merge_with(existing, LabelBacktraceKind::Return, Cow::Borrowed(&pinned)));
    }

    merged
}

enum CallResolution<'a> {
    Final(Vec<ValueRef<'a>>),
    PendingApply(ResolvedCall<'a>),
}

// preprocessed state snapshot of everything necessary to apply a function call
pub struct ResolvedCall<'a> {
    callee: ValueRef<'a>,
    arg_values: Vec<ValueRef<'a>>,
    blackbox_replacement: Option<Box<FunctionValue<'a>>>,
    method_receiver_value: Option<ValueRef<'a>>,
}

pub fn visit_call<'a>(ctx: &mut AnalysisContext<'a>, node: &CallNode<'a>) -> Vec<ValueRef<'a>> {
    match resolve_call(ctx, node) {
        CallResolution::Final(values) => values,
        CallResolution::PendingApply(resolved) => apply_call(ctx, node, resolved),
    }
}

fn resolve_call<'a>(ctx: &mut AnalysisContext<'a>, node: &CallNode<'a>) -> CallResolution<'a> {
    // we treat some built-in functions specially, not as function calls but as
    // independent quasi-types of expressions. if they don't look like a real
    // function call (e.g., take a type instead of a value as input, like make)
    // then they were already spotted and differentiated by the parser, but
    // otherwise we need to here identify all remaining built-in functions and
    // trigger their special handling, aborting function call handling on match
    if let ExprNode::Name(id) = &*node.func {
        match id.content() {
            "append" => return CallResolution::Final(vec![builtins::visit_append(ctx, node)]),
            "copy" => return CallResolution::Final(vec![builtins::visit_copy(ctx, node)]),
            "clear" => {
                builtins::visit_clear(ctx, node);

                return CallResolution::Final(vec![]);
            }
            "close" => {
                builtins::visit_close(ctx, node);

                return CallResolution::Final(vec![]);
            }
            "delete" => {
                builtins::visit_delete(ctx, node);

                return CallResolution::Final(vec![]);
            }
            _ => {} // nothing to do, it's a real function call
        }
    }

    // this looks a bit strange and convoluted, but it is necessary to guarantee
    // special handling for selections: when the callee is a selection (e.g.,
    // `x.M(...)`), we want to evaluate the base exactly once
    let (value, extracted_from_type, method_receiver) = if let ExprNode::Selection(selection) =
        &*node.func
    {
        let base_value = exprs::visit_single_expr(ctx, &selection.base);
        let is_method_form = base_value.as_package_ref().is_none();

        let extracted = if is_method_form {
            // if we detected a receiver, prefer extracting the invoked function
            // value based on type information, since typed dispatch is
            // necessarily correct

            try_extract_typed_selection_callee(ctx, selection, &base_value)
        } else {
            None
        };

        let extracted_from_type = extracted.is_some();

        let value = extracted.unwrap_or_else(|| {
            // typed dispatch didn't apply or didn't conclusively resolve, so we
            // visit the callee normally, but using `exprs::visit_single_expr`
            // would lead to the base being visited again (which we want to
            // avoid, to prevent side-effects), so instead we plug directly into
            // `visit_selection_with_base` (after all, we know this is a
            // selection, and we already visited the base)
            exprs::visit_selection_with_base(ctx, selection, &base_value).extract_collapsed_single()
        });

        let method_receiver = is_method_form.then_some((selection, base_value));

        (value, extracted_from_type, method_receiver)
    } else {
        // not a selection, so just visit normally

        (exprs::visit_single_expr(ctx, &node.func), false, None)
    };

    // can't call this `func` right away because later we need to manually call
    // `drop` on specifically this reference
    let Some(value_func) = value.as_function() else {
        ctx.report_error(AnalysisErrorKind::IllegalCallExpression {
            location: node.location.clone(),
        });

        return CallResolution::Final(vec![]);
    };

    if value_func.is_type_constructor() {
        // treating this as a blackbox would be too punishing: we want to
        // preserve the existing value shape, so we use special handling

        return CallResolution::Final(vec![visit_type_conversion(
            ctx,
            node,
            value_func.target_type().cloned(),
        )]);
    }

    // when this was detected as a method-form call but the callee could not be
    // extracted from type information, fallback to a weaker name-only heuristic
    // to determine whether the inferred method we decided to assume (from
    // `visit_selection`) is actually obviously wrong and should be discarded:
    // if there is exactly one in-package method by that name and it has a
    // cardinality incompatible with this call site, the heuristic pickup is
    // conclusively wrong (the receiver must actually be of an unrelated type
    // whose real `M` we never saw, because the input compiles). enforcing the
    // inferred method's signature would cascade into spurious errors, so we
    // use an unknown FunctionValue instead of the known-incorrect `func_value`.
    // sound: blackbox folds all input taint, Möbius accepts any cardinality
    let blackbox_replacement = if !extracted_from_type
        && let Some((selection, _)) = method_receiver.as_ref()
        && is_incompatible_cardinality_method(ctx, selection, &value_func, node.args.len())
    {
        Some(Box::new(FunctionValue::new_unknown(
            // we keep only the overall access backtrace
            value_func.backtrace().cloned(),
            // we don't know the type of the receiver, but we know it exists
            true,
        )))
    } else {
        None
    };

    let func: &FunctionValue<'a> = blackbox_replacement.as_deref().unwrap_or(&value_func);

    // can only check for correct cardinality if we have a signature, otherwise
    // we just assume everything is fine (would be wrong to error)
    if let Some(signature) = func.signature() {
        let count = signature.count_inputs();

        if node.args.len() != count {
            let variadic = signature.params.last().is_some_and(|param| param.variadic);

            // if the last parameter is variadic, then it does not count for our
            // expected cardinality, so we subtract one. we then use >= because
            // 0 or more arguments can be folded into the variadic parameter
            let expected = count.saturating_sub(1);

            if !(variadic && node.args.len() >= expected) {
                ctx.report_error(AnalysisErrorKind::IncorrectCallCardinality {
                    expected,
                    found: node.args.len(),
                    location: node.location.clone(),
                });

                return CallResolution::Final(vec![]);
            }
        }
    }

    // drop the immutable borrow of `value` (held via `value_func`/`func`)
    // before moving `value` into the resolved struct
    drop(value_func);

    // the selection ref captured alongside `base_value` was only needed for
    // the blackbox-replacement decision above; from here on, only the base
    // value matters (its taint flows in via SyntheticSlot::Receiver)
    let method_receiver_value = method_receiver.map(|(_, base)| base);

    let arg_values: Vec<_> = node
        .args
        .iter()
        .map(|arg| exprs::visit_single_expr(ctx, arg))
        .collect();

    CallResolution::PendingApply(ResolvedCall {
        callee: value,
        arg_values,
        blackbox_replacement,
        method_receiver_value,
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "Tight coupling between the sub-stages would make further splitting more confusing"
)]
fn apply_call<'a>(
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

                for (_, arg_bt) in &with_backtraces {
                    enforcement::trigger_sink(ctx, Cow::Borrowed(&sink), arg_bt.clone());
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

    if let Some(inherent_sink) = func.sink() {
        for (_, arg_bt) in &with_backtraces {
            enforcement::trigger_sink(ctx, Cow::Borrowed(inherent_sink), arg_bt.clone());
        }
    }

    let call_location = ctx.pin(node.location.clone());

    let blanket_bt = {
        let mut blanket_label = Label::Bottom;

        for directive in resolve_blanket_directives(ctx, &node.func) {
            match directive.kind() {
                BlanketDirectiveKind::AllowSink | BlanketDirectiveKind::DenySink => {
                    // we bypass SinkDescriptor::new as we already have a Label
                    let sink = SinkDescriptor {
                        kind: SinkKind::Call,
                        allow: directive.kind() == BlanketDirectiveKind::AllowSink,
                        label: directive.label(),
                        location: node.location.clone(),
                    };

                    for (_, arg_bt) in &with_backtraces {
                        enforcement::trigger_sink(ctx, Cow::Borrowed(&sink), arg_bt.clone());
                    }
                }
                BlanketDirectiveKind::Source => {
                    blanket_label = blanket_label.union(&directive.label());
                }
            }
        }

        LabelBacktrace::new_root(
            LabelBacktraceKind::BlanketSource,
            blanket_label,
            None,
            call_location.clone(),
        )
    };

    let Some(outcome) = func.outcome() else {
        // we don't have a known implementation of this function, so we must
        // treat it as a blackbox and assume the label of all its outputs is the
        // union of the label of all its inputs; we can't do anything fancy

        return visit_blackbox_call(
            ctx,
            func,
            &with_backtraces_ref,
            blanket_bt.as_ref(),
            &call_location,
            &node.location,
            func.signature(),
        );
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

    captures::apply_capture_mutations(ctx, func, &with_backtraces_ref, &node.location);

    let receiver_ref = receiver.as_ref().map(Option::as_ref);

    handle_deferred_checks(
        ctx,
        func,
        receiver_ref,
        &ids,
        &with_backtraces_ref,
        &node.location,
    );

    let mut result = calculate_call_result(
        ctx,
        func,
        receiver_ref,
        &ids,
        outcome,
        &with_backtraces_ref,
        &node.location,
    );

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

    for realized in &mut result {
        *realized = realized.with_location(call_location.clone());
    }

    // the result's static type is necessarily what the signature declares, not
    // what was passed to `return`, per Go semantics, so we should override
    tag_results_with_declared_types(ctx, func.signature(), &mut result);

    nest_blanket_source(&mut result, blanket_bt.as_ref(), &call_location);

    // re-borrow as mutable
    drop(value_func);

    if blackbox_replacement.is_none()
        && let Some(mut func_mut) = value.as_function_mut()
    {
        func_mut.record_call();
    }

    result

    // TODO: test calling variadic fn, like `f(string, ...int)` with
    // `f("hello", 1, 2, 3)`
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

fn try_extract_typed_selection_callee<'a>(
    ctx: &mut AnalysisContext<'a>,
    selection: &SelectionNode<'a>,
    base_value: &ValueRef<'a>,
) -> Option<ValueRef<'a>> {
    // exit early if base has no declared type
    let r#type = base_value.declared_type()?;
    let selector = selection.selector.content();
    let location = || ctx.pin(selection.location.clone());

    // method on the receiver type's method set, including methods promoted
    // through anonymous-embedded struct fields per Go's spec
    if let Some(method) = r#type.lookup_promoted_method(selector) {
        return Some(nest_receiver_backtrace(
            method.borrow().value().get(),
            base_value,
            location(),
        ));
    }

    // otherwise, check if this selection is really just a field access being
    // called like a method (i.e., `s.F()` where `F` is a `func(...)` field)
    if matches!(r#type.underlying(), TypeKind::Struct { .. })
        && let Some(r#struct) = base_value.as_struct()
    {
        return Some(r#struct.get_const(&selector.to_owned(), location()));
    }

    // nothing we can do
    None
}

pub fn nest_receiver_backtrace<'a>(
    method_value: ValueRef<'a>,
    receiver: &ValueRef<'a>,
    at_location: Pinned<'a, Location>,
) -> ValueRef<'a> {
    match receiver.backtrace() {
        Some(backtrace) => method_value.nest_backtrace(
            LabelBacktraceKind::MethodReceiver,
            None,
            at_location,
            [backtrace],
        ),
        None => method_value,
    }
}

fn visit_type_conversion<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &CallNode<'a>,
    target_type: Option<Rc<TypeInfo<'a>>>,
) -> ValueRef<'a> {
    let location = ctx.pin(node.location.clone());

    let [operand] = node.args.as_slice() else {
        ctx.report_error(AnalysisErrorKind::IncorrectCallCardinality {
            expected: 1,
            found: node.args.len(),
            location: node.location.clone(),
        });

        return ValueRef::new_bottom(location, target_type);
    };

    // pin the result to the call site so error messages and downstream
    // backtraces refer to `T(x)`, not just to `x`'s declaration
    exprs::visit_single_expr(ctx, operand)
        .with_location(location)
        .into_with_declared_type(target_type)
}

fn resolve_blanket_directives<'a, 'b>(
    ctx: &'b AnalysisContext<'a>,
    func_expr: &ExprNode<'a>,
) -> &'a [BlanketDirective]
where
    'a: 'b,
{
    // TODO: extend this to more than just pkg.name

    let ExprNode::Selection(selection) = func_expr else {
        return &[];
    };

    let ExprNode::Name(qualifier) = &*selection.base else {
        return &[];
    };

    let Some(pkg_path) = ctx.symtab().package_path_for_qualifier(qualifier.content()) else {
        return &[];
    };

    let key = format!("{}.{}", pkg_path, selection.selector.content());

    ctx.blanket_directives_for(&key)
}

fn nest_blanket_source<'a>(
    result: &mut [ValueRef<'a>],
    blanket_bt: Option<&LabelBacktrace<'a>>,
    call_location: &Pinned<'a, Location>,
) {
    let Some(bt) = blanket_bt else {
        return;
    };

    for value in result.iter_mut() {
        *value = value.nest_backtrace(
            LabelBacktraceKind::Expression,
            None,
            call_location.clone(),
            [bt.clone()],
        );
    }
}

fn visit_blackbox_call<'a>(
    ctx: &mut AnalysisContext<'a>,
    func: &FunctionValue<'a>,
    args: &[(ValueRef<'a>, Option<&LabelBacktrace<'a>>)],
    blanket_bt: Option<&LabelBacktrace<'a>>,
    call_location: &Pinned<'a, Location>,
    node_location: &Location,
    signature_hint: Option<&FunctionSignatureNode<'a>>,
) -> Vec<ValueRef<'a>> {
    // note that this case is still possible even if func is a closure, since
    // e.g. closures can be assigned to previously declared (but not
    // initialized) variables in an effort to make them self-recursive, as the
    // whole point of closure capturing is that outer symbols are only really
    // "evaluated" when the closure is invoked
    captures::apply_capture_mutations(ctx, func, args, node_location);

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
    tag_results_with_declared_types(ctx, signature_hint, &mut result);

    nest_blanket_source(&mut result, blanket_bt, call_location);

    result
}

fn tag_results_with_declared_types<'a>(
    ctx: &AnalysisContext<'a>,
    signature: Option<&FunctionSignatureNode<'a>>,
    results: &mut [ValueRef<'a>],
) {
    let Some(signature) = signature else {
        // nothing we can do here
        return;
    };

    let type_iter: Box<dyn Iterator<Item = &TypeNode<'a>>> = match &signature.result {
        FunctionResultNode::None => Box::new(iter::empty()),
        FunctionResultNode::Single(r#type) => Box::new(iter::once(r#type)),
        FunctionResultNode::Params(params) => Box::new(
            params
                .iter()
                .flat_map(|param| iter::repeat_n(&param.r#type, param.ids.len().max(1))),
        ),
    };

    for (result, type_node) in results.iter_mut().zip(type_iter) {
        if let Some(r#type) = ctx.types().resolve(ctx.symtab(), type_node) {
            result.set_declared_type(r#type);
        }
    }
}

// whether a heuristically-inferred method is incompatible with expected arity
//
// note: we assume the invoker already ruled out the case where this selection
// is `a.b` and `a` is a valid package import qualifier; invoker must be
// confident that this is a method, just not this specific method candidate
fn is_incompatible_cardinality_method<'a>(
    ctx: &AnalysisContext<'a>,
    selection: &SelectionNode<'a>,
    candidate: &FunctionValue<'a>,
    args_len: usize,
) -> bool {
    let Some(method) = ctx
        .symtab()
        .lookup_unique_method_in_current_package(selection.selector.content())
    else {
        return false;
    };

    let func_value = method.borrow().value().get();
    let Some(func) = func_value.as_function() else {
        return false;
    };

    let Some(signature) = func.signature() else {
        return false;
    };

    // if the method candidate that the invoker holds is not the same as the one
    // we are checking in this function, then this entire check is irrelevant,
    // so the analyzer has a bug (we assumed that the lookup above is what
    // `visit_selection` used to pick up the method that eventually propagated
    // to become the invoker's candidate, but apparently that assumption was
    // wrong and so our implied invariant has been broken; this is a bug!)
    assert_eq!(
        candidate.r#ref(),
        func.r#ref(),
        "Assumption invariant failed on method pickup strategy"
    );

    let cardinality = signature.count_inputs();
    let variadic = signature.params.last().is_some_and(|param| param.variadic);

    // exact match is plausible; an excess of args is fine iff the last param is
    // variadic (it soaks up the rest); any other shape is conclusively wrong
    args_len != cardinality && !(variadic && args_len >= cardinality.saturating_sub(1))
}

#[expect(
    clippy::option_option,
    reason = "Conveniently represent a receiver's presence/absence"
)]
fn handle_deferred_checks<'a>(
    ctx: &mut AnalysisContext<'a>,
    func: &FunctionValue<'a>,
    receiver: Option<Option<&LabelBacktrace<'a>>>,
    ids: &[(Option<&Span<'a>>, bool, &TypeNode<'a>)],
    args: &[(ValueRef<'a>, Option<&LabelBacktrace<'a>>)],
    location: &Location,
) {
    let mut deferred_checks = Vec::from(func.deferred_checks());
    let capture_concretes = captures::derive_best_backtraces_for_captures(ctx, func);

    if let Some(receiver) = receiver {
        deferred_checks = deferred_checks
            .iter()
            .filter_map(|check| check.realize(func.r#ref(), SyntheticSlot::Receiver, receiver))
            .collect();
    }

    for (index, (id, variadic, r#type)) in ids.iter().copied().enumerate() {
        #[rustfmt::skip]
        let concrete = calculate_concrete_backtrace(
            ctx,
            index,
            id,
            variadic,
            r#type,
            args,
            location
        );

        deferred_checks = deferred_checks
            .iter()
            .filter_map(|check| {
                check.realize(func.r#ref(), SyntheticSlot::Param(index), concrete.as_ref())
            })
            .collect();
    }

    for (index, concrete) in &capture_concretes {
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

    let call_branch;
    // block to force correct formatting
    {
        call_branch = calculate_effective_call_site_branch_backtrace_for(
            ctx,
            func,
            ctx.pin(location.clone()),
        );
    };

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

#[expect(
    clippy::option_option,
    reason = "Conveniently represent a receiver's presence/absence"
)]
fn calculate_call_result<'a>(
    ctx: &AnalysisContext<'a>,
    func: &FunctionValue<'a>,
    receiver: Option<Option<&LabelBacktrace<'a>>>,
    ids: &[(Option<&Span<'a>>, bool, &TypeNode<'a>)],
    outcome: &Vec<ValueRef<'a>>,
    args: &[(ValueRef<'a>, Option<&LabelBacktrace<'a>>)],
    location: &Location,
) -> Vec<ValueRef<'a>> {
    let mut result = vec![];
    let capture_concretes = captures::derive_best_backtraces_for_captures(ctx, func);

    'components: for component in outcome {
        let mut realized = component.clone();

        if let Some(receiver) = receiver {
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

        for (index, (id, variadic, r#type)) in ids.iter().copied().enumerate() {
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
                args,
                location
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

        for (index, concrete) in &capture_concretes {
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

fn calculate_concrete_backtrace<'a>(
    ctx: &AnalysisContext<'a>,
    index: usize,
    id: Option<&Span<'a>>,
    variadic: bool,
    r#type: &TypeNode<'a>,
    args: &[(ValueRef<'a>, Option<&LabelBacktrace<'a>>)],
    location: &Location,
) -> Option<LabelBacktrace<'a>> {
    if variadic {
        LabelBacktrace::fold(
            args[index..].iter().flat_map(|(_, bt)| bt).copied(),
            LabelBacktraceKind::FunctionVariadicAggregation,
            id.map(Span::content),
            ctx.pin(location.clone()),
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
            captures::derive_hybrid_value_backtrace(
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

pub fn calculate_effective_call_site_branch_backtrace_for<'a>(
    ctx: &AnalysisContext<'a>,
    func: &FunctionValue<'a>,
    at_location: Pinned<'a, Location>,
) -> Option<LabelBacktrace<'a>> {
    let call_branch = ctx.branch_backtrace().cloned();
    let func_branch = func.backtrace().and_then(|bt| {
        bt.realize(
            func.r#ref(),
            SyntheticSlot::CallSiteBranch,
            call_branch.as_ref(),
        )
    });

    LabelBacktrace::combine_options(
        call_branch,
        func_branch,
        LabelBacktraceKind::Branch,
        Cow::Owned(at_location),
    )
}
