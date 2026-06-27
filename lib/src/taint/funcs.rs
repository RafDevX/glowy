use std::{borrow::Cow, iter, path::Path};

use parser::{
    Annotation, Location, Span,
    ast::{
        BlockNode, CallNode, ExprNode, FunctionDeclNode, FunctionParamDeclNode, FunctionResultNode,
        FunctionSignatureNode, TypeNameNode, TypeNode,
    },
};

use crate::{
    Pinned,
    context::{AnalysisContext, DeferTarget},
    errors::AnalysisErrorKind,
    labels::{Label, LabelBacktrace, LabelBacktraceKind, LabelTag, SyntheticSlot},
    symbols::Symbol,
    taint::{
        BlanketDirective, BlanketDirectiveKind, SinkDescriptor, SinkKind, annotations, enforcement,
        exprs,
    },
    values::{
        BacktraceContainer, FunctionRef, FunctionValue, Mergeable, MobiusValue,
        SelfAwareBacktraceContainer, Value, ValueRef,
    },
};

pub mod builtins;
mod captures;

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

    let mut value = ValueRef::new(Value::Function(Box::new(func_val)), value_location.clone());

    if let Some(name) = decl_symbol {
        let symbol = Symbol::new_ref(name, false, value.clone());

        ctx.declare_function_or_method(receiver, symbol);
    }

    let Some(body) = body else {
        // no body provided -> no known implementation, nothing else to do here
        return value;
    };

    ctx.symtab_mut().select_next_child_scope(); // push

    macro_rules! declare_param {
        ($id:expr, $slot:expr) => {
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

            ctx.declare_new_symbol(Symbol::new_ref(
                ctx.pin($id),
                true,
                ValueRef::from(param_backtrace),
            ));
        };
    }

    if let Some(receiver) = receiver
        && let [id] = receiver.ids.as_slice()
        && id.content() != "_"
    {
        declare_param!(*id, SyntheticSlot::Receiver);
    }

    let mut param_index = 0;

    for param in &signature.params {
        for &id in &param.ids {
            // only ignore if blank identifier
            if id.content() != "_" {
                declare_param!(id, SyntheticSlot::Param(param_index));
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

    super::visit_statements(ctx, body);

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
                let label = annotations::resolve_declassification_label(ctx, annotation, false);

                if let Some(label) = label {
                    sanitizer = label;
                }
            }
            annotations::FunctionDirective::Sink => {
                sink = Some(SinkDescriptor::new(
                    SinkKind::Function,
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
    let bottom_outcome = iter::repeat_with(|| ValueRef::new_bottom(value_location.clone()))
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
        return visit_call(ctx, call);
    }

    let mut outcome = vec![];

    let exprs = if exprs.is_empty()
        && let Some(FunctionResultNode::Params(result)) = signature.map(|sig| &sig.result)
    {
        // naked returns

        result
            .iter()
            .flat_map(|p| p.ids.clone())
            .map(ExprNode::Name)
            .collect()
    } else {
        Vec::from(exprs)
    };

    for expr in &exprs {
        let expr_value = exprs::visit_single_expr(ctx, expr);

        let backtrace = expr_value.nest_backtrace(
            LabelBacktraceKind::Return,
            None,
            ctx.pin(location.clone()),
            ctx.branch_backtrace().into_iter().cloned(),
        );

        outcome.push(backtrace);
    }

    outcome
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

#[expect(
    clippy::too_many_lines,
    reason = "Very tight coupling means it would become more confusing if split up"
)]
pub fn visit_call<'a>(ctx: &mut AnalysisContext<'a>, node: &CallNode<'a>) -> Vec<ValueRef<'a>> {
    // we treat some built-in functions specially, not as function calls but as
    // independent quasi-types of expressions. if they don't look like a real
    // function call (e.g., take a type instead of a value as input, like make)
    // then they were already spotted and differentiated by the parser, but
    // otherwise we need to here identify all remaining built-in functions and
    // trigger their special handling, aborting function call handling on match
    if let ExprNode::Name(id) = &*node.func {
        match id.content() {
            "append" => return vec![builtins::visit_append(ctx, node)],
            "copy" => return vec![builtins::visit_copy(ctx, node)],
            "clear" => {
                builtins::visit_clear(ctx, node);
                return vec![];
            }
            "close" => {
                builtins::visit_close(ctx, node);
                return vec![];
            }
            "delete" => {
                builtins::visit_delete(ctx, node);
                return vec![];
            }
            _ => {} // nothing to do, it's a real function call
        }
    }

    let mut value = exprs::visit_single_expr(ctx, &node.func);

    // can't call this `func` right away because later we need to manually call
    // `drop` on specifically this reference
    let Some(value_func) = value.as_function() else {
        ctx.report_error(AnalysisErrorKind::IllegalCallExpression {
            location: node.location.clone(),
        });

        return vec![];
    };

    if value_func.is_type_constructor() {
        // treating this as a blackbox would be too punishing: we want to
        // preserve the existing value shape, so we use special handling

        return vec![visit_type_conversion(ctx, node)];
    }

    // for direct method-form calls (`x.M(...)` where `x` isn't a package
    // qualifier), `visit_selection` infers a method using a name-only heuristic
    // across the current package's method set. if exactly one in-package method
    // by that name has an arity incompatible with this call site, the pickup is
    // conclusively wrong (the receiver must actually be of an unrelated type
    // whose real `M` we never saw, because the input compiles). enforcing the
    // inferred method's signature would cascade into spurious errors, so we
    // use an unknown FunctionValue instead of the known-incorrect `func_value`.
    // sound: blackbox folds all input taint, Möbius accepts any cardinality
    let blackbox_replacement = is_incompatible_arity_method(ctx, node).then(|| {
        FunctionValue::new_unknown(
            value_func.backtrace().cloned(),
            true, // we still know this, just don't know the type
        )
    });
    // ^^ we keep only `value_func`'s overall access backtrace

    let func: &FunctionValue<'a> = blackbox_replacement.as_ref().unwrap_or(&value_func);

    // note that f(a, b int) actually has 1 parameter with 2 identifiers, so
    // we can't compare args.len() with params.len() directly; we need to
    // process them first

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

    let ids = if let Some(signature) = func.signature() {
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

        Some(ids)
    } else {
        None
    };

    // can only check for correct cardinality if we have a signature,
    // otherwise we just assume everything is fine (would be wrong to error)
    if let Some(ids) = &ids
        && node.args.len() != ids.len()
    {
        let variadic = ids.last().is_some_and(|(_, variadic, _)| *variadic);

        if !(variadic && node.args.len() > ids.len()) {
            ctx.report_error(AnalysisErrorKind::IncorrectCallCardinality {
                expected: ids.len(),
                found: node.args.len(),
                location: node.location.clone(),
            });

            return vec![];
        }
    }

    let arg_values: Vec<_> = node
        .args
        .iter()
        .map(|arg| exprs::visit_single_expr(ctx, arg))
        .collect();

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
            annotations::CallDirective::Sink => {
                let sink = SinkDescriptor::new(
                    SinkKind::Call,
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
                BlanketDirectiveKind::Sink => {
                    let sink = SinkDescriptor {
                        kind: SinkKind::Call,
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

        return dispatch_blackbox(
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

    let receiver = if let ExprNode::Selection(selection) = &*node.func {
        // we cannot use exprs::get_expr_backtrace since we need to rule out the
        // case that the ""selection"" is actually just a qualified identifier
        // and so the ""receiver"" is really just a qualifier (package ref)
        let base = exprs::visit_single_expr(ctx, &selection.base);

        if base.as_package_ref().is_some() {
            None
        } else {
            Some(base.backtrace())
        }
    } else if func.has_receiver() {
        // this is a method called via a non-selection expression, such as a
        // method value like `f := obj.M; f()`; we don't have a selection.base
        // to read the bound receiver from (here), but its taint was already
        // nested into `func.backtrace()` at the binding site in
        // `visit_selection`, and *that* backtrace gets nested into the result
        // below -- so the receiver's labels still reach the call result.
        //
        // nevertheless, we MUST still realize SyntheticSlot::Receiver (with no
        // (concrete backtrace) to cancel the synthetic; otherwise it would
        // escape this function and eventually reach `main` (breaking invariant)
        Some(None)
    } else {
        None
    };

    captures::apply_capture_mutations(ctx, func, &with_backtraces_ref, &node.location);

    handle_deferred_checks(ctx, func, &ids, &with_backtraces_ref, &node.location);

    let receiver_ref = receiver.as_ref().map(Option::as_ref);

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

fn visit_type_conversion<'a>(ctx: &mut AnalysisContext<'a>, node: &CallNode<'a>) -> ValueRef<'a> {
    let location = ctx.pin(node.location.clone());

    let [operand] = node.args.as_slice() else {
        ctx.report_error(AnalysisErrorKind::IncorrectCallCardinality {
            expected: 1,
            found: node.args.len(),
            location: node.location.clone(),
        });

        return ValueRef::new_bottom(location);
    };

    // pin the result to the call site so error messages and downstream
    // backtraces refer to `T(x)`, not just to `x`'s declaration
    exprs::visit_single_expr(ctx, operand).with_location(location)
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

fn dispatch_blackbox<'a>(
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
        )]
    };

    nest_blanket_source(&mut result, blanket_bt, call_location);

    result
}

// whether a heuristically-inferred method is incompatible with expected arity
fn is_incompatible_arity_method<'a>(ctx: &AnalysisContext<'a>, node: &CallNode<'a>) -> bool {
    let ExprNode::Selection(selection) = &*node.func else {
        return false;
    };

    // reject package-qualified calls: `pkg.Func(...)` is not a method call
    if let ExprNode::Name(name) = &*selection.base
        && ctx.symtab().qualifier_exists(name.content())
    {
        return false;
    }

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

    let arity = signature.count_inputs();
    let args_len = node.args.len();

    if args_len == arity {
        // plausible
        return false;
    }

    let variadic = signature.params.last().is_some_and(|param| param.variadic);
    if variadic && args_len > arity {
        // plausible
        return false;
    }

    true
}

fn handle_deferred_checks<'a>(
    ctx: &mut AnalysisContext<'a>,
    func: &FunctionValue<'a>,
    ids: &[(Option<&Span<'a>>, bool, &TypeNode<'a>)],
    args: &[(ValueRef<'a>, Option<&LabelBacktrace<'a>>)],
    location: &Location,
) {
    let mut deferred_checks = Vec::from(func.deferred_checks());
    let capture_concretes = captures::derive_best_backtraces_for_captures(ctx, func);

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

    // if this is a sanitizer, now declassify
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
