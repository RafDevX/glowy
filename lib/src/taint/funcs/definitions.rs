use std::{iter, rc::Rc};

use parser::{
    Annotation, Location, Span,
    ast::{
        BlockNode, FunctionParamDeclNode, FunctionResultNode, FunctionSignatureNode, TypeNameNode,
        TypeNode,
    },
};

use crate::{
    Pinned,
    context::{AnalysisContext, DeferTarget},
    decls,
    errors::AnalysisErrorKind,
    labels::{FunctionRef, Label, LabelBacktrace, LabelBacktraceKind, LabelTag, SyntheticSlot},
    symbols::Symbol,
    taint::{self, annotations, funcs::captures, goto},
    types::TypeInfo,
    values::{
        FunctionValue, InherentSink, InherentSourceOrRevocation, ReceiverKind, Value, ValueRef,
    },
};

#[expect(
    clippy::too_many_lines,
    reason = "Very tight coupling means it would become more confusing if split up"
)]
pub fn visit_function_def<'a>(
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
        FunctionRef::BuiltIn(_) | FunctionRef::BlackboxInference(_) => decl_symbol
            .as_ref()
            .map_or_else(|| crate::FAKE_LOCATION.clone(), Pinned::pinned_location),
    };

    #[rustfmt::skip]
    let func_val = build_function_value(
        ctx,
        r#ref,
        signature,
        receiver,
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

            existing.borrow_mut().set_value(value.clone(), None);
        } else {
            let symbol = Symbol::new_ref(name, false, value.clone(), None);

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

            ctx.declare_new_symbol(Symbol::new_ref(ctx.pin($id), true, param_value, None));
        };
    }

    if let Some(receiver) = receiver
        && let [id] = receiver.ids.as_slice()
        && id.content() != "_"
    {
        let receiver_type = {
            let (types, symtab) = ctx.types_mut_with_symtab();

            types.resolve(symtab, &receiver.r#type)
        };

        declare_param!(*id, SyntheticSlot::Receiver, receiver_type);
    }

    let mut param_index = 0;

    for param in &signature.params {
        let param_type = if param.variadic {
            // variadic `...T` params bind a `[]T` slice when used as a single
            // param, and that slice has no named representation in the registry

            None
        } else {
            let (types, symtab) = ctx.types_mut_with_symtab();

            types.resolve(symtab, &param.r#type)
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

    captures::register_captures(ctx, r#ref, signature, receiver, body, &mut value);

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

    // named results need to be in scope before defers run
    super::returns::prepare_named_result_params_for_defers(ctx, &signature.result, &body.location);

    super::apply_deferred_calls(ctx); // from `defer` statements

    super::returns::finalize_named_result_outcome(ctx, &signature.result, &body.location);

    captures::record_capture_fallbacks(ctx, &mut value);

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
    receiver: Option<&FunctionParamDeclNode<'a>>,
    annotation: Option<&Annotation<'a>>,
    value_location: &Pinned<'a, Location>,
) -> FunctionValue<'a> {
    let mut explicit_backtrace = None;
    let mut decl_revocation = None;
    let mut decl_sink = None;

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
            annotations::FunctionDirective::Revoke => {
                if let Some(label) = annotations::resolve_revocation_label(ctx, annotation) {
                    decl_revocation = Some(InherentSourceOrRevocation::new_unconditional(label));
                }
            }
            annotations::FunctionDirective::AllowSink
            | annotations::FunctionDirective::DenySink => {
                decl_sink = InherentSink::new(
                    directive == annotations::FunctionDirective::AllowSink,
                    &annotation.tags,
                    None,
                );

                if decl_sink.is_none() {
                    ctx.report_error(AnalysisErrorKind::InvalidDenySinkSemantics {
                        location: annotation.location.clone(),
                    });
                }
            }
        }
    }

    // we need to pre-resolve the results' declared types at definition-time,
    // since they may rely on contextual information only present here + now
    // and no longer available at invocation time, especially for unqualified
    // types used in functions defined in a different file than its invokers
    let declared_result_types = resolve_declared_result_types(ctx, &signature.result);

    let mut func_val = FunctionValue::new(
        r#ref.clone(),
        Some(signature.clone()),
        receiver.map(ReceiverKind::from),
        declared_result_types,
        explicit_backtrace,
    );

    if let Some(revocation) = decl_revocation {
        func_val.add_revocation(revocation);
    }

    if let Some(sink) = decl_sink {
        func_val.add_sink(sink);
    }

    // fold in any configured blanket directives associated with this function
    if let FunctionRef::Named(name) = r#ref
        && let Some(pkg_path) = ctx.symtab().current_package_path()
        && ctx.current_function().is_none()
    // ^^^ check for root level: technically it should not be possible for
    // nested functions to be Named (they're always anonymous literals), but we
    // might as well check that this is not shadowing some outer function (to
    // which the blanket directives actually apply), given that the parser does
    // not place any type-level restrictions on this spec condition at AST level
    {
        // in case this is a method
        let receiver_type_name = receiver.and_then(|receiver| {
            // extract from TypeNode::Name, if applicable
            decls::receiver_base_type_name(&receiver.r#type)
        });

        let directives = ctx.blanket_directives_for(pkg_path, receiver_type_name, name.content());

        func_val.absorb_blanket_directives(directives.iter());
    }

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

fn resolve_declared_result_types<'a>(
    ctx: &mut AnalysisContext<'a>,
    result: &FunctionResultNode<'a>,
) -> Vec<Option<Rc<TypeInfo<'a>>>> {
    let mut resolve = |r#type: &TypeNode<'a>| {
        let (types, symtab) = ctx.types_mut_with_symtab();

        types.resolve(symtab, r#type)
    };

    match result {
        FunctionResultNode::None => Vec::new(),
        FunctionResultNode::Single(r#type) => vec![resolve(r#type)],
        FunctionResultNode::Params(params) => params
            .iter()
            .flat_map(|param| iter::repeat_n(resolve(&param.r#type), param.ids.len().max(1)))
            .collect(),
    }
}

// sets up plumbing to allow for naked returns
fn bind_named_result_locals<'a>(ctx: &mut AnalysisContext<'a>, result: &FunctionResultNode<'a>) {
    let FunctionResultNode::Params(params) = result else {
        // FunctionResultNode::Single is always unnamed; None has no results
        return;
    };

    for param in params {
        let r#type = {
            let (types, symtab) = ctx.types_mut_with_symtab();

            types.resolve(symtab, &param.r#type)
        };

        for &id in &param.ids {
            if id.content() == "_" {
                // blank identifier
                continue;
            }

            let pinned = ctx.pin(id);
            let value = ValueRef::new_bottom(pinned.pinned_location(), r#type.clone());

            ctx.declare_new_symbol(Symbol::new_ref(pinned, true, value, None));
        }
    }
}

fn visit_function_body<'a>(ctx: &mut AnalysisContext<'a>, body: &BlockNode<'a>) {
    if !goto::block_contains_goto(body) {
        // this matches the vast majority of functions and collapses into simply
        // visiting the statement block as normal

        taint::visit_statements(ctx, &body.stmts);

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

        taint::visit_statements(ctx, &body.stmts);

        ctx.pop_error_suppression();

        goto::pop_goto_branch_backtraces(ctx);

        stable = goto::advance_goto_convergence_iteration(ctx);

        // restore state from checkpoint, since this was a speculative visit
        ctx.symtab_mut().set_child_scope_cursor(initial_cursor);
        ctx.restore_deferred_state(pre_body_deferred.clone());
    }

    // final pass with errors enabled, now that the state is stable
    taint::visit_statements(ctx, &body.stmts);

    goto::pop_goto_branch_backtraces(ctx);

    goto::pop_goto_convergence_context(ctx);
}
