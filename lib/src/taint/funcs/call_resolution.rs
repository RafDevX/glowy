use parser::ast::{CallNode, ExprNode, FunctionSignatureNode, SelectionNode};

use crate::{
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::LabelBacktraceKind,
    taint::{
        exprs,
        funcs::{CallResolution, ResolvedCall, builtins},
    },
    types::TypeKind,
    values::{FunctionValue, SelfAwareBacktraceContainer, SimpleConstValue, ValueRef},
};

pub fn resolve_call<'a>(ctx: &mut AnalysisContext<'a>, node: &CallNode<'a>) -> CallResolution<'a> {
    // we treat some built-in functions specially, not as function calls but as
    // independent quasi-types of expressions. if they don't look like a real
    // function call (e.g., take a type instead of a value as input, like make)
    // then they were already spotted and differentiated by the parser, but
    // otherwise we need to here identify all remaining built-in functions and
    // trigger their special handling, aborting function call handling on match
    if let Some(resolution) = try_resolve_special_builtin_call(ctx, node) {
        return resolution;
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

        return CallResolution::Final(vec![super::visit_type_conversion(
            ctx,
            node,
            value_func
                .declared_result_types()
                .first()
                .cloned()
                .flatten(),
        )]);
    }

    drop(value_func);

    // evaluate arguments after the function value, in Go's specified order.
    // a sole, unexpanded argument expression may be a multi-valued function
    // call whose results supply the parameters one-for-one. however: an
    // argument with `...` is different: it is one slice value supplied to a
    // variadic parameter, so it must be evaluated in a single-value context
    let mut args_with_consts = visit_call_args(ctx, node);

    let has_unknown_cardinality = !node.variadic
        && matches!(
            (node.args.as_slice(), args_with_consts.as_slice()),
            ([ExprNode::Call(_)], [(result, _)]) if result.is_mobius()
        );

    // re-borrow the function after evaluating the arguments, which may have
    // mutated analyzer state
    #[expect(clippy::shadow_unrelated, reason = "Same value as before")]
    let value_func = value.as_function().unwrap();

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
        && !has_unknown_cardinality
        && is_incompatible_cardinality_method(
            ctx,
            selection,
            &value_func,
            args_with_consts.len(),
            node.variadic,
        ) {
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

    if !validate_call_cardinality(
        ctx,
        node,
        func,
        &mut args_with_consts,
        has_unknown_cardinality,
    ) {
        return CallResolution::Final(vec![]);
    }

    // drop the immutable borrow of `value` (held via `value_func`/`func`)
    // before moving `value` into the resolved struct
    drop(value_func);

    // the selection ref captured alongside `base_value` was only needed for
    // the blackbox-replacement decision above; from here on, only the base
    // value matters (its taint flows in via SyntheticSlot::Receiver)
    let method_receiver_value = method_receiver.map(|(_, base)| base);

    let (arg_values, arg_consts) = args_with_consts.into_iter().unzip();

    CallResolution::PendingApply(ResolvedCall {
        callee: value,
        arg_values,
        arg_consts,
        blackbox_replacement,
        method_receiver_value,
    })
}

fn try_resolve_special_builtin_call<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &CallNode<'a>,
) -> Option<CallResolution<'a>> {
    let ExprNode::Name(id) = &*node.func else {
        return None;
    };

    if !ctx.symtab().resolves_to_predeclared(id.content()) {
        return None;
    }

    let mut arg_consts = vec![None; node.args.len()];

    // `name` is necessary to get a &'static str instead of a &'a str
    let (name, mut result) = match id.content() {
        "append" => (
            "append",
            vec![builtins::visit_append(ctx, node, &mut arg_consts)],
        ),
        "copy" => (
            "copy",
            vec![builtins::visit_copy(ctx, node, &mut arg_consts)],
        ),
        "clear" => ("clear", {
            builtins::visit_clear(ctx, node, &mut arg_consts);

            vec![]
        }),
        "close" => ("close", {
            builtins::visit_close(ctx, node, &mut arg_consts);

            vec![]
        }),
        "delete" => ("delete", {
            builtins::visit_delete(ctx, node, &mut arg_consts);

            vec![]
        }),
        "len" => ("len", vec![builtins::visit_len(ctx, node, &mut arg_consts)]),
        "cap" => ("cap", vec![builtins::visit_cap(ctx, node, &mut arg_consts)]),
        _ => return None,
    };

    super::apply_predeclared_blanket_revocations(ctx, name, &arg_consts, &mut result);

    Some(CallResolution::Final(result))
}

fn visit_call_args<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &CallNode<'a>,
) -> Vec<(ValueRef<'a>, Option<SimpleConstValue>)> {
    if !node.variadic && matches!(node.args.as_slice(), [ExprNode::Call(_)]) {
        return exprs::visit_multi_exprs_with_consts(ctx, &node.args);
    }

    node.args
        .iter()
        .map(|arg| {
            let known_const = exprs::try_resolve_simple_const(ctx, arg);
            let arg_value = exprs::visit_single_expr(ctx, arg);

            (arg_value, known_const)
        })
        .collect()
}

fn validate_call_cardinality<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &CallNode<'a>,
    func: &FunctionValue<'a>,
    args: &mut Vec<(ValueRef<'a>, Option<SimpleConstValue>)>,
    has_unknown_cardinality: bool,
) -> bool {
    let Some(signature) = func.signature() else {
        // without a known signature, there is no possible check to perform
        // (we just assume everything is fine; it would be unsound to error)
        return true;
    };

    let count = signature.count_inputs();

    if has_unknown_cardinality
        && let [(single, _)] = args.as_slice()
        && let Some(expanded) = single.try_expand_to(count)
    {
        *args = expanded
            .into_iter()
            .map(|expanded_value| (expanded_value, None))
            .collect();
    }

    let (expected, accepts_extra) = expected_call_cardinality(signature, node.variadic);
    let valid = args.len() == expected || (accepts_extra && args.len() > expected);

    if !valid {
        ctx.report_error(AnalysisErrorKind::IncorrectCallCardinality {
            expected,
            found: args.len(),
            location: node.location.clone(),
        });
    }

    valid
}

// `x...` occupies the variadic parameter slot itself. without `...`, that
// parameter instead accepts zero or more trailing argument values
fn expected_call_cardinality(
    signature: &FunctionSignatureNode<'_>,
    has_ellipsis: bool,
) -> (usize, bool) {
    let count = signature.count_inputs();

    let accepts_extra =
        !has_ellipsis && signature.params.last().is_some_and(|param| param.variadic);

    let expected = count - usize::from(accepts_extra);

    (expected, accepts_extra)
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
        return Some(super::nest_receiver_backtrace(
            method.borrow().value().get(),
            base_value,
            location(),
        ));
    }

    // otherwise, check if this selection is really just a field access being
    // called like a method (i.e., `s.F()` where `F` is a `func(...)` field)
    if matches!(
        r#type.strip_pointers().underlying(),
        Some(TypeKind::Struct { .. })
    ) && let Some(field) = r#type.lookup_promoted_field(selector)
        && let Some(r#struct) = base_value.as_struct()
    {
        let value = r#struct.get_const(&selector.to_owned(), location());

        // fold in the field-tag backtrace (if any) so any label declared on
        // the field via a struct tag manifests on this callable's value too
        let tag_backtrace = field.field_info().tag_backtrace().cloned();

        let value = match tag_backtrace {
            Some(tag_backtrace) => value.nest_backtrace(
                LabelBacktraceKind::Expression,
                None,
                location(),
                [tag_backtrace],
            ),
            None => value,
        };

        return Some(value);
    }

    // nothing we can do
    None
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
    variadic_call: bool,
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

    let (expected, accepts_extra) = expected_call_cardinality(signature, variadic_call);

    args_len != expected && !(accepts_extra && args_len > expected)
}
