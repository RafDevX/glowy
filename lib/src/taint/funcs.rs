use std::{borrow::Cow, rc::Rc};

use parser::{
    Annotation, Location, Span,
    ast::{BlockNode, CallNode, ExprNode, FunctionDeclNode, FunctionSignatureNode, TypeNode},
};

pub use self::{
    call_application::IterableFunctionCall,
    captures::{call_site::realize_stable_captures, resolve_accessed_capture},
    defers::DeferredCallReferents,
    returns::visit_return,
};
use crate::{
    Pinned,
    context::{AnalysisContext, DeferredCall},
    errors::AnalysisErrorKind,
    labels::{LabelBacktrace, LabelBacktraceKind, SyntheticSlot},
    policy,
    taint::exprs,
    types::TypeInfo,
    values::{FunctionRef, FunctionValue, SelfAwareBacktraceContainer, SimpleConstValue, ValueRef},
};

pub mod builtins;
mod call_application;
mod call_resolution;
mod captures;
mod defers;
mod definitions;
mod returns;

pub enum CallResolution<'a> {
    Final(Vec<ValueRef<'a>>),
    PendingApply(ResolvedCall<'a>),
}

// preprocessed state snapshot of everything necessary to apply a function call
pub struct ResolvedCall<'a> {
    callee: ValueRef<'a>,
    arg_values: Vec<ValueRef<'a>>,
    arg_consts: Vec<Option<SimpleConstValue>>,
    blackbox_replacement: Option<Box<FunctionValue<'a>>>,
    method_receiver_value: Option<ValueRef<'a>>,
}

pub fn visit_function_decl<'a>(ctx: &mut AnalysisContext<'a>, node: &FunctionDeclNode<'a>) {
    let func_name = ctx.pin(node.name);

    definitions::visit_function_def(
        ctx,
        &FunctionRef::Named(func_name),
        Some(func_name),
        &node.type_params,
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

    definitions::visit_function_def(
        ctx,
        &r#ref,
        None,
        &[],
        signature,
        None,
        Some(body),
        annotation,
    )
}

pub fn visit_call<'a>(ctx: &mut AnalysisContext<'a>, node: &CallNode<'a>) -> Vec<ValueRef<'a>> {
    match call_resolution::resolve_call(ctx, node) {
        CallResolution::Final(values) => values,
        CallResolution::PendingApply(resolved) => call_application::apply_call(ctx, node, resolved),
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

    match call_resolution::resolve_call(ctx, call) {
        CallResolution::Final(_) => {} // nothing left to do
        CallResolution::PendingApply(resolved) => {
            let referents = DeferredCallReferents::capture(ctx, &resolved, call);

            ctx.register_deferred_call(call.clone(), resolved, referents);
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
            mut resolved,
            referents,
            captured_branch_backtrace,
        } = pending;

        let installed = captured_branch_backtrace.is_some();
        if let Some(bt) = captured_branch_backtrace {
            ctx.push_branch_backtrace(bt);
        }

        referents.observe(&mut resolved);

        call_application::apply_call(ctx, &node, resolved);

        if installed {
            ctx.pop_branch_backtrace();
        }
    }
}

pub fn apply_predeclared_blanket_revocations<'a>(
    ctx: &AnalysisContext<'a>,
    name: &'static str,
    arg_consts: &[Option<SimpleConstValue>],
    result: &mut [ValueRef<'a>],
) {
    let directives = ctx.blanket_directives_for(policy::BUILTIN_PACKAGE_PATH, None, name);

    if directives.is_empty() {
        return;
    }

    // builtins with special handling bypass normal operand access and call
    // application, so we fake it here by creating a lightweight policy
    // carrier matching what those routines would have otherwise received so
    // that we can reuse the normal blanket directive machinery

    let mut fake_func = FunctionValue::new(
        FunctionRef::BuiltIn(name),
        None, // not relevant
        None,
        Vec::new(),
        None,
    );

    fake_func.absorb_blanket_directives(directives);

    call_application::apply_call_blanket_revocations(&fake_func, arg_consts, result);
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

pub fn calc_effective_call_site_branch_backtrace_for<'a>(
    ctx: &AnalysisContext<'a>,
    func: &FunctionValue<'a>,
    at_location: &Pinned<'a, Location>,
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
        Cow::Borrowed(at_location),
    )
}

fn collect_parameter_slots<'sig, 'a>(
    signature: &'sig FunctionSignatureNode<'a>,
) -> Vec<(Option<&'sig Span<'a>>, bool, &'sig TypeNode<'a>)> {
    let mut slots = vec![];

    for param in &signature.params {
        if param.ids.is_empty() {
            slots.push((None, param.variadic, &param.r#type));
        } else {
            let iter = param
                .ids
                .iter()
                .map(|id| (Some(id), param.variadic, &param.r#type));

            slots.extend(iter);
        }
    }

    slots
}
