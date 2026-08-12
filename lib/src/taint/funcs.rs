use std::{borrow::Cow, iter, rc::Rc, slice};

use glowy_go_parser::{
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
    context::{AnalysisContext, DeferTarget, DeferredCall},
    errors::AnalysisErrorKind,
    labels::{LabelBacktrace, LabelBacktraceKind, SyntheticSlot},
    policy,
    taint::exprs,
    types::TypeInfo,
    values::{
        FunctionRef, FunctionValue, SelfAwareBacktraceContainer, SimpleConstValue, Value, ValueRef,
    },
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
    method_receiver_value: Option<ValueRef<'a>>,
}

pub fn visit_function_decl<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &FunctionDeclNode<'a>,
    is_main: bool,
) {
    let func_name = ctx.pin(node.name);

    let r#ref = FunctionRef::Named {
        name: func_name,
        is_main,
    };

    definitions::visit_function_def(
        ctx,
        &r#ref,
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

pub fn visit_init_function<'a>(ctx: &mut AnalysisContext<'a>, node: &FunctionDeclNode<'a>) {
    let Some(body) = &node.body else {
        return;
    };

    let func_name = ctx.pin(node.name);
    let location = func_name.pinned_location();

    let func = FunctionValue::new(
        FunctionRef::new_named(func_name),
        Some(node.signature.clone()),
        None,
        Vec::new(),
        None,
    );

    let value = ValueRef::new(Value::Function(Box::new(func)), location, None);

    // init executes automatically and directly in package initialization order,
    // so its body must keep the immediate package-state behavior of a top-level
    // block. however, it still needs a function frame for defers, returns, and
    // function-depth-scoped state such as range-function feedback
    ctx.push_function(value, iter::empty());
    ctx.increase_branch_scope_depth();

    super::visit_block(ctx, body);
    apply_deferred_calls(ctx);

    ctx.decrease_branch_scope_depth();
    ctx.trigger_defer_target(DeferTarget::Function);
    ctx.pop_function();
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

pub fn apply_operator_blanket_revocations<'a>(
    ctx: &AnalysisContext<'a>,
    name: &str,
    operand_consts: &[Option<SimpleConstValue>],
    result: &mut ValueRef<'a>,
) {
    let directives = ctx.blanket_directives_for(policy::OPERATOR_PACKAGE_PATH, None, name);

    if directives.is_empty() {
        return;
    }

    // operators use the same policy semantics as two-argument, single-result
    // functions; a lightweight function value lets them share that machinery
    // without introducing synthetic symbols or calls into the analysis
    let mut fake_func = FunctionValue::new_unknown(None, false);

    fake_func.absorb_blanket_directives(directives);

    let result = slice::from_mut(result);

    call_application::apply_call_blanket_revocations(&fake_func, operand_consts, result);
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
