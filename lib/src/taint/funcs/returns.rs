use std::borrow::Cow;

use glowy_go_parser::{
    Location,
    ast::{ExprNode, FunctionResultNode, FunctionSignatureNode},
};

use crate::{
    context::{AnalysisContext, DeferTarget},
    errors::AnalysisErrorKind,
    labels::{Label, LabelBacktraceKind},
    taint::{exprs, mutation::LeftValue},
    values::{Mergeable, SelfAwareBacktraceContainer, ValueRef},
};

pub fn visit_return<'a>(
    ctx: &mut AnalysisContext<'a>,
    exprs: &[ExprNode<'a>],
    location: &Location,
) {
    ctx.record_range_exit_feedback(location);

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
        let raw = super::visit_call(ctx, call);

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

pub fn prepare_named_result_params_for_defers<'a>(
    ctx: &mut AnalysisContext<'a>,
    result: &FunctionResultNode<'a>,
    location: &Location,
) {
    let FunctionResultNode::Params(params) = result else {
        return;
    };

    let Some((_, outcome)) = get_current_function_outcome(ctx) else {
        return;
    };

    for (name, value) in params.iter().flat_map(|param| &param.ids).zip(outcome) {
        if name.content() == "_" {
            continue;
        }

        name.assign(
            ctx,
            LabelBacktraceKind::Return,
            value,
            None,
            true,
            None,
            &Label::Bottom,
            location,
        );
    }
}

pub fn finalize_named_result_outcome<'a>(
    ctx: &mut AnalysisContext<'a>,
    result: &FunctionResultNode<'a>,
    location: &Location,
) {
    let FunctionResultNode::Params(params) = result else {
        return;
    };

    let Some((mut value, mut outcome)) = get_current_function_outcome(ctx) else {
        return;
    };

    let pinned_location = ctx.pin(location.clone());
    let branch_backtrace = ctx.branch_backtrace();

    for (slot, name) in params.iter().flat_map(|param| &param.ids).enumerate() {
        if name.content() == "_" {
            continue;
        }

        let Some(current) = outcome.get_mut(slot) else {
            // return cardinality validation already took place, so an error was
            // already reported; just bail and keep what we have so far
            break;
        };

        let Some(symbol) = ctx.symtab().get_symbol_by_declaration(ctx.pin(*name)) else {
            continue;
        };

        *current = symbol.borrow().value().get().nest_backtrace(
            LabelBacktraceKind::Return,
            None,
            pinned_location.clone(),
            branch_backtrace.cloned(),
        );
    }

    if let Some(mut func_mut) = value.as_function_mut() {
        func_mut.set_outcome(outcome);
    }
}

fn get_current_function_outcome<'a>(
    ctx: &AnalysisContext<'a>,
) -> Option<(ValueRef<'a>, Vec<ValueRef<'a>>)> {
    let value = ctx.current_function()?;
    let outcome = value.as_function()?.outcome().cloned()?;

    Some((value, outcome))
}
