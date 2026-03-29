use std::{borrow::Cow, iter};

use parser::{
    Location, Span,
    ast::{
        BlockNode, CallNode, ExprNode, FunctionDeclNode, FunctionParamDeclNode, FunctionResultNode,
        FunctionSignatureNode,
    },
};

use crate::{
    Pinned,
    context::{AnalysisContext, DeferTarget},
    errors::AnalysisErrorKind,
    labels::{Label, LabelBacktrace, LabelBacktraceKind, LabelTag},
    symbols::Symbol,
    taint::{SinkDescriptor, SinkKind, enforcement, exprs},
    values::{
        BacktraceContainer, FunctionRef, FunctionValue, Mergeable, MobiusValue,
        SelfAwareBacktraceContainer, Value, ValueRef,
    },
};

pub mod builtins;

fn visit_function_def<'a>(
    ctx: &mut AnalysisContext<'a>,
    r#ref: &FunctionRef<'a>,
    decl_symbol: Option<Pinned<Span<'a>>>,
    signature: &FunctionSignatureNode<'a>,
    receiver: Option<&FunctionParamDeclNode<'a>>,
    body: &BlockNode<'a>,
) -> ValueRef<'a> {
    let mut func_val = FunctionValue::new(
        r#ref.clone(),
        Some(signature.clone()),
        None, // TODO: support annotations
    );

    // cannot use `vec![ValueRef::new_bottom(); signature.result.len()]`, since
    // the vec! macro would clone the ValueRef (and so they'd all point to the
    // same value, which is not what we want; they should be independent)
    let bottom_outcome = iter::once(Value::Simple(None))
        .cycle()
        .take(signature.result.len())
        // map only after cycle, otherwise Clone would just make many references
        .map(ValueRef::from)
        .collect();

    // since we know that this function has an implementation, we set a bottom
    // value as outcome (with the right cardinality), to distinguish from a
    // blackbox function without implementation (which would have unset outcome)
    func_val.set_outcome(bottom_outcome);

    let value = ValueRef::from(Value::Function(func_val));

    if let Some(name) = decl_symbol {
        let symbol = Symbol::new_ref(name, false, value.clone());

        ctx.declare_new_symbol(symbol);
    }

    ctx.symtab_mut().select_next_child_scope(); // push

    macro_rules! declare_param {
        ($id:expr, $index:expr) => {
            let synthetic = LabelTag::Synthetic {
                func: r#ref.clone(),
                index: $index,
                identifier: Some($id),
            };

            let param_backtrace = LabelBacktrace::new_root(
                LabelBacktraceKind::FunctionParameter,
                Label::from_single(synthetic),
                Some($id.content()),
                ctx.pin($id.location()),
            );

            ctx.declare_new_symbol(Symbol::new_ref(
                ctx.pin($id),
                true,
                ValueRef::from(Some(param_backtrace)),
            ));
        };
    }

    if let Some(receiver) = receiver {
        if let [id] = receiver.ids.as_slice() {
            if id.content() != "_" {
                declare_param!(*id, None);
            }
        }
    }

    let mut param_index = 0;

    for param in &signature.params {
        for &id in &param.ids {
            // only ignore if blank identifier
            if id.content() != "_" {
                declare_param!(id, Some(param_index));
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

    ctx.push_function(value.clone());
    ctx.increase_branch_scope_depth();

    super::visit_statements(ctx, body);

    ctx.decrease_branch_scope_depth();
    ctx.trigger_defer_target(DeferTarget::Function);
    ctx.pop_function();

    ctx.symtab_mut().select_parent_scope(); // pop

    value
}

pub fn visit_function_decl<'a>(ctx: &mut AnalysisContext<'a>, node: &FunctionDeclNode<'a>) {
    let func_name = ctx.pin(node.name);

    let r#ref = FunctionRef::Named(func_name.clone());

    visit_function_def(
        ctx,
        &r#ref,
        Some(func_name),
        &node.signature,
        node.receiver.as_ref(),
        &node.body,
    );
}

pub fn visit_function_literal<'a>(
    ctx: &mut AnalysisContext<'a>,
    signature: &FunctionSignatureNode<'a>,
    body: &BlockNode<'a>,
    location: &Location,
) -> ValueRef<'a> {
    let r#ref = FunctionRef::Anonymous(ctx.pin(location.clone()));

    visit_function_def(ctx, &r#ref, None, signature, None, body)
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

    let outcome = calculate_outcome(ctx, func.signature(), exprs, location);

    // merge with existing outcome, if any
    // (this allows for multiple return statements within the same function)
    let outcome = if let Some(existing) = func.outcome() {
        merge_outcomes(ctx, existing, outcome, location)
    } else {
        outcome
    };

    drop(func);

    let Some(mut func) = value.as_function_mut() else {
        ctx.report_error(AnalysisErrorKind::UnexpectedReturn {
            location: location.clone(),
        });

        return;
    };

    func.set_outcome(outcome);

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

    let exprs = if exprs.is_empty() {
        if let Some(FunctionResultNode::Params(result)) = signature.map(|sig| &sig.result) {
            // naked returns

            result
                .iter()
                .flat_map(|p| p.ids.clone())
                .map(ExprNode::Name)
                .collect()
        } else {
            vec![]
        }
    } else {
        Vec::from(exprs)
    };

    for expr in &exprs {
        let expr_backtrace = exprs::visit_single_expr(ctx, expr);

        let backtrace = expr_backtrace.nest_backtrace(
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

    for (existing, new) in existing.iter().zip(new.into_iter()) {
        merged.push(new.merge_with(existing, LabelBacktraceKind::Return, Cow::Borrowed(&pinned)));
    }

    merged
}

#[allow(clippy::too_many_lines)]
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

    let Some(func) = value.as_function() else {
        ctx.report_error(AnalysisErrorKind::IllegalCallExpression {
            location: node.location.clone(),
        });

        return vec![];
    };

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
                ids.push((None, param.variadic));
            } else {
                ids.extend(param.ids.iter().map(|id| (Some(id), param.variadic)));
            }
        }

        Some(ids)
    } else {
        None
    };

    // can only check for correct cardinality if we have a signature,
    // otherwise we just assume everything is fine (would be wrong to error)
    if let Some(ids) = &ids {
        if node.args.len() != ids.len() {
            let variadic = ids.last().is_some_and(|(_, variadic)| *variadic);

            if !(variadic && node.args.len() > ids.len()) {
                ctx.report_error(AnalysisErrorKind::IncorrectCallCardinality {
                    expected: ids.len(),
                    found: node.args.len(),
                    location: node.location.clone(),
                });

                return vec![];
            }
        }
    }

    if let Some(annotation) = &node.annotation {
        match annotation.directive {
            "sink" => {
                let sink = SinkDescriptor::new(
                    SinkKind::Call,
                    &annotation.tags,
                    node.location.clone(), // call, not annotation
                );

                for arg in &node.args {
                    let backtrace = exprs::get_expr_backtrace(ctx, arg);

                    enforcement::trigger_sink(ctx, Cow::Borrowed(&sink), backtrace);
                }
            }
            "assert" => {
                let sequence = Label::sequence_from_tags(&annotation.tags);

                for arg in &node.args {
                    let backtrace = exprs::get_expr_backtrace(ctx, arg);

                    enforcement::trigger_assertion(
                        ctx,
                        &sequence,
                        backtrace,
                        node.location.clone(),
                    );
                }
            }
            _ => ctx.report_error(AnalysisErrorKind::UnknownAnnotationDirective {
                directive: annotation.directive,
                location: annotation.location.clone(),
            }),
        }
    }

    let Some(outcome) = func.outcome() else {
        // we don't have a known implementation of this function, so we must
        // treat it as a blackbox and assume the label of all its outputs is the
        // union of the label of all its inputs; we can't do anything fancy

        let mut children = vec![];

        for arg in &node.args {
            if let Some(child) = exprs::get_expr_backtrace(ctx, arg) {
                children.push(child);
            }
        }

        let bt = LabelBacktrace::fold(
            children.iter().chain(func.backtrace()),
            LabelBacktraceKind::BlackboxCall,
            None,
            ctx.pin(node.location.clone()),
        );

        if let Some(signature) = func.signature() {
            // we have a signature, so we know exactly how many values it
            // returns and so can use that information

            return iter::once(Value::Simple(bt))
                .cycle()
                .take(signature.result.len())
                // only after cycle otherwise Clone would just make many refs
                .map(ValueRef::from)
                .collect();
        }

        // we have no way of knowing how many values this function returns, so
        // the best we can do is return a Möbius value that can be expanded to
        // however many values the invoker expects

        let mobius = MobiusValue::new(ValueRef::from(bt));

        return vec![ValueRef::from(Value::Mobius(mobius))];
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
        let value = exprs::visit_single_expr(ctx, &selection.base);

        if value.as_package_ref().is_some() {
            None
        } else {
            let location = ctx.pin(exprs::get_expr_location(&selection.base));

            Some(value.backtrace_at_location(location))
        }
    } else {
        None
    };

    handle_deferred_checks(ctx, &func, &ids, &node.args, &node.location);

    let mut result = calculate_call_result(
        ctx,
        &func,
        receiver.as_ref().map(Option::as_ref),
        &ids,
        outcome,
        &node.args,
        &node.location,
    );

    // need to nest the function's backtrace into the result because the
    // function itself was accessed
    if let Some(bt) = func.backtrace() {
        for realized in &mut result {
            *realized = realized.nest_backtrace(
                LabelBacktraceKind::Expression,
                None,
                ctx.pin(node.location.clone()),
                [bt.clone()],
            );
        }
    }

    // re-borrow as mutable
    drop(func);
    if let Some(mut func) = value.as_function_mut() {
        func.record_call();
    }

    result

    // TODO: test calling variadic fn, like `f(string, ...int)` with
    // `f("hello", 1, 2, 3)`
}

fn handle_deferred_checks<'a>(
    ctx: &mut AnalysisContext<'a>,
    func: &FunctionValue<'a>,
    ids: &[(Option<&Span<'a>>, bool)],
    args: &[ExprNode<'a>],
    location: &Location,
) {
    let mut deferred_checks = Vec::from(func.deferred_checks());

    for (index, (id, variadic)) in ids.iter().copied().enumerate() {
        let concrete = calculate_concrete_backtrace(ctx, index, id, variadic, args, location);

        deferred_checks = deferred_checks
            .iter()
            .filter_map(|check| check.realize(func.r#ref(), Some(index), concrete.as_ref()))
            .collect();
    }

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

#[allow(
    clippy::option_option,
    reason = "Conveniently represent a receiver's presence/absence"
)]
fn calculate_call_result<'a>(
    ctx: &mut AnalysisContext<'a>,
    func: &FunctionValue<'a>,
    receiver: Option<Option<&LabelBacktrace<'a>>>,
    ids: &[(Option<&Span<'a>>, bool)],
    outcome: &Vec<ValueRef<'a>>,
    args: &[ExprNode<'a>],
    location: &Location,
) -> Vec<ValueRef<'a>> {
    let mut result = vec![];

    'components: for component in outcome {
        let mut realized = component.clone();

        if let Some(receiver) = receiver {
            realized = realized.realize(func.r#ref(), None, receiver);
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

        for (index, (id, variadic)) in ids.iter().copied().enumerate() {
            if realized.is_bottom() {
                // no sense in continuing, we'll never evolve from this state

                result.push(realized);

                continue 'components;
            }

            let concrete = calculate_concrete_backtrace(ctx, index, id, variadic, args, location);

            realized = realized.realize(func.r#ref(), Some(index), concrete.as_ref());
        }

        result.push(realized);
    }

    result
}

fn calculate_concrete_backtrace<'a>(
    ctx: &mut AnalysisContext<'a>,
    index: usize,
    id: Option<&Span<'a>>,
    variadic: bool,
    args: &[ExprNode<'a>],
    location: &Location,
) -> Option<LabelBacktrace<'a>> {
    if variadic {
        let children: Vec<_> = args[index..]
            .iter()
            .filter_map(|arg| exprs::get_expr_backtrace(ctx, arg))
            .collect();

        LabelBacktrace::fold(
            &children,
            LabelBacktraceKind::FunctionVariadicAggregation,
            id.map(Span::content),
            ctx.pin(location.clone()),
        )
    } else {
        let arg = args.get(index).expect("already checked arg count");

        exprs::get_expr_backtrace(ctx, arg)
    }
}
