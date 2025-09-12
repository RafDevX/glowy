use parser::{
    Location, Span,
    ast::{
        CallNode, ExprNode, FunctionDeclNode, FunctionResultNode, FunctionSignatureNode,
        OperandNameNode,
    },
};

use crate::{
    context::{AnalysisContext, DeferTarget},
    errors::AnalysisErrorKind,
    labels::{Label, LabelBacktrace, LabelBacktraceKind, LabelTag},
    symbols::Symbol,
    taint::exprs,
    values::{
        BacktraceContainer, FunctionRef, FunctionValue, SelfAwareBacktraceContainer, Value,
        ValueRef,
    },
};

pub fn visit_function_decl<'a>(ctx: &mut AnalysisContext<'a>, node: &FunctionDeclNode<'a>) {
    let func_name = ctx.pin(node.name.clone());

    let func_ref = FunctionRef::Named(func_name.clone());

    let value = ValueRef::from(Value::Function(FunctionValue::new(
        func_ref.clone(),
        node.signature.clone(),
        None, // TODO: support annotations
    )));

    let symbol = Symbol::new_ref(func_name.clone(), false, value.clone());

    ctx.declare_new_symbol(symbol.clone());

    ctx.symtab_mut().select_next_child_scope(); // push

    let mut param_index = 0;

    for param in &node.signature.params {
        for id in &param.ids {
            if id.content() == "_" {
                // blank identifier, ignore
                param_index += 1;
                continue;
            }

            let synthetic = LabelTag::Synthetic {
                func: func_ref.clone(),
                index: param_index,
                identifier: Some(id.clone()),
            };

            let param_backtrace = LabelBacktrace::new_root(
                LabelBacktraceKind::FunctionParameter,
                Label::from_single(synthetic),
                id.content(),
                ctx.pin(id.location()),
            );

            ctx.declare_new_symbol(Symbol::new_ref(
                ctx.pin(id.clone()),
                true,
                ValueRef::from(Some(param_backtrace)),
            ));

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

    ctx.push_function(value);
    ctx.increase_branch_scope_depth();

    super::visit_statements(ctx, &node.body);

    ctx.decrease_branch_scope_depth();
    ctx.pop_function();

    ctx.symtab_mut().select_parent_scope(); // pop
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
    signature: &FunctionSignatureNode<'a>,
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
        if let Some(FunctionResultNode::Params(result)) = &signature.result {
            // naked returns

            result
                .iter()
                .flat_map(|p| p.ids.clone())
                .map(|id| OperandNameNode { package: None, id })
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

pub fn visit_call<'a>(ctx: &mut AnalysisContext<'a>, node: &CallNode<'a>) -> Vec<ValueRef<'a>> {
    let value = exprs::visit_single_expr(ctx, &node.func);

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

    let mut ids = Vec::new();
    for param in &func.signature().params {
        if param.ids.is_empty() {
            ids.push((None, param.variadic));
        } else {
            ids.extend(param.ids.iter().map(|id| (Some(id), param.variadic)));
        }
    }

    if node.args.len() != ids.len() {
        let variadic = ids.last().map(|(_, variadic)| *variadic).unwrap_or(false);

        if !(variadic && node.args.len() > ids.len()) {
            ctx.report_error(AnalysisErrorKind::IncorrectCallCardinality {
                expected: ids.len(),
                found: node.args.len(),
                location: node.location.clone(),
            });

            return vec![];
        }
    }

    let mut result = vec![];

    'components: for component in func.outcome() {
        let mut realized = None;

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
            let base = if let Some(value) = realized {
                // this is not the first iteration; continue where we left off
                value
            } else {
                // this is the first iteration; start from the outcome component
                component.clone()
            };

            if base.is_bottom() {
                // no sense in continuing, we'll never evolve from this state

                result.push(base);

                continue 'components;
            }

            let concrete = if variadic {
                let children: Vec<_> = node.args[index..]
                    .iter()
                    .filter_map(|arg| exprs::get_expr_backtrace(ctx, arg))
                    .collect();

                LabelBacktrace::fold(
                    &children,
                    LabelBacktraceKind::FunctionVariadicAggregation,
                    id.map(Span::content),
                    ctx.pin(node.location.clone()),
                )
            } else {
                let arg = node.args.get(index).expect("already checked arg count");

                exprs::get_expr_backtrace(ctx, arg)
            };

            realized = Some(base.realize(func.r#ref(), index, concrete.as_ref()));
        }

        result.push(realized.unwrap_or_else(|| component.clone()));
    }

    // need to nest the function's backtrace into the result because the
    // function itself was accessed
    if let Some(bt) = func.backtrace() {
        for realized in &mut result {
            *realized = realized.nest_backtrace(
                LabelBacktraceKind::Expression,
                None,
                ctx.pin(node.location.clone()),
                [bt.clone()],
            )
        }
    }

    result

    // TODO: test calling variadic fn, like `f(string, ...int)` with
    // `f("hello", 1, 2, 3)`
}
