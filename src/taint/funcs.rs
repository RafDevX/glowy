use std::iter;

use parser::{
    Location, Span,
    ast::{
        BlockNode, CallNode, ExprNode, FunctionDeclNode, FunctionResultNode, FunctionSignatureNode,
        OperandNameNode,
    },
};

use crate::{
    Pinned,
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

pub mod builtins;

fn visit_function_def<'a>(
    ctx: &mut AnalysisContext<'a>,
    r#ref: FunctionRef<'a>,
    decl_symbol: Option<Pinned<Span<'a>>>,
    signature: &FunctionSignatureNode<'a>,
    body: &BlockNode<'a>,
) -> ValueRef<'a> {
    let mut func_val = FunctionValue::new(
        r#ref.clone(),
        signature.clone(),
        None, // TODO: support annotations
    );

    // cannot use `vec![ValueRef::from(None); signature.result.len()]`, since
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

        ctx.declare_new_symbol(symbol.clone());
    }

    ctx.symtab_mut().select_next_child_scope(); // push

    let mut param_index = 0;

    for param in &signature.params {
        for &id in &param.ids {
            if id.content() == "_" {
                // blank identifier, ignore
                param_index += 1;
                continue;
            }

            let synthetic = LabelTag::Synthetic {
                func: r#ref.clone(),
                index: param_index,
                identifier: Some(id),
            };

            let param_backtrace = LabelBacktrace::new_root(
                LabelBacktraceKind::FunctionParameter,
                Label::from_single(synthetic),
                id.content(),
                ctx.pin(id.location()),
            );

            ctx.declare_new_symbol(Symbol::new_ref(
                ctx.pin(id),
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

    ctx.push_function(value.clone());
    ctx.increase_branch_scope_depth();

    super::visit_statements(ctx, body);

    ctx.decrease_branch_scope_depth();
    ctx.pop_function();

    ctx.symtab_mut().select_parent_scope(); // pop

    value
}

pub fn visit_function_decl<'a>(ctx: &mut AnalysisContext<'a>, node: &FunctionDeclNode<'a>) {
    let func_name = ctx.pin(node.name);

    let r#ref = FunctionRef::Named(func_name.clone());

    visit_function_def(ctx, r#ref, Some(func_name), &node.signature, &node.body);
}

pub fn visit_function_literal<'a>(
    ctx: &mut AnalysisContext<'a>,
    signature: &FunctionSignatureNode<'a>,
    body: &BlockNode<'a>,
    location: &Location,
) -> ValueRef<'a> {
    let r#ref = FunctionRef::Anonymous(ctx.pin(location.clone()));

    visit_function_def(ctx, r#ref, None, signature, body)
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
        if let FunctionResultNode::Params(result) = &signature.result {
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
    // we treat some built-in functions specially, not as function calls but as
    // independent quasi-types of expressions. if they don't look like a real
    // function call (e.g., take a type instead of a value as input, like make)
    // then they were already spotted and differentiated by the parser, but
    // otherwise we need to here identify all remaining built-in functions and
    // trigger their special handling, aborting function call handling on match
    if let ExprNode::Name(OperandNameNode { package: None, id }) = &*node.func {
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

        return iter::once(Value::Simple(bt))
            .cycle()
            .take(func.signature().result.len())
            // only after cycle otherwise Clone would just make many references
            .map(ValueRef::from)
            .collect();
    };

    let mut result = vec![];

    'components: for component in outcome {
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
