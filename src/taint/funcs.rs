use parser::{
    ast::{
        CallNode, ExprNode, FunctionDeclNode, FunctionResultNode, FunctionSignatureNode,
        OperandNameNode,
    },
    Location, Span,
};

use crate::{
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{FunctionRef, Label, LabelBacktrace, LabelBacktraceKind, LabelTag},
    symbols::{FunctionMetadata, FunctionMetadataRef, Symbol},
    taint::exprs,
};

pub fn visit_function_decl<'a>(ctx: &mut AnalysisContext<'a>, node: &FunctionDeclNode<'a>) {
    let func_name = ctx.pin(node.name.clone());

    let symbol = Symbol::new_ref(func_name.clone(), false, None);

    ctx.declare_new_symbol(symbol);

    ctx.symtab_mut().select_first_child_scope(); // push

    let func_ref = FunctionRef::Named(func_name.clone());

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
                Some(param_backtrace),
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

    let func = FunctionMetadata::new_ref(func_ref, &node.signature);
    ctx.push_function(func);

    super::visit_statements(ctx, &node.body);

    if node.signature.result.is_some() && !ctx.returning() {
        ctx.report_error(AnalysisErrorKind::MissingReturn {
            func: node.name.clone(),
        });
    }

    ctx.set_returning(false);
    ctx.pop_function();

    ctx.symtab_mut().select_parent_scope(); // pop
}

pub fn visit_return<'a>(
    ctx: &mut AnalysisContext<'a>,
    exprs: &[ExprNode<'a>],
    location: &Location,
) {
    let Some(func) = ctx.current_function() else {
        ctx.report_error(AnalysisErrorKind::UnexpectedReturn {
            location: location.clone(),
        });

        return;
    };

    let outcome = calculate_outcome(ctx, func.borrow().signature(), exprs, location);

    func.borrow_mut().set_outcome(outcome);

    ctx.set_returning(true);
}

fn calculate_outcome<'a>(
    ctx: &mut AnalysisContext<'a>,
    signature: &FunctionSignatureNode<'a>,
    exprs: &[ExprNode<'a>],
    location: &Location,
) -> Vec<Option<LabelBacktrace<'a>>> {
    // TODO: branch backtrace

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
        let child = exprs::visit_single_expr(ctx, expr);

        let backtrace = LabelBacktrace::new(
            LabelBacktraceKind::Return,
            child
                .as_ref()
                .map(|bt| bt.label().clone())
                .unwrap_or(Label::Bottom),
            // .union(branch_backtrace.unwrap_or(Label::Bottom))
            None,
            ctx.pin(location.clone()),
            child.iter(), //.chain(branch_backtrace)
        );

        outcome.push(backtrace);
    }

    outcome
}

pub fn visit_call<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &CallNode<'a>,
) -> Vec<Option<LabelBacktrace<'a>>> {
    let Some(metadata) = func_metadata_from_call_expr(ctx, &node.func) else {
        return vec![]; // error already reported
    };
    let borrowed = metadata.borrow();
    let params = &borrowed.signature().params;

    if node.args.len() != params.len() {
        let variadic = params.last().map(|p| p.variadic).unwrap_or(false);

        if !(variadic && node.args.len() > params.len()) {
            ctx.report_error(AnalysisErrorKind::IncorrectCallCardinality {
                expected: params.len(),
                found: node.args.len(),
                location: node.location.clone(),
            });

            return vec![];
        }
    }

    let mut result = vec![];

    'components: for component in borrowed.outcome() {
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

        let mut ids = Vec::new();
        for param in params {
            if param.ids.is_empty() {
                ids.push((None, param.variadic));
            } else {
                ids.extend(param.ids.iter().map(|id| (Some(id), param.variadic)));
            }
        }

        for (index, (id, variadic)) in ids.into_iter().enumerate() {
            let Some(backtrace) = realized.as_ref().unwrap_or(component) else {
                result.push(None);

                continue 'components;
            };

            let concrete = if variadic {
                let children: Vec<_> = node.args[index..]
                    .iter()
                    .filter_map(|arg| exprs::visit_single_expr(ctx, arg))
                    .collect();

                LabelBacktrace::fold(
                    &children,
                    LabelBacktraceKind::FunctionVariadicAggregation,
                    id.map(Span::content),
                    ctx.pin(node.location.clone()),
                )
            } else {
                let arg = node.args.get(index).expect("already checked arg count");

                exprs::visit_single_expr(ctx, arg)
            };

            realized = Some(backtrace.realize(borrowed.func_ref(), index, concrete.as_ref()));
        }

        result.push(realized.unwrap_or_else(|| component.clone()));
    }

    result

    // TODO: test calling variadic fn, like `f(string, ...int)` with
    // `f("hello", 1, 2, 3)`
}

/// Already reports error if [`None`] is returned.
fn func_metadata_from_call_expr<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &ExprNode<'a>,
) -> Option<FunctionMetadataRef<'a>> {
    match node {
        ExprNode::Name(operand) => {
            if let Some(symbol) = exprs::resolve_operand_name(ctx, operand) {
                symbol.borrow().func_metadata()
            } else {
                None
            }
        }
        ExprNode::Literal(lit) => todo!(),
        ExprNode::Call(call) => todo!(),
        ExprNode::Indexing(indexing) => todo!(),
        ExprNode::UnaryOp { .. } | ExprNode::BinaryOp { .. } => None,
    }
}
