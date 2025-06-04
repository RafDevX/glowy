use parser::ast::{CallNode, FunctionDeclNode};

use crate::{
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{FunctionRef, Label, LabelBacktrace, LabelBacktraceKind, LabelTag},
    symbols::{FunctionMetadata, Symbol},
};

pub fn visit_function_decl<'a>(ctx: &mut AnalysisContext<'a>, node: &FunctionDeclNode<'a>) {
    let func_name = ctx.pin(node.name.clone());

    let symbol = Symbol::new_ref(func_name.clone(), false, None);

    ctx.declare_new_symbol(symbol);

    ctx.symtab_mut().select_first_child_scope(); // push

    let mut param_index = 0;

    for param in &node.signature.params {
        for id in &param.ids {
            if id.content() == "_" {
                // blank identifier, ignore
                param_index += 1;
                continue;
            }

            let synthetic = LabelTag::Synthetic {
                func: FunctionRef::Named(func_name.clone()),
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

    let func = FunctionMetadata::new_ref(&node.signature, None);
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

pub fn visit_call<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &CallNode<'a>,
) -> Option<LabelBacktrace<'a>> {
    todo!()

    // TODO: test calling variadic fn, like `f(string, ...int)` with
    // `f("hello", 1, 2, 3)`
}
