use parser::{
    Span,
    ast::{BlockNode, FunctionParamDeclNode, FunctionSignatureNode},
};

use crate::{
    context::AnalysisContext,
    labels::{Label, LabelBacktrace, LabelBacktraceKind, LabelTag, SyntheticSlot},
    symbols::Symbol,
    taint::funcs::captures::realization::CaptureEnvSnapshot,
    values::{FunctionRef, ValueRef},
};

pub mod call_site;
mod collector;
pub mod realization;

pub fn register_closure_captures<'a>(
    ctx: &mut AnalysisContext<'a>,
    r#ref: &FunctionRef<'a>,
    signature: &FunctionSignatureNode<'a>,
    receiver: Option<&FunctionParamDeclNode<'a>>,
    body: &BlockNode<'a>,
    value: &mut ValueRef<'a>,
) {
    let FunctionRef::Anonymous(closure_location) = r#ref else {
        return;
    };

    let mut captures: Vec<_> = collector::collect_captured_symbols(signature, receiver, body)
        .into_iter()
        .collect();

    captures.sort_unstable();

    for capture in captures {
        let Some(symbol) = ctx.symtab().get_symbol_above_current_scope(capture) else {
            continue;
        };

        let (outer_decl, outer_value) = {
            let borrowed = symbol.borrow();

            if !borrowed.mutable() {
                // we don't need to worry about immutable symbols because their
                // value will remain constant forever, meaning that it's fine to
                // evaluate them within the function definition and we will
                // never be able to overwrite them from within the closure
                continue;
            }

            (borrowed.declared_name(), borrowed.value())
        };

        let Some(mut func) = value.as_function_mut() else {
            continue;
        };

        // Span offset matters: we cannot hardcode to 0 or anything else because
        // otherwise any other captures with the same name registered for other
        // closures in the chain would clash (would have the same key)
        let local_decl = ctx.pin(Span::new(capture, closure_location.inner().start, 1));

        let index = func.register_capture(outer_decl, local_decl);

        drop(func);

        let synthetic = LabelTag::Synthetic {
            func: r#ref.clone(),
            slot: SyntheticSlot::Capture(index),
            identifier: Some(*local_decl.inner()),
        };

        let capture_backtrace = LabelBacktrace::new_root(
            LabelBacktraceKind::ClosureCapture,
            Label::from_single(synthetic),
            Some(capture),
            value.location().clone(),
        )
        .unwrap(); // safe because we know label is not Bottom

        // mirror the outer's top-level shape so that shape-discriminating
        // operations inside the closure body (e.g. `m[k] = v`, `ch <- v`,
        // `delete(m, k)`) see the correct shape instead of coercing into an
        // arbitrary default, but retain the synthetic as the sole backtrace
        let local_value = outer_value.get().copy_shape(capture_backtrace);

        ctx.declare_new_symbol(Symbol::new_ref(local_decl, true, local_value, None));
    }
}

pub fn record_closure_capture_fallbacks<'a>(ctx: &AnalysisContext<'a>, value: &mut ValueRef<'a>) {
    let Some(mut func) = value.as_function_mut() else {
        return;
    };

    for (outer_decl, binding) in func.captures_mut() {
        let Some(outer_symbol) = ctx.symtab().get_symbol_by_declaration(outer_decl) else {
            continue;
        };

        let hybrid = realization::derive_hybrid_symbol_backtrace(
            ctx,
            &outer_symbol,
            &CaptureEnvSnapshot::empty(), // no overrides
        );

        binding.set_hybrid_fallback(hybrid);
    }
}
