use std::collections::BTreeMap;

use parser::{
    Span,
    ast::{BlockNode, FunctionParamDeclNode, FunctionSignatureNode},
};

use crate::{
    Pinned,
    context::AnalysisContext,
    labels::{Label, LabelBacktrace, LabelBacktraceKind, LabelTag, SyntheticSlot},
    symbols::{Symbol, SymbolRef},
    taint::funcs::captures::realization::CaptureEnvSnapshot,
    values::{FunctionRef, ValueRef},
};

pub mod call_site;
mod collector;
pub mod realization;

// both for actual closure captures and for global variables in named functions
pub fn register_captures<'a>(
    ctx: &mut AnalysisContext<'a>,
    r#ref: &FunctionRef<'a>,
    signature: &FunctionSignatureNode<'a>,
    receiver: Option<&FunctionParamDeclNode<'a>>,
    body: &BlockNode<'a>,
    value: &mut ValueRef<'a>,
) {
    if r#ref.is_main() {
        // main executes directly rather than through call application, so its
        // writes must update package state immediately. init bodies bypass this
        // function altogether, so they are not contemplated here
        return;
    }

    let mut referenced: Vec<_> = collector::collect_captured_symbols(signature, receiver, body)
        .into_iter()
        .collect();

    referenced.sort_unstable();

    let mut captures = BTreeMap::new();

    for name in referenced {
        let Some(symbol) = ctx.symtab().get_symbol_above_current_scope(name) else {
            continue;
        };

        let borrowed = symbol.borrow();

        if borrowed.mutable() {
            let declaration = borrowed.declared_name();
            drop(borrowed);

            captures.insert(declaration, symbol);

            continue;
        }

        // if we got this far, this is an immutable symbol referenced by the
        // function body. other named functions' declarations are immutable,
        // so check if this is one (gating on is_function to prevent upgrade,
        // since that would lead to any Simple becoming a Blackbox function)
        let symbol_value = borrowed.value().get();

        if !symbol_value.is_function() {
            // we are only interested in named functions
            continue;
        }

        let Some(symbol_func) = symbol_value.as_function() else {
            continue;
        };

        // if this was a function, pull its own captures into this function so
        // that global mutations can survive relay calls
        for (declaration, _) in symbol_func.captures() {
            if let Some(captured_symbol) = ctx.symtab().get_symbol_by_declaration(declaration) {
                captures.insert(declaration, captured_symbol);
            }
        }
    }

    let value_location = value.location().clone();

    let Some(mut func) = value.as_function_mut() else {
        return;
    };

    for (outer_decl, outer_symbol) in captures {
        let outer_value = outer_symbol.borrow().value();

        let local_symbol = func.register_capture_with(outer_decl, |index| {
            let synthetic = LabelTag::Synthetic {
                func: r#ref.clone(),
                slot: SyntheticSlot::Capture(index),
                identifier: Some(*outer_decl.inner()),
            };

            let capture_backtrace = LabelBacktrace::new_root(
                LabelBacktraceKind::ClosureCapture,
                Label::from_single(synthetic),
                Some(outer_decl.content()),
                value_location.clone(),
            )
            .unwrap(); // safe because we know label is not Bottom

            // mirror he outer's top-level shape so that shape-discriminating
            // operations inside the function body (e.g., `m[k] = v`, `ch <- v`)
            // see the correct shape and employ the appropriate abstraction,
            // instead of coercing into an arbitrary default, but retain the
            // synthetic as the sole backtrace
            let local_value = outer_value.get().copy_shape(capture_backtrace);

            Symbol::new_ref(outer_decl, true, local_value, None)
        });

        ctx.symtab_mut().declare_synthetic_symbol(local_symbol);
    }
}

pub fn resolve_capture_symbol<'a>(
    ctx: &AnalysisContext<'a>,
    outer_decl: Pinned<'a, Span<'a>>,
) -> SymbolRef<'a> {
    // first consider the case of chained captures and find the next level up
    if let Some(local_symbol) = ctx.active_functions().find_map(|value| {
        let function = value.as_function()?;

        function.captures().find_map(|(candidate, binding)| {
            if candidate == outer_decl {
                Some(binding.local_symbol())
            } else {
                None
            }
        })
    }) {
        return local_symbol;
    }

    // since we didn't find any match in the function stack, then the target
    // symbol is a real one, and we need to query the symtab
    ctx.symtab()
        .get_symbol_by_declaration(outer_decl)
        .expect("a captured symbol must remain registered")
}

pub fn record_capture_fallbacks<'a>(ctx: &AnalysisContext<'a>, value: &mut ValueRef<'a>) {
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
