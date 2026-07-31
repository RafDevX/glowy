use std::{collections::BTreeMap, rc::Rc};

use parser::{
    Span,
    ast::{BlockNode, FunctionParamDeclNode, FunctionSignatureNode},
};

use crate::{
    Pinned,
    context::AnalysisContext,
    labels::{Label, LabelBacktrace, LabelBacktraceKind, LabelTag, SyntheticSlot},
    symbols::{QualifiedSymbolResolutionResult, Symbol, SymbolRef},
    taint::funcs::captures::{collector::CapturedSymbol, realization::CaptureEnvSnapshot},
    values::{CaptureBinding, FunctionRef, ValueRef},
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
    previous_captures: &[Pinned<'a, Span<'a>>],
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

    let mut captures: BTreeMap<_, (_, bool)> = BTreeMap::new();

    // recreate retained bindings so their local symbols still begin this pass
    // with fresh capture synthetics
    for &declaration in previous_captures {
        if let Some(symbol) = ctx.symtab().get_symbol_by_declaration(declaration) {
            insert_capture(&mut captures, declaration, symbol, false);
        }
    }

    for captured in referenced {
        let (symbol, bind_in_function_scope) = match captured {
            CapturedSymbol::Unqualified(name) => {
                let Some(symbol) = ctx.symtab().get_symbol_above_current_scope(name) else {
                    continue;
                };

                (symbol, true)
            }
            CapturedSymbol::Selection { base, selector } => {
                let symbol = if let Some(base_symbol) = ctx.symtab().get_symbol(base) {
                    let base_value = base_symbol.borrow().value().get();

                    let Some(base_type) = base_value.declared_type() else {
                        continue;
                    };

                    let Some(method) = base_type.lookup_promoted_method(selector) else {
                        // this is a field selection, not a method reference
                        continue;
                    };

                    method
                } else {
                    let QualifiedSymbolResolutionResult::Success(symbol) =
                        ctx.symtab().get_qualified_symbol(base, selector)
                    else {
                        continue;
                    };

                    symbol
                };

                (symbol, false)
            }
        };

        let borrowed = symbol.borrow();

        if borrowed.mutable() {
            let declaration = borrowed.declared_name();
            drop(borrowed);

            insert_capture(&mut captures, declaration, symbol, bind_in_function_scope);

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
                // relayed captures are not referenced lexically by this
                // function, so exposing them in its scope could shadow a local
                // declaration with the same name
                insert_capture(&mut captures, declaration, captured_symbol, false);
            }
        }
    }

    let value_location = value.location().clone();

    let Some(mut func) = value.as_function_mut() else {
        return;
    };

    for (outer_decl, (outer_symbol, bind_in_function_scope)) in captures {
        let iteration_cell = ctx.capture_iteration_cell(&outer_symbol);

        let captured_value = iteration_cell
            .as_ref()
            .unwrap_or(&outer_symbol)
            .borrow()
            .value()
            .get();

        let local_symbol = func.register_capture_with(
            outer_decl,
            bind_in_function_scope,
            iteration_cell,
            |index| {
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

                // mirror the outer's top-level shape so that
                // shape-discriminating operations inside the function body
                // (e.g., `m[k] = v`, `ch <- v`) see the correct shape and
                // employ the appropriate abstraction, instead of coercing into
                // an arbitrary default, but also retain the synthetic as the
                // sole backtrace
                let local_value = captured_value.copy_shape(capture_backtrace);

                Symbol::new_ref(outer_decl, true, local_value, None)
            },
        );

        if bind_in_function_scope {
            ctx.symtab_mut().declare_synthetic_symbol(local_symbol);
        }
    }
}

fn insert_capture<'a>(
    captures: &mut BTreeMap<Pinned<'a, Span<'a>>, (SymbolRef<'a>, bool)>,
    declaration: Pinned<'a, Span<'a>>,
    symbol: SymbolRef<'a>,
    bind_in_function_scope: bool,
) {
    captures
        .entry(declaration)
        .and_modify(|(_, existing_bind)| *existing_bind |= bind_in_function_scope)
        .or_insert((symbol, bind_in_function_scope));
}

pub fn resolve_accessed_capture<'a>(
    ctx: &AnalysisContext<'a>,
    symbol: &SymbolRef<'a>,
) -> SymbolRef<'a> {
    let borrowed = symbol.borrow();

    if !borrowed.mutable() {
        return Rc::clone(symbol);
    }

    let declaration = borrowed.declared_name();
    drop(borrowed);

    resolve_capture_symbol(ctx, declaration)
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
        let Some(outer_symbol) = lookup_capture_definition_symbol(ctx, outer_decl, binding) else {
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

fn lookup_capture_definition_symbol<'a>(
    ctx: &AnalysisContext<'a>,
    outer_decl: Pinned<'a, Span<'a>>,
    binding: &CaptureBinding<'a>,
) -> Option<SymbolRef<'a>> {
    binding
        .iteration_cell()
        .cloned()
        .or_else(|| ctx.symtab().get_symbol_by_declaration(outer_decl))
}

fn resolve_capture_runtime_symbol<'a>(
    ctx: &AnalysisContext<'a>,
    outer_decl: Pinned<'a, Span<'a>>,
    binding: &CaptureBinding<'a>,
) -> SymbolRef<'a> {
    if let Some(iteration_cell) = binding.iteration_cell() {
        return Rc::clone(iteration_cell);
    }

    // an ordinary capture may be relayed through an active enclosing closure,
    // so its synthetic local must receive the write to allow the enclosing call
    // to realize its placeholders before propagating the value any further
    resolve_capture_symbol(ctx, outer_decl)
}
