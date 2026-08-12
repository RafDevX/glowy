use std::borrow::Cow;

use glowy_go_parser::{
    Location, Span,
    ast::{
        AmbiguousBracketAccessNode, ExprNode, MakeNode, TypeAssertionNode, TypeInstantiationNode,
        UnaryOpKind,
    },
};

use super::{channels, funcs};
use crate::{
    Pinned,
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{Label, LabelBacktrace, LabelBacktraceKind},
    policy::{self, BlanketDirective, BlanketDirectiveKind},
    symbols::{QualifiedSymbolResolutionResult, Symbol, SymbolRef},
    taint::types,
    values::{
        ExpandableValue, FunctionValue, PackageRefValue, SelfAwareBacktraceContainer,
        SimpleConstValue, Value, ValueRef,
    },
};

mod component;
mod literals;

pub use component::{visit_selection_with_base, visit_slicing_with_base};

pub fn visit_expr<'a>(ctx: &mut AnalysisContext<'a>, node: &ExprNode<'a>) -> Vec<ValueRef<'a>> {
    let single = match node {
        ExprNode::Name(name) => visit_operand_name(ctx, *name, None),
        ExprNode::Literal(lit) => literals::visit_literal(ctx, lit),
        ExprNode::Call(call) => return funcs::visit_call(ctx, call),
        ExprNode::Make(make) => visit_make_with_revocations(ctx, make),
        ExprNode::New(new) => funcs::builtins::visit_new(ctx, new),
        ExprNode::Selection(selection) => component::visit_selection(ctx, selection),
        ExprNode::Indexing(indexing) => component::visit_indexing(ctx, indexing),
        ExprNode::Slicing(slicing) => component::visit_slicing(ctx, slicing),
        ExprNode::Conversion(conversion) => visit_single_expr(ctx, &conversion.expr),
        ExprNode::TypeAssertion(assertion) => visit_type_assertion(ctx, assertion),
        ExprNode::TypeInstantiation(instantiation) => {
            // we don't do anything with these type args, so just visit the base

            visit_single_expr(ctx, &instantiation.base)
                .with_location(ctx.pin(instantiation.location.clone()))
        }
        ExprNode::AmbiguousBracketAccess(ambiguous) => {
            visit_ambiguous_bracket_access(ctx, ambiguous)
        }
        ExprNode::UnaryOp {
            kind: UnaryOpKind::Receive,
            operand,
            location,
        } => channels::visit_receive(ctx, operand, location),
        ExprNode::UnaryOp { operand, .. } => visit_single_expr(ctx, operand),
        ExprNode::BinaryOp {
            kind,
            left,
            right,
            location,
        } => {
            let pinned = ctx.pin(location.clone());

            let (left, left_const) = get_expr_backtrace_and_const(ctx, left);

            let short_circuit_backtrace = left
                .as_ref()
                .filter(|_| kind.short_circuits())
                .cloned()
                .map(|implicit| {
                    implicit.into_single_child(
                        LabelBacktraceKind::ShortCircuit,
                        None,
                        pinned.clone(),
                    )
                });

            let short_circuits = if let Some(backtrace) = short_circuit_backtrace {
                // only when the left operand of a logical operation fails at
                // short-circuiting is the right operand evaluated, so we need
                // to make sure any side-effects caused by the latter take into
                // account the calculated backtrace of the former
                ctx.push_branch_backtrace(backtrace);

                true
            } else {
                false
            };

            // now we can evaluate right
            let (mut right, right_const) = get_expr_backtrace_and_const(ctx, right);

            if short_circuits {
                ctx.pop_branch_backtrace();

                if let Some(raw) = right {
                    // we use `left` instead of `short_circuit_backtrace`
                    // because the latter would cause an extra level of
                    // backtrace, for a total of two ShortCircuit kinds

                    right = Some(raw.union(
                        left.as_ref().unwrap(),
                        LabelBacktraceKind::ShortCircuit,
                        pinned.clone(),
                    ));
                }
            }

            let backtrace = LabelBacktrace::combine_options(
                left,
                right,
                LabelBacktraceKind::Expression,
                Cow::Borrowed(&pinned),
            );

            let mut result = ValueRef::from_backtrace_or_bottom_at(backtrace, || pinned);

            if let Some((name, _)) = policy::OPERATOR_TARGET_NAMES
                .iter()
                .find(|(_, target_kind)| target_kind == kind)
            {
                funcs::apply_operator_blanket_revocations(
                    ctx,
                    name,
                    &[left_const, right_const],
                    &mut result,
                );
            }

            result
        }
    };

    vec![single]
}

pub fn visit_single_expr<'a>(ctx: &mut AnalysisContext<'a>, node: &ExprNode<'a>) -> ValueRef<'a> {
    let mut result = visit_expr(ctx, node);

    if result.is_empty() {
        ctx.report_error(AnalysisErrorKind::UnexpectedVoidExpression {
            location: node.location().into_owned(),
        });
    } else if result.len() > 1 {
        ctx.report_error(AnalysisErrorKind::UnexpectedMultiValueExpression {
            location: node.location().into_owned(),
        });
    } else {
        let value = result.pop().unwrap(); // already checked

        // collapse into single value, if Möbius/expandable
        return value.extract_collapsed_single();
    }

    ValueRef::new_bottom(ctx.pin(node.location().into_owned()), None)
}

pub fn visit_multi_exprs_with_consts<'a>(
    ctx: &mut AnalysisContext<'a>,
    nodes: &[ExprNode<'a>],
) -> Vec<(ValueRef<'a>, Option<SimpleConstValue>)> {
    if let [single] = nodes {
        // only one expression, which might end up being:
        // - a function call returning multiple values, e.g. `x, y := f()`; or
        // - just a normal expression, corresponding to a single value, but in that case
        //   visit_expr will wrap it in a vec so we're all good

        let known_const = try_resolve_simple_const(ctx, single);
        let mut values = visit_expr(ctx, single);

        if values.len() == 1 {
            vec![(values.pop().unwrap(), known_const)]
        } else {
            // known_const is not actually valid since we're returning >1 value
            values.into_iter().map(|value| (value, None)).collect()
        }
    } else {
        // single multiple expressions were provided, we know for sure that each
        // of them must yield a single value

        nodes
            .iter()
            .map(|expr| {
                // resolve before visiting so each expression observes the
                // symbol state at its own point in Go's evaluation order
                let known_const = try_resolve_simple_const(ctx, expr);
                let value = visit_single_expr(ctx, expr);

                (value, known_const)
            })
            .collect()
    }
}

pub fn get_expr_backtrace<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &ExprNode<'a>,
) -> Option<LabelBacktrace<'a>> {
    visit_single_expr(ctx, node).backtrace()
}

pub fn get_expr_backtrace_and_const<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &ExprNode<'a>,
) -> (Option<LabelBacktrace<'a>>, Option<SimpleConstValue>) {
    // resolve before visiting so that the expression observes the symbol state
    // at its own point in Go's defined evaluation order
    let known_const = try_resolve_simple_const(ctx, node);
    let backtrace = get_expr_backtrace(ctx, node);

    (backtrace, known_const)
}

pub fn get_expr_backtrace_and_untainted_const<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &ExprNode<'a>,
) -> (Option<LabelBacktrace<'a>>, Option<SimpleConstValue>) {
    // we cannot conditionally resolve known_const based on backtrace since we
    // need const resolution to happen before the expr has been visited,
    // otherwise we would take into account the symbol state at an incorrect
    // point in Go's defined evaluation order

    let (backtrace, known_const) = get_expr_backtrace_and_const(ctx, node);

    // even if a const value was resolvable, in many cases we do not want to use
    // it, since a labeled value may have been initialized from a literal and
    // its calculated label is important run-time information not present in the
    // resolved known_const, only carried by backtrace, so we cannot mislead
    // taint propagation in places where it matters (e.g., composite reads)
    let known_const = backtrace.is_none().then_some(known_const).flatten();

    (backtrace, known_const)
}

pub fn try_resolve_simple_const(
    ctx: &AnalysisContext<'_>,
    node: &ExprNode<'_>,
) -> Option<SimpleConstValue> {
    SimpleConstValue::try_resolve_from_expr_with_names(node, &|name| {
        let symbol = ctx.symtab().get_symbol(name)?;

        symbol.borrow().known_const().cloned()
    })
}

pub fn visit_operand_name<'a>(
    ctx: &mut AnalysisContext<'a>,
    name: Span<'a>,
    qualifier: Option<Span<'a>>,
) -> ValueRef<'a> {
    let location = ctx.pin(name.location());

    // a declared identifier in scope shadows an imported package qualifier of
    // the same name, so we *must* check for a symbol before committing to a
    // PackageRefValue (even if a bit costly) -- we do this lookup through
    // `get_symbol` directly to avoid incorrectly surfacing any UnknownSymbol
    // errors when we know there is a valid qualifier, as `resolve_operand_name`
    // would, and that latter method is used instead only for unknown qualifiers
    if qualifier.is_none()
        && ctx.symtab().qualifier_exists(name.content())
        && ctx.symtab().get_symbol(name.content()).is_none()
    {
        return ValueRef::new(
            Value::PackageRef(PackageRefValue::new(name)),
            location,
            None,
        );
    }

    let symbol = resolve_operand_name(ctx, name, qualifier);

    visit_operand_name_with_symbol(ctx, name, qualifier, symbol.as_ref())
}

pub fn visit_resolved_unqualified_operand_name<'a>(
    ctx: &mut AnalysisContext<'a>,
    name: Span<'a>,
    symbol: &SymbolRef<'a>,
) -> ValueRef<'a> {
    visit_operand_name_with_symbol(ctx, name, None, Some(symbol))
}

fn visit_operand_name_with_symbol<'a>(
    ctx: &mut AnalysisContext<'a>,
    name: Span<'a>,
    qualifier: Option<Span<'a>>,
    symbol: Option<&SymbolRef<'a>>,
) -> ValueRef<'a> {
    let location = ctx.pin(name.location());

    let value = if let Some(symbol) = symbol {
        symbol.borrow().value().get()
    } else {
        // error already reported
        ValueRef::new_bottom(location.clone(), None)
    };

    let blanket_directives = blanket_directives_for_operand(ctx, name, qualifier, symbol);

    // embed any potential blanket source backtrace if there are any Source
    // blanket directives targeting this symbol (propagates the backtrace in
    // question for both functions like `os.Getenv` and non-function targets
    // such as `os.Args` and `os.Stdin` which are read directly / never called)
    let blanket_source_bt = build_blanket_source_backtrace(blanket_directives, &location);
    // calculate blanket revocation label
    let blanket_revocation = build_blanket_revocation_label(blanket_directives);

    let mut value = value
        .nest_backtrace(
            LabelBacktraceKind::Expression,
            Some(name.content()),
            location.clone(),
            blanket_source_bt,
        )
        .with_location(location);

    if value.is_function()
        && let Some(mut function) = value.as_function_mut()
    {
        // unlike declared functions, predeclared (= builtin) functions have no
        // declaration visit step during which they can absorb call-level
        // blanket directives, so we have to fold directives into the accessed
        // copy here. however, despite this being necessary for predeclared
        // functions, there is no harm in doing this for all functions since
        // additions are deduplicated, keeping this simple and uniform
        function.absorb_blanket_directives(blanket_directives);
    }

    value.and_subtract_label(&blanket_revocation)
}

/// Reports error for unknown symbol or unknown qualifier, if applicable.
pub fn resolve_operand_name<'a>(
    ctx: &mut AnalysisContext<'a>,
    name: Span<'a>,
    qualifier: Option<Span<'a>>,
) -> Option<SymbolRef<'a>> {
    let symbol = if let Some(qualifier) = qualifier {
        match ctx
            .symtab()
            .get_qualified_symbol(qualifier.content(), name.content())
        {
            QualifiedSymbolResolutionResult::Success(symbol) => {
                Some(funcs::resolve_accessed_capture(ctx, &symbol))
            }
            QualifiedSymbolResolutionResult::UnknownSymbol => None,
            QualifiedSymbolResolutionResult::PendingAnalysis => {
                // this is likely the accessing of blackbox package for which we
                // do not actually have the source, so we should just return
                // None now without actually reporting any error
                // (it might be another package within the same module that we
                // will get the chance of analyzing later, but for now that
                // warrants the same treatment as any other blackbox package)

                // however, there is a chance that this symbol is associated
                // with blanket directives registered to the analyzer, in which
                // case we pretend the symbol resolution was successful and we
                // return a fake Symbol, synthesized now on the fly with no
                // information besides what can be derived from the associated
                // blanket directives, so that their details can be propagated
                return synthesize_fake_symbol_with_blanket_directives(ctx, name, qualifier);
            }
            QualifiedSymbolResolutionResult::UnknownQualifier => {
                ctx.report_error(AnalysisErrorKind::UnknownQualifier { found: qualifier });

                return None;
            }
        }
    } else {
        ctx.symtab().get_symbol(name.content())
    };

    if symbol.is_none()
        && qualifier.is_none()
        && ctx
            .symtab()
            .may_resolve_from_unavailable_wildcard_import(name.content())
    {
        // if this could possibly be an unqualified access to a wildcard import
        // of a package not under analysis, we synthesize a fake symbol to
        // represent it instead of emitting an unknown symbol error (which would
        // frequently be a false positive, because of wildcard imports, as we
        // assume input programs are valid Go programs that compile)

        let pinned = ctx.pin(name);
        let value = ValueRef::new(Value::Simple(None), pinned.pinned_location(), None);

        return Some(Symbol::new_ref(pinned, false, value, None));
    }

    if symbol.is_none() {
        // symbol not found -- report error
        ctx.report_error(AnalysisErrorKind::UnknownSymbol { found: name });
    }

    symbol
}

fn synthesize_fake_symbol_with_blanket_directives<'a>(
    ctx: &AnalysisContext<'a>,
    name: Span<'a>,
    qualifier: Span<'a>,
) -> Option<SymbolRef<'a>> {
    let package_path = ctx
        .symtab()
        .package_path_for_qualifier(qualifier.content())?;

    // we pass type_name = None because this could never be a method access
    let directives = ctx.blanket_directives_for(package_path, None, name.content());

    // don't want to upgrade to a FunctionValue for no reason; unconditional
    // source directives allow non-functions (e.g., `os.Args` or `os.Stdin`)
    let has_callable_directives = directives.iter().any(|directive| {
        matches!(
            directive.kind(),
            BlanketDirectiveKind::Revocation
                | BlanketDirectiveKind::AllowSink
                | BlanketDirectiveKind::DenySink,
        ) || directive.should_resolve_at_call_time() // e.g. if conditional
    });

    if !has_callable_directives {
        // no configured call-level blanket directives for this blackbox symbol,
        // so there is no reason to lie, thus we really do tell the invoker
        // that symbol resolution failed
        return None;
    }

    let mut func_val = FunctionValue::new_unknown(None, false);

    func_val.absorb_blanket_directives(directives);

    let location = ctx.pin(name.location());
    let value = ValueRef::new(Value::Function(Box::new(func_val)), location, None);

    Some(Symbol::new_ref(ctx.pin(name), false, value, None))
}

fn blanket_directives_for_operand<'a>(
    ctx: &AnalysisContext<'a>,
    name: Span<'a>,
    qualifier: Option<Span<'a>>,
    resolved_symbol: Option<&SymbolRef<'a>>,
) -> &'a [BlanketDirective] {
    let package_path = if let Some(qualifier) = qualifier {
        ctx.symtab()
            .package_path_for_qualifier(qualifier.content())
            .map(String::as_str)
    } else if ctx.symtab().resolves_to_predeclared(name.content()) {
        Some(policy::BUILTIN_PACKAGE_PATH)
    } else if let Some(symbol) = resolved_symbol {
        ctx.symtab()
            .package_path_for_unqualified_symbol(name.content(), symbol)
            .map(String::as_str)
    } else {
        None
    };

    let Some(package_path) = package_path else {
        return &[];
    };

    // we pass type_name = None because this could never be a method access
    ctx.blanket_directives_for(package_path, None, name.content())
}

fn build_blanket_source_backtrace<'a>(
    directives: &'a [BlanketDirective],
    at_location: &Pinned<'a, Location>,
) -> Option<LabelBacktrace<'a>> {
    let blanket_label: Label<'_> = directives
        .iter()
        .filter(|directive| {
            // only unconditional blanket sources matter here
            directive.kind() == BlanketDirectiveKind::Source
                && !directive.should_resolve_at_call_time()
        })
        .map(BlanketDirective::label)
        .sum();

    if blanket_label.is_bottom() {
        // prevent cloning location below if unnecessary
        return None;
    }

    LabelBacktrace::new_root(
        LabelBacktraceKind::BlanketSource,
        blanket_label,
        None,
        at_location.clone(),
    )
}

fn build_blanket_revocation_label(directives: &[BlanketDirective]) -> Label<'_> {
    directives
        .iter()
        .filter(|directive| {
            // only unconditional blanket revocations matter here
            directive.kind() == BlanketDirectiveKind::Revocation
                && !directive.should_resolve_at_call_time()
        })
        .map(BlanketDirective::label)
        .sum()
}

fn visit_make_with_revocations<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &MakeNode<'a>,
) -> ValueRef<'a> {
    let n_args = 1 + usize::from(node.n.is_some()) + usize::from(node.m.is_some());
    let mut arg_consts = vec![None; n_args];

    let mut result = funcs::builtins::visit_make(ctx, node, &mut arg_consts);

    if !ctx.symtab().resolves_to_predeclared("make") {
        // just in case any any user shadow exists
        return result;
    }

    funcs::apply_predeclared_blanket_revocations(
        ctx,
        "make",
        &arg_consts,
        std::slice::from_mut(&mut result),
    );

    result
}

fn visit_type_assertion<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &TypeAssertionNode<'a>,
) -> ValueRef<'a> {
    let base = visit_single_expr(ctx, &node.expr);

    visit_type_assertion_with_base(ctx, node, &base)
}

pub fn visit_type_assertion_with_base<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &TypeAssertionNode<'a>,
    base: &ValueRef<'a>,
) -> ValueRef<'a> {
    let declared_type = {
        let (types, symtab) = ctx.types_mut_with_symtab();

        types.resolve(symtab, &node.r#type)
    };

    let value = base.clone().into_with_declared_type(declared_type);

    let location = ctx.pin(node.location.clone());

    // a type assertion is expandable into 2 values: the first is just the value
    // itself (assuming the assertion is true), and the second is a boolean
    // indicating whether the assertion succeeded (essentially the same value
    // but downgraded to simplest shape to remove any complexity)
    let secondary = value.downgrade(|| location.clone());

    let expandable = ExpandableValue::new(value, vec![secondary]);

    ValueRef::new(Value::Expandable(expandable), location, None)
}

fn visit_ambiguous_bracket_access<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &AmbiguousBracketAccessNode<'a>,
) -> ValueRef<'a> {
    let is_type_known = types::is_known_type(ctx, &node.type_arg_if_instantiation);

    if is_type_known {
        // if the type is known here, it's a type instantiation
        return visit_single_expr(ctx, &TypeInstantiationNode::from(node.clone()).into());
    }

    let base = visit_single_expr(ctx, &node.base);

    if base.is_function() {
        // functions cannot be indexed, so it has to be a type instantiation
        // (we replicate the visitor implementation here since it's so simple,
        // and re-creating a TypeInstantiationNode for this visit would lead to
        // the base being visited multiple times; bad for e.g. side-effects)

        return base.with_location(ctx.pin(node.location.clone()));
    }

    // if we got here, we assume it's an indexing expression, but we cannot
    // convert our node into an IndexingNode since it'd lead to base being
    // visited multiple times (which would be bad for, e.g., side-effects)

    component::visit_indexing_with_base(
        ctx,
        &base,
        &node.base,
        &node.index_if_indexing,
        &node.location,
    )
}
