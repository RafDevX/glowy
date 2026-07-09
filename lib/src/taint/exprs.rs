use std::borrow::Cow;

use parser::{
    Location, Span,
    ast::{
        AmbiguousBracketAccessNode, ExprNode, TypeAssertionNode, TypeInstantiationNode, UnaryOpKind,
    },
};

use super::{channels, funcs};
use crate::{
    Pinned,
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{Label, LabelBacktrace, LabelBacktraceKind},
    policy::{BlanketDirective, BlanketDirectiveKind},
    symbols::{QualifiedSymbolResolutionResult, Symbol, SymbolRef},
    values::{
        ExpandableValue, FunctionValue, PackageRefValue, SelfAwareBacktraceContainer, Value,
        ValueRef,
    },
};

mod component;
mod literals;

pub use component::visit_selection_with_base;

pub fn visit_expr<'a>(ctx: &mut AnalysisContext<'a>, node: &ExprNode<'a>) -> Vec<ValueRef<'a>> {
    let single = match node {
        ExprNode::Name(name) => visit_operand_name(ctx, *name, None),
        ExprNode::Literal(lit) => literals::visit_literal(ctx, lit),
        ExprNode::Call(call) => return funcs::visit_call(ctx, call),
        ExprNode::Make(make) => funcs::builtins::visit_make(ctx, make),
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
            left,
            right,
            location,
            ..
        } => {
            let left = get_expr_backtrace(ctx, left);
            let right = get_expr_backtrace(ctx, right);

            let backtrace = LabelBacktrace::combine_options(
                left,
                right,
                LabelBacktraceKind::Expression,
                Cow::Owned(ctx.pin(location.clone())),
            );

            ValueRef::from_backtrace_or_bottom_at(backtrace, || ctx.pin(location.clone()))
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

pub fn visit_multi_exprs<'a>(
    ctx: &mut AnalysisContext<'a>,
    nodes: &[ExprNode<'a>],
) -> Vec<ValueRef<'a>> {
    if let [single] = nodes {
        // only one expression, which might end up being:
        // - a function call returning multiple values, e.g. `x, y := f()`; or
        // - just a normal expression, corresponding to a single value, but in that case
        //   visit_expr will wrap it in a vec so we're all good

        visit_expr(ctx, single)
    } else {
        // single multiple expressions were provided, we know for sure that each
        // of them must yield a single value

        nodes
            .iter()
            .map(|expr| visit_single_expr(ctx, expr))
            .collect()
    }
}

pub fn get_expr_backtrace<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &ExprNode<'a>,
) -> Option<LabelBacktrace<'a>> {
    visit_single_expr(ctx, node).backtrace()
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

    let value = if let Some(symbol) = resolve_operand_name(ctx, name, qualifier) {
        symbol.borrow().value().get()
    } else {
        // error already reported
        ValueRef::new_bottom(location.clone(), None)
    };

    // embed any potential blanket source backtrace if there are any Source
    // blanket directives targeting this symbol (propagates the backtrace in
    // question for both functions like `os.Getenv` and non-function targets
    // such as `os.Args` and `os.Stdin` which are read directly / never called)
    let blanket_source_bt = build_blanket_source_backtrace(ctx, name, qualifier, &location);

    value
        .nest_backtrace(
            LabelBacktraceKind::Expression,
            Some(name.content()),
            location.clone(),
            blanket_source_bt,
        )
        .with_location(location)
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
            QualifiedSymbolResolutionResult::Success(symbol) => Some(symbol),
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
                return synthesize_fake_symbol_with_blanket_sinks(ctx, name, qualifier);
            }
            QualifiedSymbolResolutionResult::UnknownQualifier => {
                ctx.report_error(AnalysisErrorKind::UnknownQualifier { found: qualifier });

                return None;
            }
        }
    } else {
        ctx.symtab().get_symbol(name.content())
    };

    if symbol.is_none() {
        // symbol not found -- report error
        ctx.report_error(AnalysisErrorKind::UnknownSymbol { found: name });
    }

    symbol
}

fn synthesize_fake_symbol_with_blanket_sinks<'a>(
    ctx: &AnalysisContext<'a>,
    name: Span<'a>,
    qualifier: Span<'a>,
) -> Option<SymbolRef<'a>> {
    let package_path = ctx
        .symtab()
        .package_path_for_qualifier(qualifier.content())?;

    // we pass type_name = None because this could never be a method access
    let directives = ctx.blanket_directives_for(package_path, None, name.content());

    // don't want to upgrade to a FunctionValue for no reason, source directives
    // allow non-functions (e.g., `os.Args` or `os.Stdin`)
    let has_sinks = directives.iter().any(|directive| {
        matches!(
            directive.kind(),
            BlanketDirectiveKind::AllowSink | BlanketDirectiveKind::DenySink,
        )
    });

    if !has_sinks {
        // no configured sink blanket directives for this blackbox symbol, so
        // there is no reason to lie, thus we really do tell the invoker that
        // symbol resolution failed
        return None;
    }

    let mut func_val = FunctionValue::new_unknown(None, false);

    func_val.absorb_blanket_sinks(directives);

    let location = ctx.pin(name.location());
    let value = ValueRef::new(Value::Function(Box::new(func_val)), location, None);

    Some(Symbol::new_ref(ctx.pin(name), false, value))
}

fn build_blanket_source_backtrace<'a>(
    ctx: &AnalysisContext<'a>,
    name: Span<'a>,
    qualifier: Option<Span<'a>>,
    at_location: &Pinned<'a, Location>,
) -> Option<LabelBacktrace<'a>> {
    let package_path = if let Some(qualifier) = qualifier {
        ctx.symtab()
            .package_path_for_qualifier(qualifier.content())?
    } else {
        // FIXME: if current package doesn't have this symbol, pick the first
        // wildcard import that has it; ignore universe scope

        ctx.symtab().current_package_path()?
    };

    // we pass type_name = None because this could never be a method access
    let blanket_label: Label<'_> = ctx
        .blanket_directives_for(package_path, None, name.content())
        .iter()
        .filter(|directive| directive.kind() == BlanketDirectiveKind::Source)
        .map(BlanketDirective::label)
        .sum();

    if blanket_label.is_bottom() {
        // prevent location cloning below
        return None;
    }

    LabelBacktrace::new_root(
        LabelBacktraceKind::BlanketSource,
        blanket_label,
        None,
        at_location.clone(),
    )
}

fn visit_type_assertion<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &TypeAssertionNode<'a>,
) -> ValueRef<'a> {
    let declared_type = {
        let (types, symtab) = ctx.types_mut_with_symtab();

        types.resolve(symtab, &node.r#type)
    };

    let value = visit_single_expr(ctx, &node.expr).into_with_declared_type(declared_type);

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
    let is_type_known = {
        let (types, symtab) = ctx.types_mut_with_symtab();

        types
            .resolve(symtab, &node.type_arg_if_instantiation)
            .is_some()
    };

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

    component::visit_indexing_with(ctx, &base, &node.index_if_indexing, &node.location)
}
