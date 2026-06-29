use std::borrow::Cow;

use parser::{
    Span,
    ast::{ExprNode, TypeAssertionNode, UnaryOpKind},
};

use super::{channels, funcs};
use crate::{
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{LabelBacktrace, LabelBacktraceKind},
    symbols::{QualifiedSymbolResolutionResult, SymbolRef},
    values::{ExpandableValue, PackageRefValue, SelfAwareBacktraceContainer, Value, ValueRef},
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

    let Some(symbol) = resolve_operand_name(ctx, name, qualifier) else {
        // error already reported
        return ValueRef::new_bottom(location, None);
    };

    symbol
        .borrow()
        .value()
        .get()
        .nest_backtrace(
            LabelBacktraceKind::Expression,
            Some(name.content()),
            location.clone(),
            [],
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
                // do not actually have the source, so we just return None now
                // without actually reporting any error

                return None;
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

fn visit_type_assertion<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &TypeAssertionNode<'a>,
) -> ValueRef<'a> {
    let value = visit_single_expr(ctx, &node.expr)
        .into_with_declared_type(ctx.types().resolve(ctx.symtab(), &node.r#type));

    let location = ctx.pin(node.location.clone());

    // a type assertion is expandable into 2 values: the first is just the value
    // itself (assuming the assertion is true), and the second is a boolean
    // indicating whether the assertion succeeded (essentially the same value
    // but downgraded to simplest shape to remove any complexity)
    let secondary = value.downgrade(|| location.clone());

    let expandable = ExpandableValue::new(value, vec![secondary]);

    ValueRef::new(Value::Expandable(expandable), location, None)
}
