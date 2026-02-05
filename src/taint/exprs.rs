use parser::{
    Location, Span,
    ast::{ExprNode, LiteralNode, TypeAssertionNode, UnaryOpKind},
};

use super::{channels, funcs};
use crate::{
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{LabelBacktrace, LabelBacktraceKind},
    symbols::SymbolRef,
    values::{
        BacktraceContainer, ExpandableValue, PackageRefValue, SelfAwareBacktraceContainer, Value,
        ValueRef,
    },
};

mod component;
mod literals;

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
            let left_location = ctx.pin(get_expr_location(left));
            let right_location = ctx.pin(get_expr_location(right));

            let left = visit_single_expr(ctx, left).backtrace_at_location(left_location);
            let right = visit_single_expr(ctx, right).backtrace_at_location(right_location);

            let backtrace = LabelBacktrace::combine_options(
                left,
                right,
                LabelBacktraceKind::Expression,
                ctx.pin(location.clone()),
            );

            ValueRef::from(backtrace)
        }
    };

    vec![single]
}

pub fn visit_single_expr<'a>(ctx: &mut AnalysisContext<'a>, node: &ExprNode<'a>) -> ValueRef<'a> {
    let mut result = visit_expr(ctx, node);

    if result.is_empty() {
        ctx.report_error(AnalysisErrorKind::UnexpectedVoidExpression {
            location: get_expr_location(node),
        });
    } else if result.len() > 1 {
        ctx.report_error(AnalysisErrorKind::UnexpectedMultiValueExpression {
            location: get_expr_location(node),
        });
    } else {
        let mut value = result.pop().unwrap(); // already checked

        value.try_singularize_simple_mobius();

        return if let Some(expandable) = value.as_expandable() {
            // collapse into single value
            expandable.primary()
        } else {
            value
        };
    }

    ValueRef::new_bottom()
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
    let location = ctx.pin(get_expr_location(node));

    visit_single_expr(ctx, node).backtrace_at_location(location)
}

pub fn visit_operand_name<'a>(
    ctx: &mut AnalysisContext<'a>,
    name: Span<'a>,
    qualifier: Option<Span<'a>>,
) -> ValueRef<'a> {
    if qualifier.is_none() && ctx.symtab().qualifier_exists(name.content()) {
        // FIXME: this is wrong because it means an existing qualifier will
        // always have precedence over a declared symbol with the same name,
        // but that is *not* the expected behavior -- however, this is _much_
        // simpler to handle since putting this after resolve_operand_name would
        // not prevent an unknown symbol error from being reported even when
        // a qualifier is valid

        return ValueRef::from(Value::PackageRef(PackageRefValue::new(name)));
    } else if let Some(qual) = qualifier {
        if ctx.symtab().is_package_blackbox(qual.content()) {
            // we don't know any details about this package, so we just assume
            // that the requested member (`name`) exists within it

            return ValueRef::new_bottom();
        }
    }

    let Some(symbol) = resolve_operand_name(ctx, name, qualifier) else {
        // error already reported
        return ValueRef::new_bottom();
    };

    let borrowed = symbol.borrow();

    borrowed.value().nest_backtrace(
        LabelBacktraceKind::Expression,
        Some(name.content()),
        ctx.pin(name.location()),
        [],
    )
}

/// Reports error for unknown symbol or unknown qualifier, if applicable
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
            Some(Some(symbol)) => symbol,
            Some(None) => {
                // this is likely the accessing of blackbox package for which we
                // do not actually have the source, so we just return None now
                // without actually reporting any error

                return None;
            }
            None => {
                ctx.report_error(AnalysisErrorKind::UnknownQualifier { found: qualifier });

                return None;
            }
        }
    } else {
        ctx.symtab().get_symbol(name.content())
    };

    if symbol.is_none() {
        ctx.report_error(AnalysisErrorKind::UnknownSymbol { found: name });
    }

    symbol
}

fn visit_type_assertion<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &TypeAssertionNode<'a>,
) -> ValueRef<'a> {
    let value = visit_single_expr(ctx, &node.expr);

    // a type assertion is expandable into 2 values: the first is just the value
    // itself (assuming the assertion is true), and the second is a boolean
    // indicating whether the assertion succeeded (essentially the same value
    // but downgraded to simplest shape to remove any complexity)
    let backtrace = value.backtrace_at_location(ctx.pin(node.location.clone()));

    ValueRef::from(Value::Expandable(ExpandableValue::new(
        value,
        vec![ValueRef::from(backtrace)],
    )))
}

pub fn get_expr_location(node: &ExprNode<'_>) -> Location {
    match node {
        ExprNode::Name(name) => name.location(),
        ExprNode::Literal(
            LiteralNode::Int { location, .. }
            | LiteralNode::Float { location, .. }
            | LiteralNode::Rune { location, .. }
            | LiteralNode::String { location, .. }
            | LiteralNode::Function { location, .. }
            | LiteralNode::Array { location, .. }
            | LiteralNode::Slice { location, .. }
            | LiteralNode::Map { location, .. }
            | LiteralNode::Struct { location, .. },
        ) => location.clone(),
        ExprNode::Call(call) => call.location.clone(),
        ExprNode::Make(make) => make.location.clone(),
        ExprNode::Selection(selection) => selection.location.clone(),
        ExprNode::Indexing(indexing) => indexing.location.clone(),
        ExprNode::Slicing(slicing) => slicing.location.clone(),
        ExprNode::Conversion(conversion) => conversion.location.clone(),
        ExprNode::TypeAssertion(assertion) => assertion.location.clone(),
        ExprNode::UnaryOp { location, .. } | ExprNode::BinaryOp { location, .. } => {
            location.clone()
        }
    }
}
