use parser::{
    ast::{ExprNode, IndexingNode, LiteralNode, OperandNameNode, UnaryOpKind},
    Location,
};

use crate::{
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{LabelBacktrace, LabelBacktraceKind},
    symbols::SymbolRef,
    Pinned,
};

use super::{channels, funcs};

pub fn visit_expr<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &ExprNode<'a>,
) -> Vec<Option<LabelBacktrace<'a>>> {
    match node {
        ExprNode::Name(name) => vec![visit_operand_name(ctx, name)],
        ExprNode::Literal(_) => vec![None],
        ExprNode::Call(call) => funcs::visit_call(ctx, call),
        ExprNode::Indexing(indexing) => vec![visit_indexing(ctx, indexing)],
        ExprNode::UnaryOp {
            kind: UnaryOpKind::Receive,
            operand,
            location,
        } => vec![channels::visit_receive(ctx, operand, location)],
        ExprNode::UnaryOp { operand, .. } => vec![visit_single_expr(ctx, operand)],
        ExprNode::BinaryOp {
            left,
            right,
            location,
            ..
        } => {
            let left = visit_single_expr(ctx, left);
            let right = visit_single_expr(ctx, right);

            let backtrace = match (&left, &right) {
                (None, None) => None,
                (Some(_), None) => left,
                (None, Some(_)) => right,
                (Some(l), Some(r)) => {
                    Some(l.union(r, LabelBacktraceKind::Expression, ctx.pin(location.clone())))
                }
            };

            vec![backtrace]
        }
    }
}

pub fn visit_single_expr<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &ExprNode<'a>,
) -> Option<LabelBacktrace<'a>> {
    let mut iter = visit_expr(ctx, node).into_iter();

    let first = iter.next();
    let second = iter.next();

    if first.is_some() && second.is_none() {
        #[allow(clippy::unnecessary_unwrap)]
        let single = first.unwrap();
        // ^ clippy would rather us use something more idiomatic like
        // `if let (Some(single), None) = (&first, &second)`, but that would
        // require us always cloning single (since first must be a ref or
        // otherwise it can't be used in else-branch below). We want to prevent
        // cloning since the if-branch should be much more common than the else,
        // so unwrapping here seems fine. We also must assign to a `single`
        // variable before returning `single` since attributes on expressions
        // are experimental (and not on statements), and we need to add the
        // clippy allow attribute for it to leave us be

        single
    } else {
        // we merge all of them into a single backtrace to proceed

        let children: Vec<_> = [first, second]
            .into_iter()
            .flatten()
            .chain(iter)
            .flatten()
            .collect();

        let location = children
            .iter()
            .map(LabelBacktrace::location)
            .map(Pinned::inner) // assumes all children are in same file!!
            .cloned()
            .reduce(|acc, loc| {
                let start = acc.start.min(loc.start);
                let end = acc.end.max(loc.end);

                start..end
            });

        if let Some(location) = location {
            ctx.report_error(AnalysisErrorKind::UnexpectedMultiValueExpression {
                location: location.clone(),
            });

            LabelBacktrace::fold(
                &children,
                LabelBacktraceKind::Expression,
                None,
                ctx.pin(location),
            )
        } else {
            // only happens if children are empty, where `fold` would return None anyway
            None
        }
    }
}

pub fn visit_operand_name<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &OperandNameNode<'a>,
) -> Option<LabelBacktrace<'a>> {
    let symbol = resolve_operand_name(ctx, node);

    if let Some(symbol) = symbol {
        symbol
            .borrow()
            .label_backtrace()
            .cloned()
            .map(|symbol_backtrace| {
                symbol_backtrace.as_single_child(
                    LabelBacktraceKind::Expression,
                    Some(node.id.content()),
                    ctx.pin(node.id.location()),
                )
            })
    } else {
        None
    }
}

/// Reports error for unknown qualifier and unknown symbol, if applicable
pub fn resolve_operand_name<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &OperandNameNode<'a>,
) -> Option<SymbolRef<'a>> {
    let symbol = if let Some(qualifier) = &node.package {
        if let Some(symbol) = ctx
            .symtab()
            .get_qualified_symbol(qualifier.content(), node.id.content())
        {
            symbol
        } else {
            ctx.report_error(AnalysisErrorKind::UnknownQualifier {
                found: qualifier.clone(),
            });

            return None;
        }
    } else {
        ctx.symtab().get_symbol(node.id.content())
    };

    if symbol.is_none() {
        ctx.report_error(AnalysisErrorKind::UnknownSymbol {
            found: node.id.clone(),
        });
    }

    symbol
}

pub fn visit_indexing<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &IndexingNode<'a>,
) -> Option<LabelBacktrace<'a>> {
    let expr = visit_single_expr(ctx, &node.expr);
    let index = visit_single_expr(ctx, &node.index);

    match (&expr, &index) {
        (None, None) => None,
        (Some(_), None) => expr,
        (None, Some(_)) => index,
        (Some(e), Some(i)) => Some(e.union(
            i,
            LabelBacktraceKind::Expression,
            ctx.pin(node.location.clone()),
        )),
    }
}

pub fn get_expr_location(node: &ExprNode<'_>) -> Location {
    match node {
        ExprNode::Name(name) => {
            let start = if let Some(package) = &name.package {
                package.location().start
            } else {
                name.id.location().start
            };

            start..name.id.location().end
        }
        ExprNode::Call(call) => call.location.clone(),
        ExprNode::Indexing(indexing) => indexing.location.clone(),
        ExprNode::UnaryOp { location, .. } | ExprNode::BinaryOp { location, .. } => {
            location.clone()
        }
        ExprNode::Literal(lit) => match lit {
            LiteralNode::Int { location, .. } => location.clone(),
            LiteralNode::Float { location, .. } => location.clone(),
            LiteralNode::Rune { location, .. } => location.clone(),
            LiteralNode::String { location, .. } => location.clone(),
        },
    }
}
