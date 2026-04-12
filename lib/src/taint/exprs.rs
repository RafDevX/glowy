use std::{borrow::Cow, rc::Rc};

use parser::{
    Location, Span,
    ast::{ExprNode, TypeAssertionNode, UnaryOpKind},
};

use super::{channels, funcs};
use crate::{
    Pinned,
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{Label, LabelBacktrace, LabelBacktraceKind, LabelTag},
    symbols::{QualifiedSymbolResolutionResult, SymbolRef},
    values::{
        ExpandableValue, FunctionRef, PackageRefValue, SelfAwareBacktraceContainer, Value, ValueRef,
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
        let mut value = result.pop().unwrap(); // already checked

        value.try_singularize_simple_mobius();

        return if let Some(expandable) = value.as_expandable() {
            // collapse into single value
            expandable.primary()
        } else {
            value
        };
    }

    ValueRef::new_bottom(ctx.pin(node.location().into_owned()))
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

pub struct CaptureAwareSymbolRef<'a> {
    symbol: SymbolRef<'a>,
    capture: Option<LabelBacktrace<'a>>, // synthetic
}

impl<'a> CaptureAwareSymbolRef<'a> {
    fn new_direct(symbol: SymbolRef<'a>) -> Self {
        Self {
            symbol,
            capture: None,
        }
    }

    fn new_capture(symbol: SymbolRef<'a>, capture: LabelBacktrace<'a>) -> Self {
        Self {
            symbol,
            capture: Some(capture),
        }
    }

    pub fn value(&self, at_location: &Pinned<Location>) -> ValueRef<'a> {
        let symbol = self.symbol.borrow();
        let base = symbol.value().get();

        if let Some(capture) = &self.capture {
            // check if value already has the synthetic
            if let Some(base_label) = base.backtrace().as_ref().map(LabelBacktrace::label) {
                if !base_label.contains(capture.label().as_single().unwrap()) {
                    return base.nest_backtrace(
                        LabelBacktraceKind::ClosureCapture,
                        Some(symbol.declared_name().content()),
                        at_location.clone(),
                        [capture.clone()],
                    );
                }
            }
        }

        // we need to clone_inner to ensure compliance with the stated
        // AssumedImmutable restrictions (cannot allow invokers to directly
        // mutate a Symbol's value) -- See: Symbol::value
        base.clone_inner()
    }

    pub fn into_symbol(self) -> SymbolRef<'a> {
        self.symbol
    }
}

pub fn visit_operand_name<'a>(
    ctx: &mut AnalysisContext<'a>,
    name: Span<'a>,
    qualifier: Option<Span<'a>>,
) -> ValueRef<'a> {
    let location = ctx.pin(name.location());

    if qualifier.is_none() && ctx.symtab().qualifier_exists(name.content()) {
        // FIXME: this is wrong because it means an existing qualifier will
        // always have precedence over a declared symbol with the same name,
        // but that is *not* the expected behavior -- however, this is _much_
        // simpler to handle since putting this after resolve_operand_name would
        // not prevent an unknown symbol error from being reported even when
        // a qualifier is valid

        return ValueRef::new(Value::PackageRef(PackageRefValue::new(name)), location);
    } else if let Some(qual) = qualifier {
        if ctx.symtab().is_package_blackbox(qual.content()) {
            // we don't know any details about this package, so we just assume
            // that the requested member (`name`) exists within it

            return ValueRef::new_bottom(location);
        }
    }

    let Some(symbol) = resolve_operand_name(ctx, name, qualifier) else {
        // error already reported
        return ValueRef::new_bottom(location);
    };

    symbol
        .value(&location)
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
) -> Option<CaptureAwareSymbolRef<'a>> {
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

    if let Some(symbol) = &symbol {
        if let Some((mut func, boundary)) = ctx.current_function_and_boundary() {
            if let Some(mut func) = func.as_function_mut() {
                if let FunctionRef::Anonymous(location) = func.r#ref() {
                    if !boundary.contains_symbol(symbol) {
                        // we're inside a closure and accessing a symbol
                        // declared outside of its body, meaning that this is
                        // a "capture" that needs to be treated differently:
                        // we need to share access to that symbol, meaning that
                        // if it's later mutated outside of the closure body,
                        // that'll still reflect within the closure on call

                        let borrow = symbol.borrow();
                        let decl = borrow.declared_name();

                        let location = location.clone();
                        let index = func.register_capture(Cow::Borrowed(decl));

                        let synthetic = LabelTag::Synthetic {
                            func: func.r#ref().clone(),
                            index: Some(index),
                            identifier: Some(name),
                        };

                        return Some(CaptureAwareSymbolRef::new_capture(
                            Rc::clone(symbol),
                            LabelBacktrace::new_root(
                                LabelBacktraceKind::ClosureCapture,
                                Label::from_single(synthetic),
                                Some(decl.content()),
                                location,
                            ),
                        ));
                    }
                }
            }
        }
    } else {
        // symbol not found -- report error
        ctx.report_error(AnalysisErrorKind::UnknownSymbol { found: name });
    }

    symbol.map(CaptureAwareSymbolRef::new_direct)
}

fn visit_type_assertion<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &TypeAssertionNode<'a>,
) -> ValueRef<'a> {
    let value = visit_single_expr(ctx, &node.expr);

    let location = ctx.pin(node.location.clone());

    // a type assertion is expandable into 2 values: the first is just the value
    // itself (assuming the assertion is true), and the second is a boolean
    // indicating whether the assertion succeeded (essentially the same value
    // but downgraded to simplest shape to remove any complexity)
    let secondary = value.downgrade(|| location.clone());

    let expandable = ExpandableValue::new(value, vec![secondary]);

    ValueRef::new(Value::Expandable(expandable), location)
}
