use parser::ast::{IndexingNode, SelectionNode, SlicingNode};

use crate::{
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::LabelBacktraceKind,
    values::{ExpandableValue, SelfAwareBacktraceContainer, SimpleConstValue, Value, ValueRef},
};

pub fn visit_selection<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &SelectionNode<'a>,
) -> ValueRef<'a> {
    let base = super::visit_single_expr(ctx, &node.base);

    if let Some(pkg) = base.as_package_ref() {
        // this is not actually a selection, it's just a qualified operand name

        return super::visit_operand_name(ctx, node.selector, Some(pkg.qualifier()));
    }

    let location = ctx.pin(node.location.clone());
    let selector = node.selector.content();

    // try method dispatch (current package only) before struct-field lookup.
    // the order matters: `as_struct` would upgrade a Simple/Bottom base into
    // an empty struct, after which `get_const(selector)` unconditionally
    // returns Bottom and masks the method. Go's spec forbids a method and a
    // field sharing a name on the same defined type, so dispatching the
    // method first is correct for any well-typed access.
    //
    // we nest the base's backtrace into the returned method value so taint
    // flows soundly whether the result is invoked (`x.M()`) or read as a
    // method value (`f := x.M`). for an immediate call, the receiver's taint
    // *also* propagates through `SyntheticSlot::Receiver` realization in
    // `visit_call`; the union is idempotent.
    //
    // unresolved selections (all sound, all later degrade to standard blackbox
    // handling in `visit_call`):
    // - cross-package: `x.M` where `x` is not the current package -- we don't track
    //   `x`'s static type, so we can't know it's a method
    // - locally ambiguous: two receiver types in the current package both declare
    //   the same `selector` identifier as a method
    // - interface dispatch: method-set resolution is not modeled
    if let Some(method) = ctx
        .symtab()
        .lookup_unique_method_in_current_package(selector)
    {
        let value = method.borrow().value().get();

        return match base.backtrace() {
            Some(base_bt) => value.nest_backtrace(
                LabelBacktraceKind::MethodReceiver,
                None,
                location,
                [base_bt],
            ),
            None => {
                // receiver is Bottom so we can skip all the nesting complexity
                value
            }
        };
    }

    let Some(r#struct) = base.as_struct() else {
        ctx.report_error(AnalysisErrorKind::InvalidSelectionBase {
            location: node.location.clone(),
        });

        return ValueRef::new_bottom(location);
    };

    r#struct.get_const(&selector.to_owned(), location)
}

pub fn visit_indexing<'a>(ctx: &mut AnalysisContext<'a>, node: &IndexingNode<'a>) -> ValueRef<'a> {
    let base = super::visit_single_expr(ctx, &node.base);

    let location = ctx.pin(node.location.clone());

    let Some(composite) = base.as_composite() else {
        ctx.report_error(AnalysisErrorKind::InvalidIndexingBase {
            location: node.location.clone(),
        });

        return ValueRef::new_bottom(location);
    };

    let index = SimpleConstValue::try_resolve_from_expr(&node.index);

    let result = composite.get_at_key(index.as_ref(), location.clone());

    if base.is_map() {
        // indexing a map returns a second value corresponding to whether the
        // key was or not present in the map. here, we assume that this presence
        // value has the same label as the actual returned value
        let presence = result.downgrade(|| location.clone());

        let expandable = ExpandableValue::new(result, vec![presence]);

        ValueRef::new(Value::Expandable(expandable), location)
    } else {
        result
    }
}

pub fn visit_slicing<'a>(ctx: &mut AnalysisContext<'a>, node: &SlicingNode<'a>) -> ValueRef<'a> {
    let base = super::visit_single_expr(ctx, &node.base);

    let location = ctx.pin(node.location.clone());

    // per spec, string slicing is only allowed if max is None
    // (full slicing expressions only support arrays/slices)
    let result = if node.max.is_none() && base.is_simple() {
        // either we're slicing a simple string (creating a substring), or base
        // actually has a more complex shape but just hasn't been coerced yet
        // (in which case its final "dyn + all consts" backtrace would just be
        // the current simple value) -- in both cases, the result of accessing
        // it is always just the backtrace itself (+ low/high/max)

        base.backtrace()
    } else if let Some(sliceable) = base.as_complex_sliceable() {
        let low = node
            .low
            .as_deref()
            .map(SimpleConstValue::try_resolve_from_expr);
        let high = node
            .high
            .as_deref()
            .map(SimpleConstValue::try_resolve_from_expr);

        // at this point low and high are both Option<Option<SimpleConstValue>>,
        // but we actually need to match on the inner Option (representing
        // whether a const value was determined) to know whether to use const
        // or dyn slicing, and the outer Option (representing whether a concrete
        // low/high value was explicitly provided or just omitted) should just
        // be propagated. this means we need to do some rather unintuitive
        // matching here to essentially swap the Options
        #[expect(
            clippy::items_after_statements,
            reason = "Auxiliary function makes more sense defined/explained here"
        )]
        #[expect(
            clippy::option_option,
            reason = "Access to convenient methods in auxiliary computations"
        )]
        fn transform(v: Option<&Option<SimpleConstValue>>) -> Option<Option<u64>> {
            match v {
                Some(Some(SimpleConstValue::Integer(x))) => Some(Some(*x)),
                Some(_) => None,
                None => Some(None),
            }
        }

        let low = transform(low.as_ref());
        let high = transform(high.as_ref());

        match (low, high) {
            (Some(low), Some(high)) => {
                sliceable.slice_const(low.as_ref(), high.as_ref(), location.clone())
            }
            _ => sliceable.slice_dyn(location.clone()),
        }
    } else {
        ctx.report_error(AnalysisErrorKind::InvalidSlicingBase {
            location: node.location.clone(),
        });

        None
    };

    let result = result.nest_backtrace(
        LabelBacktraceKind::Expression,
        None,
        location.clone(),
        [
            node.low
                .as_ref()
                .and_then(|l| super::get_expr_backtrace(ctx, l)),
            node.high
                .as_ref()
                .and_then(|h| super::get_expr_backtrace(ctx, h)),
            node.max
                .as_ref()
                .and_then(|m| super::get_expr_backtrace(ctx, m)),
        ]
        .into_iter()
        .flatten(),
    );

    ValueRef::from_backtrace_or_bottom_at(result, || location)
}
