use parser::{
    Location,
    ast::{ExprNode, IndexingNode, SelectionNode, SlicingNode},
};

use crate::{
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::LabelBacktraceKind,
    taint::funcs,
    types::TypeKind,
    values::{
        ExpandableValue, FunctionValue, SelfAwareBacktraceContainer, SimpleConstValue, Value,
        ValueRef,
    },
};

pub fn visit_selection<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &SelectionNode<'a>,
) -> ValueRef<'a> {
    let base = super::visit_single_expr(ctx, &node.base);

    visit_selection_with_base(ctx, node, &base)
}

pub fn visit_selection_with_base<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &SelectionNode<'a>,
    base: &ValueRef<'a>,
) -> ValueRef<'a> {
    if let Some(pkg) = base.as_package_ref() {
        // this is not actually a selection, it's just a qualified operand name
        return super::visit_operand_name(ctx, node.selector, Some(pkg.qualifier()));
    }

    // we employ multiple strategies to determine whether this selection
    // represents a method access or a field access, as well as to fetch all
    // the necessary details associated with either of them

    let location = ctx.pin(node.location.clone());
    let selector = node.selector.content();

    // Strategy A - Typed Dispatch: when the base has a known declared type, use
    // it to look up the method or struct field by name. this is the best case
    // scenario and guaranteed to be correct, including cross-package

    if let Some(r#type) = base.declared_type().cloned() {
        if let Some(method) = r#type.lookup_promoted_method(selector) {
            return funcs::nest_receiver_backtrace(method.borrow().value().get(), base, location);
        }

        // note we only call `as_struct` after we know this is actually supposed
        // to be a struct, as otherwise an unwanted upgrade would trigger

        if let TypeKind::Struct { fields } = r#type.underlying()
            && let Some(field) = fields.get(selector)
            && let Some(r#struct) = base.as_struct()
        {
            return r#struct
                .get_const(&selector.to_owned(), location)
                .into_with_declared_type(field.resolved_type());
        }
        // typed lookup didn't conclusively resolve; fall through to the
        // name-only heuristic + the final blackbox-softening leaf below
    }

    // ----------

    // Strategy B - Heuristic Dispatch: use just the name to try to find the
    // method if it was declared in the current package (cross-package not
    // supported), and only if it was the only one with that name in the current
    // package

    if let Some(method) = ctx
        .symtab()
        .lookup_unique_method_in_current_package(selector)
    {
        return funcs::nest_receiver_backtrace(method.borrow().value().get(), base, location);
    }

    // ----------

    // Strategy C - Attempted Upgrade: assume that this is a field access on a
    // struct, and so try to access/upgrade the base into one so that we can
    // treat this as a constant field access

    if let Some(r#struct) = base.as_struct() {
        return r#struct.get_const(&selector.to_owned(), location);
    }

    // ----------

    // Strategy D - Blackbox Softening: if the selector at least _plausibly_
    // names a method (i.e., if the selector is the name of at least one method
    // we are aware of, anywhere), assume this selection is method-related
    // (especially since `as_struct` above failed) and just return a blackbox
    // method value

    // note that this check would, own its own, have very low probative value of
    // this actually being method-related, but `visit_selection` by definition
    // only applies for syntactic selections (which can only be field accesses
    // or method accesses), all strategies above failed, and especially it was
    // deemed impossible to upgrade the base to support field accesses, so this
    // is our last resort to make some sense of the selection before just giving
    // up and reporting an error, meaning that the bar is very low and there are
    // very few possible situations for being in this narrow possibility space

    if ctx.types().any_method_named(selector) {
        let blackbox = FunctionValue::new_unknown(base.backtrace(), true);

        return ValueRef::new(Value::Function(Box::new(blackbox)), location, None);
    }

    // ----------

    // we really don't know what this is, so just surface the error

    ctx.report_error(AnalysisErrorKind::InvalidSelectionBase {
        location: node.location.clone(),
    });

    ValueRef::new_bottom(location, None)
}

pub fn visit_indexing<'a>(ctx: &mut AnalysisContext<'a>, node: &IndexingNode<'a>) -> ValueRef<'a> {
    let base = super::visit_single_expr(ctx, &node.base);

    visit_indexing_with(ctx, &base, &node.index, &node.location)
}

pub fn visit_indexing_with<'a>(
    ctx: &mut AnalysisContext<'a>,
    base: &ValueRef<'a>,
    index: &ExprNode<'a>,
    location: &Location,
) -> ValueRef<'a> {
    let pinned = ctx.pin(location.clone());

    let Some(composite) = base.as_composite() else {
        ctx.report_error(AnalysisErrorKind::InvalidIndexingBase {
            location: location.clone(),
        });

        return ValueRef::new_bottom(pinned, None);
    };

    let index = SimpleConstValue::try_resolve_from_expr(index);

    let result = composite.get_at_key(index.as_ref(), pinned.clone());


    if base.is_map() {
        // indexing a map returns a second value corresponding to whether the
        // key was or not present in the map. here, we assume that this presence
        // value has the same label as the actual returned value
        let presence = result.downgrade(|| pinned.clone());

        let expandable = ExpandableValue::new(result, vec![presence]);

        ValueRef::new(Value::Expandable(expandable), pinned, None)
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

    // slicing preserves the slice type per Go spec; for arrays the result is
    // anonymous `[]E` (no named type), and string slicing degrades to `string`
    // (untyped) so we can only propagate when base is itself a slice
    let declared_type = base
        .declared_type()
        .filter(|t| matches!(t.underlying(), TypeKind::Slice))
        .cloned();

    ValueRef::from_backtrace_or_bottom_at(result, || location)
        .into_with_declared_type(declared_type)
}
