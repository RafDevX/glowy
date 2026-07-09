use std::borrow::Cow;

use parser::{
    Location,
    ast::{ExprNode, IndexingNode, SelectionNode, SlicingNode},
};

use crate::{
    Pinned,
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{Label, LabelBacktrace, LabelBacktraceKind},
    policy::{BlanketDirective, BlanketDirectiveKind},
    taint::funcs,
    types::{TypeInfo, TypeKind},
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

    let location = ctx.pin(node.location.clone());
    let selector = node.selector.content();

    // before getting started, we collect any potential blanket directives that
    // may be targeting this selection, in case we know `base`'s type. this
    // covers both methods and struct fields, and we will need this information
    // regardless of the approach chosen to visit the selection
    let type_member_directives = base
        .declared_type()
        .map(AsRef::as_ref)
        .map(TypeInfo::strip_pointers)
        .map(|r#type| ctx.blanket_directives_for(r#type.package(), Some(r#type.name()), selector))
        .filter(|slice| !slice.is_empty());

    let blanket_backtrace = type_member_directives
        .and_then(|directives| build_blanket_backtrace(directives, &location));

    // ----------

    // we employ multiple strategies to determine whether this selection
    // represents a method access or a field access, as well as to fetch all
    // the necessary details associated with either of them

    // ----------

    // Strategy A - Typed Dispatch: when the base has a known declared type, use
    // it to look up the method or struct field by name. this is the best case
    // scenario and guaranteed to be correct, including cross-package

    if let Some(r#type) = base.declared_type().cloned() {
        if let Some(method) = r#type.lookup_promoted_method(selector) {
            let value = funcs::nest_receiver_backtrace(
                method.borrow().value().get(),
                base,
                location.clone(),
            );

            return nest_optional_backtrace(value, blanket_backtrace, location);
        }

        // ordering matters: `lookup_promoted_field` already gates on the
        // underlying being a struct (either directly or via an embedded chain),
        // so we only reach `as_struct` (which would otherwise force an
        // unwanted upgrade) once we know the shape is genuinely struct-like
        if let Some(promoted) = r#type.lookup_promoted_field(selector)
            && let Some(r#struct) = base.as_struct()
        {
            let field = promoted.field_info();

            let value = r#struct
                .get_const(&selector.to_owned(), location.clone())
                .into_with_declared_type(field.resolved_type());

            return nest_field_backtraces(
                value,
                [blanket_backtrace, field.tag_backtrace().cloned()],
                location,
            );
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
        let method_value = method.borrow().value().get();

        let value = funcs::nest_receiver_backtrace(method_value, base, location.clone());

        return nest_optional_backtrace(value, blanket_backtrace, location);
    }

    // ----------

    // Strategy C - Attempted Upgrade: if we have no information demonstrating
    // otherwise, assume that this is a field access on a struct, and so try to
    // access/upgrade the base into one so that we can treat this as a constant
    // field access

    let struct_shape_plausible = base
        .declared_type()
        .map(AsRef::as_ref)
        .map(TypeInfo::strip_pointers)
        .and_then(TypeInfo::underlying)
        .is_none_or(|kind| matches!(kind, TypeKind::Struct { .. }));
    // ^^^ we treat this as plausibly a struct when the base's shape is
    // unknown to us (no declared type, or an external placeholder), and also
    // when we do know it's a struct; otherwise upgrading would be known wrong

    // if there are sinks configured, this is probably not a field access
    // (we short-circuit if we already know the shape is not plausible)
    let has_type_member_sink = !struct_shape_plausible
        && type_member_directives
            .iter()
            .copied()
            .flatten()
            .any(|directive| {
                matches!(
                    directive.kind(),
                    BlanketDirectiveKind::AllowSink | BlanketDirectiveKind::DenySink
                )
            });

    if struct_shape_plausible
        && !has_type_member_sink
        && let Some(r#struct) = base.as_struct()
    {
        let value = r#struct.get_const(&selector.to_owned(), location.clone());

        return nest_field_backtraces(
            value,
            [
                blanket_backtrace,
                lookup_field_tag_backtrace(base, selector),
            ],
            location,
        );
    }

    // ----------

    // Strategy D - Blackbox Softening: if the selector at least _plausibly_
    // names a method (i.e., if the selector is the name of at least one method
    // we are aware of, anywhere), assume this selection is method-related
    // (especially since `as_struct` above failed) and just return a blackbox
    // method value. Note that while this strategy might assume something is a
    // method just based on low probative value sometimes, it is important to
    // keep in mind that there is no other solution, as if this strategy fails
    // the only alternative is to report an error and void the analysis results

    // Criterion D.1: this is a plausible method if there's a registered blanket
    // directive for it in the base's known type (we'll always want to apply it)
    let has_blanket_directives = type_member_directives.is_some();

    // Criterion D.2: this is a plausible method if we have analyzed the source
    // code of a method somewhere with this name, on any type (we short-circuit
    // if D.1 was successful, to avoid the lookup when unnecessary)
    let any_method_named = !has_blanket_directives && ctx.types().any_method_named(selector);

    // Criterion D.3: this is a plausible method if the base's declared type
    // is an external placeholder (declaration never visited, so this is likely
    // a foreign package); we cannot possibly know its method set, so `selector`
    // might plausibly be one of them. we short-circuit if D.1 or D.2 were
    // already successful to avoid the lookup when unnecessary
    let base_is_external_opaque = !any_method_named
        && base
            .declared_type()
            .map(AsRef::as_ref)
            .map(TypeInfo::strip_pointers)
            .is_some_and(TypeInfo::is_external);

    // Final D.X aggregate condition
    if has_blanket_directives || any_method_named || base_is_external_opaque {
        let blackbox_backtrace = LabelBacktrace::combine_options(
            base.backtrace(),
            blanket_backtrace,
            LabelBacktraceKind::Expression,
            Cow::Borrowed(&location),
        );

        let mut blackbox = FunctionValue::new_unknown(blackbox_backtrace, true);

        if let Some(directives) = type_member_directives {
            blackbox.absorb_blanket_sinks(directives);
        }

        return ValueRef::new(Value::Function(Box::new(blackbox)), location, None);
    }

    // ----------

    // we really don't know what this is, so just surface the error

    ctx.report_error(AnalysisErrorKind::InvalidSelectionBase {
        location: node.location.clone(),
    });

    ValueRef::new_bottom(location, None)
}

fn build_blanket_backtrace<'a>(
    directives: &'a [BlanketDirective],
    at_location: &Pinned<'a, Location>,
) -> Option<LabelBacktrace<'a>> {
    let blanket_label: Label<'_> = directives
        .iter()
        .filter(|directive| directive.kind() == BlanketDirectiveKind::Source)
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

fn nest_optional_backtrace<'a>(
    value: ValueRef<'a>,
    backtrace: Option<LabelBacktrace<'a>>,
    at_location: Pinned<'a, Location>,
) -> ValueRef<'a> {
    match backtrace {
        Some(backtrace) => value.nest_backtrace(
            LabelBacktraceKind::Expression,
            None,
            at_location,
            [backtrace],
        ),
        None => value,
    }
}

fn lookup_field_tag_backtrace<'a>(
    base: &ValueRef<'a>,
    selector: &str,
) -> Option<LabelBacktrace<'a>> {
    let field = base.declared_type()?.lookup_promoted_field(selector)?;

    field.field_info().tag_backtrace().cloned()
}

fn nest_field_backtraces<'a>(
    value: ValueRef<'a>,
    backtraces: impl IntoIterator<Item = Option<LabelBacktrace<'a>>>,
    at_location: Pinned<'a, Location>,
) -> ValueRef<'a> {
    let extras: Vec<_> = backtraces.into_iter().flatten().collect();

    if extras.is_empty() {
        // avoid an unnecessary wrapping node when nothing is being folded in
        return value;
    }

    value.nest_backtrace(LabelBacktraceKind::Expression, None, at_location, extras)
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
        .filter(|r#type| matches!(r#type.underlying(), Some(TypeKind::Slice)))
        .cloned();

    ValueRef::from_backtrace_or_bottom_at(result, || location)
        .into_with_declared_type(declared_type)
}
