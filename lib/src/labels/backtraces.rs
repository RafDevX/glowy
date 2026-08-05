use std::{
    borrow::Cow,
    collections::BTreeMap,
    hash::{self, Hash},
    iter,
    sync::Arc,
};

use parser::Location;

use crate::{
    Pinned,
    labels::{FunctionRef, Label, LabelTag, SyntheticSlot},
};

/// Represents the propagation history leading up to a label attribution.
///
/// This hierarchical structure keeps track of why a certain piece of data has
/// been assigned a specific [`Label`], particularly in the sense of what
/// operations occurred and compounded to result in a final label.
///
/// The following invariants are strictly enforced: \
///     1. No [`LabelBacktrace`] ever has a label [`Label::Bottom`]; \
///     2. Children's labels are always a subset of their parent's label (e.g.,
///     a backtrace `{blue, violet}` can have a child `{blue}` and another
///     `{violet}`, but never a `{yellow}` child); and \
///     3. All children's labels are always disjoint (e.g., if a first child
///     has label `{blue, violet}`, a second child can never have label
///     `{blue, yellow}` -- it will instead be trimmed to just `{yellow}` to
///     simplify the whole chain and limit hierarchy size).
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct LabelBacktrace<'a> {
    /// What operation caused this label attribution.
    kind: LabelBacktraceKind,
    /// The final label associated with some information.
    ///
    /// A reference-counting [`Arc`] is used to store the label (vs. just
    /// holding a [`Label`] directly) so that cloning a [`LabelBacktrace`] (even
    /// if changing one of its other fields, usually [`LabelBacktrace::kind`])
    /// does not need to allocate a new [`Label`]. This is crucial for efficient
    /// "nothing to do" paths that just return `self.clone()`, among other very
    /// hot paths. This is sound because nothing ever mutates `label`.
    ///
    /// Note that we use [`Arc`] instead of [`Rc`](std::rc::Rc) because
    /// [`LabelBacktrace`] must be [`Send`], as otherwise
    /// [`AnalysisError`](crate::errors::AnalysisError) also would not be
    /// [`Send`], which would prevent parallelism between analysis runs.
    label: Arc<Label<'a>>,
    /// Name of symbol with this label, if any/applicable.
    symbol: Option<&'a str>,
    /// Where this operation took place.
    location: Pinned<'a, Location>,
    /// Other backtraces through which this label is derived via propagation.
    ///
    /// A reference-counted slice is used to store children (vs. a [`Vec`]) so
    /// that cloning a [`LabelBacktrace`] does not recursively deep-clone the
    /// entire propagation tree. This is crucial for efficient "nothing to do"
    /// paths that just return `self.clone()`, among other very hot paths.
    ///
    /// This is sound because nothing ever mutates `children`, since there is no
    /// way to get a mutable reference to a child (i.e., [`Arc::get_mut`] is
    /// never invoked).
    ///
    /// Note that we use [`Arc`] instead of [`Rc`](std::rc::Rc) because
    /// [`LabelBacktrace`] must be [`Send`], as otherwise
    /// [`AnalysisError`](crate::errors::AnalysisError) also would not be
    /// [`Send`], which would prevent parallelism between analysis runs.
    children: Arc<[Self]>,
}

impl<'a> LabelBacktrace<'a> {
    /// Base case; no children.
    ///
    /// Returns [`None`] iff `label` is [`Label::Bottom`].
    ///
    /// Useful, in particular, for [`LabelBacktraceKind::ExplicitAnnotation`]
    /// and [`LabelBacktraceKind::FunctionParameter`].
    pub(crate) fn new_root(
        kind: LabelBacktraceKind,
        label: Label<'a>,
        symbol: Option<&'a str>,
        location: Pinned<'a, Location>,
    ) -> Option<Self> {
        if label.is_bottom() {
            None
        } else {
            Some(Self {
                kind,
                label: Arc::from(label),
                symbol,
                location,
                children: Arc::from([]),
            })
        }
    }

    /// Returns [`None`] iff `label` is [`Label::Bottom`].
    pub(crate) fn new<'b>(
        kind: LabelBacktraceKind,
        label: Label<'a>,
        symbol: Option<&'a str>,
        location: Pinned<'a, Location>,
        children: impl IntoIterator<Item = &'b Self>,
    ) -> Option<Self>
    where
        'a: 'b,
    {
        if label.is_bottom() {
            return None;
        }

        let mut remaining_label = label.clone();
        let children: Arc<_> = children
            .into_iter()
            .filter_map(|child| {
                child
                    .restrict_to_label(&remaining_label)
                    .inspect(|child| remaining_label = remaining_label.difference(&child.label))
            })
            .collect();

        Some(Self::from_normalized_parts(
            kind,
            Arc::from(label),
            symbol,
            location,
            children,
        ))
    }

    // normalized = label is not Bottom and children are disjoint + sum to label
    // (this constructor should always be used to ensure invariants are upheld!)
    fn from_normalized_parts(
        kind: LabelBacktraceKind,
        label: Arc<Label<'a>>,
        symbol: Option<&'a str>,
        location: Pinned<'a, Location>,
        children: Arc<[Self]>,
    ) -> Self {
        if let [single_child] = &*children
            && single_child.contains_frame_on_full_label_spine(
                kind,
                symbol,
                &location,
                label.as_ref(),
            )
        {
            // avoid unnecessary repeated backtraces that just make everything
            // more complex, as otherwise backtrace trees could grow almost
            // indefinitely into huge nested structures that make the entire
            // analysis process incredibly inefficient. this is especially true
            // for places reliant on convergence loops, such as mutually
            // recursive functions, since for each iteration all backtraces
            // would grow substantially while adding no new information (just
            // duplicates of what is already known), so we instead just keep
            // the existing subtree and preserve one complete representation
            return single_child.clone();
        }

        Self {
            kind,
            label,
            symbol,
            location,
            children,
        }
    }

    fn contains_frame_on_full_label_spine(
        &self,
        kind: LabelBacktraceKind,
        symbol: Option<&str>,
        location: &Pinned<'_, Location>,
        label: &Label<'a>,
    ) -> bool {
        if self.label() != label {
            // since children represent their parent's label, if the current
            // label does not exactly match what we are looking for, then we do
            // not want to deduplicate:
            //
            // (a) if self.label() is orthogonal to `label`, then `self` is
            //     irrelevant for `label`'s deduplication
            // (b) if self.label() is a subset of `label`, then its children
            //     will never exhibit a greater label than self.label(), thus
            //     they will never match the expected `label` exactly
            // (c) if self.label() is a superset of `label`, then this tree
            //     represents that there has been a revocation of some sort that
            //     caused the label to decrease, meaning we want to keep that
            //     info (not accidentally discard it in name of deduplication)
            return false;
        }

        if self.kind == kind && self.symbol == symbol && self.location == *location {
            // if the label matched above and now everything else does too
            // (except deep children comparison, which we ignore), then we know
            // that we necessarily should deduplicate
            return true;
        }

        // otherwise, if the label matched but the rest of this backtrace did
        // not, then we can recurse down the tree and try to see if our children
        // do match -- however, since children are disjoint, a child will only
        // match `label` if we only have a single child, otherwise it would
        // (by definition) only have a subset of `label` (= self.label())
        if let [single_child] = &*self.children {
            single_child.contains_frame_on_full_label_spine(kind, symbol, location, label)
        } else {
            // nope, we tried our best
            false
        }
    }

    /// Constructs a new instance equal to the union of all its children.
    pub(crate) fn fold<'b>(
        children: impl IntoIterator<Item = &'b Self> + Clone,
        with_kind: LabelBacktraceKind,
        with_symbol: Option<&'a str>,
        at_location: Pinned<'a, Location>,
    ) -> Option<Self>
    where
        'a: 'b,
    {
        let label = children.clone().into_iter().map(Self::label).sum();

        Self::new(with_kind, label, with_symbol, at_location, children)
        // ^ None iff children are empty
    }

    /// Constructs a new instance equal to this one but with one more child.
    pub(crate) fn with_child(&self, child: &Self) -> Self {
        // if self is a root backtrace with synthetic tags, such as in the case
        // of a function's synthetic implicit call-site branch backtrace that is
        // presently being composed with an existing branch backtrace, we need
        // to make sure that the former remains as-is without being merged with
        // the latter, as otherwise it will become invisible to `realize` (which
        // only takes action for root backtraces that have *only* synthetics)
        let keep_self_as_child = self.children.is_empty() && self.label.has_any_synthetic();

        let children: Vec<&Self> = if keep_self_as_child {
            vec![self, child]
        } else {
            iter::once(child).chain(self.children.iter()).collect()
        };

        Self::new(
            self.kind,
            self.label.union(child.label()),
            self.symbol,
            self.location.clone(),
            children.iter().copied(),
        )
        .unwrap() // safe because if self exists, label is not Bottom
    }

    /// Constructs a new instance with self as its only child.
    pub(crate) fn into_single_child(
        self,
        parent_kind: LabelBacktraceKind,
        parent_symbol: Option<&'a str>,
        parent_location: Pinned<'a, Location>,
    ) -> Self {
        // we don't use Self::new here to avoid clones where possible and to
        // skip unnecessary checks / optimizations -- we already know this label
        // isn't Bottom and our children cannot be compacted further

        let label = Arc::clone(&self.label);

        Self::from_normalized_parts(
            parent_kind,
            label,
            parent_symbol,
            parent_location,
            Arc::from([self]),
        )
    }

    /// Returns a new instance (with symbol = None) representing a step above
    /// in the hierarchy between two instances (self and other).
    pub(crate) fn union(
        &self,
        other: &Self,
        with_kind: LabelBacktraceKind,
        at_location: Pinned<'a, Location>,
    ) -> Self {
        Self::new(
            with_kind,
            self.label.union(&other.label),
            None,
            at_location,
            [self, other],
        )
        .unwrap() // safe because if self exists, label is not Bottom
    }

    /// Unions if both are Some, otherwise returns the only Some, if any.
    pub(crate) fn combine_options(
        a: Option<Self>,
        b: Option<Self>,
        with_kind: LabelBacktraceKind,
        at_location: Cow<Pinned<'a, Location>>,
    ) -> Option<Self> {
        match (&a, &b) {
            (None, None) => None,
            (Some(_), None) => a,
            (None, Some(_)) => b,
            (Some(x), Some(y)) => Some(x.union(y, with_kind, at_location.into_owned())),
        }
    }

    /// Realizes synthetic placeholders in the hierarchy to concrete backtraces.
    pub(crate) fn realize(
        &self,
        from_func: &FunctionRef<'a>,
        from_slot: SyntheticSlot,
        concrete: Option<&Self>,
    ) -> Option<Self> {
        self.realize_all(from_func, &[(from_slot, concrete)])
    }

    /// Realizes an ordered set of synthetic placeholders in one traversal.
    ///
    /// The order of `substitutions` has the same meaning as successive calls
    /// to [`Self::realize`]: a concrete backtrace inserted for one slot is
    /// itself affected only by substitutions which follow that slot.
    pub(crate) fn realize_all(
        &self,
        from_func: &FunctionRef<'a>,
        substitutions: &[(SyntheticSlot, Option<&Self>)],
    ) -> Option<Self> {
        self.realize_all_inner(from_func, substitutions, false)
    }

    /// Realizes placeholders in a finalized enforcement backtrace.
    ///
    /// Recursive summaries normally use aggregate roots to stay compact while
    /// labels converge, but at enforcement time, non-recursive calls must
    /// descend into those roots so no placeholder from the invoked function
    /// escapes into its caller.
    pub(crate) fn realize_all_for_enforcement(
        &self,
        from_func: &FunctionRef<'a>,
        substitutions: &[(SyntheticSlot, Option<&Self>)],
    ) -> Option<Self> {
        self.realize_all_inner(from_func, substitutions, true)
    }

    fn realize_all_inner(
        &self,
        from_func: &FunctionRef<'a>,
        substitutions: &[(SyntheticSlot, Option<&Self>)],
        realize_aggregates: bool,
    ) -> Option<Self> {
        let Some(first_relevant) = substitutions.iter().position(|(slot, _)| {
            self.label()
                .contains_synthetic_representation(from_func, *slot)
        }) else {
            // there is nothing left to be realized, so prevent recursion and
            // avoid all the downstream allocations / checks / etc.

            // this optimization leads to a 70% overall speedup in complex runs

            return Some(self.clone());
        };

        let (from_slot, concrete) = substitutions[first_relevant];
        let remaining = &substitutions[first_relevant + 1..];

        // a function-valued capture can refer back to the closure whose
        // environment we are realizing, in which case its concrete backtrace
        // may contain the very capture placeholder being substituted. such a
        // placeholder represents a recursive dependency, not an additional
        // source: for the label equation `C = C ∪ X`, the least fixed point is
        // `X`, so we remove that recursive term before substitution so it
        // cannot be reintroduced into the realized result and escape its
        // respective function (which would be a bug)
        //
        // note that this applies only to captures: a parameter or call-site
        // branch can legitimately be realized with itself while summarizing a
        // recursive call; those placeholders must survive until the outermost
        // call site and so cannot be filtered out here
        let is_recursive_substitution = concrete.is_some_and(|concrete| {
            concrete
                .label()
                .tags()
                .any(|tag| tag.is_synthetic_representation(from_func, from_slot))
        });

        let concrete_without_recursive_capture = if matches!(from_slot, SyntheticSlot::Capture(_))
            && let Some(concrete) = concrete
            && is_recursive_substitution
        {
            Some(concrete.realize(from_func, from_slot, None))
        } else {
            None
        };

        // borrow checker would not let us mutate concrete directly, since we
        // may need to hold ownership for a new backtrace and concrete is a ref
        let concrete = concrete_without_recursive_capture
            .as_ref()
            .map_or(concrete, Option::as_ref);

        let label_without_slot: Label = self
            .label()
            .tags()
            .filter(|tag| !tag.is_synthetic_representation(from_func, from_slot))
            .cloned()
            .collect();

        let realized_label = concrete
            .map(|backtrace| backtrace.label() + &label_without_slot)
            .unwrap_or(label_without_slot);

        if realized_label == *self.label() {
            // recursive calls commonly substitute a parameter with a value
            // containing that same parameter synthetic. if the aggregate label
            // is unchanged, descending into the provenance tree only unfolds
            // the recursive equation without adding any information. retain
            // the compact fixed-point representation and continue with the
            // remaining, potentially meaningful substitutions
            return self.realize_all_inner(from_func, remaining, realize_aggregates);
        }

        if is_recursive_substitution && !matches!(from_slot, SyntheticSlot::Capture(_)) {
            // parameter, receiver, and branch synthetics must remain available
            // to the eventual outermost call, unlike capture recursion above.
            // rebuilding the fully expanded provenance tree here would unfold
            // the recursive equation once per convergence pass, so instead we
            // preserve the same label equation as a shallow tree of tag roots
            return self
                .flatten_to_label(realized_label)
                .expect("recursive substitutions include the non-Bottom concrete backtrace label")
                .realize_all_inner(from_func, remaining, realize_aggregates);
        }

        let param_or_capture = matches!(
            self.kind,
            LabelBacktraceKind::FunctionParameter | LabelBacktraceKind::ClosureCapture
        );

        if param_or_capture && self.label().as_single().is_some() {
            // note that since we already checked above with
            // is_synthetic_representation, if the label has a single tag,
            // then we are a root synthetic that needs to be realized

            let realized = Self::new(
                from_slot.realized_backtrace_kind(),
                concrete.map_or(&Label::Bottom, Self::label).clone(),
                self.symbol(),
                self.location().clone(),
                concrete,
            );

            realized?.realize_all_inner(from_func, remaining, realize_aggregates)
        } else if param_or_capture && (is_recursive_substitution || !realize_aggregates) {
            // `flatten_to_label` represents a recursive equation as a
            // multi-root aggregate. keep that aggregate compact while
            // summarizing the recursive call itself; an outer, concrete call
            // can descend into the roots and discharge each placeholder
            Some(self.clone())
        } else if matches!(self.kind, LabelBacktraceKind::Branch)
            && self.children.is_empty() // root
            && self.label().as_single().is_some()
        {
            // this is the function's synthetic implicit branch backtrace, which
            // needs to be realized into the actual call-site branch backtrace
            concrete
                .cloned()?
                .realize_all_inner(from_func, remaining, realize_aggregates)
        } else {
            let children: Vec<_> = self
                .children()
                .iter()
                .filter_map(|child| {
                    child.realize_all_inner(
                        from_func,
                        &substitutions[first_relevant..],
                        realize_aggregates,
                    )
                })
                .collect();

            Self::fold(
                &children,
                *self.kind(),
                self.symbol(),
                self.location().clone(),
            )
        }
    }

    /// Replaces the provenance hierarchy with one root per tag.
    ///
    /// This preserves the aggregate label and enough synthetic provenance for
    /// later realization without retaining paths that recursively refer back
    /// to the same substitution.
    ///
    /// Returns [`None`] if `label` is [`Label::Bottom`].
    fn flatten_to_label(&self, label: Label<'a>) -> Option<Self> {
        let roots: Vec<_> = label
            .tags()
            .cloned()
            .map(|tag| {
                let kind = match &tag {
                    // we cannot use SyntheticSlot::realized_backtrace_kind
                    // because these have not yet been realized
                    LabelTag::Synthetic { slot, .. } => match slot {
                        SyntheticSlot::Param(_) | SyntheticSlot::Receiver => {
                            LabelBacktraceKind::FunctionParameter
                        }
                        SyntheticSlot::Capture(_) => LabelBacktraceKind::ClosureCapture,
                        SyntheticSlot::CallSiteBranch | SyntheticSlot::YieldFeedback => {
                            LabelBacktraceKind::Branch
                        }
                    },
                    LabelTag::Concrete(_) | LabelTag::AxisWildcard(_) => self.kind,
                };

                Self::new_root(
                    kind,
                    Label::from_single(tag),
                    self.symbol,
                    self.location.clone(),
                )
                .unwrap() // a single-tag Label cannot be Bottom
            })
            .collect();

        Self::new(self.kind, label, self.symbol, self.location.clone(), &roots)
    }

    /// Remaps one function's synthetic tags to another function's slots.
    ///
    /// This applies recursively across the entire hierarchy. Parameter and
    /// invocation slots retain their indices, while capture indices are mapped
    /// explicitly because closures allocate them independently.
    pub(crate) fn remap_synthetics(
        &self,
        from_func: &FunctionRef<'a>,
        to_func: &FunctionRef<'a>,
        capture_slots: &BTreeMap<usize, usize>,
    ) -> Self {
        if self.children().is_empty() {
            let label = self
                .label
                .remap_synthetics(from_func, to_func, capture_slots);

            Self::new(
                *self.kind(),
                label,
                self.symbol,
                self.location.clone(),
                &*self.children,
            )
            .unwrap() // safe because self exists
        } else {
            let children: Vec<_> = self
                .children()
                .iter()
                .map(|child| child.remap_synthetics(from_func, to_func, capture_slots))
                .collect();

            Self::fold(
                &children,
                *self.kind(),
                self.symbol(),
                self.location().clone(),
            )
            .unwrap() // safe because children is non-empty (we checked)
        }
    }

    /// Returns a new instance whose label only contains tags in a given
    /// constraint, pruning children if they would have [`Label::Bottom`].
    #[must_use]
    pub(crate) fn restrict_to_label(&self, constraint: &Label<'a>) -> Option<Self> {
        if self.label.is_subset_of(constraint) {
            // we already meet this restriction, so prevent recursion and avoid
            // all the downstream allocations / intersections / etc.

            // this optimization leads to a 50% overall speedup in complex runs

            return Some(self.clone());
        }

        let new_label = self.label.intersect(constraint);

        if new_label.is_bottom() {
            return None;
        }

        let children = self
            .children
            .iter()
            .filter_map(|child| child.restrict_to_label(constraint))
            .collect();

        Some(Self::from_normalized_parts(
            self.kind,
            Arc::from(new_label),
            self.symbol,
            self.location.clone(),
            children,
        ))
    }

    /// Tries to mutate the present instance so that its label has certain tags
    /// removed, pruning children if they would have [`Label::Bottom`].
    ///
    /// This method returns `true` if the mutation is successful and `false` if
    /// the whole instance should be disregarded and should instead be replaced
    /// in its entirety with `None` (i.e., if it would have [`Label::Bottom`]).
    #[must_use]
    pub(crate) fn subtract_label(&mut self, subtract: &Label<'a>) -> bool {
        if subtract.is_bottom() {
            // nothing to do
            return true;
        }

        let constraint = self.label().difference(subtract);

        if constraint.is_bottom() {
            return false;
        }

        if let Some(new) = self.restrict_to_label(&constraint) {
            *self = new;

            true
        } else {
            false
        }
    }

    /// Returns the kind of operation that caused the label assignment.
    #[must_use]
    #[inline]
    pub fn kind(&self) -> &LabelBacktraceKind {
        &self.kind
    }

    /// Returns the label in question described by this backtrace.
    ///
    /// This is guaranteed to never be [`Label::Bottom`].
    #[must_use]
    #[inline]
    pub fn label(&self) -> &Label<'a> {
        &self.label
    }

    /// Returns the name of the symbol with this label, if any/applicable.
    #[must_use]
    #[inline]
    pub fn symbol(&self) -> Option<&'a str> {
        self.symbol
    }

    /// Returns the location where the operation took place.
    #[must_use]
    #[inline]
    pub fn location(&self) -> &Pinned<'a, Location> {
        &self.location
    }

    /// Returns the backtraces that compound to yield and justify this one.
    #[must_use]
    #[inline]
    pub fn children(&self) -> &[Self] {
        &self.children
    }

    // does not check nested children
    pub(crate) fn shallow_eq(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.label == other.label
            && self.symbol == other.symbol
            && self.location == other.location
    }

    // does not hash nested children
    pub(crate) fn shallow_hash<H: hash::Hasher>(&self, state: &mut H) {
        self.kind.hash(state);
        self.label.hash(state);
        self.symbol.hash(state);
        self.location.hash(state);
    }
}

/// The concrete operation that resulted in a label assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LabelBacktraceKind {
    /// Explicit source code annotation.
    ExplicitAnnotation,
    /// Explicit instruction derived from struct field tag in the source code.
    ExplicitFieldTag,
    /// Explicit blanket information source registered to the analyzer.
    BlanketSource,
    /// Assignment of some tainted expression to a variable.
    Assignment,
    /// Bootstrapping label from initialization expression in declaration.
    DeclarationInitialization,
    /// Compounded label derived from the parts of a composite expression.
    Expression,
    /// Implicit label from potential short-circuiting of a logical operation.
    ShortCircuit,
    /// Aggregate label implicitly inherited from surrounding control flows.
    Branch,
    /// Label originating from a value sent into a given channel.
    Send,
    /// Aggregate label for values received from a given channel.
    Receive,
    /// Synthetic label assigned to a declared parameter for taint analysis.
    FunctionParameter,
    /// Concrete label associated to argument binding at function invocation.
    FunctionArgument,
    /// Aggregate label for all arguments passed to a variadic parameter.
    FunctionVariadicAggregation,
    /// Concrete label associated to a method's receiver at the binding site.
    ///
    /// Conceptually, the receiver-flavored counterpart of
    /// [`LabelBacktraceKind::FunctionArgument`], used both when a synthetic
    /// receiver placeholder is realized at a call site and when a receiver's
    /// taint is propagated into a bound method value (e.g. `f := x.M`).
    MethodReceiver,
    /// Synthetic label assigned to a captured symbol shared with outer scope.
    ClosureCapture,
    /// Concrete label associated to a captured symbol at closure invocation.
    ///
    /// The realized counterpart of [`LabelBacktraceKind::ClosureCapture`],
    /// mirroring the [`LabelBacktraceKind::FunctionParameter`] <->
    /// [`LabelBacktraceKind::FunctionArgument`] pair.
    ClosureCaptureBinding,
    /// Individual label for one particular expression in a return statement.
    Return,
    /// Conservative label returned by a function without known implementation.
    BlackboxCall,
    /// Duplication from one slice to another via the `copy` built-in.
    SliceCopy,
    /// Removal of all of a slice/map's elements via the `clear` built-in.
    CollectionClear,
    /// Blocking further sends of a channel via the `close` built-in.
    ChannelClose,
    /// Removal of a map element via the `delete` built-in.
    MapElementDelete,
    /// Composite label derived from all factors relevant to flow evaluation.
    EnforcementAggregation,
}
