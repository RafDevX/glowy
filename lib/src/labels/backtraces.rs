use std::{borrow::Cow, iter, sync::Arc};

use parser::Location;

use crate::{
    Pinned,
    labels::{FunctionRef, Label, SyntheticSlot},
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

        // if there is only one child
        if let [child] = &*children
            && *child.label == label
            && child.location == location
            && child.symbol == symbol
        {
            // avoid unnecessary repeated backtraces that just make everything more complex;
            // for example, in the example below:
            // ```go
            // // glowy::label::{high}
            // var a = 3
            // ```
            // we just want ExplicitAnnotation and not also Assignment another level up
            return Some(child.clone());
        }

        let label = Arc::from(label);

        Some(Self {
            kind,
            label,
            symbol,
            location,
            children,
        })
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

    /// Constructs a new instance with self as its only child, avoiding cloning.
    pub(crate) fn into_single_child(
        self,
        parent_kind: LabelBacktraceKind,
        parent_symbol: Option<&'a str>,
        parent_location: Pinned<'a, Location>,
    ) -> Self {
        // note that we're not using Self::new to avoid cloning self and to skip
        // unnecessary checks / label optimizations -- we already know this
        // label isn't Bottom + cannot be compacted further because self exists
        Self {
            kind: parent_kind,
            label: Arc::clone(&self.label),
            symbol: parent_symbol,
            location: parent_location,
            children: Arc::from([self]),
        }
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
        let concrete_without_recursive_capture = if matches!(from_slot, SyntheticSlot::Capture(_))
            && let Some(concrete) = concrete
            && concrete
                .label()
                .tags()
                .any(|tag| tag.is_synthetic_representation(from_func, from_slot))
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

        if matches!(
            self.kind,
            LabelBacktraceKind::FunctionParameter | LabelBacktraceKind::ClosureCapture
        ) {
            if self.label().as_single().is_some() {
                // note that since we already checked above with
                // is_synthetic_representation, if the label has a single tag,
                // then we are a root synthetic that needs to be realized

                let realized = Self::new(
                    from_slot.label_backtrace_kind(),
                    concrete.map_or(&Label::Bottom, Self::label).clone(),
                    self.symbol(),
                    self.location().clone(),
                    concrete,
                );

                realized?.realize_all(from_func, remaining)
            } else {
                Some(self.clone())
            }
        } else if matches!(self.kind, LabelBacktraceKind::Branch)
            && self.children.is_empty() // root
            && self.label().as_single().is_some()
        {
            // this is the function's synthetic implicit branch backtrace, which
            // needs to be realized into the actual call-site branch backtrace
            concrete.cloned()?.realize_all(from_func, remaining)
        } else {
            let children: Vec<_> = self
                .children()
                .iter()
                .filter_map(|child| child.realize_all(from_func, &substitutions[first_relevant..]))
                .collect();

            Self::fold(
                &children,
                *self.kind(),
                self.symbol(),
                self.location().clone(),
            )
        }
    }

    /// Rebinds all [`LabelTag::Synthetic`]s from one function to another.
    ///
    /// This applies recursively across the entire hierarchy, affecting only
    /// synthetic tags associated with the specified initial function.
    pub(crate) fn rebind_synthetic_func(
        &self,
        from_func: &FunctionRef<'a>,
        to_func: &FunctionRef<'a>,
    ) -> Self {
        if self.children().is_empty() {
            Self::new(
                *self.kind(),
                self.label.rebind_synthetic_func(from_func, to_func),
                self.symbol,
                self.location.clone(),
                &*self.children,
            )
            .unwrap() // safe because self exists
        } else {
            let children: Vec<_> = self
                .children()
                .iter()
                .map(|child| child.rebind_synthetic_func(from_func, to_func))
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
    fn restrict_to_label(&self, constraint: &Label<'a>) -> Option<Self> {
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

        Some(Self {
            kind: self.kind,
            label: Arc::from(new_label),
            symbol: self.symbol,
            location: self.location.clone(),
            children: self
                .children
                .iter()
                .filter_map(|child| child.restrict_to_label(constraint))
                .collect(),
        })
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
}

/// The concrete operation that resulted in a label assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
