use std::borrow::Cow;

use parser::Location;

use crate::{
    Pinned,
    labels::{LabelBacktrace, LabelBacktraceKind},
    snapshots::SnapshotAware,
    values::{
        BacktraceContainer, FunctionRef, Mergeable, SelfAwareBacktraceContainer, Upgrade, ValueRef,
    },
};

// represents a value of unknown, adaptable cardinality -- similar to an
// ExpandableValue, but more flexible, able to become any number of the same
// inner value, in a sort of illusion like a Möbius strip.
// (this struct by itself is very simple; its real purpose is just to
// semantically tag a value as needing some leniency when being treated)
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MobiusValue<'a>(ValueRef<'a>);

impl<'a> MobiusValue<'a> {
    pub fn new(inner: ValueRef<'a>) -> Self {
        Self(inner)
    }

    pub fn inner(&self) -> &ValueRef<'a> {
        &self.0
    }

    pub fn expand_to(&self, len: usize) -> Vec<ValueRef<'a>> {
        // note that vec! will just clone the ValueRef, but the underlying Value
        // is the same for all elements; only the references are cloned (cheap)
        vec![self.0.clone(); len]
    }
}

impl<'a> BacktraceContainer<'a> for MobiusValue<'a> {
    fn backtrace_at_location(&self, location: Pinned<Location>) -> Option<LabelBacktrace<'a>> {
        self.0.backtrace_at_location(location)
    }

    fn is_bottom(&self) -> bool {
        self.0.is_bottom()
    }

    fn allows_lossless_downgrade(&self) -> bool {
        true
    }
}

impl<'a> SelfAwareBacktraceContainer<'a> for MobiusValue<'a> {
    fn realize(
        &self,
        from_func: &FunctionRef<'a>,
        from_index: Option<usize>,
        concrete: Option<&LabelBacktrace<'a>>,
    ) -> Self {
        Self::new(self.0.realize(from_func, from_index, concrete))
    }

    fn nest_backtrace(
        &self,
        parent_kind: LabelBacktraceKind,
        parent_symbol: Option<&'a str>,
        parent_location: Pinned<Location>,
        extra_children: impl IntoIterator<Item = LabelBacktrace<'a>> + Clone,
    ) -> Self {
        Self::new(self.0.nest_backtrace(
            parent_kind,
            parent_symbol,
            parent_location,
            extra_children,
        ))
    }
}

impl Mergeable for MobiusValue<'_> {
    fn merge_with(
        &self,
        other: &Self,
        with_kind: LabelBacktraceKind,
        at_location: Cow<Pinned<Location>>,
    ) -> Self {
        Self::new(self.0.merge_with(&other.0, with_kind, at_location))
    }
}

impl<'a> Upgrade<'a> for MobiusValue<'a> {
    fn upgrade(backtrace: Option<LabelBacktrace<'a>>, location: Cow<Pinned<Location>>) -> Self {
        let inner = ValueRef::from_backtrace_or_bottom_at(backtrace, || location.into_owned());

        Self::new(inner)
    }
}

impl SnapshotAware for MobiusValue<'_> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        self.0.snapshot_aware_eq(&other.0)
    }
}
