use std::borrow::Cow;

use parser::Location;

use crate::{
    Pinned,
    labels::{Label, LabelBacktrace, LabelBacktraceKind, SyntheticSlot},
    snapshots::SnapshotAware,
    values::{
        BacktraceContainer, FunctionRef, Mergeable, SelfAwareBacktraceContainer, Upgrade, ValueRef,
    },
};

// represents a Go channel reference (e.g. as produced by `make(chan T)`).
// the inner LabelBacktrace aggregates everything observable through the
// channel: values previously sent into it, plus the branch context of any
// `close` call, etc.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ChannelValue<'a>(Option<LabelBacktrace<'a>>);

impl<'a> ChannelValue<'a> {
    pub fn new(inner: Option<LabelBacktrace<'a>>) -> Self {
        Self(inner)
    }

    pub fn inner(&self) -> Option<&LabelBacktrace<'a>> {
        self.0.as_ref()
    }

    pub fn receive(&self, at_location: Pinned<'a, Location>) -> ValueRef<'a> {
        let received = self
            .inner()
            .cloned()
            .map(|bt| bt.into_single_child(LabelBacktraceKind::Receive, None, at_location.clone()));

        ValueRef::from_backtrace_or_bottom_at(received, || at_location)
    }
}

impl<'a> BacktraceContainer<'a> for ChannelValue<'a> {
    fn backtrace_at_location(&self, location: Pinned<'a, Location>) -> Option<LabelBacktrace<'a>> {
        self.0.backtrace_at_location(location)
    }

    fn is_bottom(&self) -> bool {
        self.0.is_bottom()
    }

    fn allows_lossless_downgrade(&self) -> bool {
        true
    }

    fn subtract_label(&mut self, subtract: &Label<'a>) {
        self.0.subtract_label(subtract);
    }
}

impl<'a> SelfAwareBacktraceContainer<'a> for ChannelValue<'a> {
    fn realize(
        &self,
        from_func: &FunctionRef<'a>,
        from_slot: SyntheticSlot,
        concrete: Option<&LabelBacktrace<'a>>,
    ) -> Self {
        Self::new(self.0.realize(from_func, from_slot, concrete))
    }

    fn nest_backtrace(
        &self,
        parent_kind: LabelBacktraceKind,
        parent_symbol: Option<&'a str>,
        parent_location: Pinned<'a, Location>,
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

impl<'a> Mergeable<'a> for ChannelValue<'a> {
    fn merge_with(
        &self,
        other: &Self,
        with_kind: LabelBacktraceKind,
        at_location: Cow<Pinned<'a, Location>>,
    ) -> Self {
        Self::new(self.0.merge_with(&other.0, with_kind, at_location))
    }
}

impl<'a> Upgrade<'a> for ChannelValue<'a> {
    fn upgrade(
        backtrace: Option<LabelBacktrace<'a>>,
        _location: Cow<Pinned<'a, Location>>,
    ) -> Self {
        Self::new(backtrace)
    }
}

impl SnapshotAware for ChannelValue<'_> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        self.0.snapshot_aware_eq(&other.0)
    }
}
