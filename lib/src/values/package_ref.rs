use parser::{Location, Span};

use crate::{
    Pinned,
    labels::{Label, LabelBacktrace, LabelBacktraceKind, SyntheticSlot},
    snapshots::SnapshotAware,
    values::{BacktraceContainer, FunctionRef, SelfAwareBacktraceContainer},
};

// represents a reference to another package by the name under which it was
// imported to this file -- this replaces the need for qualified identifiers,
// since `pkg.abc` becomes represented as a selection of "pseudo-field" `abc`
// on "pseudo-struct" `pkg` (which is actually a `PackageRefValue`).
// PackageRefValues are useless on their own and can only be used in selections.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PackageRefValue<'a>(Span<'a>);

impl<'a> PackageRefValue<'a> {
    pub fn new(qualifier: Span<'a>) -> Self {
        Self(qualifier)
    }

    pub fn qualifier(&self) -> Span<'a> {
        self.0
    }
}

impl<'a> BacktraceContainer<'a> for PackageRefValue<'a> {
    fn backtrace_at_location(&self, _location: Pinned<'a, Location>) -> Option<LabelBacktrace<'a>> {
        None
    }

    fn is_bottom(&self) -> bool {
        true
    }

    fn allows_lossless_downgrade(&self) -> bool {
        false
    }

    fn subtract_label(&mut self, _subtract: &Label<'a>) {
        // nothing to do
    }
}

impl<'a> SelfAwareBacktraceContainer<'a> for PackageRefValue<'a> {
    fn realize(
        &self,
        _from_func: &FunctionRef<'a>,
        _from_slot: SyntheticSlot,
        _concrete: Option<&LabelBacktrace<'a>>,
    ) -> Self {
        self.clone()
    }

    fn realize_all(
        &self,
        _from_func: &FunctionRef<'a>,
        _substitutions: &[(SyntheticSlot, Option<&LabelBacktrace<'a>>)],
    ) -> Self {
        self.clone()
    }

    fn nest_backtrace(
        &self,
        _parent_kind: LabelBacktraceKind,
        _parent_symbol: Option<&'a str>,
        _parent_location: Pinned<'a, Location>,
        _extra_children: impl IntoIterator<Item = LabelBacktrace<'a>> + Clone,
    ) -> Self {
        self.clone()
    }
}

impl SnapshotAware for PackageRefValue<'_> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
