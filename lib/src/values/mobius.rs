use std::{borrow::Cow, collections::BTreeMap};

use parser::Location;

use crate::{
    Pinned,
    labels::{Label, LabelBacktrace, LabelBacktraceKind, SyntheticSlot},
    snapshots::SnapshotAware,
    values::{
        BacktraceContainer, FunctionRef, Mergeable, SelfAwareBacktraceContainer, Upgrade, ValueRef,
    },
};

// represents a value of unknown, adaptable cardinality -- similar to an
// ExpandableValue, but more flexible, able to become any number of the same
// inner value, in a sort of illusion like a Möbius strip
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MobiusValue<'a> {
    inner: ValueRef<'a>,
    // sometimes, we know that specific indexes have another value
    overrides: BTreeMap<usize, ValueRef<'a>>,
}

impl<'a> MobiusValue<'a> {
    pub fn new(inner: ValueRef<'a>) -> Self {
        Self {
            inner,
            overrides: BTreeMap::new(),
        }
    }

    fn value_at(&self, index: usize) -> &ValueRef<'a> {
        self.overrides.get(&index).unwrap_or(&self.inner)
    }

    pub fn inner(&self) -> &ValueRef<'a> {
        self.value_at(0)
    }

    pub fn expand_to(&self, len: usize) -> Vec<ValueRef<'a>> {
        (0..len).map(|index| self.value_at(index).clone()).collect()
    }

    pub(super) fn nest_override_expand_indices(
        &self,
        indices: impl IntoIterator<Item = usize>,
        nest_with_kind: LabelBacktraceKind,
        nest_with_symbol: Option<&'a str>,
        nest_with_location: &Pinned<'a, Location>,
        extra_children: &[LabelBacktrace<'a>],
    ) -> Self {
        let mut nested = self.clone();

        for index in indices {
            let value = nested.value_at(index).nest_backtrace(
                nest_with_kind,
                nest_with_symbol,
                nest_with_location.clone(),
                extra_children.iter().cloned(),
            );

            nested.overrides.insert(index, value);
        }

        nested
    }

    pub(super) fn subtract_override_expand_indices(
        &self,
        indices: impl IntoIterator<Item = usize>,
        subtract: &Label<'a>,
    ) -> Self {
        let mut subtracted = self.clone();

        for index in indices {
            let mut value = subtracted.value_at(index).clone_inner();

            value.subtract_label(subtract);

            subtracted.overrides.insert(index, value);
        }

        subtracted
    }
}

impl<'a> BacktraceContainer<'a> for MobiusValue<'a> {
    fn backtrace_at_location(&self, location: Pinned<'a, Location>) -> Option<LabelBacktrace<'a>> {
        self.inner().backtrace_at_location(location)
    }

    fn is_bottom(&self) -> bool {
        self.inner.is_bottom() && self.overrides.values().all(ValueRef::is_bottom)
    }

    fn allows_lossless_downgrade(&self) -> bool {
        self.overrides.keys().all(|index| *index == 0)
    }

    fn subtract_label(&mut self, subtract: &Label<'a>) {
        self.inner.subtract_label(subtract);

        for value in self.overrides.values_mut() {
            value.subtract_label(subtract);
        }
    }
}

impl<'a> SelfAwareBacktraceContainer<'a> for MobiusValue<'a> {
    fn realize(
        &self,
        from_func: &FunctionRef<'a>,
        from_slot: SyntheticSlot,
        concrete: Option<&LabelBacktrace<'a>>,
    ) -> Self {
        let inner = self.inner.realize(from_func, from_slot, concrete);
        let overrides = self
            .overrides
            .iter()
            .map(|(index, value)| (*index, value.realize(from_func, from_slot, concrete)))
            .collect();

        Self { inner, overrides }
    }

    fn realize_all(
        &self,
        from_func: &FunctionRef<'a>,
        substitutions: &[(SyntheticSlot, Option<&LabelBacktrace<'a>>)],
    ) -> Self {
        let inner = self.inner.realize_all(from_func, substitutions);
        let overrides = self
            .overrides
            .iter()
            .map(|(index, value)| (*index, value.realize_all(from_func, substitutions)))
            .collect();

        Self { inner, overrides }
    }

    fn nest_backtrace(
        &self,
        parent_kind: LabelBacktraceKind,
        parent_symbol: Option<&'a str>,
        parent_location: Pinned<'a, Location>,
        extra_children: impl IntoIterator<Item = LabelBacktrace<'a>> + Clone,
    ) -> Self {
        let overrides = self
            .overrides
            .iter()
            .map(|(index, value)| {
                let value = value.nest_backtrace(
                    parent_kind,
                    parent_symbol,
                    parent_location.clone(),
                    extra_children.clone(),
                );

                (*index, value)
            })
            .collect();

        #[rustfmt::skip]
        let inner = self.inner.nest_backtrace(
            parent_kind,
            parent_symbol,
            parent_location,
            extra_children
        );

        Self { inner, overrides }
    }
}

impl<'a> Mergeable<'a> for MobiusValue<'a> {
    fn merge_with(
        &self,
        other: &Self,
        with_kind: LabelBacktraceKind,
        at_location: Cow<Pinned<'a, Location>>,
    ) -> Self {
        let inner = self
            .inner
            .merge_with(&other.inner, with_kind, at_location.clone());

        let mut overrides = BTreeMap::new();

        for index in self.overrides.keys().chain(other.overrides.keys()) {
            if overrides.contains_key(index) {
                continue;
            }

            let value = self.value_at(*index).merge_with(
                other.value_at(*index),
                with_kind,
                at_location.clone(),
            );

            overrides.insert(*index, value);
        }

        Self { inner, overrides }
    }
}

impl<'a> Upgrade<'a> for MobiusValue<'a> {
    fn upgrade(backtrace: Option<LabelBacktrace<'a>>, location: Cow<Pinned<'a, Location>>) -> Self {
        let inner = ValueRef::from_backtrace_or_bottom_at(backtrace, || location.into_owned());

        Self::new(inner)
    }
}

impl SnapshotAware for MobiusValue<'_> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        self.inner.snapshot_aware_eq(&other.inner)
            && self.overrides.snapshot_aware_eq(&other.overrides)
    }
}
