use std::{borrow::Cow, cmp, iter};

use parser::Location;

use crate::{
    Pinned,
    labels::{Label, LabelBacktrace, LabelBacktraceKind, SyntheticSlot},
    snapshots::SnapshotAware,
    values::{
        BacktraceContainer, FunctionRef, Mergeable, SelfAwareBacktraceContainer, Upgrade, ValueRef,
    },
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExpandableValue<'a> {
    primary: ValueRef<'a>,
    secondary: Vec<ValueRef<'a>>,
    // ^ secondary may be used if multiple values are needed; else, just primary
}

impl<'a> ExpandableValue<'a> {
    pub fn new(primary: ValueRef<'a>, secondary: Vec<ValueRef<'a>>) -> Self {
        Self { primary, secondary }
    }

    pub fn primary(&self) -> ValueRef<'a> {
        self.primary.clone()
    }

    pub fn expand(&self) -> Vec<ValueRef<'a>> {
        iter::once(self.primary.clone())
            .chain(self.secondary.iter().cloned())
            .collect()
    }
}

impl<'a> BacktraceContainer<'a> for ExpandableValue<'a> {
    fn backtrace_at_location(&self, location: Pinned<'a, Location>) -> Option<LabelBacktrace<'a>> {
        let backtraces: Vec<LabelBacktrace<'a>> = iter::once(&self.primary)
            .chain(self.secondary.iter())
            .filter_map(ValueRef::backtrace)
            .collect();

        LabelBacktrace::fold(
            backtraces.iter(),
            LabelBacktraceKind::Expression,
            None,
            location,
        )
    }

    fn is_bottom(&self) -> bool {
        iter::once(&self.primary)
            .chain(self.secondary.iter())
            .all(BacktraceContainer::is_bottom)
    }

    fn allows_lossless_downgrade(&self) -> bool {
        self.secondary
            .iter()
            .all(|v| v.is_bottom() && v.allows_lossless_downgrade())
    }

    fn subtract_label(&mut self, subtract: &Label<'a>) {
        self.primary.subtract_label(subtract);

        for value in &mut self.secondary {
            value.subtract_label(subtract);
        }
    }
}

impl<'a> SelfAwareBacktraceContainer<'a> for ExpandableValue<'a> {
    fn realize(
        &self,
        from_func: &FunctionRef<'a>,
        from_slot: SyntheticSlot,
        concrete: Option<&LabelBacktrace<'a>>,
    ) -> Self {
        let primary = self.primary.realize(from_func, from_slot, concrete);

        let secondary = self
            .secondary
            .iter()
            .map(|v| v.realize(from_func, from_slot, concrete))
            .collect();

        Self { primary, secondary }
    }

    fn nest_backtrace(
        &self,
        parent_kind: LabelBacktraceKind,
        parent_symbol: Option<&'a str>,
        parent_location: Pinned<'a, Location>,
        extra_children: impl IntoIterator<Item = LabelBacktrace<'a>> + Clone,
    ) -> Self {
        let primary = self.primary.nest_backtrace(
            parent_kind,
            parent_symbol,
            parent_location.clone(),
            extra_children.clone(),
        );

        let secondary = self
            .secondary
            .iter()
            .map(|v| {
                v.nest_backtrace(
                    parent_kind,
                    parent_symbol,
                    parent_location.clone(),
                    extra_children.clone(),
                )
            })
            .collect();

        Self { primary, secondary }
    }
}

impl<'a> Mergeable<'a> for ExpandableValue<'a> {
    fn merge_with(
        &self,
        other: &Self,
        with_kind: LabelBacktraceKind,
        at_location: Cow<Pinned<'a, Location>>,
    ) -> Self {
        let primary = self
            .primary
            .merge_with(&other.primary, with_kind, at_location.clone());

        let max_len = cmp::max(self.secondary.len(), other.secondary.len());
        let mut secondary = Vec::with_capacity(max_len);

        // cannot use zip since one of the vectors might be longer
        for i in 0..max_len {
            let merged = match (self.secondary.get(i), other.secondary.get(i)) {
                (None, None) => unreachable!(),
                (Some(single), None) | (None, Some(single)) => single.clone(),
                (Some(a), Some(b)) => a.merge_with(b, with_kind, at_location.clone()),
            };

            secondary.push(merged);
        }

        Self::new(primary, secondary)
    }
}

impl<'a> Upgrade<'a> for ExpandableValue<'a> {
    fn upgrade(backtrace: Option<LabelBacktrace<'a>>, location: Cow<Pinned<'a, Location>>) -> Self {
        let primary = ValueRef::from_backtrace_or_bottom_at(backtrace, || location.into_owned());

        Self::new(primary, Vec::new())
    }
}

impl SnapshotAware for ExpandableValue<'_> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        self.primary.snapshot_aware_eq(&other.primary)
            && self.secondary.snapshot_aware_eq(&other.secondary)
    }
}
