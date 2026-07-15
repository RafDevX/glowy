use std::{
    borrow::Cow,
    collections::{HashMap, HashSet, hash_map::Entry},
    hash::Hash,
};

use parser::Location;

use crate::{
    Pinned,
    labels::{Label, LabelBacktrace, LabelBacktraceKind, SyntheticSlot},
    snapshots::SnapshotAware,
    values::{
        BacktraceContainer, FunctionRef, Mergeable, SelfAwareBacktraceContainer, SimpleConstValue,
        Upgrade, ValueRef,
    },
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CompositeValue<'a, K: Eq + Hash> {
    // known values at constant keys
    r#const: HashMap<K, ValueRef<'a>>,
    // overall backtrace affecting the entire structure, from dynamic sets, etc.
    r#dyn: Option<LabelBacktrace<'a>>,
    // exact keys strongly updated after the current dynamic state was produced
    // (helps to allow better precision and be less conservative when safe)
    dyn_overrides: HashSet<K>,
    // exact length, when statically known. only meaningful for slice-shaped
    // (u64-keyed) composites; conservatively collapsed to None when unknown
    known_len: Option<u64>,
}

impl<'a, K: Eq + Hash> CompositeValue<'a, K> {
    pub fn empty(r#dyn: Option<LabelBacktrace<'a>>) -> Self {
        Self {
            r#const: HashMap::new(),
            r#dyn,
            dyn_overrides: HashSet::new(),
            known_len: None,
        }
    }

    pub fn new(
        r#const: HashMap<K, ValueRef<'a>>,
        others: impl IntoIterator<Item = ValueRef<'a>>,
        location: Pinned<'a, Location>,
        known_len: Option<u64>,
    ) -> Self {
        let children: Vec<_> = others
            .into_iter()
            .filter_map(|value| value.backtrace())
            .collect();

        let r#dyn = LabelBacktrace::fold(
            children.iter(),
            LabelBacktraceKind::Expression,
            None,
            location,
        );

        Self {
            r#const,
            r#dyn,
            dyn_overrides: HashSet::new(),
            known_len,
        }
    }

    pub fn clear(&mut self) {
        self.r#const = HashMap::new();
        self.r#dyn = None;
        self.dyn_overrides.clear();
        // known_len is preserved since copy/clear doesn't change the underlying
        // slice's size, only its elements are reset to their zero-values
    }

    pub fn known_len(&self) -> Option<u64> {
        self.known_len
    }

    pub fn len_backtrace(&self, location: Pinned<'a, Location>) -> Option<LabelBacktrace<'a>> {
        if self.known_len.is_some() {
            // if the length is statically known, values stored at constant keys
            // do not affect it, but the dynamic backtrace still applies, as it
            // carries aggregate information introduced by control flow and
            // assignments that could have had an influence on the length

            self.r#dyn.backtrace_at_location(location)
        } else {
            // if the exact length is unknown, we have to be conservative

            self.backtrace_at_location(location)
        }
    }

    pub fn get_const(&self, key: &K, at_location: Pinned<'a, Location>) -> ValueRef<'a> {
        let value = match self.r#const.get(key).cloned() {
            Some(value) => value,
            None => ValueRef::new_bottom(at_location.clone(), None),
        };

        let dynamic_backtrace = (!self.dyn_overrides.contains(key))
            .then(|| self.r#dyn.clone())
            .flatten();

        value
            .nest_backtrace(
                LabelBacktraceKind::Expression,
                None,
                at_location.clone(),
                dynamic_backtrace,
            )
            .with_location(at_location)
    }

    pub fn get_dyn(&self, at_location: Pinned<'a, Location>) -> ValueRef<'a> {
        // since we don't know the concrete key, we must take the union of all
        // possibilities, i.e., all entries of const

        // for simplicity, we re-use the backtrace_at_location logic already
        // implemented elsewhere

        ValueRef::from_backtrace_or_bottom_at(
            self.backtrace_at_location(at_location.clone()),
            || at_location,
        )
    }

    pub fn set_const(&mut self, key: K, value: ValueRef<'a>)
    where
        // note: this function's `K: Clone` constraint is necessary to avoid
        // interning dyn_overrides into `r#const` by having it be a map from K
        // to `ConstEntry { value: ValueRef<'a>, overrides_dyn: bool }`, since
        // that would make the code more complex and would require traversing
        // `r#const` every time we now just do `self.dyn_overrides.clear()`.
        // this constraint is fine since right now all possible CompositeValue
        // keys are Clone, but in the future this can be re-assessed if a
        // non-Clone key must be supported (and `set_const` available for it)
        K: Clone,
    {
        self.r#const.insert(key.clone(), value);
        self.dyn_overrides.insert(key);
    }

    // never overwrites
    pub fn set_dyn(&mut self, value: &ValueRef<'a>, at_location: Pinned<'a, Location>) {
        let backtrace = value.backtrace();

        if backtrace.is_some() {
            // we're re-calculating the dyn backtrace, so overrides don't make
            // sense anymore, as they only represent const updates pending
            // between dyn backtrace updates
            self.dyn_overrides.clear();
        }

        self.r#dyn = LabelBacktrace::combine_options(
            self.r#dyn.clone(),
            backtrace,
            LabelBacktraceKind::Assignment,
            Cow::Owned(at_location),
        );
    }
}

impl<'a, K: Eq + Hash + Clone> CompositeValue<'a, K> {
    pub fn copy_shape(&self, backtrace: LabelBacktrace<'a>) -> Self {
        let r#const = self
            .r#const
            .iter()
            .map(|(k, v)| (k.clone(), v.copy_shape(backtrace.clone())))
            .collect();

        Self {
            r#const,
            r#dyn: Some(backtrace),
            dyn_overrides: HashSet::new(),
            known_len: self.known_len,
        }
    }
}

// slice-shaped (u64-keyed) specific operations. these mirror `append(s, x)`
// and `append(s, xs...)` on slice values, exploiting `known_len` to place the
// appended elements at their exact indices whenever that length is available
impl<'a> CompositeValue<'a, u64> {
    // append a single element
    pub fn push(
        &mut self,
        value: ValueRef<'a>,
        at_location: impl FnOnce() -> Pinned<'a, Location>,
    ) {
        if let Some(length) = self.known_len {
            // place the value at the exact index
            self.set_const(length, value);

            // grow length
            self.known_len = Some(length.saturating_add(1));
        } else {
            // degrade to r#dyn (sound but coarse)
            self.set_dyn(&value, at_location());
        }
    }

    pub fn extend(
        &mut self,
        src_slice: Option<Self>,
        src_value: &ValueRef<'a>,
        at_location: Pinned<'a, Location>,
    ) {
        if let Some(src) = src_slice
            && let Some(self_len) = self.known_len
            && let Some(src_len) = src.known_len
        {
            // both have known lengths, so be smart about it

            #[expect(clippy::iter_over_hash_type, reason = "Mutation order is irrelevant")]
            for (k, v) in &src.r#const {
                // set_const overwrites existing values, but that should be fine
                // since self's positions in the extended range of
                // [self_len, self_len + src_len[ were previously blank
                // (any reads there would have returned Bottom + dyn)
                self.set_const(self_len.saturating_add(*k), v.clone());
            }

            // fold src's dyn (which conservatively models reads at unknown
            // positions in other) into self's dyn. this over-taints self's
            // original portion but is still strictly more precise than the
            // alternative of set_dyn'ing src's aggregate backtrace (which would
            // additionally fold every const value's label into self's dyn)
            self.r#dyn = LabelBacktrace::combine_options(
                self.r#dyn.clone(),
                src.r#dyn.clone(),
                LabelBacktraceKind::Assignment,
                Cow::Owned(at_location),
            );

            if src.r#dyn.is_some() {
                self.dyn_overrides.clear();
            }

            self.known_len = Some(self_len.saturating_add(src_len));
        } else {
            // degrade to r#dyn (sound but coarse)
            self.set_dyn(src_value, at_location);
        }
    }
}

impl<'a, K: Eq + Hash + Ord> CompositeValue<'a, K> {
    pub fn slice_const(
        &self,
        low: Option<&K>,
        high: Option<&K>,
        at_location: Pinned<'a, Location>,
    ) -> Option<LabelBacktrace<'a>> {
        let children: Vec<_> = self
            .r#const
            .iter()
            .filter(|(k, _)| low.as_ref().is_none_or(|l| *k >= l))
            .filter(|(k, _)| high.as_ref().is_none_or(|h| *k < h))
            .map(|(_, v)| v)
            .filter_map(ValueRef::backtrace)
            .chain(self.r#dyn.clone())
            .collect();

        LabelBacktrace::fold(&children, LabelBacktraceKind::Expression, None, at_location)
    }

    pub fn slice_dyn(&self, at_location: Pinned<'a, Location>) -> Option<LabelBacktrace<'a>> {
        self.backtrace_at_location(at_location)
    }
}

impl<'a, K: Eq + Hash> BacktraceContainer<'a> for CompositeValue<'a, K> {
    fn backtrace_at_location(&self, location: Pinned<'a, Location>) -> Option<LabelBacktrace<'a>> {
        let children: Vec<_> = self
            .r#const
            .values()
            .filter_map(ValueRef::backtrace)
            .chain(self.r#dyn.clone())
            .collect();

        LabelBacktrace::fold(
            children.iter(),
            LabelBacktraceKind::Expression,
            None,
            location,
        )
    }

    fn is_bottom(&self) -> bool {
        if self.r#dyn.is_some() {
            false
        } else {
            self.r#const.iter().all(|(_, v)| v.is_bottom())
        }
    }

    fn allows_lossless_downgrade(&self) -> bool {
        self.r#const
            .values()
            .all(|v| v.is_bottom() && v.allows_lossless_downgrade())
    }

    fn subtract_label(&mut self, subtract: &Label<'a>) {
        if subtract.is_bottom() {
            // nothing to do; return early since otherwise this is expensive
            return;
        }

        #[expect(clippy::iter_over_hash_type, reason = "Independent mutation")]
        for value in self.r#const.values_mut() {
            value.subtract_label(subtract);
        }

        self.r#dyn.subtract_label(subtract);
    }
}

impl<'a, K: Eq + Hash + Clone> SelfAwareBacktraceContainer<'a> for CompositeValue<'a, K> {
    fn realize(
        &self,
        from_func: &FunctionRef<'a>,
        from_slot: SyntheticSlot,
        concrete: Option<&LabelBacktrace<'a>>,
    ) -> Self {
        let r#const = self
            .r#const
            .iter()
            .map(|(k, v)| (k.clone(), v.realize(from_func, from_slot, concrete)))
            .collect();

        let r#dyn = self.r#dyn.realize(from_func, from_slot, concrete);

        Self {
            r#const,
            r#dyn,
            dyn_overrides: self.dyn_overrides.clone(),
            known_len: self.known_len,
        }
    }

    // for precision; avoid flattening all components into one backtrace
    fn realize_with_shape_preservation(
        &self,
        from_func: &FunctionRef<'a>,
        from_slot: SyntheticSlot,
        concrete: &Self,
        concrete_location: Pinned<'a, Location>,
    ) -> Self {
        let contains_slot = self
            .backtrace_at_location(concrete_location)
            .as_ref()
            .map(LabelBacktrace::label)
            .is_some_and(|label| label.contains_synthetic_representation(from_func, from_slot));

        if !contains_slot {
            // slot doesn't exist, so concrete doesn't matter
            return self.realize(from_func, from_slot, None);
        }

        let mut r#const = concrete.r#const.clone();

        #[expect(
            clippy::iter_over_hash_type,
            reason = "Each key is realized independently; order is irrelevant"
        )]
        for (key, template_value) in &self.r#const {
            let concrete_value = concrete.get_const(key, template_value.location().clone());

            #[rustfmt::skip]
            let realized = template_value.realize_with_shape_preservation(
                from_func,
                from_slot,
                &concrete_value,
                concrete_value.location().clone(),
            );

            r#const.insert(key.clone(), realized);
        }

        let r#dyn = self
            .r#dyn
            .realize(from_func, from_slot, concrete.r#dyn.as_ref());

        let mut dyn_overrides = self.dyn_overrides.clone();

        if self
            .r#dyn
            .as_ref()
            .map(LabelBacktrace::label)
            .is_some_and(|label| label.is_synthetic_representation(from_func, from_slot))
        {
            // if our synthetic is the sole dynamic tag, no mutation occurred
            // since copy_shape, so overrides can be retained
            dyn_overrides.extend(concrete.dyn_overrides.iter().cloned());
        }

        let known_len = if self.known_len == concrete.known_len {
            self.known_len
        } else {
            // be conservative; it would be unsound to pick either len
            None
        };

        Self {
            r#const,
            r#dyn,
            dyn_overrides,
            known_len,
        }
    }

    fn nest_backtrace(
        &self,
        parent_kind: LabelBacktraceKind,
        parent_symbol: Option<&'a str>,
        parent_location: Pinned<'a, Location>,
        extra_children: impl IntoIterator<Item = LabelBacktrace<'a>> + Clone,
    ) -> Self {
        let r#const = self.r#const.clone();

        let has_extra_children = extra_children.clone().into_iter().next().is_some();

        #[rustfmt::skip]
        let r#dyn = self.r#dyn.nest_backtrace(
            parent_kind,
            parent_symbol,
            parent_location,
            extra_children
        );

        let dyn_overrides = if has_extra_children {
            HashSet::new()
        } else {
            self.dyn_overrides.clone()
        };

        Self {
            r#const,
            r#dyn,
            dyn_overrides,
            known_len: self.known_len,
        }
    }
}

impl<'a, K: Eq + Hash + Clone> Mergeable<'a> for CompositeValue<'a, K> {
    fn merge_with(
        &self,
        other: &Self,
        with_kind: LabelBacktraceKind,
        at_location: Cow<Pinned<'a, Location>>,
    ) -> Self {
        let mut r#const = self.r#const.clone();

        #[expect(
            clippy::iter_over_hash_type,
            reason = "Order is irrelevant; result is still deterministic"
        )]
        for (k, v) in &other.r#const {
            match r#const.entry(k.clone()) {
                Entry::Occupied(mut occupied) => {
                    let merged = occupied.get().merge_with(v, with_kind, at_location.clone());

                    occupied.insert(merged);
                }
                Entry::Vacant(vacant) => {
                    vacant.insert(v.clone());
                }
            }
        }

        let r#dyn = self
            .r#dyn
            .merge_with(&other.r#dyn, with_kind, at_location.clone());

        // a key is independent of the merged dynamic state only when its value
        // supersedes that state along every incoming control-flow path
        let dyn_overrides = self
            .dyn_overrides
            .intersection(&other.dyn_overrides)
            .cloned()
            .collect();

        // only retain length when both branches agree
        let known_len = match (self.known_len, other.known_len) {
            (Some(left), Some(right)) if left == right => Some(left),
            _ => None,
        };

        Self {
            r#const,
            r#dyn,
            dyn_overrides,
            known_len,
        }
    }
}

impl<'a, K: Eq + Hash> Upgrade<'a> for CompositeValue<'a, K> {
    fn upgrade(
        backtrace: Option<LabelBacktrace<'a>>,
        _location: Cow<Pinned<'a, Location>>,
    ) -> Self {
        Self::empty(backtrace)
    }
}

// assumes K: !SnapshotAware (i.e., it's a primitive irrelevant to this logic)
// (Rust negative trait bounds are unsupported, so we cannot enforce it)
impl<K: Eq + Hash> SnapshotAware for CompositeValue<'_, K> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        self.r#dyn.snapshot_aware_eq(&other.r#dyn)
            && self.r#const.len() == other.r#const.len()
            && self.r#const.snapshot_aware_eq(&other.r#const)
            && self.dyn_overrides == other.dyn_overrides
            && self.known_len == other.known_len
    }
}

// this is necessary because rust doesn't support using some dynamic type
// CompositeValue<'a, ?> in function return values and etc., but we want to
// re-use code for similar logic whenever possible while maintaining typing
// guarantees for integer-keyed composite values
// Method names are different than CompositeValue's for clarity and prevent
// confusion on whether a call refers to the struct's own method or this trait.
// See clippy::same_name_method
pub trait CompositeValueAdapter<'a>: BacktraceContainer<'a> {
    fn get_at_known_key(
        &self,
        key: &SimpleConstValue,
        at_location: Pinned<'a, Location>,
    ) -> ValueRef<'a>;

    fn get_at_unknown_key(&self, at_location: Pinned<'a, Location>) -> ValueRef<'a>;

    fn set_at_known_key(
        &mut self,
        key: SimpleConstValue,
        value: ValueRef<'a>,
        at_location: Pinned<'a, Location>,
    );

    fn set_at_unknown_key(&mut self, value: &ValueRef<'a>, at_location: Pinned<'a, Location>);

    fn get_at_key(
        &self,
        key: Option<&SimpleConstValue>,
        at_location: Pinned<'a, Location>,
    ) -> ValueRef<'a> {
        if let Some(key) = key {
            self.get_at_known_key(key, at_location)
        } else {
            self.get_at_unknown_key(at_location)
        }
    }

    fn set_at_key(
        &mut self,
        key: Option<SimpleConstValue>,
        value: ValueRef<'a>,
        at_location: Pinned<'a, Location>,
    ) {
        if let Some(key) = key {
            self.set_at_known_key(key, value, at_location);
        } else {
            self.set_at_unknown_key(&value, at_location);
        }
    }

    fn length_backtrace_at_location(
        &self,
        location: Pinned<'a, Location>,
    ) -> Option<LabelBacktrace<'a>>;
}

// trivial implementation
impl<'a> CompositeValueAdapter<'a> for CompositeValue<'a, SimpleConstValue> {
    fn get_at_known_key(
        &self,
        key: &SimpleConstValue,
        at_location: Pinned<'a, Location>,
    ) -> ValueRef<'a> {
        self.get_const(key, at_location)
    }

    fn get_at_unknown_key(&self, at_location: Pinned<'a, Location>) -> ValueRef<'a> {
        self.get_dyn(at_location)
    }

    fn set_at_known_key(
        &mut self,
        key: SimpleConstValue,
        value: ValueRef<'a>,
        _at_location: Pinned<'a, Location>,
    ) {
        self.set_const(key, value);
    }

    fn set_at_unknown_key(&mut self, value: &ValueRef<'a>, at_location: Pinned<'a, Location>) {
        self.set_dyn(value, at_location);
    }

    fn length_backtrace_at_location(
        &self,
        location: Pinned<'a, Location>,
    ) -> Option<LabelBacktrace<'a>> {
        self.len_backtrace(location)
    }
}

// integer key adapter
impl<'a> CompositeValueAdapter<'a> for CompositeValue<'a, u64> {
    fn get_at_known_key(
        &self,
        key: &SimpleConstValue,
        at_location: Pinned<'a, Location>,
    ) -> ValueRef<'a> {
        if let SimpleConstValue::Integer(key) = key {
            self.get_const(key, at_location)
        } else {
            self.get_dyn(at_location)
        }
    }

    fn get_at_unknown_key(&self, at_location: Pinned<'a, Location>) -> ValueRef<'a> {
        self.get_dyn(at_location)
    }

    fn set_at_known_key(
        &mut self,
        key: SimpleConstValue,
        value: ValueRef<'a>,
        at_location: Pinned<'a, Location>,
    ) {
        if let SimpleConstValue::Integer(key) = key {
            self.set_const(key, value);
        } else {
            self.set_dyn(&value, at_location);
        }
    }

    fn set_at_unknown_key(&mut self, value: &ValueRef<'a>, at_location: Pinned<'a, Location>) {
        self.set_dyn(value, at_location);
    }

    fn length_backtrace_at_location(
        &self,
        location: Pinned<'a, Location>,
    ) -> Option<LabelBacktrace<'a>> {
        self.len_backtrace(location)
    }
}
