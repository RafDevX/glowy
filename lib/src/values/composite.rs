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
    // aggregate key backtrace
    keys: Option<LabelBacktrace<'a>>,
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
            keys: None,
            known_len: None,
        }
    }

    pub fn new(
        r#const: HashMap<K, ValueRef<'a>>,
        others: impl IntoIterator<Item = ValueRef<'a>>,
        keys: Option<LabelBacktrace<'a>>,
        known_len: Option<u64>,
        location: Pinned<'a, Location>,
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
            keys,
            known_len,
        }
    }

    pub fn known_len(&self) -> Option<u64> {
        self.known_len
    }

    pub fn len_backtrace(&self, location: Pinned<'a, Location>) -> Option<LabelBacktrace<'a>> {
        if self.known_len.is_some() {
            // if the length is statically known, values stored at constant keys
            // do not affect it, but dynamic and key backtraces still apply, as
            // they carry aggregate information introduced by control flow and
            // by keyed literals whose greatest index determines the length

            LabelBacktrace::combine_options(
                self.r#dyn.clone(),
                self.keys.clone(),
                LabelBacktraceKind::Expression,
                Cow::Owned(location),
            )
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

        let keys = self.keys.as_ref().map(|_| backtrace.clone());

        Self {
            r#const,
            r#dyn: Some(backtrace),
            dyn_overrides: HashSet::new(),
            keys,
            known_len: self.known_len,
        }
    }
}

impl<'a, K: Eq + Hash> BacktraceContainer<'a> for CompositeValue<'a, K> {
    fn backtrace_at_location(&self, location: Pinned<'a, Location>) -> Option<LabelBacktrace<'a>> {
        let children: Vec<_> = self
            .r#const
            .values()
            .filter_map(ValueRef::backtrace)
            .chain(self.r#dyn.clone())
            .chain(self.keys.clone())
            .collect();

        LabelBacktrace::fold(
            children.iter(),
            LabelBacktraceKind::Expression,
            None,
            location,
        )
    }

    fn is_bottom(&self) -> bool {
        if self.r#dyn.is_some() || self.keys.is_some() {
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
        self.keys.subtract_label(subtract);
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
        let keys = self.keys.realize(from_func, from_slot, concrete);

        Self {
            r#const,
            r#dyn,
            dyn_overrides: self.dyn_overrides.clone(),
            keys,
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

        let keys = self
            .keys
            .realize(from_func, from_slot, concrete.keys.as_ref());

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
            keys,
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
            parent_location.clone(),
            extra_children.clone()
        );

        let dyn_overrides = if has_extra_children {
            HashSet::new()
        } else {
            self.dyn_overrides.clone()
        };

        #[rustfmt::skip]
        let keys = self.keys.nest_backtrace(
            parent_kind,
            parent_symbol,
            parent_location,
            extra_children
        );

        Self {
            r#const,
            r#dyn,
            dyn_overrides,
            keys,
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

        let keys = self
            .keys
            .merge_with(&other.keys, with_kind, at_location.clone());

        // only retain length when both branches agree
        let known_len = match (self.known_len, other.known_len) {
            (Some(left), Some(right)) if left == right => Some(left),
            _ => None,
        };

        Self {
            r#const,
            r#dyn,
            dyn_overrides,
            keys,
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
            && self.keys.snapshot_aware_eq(&other.keys)
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
        mut value: ValueRef<'a>,
        key_backtrace: Option<LabelBacktrace<'a>>,
        at_location: Pinned<'a, Location>,
    ) {
        if key.is_none() {
            value = value.nest_backtrace(
                LabelBacktraceKind::Assignment,
                None,
                at_location.clone(),
                key_backtrace.clone(),
            );
        }

        if let Some(key) = key {
            self.set_at_known_key(key, value, at_location.clone());
        } else {
            self.set_at_unknown_key(&value, at_location.clone());
        }

        self.record_key_backtrace(key_backtrace, at_location);
    }

    fn record_key_backtrace(
        &mut self,
        backtrace: Option<LabelBacktrace<'a>>,
        at_location: Pinned<'a, Location>,
    );

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

    fn record_key_backtrace(
        &mut self,
        backtrace: Option<LabelBacktrace<'a>>,
        at_location: Pinned<'a, Location>,
    ) {
        self.keys = LabelBacktrace::combine_options(
            self.keys.clone(),
            backtrace,
            LabelBacktraceKind::Assignment,
            Cow::Owned(at_location),
        );
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

    fn record_key_backtrace(
        &mut self,
        backtrace: Option<LabelBacktrace<'a>>,
        at_location: Pinned<'a, Location>,
    ) {
        if backtrace.is_some() {
            self.dyn_overrides.clear();
        }

        self.r#dyn = LabelBacktrace::combine_options(
            self.r#dyn.clone(),
            backtrace,
            LabelBacktraceKind::Assignment,
            Cow::Owned(at_location),
        );
    }

    fn length_backtrace_at_location(
        &self,
        location: Pinned<'a, Location>,
    ) -> Option<LabelBacktrace<'a>> {
        self.len_backtrace(location)
    }
}
