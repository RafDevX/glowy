use std::{
    borrow::Cow,
    collections::{HashMap, hash_map::Entry},
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
}

impl<'a, K: Eq + Hash> CompositeValue<'a, K> {
    pub fn empty(r#dyn: Option<LabelBacktrace<'a>>) -> Self {
        Self {
            r#const: HashMap::new(),
            r#dyn,
        }
    }

    pub fn new(
        r#const: HashMap<K, ValueRef<'a>>,
        others: impl IntoIterator<Item = ValueRef<'a>>,
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

        Self { r#const, r#dyn }
    }

    pub fn clear(&mut self) {
        self.r#const = HashMap::new();
        self.r#dyn = None;
    }

    pub fn get_const(&self, key: &K, at_location: Pinned<'a, Location>) -> ValueRef<'a> {
        let value = match self.r#const.get(key).cloned() {
            Some(value) => value,
            None => ValueRef::new_bottom(at_location.clone(), None),
        };

        value
            .nest_backtrace(
                LabelBacktraceKind::Expression,
                None,
                at_location.clone(),
                self.r#dyn.clone(),
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

    pub fn set_const(&mut self, key: K, value: ValueRef<'a>) {
        self.r#const.insert(key, value);
    }

    // never overwrites
    pub fn set_dyn(&mut self, value: &ValueRef<'a>, at_location: Pinned<'a, Location>) {
        self.r#dyn = LabelBacktrace::combine_options(
            self.r#dyn.clone(),
            value.backtrace(),
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

        Self { r#const, r#dyn }
    }

    fn nest_backtrace(
        &self,
        parent_kind: LabelBacktraceKind,
        parent_symbol: Option<&'a str>,
        parent_location: Pinned<'a, Location>,
        extra_children: impl IntoIterator<Item = LabelBacktrace<'a>> + Clone,
    ) -> Self {
        let r#const = self.r#const.clone();

        #[rustfmt::skip]
        let r#dyn = self.r#dyn.nest_backtrace(
            parent_kind,
            parent_symbol,
            parent_location,
            extra_children
        );

        Self { r#const, r#dyn }
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

        Self { r#const, r#dyn }
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
}
