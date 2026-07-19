use std::{
    borrow::Cow,
    cell::{Ref, RefMut},
    collections::HashMap,
};

use parser::Location;

use crate::{
    Pinned,
    labels::{Label, LabelBacktrace, LabelBacktraceKind, SyntheticSlot},
    snapshots::SnapshotAware,
    values::{
        BacktraceContainer, CompositeValue, CompositeValueAdapter, FunctionRef, Mergeable,
        SelfAwareBacktraceContainer, SimpleConstValue, Upgrade, Value, ValueRef,
    },
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SliceValue<'a> {
    // internal array-shaped backings sliced by this slice. a Vec is necessary
    // because control-flow merges can make several backing identities possible
    backings: Vec<SliceBacking<'a>>,
    start: SliceBound<'a>,
    end: SliceBound<'a>,
    maximum: SliceBound<'a>,
    access: Option<LabelBacktrace<'a>>,
    // revocation belongs to this descriptor, not to shared backing storage, as
    // declassifying one slice expression must not declassify all of its aliases
    revocation: Label<'a>,
}

impl<'a> SliceValue<'a> {
    pub fn new_allocated(
        composite: CompositeValue<'a, u64>,
        length: SliceBound<'a>,
        capacity: SliceBound<'a>,
        access: Option<LabelBacktrace<'a>>,
        location: Pinned<'a, Location>,
    ) -> Self {
        Self {
            backings: vec![SliceBacking::new(composite, location)],
            start: SliceBound::new(Some(0), None),
            end: length,
            maximum: capacity,
            access,
            revocation: Label::Bottom,
        }
    }

    pub fn new_from_composite(
        composite: CompositeValue<'a, u64>,
        location: Pinned<'a, Location>,
    ) -> Self {
        let length = SliceBound::new(
            composite.known_len(),
            composite.len_backtrace(location.clone()),
        );

        Self::new_allocated(composite, length.clone(), length, None, location)
    }

    pub fn read_at_index(
        &self,
        index: Option<u64>,
        location: Pinned<'a, Location>,
    ) -> ValueRef<'a> {
        let absolute = self
            .start
            .known
            .zip(index)
            .and_then(|(start, index)| start.checked_add(index));

        let boundary_backtrace = self.start.backtrace.clone();

        self.read_absolute(absolute, boundary_backtrace, location)
    }

    pub fn read_last(&self, location: Pinned<'a, Location>) -> ValueRef<'a> {
        // this is semantically equivalent to `s[len(s)-1]` but avoids tainting
        // with start's backtrace as it is canceled out in the absolute position

        let absolute = self.end.known.and_then(|end| end.checked_sub(1));

        self.read_absolute(absolute, self.end.backtrace.clone(), location)
    }

    fn read_absolute(
        &self,
        absolute: Option<u64>,
        boundary_backtrace: Option<LabelBacktrace<'a>>,
        location: Pinned<'a, Location>,
    ) -> ValueRef<'a> {
        let dependency = LabelBacktrace::combine_options(
            self.access.clone(),
            boundary_backtrace,
            LabelBacktraceKind::Expression,
            Cow::Owned(location.clone()),
        );

        let precise_key = absolute.filter(|_| dependency.is_none());

        self.backings
            .iter()
            .map(|backing| backing.read(precise_key, location.clone()))
            .reduce(|left, right| {
                left.merge_with(
                    &right,
                    LabelBacktraceKind::Expression,
                    Cow::Borrowed(&location),
                )
            })
            .unwrap_or_else(|| ValueRef::new_bottom(location.clone(), None))
            .nest_backtrace(LabelBacktraceKind::Expression, None, location, dependency)
            .and_subtract_label(&self.revocation)
    }

    fn write_at_index(
        &mut self,
        index: Option<u64>,
        value: ValueRef<'a>,
        location: Pinned<'a, Location>,
    ) {
        let absolute = self
            .start
            .known
            .zip(index)
            .and_then(|(start, index)| start.checked_add(index));

        let dependency = LabelBacktrace::fold(
            [self.access.as_ref(), self.start.backtrace.as_ref()]
                .into_iter()
                .flatten(),
            LabelBacktraceKind::Assignment,
            None,
            location.clone(),
        );

        if let [single_backing] = self.backings.as_slice()
            && dependency.is_none()
            && let Some(absolute) = absolute
        {
            single_backing.write(Some(absolute), value, Cow::Owned(location));
        } else {
            let value = value.nest_backtrace(
                LabelBacktraceKind::Assignment,
                None,
                location.clone(),
                dependency,
            );

            for backing in &self.backings {
                backing.write(None, value.clone(), Cow::Borrowed(&location));
            }
        }
    }

    fn known_len(&self) -> Option<u64> {
        let (end, start) = self.end.known.zip(self.start.known)?;

        end.checked_sub(start)
    }

    fn precise_len(&self) -> Option<u64> {
        let (start, end) = self.precise_range()?;

        Some(end - start)
    }

    pub fn len_backtrace(&self, location: Pinned<'a, Location>) -> Option<LabelBacktrace<'a>> {
        self.bound_difference_backtrace(&self.end, location)
    }

    pub fn cap_backtrace(&self, location: Pinned<'a, Location>) -> Option<LabelBacktrace<'a>> {
        self.bound_difference_backtrace(&self.maximum, location)
    }

    fn bound_difference_backtrace(
        &self,
        upper: &SliceBound<'a>,
        location: Pinned<'a, Location>,
    ) -> Option<LabelBacktrace<'a>> {
        LabelBacktrace::fold(
            [
                self.access.as_ref(),
                self.start.backtrace.as_ref(),
                upper.backtrace.as_ref(),
            ]
            .into_iter()
            .flatten(),
            LabelBacktraceKind::Expression,
            None,
            location,
        )
    }

    fn precise_range(&self) -> Option<(u64, u64)> {
        if self.access.is_none() && self.start.backtrace.is_none() && self.end.backtrace.is_none() {
            let (start, end) = self.start.known.zip(self.end.known)?;

            (start <= end).then_some((start, end))
        } else {
            None
        }
    }

    pub fn range_element(&self, location: Pinned<'a, Location>) -> ValueRef<'a> {
        let value = self.read_at_index(None, location.clone());

        value.nest_backtrace(
            LabelBacktraceKind::Expression,
            None,
            location,
            self.end.backtrace.clone(),
        )
    }

    pub fn push(&mut self, value: ValueRef<'a>, location: &Pinned<'a, Location>) {
        let dependency = LabelBacktrace::fold(
            [
                self.access.as_ref(),
                self.end.backtrace.as_ref(),
                self.maximum.backtrace.as_ref(),
            ]
            .into_iter()
            .flatten(),
            LabelBacktraceKind::Assignment,
            None,
            location.clone(),
        );

        if let Some((end, maximum)) = self.end.known.zip(self.maximum.known) {
            if end >= maximum {
                self.allocate_for_append(value, location);

                return;
            }

            if dependency.is_none()
                && let [single_backing] = self.backings.as_slice()
            {
                single_backing.write(Some(end), value, Cow::Borrowed(location));

                self.end.known = end.checked_add(1);

                return;
            }
        }

        let value = value.nest_backtrace(
            LabelBacktraceKind::Assignment,
            None,
            location.clone(),
            dependency,
        );

        for backing in &self.backings {
            backing.write(None, value.clone(), Cow::Borrowed(location));
        }

        self.end.known = self.end.known.and_then(|end| end.checked_add(1));
    }

    fn allocate_for_append(&mut self, value: ValueRef<'a>, location: &Pinned<'a, Location>) {
        let old_len = self.known_len();
        let new_len = old_len.and_then(|length| length.checked_add(1));

        let composite = if let Some((mut copied, precise_old_len)) =
            self.copy_precise_range_for_append(new_len, location)
        {
            copied.set_const(precise_old_len, value);

            copied
        } else {
            let old_value = ValueRef::from_backtrace_or_bottom_at(
                self.backtrace_at_location(location.clone()),
                || location.clone(),
            );

            // a sensitive or unknown start can select any backing element, so
            // retaining particular old entries here would be unsound. keep
            // their aggregate dependency, but strongly update the appended
            // element when its relative index is known: allocation gives us a
            // fresh backing, so that position cannot contain an old element
            let mut others = vec![old_value];

            if old_len.is_none() {
                others.push(value.clone());
            }

            let mut composite = CompositeValue::new(
                HashMap::new(), // no const; old flattened into dyn
                others,
                None,
                new_len,
                location.clone(),
            );

            if let Some(old_len) = old_len {
                composite.set_const(old_len, value);
            }

            composite
        };

        let length = SliceBound::new(new_len, self.len_backtrace(location.clone()));

        // `append` keeps the same underlying (backing) array if there is enough
        // capacity, but if we need to allocate (i.e., this function), then Go
        // spec specifies that a new backing array is used instead
        self.backings = vec![SliceBacking::new(composite, location.clone())];
        self.start = SliceBound::new(Some(0), None);
        self.end = length.clone();
        self.maximum = SliceBound::new(None, length.backtrace.clone());
        self.access = None;
    }

    fn copy_precise_range_for_append(
        &self,
        new_len: Option<u64>,
        location: &Pinned<'a, Location>,
    ) -> Option<(CompositeValue<'a, u64>, u64)> {
        // the end bound determines how many elements are copied, but a known
        // end remains exact even when its provenance is labeled. in contrast,
        // a labeled start is an element-selection dependency and must not be
        // used to retain entries at particular backing indices
        if self.access.is_some() || self.start.backtrace.is_some() {
            return None;
        }

        let old_len = self.known_len()?;
        let (start, end) = self.start.known.zip(self.end.known)?;

        let copied = self
            .backings
            .iter()
            .map(|backing| backing.copy_reindexed_range(start, end, new_len))
            .reduce(|left, right| {
                left.merge_with(
                    &right,
                    LabelBacktraceKind::Expression,
                    Cow::Borrowed(location),
                )
            })?;

        Some((copied, old_len))
    }

    pub fn extend(
        &mut self,
        source: Option<&Self>,
        source_value: &ValueRef<'a>,
        location: &Pinned<'a, Location>,
    ) {
        if let Some(source) = source
            && let Some(length) = source.precise_len()
        {
            // read before writing because source and destination may overlap
            let values: Vec<_> = (0..length)
                .map(|index| source.read_at_index(Some(index), location.clone()))
                .collect();

            for value in values {
                self.push(value, location);
            }

            return;
        }

        let source_len = match source {
            Some(source) => source.len_backtrace(location.clone()),
            None => source_value.backtrace(),
        };

        let old_end = self.end.clone();

        // the appended value represents an element of the source, not the
        // source slice descriptor itself. preserving the outer slice here can
        // also create a cycle when source and destination overlap: the value
        // written into a backing array then contains that same backing, and
        // calculating its aggregate backtrace recursively borrows the backing
        // while it is already mutably borrowed for the write
        let source_element = source.map_or_else(
            || source_value.clone_inner(),
            |source| source.range_element(location.clone()),
        );

        let value = source_element.nest_backtrace(
            LabelBacktraceKind::Assignment,
            None,
            location.clone(),
            [
                self.access.clone(),
                old_end.backtrace.clone(),
                self.maximum.backtrace.clone(),
                source_len.clone(),
            ]
            .into_iter()
            .flatten(),
        );

        for backing in &self.backings {
            backing.write(None, value.clone(), Cow::Borrowed(location));
        }

        self.end.known = old_end
            .known
            .zip(source.and_then(Self::known_len))
            .and_then(|(end, length)| end.checked_add(length));

        self.end.backtrace = LabelBacktrace::combine_options(
            old_end.backtrace,
            source_len,
            LabelBacktraceKind::Expression,
            Cow::Borrowed(location),
        );

        self.maximum.known = None;
        self.maximum.backtrace = LabelBacktrace::combine_options(
            self.maximum.backtrace.clone(),
            self.end.backtrace.clone(),
            LabelBacktraceKind::Expression,
            Cow::Borrowed(location),
        );
    }

    pub fn copy_from(
        &mut self,
        source: Option<&Self>,
        source_value: &ValueRef<'a>,
        branch_backtrace: Option<&LabelBacktrace<'a>>,
        location: &Pinned<'a, Location>,
    ) {
        if branch_backtrace.is_none()
            && let Some(source) = source
            && let Some(length) = self
                .precise_len()
                .zip(source.precise_len())
                .map(|(dst, src)| dst.min(src))
        {
            // Go spec allows copying with overlapping source and destination
            // slices, so we snapshot all source elements before mutating any
            // potentially-shared backing storage
            let copied: Vec<_> = (0..length)
                .map(|index| {
                    source
                        .read_at_index(Some(index), location.clone())
                        .nest_backtrace(LabelBacktraceKind::SliceCopy, None, location.clone(), [])
                })
                .collect();

            for (index, value) in (0..length).zip(copied) {
                self.write_at_index(Some(index), value, location.clone());
            }
        } else {
            // unknown ranges may copy any source element to any destination
            // position, and a branch-dependent copy might not execute, so it
            // must retain the old destination. in both cases, weakly add the
            // source aggregate rather than overwriting any existing element
            let copied = source_value.nest_backtrace(
                LabelBacktraceKind::SliceCopy,
                None,
                location.clone(),
                branch_backtrace.cloned(),
            );

            let aggregate = copied.nest_backtrace(
                LabelBacktraceKind::Assignment,
                None,
                location.clone(),
                self.range_dependency(LabelBacktraceKind::Assignment, location.clone()),
            );

            for backing in &self.backings {
                backing.write(None, aggregate.clone(), Cow::Borrowed(location));
            }
        }
    }

    pub fn clear(&mut self, location: &Pinned<'a, Location>) {
        let dependency = self.range_dependency(LabelBacktraceKind::Assignment, location.clone());

        if let [single_backing] = self.backings.as_slice()
            && dependency.is_none()
        {
            if let (Some(start), Some(end)) = (self.start.known, self.end.known) {
                for index in start..end {
                    single_backing.write(
                        Some(index),
                        ValueRef::new_bottom(location.clone(), None),
                        Cow::Borrowed(location),
                    );
                }
            }
        } else {
            // retain the old contents (weak update), but record which elements
            // were cleared when the range or backing identity is sensitive
            let zero = ValueRef::new_bottom(location.clone(), None).nest_backtrace(
                LabelBacktraceKind::Assignment,
                None,
                location.clone(),
                dependency,
            );

            for backing in &self.backings {
                backing.write(None, zero.clone(), Cow::Borrowed(location));
            }
        }
    }

    fn range_dependency(
        &self,
        kind: LabelBacktraceKind,
        location: Pinned<'a, Location>,
    ) -> Option<LabelBacktrace<'a>> {
        LabelBacktrace::fold(
            [
                self.access.as_ref(),
                self.start.backtrace.as_ref(),
                self.end.backtrace.as_ref(),
            ]
            .into_iter()
            .flatten(),
            kind,
            None,
            location,
        )
    }

    pub fn copy_shape(&self, backtrace: LabelBacktrace<'a>) -> Self {
        Self {
            backings: self
                .backings
                .iter()
                .map(|backing| backing.copy_shape(backtrace.clone()))
                .collect(),
            start: SliceBound::new(self.start.known, Some(backtrace.clone())),
            end: SliceBound::new(self.end.known, Some(backtrace.clone())),
            maximum: SliceBound::new(self.maximum.known, Some(backtrace.clone())),
            access: Some(backtrace),
            revocation: self.revocation.clone(),
        }
    }

    pub fn reslice(
        &self,
        low: Option<SliceBound<'a>>,
        high: Option<SliceBound<'a>>,
        maximum: Option<SliceBound<'a>>,
        location: Pinned<'a, Location>,
    ) -> Self {
        let start = low.map_or_else(
            || self.start.clone(),
            |low| self.start.add(&low, location.clone()),
        );

        let end = high.map_or_else(
            || self.end.clone(),
            |high| self.start.add(&high, location.clone()),
        );

        let maximum = maximum.map_or_else(
            || self.maximum.clone(),
            |maximum| self.start.add(&maximum, location),
        );

        Self {
            backings: self.backings.clone(),
            start,
            end,
            maximum,
            access: self.access.clone(),
            revocation: self.revocation.clone(),
        }
    }
}

impl<'a> BacktraceContainer<'a> for SliceValue<'a> {
    fn backtrace_at_location(&self, location: Pinned<'a, Location>) -> Option<LabelBacktrace<'a>> {
        let precise_range = self.precise_range();

        let backing_backtraces: Vec<_> = self
            .backings
            .iter()
            .filter_map(|backing| {
                if let Some((start, end)) = precise_range {
                    backing.element_backtrace_in_range(start, end, location.clone())
                } else {
                    backing.backtrace_at_location(location.clone())
                }
            })
            .collect();

        LabelBacktrace::fold(
            backing_backtraces
                .iter()
                .chain(&self.access)
                .chain(&self.start.backtrace)
                .chain(&self.end.backtrace)
                .chain(&self.maximum.backtrace),
            LabelBacktraceKind::Expression,
            None,
            location,
        )
        .and_subtract_label(&self.revocation)
    }

    fn is_bottom(&self) -> bool {
        self.access.is_none()
            && self.start.backtrace.is_none()
            && self.end.backtrace.is_none()
            && self.maximum.backtrace.is_none()
            && self.backings.iter().all(SliceBacking::is_bottom)
    }

    fn allows_lossless_downgrade(&self) -> bool {
        false
    }

    fn subtract_label(&mut self, subtract: &Label<'a>) {
        self.access.subtract_label(subtract);
        self.start.subtract_label(subtract);
        self.end.subtract_label(subtract);
        self.maximum.subtract_label(subtract);
        self.revocation = &self.revocation + subtract;
    }
}

impl<'a> SelfAwareBacktraceContainer<'a> for SliceValue<'a> {
    fn realize(
        &self,
        from_func: &FunctionRef<'a>,
        from_slot: SyntheticSlot,
        concrete: Option<&LabelBacktrace<'a>>,
    ) -> Self {
        Self {
            backings: self
                .backings
                .iter()
                .map(|backing| backing.realize(from_func, from_slot, concrete))
                .collect(),
            start: self.start.realize(from_func, from_slot, concrete),
            end: self.end.realize(from_func, from_slot, concrete),
            maximum: self.maximum.realize(from_func, from_slot, concrete),
            access: self.access.realize(from_func, from_slot, concrete),
            revocation: self.revocation.clone(),
        }
    }

    fn nest_backtrace(
        &self,
        parent_kind: LabelBacktraceKind,
        parent_symbol: Option<&'a str>,
        parent_location: Pinned<'a, Location>,
        extra_children: impl IntoIterator<Item = LabelBacktrace<'a>> + Clone,
    ) -> Self {
        Self {
            backings: self.backings.clone(),
            start: self
                .start
                .nest_backtrace(parent_kind, parent_symbol, parent_location.clone()),
            end: self
                .end
                .nest_backtrace(parent_kind, parent_symbol, parent_location.clone()),
            maximum: self.maximum.nest_backtrace(
                parent_kind,
                parent_symbol,
                parent_location.clone(),
            ),
            access: self.access.nest_backtrace(
                parent_kind,
                parent_symbol,
                parent_location,
                extra_children,
            ),
            revocation: self.revocation.clone(),
        }
    }
}

impl<'a> Mergeable<'a> for SliceValue<'a> {
    fn merge_with(
        &self,
        other: &Self,
        with_kind: LabelBacktraceKind,
        at_location: Cow<Pinned<'a, Location>>,
    ) -> Self {
        let mut backings = self.backings.clone();

        for candidate in &other.backings {
            if !backings
                .iter()
                .any(|backing| backing.shares_inner_with(candidate))
            {
                backings.push(candidate.clone());
            }
        }

        Self {
            backings,
            start: self
                .start
                .merge_with(&other.start, with_kind, at_location.clone()),
            end: self
                .end
                .merge_with(&other.end, with_kind, at_location.clone()),
            maximum: self
                .maximum
                .merge_with(&other.maximum, with_kind, at_location.clone()),
            access: self
                .access
                .merge_with(&other.access, with_kind, at_location),
            revocation: self.revocation.intersect(&other.revocation),
        }
    }
}

impl<'a> CompositeValueAdapter<'a> for SliceValue<'a> {
    fn get_at_known_key(
        &self,
        key: &SimpleConstValue,
        at_location: Pinned<'a, Location>,
    ) -> ValueRef<'a> {
        self.read_at_index(extract_integer_index(key), at_location)
    }

    fn get_at_unknown_key(&self, at_location: Pinned<'a, Location>) -> ValueRef<'a> {
        self.read_at_index(None, at_location)
    }

    fn set_at_known_key(
        &mut self,
        key: SimpleConstValue,
        value: ValueRef<'a>,
        at_location: Pinned<'a, Location>,
    ) {
        self.write_at_index(extract_integer_index(&key), value, at_location);
    }

    fn set_at_unknown_key(&mut self, value: &ValueRef<'a>, at_location: Pinned<'a, Location>) {
        self.write_at_index(None, value.clone(), at_location);
    }

    fn record_key_backtrace(
        &mut self,
        _backtrace: Option<LabelBacktrace<'a>>,
        _location: Pinned<'a, Location>,
    ) {
        // the adapter's default set_at_key nests an unknown key's backtrace
        // into the weakly written value. unlike a map's key set, an index does
        // not affect a slice descriptor, so there is nothing else to record
    }

    fn length_backtrace_at_location(
        &self,
        location: Pinned<'a, Location>,
    ) -> Option<LabelBacktrace<'a>> {
        self.len_backtrace(location)
    }
}

fn extract_integer_index(key: &SimpleConstValue) -> Option<u64> {
    match key {
        SimpleConstValue::Integer(index) => Some(*index),
        SimpleConstValue::Boolean(_) | SimpleConstValue::String(_) | SimpleConstValue::Nil => None,
    }
}

impl<'a> Upgrade<'a> for SliceValue<'a> {
    fn upgrade(backtrace: Option<LabelBacktrace<'a>>, location: Cow<Pinned<'a, Location>>) -> Self {
        Self::new_allocated(
            CompositeValue::empty(backtrace.clone()),
            SliceBound::new(None, backtrace.clone()),
            SliceBound::new(None, backtrace.clone()),
            backtrace.clone(),
            location.into_owned(),
        )
    }
}

impl SnapshotAware for SliceValue<'_> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        self.start.known == other.start.known
            && self.end.known == other.end.known
            && self.maximum.known == other.maximum.known
            && self
                .start
                .backtrace
                .snapshot_aware_eq(&other.start.backtrace)
            && self.end.backtrace.snapshot_aware_eq(&other.end.backtrace)
            && self
                .maximum
                .backtrace
                .snapshot_aware_eq(&other.maximum.backtrace)
            && self.access.snapshot_aware_eq(&other.access)
            && self.revocation == other.revocation
            && self.backings.len() == other.backings.len()
            && self
                .backings
                .iter()
                .zip(&other.backings)
                .all(|(left, right)| left.snapshot_aware_eq(right))
    }
}

// wrapper to allow custom methods; inner Value is always Array
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SliceBacking<'a>(ValueRef<'a>);

impl<'a> SliceBacking<'a> {
    fn new(composite: CompositeValue<'a, u64>, location: Pinned<'a, Location>) -> Self {
        Self(ValueRef::new(Value::Array(composite), location, None))
    }

    fn as_array(&self) -> Ref<'_, CompositeValue<'a, u64>> {
        self.0
            .as_array()
            .expect("slice backing storage must be array-shaped")
    }

    fn as_array_mut(&self) -> RefMut<'_, CompositeValue<'a, u64>> {
        self.0
            .as_array_mut()
            .expect("slice backing storage must be array-shaped")
    }

    fn read(&self, key: Option<u64>, location: Pinned<'a, Location>) -> ValueRef<'a> {
        let array = self.as_array();

        match key {
            Some(key) => array.get_const(&key, location),
            None => array.get_dyn(location),
        }
    }

    fn write(&self, key: Option<u64>, value: ValueRef<'a>, location: Cow<Pinned<'a, Location>>) {
        let mut array = self.as_array_mut();

        if let Some(key) = key {
            array.set_const(key, value);
        } else {
            array.set_dyn(&value, location.into_owned());
        }
    }

    fn shares_inner_with(&self, other: &Self) -> bool {
        self.0.shares_inner_with(&other.0)
    }

    fn is_bottom(&self) -> bool {
        self.0.is_bottom()
    }

    fn backtrace_at_location(&self, location: Pinned<'a, Location>) -> Option<LabelBacktrace<'a>> {
        self.0.backtrace_at_location(location)
    }

    fn copy_shape(&self, backtrace: LabelBacktrace<'a>) -> Self {
        Self(self.0.copy_shape(backtrace))
    }

    fn realize(
        &self,
        from_func: &FunctionRef<'a>,
        from_slot: SyntheticSlot,
        concrete: Option<&LabelBacktrace<'a>>,
    ) -> Self {
        Self(self.0.realize(from_func, from_slot, concrete))
    }

    fn element_backtrace_in_range(
        &self,
        start: u64,
        end: u64,
        location: Pinned<'a, Location>,
    ) -> Option<LabelBacktrace<'a>> {
        self.as_array()
            .element_backtrace_in_range(start, end, location)
    }

    fn copy_reindexed_range(
        &self,
        start: u64,
        end: u64,
        known_len: Option<u64>,
    ) -> CompositeValue<'a, u64> {
        self.as_array().copy_reindexed_range(start, end, known_len)
    }
}

impl SnapshotAware for SliceBacking<'_> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        self.0.snapshot_aware_eq(&other.0)
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SliceBound<'a> {
    known: Option<u64>,
    backtrace: Option<LabelBacktrace<'a>>,
}

impl<'a> SliceBound<'a> {
    pub fn new(known: Option<u64>, backtrace: Option<LabelBacktrace<'a>>) -> Self {
        Self { known, backtrace }
    }

    pub fn into_backtrace(self) -> Option<LabelBacktrace<'a>> {
        self.backtrace
    }

    fn add(&self, other: &Self, location: Pinned<'a, Location>) -> Self {
        let known = self
            .known
            .zip(other.known)
            .and_then(|(left, right)| left.checked_add(right));

        let backtrace = LabelBacktrace::combine_options(
            self.backtrace.clone(),
            other.backtrace.clone(),
            LabelBacktraceKind::Expression,
            Cow::Owned(location),
        );

        Self::new(known, backtrace)
    }

    fn realize(
        &self,
        from_func: &FunctionRef<'a>,
        from_slot: SyntheticSlot,
        concrete: Option<&LabelBacktrace<'a>>,
    ) -> Self {
        Self::new(
            self.known,
            self.backtrace.realize(from_func, from_slot, concrete),
        )
    }

    fn nest_backtrace(
        &self,
        parent_kind: LabelBacktraceKind,
        parent_symbol: Option<&'a str>,
        parent_location: Pinned<'a, Location>,
    ) -> Self {
        Self::new(
            self.known,
            self.backtrace
                .nest_backtrace(parent_kind, parent_symbol, parent_location, []),
        )
    }

    fn subtract_label(&mut self, subtract: &Label<'a>) {
        self.backtrace.subtract_label(subtract);
    }
}

impl<'a> Mergeable<'a> for SliceBound<'a> {
    fn merge_with(
        &self,
        other: &Self,
        with_kind: LabelBacktraceKind,
        at_location: Cow<Pinned<'a, Location>>,
    ) -> Self {
        let known = if self.known == other.known {
            self.known
        } else {
            None
        };

        let backtrace = self
            .backtrace
            .merge_with(&other.backtrace, with_kind, at_location);

        Self::new(known, backtrace)
    }
}
