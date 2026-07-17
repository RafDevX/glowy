use std::{borrow::Cow, cell::RefCell, rc::Rc};

use parser::Location;

use crate::{
    Pinned,
    labels::{Label, LabelBacktrace, LabelBacktraceKind, SyntheticSlot},
    snapshots::SnapshotAware,
    values::{
        BacktraceContainer, FunctionRef, Mergeable, SelfAwareBacktraceContainer, Upgrade, ValueRef,
    },
};

#[derive(Clone, Debug)]
pub struct ChannelValue<'a> {
    // a Vec is necessary because control-flow merges can produce multiple
    // possible channel identities
    allocations: Vec<Rc<ChannelAllocation<'a>>>,
    // aggregate for an identity-free alternative or effects awaiting binding to
    // concrete allocations. Bottom means every alternative has known identity
    unbound: ChannelAggregate<'a>,
}

impl<'a> ChannelValue<'a> {
    pub fn new(inner: Option<LabelBacktrace<'a>>) -> Self {
        Self {
            allocations: Vec::new(),
            unbound: ChannelAggregate::new_uniform(inner),
        }
    }

    pub fn new_allocated(
        initial: Option<LabelBacktrace<'a>>,
        location: Pinned<'a, Location>,
    ) -> Self {
        Self {
            allocations: vec![Rc::new(ChannelAllocation {
                allocation_site: location,
                aggregate: RefCell::new(ChannelAggregate::new_uniform(initial)),
            })],
            unbound: ChannelAggregate::new_bottom(),
        }
    }

    pub fn send(
        &mut self,
        payload: Option<LabelBacktrace<'a>>,
        control: Option<LabelBacktrace<'a>>,
        location: &Pinned<'a, Location>,
    ) {
        self.record(payload, control, LabelBacktraceKind::Send, location);
    }

    pub fn close(&mut self, control: Option<LabelBacktrace<'a>>, location: &Pinned<'a, Location>) {
        self.record(None, control, LabelBacktraceKind::ChannelClose, location);
    }

    pub fn record_receive(&mut self, control: LabelBacktrace<'a>, location: &Pinned<'a, Location>) {
        self.record(None, Some(control), LabelBacktraceKind::Receive, location);
    }

    fn record(
        &mut self,
        payload: Option<LabelBacktrace<'a>>,
        control: Option<LabelBacktrace<'a>>,
        kind: LabelBacktraceKind,
        location: &Pinned<'a, Location>,
    ) {
        let effect = ChannelAggregate::new(payload, control);

        for allocation in &self.allocations {
            allocation.merge_effect(&effect, kind, location);
        }

        self.unbound = self
            .unbound
            .merge_with(&effect, kind, Cow::Borrowed(location));
    }

    pub fn receive(&self, location: &Pinned<'a, Location>) -> (ValueRef<'a>, ValueRef<'a>) {
        let state_count = self.allocations.len() + usize::from(!self.unbound.is_bottom());
        let capacity = 2 * state_count;
        let mut value_backtraces = Vec::with_capacity(capacity);
        let mut success_backtraces = Vec::with_capacity(state_count);

        let mut append = |aggregate: &ChannelAggregate<'a>| {
            value_backtraces.extend(aggregate.iter().cloned());
            success_backtraces.extend(aggregate.control().into_iter().cloned());
        };

        for allocation in &self.allocations {
            append(&allocation.aggregate.borrow());
        }

        append(&self.unbound);

        let fold = |parts: &[LabelBacktrace<'a>]| {
            let backtrace = LabelBacktrace::fold(
                parts.iter(),
                LabelBacktraceKind::Receive,
                None,
                location.clone(),
            );

            ValueRef::from_backtrace_or_bottom_at(backtrace, || location.clone())
        };

        (fold(&value_backtraces), fold(&success_backtraces))
    }

    fn commit_unbound_to_allocations(&mut self) {
        if self.allocations.is_empty() || self.unbound.is_bottom() {
            return;
        }

        if self
            .unbound
            .iter()
            .map(LabelBacktrace::label)
            .any(Label::has_any_synthetic)
        {
            return;
        }

        let Some(location) = self.unbound.iter().map(LabelBacktrace::location).next() else {
            unreachable!("non-Bottom unbound should be non-empty");
        };

        for allocation in &self.allocations {
            allocation.merge_effect(&self.unbound, LabelBacktraceKind::Assignment, location);
        }

        self.unbound = ChannelAggregate::new_bottom();
    }

    fn map_aggregates(
        &self,
        transform: impl Fn(&ChannelAggregate<'a>) -> ChannelAggregate<'a>,
    ) -> Self {
        let allocations = self
            .allocations
            .iter()
            .map(|allocation| allocation.map_aggregate(&transform))
            .collect();

        Self {
            allocations,
            unbound: transform(&self.unbound),
        }
    }

    fn merged_aggregate(
        &self,
        kind: LabelBacktraceKind,
        location: &Pinned<'a, Location>,
    ) -> ChannelAggregate<'a> {
        self.allocations
            .iter()
            .fold(self.unbound.clone(), |aggregate, allocation| {
                aggregate.merge_with(
                    &allocation.aggregate.borrow(),
                    kind,
                    Cow::Borrowed(location),
                )
            })
    }
}

impl PartialEq for ChannelValue<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.unbound == other.unbound
            && self.allocations.len() == other.allocations.len()
            && self
                .allocations
                .iter()
                .zip(&other.allocations)
                .all(|(left, right)| Rc::ptr_eq(left, right))
    }
}

impl Eq for ChannelValue<'_> {}

impl<'a> BacktraceContainer<'a> for ChannelValue<'a> {
    fn backtrace_at_location(&self, location: Pinned<'a, Location>) -> Option<LabelBacktrace<'a>> {
        self.receive(&location).0.backtrace()
    }

    fn is_bottom(&self) -> bool {
        self.unbound.is_bottom()
            && self
                .allocations
                .iter()
                .all(|allocation| allocation.aggregate.borrow().is_bottom())
    }

    fn allows_lossless_downgrade(&self) -> bool {
        self.allocations.is_empty()
    }

    fn subtract_label(&mut self, subtract: &Label<'a>) {
        self.unbound.payload.subtract_label(subtract);
        self.unbound.control.subtract_label(subtract);
    }
}

impl<'a> SelfAwareBacktraceContainer<'a> for ChannelValue<'a> {
    fn realize(
        &self,
        from_func: &FunctionRef<'a>,
        from_slot: SyntheticSlot,
        concrete: Option<&LabelBacktrace<'a>>,
    ) -> Self {
        let mut realized = self.map_aggregates(|aggregate| {
            // realize all aggregates
            aggregate.realize(from_func, from_slot, concrete)
        });

        if from_slot == SyntheticSlot::CallSiteBranch {
            // call-site branch realization is the final step in every existing
            // realization pipeline, so committing here avoids a second
            // deferred-state model while ensuring no unresolved synthetics
            // escape into a concrete channel allocation
            realized.commit_unbound_to_allocations();
        }

        realized
    }

    fn realize_with_shape_preservation(
        &self,
        from_func: &FunctionRef<'a>,
        from_slot: SyntheticSlot,
        concrete: &Self,
        concrete_location: Pinned<'a, Location>,
    ) -> Self {
        let template = self.realize(from_func, from_slot, None);

        let template_aggregate =
            template.merged_aggregate(LabelBacktraceKind::Assignment, &concrete_location);

        Self {
            allocations: concrete.allocations.clone(),
            unbound: concrete.unbound.merge_with(
                &template_aggregate,
                LabelBacktraceKind::Assignment,
                Cow::Borrowed(&concrete_location),
            ),
        }
    }

    fn nest_backtrace(
        &self,
        parent_kind: LabelBacktraceKind,
        parent_symbol: Option<&'a str>,
        parent_location: Pinned<'a, Location>,
        extra_children: impl IntoIterator<Item = LabelBacktrace<'a>> + Clone,
    ) -> Self {
        self.map_aggregates(|aggregate| {
            aggregate.nest_backtrace(
                parent_kind,
                parent_symbol,
                parent_location.clone(),
                extra_children.clone(),
            )
        })
    }
}

impl<'a> Mergeable<'a> for ChannelValue<'a> {
    fn merge_with(
        &self,
        other: &Self,
        with_kind: LabelBacktraceKind,
        at_location: Cow<Pinned<'a, Location>>,
    ) -> Self {
        let mut allocations = self.allocations.clone();

        let unbound = self
            .unbound
            .merge_with(&other.unbound, with_kind, at_location.clone());

        for candidate in &other.allocations {
            if let Some(existing) = allocations
                .iter()
                .find(|allocation| allocation.allocation_site == candidate.allocation_site)
            {
                if !Rc::ptr_eq(existing, candidate) {
                    existing.merge_effect(
                        &candidate.aggregate.borrow(),
                        with_kind,
                        at_location.as_ref(),
                    );
                }
            } else {
                allocations.push(Rc::clone(candidate));
            }
        }

        Self {
            allocations,
            unbound,
        }
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
        self.unbound.snapshot_aware_eq(&other.unbound)
            && self.allocations.snapshot_aware_eq(&other.allocations)
    }
}

#[derive(Clone, Debug, PartialEq)]
struct ChannelAggregate<'a> {
    // aggregate of values sent into the channel
    payload: Option<LabelBacktrace<'a>>,
    // aggregate of delivery metainformation, i.e., if `close` was invoked
    control: Option<LabelBacktrace<'a>>,
}

impl<'a> ChannelAggregate<'a> {
    fn new(payload: Option<LabelBacktrace<'a>>, control: Option<LabelBacktrace<'a>>) -> Self {
        Self { payload, control }
    }

    fn new_uniform(backtrace: Option<LabelBacktrace<'a>>) -> Self {
        Self::new(backtrace.clone(), backtrace)
    }

    fn new_bottom() -> Self {
        Self::new_uniform(None)
    }

    fn is_bottom(&self) -> bool {
        self.payload.is_none() && self.control.is_none()
    }

    fn control(&self) -> Option<&LabelBacktrace<'a>> {
        self.control.as_ref()
    }

    fn iter(&self) -> impl Iterator<Item = &LabelBacktrace<'a>> {
        self.payload.iter().chain(self.control.iter())
    }

    fn realize(
        &self,
        from_func: &FunctionRef<'a>,
        from_slot: SyntheticSlot,
        concrete: Option<&LabelBacktrace<'a>>,
    ) -> Self {
        Self::new(
            self.payload.realize(from_func, from_slot, concrete),
            self.control.realize(from_func, from_slot, concrete),
        )
    }

    fn nest_backtrace(
        &self,
        parent_kind: LabelBacktraceKind,
        parent_symbol: Option<&'a str>,
        parent_location: Pinned<'a, Location>,
        extra_children: impl IntoIterator<Item = LabelBacktrace<'a>> + Clone,
    ) -> Self {
        Self::new(
            self.payload.nest_backtrace(
                parent_kind,
                parent_symbol,
                parent_location.clone(),
                extra_children.clone(),
            ),
            self.control.nest_backtrace(
                parent_kind,
                parent_symbol,
                parent_location,
                extra_children,
            ),
        )
    }
}

impl<'a> Mergeable<'a> for ChannelAggregate<'a> {
    fn merge_with(
        &self,
        other: &Self,
        with_kind: LabelBacktraceKind,
        at_location: Cow<Pinned<'a, Location>>,
    ) -> Self {
        let payload = self
            .payload
            .merge_with(&other.payload, with_kind, at_location.clone());

        let control = self
            .control
            .merge_with(&other.control, with_kind, at_location);

        Self::new(payload, control)
    }
}

impl SnapshotAware for ChannelAggregate<'_> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        self.payload.snapshot_aware_eq(&other.payload)
            && self.control.snapshot_aware_eq(&other.control)
    }
}

#[derive(Debug)]
struct ChannelAllocation<'a> {
    allocation_site: Pinned<'a, Location>,
    aggregate: RefCell<ChannelAggregate<'a>>,
}

impl<'a> ChannelAllocation<'a> {
    fn map_aggregate(
        self: &Rc<Self>,
        transform: &impl Fn(&ChannelAggregate<'a>) -> ChannelAggregate<'a>,
    ) -> Rc<Self> {
        let aggregate = self.aggregate.borrow();
        let transformed = transform(&aggregate);

        // preserve aliases when the traversal is a no-op. if aggregate changed,
        // detach instead of rewriting a reusable function summary in place
        if transformed == *aggregate {
            return Rc::clone(self);
        }

        Rc::new(Self {
            allocation_site: self.allocation_site.clone(),
            aggregate: RefCell::new(transformed),
        })
    }

    fn merge_effect(
        &self,
        effect: &ChannelAggregate<'a>,
        kind: LabelBacktraceKind,
        location: &Pinned<'a, Location>,
    ) {
        let mut aggregate = self.aggregate.borrow_mut();

        let merged = aggregate.merge_with(effect, kind, Cow::Borrowed(location));

        // avoid growing equivalent backtrace trees during local convergence
        if !aggregate.snapshot_aware_eq(&merged) {
            *aggregate = merged;
        }
    }
}

impl SnapshotAware for ChannelAllocation<'_> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        self.allocation_site == other.allocation_site
            && self
                .aggregate
                .borrow()
                .snapshot_aware_eq(&other.aggregate.borrow())
    }
}
