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
        capacity: Option<LabelBacktrace<'a>>,
        location: Pinned<'a, Location>,
    ) -> Self {
        Self {
            allocations: vec![Rc::new(ChannelAllocation {
                allocation_site: location,
                aggregate: RefCell::new(ChannelAggregate::new_with_capacity(capacity)),
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
        self.record(
            &ChannelAggregate::new_send(payload, control),
            LabelBacktraceKind::Send,
            location,
        );
    }

    pub fn close(&mut self, control: Option<LabelBacktrace<'a>>, location: &Pinned<'a, Location>) {
        self.record(
            &ChannelAggregate::new_close(control),
            LabelBacktraceKind::ChannelClose,
            location,
        );
    }

    pub fn record_receive(&mut self, control: LabelBacktrace<'a>, location: &Pinned<'a, Location>) {
        self.record(
            &ChannelAggregate::new_receive(control),
            LabelBacktraceKind::Receive,
            location,
        );
    }

    fn record(
        &mut self,
        effect: &ChannelAggregate<'a>,
        kind: LabelBacktraceKind,
        location: &Pinned<'a, Location>,
    ) {
        for allocation in &self.allocations {
            allocation.merge_effect(effect, kind, location);
        }

        self.unbound = self
            .unbound
            .merge_with(effect, kind, Cow::Borrowed(location));
    }

    pub fn receive(&self, location: &Pinned<'a, Location>) -> (ValueRef<'a>, ValueRef<'a>) {
        let state_count = self.allocations.len() + usize::from(!self.unbound.is_bottom());
        let mut value_backtraces = Vec::with_capacity(4 * state_count);
        let mut success_backtraces = Vec::with_capacity(3 * state_count);

        let mut append = |aggregate: &ChannelAggregate<'a>| {
            value_backtraces.extend(aggregate.iter().cloned());
            success_backtraces.extend(aggregate.delivery_iter().cloned());
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

    pub fn len_backtrace(&self, location: Pinned<'a, Location>) -> Option<LabelBacktrace<'a>> {
        self.observation_backtrace(ChannelObservation::Occupancy, location)
    }

    pub fn cap_backtrace(&self, location: Pinned<'a, Location>) -> Option<LabelBacktrace<'a>> {
        self.observation_backtrace(ChannelObservation::Capacity, location)
    }

    // whether a communication may proceed
    pub fn readiness_backtrace(
        &self,
        location: Pinned<'a, Location>,
    ) -> Option<LabelBacktrace<'a>> {
        let mut children = Vec::with_capacity(3 * (self.allocations.len() + 1));

        for allocation in &self.allocations {
            children.extend(allocation.aggregate.borrow().delivery_iter().cloned());
        }

        children.extend(self.unbound.delivery_iter().cloned());

        LabelBacktrace::fold(
            children.iter(),
            LabelBacktraceKind::Expression,
            None,
            location,
        )
    }

    fn observation_backtrace(
        &self,
        observation: ChannelObservation,
        location: Pinned<'a, Location>,
    ) -> Option<LabelBacktrace<'a>> {
        let mut children = Vec::with_capacity(self.allocations.len() + 1);

        for allocation in &self.allocations {
            children.extend(
                allocation
                    .aggregate
                    .borrow()
                    .observation(observation)
                    .cloned(),
            );
        }

        children.extend(self.unbound.observation(observation).cloned());

        LabelBacktrace::fold(
            children.iter(),
            LabelBacktraceKind::Expression,
            None,
            location,
        )
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
        self.unbound.delivery.subtract_label(subtract);
        self.unbound.occupancy.subtract_label(subtract);
        self.unbound.capacity.subtract_label(subtract);
    }
}

impl<'a> SelfAwareBacktraceContainer<'a> for ChannelValue<'a> {
    fn realize_unified<'b>(&self, unified: super::UnifiedRealization<'a, 'b>) -> Self {
        let mut realized = self.map_aggregates(|aggregate| {
            // realize all aggregates
            aggregate.realize_unified(unified)
        });

        if matches!(
            unified,
            super::UnifiedRealization::Single {
                from_slot: SyntheticSlot::CallSiteBranch,
                ..
            } | super::UnifiedRealization::Multiple { .. }
        ) {
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
    // delivery metainformation, i.e., whether `close` was invoked
    delivery: Option<LabelBacktrace<'a>>,
    // metainformation regarding the number of queued elements
    occupancy: Option<LabelBacktrace<'a>>,
    // metainformation regarding the channel's immutable buffer capacity
    capacity: Option<LabelBacktrace<'a>>,
}

impl<'a> ChannelAggregate<'a> {
    fn new(
        payload: Option<LabelBacktrace<'a>>,
        delivery: Option<LabelBacktrace<'a>>,
        occupancy: Option<LabelBacktrace<'a>>,
        capacity: Option<LabelBacktrace<'a>>,
    ) -> Self {
        Self {
            payload,
            delivery,
            occupancy,
            capacity,
        }
    }

    fn new_uniform(backtrace: Option<LabelBacktrace<'a>>) -> Self {
        Self::new(
            backtrace.clone(),
            backtrace.clone(),
            backtrace.clone(),
            backtrace,
        )
    }

    fn new_with_capacity(capacity: Option<LabelBacktrace<'a>>) -> Self {
        Self::new(None, None, None, capacity)
    }

    fn new_send(
        payload: Option<LabelBacktrace<'a>>,
        occupancy: Option<LabelBacktrace<'a>>,
    ) -> Self {
        Self::new(payload, None, occupancy, None)
    }

    fn new_close(delivery: Option<LabelBacktrace<'a>>) -> Self {
        Self::new(None, delivery, None, None)
    }

    fn new_receive(occupancy: LabelBacktrace<'a>) -> Self {
        Self::new(None, None, Some(occupancy), None)
    }

    fn new_bottom() -> Self {
        Self::new_uniform(None)
    }

    fn is_bottom(&self) -> bool {
        self.iter().next().is_none()
    }

    fn observation(&self, observation: ChannelObservation) -> Option<&LabelBacktrace<'a>> {
        match observation {
            ChannelObservation::Occupancy => self.occupancy.as_ref(),
            ChannelObservation::Capacity => self.capacity.as_ref(),
        }
    }

    fn iter(&self) -> impl Iterator<Item = &LabelBacktrace<'a>> {
        self.payload
            .iter()
            .chain(self.delivery.iter())
            .chain(self.occupancy.iter())
            .chain(self.capacity.iter())
    }

    fn delivery_iter(&self) -> impl Iterator<Item = &LabelBacktrace<'a>> {
        self.delivery
            .iter()
            .chain(self.occupancy.iter())
            .chain(self.capacity.iter())
    }

    fn realize_unified<'b>(&self, unified: super::UnifiedRealization<'a, 'b>) -> Self {
        Self::new(
            self.payload.realize_unified(unified),
            self.delivery.realize_unified(unified),
            self.occupancy.realize_unified(unified),
            self.capacity.realize_unified(unified),
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
            self.delivery.nest_backtrace(
                parent_kind,
                parent_symbol,
                parent_location.clone(),
                extra_children.clone(),
            ),
            self.occupancy.nest_backtrace(
                parent_kind,
                parent_symbol,
                parent_location.clone(),
                extra_children.clone(),
            ),
            self.capacity.nest_backtrace(
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

        let delivery = self
            .delivery
            .merge_with(&other.delivery, with_kind, at_location.clone());

        let occupancy = self
            .occupancy
            .merge_with(&other.occupancy, with_kind, at_location.clone());

        let capacity = self
            .capacity
            .merge_with(&other.capacity, with_kind, at_location);

        Self::new(payload, delivery, occupancy, capacity)
    }
}

impl SnapshotAware for ChannelAggregate<'_> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        self.payload.snapshot_aware_eq(&other.payload)
            && self.delivery.snapshot_aware_eq(&other.delivery)
            && self.occupancy.snapshot_aware_eq(&other.occupancy)
            && self.capacity.snapshot_aware_eq(&other.capacity)
    }
}

#[derive(Clone, Copy)]
enum ChannelObservation {
    Occupancy,
    Capacity,
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
