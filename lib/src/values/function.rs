use std::{
    borrow::Cow,
    cell::RefCell,
    cmp,
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt,
    rc::Rc,
};

use parser::{
    Location, Span,
    ast::{
        FunctionParamDeclNode, FunctionResultNode, FunctionSignatureNode, TypeNameNode, TypeNode,
    },
};
use uuid::Uuid;

use crate::{
    Pinned, SinkDescriptor,
    context::{AnalysisContext, DeferredEnforcementCheck},
    labels::{Label, LabelBacktrace, LabelBacktraceKind, SyntheticSlot},
    policy::{BlanketDirective, BlanketDirectiveKind, BlanketSourceArgPredicate, SinkKind},
    snapshots::SnapshotAware,
    symbols::{Symbol, SymbolRef},
    types::{TypeDeclarationContext, TypeInfo},
    values::{
        BacktraceContainer, Mergeable, SelfAwareBacktraceContainer, SimpleConstValue, Upgrade,
        ValueRef,
    },
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FunctionValue<'a> {
    r#ref: FunctionRef<'a>,
    signature: Option<FunctionSignatureNode<'a>>, // None if no known decl
    // whether aliasing semantics should be employed for the receiver (if any)
    // (unknown blackbox receivers are conservatively classified as pointers)
    receiver_kind: Option<ReceiverKind>,
    // result types resolved at definition (context may be missing at call-time)
    declared_result_types: Vec<Option<Rc<TypeInfo<'a>>>>,
    // whether this value represents a type symbol that, when "called", really
    // expresses a type conversion rather than a function invocation
    is_type_constructor: bool,
    // if this is a type constructor, the underlying type of the defined type
    // (i.e., the `X` in `type T X`), which allows dispatching named-type
    // composite literals such as `T{...` to the correct shape interpretation
    // when X is array/slice/map rather than struct. this also captures the
    // declaration file context needed to resolve names within X
    declared_underlying_type: Option<(TypeNode<'a>, TypeDeclarationContext<'a>)>,
    // expected result yielded by invoking this function (with synthetics)
    outcome: Option<Vec<ValueRef<'a>>>, // None if no known implementation
    // overall backtrace, e.g. from func lit assignments w/ explicit annotations
    backtrace: Option<LabelBacktrace<'a>>,
    // blanket sources that need to be applied to selected results at call time
    sources: Vec<InherentSourceOrRevocation<'a>>,
    // revocations to apply to the selected results at call time
    revocations: Vec<InherentSourceOrRevocation<'a>>,
    // inherent sinks that any call to this function implicitly triggers
    sinks: Vec<InherentSink<'a>>,
    // from sinks within the function, to which synthetic tags were passed
    deferred_checks: Vec<DeferredEnforcementCheck<'a>>,
    // mutable symbols from outer lexical scopes captured by this function
    // (key is the original symbol declaration, which must be pinned since this
    // function might be called from another file, and value is meta-information
    // including the unique index used by call-site realization)
    captures: HashMap<Pinned<'a, Span<'a>>, CaptureBinding<'a>>,
    // declaration site of the first parameter's identifier when this function
    // is shaped as a range-over-func iterator (i.e., first param has type
    // `func(...) bool`); None otherwise. used to recognize calls to that
    // parameter as yield calls while visiting the function body
    yield_param: Option<Pinned<'a, Span<'a>>>,
    // labels accumulated from yield(args) calls inside the function body, one
    // entry per yield argument position (per the yield param's signature).
    // each entry includes the corresponding arg's backtrace unioned with the
    // branch backtrace active at the call site. empty if not iter-shaped or
    // if the yield function takes no arguments
    yield_acc: Vec<Option<LabelBacktrace<'a>>>,
    // how many times this function has been called
    // (must be a shared ref, rather than a raw usize, since otherwise mutation
    // would not work as we'd only modify derived operand-name-access tainted
    // values from `nest_backtrace`, not the original underlying values, and so
    // this mutation would never be reflected in future function accesses)
    call_count: Rc<RefCell<usize>>,
}

impl<'a> FunctionValue<'a> {
    pub fn new(
        r#ref: FunctionRef<'a>,
        signature: Option<FunctionSignatureNode<'a>>,
        receiver_kind: Option<ReceiverKind>,
        declared_result_types: Vec<Option<Rc<TypeInfo<'a>>>>,
        backtrace: Option<LabelBacktrace<'a>>,
    ) -> Self {
        Self {
            r#ref,
            signature,
            receiver_kind,
            declared_result_types,
            is_type_constructor: false,
            declared_underlying_type: None,
            outcome: None,
            backtrace,
            sources: Vec::new(),
            revocations: Vec::new(),
            sinks: Vec::new(),
            deferred_checks: vec![],
            captures: HashMap::new(),
            yield_param: None,
            yield_acc: vec![],
            call_count: Rc::new(RefCell::new(0)),
        }
    }

    pub fn new_builtin(
        name: &'static str,
        params: &[&'static str],
        variadic: bool,
        n_returned: usize,
    ) -> Self {
        let r#ref = FunctionRef::BuiltIn(name);

        let param_ids: Vec<_> = params.iter().map(|id| Span::new(id, 0, 1)).collect();

        let dummy_type = TypeNode::Name(TypeNameNode {
            package: None,
            id: *crate::FAKE_SPAN.inner(),
            args: vec![],
        });

        let result = match n_returned {
            0 => FunctionResultNode::None,
            1 => FunctionResultNode::Single(dummy_type.clone()),
            n => FunctionResultNode::Params(vec![
                FunctionParamDeclNode {
                    ids: vec![],
                    variadic: false,
                    r#type: dummy_type.clone()
                };
                n
            ]),
        };

        let signature_params = if param_ids.is_empty() {
            Vec::new()
        } else {
            vec![FunctionParamDeclNode {
                ids: param_ids,
                variadic,
                r#type: dummy_type,
            }]
        };

        let signature = FunctionSignatureNode {
            params: signature_params,
            result,
        };

        Self::new(r#ref, Some(signature), None, vec![None; n_returned], None)
    }

    pub fn new_type_constructor(
        r#ref: FunctionRef<'a>,
        underlying: Option<(TypeNode<'a>, TypeDeclarationContext<'a>)>,
        target_type: Option<Rc<TypeInfo<'a>>>,
    ) -> Self {
        let dummy_type = TypeNode::Name(TypeNameNode {
            package: None,
            id: *crate::FAKE_SPAN.inner(),
            args: vec![],
        });

        let signature = FunctionSignatureNode {
            params: vec![FunctionParamDeclNode {
                ids: vec![*crate::FAKE_SPAN.inner()],
                variadic: false,
                r#type: dummy_type.clone(),
            }],
            result: FunctionResultNode::Single(dummy_type),
        };

        let mut value = Self::new(
            r#ref,
            Some(signature), // never actually used for analysis, so dummy values are ok
            None,
            vec![target_type],
            None,
        );

        value.is_type_constructor = true;
        value.declared_underlying_type = underlying;

        value
    }

    pub fn new_unknown(backtrace: Option<LabelBacktrace<'a>>, has_receiver: bool) -> Self {
        let r#ref = FunctionRef::BlackboxInference(Uuid::new_v4());

        // conservatively preserve the possibility of mutable referent state
        let receiver_kind = has_receiver.then_some(ReceiverKind::Pointer);

        Self::new(r#ref, None, receiver_kind, Vec::new(), backtrace)
    }

    pub fn r#ref(&self) -> &FunctionRef<'a> {
        &self.r#ref
    }

    pub fn signature(&self) -> Option<&FunctionSignatureNode<'a>> {
        self.signature.as_ref()
    }

    pub fn has_receiver(&self) -> bool {
        self.receiver_kind.is_some()
    }

    pub fn receiver_is_pointer(&self) -> bool {
        self.receiver_kind == Some(ReceiverKind::Pointer)
    }

    pub fn declared_result_types(&self) -> &[Option<Rc<TypeInfo<'a>>>] {
        &self.declared_result_types
    }

    pub fn is_type_constructor(&self) -> bool {
        self.is_type_constructor
    }

    pub fn constructed_type(&self) -> Option<Rc<TypeInfo<'a>>> {
        if !self.is_type_constructor {
            return None;
        }

        self.declared_result_types.first().cloned().flatten()
    }

    pub fn declared_underlying_type(&self) -> Option<(&TypeNode<'a>, &TypeDeclarationContext<'a>)> {
        self.declared_underlying_type.as_ref().map(|(t, c)| (t, c))
    }

    pub fn outcome(&self) -> Option<&Vec<ValueRef<'a>>> {
        self.outcome.as_ref()
    }

    pub fn set_outcome(&mut self, outcome: Vec<ValueRef<'a>>) {
        self.outcome = Some(outcome);
    }

    pub fn backtrace(&self) -> Option<&LabelBacktrace<'a>> {
        self.backtrace.as_ref()
    }

    pub fn sources(&self) -> &[InherentSourceOrRevocation<'a>] {
        &self.sources
    }

    pub fn add_source(&mut self, source: InherentSourceOrRevocation<'a>) {
        if !self.sources.contains(&source) {
            self.sources.push(source);
        }
    }

    pub fn revocations(&self) -> &[InherentSourceOrRevocation<'a>] {
        &self.revocations
    }

    pub fn add_revocation(&mut self, revocation: InherentSourceOrRevocation<'a>) {
        if !self.revocations.contains(&revocation) {
            self.revocations.push(revocation);
        }
    }

    pub fn sinks(&self) -> &[InherentSink<'a>] {
        &self.sinks
    }

    pub fn add_sink(&mut self, sink: InherentSink<'a>) {
        if !self.sinks.contains(&sink) {
            self.sinks.push(sink);
        }
    }

    pub(crate) fn absorb_blanket_directives(
        &mut self,
        directives: impl IntoIterator<Item = &'a BlanketDirective>,
    ) {
        for directive in directives {
            match directive.kind() {
                BlanketDirectiveKind::Source => {
                    if directive.should_resolve_at_call_time() {
                        self.add_source(InherentSourceOrRevocation {
                            label: directive.label().clone(),
                            predicate: directive.arg_predicate().cloned(),
                            result_selector: directive.result_selector().clone(),
                        });
                    }
                }
                BlanketDirectiveKind::Revocation => {
                    self.add_revocation(InherentSourceOrRevocation {
                        label: directive.label().clone(),
                        predicate: directive.arg_predicate().cloned(),
                        result_selector: directive.result_selector().clone(),
                    });
                }
                BlanketDirectiveKind::AllowSink | BlanketDirectiveKind::DenySink => {
                    // we don't use InherentSink::new because we already have a
                    // Label, there is no need to convert tags back and forth
                    self.add_sink(InherentSink {
                        allow: directive.kind() == BlanketDirectiveKind::AllowSink,
                        label: directive.label().clone(),
                        arg_index: directive.arg_index(),
                    });
                }
            }
        }
    }

    pub fn deferred_checks(&self) -> &[DeferredEnforcementCheck<'a>] {
        &self.deferred_checks
    }

    pub fn defer_check(&mut self, check: DeferredEnforcementCheck<'a>) {
        if self
            .deferred_checks
            .iter_mut()
            .any(|existing| existing.merge_if_same_site(&check))
        {
            // the new check was merged into an existing deferred check, so
            // there is no need to add it
            return;
        }

        self.deferred_checks.push(check);
    }

    #[must_use = "if false, invoker should report a soundness limitation"]
    pub fn try_merge_summary_from(
        &mut self,
        other: &Self,
        merge_kind: LabelBacktraceKind,
        location: &Pinned<'a, Location>,
    ) -> bool {
        // a joined summary can only reuse a single call realization when every
        // slot has the same meaning in both original functions

        if !self.is_summary_shape_compatible_with(other) {
            return false;
        }

        let Some(capture_slots) = self.capture_slot_remapping_for(other) else {
            return false;
        };

        // canonicalizing the incoming summary once keeps every downstream
        // realization on the ordinary single-function path
        let mut remapping = super::UnifiedRealization::remap(
            other.r#ref(),
            self.r#ref(),
            // capture slots need an explicit mapping because each closure
            // allocates them independently
            &capture_slots,
        );

        let mut incoming = other.realize_unified(&mut remapping);
        incoming.remap_capture_indices(&capture_slots);

        self.receiver_kind = merge_receiver_kinds(self.receiver_kind, incoming.receiver_kind);

        if self.signature.is_none() {
            self.signature.clone_from(&incoming.signature);
        }

        if self.declared_result_types.is_empty() {
            self.declared_result_types
                .clone_from(&incoming.declared_result_types);
        } else {
            for (left, right) in self
                .declared_result_types
                .iter_mut()
                .zip(&incoming.declared_result_types)
            {
                if left.is_none() {
                    left.clone_from(right);
                }
            }
        }

        // if either implementation is unknown, the joined call must keep
        // blackbox result semantics; body side effects and checks remain
        // summarized separately below
        self.outcome = self
            .outcome
            .take()
            .map(Vec::into_iter)
            .zip(incoming.outcome.as_ref())
            .map(|(left, right)| {
                left.zip(right)
                    .map(|(left, right)| {
                        left.merge_with(right, merge_kind, Cow::Borrowed(location))
                    })
                    .collect()
            });

        for source in &incoming.sources {
            self.add_source(source.clone());
        }

        // a revocation is safe at the join only if every possible callee
        // applies it, unlike sources and sinks which should be unioned together
        self.revocations
            .retain(|revocation| incoming.revocations.contains(revocation));

        for sink in &incoming.sinks {
            self.add_sink(sink.clone());
        }

        for check in &incoming.deferred_checks {
            self.defer_check(check.clone());
        }

        self.merge_captures_from(&incoming, merge_kind, location);

        for (left, right) in self.yield_acc.iter_mut().zip(&incoming.yield_acc) {
            *left = LabelBacktrace::combine_options(
                left.take(),
                right.clone(),
                merge_kind,
                Cow::Borrowed(location),
            );
        }

        if self.yield_param.is_none() {
            self.yield_param = incoming.yield_param;
        }

        true
    }

    fn is_summary_shape_compatible_with(&self, other: &Self) -> bool {
        let outcomes_are_compatible = || {
            self.outcome
                .as_ref()
                .zip(other.outcome.as_ref())
                .is_none_or(|(left, right)| left.len() == right.len())
        };

        // Mergeable deliberately flattens function-shaped values, but doing
        // that to a returned function would discard its own callable summary,
        // so we consider it to be unsafe
        let has_function_outcome = || {
            self.outcome
                .iter()
                .flatten()
                .chain(other.outcome.iter().flatten())
                .any(ValueRef::is_function)
        };

        self.is_type_constructor == other.is_type_constructor
            && self.declared_underlying_type == other.declared_underlying_type
            && self.yield_acc.len() == other.yield_acc.len()
            && signatures_have_compatible_slots(self.signature.as_ref(), other.signature.as_ref())
            && outcomes_are_compatible()
            && !has_function_outcome()
    }

    fn capture_slot_remapping_for(&self, other: &Self) -> Option<BTreeMap<usize, usize>> {
        let mut captures: Vec<_> = other.captures.iter().collect();
        captures.sort_unstable_by_key(|(_, binding)| binding.index);
        // ^^ unstable is fine since indexes should be unique

        let mut next_index = self.captures.len();
        let mut remapping = BTreeMap::new();

        for (outer_decl, incoming) in captures {
            let target_index = if let Some(existing) = self.captures.get(outer_decl) {
                if !existing.can_merge_with(incoming) {
                    return None;
                }

                existing.index
            } else {
                let index = next_index;

                next_index += 1;

                index
            };

            remapping.insert(incoming.index, target_index);
        }

        Some(remapping)
    }

    fn remap_capture_indices(&mut self, remapping: &BTreeMap<usize, usize>) {
        #[expect(clippy::iter_over_hash_type, reason = "Independent metadata update")]
        for binding in self.captures.values_mut() {
            let mapped = remapping
                .get(&binding.index)
                .expect("every capture binding must have a slot remapping");

            binding.index = *mapped;
        }
    }

    fn merge_captures_from(
        &mut self,
        other: &Self,
        merge_kind: LabelBacktraceKind,
        location: &Pinned<'a, Location>,
    ) {
        let mut captures: Vec<_> = other.captures.iter().collect();
        captures.sort_unstable_by_key(|(_, binding)| binding.index);
        // ^^ unstable is fine since indexes should be unique

        for (outer_decl, other_binding) in captures {
            if let Some(binding) = self.captures.get_mut(outer_decl) {
                binding.merge_body_state_from(other_binding, merge_kind, location);
            } else {
                self.captures.insert(*outer_decl, other_binding.clone());
            }
        }
    }

    pub fn parameter_count(&self) -> Option<usize> {
        let count = self.signature()?.count_inputs();

        Some(count)
    }

    pub fn captures(
        &self,
    ) -> impl ExactSizeIterator<Item = (Pinned<'a, Span<'a>>, &CaptureBinding<'a>)> {
        self.captures.iter().map(|(k, v)| (*k, v))
    }

    pub fn captures_mut(
        &mut self,
    ) -> impl ExactSizeIterator<Item = (Pinned<'a, Span<'a>>, &mut CaptureBinding<'a>)> {
        self.captures.iter_mut().map(|(k, v)| (*k, v))
    }

    #[must_use]
    pub fn register_capture_with(
        &mut self,
        outer_decl: Pinned<'a, Span<'a>>,
        iteration_cell: Option<SymbolRef<'a>>,
        make_local_symbol: impl FnOnce(usize) -> SymbolRef<'a>,
    ) -> SymbolRef<'a> {
        let capture_index = self.captures.len();

        let binding = self.captures.entry(outer_decl).or_insert_with(|| {
            CaptureBinding::new(
                capture_index,
                make_local_symbol(capture_index),
                iteration_cell,
            )
        });

        binding.local_symbol()
    }

    #[must_use]
    pub fn record_capture_mutation(
        &mut self,
        local_symbol: &SymbolRef<'a>,
        mutation_backtrace: impl FnOnce() -> Option<LabelBacktrace<'a>>,
        location: Cow<Pinned<'a, Location>>,
    ) -> bool {
        let Some(binding) = self
            .captures
            .values_mut()
            .find(|binding| Rc::ptr_eq(&binding.local_symbol, local_symbol))
        else {
            return false;
        };

        // calculating the mutation backtrace can be very expensive sometimes,
        // so we only do it here where we know we actually need it
        let Some(mutation_backtrace) = mutation_backtrace() else {
            return true;
        };

        // the entry snapshot already accounts for the capture's value before
        // the mutation, and will eventually be unioned with this value, but for
        // now we need to get rid of the capture synthetic, as otherwise the
        // capture-concrete fixed point could try to realize a capture with a
        // concrete that still contains itself
        let realized = mutation_backtrace.realize(
            &self.r#ref,
            SyntheticSlot::Capture(binding.index()),
            None, // just get rid of it
        );

        binding.record_mutation_backtrace(realized, location);

        true
    }

    pub fn call_count(&self) -> usize {
        *self.call_count.borrow()
    }

    pub fn yield_param(&self) -> Option<&Pinned<'a, Span<'a>>> {
        self.yield_param.as_ref()
    }

    pub fn yield_acc(&self) -> &[Option<LabelBacktrace<'a>>] {
        &self.yield_acc
    }

    pub fn mark_range_iter_shaped(
        &mut self,
        yield_param: Pinned<'a, Span<'a>>,
        yield_n_values: usize,
    ) {
        self.yield_param = Some(yield_param);
        self.yield_acc = vec![None; yield_n_values];
    }

    pub fn record_yield_call(
        &mut self,
        arg_backtraces: &[Option<&LabelBacktrace<'a>>],
        branch_backtrace: Option<&LabelBacktrace<'a>>,
        at_location: &Pinned<'a, Location>,
    ) {
        // taint the function value itself with the branch context: a call to
        // this function may behave conditionally on whatever the branch
        // depends on (relevant when iter has 0 yield values, since outcome
        // is empty and `downgrade` is the only signal available)
        if let Some(branch) = branch_backtrace {
            self.backtrace = LabelBacktrace::combine_options(
                self.backtrace.take(),
                Some(branch.clone()),
                LabelBacktraceKind::Branch,
                Cow::Borrowed(at_location),
            );
        }

        for (slot, arg) in self.yield_acc.iter_mut().zip(arg_backtraces) {
            let contribution = LabelBacktrace::combine_options(
                arg.cloned(),
                branch_backtrace.cloned(),
                LabelBacktraceKind::Branch,
                Cow::Borrowed(at_location),
            );

            *slot = LabelBacktrace::combine_options(
                slot.take(),
                contribution,
                LabelBacktraceKind::Expression,
                Cow::Borrowed(at_location),
            );
        }
    }

    pub fn record_call(&mut self) {
        *self.call_count.borrow_mut() += 1;
    }

    // downgrade + realize the injected synthetic branch backtrace at call-site
    pub fn downgrade_as_call(
        &self,
        ctx: &AnalysisContext<'a>,
        location: Pinned<'a, Location>,
    ) -> ValueRef<'a> {
        let backtrace = self.backtrace_at_location(location.clone());
        let downgraded = ValueRef::from_backtrace_or_bottom_at(backtrace, || location);

        downgraded.realize(
            self.r#ref(),
            SyntheticSlot::CallSiteBranch,
            ctx.branch_backtrace(),
        )
    }
}

impl<'a> BacktraceContainer<'a> for FunctionValue<'a> {
    fn backtrace_at_location(&self, location: Pinned<'a, Location>) -> Option<LabelBacktrace<'a>> {
        self.backtrace
            .clone()
            .map(|bt| (bt.symbol(), bt)) // thanks borrow checker, very cool
            .map(|(sym, bt)| bt.into_single_child(LabelBacktraceKind::Expression, sym, location))
    }

    fn is_bottom(&self) -> bool {
        self.backtrace.is_none()
    }

    fn allows_lossless_downgrade(&self) -> bool {
        self.signature.is_none()
            && self.outcome.is_none()
            && self.sources.is_empty()
            && self.revocations.is_empty()
            && self.sinks.is_empty()
            && self.deferred_checks.is_empty()
            && self.call_count() == 0
            && self.captures.is_empty()
            && self.yield_param.is_none()
            && self.yield_acc.iter().all(Option::is_none)
    }

    fn subtract_label(&mut self, subtract: &Label<'a>) {
        self.backtrace.subtract_label(subtract);

        for slot in &mut self.yield_acc {
            slot.subtract_label(subtract);
        }
    }
}

impl<'a> SelfAwareBacktraceContainer<'a> for FunctionValue<'a> {
    fn realize_unified<'b>(&self, unified: &mut super::UnifiedRealization<'a, 'b>) -> Self {
        // we need to recursively realize everything in the outcome, for example
        // to deal with the case where a function returns another function
        // (since then the inner function could depend on the outer's params)
        let outcome = self
            .outcome
            .as_ref()
            .map(|vec| vec.iter().map(|val| val.realize_unified(unified)).collect());

        let backtrace = self.backtrace.realize_unified(unified);

        let deferred_checks = self
            .deferred_checks
            .iter()
            .filter_map(|check| check.realize_unified(unified))
            .collect();

        let captures = self
            .captures
            .iter()
            .map(|(outer_decl, binding)| (*outer_decl, binding.realize_unified(unified)))
            .collect();

        let yield_acc = self
            .yield_acc
            .iter()
            .map(|slot| slot.realize_unified(unified))
            .collect();

        Self {
            r#ref: self.r#ref.clone(),
            signature: self.signature.clone(),
            receiver_kind: self.receiver_kind,
            declared_result_types: self.declared_result_types.clone(),
            is_type_constructor: self.is_type_constructor,
            declared_underlying_type: self.declared_underlying_type.clone(),
            outcome,
            backtrace,
            sources: self.sources.clone(),
            revocations: self.revocations.clone(),
            sinks: self.sinks.clone(),
            deferred_checks,
            captures,
            yield_param: self.yield_param,
            yield_acc,
            call_count: Rc::clone(&self.call_count), // preserve link to shared val
        }
    }

    fn nest_backtrace(
        &self,
        parent_kind: LabelBacktraceKind,
        parent_symbol: Option<&'a str>,
        parent_location: Pinned<'a, Location>,
        extra_children: impl IntoIterator<Item = LabelBacktrace<'a>> + Clone,
    ) -> Self {
        let backtrace = self.backtrace.nest_backtrace(
            parent_kind,
            parent_symbol,
            parent_location,
            extra_children,
        );

        Self {
            r#ref: self.r#ref.clone(),
            signature: self.signature.clone(),
            receiver_kind: self.receiver_kind,
            declared_result_types: self.declared_result_types.clone(),
            is_type_constructor: self.is_type_constructor,
            declared_underlying_type: self.declared_underlying_type.clone(),
            outcome: self.outcome.clone(),
            backtrace,
            sources: self.sources.clone(),
            revocations: self.revocations.clone(),
            sinks: self.sinks.clone(),
            deferred_checks: self.deferred_checks.clone(),
            captures: self.captures.clone(),
            yield_param: self.yield_param,
            yield_acc: self.yield_acc.clone(),
            call_count: Rc::clone(&self.call_count), // preserve link to shared val
        }
    }
}

impl<'a> Upgrade<'a> for FunctionValue<'a> {
    fn upgrade(
        backtrace: Option<LabelBacktrace<'a>>,
        _location: Cow<Pinned<'a, Location>>,
    ) -> Self {
        Self::new_unknown(backtrace, false)
    }
}

impl SnapshotAware for FunctionValue<'_> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        self.r#ref.snapshot_aware_eq(&other.r#ref)
            && self.signature == other.signature
            && self.receiver_kind == other.receiver_kind
            && self.declared_result_types == other.declared_result_types
            && self.is_type_constructor == other.is_type_constructor
            && self.declared_underlying_type == other.declared_underlying_type
            && self.outcome.snapshot_aware_eq(&other.outcome)
            && self.backtrace.snapshot_aware_eq(&other.backtrace)
            && self.sources == other.sources
            && self.revocations == other.revocations
            && self.sinks == other.sinks
            // propagation order is irrelevant, so we do not use Vec's impl of
            // SnapshotAwareEr: `defer_check` guarantees that each source-level
            // check is registered at most once
            && self.deferred_checks.len() == other.deferred_checks.len()
            && self.deferred_checks.iter().all(|check| {
                other
                    .deferred_checks
                    .iter()
                    .any(|candidate| check.snapshot_aware_eq(candidate))
            })
            && self.captures.snapshot_aware_eq(&other.captures)
            && self.yield_param == other.yield_param
            && self.yield_acc.snapshot_aware_eq(&other.yield_acc)
        // intentionally ignoring call count
    }
}

fn signatures_have_compatible_slots(
    left: Option<&FunctionSignatureNode<'_>>,
    right: Option<&FunctionSignatureNode<'_>>,
) -> bool {
    let (Some(left), Some(right)) = (left, right) else {
        // a missing blackbox signature can be shaped by the known alternative
        return true;
    };

    left.result.len() == right.result.len()
        && left.count_inputs() == right.count_inputs()
        && left.params.last().is_some_and(|param| param.variadic)
            == right.params.last().is_some_and(|param| param.variadic)
}

fn merge_receiver_kinds(
    left: Option<ReceiverKind>,
    right: Option<ReceiverKind>,
) -> Option<ReceiverKind> {
    match (left, right) {
        // treating a possible value receiver as a pointer receiver may retain
        // extra mutable state, but cannot lose a flow
        (Some(ReceiverKind::Pointer), _) | (_, Some(ReceiverKind::Pointer)) => {
            Some(ReceiverKind::Pointer)
        }
        (Some(ReceiverKind::Value), _) | (_, Some(ReceiverKind::Value)) => {
            Some(ReceiverKind::Value)
        }
        (None, None) => None,
    }
}

/// Represents an unambiguous reference to a function declaration.
///
/// Among other uses, this is necessary to guarantee uniqueness of a
/// [`LabelTag::Synthetic`](crate::labels::LabelTag::Synthetic) when paired with
/// a function parameter index or another equivalent function-specific
/// identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FunctionRef<'a> {
    /// A normal function with a native declared name.
    ///
    /// This is a unique identifier because of the embedded location information
    /// offered by [`Pinned`] and [`Span`].
    Named {
        /// The declared function name, bound to its source location.
        name: Pinned<'a, Span<'a>>,
        /// Whether this function is the program's primary entrypoint.
        ///
        /// This corresponds to whether this is `func main` declared in the root
        /// package scope of a package called `main`, per the Go spec.
        is_main: bool,
    },
    /// An anonymous function literal.
    Anonymous(Pinned<'a, Location>),
    /// A built-in function provided by the language or the Go standard library.
    BuiltIn(&'static str),
    /// An inferred function for which no declaration exists/was found.
    BlackboxInference(Uuid),
}

impl<'a> FunctionRef<'a> {
    pub(crate) fn new_named(name: Pinned<'a, Span<'a>>) -> Self {
        Self::Named {
            name,
            is_main: false,
        }
    }

    /// Returns the function's declared symbol name, if any exists.
    #[must_use]
    #[inline]
    pub fn declared_name(&self) -> Option<&'a str> {
        match self {
            Self::Named { name, .. } => Some(name.content()),
            Self::BuiltIn(name) => Some(name),
            Self::Anonymous(_) | Self::BlackboxInference(_) => None,
        }
    }

    /// Returns whether the function is considered to be the main entrypoint.
    ///
    /// This is recorded from the declaration's package context.
    #[must_use]
    #[inline]
    pub fn is_main(&self) -> bool {
        matches!(self, Self::Named { is_main: true, .. })
    }
}

impl fmt::Display for FunctionRef<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Named { name, .. } => name.content().fmt(f),
            Self::Anonymous(pin) => write!(
                f,
                "lit@\"{}\"#{}-{}",
                pin.file().display(),
                pin.inner().start,
                pin.inner().end
            ),
            Self::BuiltIn(name) => name.fmt(f),
            Self::BlackboxInference(uuid) => write!(f, "inferred@{}", uuid.hyphenated()),
        }
    }
}

// need to impl manually because Pinned<Location> doesn't impl Ord (nor should
// it), even though in this particular case we really do need a total order,
// even if a bit arbitrary
impl Ord for FunctionRef<'_> {
    #[inline]
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match (self, other) {
            (
                Self::Named {
                    name: a_name,
                    is_main: a_is_main,
                },
                Self::Named {
                    name: b_name,
                    is_main: b_is_main,
                },
            ) => a_name.cmp(b_name).then(a_is_main.cmp(b_is_main)),
            (Self::Named { .. }, _) => cmp::Ordering::Less,
            (_, Self::Named { .. }) => cmp::Ordering::Greater,
            (Self::Anonymous(a), Self::Anonymous(b)) => a.partial_cmp(b).unwrap_or_else(|| {
                a.file()
                    .cmp(b.file())
                    .then(a.inner().start.cmp(&b.inner().start))
                    .then(b.inner().end.cmp(&b.inner().end))
            }),
            (Self::Anonymous(_), _) => cmp::Ordering::Less,
            (_, Self::Anonymous(_)) => cmp::Ordering::Greater,
            (Self::BuiltIn(a), Self::BuiltIn(b)) => a.cmp(b),
            (Self::BuiltIn(_), _) => cmp::Ordering::Less,
            (_, Self::BuiltIn(_)) => cmp::Ordering::Greater,
            (Self::BlackboxInference(a), Self::BlackboxInference(b)) => a.cmp(b),
        }
    }
}

impl PartialOrd for FunctionRef<'_> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl SnapshotAware for FunctionRef<'_> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Named {
                    name: a_name,
                    is_main: a_is_main,
                },
                Self::Named {
                    name: b_name,
                    is_main: b_is_main,
                },
            ) => a_name == b_name && a_is_main == b_is_main,
            (Self::Anonymous(a), Self::Anonymous(b)) => a == b,
            (Self::BuiltIn(a), Self::BuiltIn(b)) => a == b,
            // UUIDs might differ between analyzer iterations
            // (they're randomly generated upon upgrade)
            (Self::BlackboxInference(_), Self::BlackboxInference(_)) => true,

            // not using wildcard to force revisiting impl for any new variants
            (
                Self::Named { .. }
                | Self::Anonymous(_)
                | Self::BuiltIn(_)
                | Self::BlackboxInference(_),
                _,
            ) => false,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReceiverKind {
    Value,
    Pointer,
}

impl From<&FunctionParamDeclNode<'_>> for ReceiverKind {
    fn from(receiver: &FunctionParamDeclNode<'_>) -> Self {
        if matches!(receiver.r#type, TypeNode::Pointer { .. }) {
            Self::Pointer
        } else {
            Self::Value
        }
    }
}

#[derive(Clone)]
pub struct CaptureBinding<'a> {
    // unique index that has been reserved for this capture to identify it
    // within the context of the function in question, which can be used in
    // synthetic tags by the realization pipeline when the function is actually
    // invoked to turn them into concrete labels
    index: usize,
    // synthetic local symbol installed in the function scope for this capture
    // (with a placeholder synthetic tag as its label)
    local_symbol: SymbolRef<'a>,
    // range variables declared with `:=` denote distinct storage on each
    // iteration, so this state represents the particular abstract iteration
    // environment captured by this closure
    iteration_cell: Option<SymbolRef<'a>>,
    // currently best known hybrid backtrace for this capture's outer symbol,
    // used as a fallback when fetching the outer symbol's current value yields
    // a partially or fully synthetic label -- however, there is a risk that
    // this fallback is stale, in which case using it is silently unsound!
    // (hybrid means we try our best for it to be fully concrete, but sometimes
    // it might be impossible to completely realize synthetic tags, so this
    // backtrace might still be partially or fully synthetic)
    // fallback value is None if not yet set, while Some(None) means Bottom
    #[expect(
        clippy::option_option,
        reason = "Conveniently represent the presence/absence of an Option<LabelBacktrace>"
    )]
    hybrid_fallback: Option<Option<LabelBacktrace<'a>>>,
    // union of backtraces observed after mutating the fake local capture symbol
    // over the course of the function body, so all reads see all possible
    // mutations (conservatively merged) rather than just the last, when the
    // capture synthetics are realized at the end
    mutation_backtrace: Option<LabelBacktrace<'a>>,
}

impl<'a> CaptureBinding<'a> {
    fn new(
        index: usize,
        local_symbol: SymbolRef<'a>,
        iteration_cell: Option<SymbolRef<'a>>,
    ) -> Self {
        Self {
            index,
            local_symbol,
            iteration_cell,
            hybrid_fallback: None,
            mutation_backtrace: None,
        }
    }

    pub fn index(&self) -> usize {
        self.index
    }

    pub fn local_symbol(&self) -> SymbolRef<'a> {
        Rc::clone(&self.local_symbol)
    }

    pub fn iteration_cell(&self) -> Option<&SymbolRef<'a>> {
        self.iteration_cell.as_ref()
    }

    #[expect(
        clippy::option_option,
        reason = "Conveniently represent the presence/absence of an Option<LabelBacktrace>"
    )]
    pub fn hybrid_fallback(&self) -> Option<Option<&LabelBacktrace<'a>>> {
        self.hybrid_fallback.as_ref().map(Option::as_ref)
    }

    pub fn set_hybrid_fallback(&mut self, hybrid_fallback: Option<LabelBacktrace<'a>>) {
        self.hybrid_fallback = Some(hybrid_fallback);
    }

    pub fn mutation_backtrace(&self) -> Option<&LabelBacktrace<'a>> {
        self.mutation_backtrace.as_ref()
    }

    pub fn record_mutation_backtrace(
        &mut self,
        mutation_backtrace: Option<LabelBacktrace<'a>>,
        location: Cow<Pinned<'a, Location>>,
    ) {
        self.mutation_backtrace = LabelBacktrace::combine_options(
            self.mutation_backtrace.take(),
            mutation_backtrace,
            LabelBacktraceKind::ClosureCaptureBinding,
            location,
        );
    }

    fn can_merge_with(&self, other: &Self) -> bool {
        match (&self.iteration_cell, &other.iteration_cell) {
            // closures created by distinct range iterations intentionally hold
            // different cells but can still be joined by merging cell state
            (None, None) | (Some(_), Some(_)) => true,
            _ => false,
        }
    }

    fn merge_body_state_from(
        &mut self,
        other: &Self,
        kind: LabelBacktraceKind,
        location: &Pinned<'a, Location>,
    ) {
        merge_symbol_state(&self.local_symbol, &other.local_symbol, kind, location);

        if let (Some(left), Some(right)) = (&self.iteration_cell, &other.iteration_cell)
            && !Rc::ptr_eq(left, right)
        {
            merge_symbol_state(left, right, kind, location);
        }

        self.hybrid_fallback = match (self.hybrid_fallback.take(), other.hybrid_fallback.clone()) {
            (Some(left), Some(right)) => Some(LabelBacktrace::combine_options(
                left,
                right,
                kind,
                Cow::Borrowed(location),
            )),
            (left, right) => left.or(right),
        };

        self.mutation_backtrace = LabelBacktrace::combine_options(
            self.mutation_backtrace.take(),
            other.mutation_backtrace.clone(),
            kind,
            Cow::Borrowed(location),
        );
    }

    fn realize_unified<'b>(&self, unified: &mut super::UnifiedRealization<'a, 'b>) -> Self {
        let mut binding = self.clone();

        if unified.is_remapping() {
            let borrowed = binding.local_symbol.borrow();
            let value = borrowed.value().get().realize_unified(unified);

            let new_symbol = Symbol::new_ref(
                borrowed.declared_name(),
                borrowed.mutable(),
                value,
                borrowed.known_const().cloned(),
            );

            drop(borrowed);

            binding.local_symbol = new_symbol;
        }

        binding.iteration_cell = binding.iteration_cell.map(|symbol| {
            let (declared_name, mutable, current, known_const) = {
                let symbol = symbol.borrow();

                (
                    symbol.declared_name(),
                    symbol.mutable(),
                    symbol.value().get(),
                    symbol.known_const().cloned(),
                )
            };

            let realized = current.realize_unified(unified);

            if !unified.is_remapping() && realized.snapshot_aware_eq(&current) {
                // preserve sharing between closures from the same iteration
                // when this realization has nothing to substitute
                symbol
            } else {
                Symbol::new_ref(declared_name, mutable, realized, known_const)
            }
        });

        if let Some(Some(fallback)) = binding.hybrid_fallback() {
            let realized = unified.dispatch(fallback);

            binding.set_hybrid_fallback(realized);
        }

        binding.mutation_backtrace = binding.mutation_backtrace.realize_unified(unified);

        binding
    }

    fn iteration_cell_eq_by(
        &self,
        other: &Self,
        cmp: impl FnOnce(&ValueRef<'a>, &ValueRef<'a>) -> bool,
    ) -> bool {
        match (&self.iteration_cell, &other.iteration_cell) {
            (None, None) => true,
            (Some(left), Some(right)) => {
                let left = left.borrow();
                let right = right.borrow();

                left.known_const() == right.known_const()
                    && cmp(&left.value().get(), &right.value().get())
            }
            _ => false,
        }
    }
}

impl SnapshotAware for CaptureBinding<'_> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        // local_symbol is transient identity; its value is compared as part of
        // the enclosing symbol-table snapshot. iteration_cell is not registered
        // there, so its state must be compared explicitly
        self.index == other.index
            && self.iteration_cell_eq_by(other, SnapshotAware::snapshot_aware_eq)
            && self
                .hybrid_fallback
                .snapshot_aware_eq(&other.hybrid_fallback)
            && self
                .mutation_backtrace
                .snapshot_aware_eq(&other.mutation_backtrace)
    }
}

impl PartialEq for CaptureBinding<'_> {
    fn eq(&self, other: &Self) -> bool {
        // local_symbol is implementation state, not capture metadata
        self.index == other.index
            && self.iteration_cell_eq_by(other, PartialEq::eq)
            && self.hybrid_fallback == other.hybrid_fallback
            && self.mutation_backtrace == other.mutation_backtrace
    }
}

impl Eq for CaptureBinding<'_> {}

impl fmt::Debug for CaptureBinding<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // omit local_symbol (implementation state, not capture metadata)
        f.debug_struct("CaptureBinding")
            .field("index", &self.index)
            .field("has_iteration_cell", &self.iteration_cell.is_some())
            .field("hybrid_fallback", &self.hybrid_fallback)
            .field("mutation_backtrace", &self.mutation_backtrace)
            .finish_non_exhaustive()
    }
}

fn merge_symbol_state<'a>(
    left: &SymbolRef<'a>,
    right: &SymbolRef<'a>,
    kind: LabelBacktraceKind,
    location: &Pinned<'a, Location>,
) {
    let (left_value, left_const) = {
        let symbol = left.borrow();

        (symbol.value().get(), symbol.known_const().cloned())
    };

    let (right_value, right_const) = {
        let symbol = right.borrow();

        (symbol.value().get(), symbol.known_const().cloned())
    };

    if left_value.snapshot_aware_eq(&right_value) && left_const == right_const {
        return;
    }

    let merged_value = left_value.merge_with(&right_value, kind, Cow::Borrowed(location));

    let merged_const = if left_const == right_const {
        left_const
    } else {
        None
    };

    left.borrow_mut().set_value(merged_value, merged_const);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InherentSourceOrRevocation<'a> {
    label: Label<'a>,
    result_selector: BTreeSet<usize>,
    predicate: Option<BlanketSourceArgPredicate>,
}

impl<'a> InherentSourceOrRevocation<'a> {
    pub fn new_unconditional(label: Label<'a>) -> Self {
        InherentSourceOrRevocation {
            label,
            result_selector: BTreeSet::new(),
            predicate: None,
        }
    }

    pub fn label(&self) -> &Label<'a> {
        &self.label
    }

    pub fn result_selector(&self) -> &BTreeSet<usize> {
        &self.result_selector
    }

    pub fn applies_to_result(&self, result_index: usize) -> bool {
        self.result_selector.is_empty() || self.result_selector.contains(&result_index)
    }

    pub fn applies_to_args(&self, arg_consts: &[Option<SimpleConstValue>]) -> bool {
        let Some(predicate) = &self.predicate else {
            return true;
        };

        let actual_consts = if let Some(selection) = predicate.arg_index() {
            if selection < arg_consts.len() {
                &arg_consts[selection..=selection]
            } else {
                // should only happened for a misconfigured predicate selection
                &[]
            }
        } else {
            arg_consts
        };

        actual_consts.iter().any(|actual| {
            actual
                .as_ref()
                .is_none_or(|actual| predicate.matches_const(actual))
            // ^^ if we cannot resolve a SimpleConstValue, we have to be
            // conservative and assume it could match the predicate
        })
    }
}

// we cannot use SinkDescriptor directly because inherent sinks are floating,
// i.e., they have no associated location until triggered at a call site
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InherentSink<'a> {
    allow: bool, // whitelist-based (allow) sink, vs. blacklist-based (deny)
    label: Label<'a>,
    arg_index: Option<usize>, // 0-indexed; None = applies to every argument
}

impl<'a> InherentSink<'a> {
    // returns None for a `deny` sink with Bottom label
    pub(crate) fn new(allow: bool, tags: &[&'a str], arg_index: Option<usize>) -> Option<Self> {
        if !allow && tags.is_empty() {
            return None;
        }

        let mut label = Label::from_tags(tags);
        label.accept_wildcards();

        Some(Self {
            allow,
            label,
            arg_index,
        })
    }

    pub fn as_descriptor_at(&self, location: Location) -> SinkDescriptor<'a> {
        // we don't use SinkDescriptor::new because we already have a Label
        SinkDescriptor {
            kind: SinkKind::Call,
            allow: self.allow,
            label: self.label.clone(),
            location,
        }
    }

    pub fn applies_to_arg(&self, index: usize) -> bool {
        self.arg_index.is_none_or(|target| target == index)
    }
}
