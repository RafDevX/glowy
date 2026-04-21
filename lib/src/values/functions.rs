use std::{borrow::Cow, cell::RefCell, cmp, collections::HashMap, fmt, rc::Rc};

use parser::{
    Location, Span,
    ast::{FunctionParamDeclNode, FunctionResultNode, FunctionSignatureNode, TypeNode},
};
use uuid::Uuid;

use crate::{
    Pinned,
    context::DeferredEnforcementCheck,
    labels::{Label, LabelBacktrace, LabelBacktraceKind},
    snapshots::SnapshotAware,
    values::{BacktraceContainer, SelfAwareBacktraceContainer, Upgrade, ValueRef},
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FunctionValue<'a> {
    r#ref: FunctionRef<'a>,
    signature: Option<FunctionSignatureNode<'a>>, // None if no known decl
    // ^ this will generally only be None for blackbox-inferred functions
    outcome: Option<Vec<ValueRef<'a>>>, // None if no known implementation
    // overall backtrace, e.g. from func lit assignments w/ explicit annotations
    backtrace: Option<LabelBacktrace<'a>>,
    // from sinks within the function, to which synthetic tags were passed
    deferred_checks: Vec<DeferredEnforcementCheck<'a>>,
    // symbols from outer lexical scopes captured by this closure, if applicable
    // (key is original symbol declaration, which must be pinned since this
    // closure might be called from another file, and value is meta-information
    // including the fake unique param index we are using to refer to this
    // capture so we can hook into the existing parameter realization system
    // even for closure capture resolution whenever the function literal is
    // actually invoked) -- map is empty if this is not a function literal
    captures: HashMap<Pinned<'a, Span<'a>>, CaptureBinding<'a>>,
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
        backtrace: Option<LabelBacktrace<'a>>,
    ) -> Self {
        Self {
            r#ref,
            signature,
            outcome: None,
            backtrace,
            deferred_checks: vec![],
            captures: HashMap::new(),
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

        let param_ids = params.iter().map(|id| Span::new(id, 0, 1)).collect();

        let dummy_type = TypeNode::Name {
            package: None,
            id: Span::new("unknown", 0, 1),
            args: vec![],
        };

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

        let signature = FunctionSignatureNode {
            params: vec![FunctionParamDeclNode {
                ids: param_ids,
                variadic,
                r#type: dummy_type,
            }],
            result,
        };

        Self::new(r#ref, Some(signature), None)
    }

    fn new_unknown(backtrace: Option<LabelBacktrace<'a>>) -> Self {
        let r#ref = FunctionRef::BlackboxInference(Uuid::new_v4());

        Self::new(r#ref, None, backtrace)
    }

    pub fn r#ref(&self) -> &FunctionRef<'a> {
        &self.r#ref
    }

    pub fn signature(&self) -> Option<&FunctionSignatureNode<'a>> {
        self.signature.as_ref()
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

    pub fn deferred_checks(&self) -> &[DeferredEnforcementCheck<'a>] {
        &self.deferred_checks
    }

    pub fn defer_check(&mut self, check: DeferredEnforcementCheck<'a>) {
        self.deferred_checks.push(check);
    }

    pub fn parameter_count(&self) -> Option<usize> {
        let count = self
            .signature()?
            .params
            .iter()
            .map(|param| cmp::max(1, param.ids.len()))
            .sum();

        Some(count)
    }

    pub fn captures(&self) -> impl Iterator<Item = (Pinned<'a, Span<'a>>, &CaptureBinding<'a>)> {
        self.captures.iter().map(|(k, v)| (*k, v))
    }

    pub fn captures_mut(
        &mut self,
    ) -> impl Iterator<Item = (Pinned<'a, Span<'a>>, &mut CaptureBinding<'a>)> {
        self.captures.iter_mut().map(|(k, v)| (*k, v))
    }

    #[must_use]
    pub fn register_capture(
        &mut self,
        outer_decl: Pinned<'a, Span<'a>>,
        local_decl: Pinned<'a, Span<'a>>,
    ) -> usize {
        // cannot use HashMap's Entry API because we need to borrow self for
        // calculations as the same time it'd be immutably borrowed for Entry

        if let Some(existing) = self.captures.get(&outer_decl) {
            existing.fake_param_index()
        } else {
            // we manufacture a unique parameter index to use within the
            // realization pipeline which represents this ""parameter""
            // (i.e., the captured symbol)
            let fake_param_index = self.parameter_count().unwrap_or(0) + self.captures.len();

            self.captures.insert(
                outer_decl,
                CaptureBinding::new(fake_param_index, local_decl),
            );

            fake_param_index
        }
    }

    pub fn call_count(&self) -> usize {
        *self.call_count.borrow()
    }

    pub fn record_call(&mut self) {
        *self.call_count.borrow_mut() += 1;
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
            && self.deferred_checks.is_empty()
            && self.call_count() == 0
            && self.captures.is_empty()
    }

    fn subtract_label(&mut self, subtract: &Label<'a>) {
        self.backtrace.subtract_label(subtract);
    }
}

impl<'a> SelfAwareBacktraceContainer<'a> for FunctionValue<'a> {
    fn realize(
        &self,
        from_func: &FunctionRef<'a>,
        from_index: Option<usize>,
        concrete: Option<&LabelBacktrace<'a>>,
    ) -> Self {
        // we need to recursively realize everything in the outcome, for example
        // to deal with the case where a function returns another function
        // (since then the inner function could depend on the outer's params)
        let outcome = self.outcome.as_ref().map(|vec| {
            vec.iter()
                .map(|val| val.realize(from_func, from_index, concrete))
                .collect()
        });

        let backtrace = self.backtrace.realize(from_func, from_index, concrete);

        let deferred_checks = self
            .deferred_checks
            .iter()
            .filter_map(|check| check.realize(from_func, from_index, concrete))
            .collect();

        let captures = self
            .captures
            .iter()
            .map(|(outer_decl, binding)| {
                (
                    *outer_decl,
                    binding.realize(from_func, from_index, concrete),
                )
            })
            .collect();

        Self {
            r#ref: self.r#ref.clone(),
            signature: self.signature.clone(),
            outcome,
            backtrace,
            deferred_checks,
            captures,
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
            outcome: self.outcome.clone(),
            backtrace,
            deferred_checks: self.deferred_checks.clone(),
            captures: self.captures.clone(),
            call_count: Rc::clone(&self.call_count), // preserve link to shared val
        }
    }
}

impl<'a> Upgrade<'a> for FunctionValue<'a> {
    fn upgrade(
        backtrace: Option<LabelBacktrace<'a>>,
        _location: Cow<Pinned<'a, Location>>,
    ) -> Self {
        Self::new_unknown(backtrace)
    }
}

impl SnapshotAware for FunctionValue<'_> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        self.r#ref.snapshot_aware_eq(&other.r#ref)
            && self.signature == other.signature
            && self.outcome.snapshot_aware_eq(&other.outcome)
            && self.backtrace.snapshot_aware_eq(&other.backtrace)
            && self
                .deferred_checks
                .snapshot_aware_eq(&other.deferred_checks)
            && self.captures.len() == other.captures.len()
            && self.captures.iter().all(|(decl, binding)| {
                other
                    .captures
                    .get(decl)
                    .is_some_and(|other_binding| binding.snapshot_aware_eq(other_binding))
            })
        // intentionally ignoring call count
    }
}

/// Represents an unambiguous reference to a function declaration.
///
/// Among other uses, this is necessary to guarantee uniqueness of a
/// [`crate::labels::LabelTag::Synthetic`] when paired with a function parameter
/// index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FunctionRef<'a> {
    /// A normal function with a native declared name.
    ///
    /// This is a unique identifier because of the embedded location information
    /// offered by [`Pinned`] and [`Span`].
    Named(Pinned<'a, Span<'a>>),
    /// An anonymous function literal.
    Anonymous(Pinned<'a, Location>),
    /// A built-in function provided by the language or the Go standard library.
    BuiltIn(&'static str),
    /// An inferred function for which no declaration exists/was found.
    BlackboxInference(Uuid),
}

impl<'a> FunctionRef<'a> {
    pub fn declared_name(&self) -> Option<&'a str> {
        match self {
            Self::Named(span) => Some(span.content()),
            Self::BuiltIn(name) => Some(name),
            Self::Anonymous(_) | Self::BlackboxInference(_) => None,
        }
    }

    pub fn is_main(&self) -> bool {
        if let Self::Named(name) = self {
            name.content() == "main" && name.file() == "/main.go"
        } else {
            false
        }
    }
}

impl fmt::Display for FunctionRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Named(name) => name.content().fmt(f),
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
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match (self, other) {
            (Self::Named(a), Self::Named(b)) => a.cmp(b),
            (Self::Named(_), _) => cmp::Ordering::Less,
            (_, Self::Named(_)) => cmp::Ordering::Greater,
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
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl SnapshotAware for FunctionRef<'_> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Named(a), Self::Named(b)) => a == b,
            (Self::Anonymous(a), Self::Anonymous(b)) => a == b,
            (Self::BuiltIn(a), Self::BuiltIn(b)) => a == b,
            // UUIDs might differ between analyzer iterations
            // (they're randomly generated upon upgrade)
            (Self::BlackboxInference(_), Self::BlackboxInference(_)) => true,

            // not using wildcard to force revisiting impl for any new variants
            (
                Self::Named(_) | Self::Anonymous(_) | Self::BuiltIn(_) | Self::BlackboxInference(_),
                _,
            ) => false,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CaptureBinding<'a> {
    // fake function parameter that has been reserved for this capture so that
    // we can later plug into the existing realization pipeline when the closure
    // is actually invoked, allowing synthetic tags to become concrete labels
    fake_param_index: usize,
    // fake local symbol declaration created within the closure scope for this
    // capture (with a placeholder synthetic tag as its label)
    local_decl: Pinned<'a, Span<'a>>,
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
}

impl<'a> CaptureBinding<'a> {
    fn new(fake_param_index: usize, local_decl: Pinned<'a, Span<'a>>) -> Self {
        Self {
            fake_param_index,
            local_decl,
            hybrid_fallback: None,
        }
    }

    pub fn fake_param_index(&self) -> usize {
        self.fake_param_index
    }

    pub fn local_decl(&self) -> Pinned<'a, Span<'a>> {
        self.local_decl
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

    fn realize(
        &self,
        from_func: &FunctionRef<'a>,
        from_index: Option<usize>,
        concrete: Option<&LabelBacktrace<'a>>,
    ) -> Self {
        let mut binding = self.clone();

        if let Some(Some(fallback)) = binding.hybrid_fallback() {
            let realized = fallback.realize(from_func, from_index, concrete);

            binding.set_hybrid_fallback(realized);
        }

        binding
    }
}

impl SnapshotAware for CaptureBinding<'_> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        self.fake_param_index == other.fake_param_index
            && self.local_decl == other.local_decl
            && self
                .hybrid_fallback
                .snapshot_aware_eq(&other.hybrid_fallback)
    }
}
