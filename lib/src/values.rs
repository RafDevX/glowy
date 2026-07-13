use std::{
    borrow::Cow,
    cell::{Ref, RefCell, RefMut},
    fmt,
    hash::Hash,
    iter,
    rc::Rc,
};

use parser::{
    Location,
    ast::{BinaryOpKind, ExprNode, LiteralNode, UnaryOpKind},
};

pub use self::{
    channel::ChannelValue,
    composite::{CompositeValue, CompositeValueAdapter},
    expandable::ExpandableValue,
    function::{
        CaptureBinding, FunctionRef, FunctionValue, InherentSink, InherentSourceOrRevocation,
    },
    mobius::MobiusValue,
    package_ref::PackageRefValue,
    shapes::Value,
};
use crate::{
    Pinned,
    labels::{Label, LabelBacktrace, LabelBacktraceKind, SyntheticSlot},
    snapshots::SnapshotAware,
    types::TypeInfo,
};

mod channel;
mod composite;
mod expandable;
mod function;
mod mobius;
mod package_ref;
mod shapes;

// wrapper struct (vs. type alias) allows impl'ing despite orphan rule
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ValueRef<'a> {
    value: Rc<RefCell<Value<'a>>>,
    location: Pinned<'a, Location>,
    // declared static type, derived directly from explicit syntax.
    // this is None if unknown, which is the most common case, as we only do
    // very rudimentary type propagation to help improve (slightly) method
    // dispatch by receiver type without resorting to too complex type handling
    declared_type: Option<Rc<TypeInfo<'a>>>,
}

impl<'a> ValueRef<'a> {
    pub fn new(
        value: Value<'a>,
        location: Pinned<'a, Location>,
        declared_type: Option<Rc<TypeInfo<'a>>>,
    ) -> Self {
        Self {
            value: Rc::new(RefCell::new(value)),
            location,
            declared_type,
        }
    }

    pub fn new_bottom(
        location: Pinned<'a, Location>,
        declared_type: Option<Rc<TypeInfo<'a>>>,
    ) -> Self {
        Self::new(Value::Simple(None), location, declared_type)
    }

    pub fn from_backtrace_or_bottom_at<F>(
        backtrace: Option<LabelBacktrace<'a>>,
        bottom_at: F,
    ) -> Self
    where
        F: FnOnce() -> Pinned<'a, Location>,
    {
        if let Some(backtrace) = backtrace {
            Self::from(backtrace)
        } else {
            Self::new_bottom(bottom_at(), None)
        }
    }

    pub fn with_location(&self, location: Pinned<'a, Location>) -> Self {
        Self {
            value: Rc::clone(&self.value),
            location,
            declared_type: self.declared_type.clone(), // cheap
        }
    }

    // takes ownership to avoid cloning location
    // (otherwise, use Self::set_declared_type)
    pub fn into_with_declared_type(mut self, declared_type: Option<Rc<TypeInfo<'a>>>) -> Self {
        self.declared_type = declared_type;

        self
    }

    /// Copy by value or by reference according to Go aliasing rules.
    pub fn copy(&self) -> Self {
        let borrowed = self.value.borrow();

        if borrowed.is_copy_by_reference() {
            self.clone()
        } else {
            Self {
                value: Rc::new(RefCell::new(borrowed.clone())),
                location: self.location.clone(),
                declared_type: self.declared_type.clone(), // cheap
            }
        }
    }

    /// Force cloning inner value (copy by value).
    pub fn clone_inner(&self) -> Self {
        let borrowed = self.value.borrow();

        Self {
            value: Rc::new(RefCell::new(borrowed.clone())),
            location: self.location.clone(),
            declared_type: self.declared_type.clone(), // cheap
        }
    }

    pub fn backtrace(&self) -> Option<LabelBacktrace<'a>> {
        self.value
            .borrow()
            .backtrace_at_location(self.location.clone())
    }

    pub fn location(&self) -> &Pinned<'a, Location> {
        &self.location
    }

    pub fn declared_type(&self) -> Option<&Rc<TypeInfo<'a>>> {
        self.declared_type.as_ref()
    }

    pub fn set_declared_type(&mut self, declared_type: Rc<TypeInfo<'a>>) {
        self.declared_type = Some(declared_type);
    }

    pub fn is_simple(&self) -> bool {
        matches!(*self.value.borrow(), Value::Simple(_))
    }

    pub fn is_mobius(&self) -> bool {
        matches!(*self.value.borrow(), Value::Mobius(_))
    }

    pub fn is_channel(&self) -> bool {
        matches!(*self.value.borrow(), Value::Channel(_))
    }

    pub fn is_map(&self) -> bool {
        matches!(*self.value.borrow(), Value::Map(_))
    }

    pub fn is_composite(&self) -> bool {
        matches!(
            *self.value.borrow(),
            Value::Array(_) | Value::Slice(_) | Value::Map(_) | Value::Struct(_)
        )
    }

    pub fn is_function(&self) -> bool {
        matches!(*self.value.borrow(), Value::Function(_))
    }

    /// Downgrade a complex shape into a [`Value::Simple`] of same backtrace.
    pub fn downgrade<F>(&self, location_if_bottom: F) -> Self
    where
        F: FnOnce() -> Pinned<'a, Location>,
    {
        Self::from_backtrace_or_bottom_at(self.backtrace(), location_if_bottom)
    }

    pub fn copy_shape(&self, backtrace: LabelBacktrace<'a>) -> Self {
        let inner = self.value.borrow().copy_shape(backtrace);

        Self::new(inner, self.location.clone(), self.declared_type.clone())
    }

    pub fn try_upgrade_to_channel(&self) {
        self.try_upgrade_to(Value::Channel);
    }

    pub fn try_upgrade_to_array(&self) {
        self.try_upgrade_to(Value::Array);
    }

    pub fn try_upgrade_to_slice(&self) {
        self.try_upgrade_to(Value::Slice);
    }

    pub fn try_upgrade_to_struct(&self) {
        self.try_upgrade_to(Value::Struct);
    }

    /// Coerce a [`Value::Simple`] to take a complex shape when first used.
    fn try_upgrade_to<C: Upgrade<'a>>(&self, f: impl FnOnce(C) -> Value<'a>) {
        // a Möbius wrapping a Simple represents a single value of unknown
        // cardinality; shape coercion implies single-value treatment, so
        // collapse it first to expose the inner Simple to the upgrade below
        self.try_singularize_simple_mobius();

        let borrow = self.value.borrow();

        if let Value::Simple(backtrace) = &*borrow {
            let inner = C::upgrade(backtrace.clone(), Cow::Borrowed(&self.location));

            drop(borrow); // release the immutable borrow

            *self.value.borrow_mut() = f(inner);
        }
    }

    fn try_singularize_simple_mobius(&self) {
        let new = if let Value::Mobius(mobius) = &*self.value.borrow()
            && let value @ Value::Simple(_) = &*mobius.inner().value.borrow()
        {
            Some(value.clone())
        } else {
            None
        };

        if let Some(new) = new {
            *self.value.borrow_mut() = new;
        }
    }

    pub fn try_expand_to(&self, desired_len: usize) -> Option<Vec<Self>> {
        // this utility method enforces correctness by *always* checking for
        // Möbius *before* expandable: it is very important to always check
        // Möbius first and foremost, as otherwise it would be upgraded
        // into a size-1 expandable, discarding the important information
        // that it can already be expanded to any arbitrary size

        if let Some(mobius) = self.as_mobius() {
            Some(mobius.expand_to(desired_len))
        } else {
            // note that this might lead to a different length than the one
            // requested via `desired_len`!
            self.as_expandable().as_deref().map(ExpandableValue::expand)
        }
    }

    pub fn supports_overriding_expand_indices(&self) -> bool {
        matches!(
            *self.value.borrow(),
            Value::Expandable(_) | Value::Mobius(_)
        )
    }

    pub fn try_nest_override_expand_indices(
        &self,
        indices: impl IntoIterator<Item = usize>,
        nest_with_kind: LabelBacktraceKind,
        nest_with_symbol: Option<&'a str>,
        nest_with_location: &Pinned<'a, Location>,
        extra_children: &[LabelBacktrace<'a>],
    ) -> Option<Self> {
        let borrowed = self.value.borrow();

        let new = match &*borrowed {
            Value::Expandable(expandable) => {
                Value::Expandable(expandable.nest_override_expand_indices(
                    indices,
                    nest_with_kind,
                    nest_with_symbol,
                    nest_with_location,
                    extra_children,
                ))
            }
            Value::Mobius(mobius) => Value::Mobius(mobius.nest_override_expand_indices(
                indices,
                nest_with_kind,
                nest_with_symbol,
                nest_with_location,
                extra_children,
            )),
            Value::Simple(_)
            | Value::PackageRef(_)
            | Value::Channel(_)
            | Value::Array(_)
            | Value::Slice(_)
            | Value::Map(_)
            | Value::Struct(_)
            | Value::Function(_) => return None,
        };

        Some(Self::new(
            new,
            self.location.clone(),
            self.declared_type.clone(),
        ))
    }

    pub fn try_subtract_override_expand_indices(
        &self,
        indices: impl IntoIterator<Item = usize>,
        subtract: &Label<'a>,
    ) -> Option<Self> {
        let borrowed = self.value.borrow();

        let new = match &*borrowed {
            Value::Expandable(expandable) => {
                Value::Expandable(expandable.subtract_override_expand_indices(indices, subtract))
            }
            Value::Mobius(mobius) => {
                Value::Mobius(mobius.subtract_override_expand_indices(indices, subtract))
            }
            Value::Simple(_)
            | Value::PackageRef(_)
            | Value::Channel(_)
            | Value::Array(_)
            | Value::Slice(_)
            | Value::Map(_)
            | Value::Struct(_)
            | Value::Function(_) => return None,
        };

        Some(Self::new(
            new,
            self.location.clone(),
            self.declared_type.clone(),
        ))
    }

    pub fn extract_collapsed_single(&self) -> Self {
        // we match the inner `Value` variant directly rather than going through
        // `as_mobius`/`as_expandable`: those getters call `try_upgrade_to`,
        // which would coerce a `Simple` into a size-1 wrapper -- pointlessly
        // destructive (a `Simple` is already a single value), and worse, the
        // coerced inner is reconstructed without the outer's `declared_type`,
        // silently breaking downstream typed dispatch

        match &*self.value.borrow() {
            Value::Mobius(mobius) => {
                let inner = mobius.inner();

                // prefer the inner's `declared_type` (the typical case where
                // the producer tagged it on the inner directly), falling back
                // to the outer's tag so type identity survives the unwrap
                // regardless of where it was stamped
                let declared_type = inner
                    .declared_type
                    .clone()
                    .or_else(|| self.declared_type.clone());

                Self::new(
                    inner.value.borrow().clone(),
                    self.location.clone(),
                    declared_type,
                )
            }
            Value::Expandable(expandable) => {
                let mut primary = expandable.primary();

                // primary may have been recorded without a `declared_type`
                // even when the outer ValueRef carries one; propagate it so
                // downstream typed dispatch sees the right type
                if primary.declared_type.is_none() {
                    primary.declared_type.clone_from(&self.declared_type);
                }

                primary
            }
            // exhaustive to force re-visiting impl if a new type is ever added
            Value::Simple(_)
            | Value::PackageRef(_)
            | Value::Channel(_)
            | Value::Array(_)
            | Value::Slice(_)
            | Value::Map(_)
            | Value::Struct(_)
            | Value::Function(_) => self.clone(),
        }
    }
}

macro_rules! extract_inner {
    ($variant:path, $value:expr) => {
        match $value {
            $variant(inner) => Some(inner),
            _ => None,
        }
    };
    ($variant:path) => {
        |value| extract_inner!($variant, value)
    };
    (*, $variant:path) => {
        |value| extract_inner!($variant, value).map(|r#box| &**r#box)
    };
    (*mut, $variant:path) => {
        |value| extract_inner!($variant, value).map(|r#box| &mut **r#box)
    };
}

#[expect(
    clippy::multiple_inherent_impl,
    reason = "Scope the below `expect` to only the relevant methods"
)]
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "We explicitly want to match only one variant and ignore all others"
)]
impl<'a> ValueRef<'a> {
    // private to force going through Self::try_expand_to
    fn as_expandable(&self) -> Option<Ref<'_, ExpandableValue<'a>>> {
        self.try_upgrade_to(Value::Expandable);

        Ref::filter_map(self.value.borrow(), extract_inner!(Value::Expandable)).ok()
    }

    // private to force going through Self::try_expand_to
    fn as_mobius(&self) -> Option<Ref<'_, MobiusValue<'a>>> {
        if !self.is_mobius() {
            // if this is already a Möbius, don't try to upgrade, since it'd
            // also singularize it first, making it lose any per-index overrides
            // that `self` might carry in its internal state
            self.try_upgrade_to(Value::Mobius);
        }

        Ref::filter_map(self.value.borrow(), extract_inner!(Value::Mobius)).ok()
    }

    pub fn as_package_ref(&self) -> Option<Ref<'_, PackageRefValue<'a>>> {
        // no coercion because there's no 'blank' package ref

        Ref::filter_map(self.value.borrow(), extract_inner!(Value::PackageRef)).ok()
    }

    pub fn as_channel(&self) -> Option<Ref<'_, ChannelValue<'a>>> {
        self.try_upgrade_to(Value::Channel);

        Ref::filter_map(self.value.borrow(), extract_inner!(Value::Channel)).ok()
    }

    pub fn as_slice_mut(&mut self) -> Option<RefMut<'_, CompositeValue<'a, u64>>> {
        self.try_upgrade_to(Value::Slice);

        RefMut::filter_map(self.value.borrow_mut(), extract_inner!(Value::Slice)).ok()
    }

    pub fn as_map_mut(&mut self) -> Option<RefMut<'_, CompositeValue<'a, SimpleConstValue>>> {
        self.try_upgrade_to(Value::Map);

        RefMut::filter_map(self.value.borrow_mut(), extract_inner!(Value::Map)).ok()
    }

    // (complex because Simple is technically also sliceable but not supported
    // here due to the upgrade that would change it to a complex shape)
    pub fn as_complex_sliceable(&self) -> Option<Ref<'_, CompositeValue<'a, u64>>> {
        self.try_upgrade_to(Value::Slice);

        Ref::filter_map(self.value.borrow(), |value| match value {
            Value::Array(composite) | Value::Slice(composite) => Some(composite),
            _ => None,
        })
        .ok()
    }

    pub fn as_composite(&self) -> Option<Ref<'_, dyn CompositeValueAdapter<'a>>> {
        self.try_upgrade_to(Value::Array);

        Ref::filter_map(self.value.borrow(), |value| match value {
            Value::Array(composite) | Value::Slice(composite) => {
                Some(composite as &dyn CompositeValueAdapter<'a>)
            }
            Value::Map(composite) => Some(composite),
            _ => None,
        })
        .ok()
    }

    pub fn as_composite_mut(&mut self) -> Option<RefMut<'_, dyn CompositeValueAdapter<'a>>> {
        self.try_upgrade_to(Value::Array);

        RefMut::filter_map(self.value.borrow_mut(), |value| match value {
            Value::Array(composite) | Value::Slice(composite) => {
                Some(composite as &mut dyn CompositeValueAdapter<'a>)
            }
            Value::Map(composite) => Some(composite),
            _ => None,
        })
        .ok()
    }

    pub fn as_struct(&self) -> Option<Ref<'_, CompositeValue<'a, String>>> {
        self.try_upgrade_to(Value::Struct);

        Ref::filter_map(self.value.borrow(), extract_inner!(Value::Struct)).ok()
    }

    pub fn as_struct_mut(&self) -> Option<RefMut<'_, CompositeValue<'a, String>>> {
        self.try_upgrade_to(Value::Struct);

        RefMut::filter_map(self.value.borrow_mut(), extract_inner!(Value::Struct)).ok()
    }

    pub fn as_function(&self) -> Option<Ref<'_, FunctionValue<'a>>> {
        self.try_upgrade_to(Value::Function);

        Ref::filter_map(self.value.borrow(), extract_inner!(*, Value::Function)).ok()
    }

    pub fn as_function_mut(&mut self) -> Option<RefMut<'_, FunctionValue<'a>>> {
        self.try_upgrade_to(Value::Function);

        RefMut::filter_map(
            self.value.borrow_mut(),
            extract_inner!(*mut, Value::Function),
        )
        .ok()
    }
}

impl<'a> From<LabelBacktrace<'a>> for ValueRef<'a> {
    fn from(backtrace: LabelBacktrace<'a>) -> Self {
        Self::new(
            Value::Simple(Some(backtrace.clone())),
            backtrace.location().clone(),
            None,
        )
    }
}

pub trait BacktraceContainer<'a> {
    fn backtrace_at_location(&self, location: Pinned<'a, Location>) -> Option<LabelBacktrace<'a>>;

    fn is_bottom(&self) -> bool;

    // whether the only information that would be lost if this value was to be
    // replaced with a Value::Simple would literally be just the shape
    // discrimination (e.g., this is always true for a MobiusValue because it
    // stores no additional metadata besides the fact of its own existence)
    fn allows_lossless_downgrade(&self) -> bool;

    // recursion helper for revocation
    fn subtract_label(&mut self, subtract: &Label<'a>);
}

impl<'a> BacktraceContainer<'a> for ValueRef<'a> {
    fn backtrace_at_location(&self, location: Pinned<'a, Location>) -> Option<LabelBacktrace<'a>> {
        self.with_location(location).backtrace()
    }

    fn is_bottom(&self) -> bool {
        self.value.borrow().is_bottom()
    }

    fn allows_lossless_downgrade(&self) -> bool {
        self.value.borrow().allows_lossless_downgrade()
    }

    fn subtract_label(&mut self, subtract: &Label<'a>) {
        if subtract.is_bottom() {
            // nothing to do
            return;
        }

        self.value.borrow_mut().subtract_label(subtract);
    }
}

// can't be part of BacktraceContainer because returning Self is sadly not
// dyn-compatible (nor is `param: impl Trait`)
pub trait SelfAwareBacktraceContainer<'a> {
    fn realize(
        &self,
        from_func: &FunctionRef<'a>,
        from_slot: SyntheticSlot,
        concrete: Option<&LabelBacktrace<'a>>,
    ) -> Self;

    fn nest_backtrace(
        &self,
        parent_kind: LabelBacktraceKind,
        parent_symbol: Option<&'a str>,
        parent_location: Pinned<'a, Location>,
        extra_children: impl IntoIterator<Item = LabelBacktrace<'a>> + Clone,
    ) -> Self;
    // ^ ideally should be Item = &'b LabelBacktrace<'a>, but borrow checker
    // hates it and there doesn't seem to be any workaround to make it compile
}

impl<'a> SelfAwareBacktraceContainer<'a> for ValueRef<'a> {
    fn realize(
        &self,
        from_func: &FunctionRef<'a>,
        from_slot: SyntheticSlot,
        concrete: Option<&LabelBacktrace<'a>>,
    ) -> Self {
        let borrowed = self.value.borrow();

        let realized = borrowed.realize(from_func, from_slot, concrete);

        Self::new(
            realized,
            self.location.clone(),
            self.declared_type.clone(), // cheap
        )
    }

    fn nest_backtrace(
        &self,
        parent_kind: LabelBacktraceKind,
        parent_symbol: Option<&'a str>,
        parent_location: Pinned<'a, Location>,
        extra_children: impl IntoIterator<Item = LabelBacktrace<'a>> + Clone,
    ) -> Self {
        let borrowed = self.value.borrow();

        #[rustfmt::skip]
        let nested = borrowed.nest_backtrace(
            parent_kind,
            parent_symbol,
            parent_location,
            extra_children,
        );

        Self::new(
            nested,
            self.location.clone(),
            self.declared_type.clone(), // cheap
        )
    }
}

// can't be part of SelfAwareBacktraceContainer because some sub-containers
// might not want to implement this, such as PackageRefValue (where this would
// make absolutely no sense and even be semantically incorrect)
pub trait Mergeable<'a> {
    fn merge_with(
        &self,
        other: &Self,
        with_kind: LabelBacktraceKind,
        at_location: Cow<Pinned<'a, Location>>,
    ) -> Self;
}

impl<'a> Mergeable<'a> for ValueRef<'a> {
    fn merge_with(
        &self,
        other: &Self,
        with_kind: LabelBacktraceKind,
        at_location: Cow<Pinned<'a, Location>>,
    ) -> Self {
        let b1 = self.value.borrow();
        let b2 = other.value.borrow();

        let merged = b1.merge_with(&b2, with_kind, at_location);

        let declared_type = if let Some(t1) = self.declared_type()
            && let Some(t2) = other.declared_type()
            && Rc::ptr_eq(t1, t2)
        {
            Some(Rc::clone(t1))
        } else {
            None
        };

        Self::new(merged, self.location.clone(), declared_type)
    }
}

impl SnapshotAware for ValueRef<'_> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        if Rc::ptr_eq(&self.value, &other.value) {
            // in the rare case we already know the two values are (literally)
            // the same one, we can just exit early
            return true;
        }

        self.value.borrow().snapshot_aware_eq(&other.value.borrow())
    }
}

impl<'a> BacktraceContainer<'a> for Option<LabelBacktrace<'a>> {
    fn backtrace_at_location(&self, location: Pinned<'a, Location>) -> Self {
        self.clone()
            .map(|bt| (bt.symbol(), bt)) // thanks borrow checker, very cool
            .map(|(sym, bt)| bt.into_single_child(LabelBacktraceKind::Expression, sym, location))
    }

    fn is_bottom(&self) -> bool {
        self.is_none()
    }

    fn allows_lossless_downgrade(&self) -> bool {
        true
    }

    fn subtract_label(&mut self, subtract: &Label<'a>) {
        self.take_if(|bt| !bt.subtract_label(subtract));
    }
}

impl<'a> SelfAwareBacktraceContainer<'a> for Option<LabelBacktrace<'a>> {
    fn realize(
        &self,
        from_func: &FunctionRef<'a>,
        from_slot: SyntheticSlot,
        concrete: Option<&LabelBacktrace<'a>>,
    ) -> Self {
        if let Some(bt) = self {
            bt.realize(from_func, from_slot, concrete)
        } else {
            None
        }
    }

    fn nest_backtrace(
        &self,
        parent_kind: LabelBacktraceKind,
        parent_symbol: Option<&'a str>,
        parent_location: Pinned<'a, Location>,
        extra_children: impl IntoIterator<Item = LabelBacktrace<'a>> + Clone,
    ) -> Self {
        let children: Vec<_> = iter::empty()
            .chain(self.clone())
            .chain(extra_children)
            .collect();

        LabelBacktrace::fold(children.iter(), parent_kind, parent_symbol, parent_location)
    }
}

impl<'a> Mergeable<'a> for Option<LabelBacktrace<'a>> {
    fn merge_with(
        &self,
        other: &Self,
        with_kind: LabelBacktraceKind,
        at_location: Cow<Pinned<'a, Location>>,
    ) -> Self {
        match (self, other) {
            (None, None) => None,
            (Some(only), None) | (None, Some(only)) => Some(only.clone()),
            (Some(a), Some(b)) => Some(LabelBacktrace::union(
                a,
                b,
                with_kind,
                at_location.into_owned(),
            )),
        }
    }
}

trait Upgrade<'a> {
    // Coerce from a Value::Simple to Self, preserving inner backtrace
    fn upgrade(backtrace: Option<LabelBacktrace<'a>>, location: Cow<Pinned<'a, Location>>) -> Self;
}

impl<'a, T: Upgrade<'a>> Upgrade<'a> for Box<T> {
    fn upgrade(backtrace: Option<LabelBacktrace<'a>>, location: Cow<Pinned<'a, Location>>) -> Self {
        Self::new(T::upgrade(backtrace, location))
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum SimpleConstValue {
    Boolean(bool),
    Integer(u64),
    String(String),
}

// basic support for literal-only composition, e.g. `2 + 3` is recognized as 5
impl SimpleConstValue {
    pub fn try_resolve_from_expr(expr: &ExprNode<'_>) -> Option<Self> {
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "We explicitly only want a very restricted set of expressions"
        )]
        let result = match expr {
            ExprNode::Literal(LiteralNode::String { value, .. }) => Self::String(value.clone()),
            ExprNode::Literal(LiteralNode::Int { value, .. }) => Self::Integer(*value),
            ExprNode::UnaryOp {
                kind: UnaryOpKind::Identity,
                operand,
                ..
            } => Self::try_resolve_from_expr(operand)?,
            ExprNode::BinaryOp {
                kind, left, right, ..
            } => {
                let left = Self::try_resolve_from_expr(left)?;
                let right = Self::try_resolve_from_expr(right)?;

                // some operations are treated specially
                #[expect(
                    clippy::wildcard_enum_match_arm,
                    reason = "Only interested in some kinds here; rest is handled below"
                )]
                match kind {
                    BinaryOpKind::Sum => {
                        // check right before left to avoid having to clone either
                        // (since we never need ownership of right)
                        if let Self::String(right) = &right
                            && let Self::String(left) = left
                        {
                            // string concatenation
                            return Some(Self::String(left + right));
                        }
                    }
                    BinaryOpKind::Eq => return Some(Self::Boolean(left == right)),
                    BinaryOpKind::NotEq => return Some(Self::Boolean(left != right)),
                    BinaryOpKind::LogicalAnd => {
                        if let (Self::Boolean(left), Self::Boolean(right)) = (&left, &right) {
                            return Some(Self::Boolean(*left && *right));
                        }
                    }
                    BinaryOpKind::LogicalOr => {
                        if let (Self::Boolean(left), Self::Boolean(right)) = (&left, &right) {
                            return Some(Self::Boolean(*left || *right));
                        }
                    }
                    _ => {}
                }

                // otherwise, must be integer operation

                let Self::Integer(left) = left else {
                    return None;
                };
                let Self::Integer(right) = right else {
                    return None;
                };

                match kind {
                    BinaryOpKind::Sum => Self::Integer(left.saturating_add(right)),
                    BinaryOpKind::Diff => Self::Integer(left.saturating_sub(right)),
                    BinaryOpKind::Product => Self::Integer(left.saturating_mul(right)),
                    BinaryOpKind::Quotient if right != 0 => {
                        Self::Integer(left.saturating_div(right))
                    }
                    BinaryOpKind::Remainder => Self::Integer(left % right),
                    BinaryOpKind::ShiftLeft => Self::Integer(left << right),
                    BinaryOpKind::ShiftRight => Self::Integer(left >> right),
                    BinaryOpKind::BitwiseOr => Self::Integer(left | right),
                    BinaryOpKind::BitwiseAnd => Self::Integer(left & right),
                    BinaryOpKind::BitwiseXor => Self::Integer(left ^ right),
                    BinaryOpKind::BitClear => Self::Integer(left & !right),

                    BinaryOpKind::Less => Self::Boolean(left < right),
                    BinaryOpKind::LessEq => Self::Boolean(left <= right),
                    BinaryOpKind::Greater => Self::Boolean(left > right),
                    BinaryOpKind::GreaterEq => Self::Boolean(left >= right),

                    // already handled above
                    BinaryOpKind::Eq | BinaryOpKind::NotEq => unreachable!(),

                    // not using wildcard to force revisiting this
                    // implementation if a new op kind is added
                    BinaryOpKind::LogicalAnd | BinaryOpKind::LogicalOr | BinaryOpKind::Quotient => {
                        return None;
                    }
                }
            }
            _ => return None,
        };

        Some(result)
    }
}

impl fmt::Display for SimpleConstValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Boolean(inner) => inner.fmt(f),
            Self::Integer(inner) => inner.fmt(f),
            Self::String(inner) => inner.fmt(f),
        }
    }
}
