use std::{
    borrow::Cow,
    cell::{Ref, RefCell, RefMut},
    cmp,
    collections::{HashMap, hash_map::Entry},
    fmt,
    hash::Hash,
    iter,
    rc::Rc,
};

use parser::{
    Location, Span,
    ast::{
        BinaryOpKind, ExprNode, FunctionParamDeclNode, FunctionResultNode, FunctionSignatureNode,
        LiteralNode, TypeNode, UnaryOpKind,
    },
};
use uuid::Uuid;

use crate::{
    Pinned,
    context::DeferredEnforcementCheck,
    labels::{LabelBacktrace, LabelBacktraceKind},
    snapshots::SnapshotAware,
};

// wrapper struct (vs. type alias) allows impl'ing despite orphan rule
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ValueRef<'a> {
    value: Rc<RefCell<Value<'a>>>,
    location: Pinned<Location>,
}

impl<'a> ValueRef<'a> {
    pub fn new(value: Value<'a>, location: Pinned<Location>) -> Self {
        Self {
            value: Rc::new(RefCell::new(value)),
            location,
        }
    }

    pub fn new_bottom(location: Pinned<Location>) -> Self {
        Self::new(Value::Simple(None), location)
    }

    pub fn from_backtrace_or_bottom_at<F>(
        backtrace: Option<LabelBacktrace<'a>>,
        bottom_at: F,
    ) -> Self
    where
        F: FnOnce() -> Pinned<Location>,
    {
        if let Some(backtrace) = backtrace {
            Self::from(backtrace)
        } else {
            Self::new_bottom(bottom_at())
        }
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
            }
        }
    }

    /// Force cloning inner value (copy by value).
    pub fn clone_inner(&self) -> Self {
        let borrowed = self.value.borrow();

        Self {
            value: Rc::new(RefCell::new(borrowed.clone())),
            location: self.location.clone(),
        }
    }

    pub fn with_location(&self, location: Pinned<Location>) -> Self {
        Self {
            value: Rc::clone(&self.value),
            location,
        }
    }

    pub fn location(&self) -> &Pinned<Location> {
        &self.location
    }

    pub fn backtrace(&self) -> Option<LabelBacktrace<'a>> {
        self.value
            .borrow()
            .backtrace_at_location(self.location.clone())
    }

    pub fn is_simple(&self) -> bool {
        matches!(*self.value.borrow(), Value::Simple(_))
    }

    pub fn is_map(&self) -> bool {
        matches!(*self.value.borrow(), Value::Map(_))
    }

    /// Downgrade a complex shape into a [`Value::Simple`] of same backtrace.
    pub fn downgrade<F>(&self, location_if_bottom: F) -> Self
    where
        F: FnOnce() -> Pinned<Location>,
    {
        Self::from_backtrace_or_bottom_at(self.backtrace(), location_if_bottom)
    }

    /// Coerce a [`Value::Simple`] to take a complex shape when first used.
    fn try_upgrade_to<C: Upgrade<'a>>(&self, f: impl FnOnce(C) -> Value<'a>) {
        let borrow = self.value.borrow();

        if let Value::Simple(backtrace) = &*borrow {
            let inner = C::upgrade(backtrace.clone(), Cow::Borrowed(&self.location));

            drop(borrow); // release the immutable borrow

            *self.value.borrow_mut() = f(inner);
        }
    }

    pub fn try_singularize_simple_mobius(&mut self) {
        let new = if let Value::Mobius(MobiusValue(inner)) = &*self.value.borrow() {
            if let value @ Value::Simple(_) = &*inner.value.borrow() {
                Some(value.clone())
            } else {
                None
            }
        } else {
            None
        };

        if let Some(new) = new {
            *self.value.borrow_mut() = new;
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
    pub fn as_expandable(&self) -> Option<Ref<'_, ExpandableValue<'a>>> {
        self.try_upgrade_to(Value::Expandable);

        Ref::filter_map(self.value.borrow(), extract_inner!(Value::Expandable)).ok()
    }

    pub fn as_mobius(&self) -> Option<Ref<'_, MobiusValue<'a>>> {
        self.try_upgrade_to(Value::Mobius);

        Ref::filter_map(self.value.borrow(), extract_inner!(Value::Mobius)).ok()
    }

    pub fn as_package_ref(&self) -> Option<Ref<'_, PackageRefValue<'a>>> {
        // no coercion because there's no 'blank' package ref

        Ref::filter_map(self.value.borrow(), extract_inner!(Value::PackageRef)).ok()
    }

    pub fn as_slice_mut(&mut self) -> Option<RefMut<'_, CompositeValue<'a, u64>>> {
        self.try_upgrade_to(Value::Slice);

        RefMut::filter_map(self.value.borrow_mut(), extract_inner!(Value::Slice)).ok()
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
        )
    }
}

pub trait BacktraceContainer<'a> {
    fn backtrace_at_location(&self, location: Pinned<Location>) -> Option<LabelBacktrace<'a>>;

    fn is_bottom(&self) -> bool;

    // whether the only information that would be lost if this value was to be
    // replaced with a Value::Simple would literally be just the shape
    // discrimination (e.g., this is always true for a MobiusValue because it
    // stores no additional metadata besides the fact of its own existence)
    fn allows_lossless_downgrade(&self) -> bool;
}

impl<'a> BacktraceContainer<'a> for ValueRef<'a> {
    fn backtrace_at_location(&self, location: Pinned<Location>) -> Option<LabelBacktrace<'a>> {
        self.with_location(location).backtrace()
    }

    fn is_bottom(&self) -> bool {
        self.value.borrow().is_bottom()
    }

    fn allows_lossless_downgrade(&self) -> bool {
        self.value.borrow().allows_lossless_downgrade()
    }
}

// can't be part of BacktraceContainer because returning Self is sadly not
// dyn-compatible (nor is `param: impl Trait`)
pub trait SelfAwareBacktraceContainer<'a> {
    fn realize(
        &self,
        from_func: &FunctionRef<'a>,
        from_index: Option<usize>, // None for receiver
        concrete: Option<&LabelBacktrace<'a>>,
    ) -> Self;

    fn nest_backtrace(
        &self,
        parent_kind: LabelBacktraceKind,
        parent_symbol: Option<&'a str>,
        parent_location: Pinned<Location>,
        extra_children: impl IntoIterator<Item = LabelBacktrace<'a>> + Clone,
    ) -> Self;
    // ^ ideally should be Item = &'b LabelBacktrace<'a>, but borrow checker
    // hates it and there doesn't seem to be any workaround to make it compile
}

impl<'a> SelfAwareBacktraceContainer<'a> for ValueRef<'a> {
    fn realize(
        &self,
        from_func: &FunctionRef<'a>,
        from_index: Option<usize>,
        concrete: Option<&LabelBacktrace<'a>>,
    ) -> Self {
        let borrowed = self.value.borrow();

        let realized = borrowed.realize(from_func, from_index, concrete);

        Self {
            value: Rc::new(RefCell::new(realized)),
            location: self.location.clone(),
        }
    }

    fn nest_backtrace(
        &self,
        parent_kind: LabelBacktraceKind,
        parent_symbol: Option<&'a str>,
        parent_location: Pinned<Location>,
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

        Self {
            value: Rc::new(RefCell::new(nested)),
            location: self.location.clone(),
        }
    }
}

// can't be part of SelfAwareBacktraceContainer because some sub-containers
// might not want to implement this, such as PackageRefValue (where this would
// make absolutely no sense and even be semantically incorrect)
pub trait Mergeable {
    fn merge_with(
        &self,
        other: &Self,
        with_kind: LabelBacktraceKind,
        at_location: Cow<Pinned<Location>>,
    ) -> Self;
}

impl Mergeable for ValueRef<'_> {
    fn merge_with(
        &self,
        other: &Self,
        with_kind: LabelBacktraceKind,
        at_location: Cow<Pinned<Location>>,
    ) -> Self {
        let b1 = self.value.borrow();
        let b2 = other.value.borrow();

        let merged = b1.merge_with(&b2, with_kind, at_location);

        Self {
            value: Rc::new(RefCell::new(merged)),
            location: self.location.clone(),
        }
    }
}

impl SnapshotAware for ValueRef<'_> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        self.value.borrow().snapshot_aware_eq(&other.value.borrow())
    }
}

impl<'a> BacktraceContainer<'a> for Option<LabelBacktrace<'a>> {
    fn backtrace_at_location(&self, location: Pinned<Location>) -> Self {
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
}

impl<'a> SelfAwareBacktraceContainer<'a> for Option<LabelBacktrace<'a>> {
    fn realize(
        &self,
        from_func: &FunctionRef<'a>,
        from_index: Option<usize>,
        concrete: Option<&LabelBacktrace<'a>>,
    ) -> Self {
        if let Some(bt) = self {
            bt.realize(from_func, from_index, concrete)
        } else {
            None
        }
    }

    fn nest_backtrace(
        &self,
        parent_kind: LabelBacktraceKind,
        parent_symbol: Option<&'a str>,
        parent_location: Pinned<Location>,
        extra_children: impl IntoIterator<Item = LabelBacktrace<'a>> + Clone,
    ) -> Self {
        let children: Vec<_> = iter::empty()
            .chain(self.clone())
            .chain(extra_children)
            .collect();

        LabelBacktrace::fold(children.iter(), parent_kind, parent_symbol, parent_location)
    }
}

impl Mergeable for Option<LabelBacktrace<'_>> {
    fn merge_with(
        &self,
        other: &Self,
        with_kind: LabelBacktraceKind,
        at_location: Cow<Pinned<Location>>,
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

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Value<'a> {
    Simple(Option<LabelBacktrace<'a>>),
    // ^^^ a Value::Simple might be automatically coerced into one of the more
    // complex shapes below when used (or it might always just be Simple)
    Expandable(ExpandableValue<'a>),
    Mobius(MobiusValue<'a>),
    PackageRef(PackageRefValue<'a>),
    Array(CompositeValue<'a, u64>),
    Slice(CompositeValue<'a, u64>),
    Map(CompositeValue<'a, SimpleConstValue>),
    Struct(CompositeValue<'a, String>),
    Function(Box<FunctionValue<'a>>),
}

impl<'a> Value<'a> {
    fn is_copy_by_reference(&self) -> bool {
        // https://go.dev/ref/spec#Representation_of_values
        matches!(self, Self::Slice(..) | Self::Function { .. })
    }

    fn sub_container(&self) -> &dyn BacktraceContainer<'a> {
        match self {
            Self::Simple(opt) => opt,
            Self::Expandable(exp) => exp,
            Self::Mobius(mobius) => mobius,
            Self::PackageRef(pkg) => pkg,
            Self::Array(composite) | Self::Slice(composite) => composite,
            Self::Map(composite) => composite,
            Self::Struct(composite) => composite,
            Self::Function(func) => &**func,
        }
    }
}

impl<'a> BacktraceContainer<'a> for Value<'a> {
    fn backtrace_at_location(&self, location: Pinned<Location>) -> Option<LabelBacktrace<'a>> {
        self.sub_container().backtrace_at_location(location)
    }

    fn is_bottom(&self) -> bool {
        self.sub_container().is_bottom()
    }

    fn allows_lossless_downgrade(&self) -> bool {
        self.sub_container().allows_lossless_downgrade()
    }
}

impl<'a> SelfAwareBacktraceContainer<'a> for Value<'a> {
    // would prefer using `self.sub_container().method(...)`, but this trait
    // isn't dyn-compatible, so we must use a macro instead

    fn realize(
        &self,
        from_func: &FunctionRef<'a>,
        from_index: Option<usize>,
        concrete: Option<&LabelBacktrace<'a>>,
    ) -> Self {
        macro_rules! recurs {
            ($sub:expr) => {
                $sub.realize(from_func, from_index, concrete)
            };
        }

        match self {
            Self::Simple(bt) => Self::Simple(recurs!(bt)),
            Self::Expandable(exp) => Self::Expandable(recurs!(exp)),
            Self::Mobius(mobius) => Self::Mobius(recurs!(mobius)),
            Self::PackageRef(pkg) => Self::PackageRef(recurs!(pkg)),
            Self::Array(composite) => Self::Array(recurs!(composite)),
            Self::Slice(composite) => Self::Slice(recurs!(composite)),
            Self::Map(composite) => Self::Map(recurs!(composite)),
            Self::Struct(composite) => Self::Struct(recurs!(composite)),
            Self::Function(func) => Self::Function(Box::new(recurs!(&**func))),
        }
    }

    fn nest_backtrace(
        &self,
        parent_kind: LabelBacktraceKind,
        parent_symbol: Option<&'a str>,
        parent_location: Pinned<Location>,
        extra_children: impl IntoIterator<Item = LabelBacktrace<'a>> + Clone,
    ) -> Self {
        macro_rules! recurs {
            ($sub:expr) => {
                $sub.nest_backtrace(parent_kind, parent_symbol, parent_location, extra_children)
            };
        }

        match self {
            Self::Simple(bt) => Self::Simple(recurs!(bt)),
            Self::Expandable(exp) => Self::Expandable(recurs!(exp)),
            Self::Mobius(mobius) => Self::Mobius(recurs!(mobius)),
            Self::PackageRef(pkg) => Self::PackageRef(recurs!(pkg)),
            Self::Array(composite) => Self::Array(recurs!(composite)),
            Self::Slice(composite) => Self::Slice(recurs!(composite)),
            Self::Map(composite) => Self::Map(recurs!(composite)),
            Self::Struct(composite) => Self::Struct(recurs!(composite)),
            Self::Function(func) => Self::Function(Box::new(recurs!(&**func))),
        }
    }
}

impl Mergeable for Value<'_> {
    fn merge_with(
        &self,
        other: &Self,
        with_kind: LabelBacktraceKind,
        at_location: Cow<Pinned<Location>>,
    ) -> Self {
        macro_rules! recurs {
            ($a:expr, $b:expr) => {
                $a.merge_with($b, with_kind, at_location)
            };
        }

        match (self, other) {
            (Self::Simple(a), Self::Simple(b)) => Self::Simple(recurs!(a, b)),
            (Self::Expandable(a), Self::Expandable(b)) => Self::Expandable(recurs!(a, b)),
            (Self::Mobius(a), Self::Mobius(b)) => Self::Mobius(recurs!(a, b)),
            (Self::PackageRef(_), Self::PackageRef(_)) => Self::Simple(None),
            (Self::Array(a), Self::Array(b)) => Self::Array(recurs!(a, b)),
            (Self::Slice(a), Self::Slice(b)) => Self::Slice(recurs!(a, b)),
            (Self::Map(a), Self::Map(b)) => Self::Map(recurs!(a, b)),
            (Self::Struct(a), Self::Struct(b)) => Self::Struct(recurs!(a, b)),
            // intentionally not handling (Fn, Fn)
            // ---
            (Self::Simple(None), other) | (other, Self::Simple(None)) => other.clone(),
            (Self::Simple(Some(bt)), other) | (other, Self::Simple(Some(bt))) => other
                .nest_backtrace(
                    with_kind,
                    None,
                    at_location.into_owned(),
                    iter::once(bt.clone()),
                ),

            // no wildcard _ so we rely on exhaustiveness for maintainability
            // (compiler will error if a new variant is added and this method
            // is not updated to reflect that)
            (
                Self::Expandable(_)
                | Self::Mobius(_)
                | Self::PackageRef(_)
                | Self::Array(_)
                | Self::Slice(_)
                | Self::Map(_)
                | Self::Struct(_)
                | Self::Function(_),
                _,
            ) => {
                let location = at_location.clone().into_owned();
                let a = self.backtrace_at_location(location.clone());
                let b = other.backtrace_at_location(location);

                Self::Simple(recurs!(a, &b))
            }
        }
    }
}

impl SnapshotAware for Value<'_> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Simple(a), Self::Simple(b)) => a.snapshot_aware_eq(b),
            (Self::Expandable(a), Self::Expandable(b)) => a.snapshot_aware_eq(b),
            (Self::Mobius(a), Self::Mobius(b)) => a.snapshot_aware_eq(b),
            (Self::PackageRef(a), Self::PackageRef(b)) => a.snapshot_aware_eq(b),
            (Self::Array(a), Self::Array(b)) | (Self::Slice(a), Self::Slice(b)) => {
                a.snapshot_aware_eq(b)
            }
            (Self::Map(a), Self::Map(b)) => a.snapshot_aware_eq(b),
            (Self::Struct(a), Self::Struct(b)) => a.snapshot_aware_eq(b),
            (Self::Function(a), Self::Function(b)) => a.snapshot_aware_eq(b),

            // no wildcard _ so we rely on exhaustiveness for maintainability
            // (compiler will error if a new variant is added and this method
            // is not updated to reflect that)
            (
                Self::Simple(_)
                | Self::Expandable(_)
                | Self::Mobius(_)
                | Self::PackageRef(_)
                | Self::Array(_)
                | Self::Slice(_)
                | Self::Map(_)
                | Self::Struct(_)
                | Self::Function(_),
                _,
            ) => false,
        }
    }
}

trait Upgrade<'a> {
    // Coerce from a Value::Simple to Self, preserving inner backtrace
    fn upgrade(backtrace: Option<LabelBacktrace<'a>>, location: Cow<Pinned<Location>>) -> Self;
}

impl<'a, T: Upgrade<'a>> Upgrade<'a> for Box<T> {
    fn upgrade(backtrace: Option<LabelBacktrace<'a>>, location: Cow<Pinned<Location>>) -> Self {
        Self::new(T::upgrade(backtrace, location))
    }
}

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
    fn backtrace_at_location(&self, location: Pinned<Location>) -> Option<LabelBacktrace<'a>> {
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
}

impl<'a> SelfAwareBacktraceContainer<'a> for ExpandableValue<'a> {
    fn realize(
        &self,
        from_func: &FunctionRef<'a>,
        from_index: Option<usize>,
        concrete: Option<&LabelBacktrace<'a>>,
    ) -> Self {
        let primary = self.primary.realize(from_func, from_index, concrete);

        let secondary = self
            .secondary
            .iter()
            .map(|v| v.realize(from_func, from_index, concrete))
            .collect();

        Self { primary, secondary }
    }

    fn nest_backtrace(
        &self,
        parent_kind: LabelBacktraceKind,
        parent_symbol: Option<&'a str>,
        parent_location: Pinned<Location>,
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

impl Mergeable for ExpandableValue<'_> {
    fn merge_with(
        &self,
        other: &Self,
        with_kind: LabelBacktraceKind,
        at_location: Cow<Pinned<Location>>,
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
    fn upgrade(backtrace: Option<LabelBacktrace<'a>>, location: Cow<Pinned<Location>>) -> Self {
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

// represents a value of unknown, adaptable cardinality -- similar to an
// ExpandableValue, but more flexible, able to become any number of the same
// inner value, in a sort of illusion like a Möbius strip.
// (this struct by itself is very simple; its real purpose is just to
// semantically tag a value as needing some leniency when being treated)
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MobiusValue<'a>(ValueRef<'a>);

impl<'a> MobiusValue<'a> {
    pub fn new(inner: ValueRef<'a>) -> Self {
        Self(inner)
    }

    pub fn expand_to(&self, len: usize) -> Vec<ValueRef<'a>> {
        // note that vec! will just clone the ValueRef, but the underlying Value
        // is the same for all elements; only the references are cloned (cheap)
        vec![self.0.clone(); len]
    }
}

impl<'a> BacktraceContainer<'a> for MobiusValue<'a> {
    fn backtrace_at_location(&self, location: Pinned<Location>) -> Option<LabelBacktrace<'a>> {
        self.0.backtrace_at_location(location)
    }

    fn is_bottom(&self) -> bool {
        self.0.is_bottom()
    }

    fn allows_lossless_downgrade(&self) -> bool {
        true
    }
}

impl<'a> SelfAwareBacktraceContainer<'a> for MobiusValue<'a> {
    fn realize(
        &self,
        from_func: &FunctionRef<'a>,
        from_index: Option<usize>,
        concrete: Option<&LabelBacktrace<'a>>,
    ) -> Self {
        Self::new(self.0.realize(from_func, from_index, concrete))
    }

    fn nest_backtrace(
        &self,
        parent_kind: LabelBacktraceKind,
        parent_symbol: Option<&'a str>,
        parent_location: Pinned<Location>,
        extra_children: impl IntoIterator<Item = LabelBacktrace<'a>> + Clone,
    ) -> Self {
        Self::new(self.0.nest_backtrace(
            parent_kind,
            parent_symbol,
            parent_location,
            extra_children,
        ))
    }
}

impl Mergeable for MobiusValue<'_> {
    fn merge_with(
        &self,
        other: &Self,
        with_kind: LabelBacktraceKind,
        at_location: Cow<Pinned<Location>>,
    ) -> Self {
        Self::new(self.0.merge_with(&other.0, with_kind, at_location))
    }
}

impl<'a> Upgrade<'a> for MobiusValue<'a> {
    fn upgrade(backtrace: Option<LabelBacktrace<'a>>, location: Cow<Pinned<Location>>) -> Self {
        let inner = ValueRef::from_backtrace_or_bottom_at(backtrace, || location.into_owned());

        Self::new(inner)
    }
}

impl SnapshotAware for MobiusValue<'_> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        self.0.snapshot_aware_eq(&other.0)
    }
}

// represents a reference to another package by the name under which it was
// imported to this file -- this replaces the need for qualified identifiers,
// since `pkg.abc` becomes represented as a selection of "pseudo-field" `abc`
// on "pseudo-struct" `pkg` (which is actually a `PackageRefValue`).
// PackageRefValues are useless on their own and can only be used in selections.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PackageRefValue<'a>(Span<'a>);

impl<'a> PackageRefValue<'a> {
    pub fn new(qualifier: Span<'a>) -> Self {
        Self(qualifier)
    }

    pub fn qualifier(&self) -> Span<'a> {
        self.0
    }
}

impl<'a> BacktraceContainer<'a> for PackageRefValue<'a> {
    fn backtrace_at_location(&self, _location: Pinned<Location>) -> Option<LabelBacktrace<'a>> {
        None
    }

    fn is_bottom(&self) -> bool {
        true
    }

    fn allows_lossless_downgrade(&self) -> bool {
        false
    }
}

impl<'a> SelfAwareBacktraceContainer<'a> for PackageRefValue<'a> {
    fn realize(
        &self,
        _from_func: &FunctionRef<'a>,
        _from_index: Option<usize>,
        _concrete: Option<&LabelBacktrace<'a>>,
    ) -> Self {
        self.clone()
    }

    fn nest_backtrace(
        &self,
        _parent_kind: LabelBacktraceKind,
        _parent_symbol: Option<&'a str>,
        _parent_location: Pinned<Location>,
        _extra_children: impl IntoIterator<Item = LabelBacktrace<'a>> + Clone,
    ) -> Self {
        self.clone()
    }
}

impl SnapshotAware for PackageRefValue<'_> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

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
        location: Pinned<Location>,
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

    pub fn get_const(&self, key: &K, at_location: Pinned<Location>) -> ValueRef<'a> {
        let value = match self.r#const.get(key).cloned() {
            Some(value) => value,
            None => ValueRef::new_bottom(at_location.clone()),
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

    pub fn get_dyn(&self, at_location: Pinned<Location>) -> ValueRef<'a> {
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
    pub fn set_dyn(&mut self, value: &ValueRef<'a>, at_location: Pinned<Location>) {
        self.r#dyn = LabelBacktrace::combine_options(
            self.r#dyn.clone(),
            value.backtrace(),
            LabelBacktraceKind::Assignment,
            Cow::Owned(at_location),
        );
    }
}

impl<'a, K: Eq + Hash + Ord> CompositeValue<'a, K> {
    pub fn slice_const(
        &self,
        low: Option<&K>,
        high: Option<&K>,
        at_location: Pinned<Location>,
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

    pub fn slice_dyn(&self, at_location: Pinned<Location>) -> Option<LabelBacktrace<'a>> {
        self.backtrace_at_location(at_location)
    }
}

impl<'a, K: Eq + Hash> BacktraceContainer<'a> for CompositeValue<'a, K> {
    fn backtrace_at_location(&self, location: Pinned<Location>) -> Option<LabelBacktrace<'a>> {
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
}

impl<'a, K: Eq + Hash + Clone> SelfAwareBacktraceContainer<'a> for CompositeValue<'a, K> {
    fn realize(
        &self,
        from_func: &FunctionRef<'a>,
        from_index: Option<usize>,
        concrete: Option<&LabelBacktrace<'a>>,
    ) -> Self {
        let r#const = self
            .r#const
            .iter()
            .map(|(k, v)| (k.clone(), v.realize(from_func, from_index, concrete)))
            .collect();

        let r#dyn = self.r#dyn.realize(from_func, from_index, concrete);

        Self { r#const, r#dyn }
    }

    fn nest_backtrace(
        &self,
        parent_kind: LabelBacktraceKind,
        parent_symbol: Option<&'a str>,
        parent_location: Pinned<Location>,
        extra_children: impl IntoIterator<Item = LabelBacktrace<'a>> + Clone,
    ) -> Self {
        let r#const = self.r#const.clone();

        let r#dyn =
            self.r#dyn
                .nest_backtrace(parent_kind, parent_symbol, parent_location, extra_children);

        Self { r#const, r#dyn }
    }
}

impl<K: Eq + Hash + Clone> Mergeable for CompositeValue<'_, K> {
    fn merge_with(
        &self,
        other: &Self,
        with_kind: LabelBacktraceKind,
        at_location: Cow<Pinned<Location>>,
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
    fn upgrade(backtrace: Option<LabelBacktrace<'a>>, _location: Cow<Pinned<Location>>) -> Self {
        Self::empty(backtrace)
    }
}

// assumes K: !SnapshotAware (i.e., it's a primitive irrelevant to this logic)
// (Rust negative trait bounds are unsupported, so we cannot enforce it)
impl<K: Eq + Hash> SnapshotAware for CompositeValue<'_, K> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        self.r#dyn.snapshot_aware_eq(&other.r#dyn)
            && self.r#const.len() == other.r#const.len()
            && self
                .r#const
                .iter()
                .all(|(k, v)| other.r#const.get(k).snapshot_aware_eq(&Some(v)))
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
        at_location: Pinned<Location>,
    ) -> ValueRef<'a>;

    fn get_at_unknown_key(&self, at_location: Pinned<Location>) -> ValueRef<'a>;

    fn set_at_known_key(
        &mut self,
        key: SimpleConstValue,
        value: ValueRef<'a>,
        at_location: Pinned<Location>,
    );

    fn set_at_unknown_key(&mut self, value: &ValueRef<'a>, at_location: Pinned<Location>);

    fn get_at_key(
        &self,
        key: Option<&SimpleConstValue>,
        at_location: Pinned<Location>,
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
        at_location: Pinned<Location>,
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
        at_location: Pinned<Location>,
    ) -> ValueRef<'a> {
        self.get_const(key, at_location)
    }

    fn get_at_unknown_key(&self, at_location: Pinned<Location>) -> ValueRef<'a> {
        self.get_dyn(at_location)
    }

    fn set_at_known_key(
        &mut self,
        key: SimpleConstValue,
        value: ValueRef<'a>,
        _at_location: Pinned<Location>,
    ) {
        self.set_const(key, value);
    }

    fn set_at_unknown_key(&mut self, value: &ValueRef<'a>, at_location: Pinned<Location>) {
        self.set_dyn(value, at_location);
    }
}

// integer key adapter
impl<'a> CompositeValueAdapter<'a> for CompositeValue<'a, u64> {
    fn get_at_known_key(
        &self,
        key: &SimpleConstValue,
        at_location: Pinned<Location>,
    ) -> ValueRef<'a> {
        if let SimpleConstValue::Integer(key) = key {
            self.get_const(key, at_location)
        } else {
            self.get_dyn(at_location)
        }
    }

    fn get_at_unknown_key(&self, at_location: Pinned<Location>) -> ValueRef<'a> {
        self.get_dyn(at_location)
    }

    fn set_at_known_key(
        &mut self,
        key: SimpleConstValue,
        value: ValueRef<'a>,
        at_location: Pinned<Location>,
    ) {
        if let SimpleConstValue::Integer(key) = key {
            self.set_const(key, value);
        } else {
            self.set_dyn(&value, at_location);
        }
    }

    fn set_at_unknown_key(&mut self, value: &ValueRef<'a>, at_location: Pinned<Location>) {
        self.set_dyn(value, at_location);
    }
}

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
    captures: HashMap<Pinned<Span<'a>>, CaptureBinding<'a>>,
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

    pub fn captures(&self) -> impl Iterator<Item = (&Pinned<Span<'a>>, &CaptureBinding<'a>)> {
        self.captures.iter()
    }

    pub fn captures_mut(
        &mut self,
    ) -> impl Iterator<Item = (&Pinned<Span<'a>>, &mut CaptureBinding<'a>)> {
        self.captures.iter_mut()
    }

    #[must_use]
    pub fn register_capture(
        &mut self,
        outer_decl: Cow<Pinned<Span<'a>>>,
        local_decl: Pinned<Span<'a>>,
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

            // self.captures
            //     .entry(outer_decl.into_owned())
            //     .insert_entry(CaptureBinding::new(fake_param_index, local_decl))
            //     .get()

            self.captures.insert(
                outer_decl.into_owned(),
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
    fn backtrace_at_location(&self, location: Pinned<Location>) -> Option<LabelBacktrace<'a>> {
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
                    outer_decl.clone(),
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
        parent_location: Pinned<Location>,
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
    fn upgrade(backtrace: Option<LabelBacktrace<'a>>, _location: Cow<Pinned<Location>>) -> Self {
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
    Named(Pinned<Span<'a>>),
    /// An anonymous function literal.
    Anonymous(Pinned<Location>),
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
    local_decl: Pinned<Span<'a>>,
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
    fn new(fake_param_index: usize, local_decl: Pinned<Span<'a>>) -> Self {
        Self {
            fake_param_index,
            local_decl,
            hybrid_fallback: None,
        }
    }

    pub fn fake_param_index(&self) -> usize {
        self.fake_param_index
    }

    pub fn local_decl(&self) -> &Pinned<Span<'a>> {
        &self.local_decl
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
                        if let Self::String(right) = &right {
                            if let Self::String(left) = left {
                                // string concatenation
                                return Some(Self::String(left + right));
                            }
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
