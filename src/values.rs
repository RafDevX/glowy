use std::{
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
    labels::{LabelBacktrace, LabelBacktraceKind},
};

// wrapper struct (vs. type alias) allows impl'ing despite orphan rule
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ValueRef<'a>(Rc<RefCell<Value<'a>>>);

impl<'a> ValueRef<'a> {
    #[inline]
    pub fn new_bottom() -> Self {
        Self::from(None)
    }

    /// Copy by value or by reference according to Go aliasing rules
    pub fn copy(&self) -> Self {
        let borrowed = self.0.borrow();

        if borrowed.is_copy_by_reference() {
            self.clone()
        } else {
            Self::from(borrowed.clone())
        }
    }

    /// Force cloning inner value (copy by value)
    pub fn clone_inner(&self) -> Self {
        let borrowed = self.0.borrow();

        Self::from(borrowed.clone())
    }

    pub fn is_simple(&self) -> bool {
        matches!(*self.0.borrow(), Value::Simple(_))
    }

    pub fn is_map(&self) -> bool {
        matches!(*self.0.borrow(), Value::Map(_))
    }

    // coerce a Value::Simple to take a complex shape when used
    fn try_upgrade_to<C: Upgrade<'a>>(&self, f: impl FnOnce(C) -> Value<'a>) {
        let borrow = self.0.borrow();

        if let Value::Simple(backtrace) = &*borrow {
            let inner = C::upgrade(backtrace.clone());

            drop(borrow); // release the immutable borrow

            *self.0.borrow_mut() = f(inner);
        }
    }

    pub fn try_singularize_simple_mobius(&mut self) {
        let new = if let Value::Mobius(MobiusValue(inner)) = &*self.0.borrow() {
            if let value @ Value::Simple(_) = &*inner.0.borrow() {
                Some(value.clone())
            } else {
                None
            }
        } else {
            None
        };

        if let Some(new) = new {
            *self.0.borrow_mut() = new;
        }
    }

    pub fn as_expandable(&self) -> Option<Ref<'_, ExpandableValue<'a>>> {
        self.try_upgrade_to(Value::Expandable);

        Ref::filter_map(self.0.borrow(), |value| match value {
            Value::Expandable(exp) => Some(exp),
            _ => None,
        })
        .ok()
    }

    pub fn as_mobius(&self) -> Option<Ref<'_, MobiusValue<'a>>> {
        self.try_upgrade_to(Value::Mobius);

        Ref::filter_map(self.0.borrow(), |value| match value {
            Value::Mobius(mobius) => Some(mobius),
            _ => None,
        })
        .ok()
    }

    pub fn as_package_ref(&self) -> Option<Ref<'_, PackageRefValue<'a>>> {
        // no coercion because there's no 'blank' package ref

        Ref::filter_map(self.0.borrow(), |value| match value {
            Value::PackageRef(pkg) => Some(pkg),
            _ => None,
        })
        .ok()
    }

    pub fn as_slice_mut(&mut self) -> Option<RefMut<'_, CompositeValue<'a, u64>>> {
        self.try_upgrade_to(Value::Slice);

        RefMut::filter_map(self.0.borrow_mut(), |value| match value {
            Value::Slice(composite) => Some(composite),
            _ => None,
        })
        .ok()
    }

    // (complex because Simple is technically also sliceable but not supported
    // here due to the upgrade that would change it to a complex shape)
    pub fn as_complex_sliceable(&self) -> Option<Ref<'_, CompositeValue<'a, u64>>> {
        self.try_upgrade_to(Value::Slice);

        Ref::filter_map(self.0.borrow(), |value| match value {
            Value::Array(composite) | Value::Slice(composite) => Some(composite),
            _ => None,
        })
        .ok()
    }

    pub fn as_composite(&self) -> Option<Ref<'_, dyn CompositeValueAdapter<'a>>> {
        self.try_upgrade_to(Value::Array);

        Ref::filter_map(self.0.borrow(), |value| match value {
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

        RefMut::filter_map(self.0.borrow_mut(), |value| match value {
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

        Ref::filter_map(self.0.borrow(), |value| match value {
            Value::Struct(r#struct) => Some(r#struct),
            _ => None,
        })
        .ok()
    }

    pub fn as_struct_mut(&self) -> Option<RefMut<'_, CompositeValue<'a, String>>> {
        self.try_upgrade_to(Value::Struct);

        RefMut::filter_map(self.0.borrow_mut(), |value| match value {
            Value::Struct(r#struct) => Some(r#struct),
            _ => None,
        })
        .ok()
    }

    pub fn as_function(&self) -> Option<Ref<'_, FunctionValue<'a>>> {
        self.try_upgrade_to(Value::Function);

        Ref::filter_map(self.0.borrow(), |value| match value {
            Value::Function(func) => Some(func),
            _ => None,
        })
        .ok()
    }

    pub fn as_function_mut(&mut self) -> Option<RefMut<'_, FunctionValue<'a>>> {
        self.try_upgrade_to(Value::Function);

        RefMut::filter_map(self.0.borrow_mut(), |value| match value {
            Value::Function(func) => Some(func),
            _ => None,
        })
        .ok()
    }
}

impl<'a> From<Value<'a>> for ValueRef<'a> {
    fn from(value: Value<'a>) -> Self {
        Self(Rc::new(RefCell::new(value)))
    }
}

impl<'a> From<Option<LabelBacktrace<'a>>> for ValueRef<'a> {
    fn from(bt: Option<LabelBacktrace<'a>>) -> Self {
        Value::Simple(bt).into()
    }
}

pub trait BacktraceContainer<'a> {
    // custom trait because From would not allow passing Location as parameter
    fn backtrace_at_location(&self, location: Pinned<Location>) -> Option<LabelBacktrace<'a>>;

    fn is_bottom(&self) -> bool;
}

impl<'a> BacktraceContainer<'a> for ValueRef<'a> {
    fn backtrace_at_location(&self, location: Pinned<Location>) -> Option<LabelBacktrace<'a>> {
        let borrowed = self.0.borrow();

        borrowed.backtrace_at_location(location)
    }

    fn is_bottom(&self) -> bool {
        let borrowed = self.0.borrow();

        borrowed.is_bottom()
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
        let borrowed = self.0.borrow();

        ValueRef::from(borrowed.realize(from_func, from_index, concrete))
    }

    fn nest_backtrace(
        &self,
        parent_kind: LabelBacktraceKind,
        parent_symbol: Option<&'a str>,
        parent_location: Pinned<Location>,
        extra_children: impl IntoIterator<Item = LabelBacktrace<'a>> + Clone,
    ) -> Self {
        let borrowed = self.0.borrow();

        ValueRef::from(borrowed.nest_backtrace(
            parent_kind,
            parent_symbol,
            parent_location,
            extra_children,
        ))
    }
}

impl<'a> BacktraceContainer<'a> for Option<LabelBacktrace<'a>> {
    fn backtrace_at_location(&self, location: Pinned<Location>) -> Option<LabelBacktrace<'a>> {
        self.clone()
            .map(|bt| (bt.symbol(), bt)) // thanks borrow checker, very cool
            .map(|(sym, bt)| bt.into_single_child(LabelBacktraceKind::Expression, sym, location))
    }

    fn is_bottom(&self) -> bool {
        self.is_none()
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
    Function(FunctionValue<'a>),
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
            Self::Function(func) => func,
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
            Self::Function(func) => Self::Function(recurs!(func)),
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
            Self::Function(func) => Self::Function(recurs!(func)),
        }
    }
}

trait Upgrade<'a> {
    // Coerce from a Value::Simple to Self, preserving inner backtrace
    fn upgrade(backtrace: Option<LabelBacktrace<'a>>) -> Self;
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
            .filter_map(|v| v.backtrace_at_location(location.clone()))
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

impl<'a> Upgrade<'a> for ExpandableValue<'a> {
    fn upgrade(backtrace: Option<LabelBacktrace<'a>>) -> Self {
        Self::new(ValueRef::from(backtrace), Vec::new())
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

impl<'a> Upgrade<'a> for MobiusValue<'a> {
    fn upgrade(backtrace: Option<LabelBacktrace<'a>>) -> Self {
        Self::new(ValueRef::from(backtrace))
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

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CompositeValue<'a, K: Eq + Hash> {
    // known values at constant keys
    r#const: HashMap<K, ValueRef<'a>>,
    // overall backtrace affecting the entire structure, from dynamic sets, etc.
    r#dyn: Option<LabelBacktrace<'a>>,
    // default value returned by get if the key is not found on access
    default_value: Option<ValueRef<'a>>,
}

impl<'a, K: Eq + Hash> CompositeValue<'a, K> {
    pub fn empty(r#dyn: Option<LabelBacktrace<'a>>) -> Self {
        Self {
            r#const: HashMap::new(),
            r#dyn,
            default_value: None,
        }
    }

    pub fn new(
        r#const: HashMap<K, ValueRef<'a>>,
        others: impl IntoIterator<Item = ValueRef<'a>>,
        location: Pinned<Location>,
    ) -> Self {
        let children: Vec<_> = others
            .into_iter()
            .filter_map(|v| v.backtrace_at_location(location.clone()))
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
            default_value: None,
        }
    }

    pub fn set_default_value(&mut self, default_value: ValueRef<'a>) {
        self.default_value = Some(default_value);
    }

    pub fn clear(&mut self) {
        self.r#const = HashMap::new();
        self.r#dyn = None;
        self.default_value = None;
    }

    pub fn get_const(&self, key: &K, at_location: Pinned<Location>) -> ValueRef<'a> {
        let value = match self.r#const.get(key).cloned() {
            Some(value) => value,
            None => self
                .default_value
                .as_ref()
                .map_or_else(ValueRef::new_bottom, ValueRef::clone_inner),
        };

        value.nest_backtrace(
            LabelBacktraceKind::Expression,
            None,
            at_location,
            self.r#dyn.clone(),
        )
    }

    pub fn get_dyn(&self, at_location: Pinned<Location>) -> ValueRef<'a> {
        // since we don't know the concrete key, we must take the union of all
        // possibilities, i.e., all entries of const

        // for simplicity, we re-use the backtrace_at_location logic already
        // implemented elsewhere

        let backtrace = self.backtrace_at_location(at_location);

        if backtrace.is_none() {
            if let Some(default) = &self.default_value {
                return default.clone_inner();
            }
        }

        ValueRef::from(backtrace)
    }

    pub fn set_const(
        &mut self,
        key: K,
        value: ValueRef<'a>,
        overwrite: bool,
        at_location: Pinned<Location>,
    ) {
        match self.r#const.entry(key) {
            Entry::Occupied(mut existing) if !overwrite => {
                existing.insert(value.nest_backtrace(
                    LabelBacktraceKind::Assignment,
                    None,
                    at_location.clone(),
                    existing.get().backtrace_at_location(at_location),
                ));
            }
            Entry::Occupied(mut existing) => {
                existing.insert(value);
            }
            Entry::Vacant(empty) => {
                empty.insert(value);
            }
        }
    }

    // never overwrites
    pub fn set_dyn(&mut self, value: &ValueRef<'a>, at_location: Pinned<Location>) {
        self.r#dyn = LabelBacktrace::combine_options(
            self.r#dyn.clone(),
            value.backtrace_at_location(at_location.clone()),
            LabelBacktraceKind::Assignment,
            at_location,
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
            .filter_map(|(_, v)| v.backtrace_at_location(at_location.clone()))
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
            .filter_map(|v| v.backtrace_at_location(location.clone()))
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

        Self {
            r#const,
            r#dyn,
            default_value: self.default_value.clone(), // ref-clone is fine here
        }
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

        Self {
            r#const,
            r#dyn,
            default_value: self.default_value.clone(), // ref-clone is fine here
        }
    }
}

impl<'a, K: Eq + Hash> Upgrade<'a> for CompositeValue<'a, K> {
    fn upgrade(backtrace: Option<LabelBacktrace<'a>>) -> Self {
        Self::empty(backtrace)
    }
}

// this is necessary because rust doesn't support using some dynamic type
// CompositeValue<'a, ?> in function return values and etc., but we want to
// re-use code for similar logic whenever possible while maintaining typing
// guarantees for integer-keyed composite values
pub trait CompositeValueAdapter<'a>: BacktraceContainer<'a> {
    fn get_const(&self, key: &SimpleConstValue, at_location: Pinned<Location>) -> ValueRef<'a>;
    fn get_dyn(&self, at_location: Pinned<Location>) -> ValueRef<'a>;
    fn set_const(
        &mut self,
        key: SimpleConstValue,
        value: ValueRef<'a>,
        overwrite: bool,
        at_location: Pinned<Location>,
    );
    fn set_dyn(&mut self, value: &ValueRef<'a>, at_location: Pinned<Location>);
}

// trivial implementation
impl<'a> CompositeValueAdapter<'a> for CompositeValue<'a, SimpleConstValue> {
    fn get_const(&self, key: &SimpleConstValue, at_location: Pinned<Location>) -> ValueRef<'a> {
        self.get_const(key, at_location)
    }

    fn get_dyn(&self, at_location: Pinned<Location>) -> ValueRef<'a> {
        self.get_dyn(at_location)
    }

    fn set_const(
        &mut self,
        key: SimpleConstValue,
        value: ValueRef<'a>,
        overwrite: bool,
        at_location: Pinned<Location>,
    ) {
        self.set_const(key, value, overwrite, at_location);
    }

    fn set_dyn(&mut self, value: &ValueRef<'a>, at_location: Pinned<Location>) {
        self.set_dyn(value, at_location);
    }
}

// integer key adapter
impl<'a> CompositeValueAdapter<'a> for CompositeValue<'a, u64> {
    fn get_const(&self, key: &SimpleConstValue, at_location: Pinned<Location>) -> ValueRef<'a> {
        if let SimpleConstValue::Integer(key) = key {
            self.get_const(key, at_location)
        } else {
            self.get_dyn(at_location)
        }
    }

    fn get_dyn(&self, at_location: Pinned<Location>) -> ValueRef<'a> {
        self.get_dyn(at_location)
    }

    fn set_const(
        &mut self,
        key: SimpleConstValue,
        value: ValueRef<'a>,
        overwrite: bool,
        at_location: Pinned<Location>,
    ) {
        if let SimpleConstValue::Integer(key) = key {
            self.set_const(key, value, overwrite, at_location);
        } else {
            self.set_dyn(&value, at_location);
        }
    }

    fn set_dyn(&mut self, value: &ValueRef<'a>, at_location: Pinned<Location>) {
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
}

impl<'a> BacktraceContainer<'a> for FunctionValue<'a> {
    fn backtrace_at_location(&self, location: Pinned<Location>) -> Option<LabelBacktrace<'a>> {
        self.backtrace
            .clone()
            .map(|bt| (bt.symbol(), bt)) // thanks borrow checker, very cool
            .map(|(sym, bt)| bt.into_single_child(LabelBacktraceKind::Expression, sym, location))
    }

    fn is_bottom(&self) -> bool {
        if self.backtrace.is_some() {
            false
        } else if let Some(outcome) = &self.outcome {
            outcome.iter().all(ValueRef::is_bottom)
        } else {
            true
        }
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

        Self {
            r#ref: self.r#ref.clone(),
            signature: self.signature.clone(),
            outcome,
            backtrace,
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
        }
    }
}

impl<'a> Upgrade<'a> for FunctionValue<'a> {
    fn upgrade(backtrace: Option<LabelBacktrace<'a>>) -> Self {
        Self::new_unknown(backtrace)
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

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum SimpleConstValue {
    Integer(u64),
    String(String),
}

// basic support for literal-only composition, e.g. `2 + 3` is recognized as 5
impl SimpleConstValue {
    pub fn try_resolve_from_expr(expr: &ExprNode<'_>) -> Option<Self> {
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
                let l = Self::try_resolve_from_expr(left)?;
                let r = Self::try_resolve_from_expr(right)?;

                if *kind == BinaryOpKind::Sum {
                    if let Self::String(l) = l {
                        if let Self::String(r) = r {
                            // string concatenation
                            return Some(Self::String(l + &r));
                        }
                    }
                }

                // otherwise, must be integer operation

                let Self::Integer(l) = Self::try_resolve_from_expr(left)? else {
                    return None;
                };
                let Self::Integer(r) = Self::try_resolve_from_expr(right)? else {
                    return None;
                };

                let combined = match kind {
                    BinaryOpKind::Sum => l.saturating_add(r),
                    BinaryOpKind::Diff => l.saturating_sub(r),
                    BinaryOpKind::Product => l.saturating_mul(r),
                    BinaryOpKind::Quotient if r != 0 => l.saturating_div(r),
                    BinaryOpKind::Remainder => l % r,
                    BinaryOpKind::ShiftLeft => l << r,
                    BinaryOpKind::ShiftRight => l >> r,
                    BinaryOpKind::BitwiseOr => l | r,
                    BinaryOpKind::BitwiseAnd => l & r,
                    BinaryOpKind::BitwiseXor => l ^ r,
                    _ => return None,
                };

                Self::Integer(combined)
            }
            _ => return None,
        };

        Some(result)
    }
}
