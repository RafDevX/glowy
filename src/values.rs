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
    ast::{BinaryOpKind, ExprNode, FunctionSignatureNode, LiteralNode, TypeNode, UnaryOpKind},
};

use crate::{
    Pinned,
    labels::{LabelBacktrace, LabelBacktraceKind},
};

// wrapper struct (vs. type alias) allows impl'ing despite orphan rule
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ValueRef<'a>(Rc<RefCell<Value<'a>>>);

impl<'a> ValueRef<'a> {
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

    /// Generate a new value just from type information, without init expression
    ///
    /// In most cases, Go's zero value corresponds to a `Value::Simple(None)`,
    /// usually from `nil`, but for array types we need to have an actual
    /// `Value::Array(...)` since they can be used from the get-go and otherwise
    /// we would later not recognize the value as a valid indexing base.
    ///
    /// Input is an `Option` for easier compatibility with invoking code.
    pub fn uninitialized_from_type(r#type: Option<&TypeNode<'a>>) -> Self {
        if let Some(TypeNode::Array { element, .. }) = r#type {
            // TODO: support nested array types
            let mut composite = CompositeValue::empty();

            if let TypeNode::Array { .. } = &**element {
                let inner = Self::uninitialized_from_type(Some(element));

                composite.set_default_value(inner);
            }

            Self::from(Value::Array(composite))
        } else {
            Self::from(None)
        }
    }

    pub fn is_simple(&self) -> bool {
        matches!(*self.0.borrow(), Value::Simple(_))
    }

    pub fn is_map(&self) -> bool {
        matches!(*self.0.borrow(), Value::Map(_))
    }

    pub fn as_expandable(&self) -> Option<Ref<ExpandableValue<'a>>> {
        Ref::filter_map(self.0.borrow(), |value| match value {
            Value::Expandable(exp) => Some(exp),
            _ => None,
        })
        .ok()
    }

    pub fn as_slice_mut(&mut self) -> Option<RefMut<CompositeValue<'a, u64>>> {
        RefMut::filter_map(self.0.borrow_mut(), |value| match value {
            Value::Slice(composite) => Some(composite),
            _ => None,
        })
        .ok()
    }

    pub fn as_composite(&self) -> Option<Ref<dyn CompositeValueAdapter<'a>>> {
        Ref::filter_map(self.0.borrow(), |value| match value {
            Value::Array(composite) | Value::Slice(composite) => {
                Some(composite as &dyn CompositeValueAdapter<'a>)
            }
            Value::Map(composite) => Some(composite),
            _ => None,
        })
        .ok()
    }

    pub fn as_composite_mut(&mut self) -> Option<RefMut<dyn CompositeValueAdapter<'a>>> {
        RefMut::filter_map(self.0.borrow_mut(), |value| match value {
            Value::Array(composite) | Value::Slice(composite) => {
                Some(composite as &mut dyn CompositeValueAdapter<'a>)
            }
            Value::Map(composite) => Some(composite),
            _ => None,
        })
        .ok()
    }

    pub fn as_function(&self) -> Option<Ref<FunctionValue<'a>>> {
        Ref::filter_map(self.0.borrow(), |value| match value {
            Value::Function(func) => Some(func),
            _ => None,
        })
        .ok()
    }

    pub fn as_function_mut(&mut self) -> Option<RefMut<FunctionValue<'a>>> {
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
        from_index: usize,
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
        from_index: usize,
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
        from_index: usize,
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
    Expandable(ExpandableValue<'a>),
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
        from_index: usize,
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
            Self::Array(composite) => Self::Array(recurs!(composite)),
            Self::Slice(composite) => Self::Slice(recurs!(composite)),
            Self::Map(composite) => Self::Map(recurs!(composite)),
            Self::Struct(composite) => Self::Struct(recurs!(composite)),
            Self::Function(func) => Self::Function(recurs!(func)),
        }
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
            .all(|v| v.is_bottom())
    }
}

impl<'a> SelfAwareBacktraceContainer<'a> for ExpandableValue<'a> {
    fn realize(
        &self,
        from_func: &FunctionRef<'a>,
        from_index: usize,
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
    pub fn empty() -> Self {
        Self {
            r#const: HashMap::new(),
            r#dyn: None,
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

    pub fn get_const(&self, key: K, at_location: Pinned<Location>) -> ValueRef<'a> {
        let value = match self.r#const.get(&key).cloned() {
            Some(value) => value,
            None => self
                .default_value
                .as_ref()
                .map(ValueRef::clone_inner)
                .unwrap_or_else(|| ValueRef::from(None)),
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
    pub fn set_dyn(&mut self, value: ValueRef<'a>, at_location: Pinned<Location>) {
        self.r#dyn = LabelBacktrace::combine_options(
            self.r#dyn.clone(),
            value.backtrace_at_location(at_location.clone()),
            LabelBacktraceKind::Assignment,
            at_location,
        );
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
        from_index: usize,
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

// this is necessary because rust doesn't support using some dynamic type
// CompositeValue<'a, ?> in function return values and etc., but we want to
// re-use code for similar logic whenever possible while maintaining typing
// guarantees for integer-keyed composite values
pub trait CompositeValueAdapter<'a>: BacktraceContainer<'a> {
    fn get_const(&self, key: SimpleConstValue, at_location: Pinned<Location>) -> ValueRef<'a>;
    fn get_dyn(&self, at_location: Pinned<Location>) -> ValueRef<'a>;
    fn set_const(
        &mut self,
        key: SimpleConstValue,
        value: ValueRef<'a>,
        overwrite: bool,
        at_location: Pinned<Location>,
    );
    fn set_dyn(&mut self, value: ValueRef<'a>, at_location: Pinned<Location>);
}

// trivial implementation
impl<'a> CompositeValueAdapter<'a> for CompositeValue<'a, SimpleConstValue> {
    fn get_const(&self, key: SimpleConstValue, at_location: Pinned<Location>) -> ValueRef<'a> {
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

    fn set_dyn(&mut self, value: ValueRef<'a>, at_location: Pinned<Location>) {
        self.set_dyn(value, at_location);
    }
}

// integer key adapter
impl<'a> CompositeValueAdapter<'a> for CompositeValue<'a, u64> {
    fn get_const(&self, key: SimpleConstValue, at_location: Pinned<Location>) -> ValueRef<'a> {
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
            self.set_dyn(value, at_location);
        }
    }

    fn set_dyn(&mut self, value: ValueRef<'a>, at_location: Pinned<Location>) {
        self.set_dyn(value, at_location);
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FunctionValue<'a> {
    r#ref: FunctionRef<'a>,
    signature: FunctionSignatureNode<'a>,
    outcome: Vec<ValueRef<'a>>,
    // overall backtrace, e.g. from func lit assignments w/ explicit annotations
    backtrace: Option<LabelBacktrace<'a>>,
}

impl<'a> FunctionValue<'a> {
    pub fn new(
        r#ref: FunctionRef<'a>,
        signature: FunctionSignatureNode<'a>,
        backtrace: Option<LabelBacktrace<'a>>,
    ) -> Self {
        Self {
            r#ref,
            signature,
            outcome: Vec::new(),
            backtrace,
        }
    }

    pub fn r#ref(&self) -> &FunctionRef<'a> {
        &self.r#ref
    }

    pub fn signature(&self) -> &FunctionSignatureNode<'a> {
        &self.signature
    }

    pub fn outcome(&self) -> &Vec<ValueRef<'a>> {
        &self.outcome
    }

    pub fn set_outcome(&mut self, outcome: Vec<ValueRef<'a>>) {
        self.outcome = outcome;
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
        self.backtrace.is_none()
    }
}

impl<'a> SelfAwareBacktraceContainer<'a> for FunctionValue<'a> {
    fn realize(
        &self,
        from_func: &FunctionRef<'a>,
        from_index: usize,
        concrete: Option<&LabelBacktrace<'a>>,
    ) -> Self {
        let mut new = self.clone();

        new.backtrace = new.backtrace.realize(from_func, from_index, concrete);

        new
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
    BuiltIn {
        package_name: &'static str,
        name: &'static str,
    },
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
            Self::BuiltIn { package_name, name } => write!(f, "{package_name}.{name}"),
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
            (
                Self::BuiltIn {
                    package_name: a_package_name,
                    name: a_name,
                },
                Self::BuiltIn {
                    package_name: b_package_name,
                    name: b_name,
                },
            ) => a_package_name.cmp(b_package_name).then(a_name.cmp(b_name)),
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
