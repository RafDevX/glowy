//! Module for taint analysis label manipulation.
//!
//! Glowy's main functionality centers on tracking data flow between initial
//! sources and ultimately leading up to sinks, where a specific security
//! condition is checked to try to infer security faults. This is accomplished
//! by assigning every piece of data a **label**, which is then propagated
//! to other data that depends on the first.
//!
//! Labels are essentially just sets of **tags**, such as `{admiral, secret}`,
//! which may be empty (`{ }`, also called **bottom**). For more information,
//! see [`Label`] and [`LabelTag`].
//!
//! These labels' evolution and propagation history can be easily tracked using
//! a hierarchy structure, which is here implemented via [`LabelBacktrace`].

use std::{cmp, collections::BTreeSet, fmt, iter};

use parser::{Location, Span};

use crate::Pinned;

/// Represents an individual tag within a label.
///
/// This enum is used to model the different kinds of tags that may exist
/// within a [`Label`]. For example, each of the colors in the label
/// `{blue, red, violet}` would correspond to an instance of
/// [`LabelTag::Concrete`] with the respective name.
///
/// [`LabelTag`] derives [`Ord`], which means that when ordered tags are always
/// first discriminated by kind (the first variant comes first, and so on), and
/// then lexicographically by its internal value/identifier.
#[derive(Debug, Clone)]
pub enum LabelTag<'a> {
    /// A concrete user-facing tag, like `blue` or `violet`.
    Concrete(&'a str),
    /// An artificial tag conceptually representing a function argument's label.
    Synthetic {
        /// A reference to the associated function.
        func: FunctionRef<'a>,
        /// The parameter's index within the function's signature.
        index: usize,
        /// The parameter's assigned identifier, if any.
        ///
        /// Note that this is redundant with [`LabelTag::Synthetic::index`], but
        /// allows for a more human-friendly representation when present.
        identifier: Option<Span<'a>>,
    },
}

impl<'a> fmt::Display for LabelTag<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Concrete(tag) => write!(f, "{tag}"),
            Self::Synthetic {
                func,
                index,
                identifier,
            } => {
                if let Some(id) = identifier {
                    write!(f, "<{func}#{index}:{}>", id.content())
                } else {
                    write!(f, "<{func}#{index}>")
                }
            }
        }
    }
}

impl Ord for LabelTag<'_> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match (self, other) {
            (Self::Concrete(_), Self::Synthetic { .. }) => cmp::Ordering::Less,
            (Self::Synthetic { .. }, Self::Concrete(_)) => cmp::Ordering::Greater,
            (Self::Concrete(left), Self::Concrete(right)) => left.cmp(right),
            (
                Self::Synthetic {
                    func: left_func,
                    index: left_index,
                    ..
                },
                Self::Synthetic {
                    func: right_func,
                    index: right_index,
                    ..
                },
            ) => left_func.cmp(right_func).then(left_index.cmp(right_index)),
        }
    }
}

impl PartialOrd for LabelTag<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for LabelTag<'_> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Concrete(left), Self::Concrete(right)) => left == right,
            (
                Self::Synthetic {
                    func: left_func,
                    index: left_index,
                    ..
                },
                Self::Synthetic {
                    func: right_func,
                    index: right_index,
                    ..
                },
            ) => left_func == right_func && left_index == right_index,
            _ => false,
        }
    }
}

impl Eq for LabelTag<'_> {}

/// Represents an unambiguous reference to a function declaration.
///
/// This is useful to guarantee uniqueness of a [`LabelTag::Synthetic`] when
/// paired with a function parameter index.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum FunctionRef<'a> {
    /// A normal function with a native declared name.
    ///
    /// This is a unique identifier because of the embedded location information
    /// offered by [`Pinned`] and [`Span`].
    Named(Pinned<Span<'a>>),
    /// An anonymous function literal.
    ///
    /// As an internal identifier, a pointer to the AST node is used to
    /// guarantee uniqueness. This is evidently not deterministic across
    /// different program executions, but in general synthetic tags are not
    /// exposed anyway, so they should not be relied on for observability.
    Anonymous(*const bool), // FIXME: Anonymous(*const FunctionLiteralNode),
}

impl<'a> fmt::Display for FunctionRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Named(name) => name.content().fmt(f),
            Self::Anonymous(ptr) => write!(f, "lit@{:x}", (*ptr as usize) & 0xffff),
        }
    }
}

/// Represents the security typing associated with some piece of data.
///
/// This enum models metadata connected with information and, more concretely,
/// its provenience. It generally corresponds to a set of [`LabelTag`]s, such as
/// `{blue, red, violet}` (which are always provided ordered by type and then
/// lexicographically).
///
/// The most common variant is [`Label::Tags`], but [`Label::Bottom`] should be
/// used instead of an empty set (i.e., `{ }`). Formally, a `Top` variant could
/// also exist, but it is not actually needed in Glowy so it is not here
/// implemented.
///
/// Label derivation and hierarchy is tracked through [`LabelBacktrace`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Label<'a> {
    /// A non-empty set of [`LabelTag`]s.
    Tags(BTreeSet<LabelTag<'a>>),
    /// A base, empty label; corresponds to an empty set.
    Bottom,
}

impl<'a> Label<'a> {
    /// Constructs a new instance given a slice of concrete tags.
    ///
    /// This returns [`Label::Bottom`] if the slice is empty, or otherwise a
    /// [`Label::Tags`] with all elements converted to a [`LabelTag::Concrete`].
    pub fn from_tags(tags: &[&'a str]) -> Self {
        if tags.is_empty() {
            Self::Bottom
        } else {
            let set = BTreeSet::from_iter(tags.iter().map(|tag| LabelTag::Concrete(tag)));

            Self::Tags(set)
        }
    }

    /// Constructs a new instance from a single [`LabelTag`].
    ///
    /// This is a convenience method particularly useful for dealing with a
    /// [`LabelTag::Synthetic`]. For other uses, prefer [`Label::from_tags`].
    pub fn from_single(tag: LabelTag<'a>) -> Self {
        let mut set = BTreeSet::new();
        set.insert(tag);

        Self::Tags(set)
    }

    /// Returns the union of `self` and `other` as a new [`Label`].
    ///
    /// For example, `{a, b, c}` intersected with `{b, d}` yields
    /// `{a, b, c, d}`.
    pub fn union(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Bottom, l) | (l, Self::Bottom) => l.clone(),
            (Self::Tags(left), Self::Tags(right)) => Self::Tags(left | right),
        }
    }

    /// Returns the intersection of `self` and `other` as a new [`Label`].
    ///
    /// For example, `{a, b, c}` intersected with `{b, d, e}` yields `{b}`.
    /// If the intersection is null, [`Label::Bottom`] is returned as expected.
    pub fn intersect(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Tags(left), Self::Tags(right)) => {
                let new_tags = left & right;

                if new_tags.is_empty() {
                    Self::Bottom
                } else {
                    Self::Tags(new_tags)
                }
            }
        }
    }

    /// Returns the difference of `self` and `other` as a new [`Label`].
    ///
    /// For example, `{a, c}` subtracted from `{a, b, c}` yields `{b}`.
    /// If the difference is null, [`Label::Bottom`] is returned as expected.
    pub fn difference(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Bottom, _) => Self::Bottom,
            (_, Self::Bottom) => self.clone(),
            (Self::Tags(left), Self::Tags(right)) => {
                let new_tags = left - right;

                if new_tags.is_empty() {
                    Self::Bottom
                } else {
                    Self::Tags(new_tags)
                }
            }
        }
    }

    pub(crate) fn is_synthetic_func_param_decl(
        &self,
        param_func: &FunctionRef<'a>,
        param_index: usize,
    ) -> bool {
        let Self::Tags(tags) = self else {
            return false;
        };

        if tags.len() != 1 {
            return false;
        }

        let Some(LabelTag::Synthetic { func, index, .. }) = tags.first() else {
            return false;
        };

        func == param_func && *index == param_index
    }
}

impl<'a> PartialOrd for Label<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        if self == other {
            return Some(cmp::Ordering::Equal);
        }

        match (self, other) {
            (Self::Bottom, _) => Some(cmp::Ordering::Less), // {} < {a, ...}
            (_, Self::Bottom) => Some(cmp::Ordering::Greater), // {a, ...} > {}
            (Self::Tags(left), Self::Tags(right)) => {
                if left.is_subset(right) {
                    // e.g., {a, b} < {a, b, c}
                    Some(cmp::Ordering::Less)
                } else if right.is_subset(left) {
                    // e.g., {a, b, c} > {a, b}
                    Some(cmp::Ordering::Greater)
                } else {
                    None // not comparable
                }
            }
        }
    }
}

impl<'a> fmt::Display for Label<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Label::Tags(tags) => {
                write!(f, "{{")?;
                let mut iter = tags.iter();
                if let Some(first) = iter.next() {
                    write!(f, "{first}")?;
                    for tag in iter {
                        write!(f, ", {tag}")?;
                    }
                }
                write!(f, "}}")
            }
            Label::Bottom => write!(f, "{{}}"),
        }
    }
}

/// Represents the propagation history leading up to a label attribution.
///
/// This hierarchical structure keeps track of why a certain piece of data has
/// been assigned a specific [`Label`], particularly in the sense of what
/// operations occurred and compounded to result in a final label.
///
/// The following invariants are strictly enforced:
///     1. No [`LabelBacktrace`] ever has a label [`Label::Bottom`];
///     2. Children's labels are always a subset of their parent's label (e.g.,
///     a backtrace `{blue, violet}` can have a child `{blue}` and another
///     `{violet}`, but never a `{yellow}` child); and
///     3. All children's labels are always disjoint (e.g., if a first child
///     has label `{blue, violet}`, a second child can never have label
///     `{blue, yellow}` -- it will instead be trimmed to just `{yellow}` to
///     simplify the whole chain and limit hierarchy size).
#[derive(Debug, Clone, PartialEq)]
pub struct LabelBacktrace<'a> {
    /// What operation caused this label attribution.
    kind: LabelBacktraceKind,
    /// The final label associated with some information.
    label: Label<'a>,
    /// Name of symbol with this label, if any/applicable.
    symbol: Option<&'a str>,
    /// Where this operation took place.
    location: Pinned<Location>,
    /// Other backtraces through which this label is derived via propagation.
    children: Vec<LabelBacktrace<'a>>,
}

impl<'a> LabelBacktrace<'a> {
    /// Base case; no children.
    ///
    /// Useful, in particular, for [`LabelBacktraceKind::ExplicitAnnotation`]
    /// and [`LabelBacktraceKind::FunctionParameter`].
    pub(crate) fn new_root(
        kind: LabelBacktraceKind,
        label: Label<'a>,
        symbol: &'a str,
        location: Pinned<Location>,
    ) -> Self {
        Self {
            kind,
            label,
            symbol: Some(symbol),
            location,
            children: vec![],
        }
    }

    /// Returns [`None`] iff `label` is [`Label::Bottom`].
    pub(crate) fn new<'b>(
        kind: LabelBacktraceKind,
        label: Label<'a>,
        symbol: Option<&'a str>,
        location: Pinned<Location>,
        children: impl IntoIterator<Item = &'b Self>,
    ) -> Option<Self>
    where
        'a: 'b,
    {
        if label == Label::Bottom {
            return None;
        }

        let mut remaining_label = label.clone();
        let children: Vec<_> = children
            .into_iter()
            .filter_map(|child| {
                child
                    .restrict_to_label(&remaining_label)
                    .inspect(|child| remaining_label = remaining_label.difference(&child.label))
            })
            .collect();

        // if there is only one child
        if let [child] = children.as_slice() {
            if child.label == label && child.location == location && child.symbol == symbol {
                // avoid unnecessary repeated backtraces that just make everything more complex;
                // for example, in the example below:
                // ```go
                // // glowy::label::{high}
                // var a = 3
                // ```
                // we just want ExplicitAnnotation and not also Assignment another level up
                return Some(child.clone());
            }
        }

        Some(Self {
            kind,
            label,
            symbol,
            location,
            children,
        })
    }

    /// Constructs a new instance equal to the union of all its children.
    pub(crate) fn fold<'b>(
        children: impl IntoIterator<Item = &'b LabelBacktrace<'a>> + Clone,
        with_kind: LabelBacktraceKind,
        with_symbol: Option<&'a str>,
        at_location: Pinned<Location>,
    ) -> Option<Self>
    where
        'a: 'b,
    {
        let label = children
            .clone()
            .into_iter()
            .fold(Label::Bottom, |acc, bt| acc.union(bt.label()));

        Self::new(with_kind, label, with_symbol, at_location, children)
        // ^ None iff children are empty
    }

    /// Constructs a new instance equal to this one but with one more child.
    pub(crate) fn with_child(&self, child: &LabelBacktrace<'a>) -> Self {
        Self::new(
            self.kind,
            self.label.union(child.label()),
            self.symbol,
            self.location.clone(),
            iter::once(child).chain(self.children.iter()),
        )
        .unwrap() // safe because if self exists, label is not Bottom
    }

    /// Returns a new instance (with symbol = None) representing a step above
    /// in the hierarchy between two instances (self and other).
    pub(crate) fn union(
        &self,
        other: &Self,
        with_kind: LabelBacktraceKind,
        at_location: Pinned<Location>,
    ) -> Self {
        Self::new(
            with_kind,
            self.label.union(&other.label),
            None,
            at_location,
            [self, other],
        )
        .unwrap() // safe because if self exists, label is not Bottom
    }

    /// Realizes synthetic placeholders in the hierarchy to concrete backtraces.
    pub(crate) fn realize(
        &self,
        from_func: &FunctionRef<'a>,
        from_index: usize,
        concrete: Option<&Self>,
    ) -> Option<Self> {
        if self.kind == LabelBacktraceKind::FunctionParameter {
            if self
                .label()
                .is_synthetic_func_param_decl(from_func, from_index)
            {
                Self::new(
                    LabelBacktraceKind::FunctionArgument,
                    concrete.map(Self::label).unwrap_or(&Label::Bottom).clone(),
                    self.symbol(),
                    self.location().clone(),
                    concrete,
                )
            } else {
                Some(self.clone())
            }
        } else if self.children.is_empty() {
            // should only happen for e.g. ExplicitAnnotation with an unrelated
            // and concrete label, at least in theory

            Some(self.clone())
        } else {
            let children: Vec<_> = self
                .children()
                .iter()
                .flat_map(|child| child.realize(from_func, from_index, concrete))
                .collect();

            Self::fold(
                &children,
                *self.kind(),
                self.symbol(),
                self.location().clone(),
            )
        }
    }

    /// Returns a new instance whose label only contains tags in a given
    /// constraint, pruning children if they would have [`Label::Bottom`].
    fn restrict_to_label(&self, constraint: &Label<'a>) -> Option<Self> {
        let new_label = self.label.intersect(constraint);

        if new_label == Label::Bottom {
            return None;
        }

        Some(Self {
            kind: self.kind,
            label: new_label,
            symbol: self.symbol,
            location: self.location.clone(),
            children: self
                .children
                .iter()
                .filter_map(|child| child.restrict_to_label(constraint))
                .collect(),
        })
    }

    /// Returns the kind of operation that caused the label assignment.
    pub fn kind(&self) -> &LabelBacktraceKind {
        &self.kind
    }

    /// Returns the label in question described by this backtrace.
    pub fn label(&self) -> &Label<'a> {
        &self.label
    }

    /// Returns the name of the symbol with this label, if any/applicable.
    pub fn symbol(&self) -> Option<&'a str> {
        self.symbol
    }

    /// Returns the location where the operation took place.
    pub fn location(&self) -> &Pinned<Location> {
        &self.location
    }

    /// Returns the backtraces that compound to yield and justify this one.
    pub fn children(&self) -> &[Self] {
        &self.children
    }
}

/// The concrete operation that resulted in a label assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelBacktraceKind {
    /// Explicit source code annotation.
    ExplicitAnnotation,
    /// Assignment of some tainted expression to a variable.
    Assignment,
    /// Compounded label derived from the parts of a composite expression.
    Expression,
    /// Aggregate label implicitly inherited from surrounding control flows.
    Branch,
    /// Label originating from a value sent into a given channel.
    Send,
    /// Aggregate label for values received from a given channel.
    Receive,
    /// Synthetic label assigned to a declared parameter for taint analysis.
    FunctionParameter,
    /// Concrete label associated to argument binding at function invocation.
    FunctionArgument,
    /// Aggregate label for all arguments passed to a variadic parameter.
    FunctionVariadicAggregation,
    /// Individual label for one particular expression in a return statement.
    Return,
}
