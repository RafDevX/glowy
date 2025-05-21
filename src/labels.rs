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

use std::{cmp, collections::BTreeSet, fmt};

use parser::Location;

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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum LabelTag<'a> {
    /// A concrete user-facing tag, like `blue` or `violet`.
    Concrete(&'a str),
}

impl<'a> fmt::Display for LabelTag<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Concrete(tag) => write!(f, "{tag}"),
            // ...
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

            Label::Tags(set)
        }
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
    /// Base case; no children
    pub(crate) fn new_explicit_annotation(
        label: Label<'a>,
        symbol: &'a str,
        location: Pinned<Location>,
    ) -> Self {
        Self {
            kind: LabelBacktraceKind::ExplicitAnnotation,
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

        Some(Self {
            kind,
            label,
            symbol,
            location,
            children,
        })
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
}
