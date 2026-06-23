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

use std::{borrow::Cow, cmp, collections::BTreeSet, fmt, hash, iter, mem};

use parser::{Location, Span};

use crate::Pinned;
// we need this to be publicly accessible and documented, since it's referenced
// publicly by LabelTag::Synthetic
pub use crate::values::FunctionRef;

/// Represents a synthetic label tag's purpose and identity, for some function.
///
/// This enum models the possible reasons for why a specific
/// [`LabelTag::Synthetic`] can be synthesized to artificially represent a
/// [`Label`] whose value is not yet known and cannot be known until later
/// during the analysis. It further provides sufficient context to identify a
/// specific instance (within the context of a given function), such as the
/// respective parameter index.
///
/// By definition, synthetic tags are transient auxiliary objects and are never
/// returned to library consumers as part of the reported results for high-level
/// program analysis, making this enum mostly an internal artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SyntheticSlot {
    /// Conceptual placeholder for a function argument's label.
    ///
    /// The enclosed value is the index of the parameter in question within the
    /// function's signature. It should be noted that this index is counted in
    /// its most intuitive sense, not based on formal parameter definitions per
    /// the Go spec: for example, in `func f(x, y int)`, `x` is counted as 0 and
    /// `y` is counted as 1, rather than both being counted as 0.
    Param(usize),
    /// Conceptual placeholder for a function receiver's label.
    Receiver,
    /// Conceptual placeholder for a captured symbol's label.
    ///
    /// The enclosed value is the registered index of the symbol capture within
    /// the internal analysis function value in question.
    ///
    /// A synthetic representation is necessary because a closure function
    /// sharing symbols with an outer scope still experiences mutations to them
    /// happening after the closure's definition but before its invocation,
    /// which means that the real label is unknown until invocation time.
    Capture(usize),
    /// Conceptual placeholder for the implicit branch label at invocation time.
    ///
    /// This is automatically injected into the branch label when analyzing the
    /// body of any (non-`main`) function so that it later can be realized at
    /// call-time into the branch label present then, if any so exists.
    ///
    /// Though a bit esoteric, this is crucial to detect implicit information
    /// flows when functions are invoked only conditionally, especially for
    /// functions that do not take arguments and so cannot propagate this
    /// information any other way.
    CallSiteBranch,
}

impl SyntheticSlot {
    fn label_backtrace_kind(&self) -> LabelBacktraceKind {
        match self {
            Self::Param(_) => LabelBacktraceKind::FunctionArgument,
            Self::Receiver => LabelBacktraceKind::MethodReceiver,
            Self::Capture(_) => LabelBacktraceKind::ClosureCaptureBinding,
            // CallSiteBranch is realized via [`LabelBacktrace::realize`]'s
            // dedicated Branch arm, which substitutes the concrete branch
            // backtrace wholesale (preserving its kind), so this method is
            // not actually invoked for it -- we still return Branch for
            // robustness against future refactors that route through here
            Self::CallSiteBranch => LabelBacktraceKind::Branch,
        }
    }
}

impl fmt::Display for SyntheticSlot {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Param(index) => write!(f, "#{index}"),
            Self::Receiver => write!(f, "$RECEIVER"),
            Self::Capture(index) => write!(f, "$CAPTURE#{index}"),
            Self::CallSiteBranch => write!(f, "$BRANCH"),
        }
    }
}

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
    /// An artificial tag conceptually representing an unknown label.
    ///
    /// This is used internally during the analysis of function bodies, such as
    /// to represent each argument's label before knowing when the function is
    /// actually invoked (and what values are passed as arguments).
    Synthetic {
        /// A reference to the associated function.
        func: FunctionRef<'a>,
        /// The modality under which this tag is synthesized.
        ///
        /// This value uniquely identifies this tag within the context of a
        /// given function, which means that it also universally represents it
        /// when combined with a [`FunctionRef`].
        slot: SyntheticSlot,
        /// The parameter's assigned identifier, if any.
        ///
        /// Note that this is redundant with [`LabelTag::Synthetic::slot`], but
        /// allows for a more human-friendly representation when present.
        identifier: Option<Span<'a>>,
    },
}

impl<'a> LabelTag<'a> {
    fn is_synthetic_representation(&self, func: &FunctionRef<'a>, slot: SyntheticSlot) -> bool {
        let LabelTag::Synthetic {
            func: tag_func,
            slot: tag_slot,
            ..
        } = self
        else {
            return false;
        };

        tag_func == func && *tag_slot == slot
    }
}

impl fmt::Display for LabelTag<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Concrete(tag) => write!(f, "{tag}"),
            Self::Synthetic {
                func,
                slot,
                identifier,
            } => {
                if let Some(id) = identifier {
                    write!(f, "<{func}{slot}:{}>", id.content())
                } else {
                    write!(f, "<{func}{slot}>")
                }
            }
        }
    }
}

impl Ord for LabelTag<'_> {
    #[inline]
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match (self, other) {
            (Self::Concrete(_), Self::Synthetic { .. }) => cmp::Ordering::Less,
            (Self::Synthetic { .. }, Self::Concrete(_)) => cmp::Ordering::Greater,
            (Self::Concrete(left), Self::Concrete(right)) => left.cmp(right),
            (
                Self::Synthetic {
                    func: left_func,
                    slot: left_slot,
                    ..
                },
                Self::Synthetic {
                    func: right_func,
                    slot: right_slot,
                    ..
                },
            ) => left_func.cmp(right_func).then(left_slot.cmp(right_slot)),
        }
    }
}

impl PartialOrd for LabelTag<'_> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for LabelTag<'_> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Concrete(left), Self::Concrete(right)) => left == right,
            (
                Self::Synthetic {
                    func: left_func,
                    slot: left_slot,
                    ..
                },
                Self::Synthetic {
                    func: right_func,
                    slot: right_slot,
                    ..
                },
            ) => left_func == right_func && left_slot == right_slot,
            _ => false,
        }
    }
}

impl Eq for LabelTag<'_> {}

impl hash::Hash for LabelTag<'_> {
    #[inline]
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        mem::discriminant(self).hash(state);

        match self {
            LabelTag::Concrete(tag) => tag.hash(state),
            LabelTag::Synthetic { func, slot, .. } => {
                func.hash(state);
                slot.hash(state);
            }
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    ///
    /// # Example Usage
    ///
    /// ```
    /// # use glowy::labels::Label;
    /// #
    /// assert_eq!(Label::from_tags(&["dog", "cat"]).to_string(), "{cat, dog}");
    ///
    /// assert_eq!(Label::from_tags(&[]), Label::Bottom);
    /// ```
    #[inline]
    pub fn from_tags(tags: &[&'a str]) -> Self {
        if tags.is_empty() {
            Self::Bottom
        } else {
            let set = tags.iter().copied().map(LabelTag::Concrete).collect();

            Self::Tags(set)
        }
    }

    /// Constructs an ordered sequence of [`Label`]s given a slice of strings.
    ///
    /// This returns a [`Vec`] where each label corresponds to a [`Label`]
    /// obtained via [`Label::from_tags`] for each slice partition as separated
    /// by the separator `->`. The resulting sequence represents a set of
    /// [`Label`]s to be used independently at different points in time,
    /// chronologically as specified by the sequence and according to context.
    ///
    /// # Example Usage
    ///
    /// ```
    /// # use glowy::labels::Label;
    /// #
    /// assert_eq!(
    ///     Label::sequence_from_tags(&["->", "dog", "cat", "->", "bird"])
    ///         .iter()
    ///         .map(ToString::to_string)
    ///         .collect::<Vec<_>>(),
    ///     vec!["{}", "{cat, dog}", "{bird}"]
    /// )
    /// ```
    #[inline]
    pub fn sequence_from_tags(tags: &[&'a str]) -> Vec<Self> {
        tags.split(|tag| *tag == "->")
            .map(Self::from_tags)
            .collect()
    }

    /// Constructs a new instance from a single [`LabelTag`].
    ///
    /// This is a convenience method particularly useful for dealing with a
    /// [`LabelTag::Synthetic`]. For other uses, prefer [`Label::from_tags`].
    ///
    /// # Example Usage
    ///
    /// ```
    /// # use glowy::labels::{Label, LabelTag};
    /// #
    /// let tag = LabelTag::Concrete("secret");
    /// assert_eq!(Label::from_single(tag).to_string(), "{secret}");
    /// ```
    #[must_use]
    #[inline]
    pub fn from_single(tag: LabelTag<'a>) -> Self {
        let mut set = BTreeSet::new();
        set.insert(tag);

        Self::Tags(set)
    }

    /// Returns the union of `self` and `other` as a new [`Label`].
    ///
    /// For example, `{a, b, c}` intersected with `{b, d}` yields
    /// `{a, b, c, d}`.
    ///
    /// # Example Usage
    ///
    /// ```
    /// # use glowy::labels::Label;
    /// #
    /// let x = Label::from_tags(&["alice", "charlie"]);
    /// let y = Label::from_tags(&["bob", "david", "eve"]);
    ///
    /// assert_eq!(x.union(&y).to_string(), "{alice, bob, charlie, david, eve}");
    /// ```
    #[must_use]
    #[inline]
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
    ///
    /// # Example Usage
    ///
    /// ```
    /// # use glowy::labels::Label;
    /// #
    /// let x = Label::from_tags(&["alice", "bob", "frank"]);
    /// let y = Label::from_tags(&["bob", "charlie", "david"]);
    /// let z = Label::from_tags(&["alice", "eve", "frank"]);
    ///
    /// assert_eq!(x.intersect(&y).to_string(), "{bob}");
    /// assert_eq!(x.intersect(&z).to_string(), "{alice, frank}");
    /// assert_eq!(y.intersect(&z).to_string(), "{}");
    /// ```
    #[must_use]
    #[inline]
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
    ///
    /// # Example Usage
    ///
    /// ```
    /// # use glowy::labels::Label;
    /// #
    /// let x = Label::from_tags(&["alice", "bob", "charlie", "david"]);
    /// let y = Label::from_tags(&["alice", "david"]);
    ///
    /// assert_eq!(x.difference(&y).to_string(), "{bob, charlie}");
    /// assert_eq!(y.difference(&x).to_string(), "{}");
    /// assert_eq!(x.difference(&Label::Bottom), x);
    /// assert_eq!(Label::Bottom.difference(&x), Label::Bottom);
    /// ```
    #[must_use]
    #[inline]
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

    /// Returns whether this [`Label`] is a subset of another [`Label`].
    ///
    /// In other words, this method returns if `other` contains at least all
    /// tags in `self`. As would be expected, a [`Label::Bottom`] is a subset of
    /// all [`Label`]s (including itself), but no [`Label`] is a subset of
    /// [`Label::Bottom`] except for itself.
    ///
    /// For example, `{a, c}` is a subset of `{a, b, c}` but not of `{a, b, d}`.
    ///
    /// # Example Usage
    ///
    /// ```
    /// # use glowy::labels::Label;
    /// #
    /// let x = Label::from_tags(&["alice", "bob", "charlie", "david"]);
    /// let y = Label::from_tags(&["alice", "charlie"]);
    /// let z = Label::from_tags(&["david"]);
    ///
    /// assert!(y.is_subset_of(&x));
    /// assert!(z.is_subset_of(&x));
    /// assert!(!x.is_subset_of(&y));
    /// assert!(!y.is_subset_of(&z));
    /// assert!(!z.is_subset_of(&y));
    /// assert!(Label::Bottom.is_subset_of(&x));
    /// assert!(!x.is_subset_of(&Label::Bottom));
    /// ```
    #[must_use]
    #[inline]
    pub fn is_subset_of(&self, other: &Self) -> bool {
        match self {
            Self::Bottom => true,
            Self::Tags(sub) => match other {
                Self::Bottom => false,
                Self::Tags(sup) => sub.is_subset(sup),
            },
        }
    }

    /// Returns whether this [`Label`] contains a given [`LabelTag`].
    ///
    /// For example, `{a, b, c}` contains `c` but not `d`. If `self` is
    /// [`Label::Bottom`], it is considered not to contain any tag, as expected.
    ///
    /// # Example Usage
    ///
    /// ```
    /// # use glowy::labels::{Label, LabelTag};
    /// #
    /// let x = Label::from_tags(&["alice", "bob", "charlie"]);
    /// let y = Label::from_single(LabelTag::Concrete("david"));
    /// let z = Label::Bottom;
    ///
    /// assert!(x.contains(&LabelTag::Concrete("bob")));
    /// assert!(!x.contains(&LabelTag::Concrete("david")));
    /// assert!(y.contains(&LabelTag::Concrete("david")));
    /// assert!(!y.contains(&LabelTag::Concrete("charlie")));
    /// assert!(!z.contains(&LabelTag::Concrete("alice")));
    /// ```
    #[must_use]
    #[inline]
    pub fn contains(&self, tag: &LabelTag<'a>) -> bool {
        match self {
            Self::Bottom => false,
            Self::Tags(tags) => tags.contains(tag),
        }
    }

    /// Returns whether this [`Label`] is a [`Label::Bottom`].
    ///
    /// For example, `{a}` and `{a, b, c}` are not Bottom, while `{}` is.
    ///
    /// # Example Usage
    ///
    /// ```
    /// # use glowy::labels::Label;
    /// #
    /// assert!(Label::Bottom.is_bottom());
    /// assert!(Label::from_tags(&[]).is_bottom());
    /// assert!(!Label::from_tags(&["alice"]).is_bottom());
    /// assert!(!Label::from_tags(&["alice", "bob"]).is_bottom());
    /// ```
    #[must_use]
    #[inline]
    pub fn is_bottom(&self) -> bool {
        matches!(self, Self::Bottom)
    }

    /// Returns an iterator over the [`LabelTag`]s in this label.
    ///
    /// For [`Label::Bottom`], this iterator is empty. For [`Label::Tags`], it
    /// yields each tag according to their natural ordering (see
    /// [`LabelTag::cmp`]).
    ///
    /// # Example Usage
    ///
    /// ```
    /// # use glowy::labels::Label;
    /// #
    /// let x = Label::Bottom;
    /// let y = Label::from_tags(&["alice"]);
    /// let z = Label::from_tags(&["bob", "charlie"]);
    ///
    /// assert_eq!(x.tags().count(), 0);
    /// assert_eq!(
    ///     y.tags().map(ToString::to_string).collect::<Vec<_>>(),
    ///     vec!["alice"]
    /// );
    /// assert_eq!(
    ///     z.tags().map(ToString::to_string).collect::<Vec<_>>(),
    ///     vec!["bob", "charlie"]
    /// );
    /// ```
    #[inline]
    pub fn tags(&self) -> impl Iterator<Item = &LabelTag<'a>> + Clone {
        let tags = match self {
            Self::Bottom => None,
            Self::Tags(tags) => Some(tags),
        };

        tags.into_iter().flatten()
    }

    pub(crate) fn as_single(&self) -> Option<&LabelTag<'a>> {
        if let Self::Tags(tags) = self
            && tags.len() == 1
        {
            return tags.first();
        }

        None
    }

    pub(crate) fn has_any_synthetic(&self) -> bool {
        self.tags().any(|t| matches!(t, LabelTag::Synthetic { .. }))
    }

    pub(crate) fn is_synthetic_representation(
        &self,
        func: &FunctionRef<'a>,
        slot: SyntheticSlot,
    ) -> bool {
        let Some(single) = self.as_single() else {
            return false;
        };

        single.is_synthetic_representation(func, slot)
    }

    pub(crate) fn rebind_synthetic_func(
        &self,
        from_func: &FunctionRef<'a>,
        to_func: &FunctionRef<'a>,
    ) -> Self {
        let Self::Tags(tags) = self else {
            return Self::Bottom;
        };

        let rebound: BTreeSet<_> = tags
            .iter()
            .map(|t| match t {
                LabelTag::Synthetic {
                    func,
                    slot,
                    identifier,
                } if func == from_func => LabelTag::Synthetic {
                    func: to_func.clone(),
                    slot: *slot,
                    identifier: *identifier,
                },
                LabelTag::Synthetic { .. } | LabelTag::Concrete(_) => t.clone(),
            })
            .collect();

        Self::Tags(rebound)
    }
}

impl PartialOrd for Label<'_> {
    #[inline]
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

impl fmt::Display for Label<'_> {
    #[inline]
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

// useful for when it would be too bothersome to keep &'a str lifetimes around
#[derive(Clone, Debug)]
pub(crate) struct OwnedLabel(Vec<String>);

impl OwnedLabel {
    pub(crate) fn as_label(&'_ self) -> Label<'_> {
        let slices: Vec<_> = self.0.iter().map(String::as_str).collect();

        Label::from_tags(&slices)
    }
}

impl From<Vec<String>> for OwnedLabel {
    fn from(vec: Vec<String>) -> Self {
        Self(vec)
    }
}

impl From<&Label<'_>> for OwnedLabel {
    fn from(label: &Label<'_>) -> Self {
        let tags = label
            .tags()
            .filter_map(|tag| match tag {
                LabelTag::Concrete(s) => Some((*s).to_owned()),
                LabelTag::Synthetic { .. } => None,
            })
            .collect();

        Self(tags)
    }
}

pub(crate) enum OwnedLabelCow<'a, 'b> {
    Owned(OwnedLabel),
    Borrowed(&'b Label<'a>),
}

impl OwnedLabelCow<'_, '_> {
    pub(crate) fn into_owned(self) -> OwnedLabel {
        match self {
            Self::Owned(owned) => owned,
            Self::Borrowed(borrowed) => borrowed.into(),
        }
    }
}

impl From<OwnedLabel> for OwnedLabelCow<'_, '_> {
    fn from(owned: OwnedLabel) -> Self {
        Self::Owned(owned)
    }
}

impl<'a, 'b> From<&'b Label<'a>> for OwnedLabelCow<'a, 'b> {
    fn from(borrowed: &'b Label<'a>) -> Self {
        Self::Borrowed(borrowed)
    }
}

/// Represents the propagation history leading up to a label attribution.
///
/// This hierarchical structure keeps track of why a certain piece of data has
/// been assigned a specific [`Label`], particularly in the sense of what
/// operations occurred and compounded to result in a final label.
///
/// The following invariants are strictly enforced: \
///     1. No [`LabelBacktrace`] ever has a label [`Label::Bottom`]; \
///     2. Children's labels are always a subset of their parent's label (e.g.,
///     a backtrace `{blue, violet}` can have a child `{blue}` and another
///     `{violet}`, but never a `{yellow}` child); and \
///     3. All children's labels are always disjoint (e.g., if a first child
///     has label `{blue, violet}`, a second child can never have label
///     `{blue, yellow}` -- it will instead be trimmed to just `{yellow}` to
///     simplify the whole chain and limit hierarchy size).
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct LabelBacktrace<'a> {
    /// What operation caused this label attribution.
    kind: LabelBacktraceKind,
    /// The final label associated with some information.
    label: Label<'a>,
    /// Name of symbol with this label, if any/applicable.
    symbol: Option<&'a str>,
    /// Where this operation took place.
    location: Pinned<'a, Location>,
    /// Other backtraces through which this label is derived via propagation.
    children: Vec<Self>,
}

impl<'a> LabelBacktrace<'a> {
    /// Base case; no children.
    ///
    /// Returns [`None`] iff `label` is [`Label::Bottom`].
    ///
    /// Useful, in particular, for [`LabelBacktraceKind::ExplicitAnnotation`]
    /// and [`LabelBacktraceKind::FunctionParameter`].
    pub(crate) fn new_root(
        kind: LabelBacktraceKind,
        label: Label<'a>,
        symbol: Option<&'a str>,
        location: Pinned<'a, Location>,
    ) -> Option<Self> {
        if label.is_bottom() {
            None
        } else {
            Some(Self {
                kind,
                label,
                symbol,
                location,
                children: vec![],
            })
        }
    }

    /// Returns [`None`] iff `label` is [`Label::Bottom`].
    pub(crate) fn new<'b>(
        kind: LabelBacktraceKind,
        label: Label<'a>,
        symbol: Option<&'a str>,
        location: Pinned<'a, Location>,
        children: impl IntoIterator<Item = &'b Self>,
    ) -> Option<Self>
    where
        'a: 'b,
    {
        if label.is_bottom() {
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
        if let [child] = children.as_slice()
            && child.label == label
            && child.location == location
            && child.symbol == symbol
        {
            // avoid unnecessary repeated backtraces that just make everything more complex;
            // for example, in the example below:
            // ```go
            // // glowy::label::{high}
            // var a = 3
            // ```
            // we just want ExplicitAnnotation and not also Assignment another level up
            return Some(child.clone());
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
        children: impl IntoIterator<Item = &'b Self> + Clone,
        with_kind: LabelBacktraceKind,
        with_symbol: Option<&'a str>,
        at_location: Pinned<'a, Location>,
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
    pub(crate) fn with_child(&self, child: &Self) -> Self {
        // if self is a root backtrace with synthetic tags, such as in the case
        // of a function's synthetic implicit call-site branch backtrace that is
        // presently being composed with an existing branch backtrace, we need
        // to make sure that the former remains as-is without being merged with
        // the latter, as otherwise it will become invisible to `realize` (which
        // only takes action for root backtraces that have *only* synthetics)
        let keep_self_as_child = self.children.is_empty() && self.label.has_any_synthetic();

        let children: Vec<&Self> = if keep_self_as_child {
            vec![self, child]
        } else {
            iter::once(child).chain(self.children.iter()).collect()
        };

        Self::new(
            self.kind,
            self.label.union(child.label()),
            self.symbol,
            self.location.clone(),
            children.iter().copied(),
        )
        .unwrap() // safe because if self exists, label is not Bottom
    }

    /// Constructs a new instance with self as its only child, avoiding cloning.
    pub(crate) fn into_single_child(
        self,
        parent_kind: LabelBacktraceKind,
        parent_symbol: Option<&'a str>,
        parent_location: Pinned<'a, Location>,
    ) -> Self {
        // note that we're not using Self::new to avoid cloning self and to skip
        // unnecessary checks / label optimizations -- we already know this
        // label isn't Bottom + cannot be compacted further because self exists
        Self {
            kind: parent_kind,
            label: self.label.clone(),
            symbol: parent_symbol,
            location: parent_location,
            children: vec![self],
        }
    }

    /// Returns a new instance (with symbol = None) representing a step above
    /// in the hierarchy between two instances (self and other).
    pub(crate) fn union(
        &self,
        other: &Self,
        with_kind: LabelBacktraceKind,
        at_location: Pinned<'a, Location>,
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

    /// Unions if both are Some, otherwise returns the only Some, if any.
    pub(crate) fn combine_options(
        a: Option<Self>,
        b: Option<Self>,
        with_kind: LabelBacktraceKind,
        at_location: Cow<Pinned<'a, Location>>,
    ) -> Option<Self> {
        match (&a, &b) {
            (None, None) => None,
            (Some(_), None) => a,
            (None, Some(_)) => b,
            (Some(x), Some(y)) => Some(x.union(y, with_kind, at_location.into_owned())),
        }
    }

    /// Realizes synthetic placeholders in the hierarchy to concrete backtraces.
    pub(crate) fn realize(
        &self,
        from_func: &FunctionRef<'a>,
        from_slot: SyntheticSlot,
        concrete: Option<&Self>,
    ) -> Option<Self> {
        if !self
            .label()
            .tags()
            .any(|tag| tag.is_synthetic_representation(from_func, from_slot))
        {
            // there is nothing left to be realized, so prevent recursion and
            // avoid all the downstream allocations / checks / etc.

            // this optimization leads to a 70% overall speedup in complex runs

            return Some(self.clone());
        }

        if matches!(
            self.kind,
            LabelBacktraceKind::FunctionParameter | LabelBacktraceKind::ClosureCapture
        ) {
            if self.label().as_single().is_some() {
                // note that since we already checked above with
                // is_synthetic_representation, if the label has a single tag,
                // then we are a root synthetic that needs to be realized

                Self::new(
                    from_slot.label_backtrace_kind(),
                    concrete.map_or(&Label::Bottom, Self::label).clone(),
                    self.symbol(),
                    self.location().clone(),
                    concrete,
                )
            } else {
                Some(self.clone())
            }
        } else if matches!(self.kind, LabelBacktraceKind::Branch)
            && self.children.is_empty() // root
            && self.label().as_single().is_some()
        {
            // this is the function's synthetic implicit branch backtrace, which
            // needs to be realized into the actual call-site branch backtrace
            concrete.cloned()
        } else {
            let children: Vec<_> = self
                .children()
                .iter()
                .filter_map(|child| child.realize(from_func, from_slot, concrete))
                .collect();

            Self::fold(
                &children,
                *self.kind(),
                self.symbol(),
                self.location().clone(),
            )
        }
    }

    /// Rebinds all [`LabelTag::Synthetic`]s from one function to another.
    ///
    /// This applies recursively across the entire hierarchy, affecting only
    /// synthetic tags associated with the specified initial function.
    pub(crate) fn rebind_synthetic_func(
        &self,
        from_func: &FunctionRef<'a>,
        to_func: &FunctionRef<'a>,
    ) -> Self {
        if self.children().is_empty() {
            Self::new(
                *self.kind(),
                self.label.rebind_synthetic_func(from_func, to_func),
                self.symbol,
                self.location.clone(),
                &self.children,
            )
            .unwrap() // safe because self exists
        } else {
            let children: Vec<_> = self
                .children()
                .iter()
                .map(|child| child.rebind_synthetic_func(from_func, to_func))
                .collect();

            Self::fold(
                &children,
                *self.kind(),
                self.symbol(),
                self.location().clone(),
            )
            .unwrap() // safe because children is non-empty (we checked)
        }
    }

    /// Returns a new instance whose label only contains tags in a given
    /// constraint, pruning children if they would have [`Label::Bottom`].
    #[must_use]
    fn restrict_to_label(&self, constraint: &Label<'a>) -> Option<Self> {
        if self.label.is_subset_of(constraint) {
            // we already meet this restriction, so prevent recursion and avoid
            // all the downstream allocations / intersections / etc.

            // this optimization leads to a 50% overall speedup in complex runs

            return Some(self.clone());
        }

        let new_label = self.label.intersect(constraint);

        if new_label.is_bottom() {
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

    /// Tries to mutate the present instance so that its label has certain tags
    /// removed, pruning children if they would have [`Label::Bottom`].
    ///
    /// This method returns `true` if the mutation is successful and `false` if
    /// the whole instance should be disregarded and should instead be replaced
    /// in its entirety with `None` (i.e., if it would have [`Label::Bottom`]).
    #[must_use]
    pub(crate) fn subtract_label(&mut self, subtract: &Label<'a>) -> bool {
        if subtract.is_bottom() {
            // nothing to do
            return true;
        }

        let constraint = self.label().difference(subtract);

        if constraint.is_bottom() {
            return false;
        }

        if let Some(new) = self.restrict_to_label(&constraint) {
            *self = new;

            true
        } else {
            false
        }
    }

    /// Returns the kind of operation that caused the label assignment.
    #[must_use]
    #[inline]
    pub fn kind(&self) -> &LabelBacktraceKind {
        &self.kind
    }

    /// Returns the label in question described by this backtrace.
    ///
    /// This is guaranteed to never be [`Label::Bottom`].
    #[must_use]
    #[inline]
    pub fn label(&self) -> &Label<'a> {
        &self.label
    }

    /// Returns the name of the symbol with this label, if any/applicable.
    #[must_use]
    #[inline]
    pub fn symbol(&self) -> Option<&'a str> {
        self.symbol
    }

    /// Returns the location where the operation took place.
    #[must_use]
    #[inline]
    pub fn location(&self) -> &Pinned<'a, Location> {
        &self.location
    }

    /// Returns the backtraces that compound to yield and justify this one.
    #[must_use]
    #[inline]
    pub fn children(&self) -> &[Self] {
        &self.children
    }
}

// allow consuming backtrace to convert it to its label without cloning
impl<'a> From<LabelBacktrace<'a>> for Label<'a> {
    #[inline]
    fn from(backtrace: LabelBacktrace<'a>) -> Self {
        backtrace.label
    }
}

/// The concrete operation that resulted in a label assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LabelBacktraceKind {
    /// Explicit source code annotation.
    ExplicitAnnotation,
    /// Explicit blanket information source registered to the analyzer.
    BlanketSource,
    /// Assignment of some tainted expression to a variable.
    Assignment,
    /// Bootstrapping label from initialization expression in declaration.
    DeclarationInitialization,
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
    /// Concrete label associated to a method's receiver at the binding site.
    ///
    /// Conceptually, the receiver-flavored counterpart of
    /// [`LabelBacktraceKind::FunctionArgument`], used both when a synthetic
    /// receiver placeholder is realized at a call site and when a receiver's
    /// taint is propagated into a bound method value (e.g. `f := x.M`).
    MethodReceiver,
    /// Synthetic label assigned to a captured symbol shared with outer scope.
    ClosureCapture,
    /// Concrete label associated to a captured symbol at closure invocation.
    ///
    /// The realized counterpart of [`LabelBacktraceKind::ClosureCapture`],
    /// mirroring the [`LabelBacktraceKind::FunctionParameter`] <->
    /// [`LabelBacktraceKind::FunctionArgument`] pair.
    ClosureCaptureBinding,
    /// Individual label for one particular expression in a return statement.
    Return,
    /// Conservative label returned by a function without known implementation.
    BlackboxCall,
    /// Duplication from one slice to another via the `copy` built-in.
    SliceCopy,
    /// Removal of all of a slice/map's elements via the `clear` built-in.
    CollectionClear,
    /// Blocking further sends of a channel via the `close` built-in.
    ChannelClose,
    /// Removal of a map element via the `delete` built-in.
    MapElementDelete,
    /// Composite label derived from all factors relevant to flow evaluation.
    EnforcementAggregation,
}
