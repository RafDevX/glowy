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

use std::{borrow::Cow, cmp, collections::BTreeSet, fmt, iter, mem, ops};

pub use backtraces::{LabelBacktrace, LabelBacktraceKind};
pub use tags::{ConcreteLabelTag, LabelTag, SyntheticSlot};

use crate::IntoCowStr;
// we need this to be publicly accessible and documented, since it's referenced
// publicly by LabelTag::Synthetic
pub use crate::values::FunctionRef;

mod backtraces;
mod tags;

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
/// If this label has been re-interpreted to support wildcard axis tags (i.e.,
/// if [`Label::accept_wildcards`] has been invoked), redundant wildcard
/// specialization is guaranteed to be discarded. For example, if wildcards are
/// accepted, a label `{cat, dir:*, dir:north}` will never exist, since it is
/// simplified to just `{cat, dir:*}`.
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
    /// For invoker convenience, several different types are accepted as input,
    /// including `&[&'a str]` and `Vec<String>`. See [`IntoCowStr`] for more
    /// details. A [`Cow`] is used internally so that tags may either borrow
    /// from source (typical for annotations lifted from the codebase, which are
    /// already `&'a str` slices of the source code) or own their content
    /// (necessary when the tag content originates from an owned [`String`],
    /// such as in the case of struct field tags).
    ///
    /// # Example Usage
    ///
    /// ```
    /// # use glowy::labels::Label;
    /// #
    /// assert_eq!(Label::from_tags(&["dog", "cat"]).to_string(), "{cat, dog}");
    ///
    /// // it is easier to just use `Label::Bottom`, vs. passing an empty Vec
    /// assert_eq!(Label::from_tags(Vec::<String>::new()), Label::Bottom);
    /// ```
    #[must_use]
    #[inline]
    pub fn from_tags<I, S>(tags: I) -> Self
    where
        I: IntoIterator<Item = S>,
        I::IntoIter: ExactSizeIterator,
        S: IntoCowStr<'a>,
    {
        let iter = tags.into_iter();

        // ExactSizeIterator::is_empty exists but is unstable since 2016...
        if iter.len() == 0 {
            Self::Bottom
        } else {
            let set: BTreeSet<_> = iter.map(LabelTag::from).collect();

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
    /// let tag = LabelTag::from("secret");
    /// assert_eq!(Label::from_single(tag).to_string(), "{secret}");
    /// ```
    #[must_use]
    #[inline]
    pub fn from_single(tag: LabelTag<'a>) -> Self {
        let mut set = BTreeSet::new();
        set.insert(tag);

        Self::Tags(set)
    }

    /// Upgrades all applicable tags to [`LabelTag::AxisWildcard`].
    ///
    /// Axis wildcard tags are considered opt-in behavior for only very narrow
    /// situations within the analysis process. This method reinterprets all of
    /// the [`Label`]'s tags to convert any axis-bound [`LabelTag::Concrete`]s
    /// with a tag component corresponding to the literal `*` into full-fledged
    /// [`LabelTag::AxisWildcard`]s.
    ///
    /// Note that, as per [`Label`]'s guaranteed, redundant wildcard
    /// specializations are discarded if present: this means that any
    /// [`LabelTag::Concrete`] with a defined axis matching a newly-interpreted
    /// [`LabelTag::AxisWildcard`] is removed, so `{cat, color:*, color:blue}`
    /// is transparently collapsed into `{cat, color:*}`.
    ///
    /// See [`LabelTag::try_upgrade_to_wildcard`] for more information, as this
    /// method uses that one under the hood.
    ///
    /// # Example Usage
    ///
    /// ```
    /// # use glowy::labels::{Label, LabelTag};
    /// #
    /// let mut label = Label::from_tags(&["not-bound", "dir:north", "dir:*"]);
    ///
    /// label.accept_wildcards();
    ///
    /// let mut tags = label.tags();
    /// assert_eq!(tags.next(), Some(&LabelTag::from("not-bound"))); // concrete
    /// assert_eq!(tags.next(), Some(&LabelTag::AxisWildcard("dir".into())));
    /// assert_eq!(tags.next(), None);
    /// ```
    #[inline]
    pub fn accept_wildcards(&mut self) {
        let Self::Tags(tags) = self else {
            return;
        };

        // we need to rebuild the whole set since some tags might have changed
        let new_tags = mem::take(tags)
            .into_iter()
            .map(LabelTag::try_upgrade_to_wildcard)
            .collect();

        *tags = discard_wildcard_specializations(new_tags);
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
            (Self::Tags(left), Self::Tags(right)) => {
                Self::Tags(discard_wildcard_specializations(left | right))
            }
        }
    }

    /// Returns the intersection of `self` and `other` as a new [`Label`].
    ///
    /// For example, `{a, b, c}` intersected with `{b, d, e}` yields `{b}`.
    /// If the intersection is null, [`Label::Bottom`] is returned as expected.
    ///
    /// Any [`LabelTag::AxisWildcard`] present is eclipsed by any
    /// [`LabelTag::Concrete`] bound to the same axis, with the latter tag
    /// being included in the intersection. For example, `{boat, cat, color:*}`
    /// intersected with `{cat, color:red}` yields `{cat, color:red}`.
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
    ///
    /// let left = Label::from_tags(&["cat", "dir:north", "dir:south", "dog"]);
    /// let mut right = Label::from_tags(&["dir:*", "dog"]);
    /// right.accept_wildcards();
    ///
    /// assert_eq!(
    ///     left.intersect(&right).to_string(),
    ///     "{dog, dir:north, dir:south}" // `dir:*` is eclipsed, but these stay
    /// );
    /// ```
    #[must_use]
    #[inline]
    pub fn intersect(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Tags(left), Self::Tags(right)) => {
                let mut new_tags = left & right;

                for tag in left.symmetric_difference(right) {
                    if let LabelTag::Concrete(concrete) = tag
                        && let Some(axis) = concrete.axis()
                    {
                        let probe = LabelTag::AxisWildcard(Cow::Borrowed(axis));

                        // note that this will not falsely trigger for {a:b} in
                        // {a:*, a:b} ∩ {cat}, even though it does exist in the
                        // symmetric difference and one of the sets has the
                        // matching wildcard, simply because the left label
                        // cannot ever exist: we explicitly forbid redundant
                        // wildcard specializations in well-formed labels
                        if left.contains(&probe) || right.contains(&probe) {
                            new_tags.insert(tag.clone());
                        }
                    }
                }

                if new_tags.is_empty() {
                    Self::Bottom
                } else {
                    // no risk of wildcard specializations being introduced,
                    // since the intersection is necessarily a subset of self
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
    /// Any [`LabelTag::AxisWildcard`] present eclipses any
    /// [`LabelTag::Concrete`] bound to the same axis, with neither being
    /// included in the returned difference set. For example, `{cat, color:*}`
    /// subtracted from `{boat, cat, color:red}` yields `{boat}`.
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
    ///
    /// let left = Label::from_tags(&["cat", "dir:north", "dir:south", "dog"]);
    /// let mut right = Label::from_tags(&["dir:*", "dog"]);
    /// right.accept_wildcards();
    ///
    /// assert_eq!(left.difference(&right).to_string(), "{cat}");
    /// assert_eq!(right.difference(&left).to_string(), "{dir:*}");
    /// ```
    #[must_use]
    #[inline]
    pub fn difference(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Bottom, _) => Self::Bottom,
            (_, Self::Bottom) => self.clone(),
            (Self::Tags(left), Self::Tags(right)) => {
                let mut new_tags = left - right;

                // if left has {a:b} and right has {a:*}, diff cannot have {a:b}
                new_tags.retain(|tag| {
                    !matches!(
                    tag,
                    LabelTag::Concrete(concrete) if concrete.axis().is_some_and(
                        |axis| right.contains(&LabelTag::AxisWildcard(Cow::Borrowed(axis)))
                    ))
                });

                if new_tags.is_empty() {
                    Self::Bottom
                } else {
                    // no risk of wildcard specializations being introduced,
                    // since the difference is necessarily a subset of self
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
    /// Any [`LabelTag::AxisWildcard`] present in `other` allows any
    /// [`LabelTag::Concrete`] bound to the same axis in `self` to count towards
    /// `self` being a subset of `other`. For example, `{cat, color:red}` is a
    /// subset of `{boat, cat, color:*}`.
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
    ///
    /// let left = Label::from_tags(&["cat", "dir:north", "dir:south"]);
    /// let mut right = Label::from_tags(&["cat", "dir:*"]);
    /// right.accept_wildcards();
    ///
    /// assert!(left.is_subset_of(&right));
    /// assert!(!right.is_subset_of(&left));
    /// ```
    #[must_use]
    #[inline]
    pub fn is_subset_of(&self, other: &Self) -> bool {
        match self {
            Self::Bottom => true,
            Self::Tags(sub) => match other {
                Self::Bottom => false,
                Self::Tags(sup) => sub.iter().all(|tag| {
                    sup.contains(tag)
                        || matches!(
                            tag,
                            LabelTag::Concrete(concrete) if concrete.axis().is_some_and(
                                |axis| sup.contains(&LabelTag::AxisWildcard(Cow::Borrowed(axis)))
                            )
                        )
                }),
            },
        }
    }

    /// Returns whether this [`Label`] contains a given [`LabelTag`].
    ///
    /// For example, `{a, b, c}` contains `c` but not `d`. If `self` is
    /// [`Label::Bottom`], it is considered not to contain any tag, as expected.
    ///
    /// Any [`LabelTag::AxisWildcard`] in `self` allows any
    /// [`LabelTag::Concrete`] bound to the same axis to be considered as
    /// containing to `self`. For example, `{color:red}` is contained in
    /// `{cat, color:*}`.
    ///
    /// # Example Usage
    ///
    /// ```
    /// # use glowy::labels::{Label, LabelTag};
    /// #
    /// let x = Label::from_tags(&["alice", "bob", "charlie"]);
    /// let y = Label::from_single(LabelTag::from("david"));
    /// let z = Label::Bottom;
    ///
    /// assert!(x.contains(&LabelTag::from("bob")));
    /// assert!(!x.contains(&LabelTag::from("david")));
    /// assert!(y.contains(&LabelTag::from("david")));
    /// assert!(!y.contains(&LabelTag::from("charlie")));
    /// assert!(!z.contains(&LabelTag::from("alice")));
    /// ```
    #[must_use]
    #[inline]
    pub fn contains(&self, tag: &LabelTag<'a>) -> bool {
        match self {
            Self::Bottom => false,
            Self::Tags(tags) => {
                if tags.contains(tag) {
                    true
                } else if let LabelTag::Concrete(concrete) = tag
                    && let Some(axis) = concrete.axis()
                {
                    // {a:*} contains {a:b}
                    tags.contains(&LabelTag::AxisWildcard(Cow::Borrowed(axis)))
                } else {
                    false
                }
            }
        }
    }

    /// Returns the restriction of this label to the provided axes.
    ///
    /// This operation constructs a new instance of [`Label`] which is identical
    /// to `self`, except for the omission of [`LabelTag`]s with a defined axis
    /// not whitelisted by `axes`.
    ///
    /// In particular, this means that:
    /// - [`Label::Bottom`] is always restricted to [`Label::Bottom`];
    /// - any [`LabelTag`] without a defined axis is never omitted; and
    /// - if `axes` is empty, only [`LabelTag`]s without an axis are included.
    ///
    /// # Example Usage
    ///
    /// ```
    /// # use glowy::labels::Label;
    /// # use std::collections::BTreeSet;
    /// #
    /// let x = Label::from_tags(&["cat", "color:blue", "color:red", "q:no"]);
    /// let y = Label::from_tags(&["alice", "bob"]);
    /// let z = Label::Bottom;
    ///
    /// let color = BTreeSet::from(["color"]);
    /// let q = BTreeSet::from(["q"]);
    ///
    /// assert_eq!(
    ///     x.restrict_to_axes(&color),
    ///     Label::from_tags(&["cat", "color:blue", "color:red"])
    /// );
    /// assert_eq!(x.restrict_to_axes(&q), Label::from_tags(&["cat", "q:no"]));
    ///
    /// assert_eq!(y.restrict_to_axes(&color), y);
    /// assert_eq!(y.restrict_to_axes(&q), y);
    ///
    /// assert_eq!(z.restrict_to_axes(&color), Label::Bottom);
    /// assert_eq!(z.restrict_to_axes(&q), Label::Bottom);
    /// ```
    #[must_use]
    #[inline]
    pub fn restrict_to_axes(&self, axes: &BTreeSet<&str>) -> Self {
        let Self::Tags(tags) = self else {
            return Self::Bottom;
        };

        let restricted: BTreeSet<_> = tags
            .iter()
            .filter(|tag| tag.axis().is_none_or(|axis| axes.contains(axis)))
            .cloned()
            .collect();

        if restricted.is_empty() {
            Self::Bottom
        } else {
            // no risk of wildcard specializations being introduced, since the
            // restriction is always necessarily a subset of self
            Self::Tags(restricted)
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
    /// assert!(Label::from_tags::<&[&str], _>(&[]).is_bottom());
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

    /// Returns a set of all axes explicitly mentioned by this label's tags.
    ///
    /// All of this [`Label`]'s [`LabelTag`]'s axes (if any) are collected and
    /// deduplicated into a [`BTreeSet`]. For [`Label::Bottom`], the returned
    /// set is empty. For [`Label::Tags`], it yields each axis exactly once and
    /// according to their natural ordering (lexicographical), per standard
    /// [`BTreeSet`] guarantees.
    ///
    /// # Example Usage
    ///
    /// ```
    /// # use glowy::labels::Label;
    /// # use std::collections::BTreeSet;
    /// #
    /// let x = Label::Bottom;
    /// let y = Label::from_tags(&["alice", "bob"]);
    /// let z = Label::from_tags(&["cat", "color:blue", "color:red", "q:no"]);
    ///
    /// assert_eq!(x.axes(), BTreeSet::new());
    /// assert_eq!(y.axes(), BTreeSet::new());
    /// assert_eq!(z.axes(), BTreeSet::from(["color", "q"]));
    /// ```
    #[must_use]
    #[inline]
    pub fn axes(&self) -> BTreeSet<&str> {
        self.tags().filter_map(LabelTag::axis).collect()
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

    pub(crate) fn contains_synthetic_representation(
        &self,
        func: &FunctionRef<'a>,
        slot: SyntheticSlot,
    ) -> bool {
        self.tags()
            .any(|tag| tag.is_synthetic_representation(func, slot))
    }

    fn rebind_synthetic_func(
        &self,
        from_func: &FunctionRef<'a>,
        to_func: &FunctionRef<'a>,
    ) -> Self {
        let Self::Tags(tags) = self else {
            return Self::Bottom;
        };

        let rebound: BTreeSet<_> = tags
            .iter()
            .map(|tag| match tag {
                LabelTag::Synthetic {
                    func,
                    slot,
                    identifier,
                } if func == from_func => LabelTag::Synthetic {
                    func: to_func.clone(),
                    slot: *slot,
                    identifier: *identifier,
                },
                LabelTag::Concrete(_) | LabelTag::AxisWildcard(_) | LabelTag::Synthetic { .. } => {
                    tag.clone()
                }
            })
            .collect();

        Self::Tags(discard_wildcard_specializations(rebound))
    }
}

impl PartialOrd for Label<'_> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        if self == other {
            Some(cmp::Ordering::Equal)
        } else if self.is_subset_of(other) {
            // e.g., {} < {a, ...}
            // e.g., {a, b} < {a, b, c}
            // e.g., {cat, dir:north, dir:south} < {cat, dir:*}
            Some(cmp::Ordering::Less)
        } else if other.is_subset_of(self) {
            // e.g., {a, ...} > {}
            // e.g., {a, b, c} > {a, b}
            // e.g., {cat, dir:*} > {cat, dir:north, dir:south}
            Some(cmp::Ordering::Greater)
        } else {
            None // not comparable
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

impl<'a> ops::Add<Self> for &Label<'a> {
    type Output = Label<'a>;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        self.union(rhs)
    }
}

impl ops::Add<&Self> for Label<'_> {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        (&self) + rhs
    }
}

impl<'b> iter::Sum<&'b Self> for Label<'_> {
    #[inline]
    fn sum<I: for<'c> Iterator<Item = &'b Self>>(iter: I) -> Self {
        iter.fold(Self::Bottom, |a, b| a + b)
    }
}

impl iter::Sum<Self> for Label<'_> {
    #[inline]
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::Bottom, |a, b| a + &b)
    }
}

// it's silly for a label to be {cat, dir:*, dir:north}, so make it {cat, dir:*}
fn discard_wildcard_specializations(mut set: BTreeSet<LabelTag<'_>>) -> BTreeSet<LabelTag<'_>> {
    let wildcards: BTreeSet<_> = set
        .iter()
        .filter_map(|tag| {
            if let LabelTag::AxisWildcard(axis) = tag {
                Some(axis.clone().into_owned())
            } else {
                None
            }
        })
        .collect();

    if wildcards.is_empty() {
        // the most common case is that there's nothing to do
        return set;
    }

    set.retain(|tag| {
        if let LabelTag::Concrete(concrete) = tag
            && let Some(axis) = concrete.axis()
        {
            !wildcards.contains(axis)
        } else {
            true
        }
    });

    set
}
