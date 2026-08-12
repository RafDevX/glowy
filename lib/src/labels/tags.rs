use std::{borrow::Cow, cmp, fmt, hash, mem};

use crate::{
    IntoCowStr, Span,
    labels::{FunctionRef, LabelBacktraceKind},
};

const WELL_KNOWN_AXIS_PREFIXES: &[(char, &str)] = &[('$', "secret"), ('?', "untrusted")];

/// Represents a concrete label tag's canonical structured layout.
///
/// This struct is used to hold a [`LabelTag::Concrete`]'s underlying tag, as
/// well as the axis it is bound to (if any). Both values are in their canonical
/// form: for example, a concrete tag specified as `$env` is here expanded into
/// tag `env` on axis `secret`. See [`ConcreteLabelTag::new`] for more
/// information.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConcreteLabelTag<'a> {
    axis: Option<Cow<'a, str>>,
    tag: Cow<'a, str>,
}

impl<'a> ConcreteLabelTag<'a> {
    /// Constructs a new instance given an (optional) axis and a tag component.
    ///
    /// If no axis is specified and the tag carries a well-known prefix, the
    /// prefix is stripped and the tag is associated with the prefix's
    /// corresponding axis. In particular, for the current version of Glowy,
    /// the prefix `$` is associated with axis `secret` and the prefix `?` is
    /// associated with axis `untrusted`, but more prefix shorthands may be
    /// added without notice, so consumers are advised to avoid non-alphanumeric
    /// characters at the beginning of custom tags.
    ///
    /// In many cases, it may prove more convenient to avoid using this method
    /// in favor of using one of the struct's [`From`] implementations, which
    /// support parsing an axis and a tag from a string.
    ///
    /// # Example Usage
    ///
    /// ```
    /// # use glowy::labels::ConcreteLabelTag;
    /// #
    /// let bound = ConcreteLabelTag::new(Some("dir"), "north");
    /// let not_bound = ConcreteLabelTag::new(None::<&str>, "violet");
    /// let prefixed = ConcreteLabelTag::new(None::<&str>, "$env");
    ///
    /// assert_eq!(bound.to_string(), "dir:north");
    /// assert_eq!(not_bound.to_string(), "violet");
    /// assert_eq!(prefixed.to_string(), "secret:env");
    /// ```
    #[must_use]
    #[inline]
    pub fn new(axis: Option<impl IntoCowStr<'a>>, tag: impl IntoCowStr<'a>) -> Self {
        let tag_cow = tag.into_cow();

        if axis.is_none() {
            macro_rules! search_prefixes {
                ($full:expr, $convert:expr) => {
                    for (prefix, new_axis) in WELL_KNOWN_AXIS_PREFIXES {
                        if let Some(stripped) = $full.strip_prefix(*prefix).map(str::trim)
                            && !stripped.is_empty()
                        {
                            return Self::new(Some(*new_axis), $convert(stripped));
                        }
                    }
                };
            }

            match &tag_cow {
                Cow::Borrowed(inner) => {
                    search_prefixes!(inner, |s| s)
                }
                Cow::Owned(inner) => {
                    search_prefixes!(inner, str::to_owned)
                }
            }
        }

        Self {
            axis: axis.map(IntoCowStr::into_cow),
            tag: tag_cow,
        }
    }

    /// Returns the axis to which this [`LabelTag`] is bound, if any.
    #[must_use]
    #[inline]
    pub fn axis(&self) -> Option<&str> {
        self.axis.as_deref()
    }

    /// Returns the actual tag component identifying this [`LabelTag`].
    #[must_use]
    #[inline]
    pub fn tag(&self) -> &str {
        &self.tag
    }
}

impl fmt::Display for ConcreteLabelTag<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(axis) = &self.axis {
            write!(f, "{axis}:")?;
        }

        self.tag.fmt(f)
    }
}

impl<'a> From<Cow<'a, str>> for ConcreteLabelTag<'a> {
    #[inline]
    fn from(cow: Cow<'a, str>) -> Self {
        fn split_axis_tag(s: &str) -> Option<(&str, &str)> {
            let (axis, tag) = s.split_once(':')?;

            let axis = axis.trim();
            let tag = tag.trim();

            if axis.is_empty() || tag.is_empty() {
                None
            } else {
                Some((axis, tag))
            }
        }

        match cow {
            Cow::Borrowed(s) => {
                if let Some((axis, tag)) = split_axis_tag(s) {
                    return Self::new(Some(axis), tag);
                }

                Self::new(None::<&str>, s)
            }
            Cow::Owned(s) => {
                if let Some((axis, tag)) = split_axis_tag(&s) {
                    return Self::new(Some(axis.to_owned()), tag.to_owned());
                }

                Self::new(None::<&str>, s)
            }
        }
    }
}

impl<'a, T: IntoCowStr<'a>> From<T> for ConcreteLabelTag<'a> {
    #[inline]
    fn from(s: T) -> Self {
        Self::from(s.into_cow())
    }
}

/// Represents a synthetic label tag's purpose and identity, for some function.
///
/// This enum models the possible reasons for why a specific
/// [`LabelTag::Synthetic`] can be synthesized to artificially represent a
/// [`Label`](super::Label) whose value is not yet known and cannot be known
/// until later during the analysis. It further provides sufficient context to
/// identify a specific instance (within the context of a given function), such
/// as the respective parameter index.
///
/// By definition, synthetic tags are transient auxiliary objects and are never
/// returned to library consumers as part of the reported results for high-level
/// program analysis, making this enum mostly an internal artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
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
    /// Conceptual placeholder for a range-over-function feedback via `yield`.
    ///
    /// Functions used as iterators in range loops accept a `yield` callback to
    /// which they can pass values passed on to the loop body, but these `yield`
    /// calls also themselves yield a boolean return value indicating whether
    /// the loop requires more values be passed (`true`) or whether the loop has
    /// finished (`false`), which can happen, for example, via `break`.
    ///
    /// This means that besides the iterator function influencing the loop body,
    /// the loop body can also propagate feedback to the iterator function based
    /// on when/if the loop is exited, hence the need for this synthetic slot.
    ///
    /// The concrete label is determined by control transfers in the caller's
    /// loop body which make the compiler-synthesized `yield` return `false`.
    YieldFeedback,
}

impl SyntheticSlot {
    pub(super) fn realized_backtrace_kind(&self) -> LabelBacktraceKind {
        match self {
            Self::Param(_) => LabelBacktraceKind::FunctionArgument,
            Self::Receiver => LabelBacktraceKind::MethodReceiver,
            Self::Capture(_) => LabelBacktraceKind::ClosureCaptureBinding,
            // branch-adjacent synthetics are realized via
            // [`LabelBacktrace::realize`]'s dedicated Branch arm, which
            // substitutes the concrete branch backtrace wholesale (preserving
            // its kind), so this method is not normally invoked for them
            Self::CallSiteBranch | Self::YieldFeedback => LabelBacktraceKind::Branch,
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
            Self::YieldFeedback => write!(f, "$YIELD_FEEDBACK"),
        }
    }
}

/// Represents an individual tag within a label.
///
/// This enum is used to model the different kinds of tags that may exist
/// within a [`Label`](super::Label). For example, each of the colors in the
/// label `{blue, red, violet}` would correspond to an instance of
/// [`LabelTag::Concrete`] with the respective name.
///
/// [`LabelTag`] derives [`Ord`], which means that when ordered tags are always
/// first discriminated by kind (the first variant comes first, and so on), and
/// then lexicographically by its internal value/identifier.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum LabelTag<'a> {
    /// A concrete user-facing tag, like `blue`, `violet`, or `dir:north`.
    Concrete(ConcreteLabelTag<'a>),
    /// A shorthand for all concrete tags of a given axis, like `dir:*`.
    AxisWildcard(Cow<'a, str>),
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
    /// Returns this label tag's defined axis, if any.
    #[must_use]
    #[inline]
    pub fn axis(&self) -> Option<&str> {
        match self {
            LabelTag::Concrete(concrete) => concrete.axis(),
            LabelTag::AxisWildcard(axis) => Some(axis),
            LabelTag::Synthetic { .. } => None,
        }
    }

    /// Converts `self` into a [`LabelTag::AxisWildcard`], if applicable.
    ///
    /// Axis wildcards only have a defined semantic meaning if very narrow
    /// cases, so they exist only as opt-in behavior. For example, a tag
    /// `dir:*` will generally be interpreted as a normal [`LabelTag::Concrete`]
    /// composed of the literal `*` in the scope of axis `dir`, but in certain
    /// very specific (and documented) analysis contexts it may be upgraded
    /// into a [`LabelTag::AxisWildcard`], since it has a defined axis and its
    /// tag component is `*`.
    ///
    /// Only [`LabelTag::Concrete`]s meeting the conditions above may be
    /// upgraded into a [`LabelTag::AxisWildcard`]; other variants and other
    /// cases of [`LabelTag::Concrete`] are returned as-is.
    ///
    /// # Example Usage
    ///
    /// ```
    /// # use glowy::labels::LabelTag;
    /// #
    /// let x = LabelTag::from("dir:*");
    /// let y = LabelTag::from("dir:north");
    /// let z = LabelTag::from("unbounded");
    ///
    /// let wildcard = LabelTag::AxisWildcard("dir".into());
    ///
    /// assert_eq!(x.try_upgrade_to_wildcard(), wildcard);
    /// assert_eq!(z.try_upgrade_to_wildcard(), LabelTag::from("unbounded"));
    /// assert_eq!(y.try_upgrade_to_wildcard(), LabelTag::from("dir:north"));
    /// ```
    #[must_use]
    #[inline]
    pub fn try_upgrade_to_wildcard(self) -> Self {
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "We explicitly want to match only one case and ignore all others"
        )]
        match self {
            Self::Concrete(ConcreteLabelTag {
                axis: Some(axis),
                tag,
            }) if tag == "*" => Self::AxisWildcard(axis),
            other => other,
        }
    }

    pub(super) fn is_synthetic_representation(
        &self,
        func: &FunctionRef<'a>,
        slot: SyntheticSlot,
    ) -> bool {
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
            Self::Concrete(tag) => tag.fmt(f),
            Self::AxisWildcard(axis) => write!(f, "{axis}:*"),
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
            (Self::Concrete(_), Self::AxisWildcard(_) | Self::Synthetic { .. })
            | (Self::AxisWildcard(_), Self::Synthetic { .. }) => cmp::Ordering::Less,
            (Self::Synthetic { .. }, Self::Concrete(_) | Self::AxisWildcard(_))
            | (Self::AxisWildcard(_), Self::Concrete(_)) => cmp::Ordering::Greater,
            (Self::Concrete(left), Self::Concrete(right)) => left.cmp(right),
            (Self::AxisWildcard(left), Self::AxisWildcard(right)) => left.cmp(right),
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
            (Self::AxisWildcard(left), Self::AxisWildcard(right)) => left == right,
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
            LabelTag::AxisWildcard(axis) => axis.hash(state),
            LabelTag::Synthetic { func, slot, .. } => {
                func.hash(state);
                slot.hash(state);
            }
        }
    }
}

impl<'a, T: Into<ConcreteLabelTag<'a>>> From<T> for LabelTag<'a> {
    #[inline]
    fn from(s: T) -> Self {
        Self::Concrete(s.into())
    }
}
