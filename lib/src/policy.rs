//! Module for security policy definition and manipulation.
//!
//! Glowy implements enforcement checks that validate a value's propagated taint
//! against a defined security policy, configured in several different ways for
//! the consumer's convenience. This module contains several necessary types and
//! functionality to allow representing (parts of) such a policy.

pub(crate) use blanket_directives::{
    BlanketDirective, BlanketDirectiveKind, BlanketDirectives, PackageBlanketDirectives,
};
use parser::Location;
pub use targets::{
    BUILTIN_PACKAGE_PATH, BlanketDirectiveTarget, BlanketDirectiveTargetParseError,
    BlanketSourceArgPredicate, BlanketSourcePredicateValue, OPERATOR_PACKAGE_PATH,
    OPERATOR_TARGET_NAMES,
};

use crate::{labels::Label, snapshots::SnapshotAware};

mod blanket_directives;
mod targets;

/// Standard base security policy with sensible defaults.
///
/// Glowy ships with a default, standard security policy designed for supporting
/// a softer bootstrap curve for stakeholders to start using the provided
/// analysis features. This base policy is heuristics-driven and
/// domain-agnostic, meaning that it will often be wrong in many fronts. It is
/// designed as a starting resource, under the expectation of being replaced by
/// a custom security policy before any serious use. When such a (more adequate)
/// policy exists, the base configuration should be disabled by setting the
/// [`AnalysisConfig::inherit_base_policy`][ACibp] option to `false`.
///
/// This constant holds a TOML-formatted string representation of the current
/// base security policy, and is only present when Cargo feature
/// `base-security-policy` is enabled.
///
/// [ACibp]: crate::AnalysisConfig::inherit_base_policy
#[cfg(feature = "base-security-policy")]
#[cfg_attr(docsrs, doc(cfg(feature = "base-security-policy")))]
pub const BASE_SECURITY_POLICY: &str = include_str!("../base-security-policy.toml");

/// Structured information representing a declared sink.
///
/// This is a lightweight descriptor capturing the essential details of an
/// information flow sink as declared by the security policy in effect.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SinkDescriptor<'a> {
    /// The type of sink in question.
    pub kind: SinkKind,
    /// Whether this is a whitelist-based sink (allow), vs. blacklist (deny).
    pub allow: bool,
    /// The sink's declared expected information label.
    pub label: Label<'a>,
    /// Where the sink was found.
    pub location: Location,
}

impl<'a> SinkDescriptor<'a> {
    pub(crate) fn new(
        kind: SinkKind,
        allow: bool,
        tags: &[&'a str],
        location: Location,
    ) -> Option<Self> {
        if !allow && tags.is_empty() {
            // a `deny` sink with Bottom label makes no sense
            return None;
        }

        let mut label = Label::from_tags(tags);
        label.accept_wildcards();

        Some(Self {
            kind,
            allow,
            label,
            location,
        })
    }

    /// Evaluates whether a given [`Label`] is accepted by the present sink.
    ///
    /// This method implements the core functionality of how sinks are
    /// interpreted by the analyzer, bridging between a defined security policy
    /// and its actual events when applied to a calculated taint label.
    ///
    /// All sinks always accept [`Label::Bottom`], but any other [`Label`] is
    /// only considered valid if:
    /// - its [restriction](Label::restrict_to_axes) to the explicit axes of
    ///   this sink's inherent policy label is a [subset
    ///   of](Label::is_subset_of) or is [equal](Label::eq) to the sink's
    ///   aforementioned inherent policy label, for allow sinks
    ///   (Axis-Restricting Whitelist Enforcement);
    /// - its [intersection](Label::intersect) with this sink's inherent policy
    ///   label is exactly [`Label::Bottom`], for deny sinks (Blacklist
    ///   Enforcement).
    ///
    /// This is used by enforcement checks to determine whether an insecure
    /// information flow error should be reported (i.e.,
    /// [`AnalysisErrorKind::InsecureFlow`][AEKif]).
    ///
    /// [AEKif]: crate::errors::AnalysisErrorKind::InsecureFlow
    #[must_use]
    #[inline]
    pub fn accepts(&self, label: &Label<'a>) -> bool {
        if label.is_bottom() {
            // Bottom is always accepted; we can skip the more expensive checks
            return true;
        }

        if self.allow {
            // allow sink - axis-restricting whitelist

            let axes = self.label.axes();
            let restricted = label.restrict_to_axes(&axes);

            restricted <= self.label
        } else {
            // deny sink - blacklist

            label.intersect(&self.label).is_bottom()
        }
    }
}

impl SnapshotAware for SinkDescriptor<'_> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.allow == other.allow
            && self.label.snapshot_aware_eq(&other.label)
            && self.location == other.location
    }
}

/// Represents a specific type of information flow sinks.
///
/// This is useful to know, for example, to provide more personalized error
/// messages when a sink's information flow invariant is violated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SinkKind {
    /// A variable/constant declaration.
    Declaration,
    /// An assignment to an existing symbol.
    Assignment,
    /// A function call.
    Call,
    /// A deferred sink via a declared function or defined function literal.
    Function,
    /// A send statement.
    Send,
}
