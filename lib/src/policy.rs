//! Module for security policy definition and manipulation.
//!
//! Glowy implements enforcement checks that validate a value's propagated taint
//! against a defined security policy, configured in several different ways for
//! the consumer's convenience. This module contains several necessary types and
//! functionality to allow representing (parts of) such a policy.

use std::collections::HashMap;

use parser::Location;

use crate::{
    labels::{Label, OwnedLabel, OwnedLabelCow},
    snapshots::SnapshotAware,
};

/// Structured information representing a declared sink.
///
/// This is a lightweight descriptor capturing the essential details of an
/// information flow sink as declared by the security policy in effect.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SinkDescriptor<'a> {
    /// The type of sink in question.
    pub kind: SinkKind,
    /// Whether this is a confidentiality sink (allow), vs. integrity (deny).
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

        let label = Label::from_tags(tags);

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
    /// - it is a [subset of](Label::is_subset_of) or it is [equal](Label::eq)
    ///   to this sink's inherent policy label, for confidentiality (allow)
    ///   sinks --- whitelist enforcement;
    /// - its [intersection](Label::intersect) with this sink's inherent policy
    ///   label is exactly [`Label::Bottom`], for integrity (deny) sinks ---
    ///   blacklist enforcement.
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
            // confidentiality sink (allow - whitelist)
            *label <= self.label
        } else {
            // integrity sink (deny - blacklist)
            label.intersect(&self.label).is_bottom()
        }
    }
}

impl SnapshotAware for SinkDescriptor<'_> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        self == other
    }
}

/// Represents a specific type of information flow sinks.
///
/// This is useful to know, for example, to provide more personalized error
/// messages when a sink's information flow invariant is violated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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

/// The map's key is a function path (e.g., `os.Remove` or
/// `example.com/company-name/proj/sub-package.funcName`).
pub(crate) type BlanketDirectives = HashMap<String, Vec<BlanketDirective>>;

#[derive(Clone, Debug)]
pub(crate) struct BlanketDirective {
    kind: BlanketDirectiveKind,
    label: OwnedLabel,
}

impl BlanketDirective {
    pub(crate) fn new<'c1: 'c2, 'c2>(
        kind: BlanketDirectiveKind,
        label: impl Into<OwnedLabelCow<'c1, 'c2>>,
    ) -> Self {
        Self {
            kind,
            label: label.into().into_owned(),
        }
    }

    pub fn kind(&self) -> BlanketDirectiveKind {
        self.kind
    }

    pub fn label(&self) -> Label<'_> {
        self.label.as_label()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum BlanketDirectiveKind {
    Source,
    AllowSink,
    DenySink,
}
