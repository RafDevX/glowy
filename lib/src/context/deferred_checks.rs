use std::path::Path;

use parser::Location;

use crate::{
    Pinned,
    labels::{Label, LabelBacktrace, LabelBacktraceKind},
    policy::SinkDescriptor,
    snapshots::SnapshotAware,
    values::{self, SelfAwareBacktraceContainer},
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DeferredEnforcementCheck<'a> {
    Sink {
        sink: SinkDescriptor<'a>,
        found: LabelBacktrace<'a>,
        file: &'a Path, // cannot use Pinned since lifetimes are important
    },
    Assertion {
        expected_sequence: Vec<Label<'a>>,
        found: Option<LabelBacktrace<'a>>,
        file: &'a Path, // cannot use Pinned since lifetimes are important
        location: Location,
    },
}

impl<'a> DeferredEnforcementCheck<'a> {
    /// Merges another observation of the same source-level enforcement check.
    ///
    /// Recursive call graphs can propagate the same deferred check through
    /// several paths and convergence iterations. Keeping one entry per check
    /// identity prevents combinatorial growth, while union'ing its backtraces
    /// preserves every observed label. Alternative provenance which adds no
    /// label is intentionally discarded because it cannot affect enforcement.
    pub fn merge_if_same_site(&mut self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Sink { sink, found, file },
                Self::Sink {
                    sink: other_sink,
                    found: other_found,
                    file: other_file,
                },
            ) if sink == other_sink && file == other_file => {
                if other_found.label().is_subset_of(found.label()) {
                    // no need to union, since found >= other_found:
                    // (a) for allow sinks, a whitelist that allows found would
                    //     also necessarily allow a smaller other_found
                    // (b) for deny sinks, a blacklist that does not disallow
                    //     found would also necessarily not disallow a smaller
                    //     other_found
                    // thus, in either case, we can discard other_found in favor
                    // of just keeping found
                } else {
                    *found = found.union(
                        other_found,
                        LabelBacktraceKind::EnforcementAggregation,
                        Pinned::new(*file, sink.location.clone()),
                    );
                }

                true
            }
            (
                Self::Assertion {
                    expected_sequence,
                    found,
                    file,
                    location,
                },
                Self::Assertion {
                    expected_sequence: other_expected,
                    found: other_found,
                    file: other_file,
                    location: other_location,
                },
            ) if expected_sequence == other_expected
                && file == other_file
                && location == other_location
                && found.as_ref().map(LabelBacktrace::label)
                    == other_found.as_ref().map(LabelBacktrace::label) =>
            {
                // assertions are equality based and thus only be merged if
                // their labels match exactly, but should still be merged
                // regardless of provenance information (= backtrace children)
                // to prevent uncontrolled growth that results in extreme
                // inefficiencies for e.g. mutually recursive functions

                true
            }
            _ => false,
        }
    }

    // might return None if a sink enforcement check no longer makes sense
    // (`found` is now Bottom, so the check would always pass)
    pub fn realize_unified<'b>(
        &self,
        unified: &mut values::UnifiedRealization<'a, 'b>,
    ) -> Option<Self> {
        let realized = match self {
            Self::Sink { sink, found, file } => Self::Sink {
                sink: sink.clone(),
                found: unified.dispatch(found)?,
                file,
            },
            Self::Assertion {
                expected_sequence,
                found,
                file,
                location,
            } => Self::Assertion {
                expected_sequence: expected_sequence.clone(),
                found: found.realize_unified(unified),
                file,
                location: location.clone(),
            },
        };

        Some(realized)
    }
}

impl SnapshotAware for DeferredEnforcementCheck<'_> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        match (self, other) {
            #[expect(clippy::suspicious_operation_groupings, reason = "False positive")]
            (
                Self::Sink {
                    sink: sink_a,
                    found: found_a,
                    file: file_a,
                },
                Self::Sink {
                    sink: sink_b,
                    found: found_b,
                    file: file_b,
                },
            ) => {
                sink_a.snapshot_aware_eq(sink_b)
                    && found_a.snapshot_aware_eq(found_b)
                    && file_a == file_b
            }
            (
                Self::Assertion {
                    expected_sequence: expected_sequence_a,
                    found: found_a,
                    file: file_a,
                    location: location_a,
                },
                Self::Assertion {
                    expected_sequence: expected_sequence_b,
                    found: found_b,
                    file: file_b,
                    location: location_b,
                },
            ) => {
                expected_sequence_a == expected_sequence_b
                    && found_a.snapshot_aware_eq(found_b)
                    && file_a == file_b
                    && location_a == location_b
            }

            // no wildcard _ so we rely on exhaustiveness for maintainability
            // (compiler will error if a new variant is added and this method
            // is not updated to reflect that)
            (Self::Sink { .. } | Self::Assertion { .. }, _) => false,
        }
    }
}
