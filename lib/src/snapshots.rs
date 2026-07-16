use std::{
    collections::{BTreeMap, HashMap},
    hash,
    rc::Rc,
};

use crate::{
    labels::LabelBacktrace,
    values::{SimpleConstValue, ValueRef},
};

/// Annotation that an inner value MAY NOT be used for internal mutability.
///
/// This is a wrapper type with no behavior, used exclusively to clearly signal
/// the semantic invariant that the contained data should not be directly
/// mutated, as otherwise it would break a logical assumption.
pub struct AssumedImmutable<T>(T);

impl<T> AssumedImmutable<T> {
    /// Construct a new instance.
    pub fn new(inner: T) -> Self {
        Self(inner)
    }

    /// Accept the imposed conditions and access the inner value.
    pub fn get(self) -> T {
        self.0
    }
}

/// Opaque type capturing relevant [`SymbolTable`] details at a point in time.
#[derive(PartialEq, Eq, Debug)]
pub struct SymbolTableSnapshot<'a>(Vec<SymbolTableSnapshotItem<'a>>);

impl<'a> From<Vec<SymbolTableSnapshotItem<'a>>> for SymbolTableSnapshot<'a> {
    fn from(items: Vec<SymbolTableSnapshotItem<'a>>) -> Self {
        Self(items)
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct SymbolTableSnapshotItem<'a> {
    namespace: Rc<str>,
    path: Vec<usize>, // reversed for more efficient building
    name: &'a str,
    mutable: bool,
    value: SnapshotAwareGuard<ValueRef<'a>>,
    known_const: Option<SimpleConstValue>,
}

impl<'a> SymbolTableSnapshotItem<'a> {
    pub fn new(
        namespace: Rc<str>,
        name: &'a str,
        mutable: bool,
        value: ValueRef<'a>,
        known_const: Option<SimpleConstValue>,
    ) -> Self {
        Self {
            namespace,
            path: Vec::new(),
            name,
            mutable,
            value: SnapshotAwareGuard(value),
            known_const,
        }
    }

    pub fn push_to_path(&mut self, index: usize) {
        self.path.push(index);
    }
}

/// Represents a barrier at which normal comparison is snapshot-aware.
///
/// An instance of this type wraps an inner [`SnapshotAware`]-implementing value
/// and establishes a semantic relationship that any equality checks (per the
/// [`PartialEq`] and [`Eq`] traits) should disregard any differences irrelevant
/// for snapshot comparison.
///
/// This makes it possible for higher-level invokers to use standard comparison
/// constructs (such as the `==` operator) without worrying about specific
/// implementation details native to the snapshot logic, thereby simplifying
/// snapshot processing and manipulation.
#[derive(Debug)]
struct SnapshotAwareGuard<T: SnapshotAware>(T);

impl<T: SnapshotAware> PartialEq for SnapshotAwareGuard<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0.snapshot_aware_eq(&other.0)
    }
}

impl<T: SnapshotAware> Eq for SnapshotAwareGuard<T> {}

/// Alternative comparison considering only snapshot-relevant details.
///
/// This trait (and its only trait item) should be construed as working
/// similarly to [`PartialEq::eq`], but with the special consideration that two
/// instances should be considered equal (i.e., method calls should return
/// `true`) in all cases where any distinctions are irrelevant for snapshot
/// comparison. A relationship similar to [`Eq`] is also implied, in the same
/// terms.
///
/// Notably, the implementation should exhibit behavior different from normal
/// comparison with regard to the direct or indirect comparison of any
/// [`LabelBacktrace`]. The simplest way to achieve this is to propagate calls
/// until the backtrace's implementation of this trait is eventually reached,
/// deferring to normal `==` comparison for other unrelated types that do not
/// contain a backtrace.
///
/// Note that a benefit of this being a separate trait is that implementing
/// types do not necessarily need to implement [`PartialEq`], and any possible
/// implementations of [`PartialOrd`] / [`Ord`] do not need to be consistent
/// with this implementation.
pub trait SnapshotAware {
    fn snapshot_aware_eq(&self, other: &Self) -> bool;
}

impl SnapshotAware for LabelBacktrace<'_> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        // the whole point of SnapshotAware is we only care about labels;
        // in the future it might be worth considering comparing other fields,
        // but never `children` (avoiding `children` is why we have to do all
        // this, since otherwise it'd lead to an infinite loop)
        self.label() == other.label()
    }
}

// utility blanket impls for common types

impl<T: SnapshotAware> SnapshotAware for &T {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        (*self).snapshot_aware_eq(*other)
    }
}

impl<T: SnapshotAware> SnapshotAware for Option<T> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Some(a), Some(b)) => a.snapshot_aware_eq(b),
            (None, None) => true,
            _ => false,
        }
    }
}

impl<T: SnapshotAware, U: SnapshotAware> SnapshotAware for (T, U) {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        self.0.snapshot_aware_eq(&other.0) && self.1.snapshot_aware_eq(&other.1)
    }
}

impl<T: SnapshotAware> SnapshotAware for Vec<T> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }

        self.iter()
            .zip(other.iter())
            .all(|(a, b)| a.snapshot_aware_eq(b))
    }
}

impl<K: Eq + hash::Hash, V: SnapshotAware> SnapshotAware for HashMap<K, V> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        self.len() == other.len()
            && self
                .iter()
                .all(|(key, value)| other.get(key).snapshot_aware_eq(&Some(value)))
    }
}

impl<K: Eq, V: SnapshotAware> SnapshotAware for BTreeMap<K, V> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        self.len() == other.len()
            && self.iter().zip(other.iter()).all(
                |((left_key, left_value), (right_key, right_value))| {
                    left_key == right_key && left_value.snapshot_aware_eq(right_value)
                },
            )
    }
}

// trivial implementations for some basic types
// (cannot have a blanket impl for T: Copy because &refs are Copy too)

macro_rules! impl_trivial_snapshot_aware {
    ($($type:ty),* $(,)?) => {
        $(impl SnapshotAware for $type {
            fn snapshot_aware_eq(&self, other: &Self) -> bool {
                self == other
            }
        })*
    };
}

impl_trivial_snapshot_aware!(
    u8, u16, u32, u64, u128, usize, // unsigned
    i8, i16, i32, i64, i128, isize, // signed
    f32, f64, bool, char, // others
);
