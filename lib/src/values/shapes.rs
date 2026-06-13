use std::{borrow::Cow, iter};

use parser::Location;

use crate::{
    Pinned,
    labels::{Label, LabelBacktrace, LabelBacktraceKind, SyntheticSlot},
    snapshots::SnapshotAware,
    values::{
        BacktraceContainer, Mergeable, MobiusValue, PackageRefValue, SelfAwareBacktraceContainer,
        SimpleConstValue,
        composite::CompositeValue,
        expandable::ExpandableValue,
        functions::{FunctionRef, FunctionValue},
    },
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Value<'a> {
    Simple(Option<LabelBacktrace<'a>>),
    // ^^^ a Value::Simple might be automatically coerced into one of the more
    // complex shapes below when used (or it might always just be Simple)
    Expandable(ExpandableValue<'a>),
    Mobius(MobiusValue<'a>),
    PackageRef(PackageRefValue<'a>),
    Array(CompositeValue<'a, u64>),
    Slice(CompositeValue<'a, u64>),
    Map(CompositeValue<'a, SimpleConstValue>),
    Struct(CompositeValue<'a, String>),
    Function(Box<FunctionValue<'a>>),
}

impl<'a> Value<'a> {
    pub(super) fn is_copy_by_reference(&self) -> bool {
        // https://go.dev/ref/spec#Representation_of_values
        matches!(self, Self::Slice(..) | Self::Function { .. })
    }

    fn sub_container(&self) -> &dyn BacktraceContainer<'a> {
        match self {
            Self::Simple(opt) => opt,
            Self::Expandable(exp) => exp,
            Self::Mobius(mobius) => mobius,
            Self::PackageRef(pkg) => pkg,
            Self::Array(composite) | Self::Slice(composite) => composite,
            Self::Map(composite) => composite,
            Self::Struct(composite) => composite,
            Self::Function(func) => &**func,
        }
    }

    fn sub_container_mut(&mut self) -> &mut dyn BacktraceContainer<'a> {
        match self {
            Self::Simple(opt) => opt,
            Self::Expandable(exp) => exp,
            Self::Mobius(mobius) => mobius,
            Self::PackageRef(pkg) => pkg,
            Self::Array(composite) | Self::Slice(composite) => composite,
            Self::Map(composite) => composite,
            Self::Struct(composite) => composite,
            Self::Function(func) => &mut **func,
        }
    }
}

impl<'a> BacktraceContainer<'a> for Value<'a> {
    fn backtrace_at_location(&self, location: Pinned<'a, Location>) -> Option<LabelBacktrace<'a>> {
        self.sub_container().backtrace_at_location(location)
    }

    fn is_bottom(&self) -> bool {
        self.sub_container().is_bottom()
    }

    fn allows_lossless_downgrade(&self) -> bool {
        self.sub_container().allows_lossless_downgrade()
    }

    fn subtract_label(&mut self, subtract: &Label<'a>) {
        self.sub_container_mut().subtract_label(subtract);
    }
}

impl<'a> SelfAwareBacktraceContainer<'a> for Value<'a> {
    // would prefer using `self.sub_container().method(...)`, but this trait
    // isn't dyn-compatible, so we must use a macro instead

    fn realize(
        &self,
        from_func: &FunctionRef<'a>,
        from_slot: SyntheticSlot,
        concrete: Option<&LabelBacktrace<'a>>,
    ) -> Self {
        macro_rules! recurs {
            ($sub:expr) => {
                $sub.realize(from_func, from_slot, concrete)
            };
        }

        match self {
            Self::Simple(bt) => Self::Simple(recurs!(bt)),
            Self::Expandable(exp) => Self::Expandable(recurs!(exp)),
            Self::Mobius(mobius) => Self::Mobius(recurs!(mobius)),
            Self::PackageRef(pkg) => Self::PackageRef(recurs!(pkg)),
            Self::Array(composite) => Self::Array(recurs!(composite)),
            Self::Slice(composite) => Self::Slice(recurs!(composite)),
            Self::Map(composite) => Self::Map(recurs!(composite)),
            Self::Struct(composite) => Self::Struct(recurs!(composite)),
            Self::Function(func) => Self::Function(Box::new(recurs!(&**func))),
        }
    }

    fn nest_backtrace(
        &self,
        parent_kind: LabelBacktraceKind,
        parent_symbol: Option<&'a str>,
        parent_location: Pinned<'a, Location>,
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
            Self::Mobius(mobius) => Self::Mobius(recurs!(mobius)),
            Self::PackageRef(pkg) => Self::PackageRef(recurs!(pkg)),
            Self::Array(composite) => Self::Array(recurs!(composite)),
            Self::Slice(composite) => Self::Slice(recurs!(composite)),
            Self::Map(composite) => Self::Map(recurs!(composite)),
            Self::Struct(composite) => Self::Struct(recurs!(composite)),
            Self::Function(func) => Self::Function(Box::new(recurs!(&**func))),
        }
    }
}

impl<'a> Mergeable<'a> for Value<'a> {
    fn merge_with(
        &self,
        other: &Self,
        with_kind: LabelBacktraceKind,
        at_location: Cow<Pinned<'a, Location>>,
    ) -> Self {
        macro_rules! recurs {
            ($a:expr, $b:expr) => {
                $a.merge_with($b, with_kind, at_location)
            };
        }

        match (self, other) {
            (Self::Simple(a), Self::Simple(b)) => Self::Simple(recurs!(a, b)),
            (Self::Expandable(a), Self::Expandable(b)) => Self::Expandable(recurs!(a, b)),
            (Self::Mobius(a), Self::Mobius(b)) => Self::Mobius(recurs!(a, b)),
            (Self::PackageRef(_), Self::PackageRef(_)) => Self::Simple(None),
            (Self::Array(a), Self::Array(b)) => Self::Array(recurs!(a, b)),
            (Self::Slice(a), Self::Slice(b)) => Self::Slice(recurs!(a, b)),
            (Self::Map(a), Self::Map(b)) => Self::Map(recurs!(a, b)),
            (Self::Struct(a), Self::Struct(b)) => Self::Struct(recurs!(a, b)),
            // intentionally not handling (Fn, Fn)
            // ---
            (Self::Simple(None), other) | (other, Self::Simple(None)) => other.clone(),
            (Self::Simple(Some(bt)), other) | (other, Self::Simple(Some(bt))) => other
                .nest_backtrace(
                    with_kind,
                    None,
                    at_location.into_owned(),
                    iter::once(bt.clone()),
                ),

            // no wildcard _ so we rely on exhaustiveness for maintainability
            // (compiler will error if a new variant is added and this method
            // is not updated to reflect that)
            (
                Self::Expandable(_)
                | Self::Mobius(_)
                | Self::PackageRef(_)
                | Self::Array(_)
                | Self::Slice(_)
                | Self::Map(_)
                | Self::Struct(_)
                | Self::Function(_),
                _,
            ) => {
                let location = at_location.clone().into_owned();
                let a = self.backtrace_at_location(location.clone());
                let b = other.backtrace_at_location(location);

                Self::Simple(recurs!(a, &b))
            }
        }
    }
}

impl SnapshotAware for Value<'_> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Simple(a), Self::Simple(b)) => a.snapshot_aware_eq(b),
            (Self::Expandable(a), Self::Expandable(b)) => a.snapshot_aware_eq(b),
            (Self::Mobius(a), Self::Mobius(b)) => a.snapshot_aware_eq(b),
            (Self::PackageRef(a), Self::PackageRef(b)) => a.snapshot_aware_eq(b),
            (Self::Array(a), Self::Array(b)) | (Self::Slice(a), Self::Slice(b)) => {
                a.snapshot_aware_eq(b)
            }
            (Self::Map(a), Self::Map(b)) => a.snapshot_aware_eq(b),
            (Self::Struct(a), Self::Struct(b)) => a.snapshot_aware_eq(b),
            (Self::Function(a), Self::Function(b)) => a.snapshot_aware_eq(b),

            // no wildcard _ so we rely on exhaustiveness for maintainability
            // (compiler will error if a new variant is added and this method
            // is not updated to reflect that)
            (
                Self::Simple(_)
                | Self::Expandable(_)
                | Self::Mobius(_)
                | Self::PackageRef(_)
                | Self::Array(_)
                | Self::Slice(_)
                | Self::Map(_)
                | Self::Struct(_)
                | Self::Function(_),
                _,
            ) => false,
        }
    }
}
