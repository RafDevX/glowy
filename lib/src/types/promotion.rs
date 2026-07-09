use std::{collections::HashSet, iter, ops, rc::Rc};

use crate::{
    symbols::SymbolRef,
    types::{StructFieldInfo, TypeInfo, TypeKind},
};

#[derive(Debug, Clone)]
pub struct PromotedField<'a> {
    owner: Rc<TypeInfo<'a>>, // where the field is directly declared
    name: &'a str,
}

impl<'a> PromotedField<'a> {
    pub fn owner(&self) -> &Rc<TypeInfo<'a>> {
        &self.owner
    }

    pub fn name(&self) -> &'a str {
        self.name
    }

    pub fn field_info(&self) -> &StructFieldInfo<'a> {
        self.owner
            .get_field(self.name)
            .expect("promoted field must exist in owner (established at lookup time)")
    }
}

pub fn lookup_promoted_field<'a>(name: &str, root: &Rc<TypeInfo<'a>>) -> Option<PromotedField<'a>> {
    lookup_promoted(name, root, &FieldProbe)
}

pub fn lookup_promoted_method<'a>(name: &str, root: &Rc<TypeInfo<'a>>) -> Option<SymbolRef<'a>> {
    lookup_promoted(name, root, &MethodProbe)
}

fn lookup_promoted<'a, P: PromotionProbe<'a>>(
    name: &str,
    root: &Rc<TypeInfo<'a>>,
    probe: &P,
) -> Option<P::Candidate> {
    if let Some(direct) = probe.probe(root, name) {
        // direct declarations shadow every embedded candidate
        return Some(direct);
    }

    let mut visited = HashSet::from([Rc::as_ptr(root)]);

    match search_subtree(name, root, &mut visited, probe) {
        PromotionFrontier::Unique(candidate) => Some(candidate),
        PromotionFrontier::None | PromotionFrontier::Ambiguous => None,
    }
}

fn search_subtree<'a, P: PromotionProbe<'a>>(
    name: &str,
    root: &Rc<TypeInfo<'a>>,
    visited: &mut HashSet<*const TypeInfo<'a>>,
    probe: &P,
) -> PromotionFrontier<P::Candidate> {
    // only the *shallowest* depth at which `name` is found contributes, and
    // that depth must contribute exactly one candidate (multiple paths
    // converging on the same underlying candidate are still treated as one,
    // as the spec specifies "unambiguous")

    // embedded interfaces are skipped: their members are resolved by
    // dynamic dispatch, which we don't model

    let Some(TypeKind::Struct { fields }) = root.underlying() else {
        return PromotionFrontier::None;
    };

    // first pass: collect matches at the immediate next depth -- per the
    // spec, shallowest wins, so we must finish *this* level before
    // recursing into anything deeper (breadth-first search)

    let mut at_this_depth = PromotionFrontier::None;
    let mut descend_into = Vec::new();

    for field in fields.values() {
        if !field.is_embedded() {
            // we only care about embedded fields
            continue;
        }

        let Some(field_type) = field.resolved_type() else {
            // skip unresolved type (e.g., not known yet)
            continue;
        };

        if matches!(field_type.underlying(), Some(TypeKind::Interface)) {
            // skip embedded interfaces (unsupported)
            continue;
        }

        if !visited.insert(Rc::as_ptr(&field_type)) {
            // skip already visited

            // note that this is necessary to ensure termination, since type
            // graphs are not required to be acyclic, since Go allows for
            // pointer-cycle embeds (e.g., `A { *B }` + `B { *A }`)
            continue;
        }

        match probe.probe(&field_type, name) {
            Some(candidate) => {
                at_this_depth = at_this_depth + PromotionFrontier::Unique(candidate);
            }
            None => descend_into.push(field_type),
        }
    }

    if !matches!(at_this_depth, PromotionFrontier::None) {
        // shallowest-wins: a hit at this depth shadows any deeper match
        return at_this_depth;
    }

    // second pass: nothing at this depth, so recurse uniformly

    // merging across siblings captures the case where two non-overlapping
    // subtrees both produce a (possibly distinct) match at the same deeper
    // depth, which Go treats as ambiguous
    descend_into
        .into_iter()
        .map(|child| search_subtree(name, &child, visited, probe))
        .sum()
}

enum PromotionFrontier<T: PromotionCandidate> {
    None,
    Unique(T), // at same depth
    Ambiguous,
}

impl<T: PromotionCandidate> ops::Add for PromotionFrontier<T> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Self::None, single) | (single, Self::None) => single,
            (Self::Unique(left), Self::Unique(right)) if left.is_same_candidate(&right) => {
                Self::Unique(left)
            }
            _ => Self::Ambiguous,
        }
    }
}

impl<T: PromotionCandidate> iter::Sum for PromotionFrontier<T> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::None, |a, b| a + b)
    }
}

trait PromotionProbe<'a> {
    type Candidate: PromotionCandidate;

    fn probe(&self, r#type: &Rc<TypeInfo<'a>>, name: &str) -> Option<Self::Candidate>;
}

struct MethodProbe;

impl<'a> PromotionProbe<'a> for MethodProbe {
    type Candidate = SymbolRef<'a>;

    fn probe(&self, r#type: &Rc<TypeInfo<'a>>, name: &str) -> Option<Self::Candidate> {
        r#type.get_method(name)
    }
}

struct FieldProbe;

impl<'a> PromotionProbe<'a> for FieldProbe {
    type Candidate = PromotedField<'a>;

    fn probe(&self, r#type: &Rc<TypeInfo<'a>>, name: &str) -> Option<Self::Candidate> {
        let TypeKind::Struct { fields } = r#type.strip_pointers().underlying()? else {
            return None;
        };

        // find the `&'a str` key so the returned `PromotedField` can borrow it
        // with the same lifetime as everything else on the type registry
        let (&key, _) = fields.get_key_value(name)?;

        Some(PromotedField {
            owner: Rc::clone(r#type),
            name: key,
        })
    }
}

trait PromotionCandidate: Sized {
    fn is_same_candidate(&self, other: &Self) -> bool;
}

impl PromotionCandidate for SymbolRef<'_> {
    fn is_same_candidate(&self, other: &Self) -> bool {
        Rc::ptr_eq(self, other)
    }
}

impl PromotionCandidate for PromotedField<'_> {
    fn is_same_candidate(&self, other: &Self) -> bool {
        // fields are identified by their declaring `TypeInfo` and their name;
        // since a search always fixes `name`, only the owner needs comparing
        Rc::ptr_eq(&self.owner, &other.owner)
    }
}
