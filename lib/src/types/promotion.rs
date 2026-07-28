use std::rc::Rc;

use crate::{
    symbols::SymbolRef,
    types::{StructFieldInfo, TypeInfo, TypeKind},
};

#[derive(Debug, Clone)]
pub struct PromotedField<'a> {
    // the type through which the field was found at the matching depth
    owner: Rc<TypeInfo<'a>>,
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

    // only the *shallowest* depth at which `name` is found contributes, and
    // that depth must contribute exactly one candidate

    // we search all embedding paths one depth at a time; `frontier` keeps each
    // active path, in the form `(current_entry, ascendants_path)`
    let mut frontier = vec![(Rc::clone(root), vec![Rc::as_ptr(root)])];

    loop {
        let mut found = None;
        let mut next_frontier = Vec::new();

        for (current, path) in frontier {
            let Some(fields) = current.underlying_struct_fields() else {
                continue;
            };

            for field in fields.values() {
                if !field.is_embedded() {
                    // we only care about embedded fields
                    continue;
                }

                let Some(field_type) = field.resolved_type() else {
                    // skip unresolved types (e.g., not known yet)
                    continue;
                };

                if matches!(field_type.underlying(), Some(TypeKind::Interface)) {
                    // embedded interfaces are resolved by dynamic dispatch,
                    // which is not modeled here, so skip them
                    continue;
                }

                let type_identity = Rc::as_ptr(&field_type);
                if path.contains(&type_identity) {
                    // this type already occurs in the current embedding path,
                    // so descending further would repeat an embedding cycle
                    continue;
                }

                if let Some(candidate) = probe.probe(&field_type, name) {
                    if found.is_some() {
                        // exactly one occurrence must exist at the shallowest
                        // depth, even if both paths reach the same declaration
                        return None;
                    }
                    found = Some(candidate);
                } else {
                    let mut child_path = path.clone();
                    child_path.push(type_identity);

                    next_frontier.push((field_type, child_path));
                }
            }
        }

        if found.is_some() || next_frontier.is_empty() {
            return found;
        }

        frontier = next_frontier;
    }
}

trait PromotionProbe<'a> {
    type Candidate;

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
        let fields = r#type.underlying_struct_fields()?;

        // find the `&'a str` key so the returned `PromotedField` can borrow it
        // with the same lifetime as everything else on the type registry
        let (&key, _) = fields.get_key_value(name)?;

        Some(PromotedField {
            owner: Rc::clone(r#type),
            name: key,
        })
    }
}
