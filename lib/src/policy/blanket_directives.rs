use std::collections::{BTreeSet, HashMap};

use crate::{FullPackagePath, labels::Label, policy::targets::BlanketSourceArgPredicate};

pub type BlanketDirectives = HashMap<FullPackagePath, PackageBlanketDirectives>;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PackageBlanketDirectives {
    // top-level package symbols: functions (`os.GetEnv`) & bindings (`os.Args`)
    pub symbols: HashMap<String, Vec<BlanketDirective>>,
    // type-associated members: methods (`DB.Query`) & fields (`Request.Body`)
    pub type_members: HashMap<String, HashMap<String, Vec<BlanketDirective>>>,
}

impl PackageBlanketDirectives {
    pub fn get(&self, type_name: Option<&str>, member_name: &str) -> Option<&[BlanketDirective]> {
        match type_name {
            None => self.symbols.get(member_name).map(Vec::as_slice),
            Some(type_name) => self
                .type_members
                .get(type_name)
                .and_then(|inner| inner.get(member_name))
                .map(Vec::as_slice),
        }
    }

    pub fn push(
        &mut self,
        type_name: Option<String>,
        member_name: String,
        directive: BlanketDirective,
    ) {
        let entry = match type_name {
            None => self.symbols.entry(member_name).or_default(),
            Some(type_name) => self
                .type_members
                .entry(type_name)
                .or_default()
                .entry(member_name)
                .or_default(),
        };

        entry.push(directive);
    }

    pub fn iter(&self) -> impl Iterator<Item = &BlanketDirective> {
        self.symbols.values().flatten().chain(
            self.type_members
                .values()
                .flat_map(HashMap::values)
                .flatten(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlanketDirective {
    kind: BlanketDirectiveKind,
    label: Label<'static>,
    result_selector: BTreeSet<usize>,
    arg_index: Option<usize>,
    arg_predicate: Option<BlanketSourceArgPredicate>,
}

impl BlanketDirective {
    pub(crate) fn new(
        kind: BlanketDirectiveKind,
        result_selector: BTreeSet<usize>,
        arg_index: Option<usize>,
        arg_predicate: Option<BlanketSourceArgPredicate>,
        mut label: Label<'static>,
    ) -> Self {
        let (arg_index, arg_predicate, result_selector) = match kind {
            // non-sinks don't have a meaningful notion of "this arg only"
            BlanketDirectiveKind::Source | BlanketDirectiveKind::Revocation => {
                (None, arg_predicate, result_selector)
            }
            // sinks don't have a meaningful notion of "only when this matches"
            // or of selecting only specific function results
            BlanketDirectiveKind::AllowSink | BlanketDirectiveKind::DenySink => {
                (arg_index, None, BTreeSet::new())
            }
        };

        if kind.accepts_wildcards() {
            label.accept_wildcards();
        }

        Self {
            kind,
            label,
            result_selector,
            arg_index,
            arg_predicate,
        }
    }

    pub fn kind(&self) -> BlanketDirectiveKind {
        self.kind
    }

    pub fn label(&self) -> &Label<'_> {
        &self.label
    }

    pub fn result_selector(&self) -> &BTreeSet<usize> {
        &self.result_selector
    }

    pub fn arg_index(&self) -> Option<usize> {
        self.arg_index
    }

    pub fn arg_predicate(&self) -> Option<&BlanketSourceArgPredicate> {
        self.arg_predicate.as_ref()
    }

    pub fn should_resolve_at_call_time(&self) -> bool {
        self.arg_predicate().is_some() || !self.result_selector().is_empty()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlanketDirectiveKind {
    Source,
    Revocation,
    AllowSink,
    DenySink,
}

impl BlanketDirectiveKind {
    pub fn accepts_wildcards(self) -> bool {
        match self {
            Self::Source => false,
            Self::Revocation | Self::AllowSink | Self::DenySink => true,
        }
    }
}
