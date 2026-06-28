//! Static type-identity registry and the named-type metadata it stores.
//!
//! [`TypeInfo`] records the lightweight static identity of a Go defined type
//! (named type); [`TypeRegistry`] owns these per-package and is the public
//! entry point for type registration, lookup, and resolution. The registry is
//! later consumed during analysis to drive more fine-tuned, type-aware method
//! dispatch without growing a full type-checker.
//!
//! Importantly, we perform only very simple type propagation, following a "best
//! effort" approach: this is not supposed to guarantee full type checking, as
//! Go's compiler already does that, and we assume analyzed input compiles.
//!
//! Each named type allocates a single [`TypeInfo`] (shared via [`Rc`]); aliases
//! reuse the same [`Rc`] as their target, mirroring Go's spec (an alias is the
//! same type as its target). Identity comparison is therefore cheap (uses
//! [`Rc::ptr_eq`]).

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    fmt, mem,
    rc::Rc,
};

use parser::ast::{FieldDeclNode, TypeNameNode, TypeNode};

use crate::{
    FullPackagePath,
    symbols::{FileImportsRecord, SymbolRef, SymbolTable},
};

/// Identity and metadata of a Go defined type (named type).
///
/// Allocated once per `(package, name)` and shared via [`Rc`] from every
/// declared-type slot that references it. Identity is the wrapping [`Rc`]
/// (via [`Rc::ptr_eq`]).
///
/// Aliases (`type T = X`) do not allocate a separate [`TypeInfo`]: the alias
/// name maps to the same [`Rc`] as its target, matching Go's spec semantics.
pub struct TypeInfo<'a> {
    package: FullPackagePath,
    name: &'a str,
    underlying: TypeKind<'a>,
    // note that this is just an alternative index to what is already stored in
    // the respective package envelope, so both SymbolRefs point to the exact
    // same Symbol (these are merely two alternative lookup strategies)
    methods: RefCell<HashMap<&'a str, SymbolRef<'a>>>,
}

impl<'a> TypeInfo<'a> {
    fn new(package: FullPackagePath, name: &'a str, underlying: TypeKind<'a>) -> Self {
        Self {
            package,
            name,
            underlying,
            methods: RefCell::new(HashMap::new()),
        }
    }

    pub fn package(&self) -> &FullPackagePath {
        &self.package
    }

    pub fn name(&self) -> &'a str {
        self.name
    }

    pub fn underlying(&self) -> &TypeKind<'a> {
        &self.underlying
    }

    pub fn get_method(&self, name: &str) -> Option<SymbolRef<'a>> {
        self.methods.borrow().get(name).cloned()
    }

    pub fn register_method(&self, name: &'a str, symbol: SymbolRef<'a>) -> Option<SymbolRef<'a>> {
        self.methods.borrow_mut().insert(name, symbol)
    }
}

impl PartialEq for TypeInfo<'_> {
    fn eq(&self, other: &Self) -> bool {
        // identity of a defined type is its (package, name); the methods set is
        // mutated post-construction but does not contribute to type identity
        self.package == other.package && self.name == other.name
    }
}

impl Eq for TypeInfo<'_> {}

impl fmt::Debug for TypeInfo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[expect(
            clippy::unneeded_field_pattern,
            reason = "Force revisiting this implementation if a field is added"
        )]
        let Self {
            package,
            name,
            underlying,
            methods: _,
        } = self;

        f.debug_struct("TypeInfo")
            .field("package", package)
            .field("name", name)
            .field("underlying", underlying)
            // intentionally omitting `methods` to avoid borrowing the RefCell,
            // since callers might already hold a borrow
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum TypeKind<'a> {
    // built-in types (`int`, `string`, ...), defined-type chain
    // (`type Wrapper Other`), or otherwise anything opaque to analysis
    Opaque,
    Struct { fields: Vec<FieldInfo<'a>> },
    Map,
    Slice,
    Array,
    Channel,
    Interface, // no extra info stored: interface dispatch is not modeled
    Function,
    Pointer(Rc<TypeInfo<'a>>),
}

#[derive(Debug)]
pub struct FieldInfo<'a> {
    name: &'a str,
    // we need interior mutability (via RefCell) since sometimes a field's
    // declared type may live in a sibling file or another package not yet seen
    // at the this struct's type declaration is first found
    r#type: RefCell<Option<Rc<TypeInfo<'a>>>>,
    embedded: bool,
    declared_type_node: TypeNode<'a>,
}

impl<'a> FieldInfo<'a> {
    pub fn new(
        name: &'a str,
        r#type: Option<Rc<TypeInfo<'a>>>,
        declared_type_node: TypeNode<'a>,
        embedded: bool,
    ) -> Self {
        Self {
            name,
            r#type: RefCell::new(r#type),
            embedded,
            declared_type_node,
        }
    }

    pub fn name(&self) -> &'a str {
        self.name
    }

    pub fn resolved_type(&self) -> Option<Rc<TypeInfo<'a>>> {
        self.r#type.borrow().clone()
    }

    pub fn is_resolved(&self) -> bool {
        self.r#type.borrow().is_some()
    }

    pub fn set_resolved_type(&self, r#type: Rc<TypeInfo<'a>>) {
        *self.r#type.borrow_mut() = Some(r#type);
    }

    pub fn is_embedded(&self) -> bool {
        self.embedded
    }

    pub fn declared_type_node(&self) -> &TypeNode<'a> {
        &self.declared_type_node
    }
}

/// Registry of named (defined) Go types.
///
/// Parallels [`SymbolTable`] in scope: [`SymbolTable`] owns scopes and symbols,
/// while [`TypeRegistry`] owns the type-identity index and all related state.
#[derive(Debug)]
pub struct TypeRegistry<'a> {
    /// Currently known defined types.
    ///
    /// Keyed first by declaring package, then by unqualified name. Aliases
    /// (`type T = X`) share their target's [`Rc<TypeInfo>`] entry.
    ///
    /// The two-level nesting (vs. a flat `(String, &str)` key) lets lookups
    /// borrow the package path as `&str` without allocating a temporary
    /// owned key.
    types: HashMap<FullPackagePath, HashMap<&'a str, Rc<TypeInfo<'a>>>>,

    /// Deferred type-registry resolution retries.
    deferred: DeferredQueues<'a>,

    /// Set of every method name observed across the entire analyzed corpus.
    global_method_names: HashSet<&'a str>,

    /// Snapshot of the current file's import state.
    ///
    /// We use an [`Rc`] so that the snapshot can be reused and re-referenced
    /// across multiple locations, without needing to be cloned.
    current_file_imports_snapshot: Option<Rc<FileImportsRecord>>,
}

impl<'a> TypeRegistry<'a> {
    pub fn new() -> Self {
        Self {
            types: HashMap::new(),
            deferred: DeferredQueues::default(),
            global_method_names: HashSet::new(),
            current_file_imports_snapshot: None,
        }
    }

    pub fn declare(
        &mut self,
        symtab: &SymbolTable<'a>,
        package: FullPackagePath,
        name: &'a str,
        underlying: &TypeNode<'a>,
    ) -> Rc<TypeInfo<'a>> {
        let underlying = self.build_kind(symtab, underlying);

        let inner = self.types.entry(package.clone()).or_default();

        if let Some(existing) = inner.get(name) {
            return Rc::clone(existing);
        }

        let info = Rc::new(TypeInfo::new(package, name, underlying));

        inner.insert(name, Rc::clone(&info));

        info
    }

    pub fn declare_alias(
        &mut self,
        symtab: &SymbolTable<'a>,
        package: FullPackagePath,
        name: &'a str,
        target: &TypeNode<'a>,
    ) -> Option<Rc<TypeInfo<'a>>> {
        if let Some(existing) = self.lookup(&package, name) {
            return Some(existing);
        }

        let resolved = self.resolve(symtab, target)?;

        self.types
            .entry(package)
            .or_default()
            .insert(name, Rc::clone(&resolved));

        Some(resolved)
    }

    pub fn lookup(&self, package: &str, name: &str) -> Option<Rc<TypeInfo<'a>>> {
        self.types
            .get(package)
            .and_then(|inner| inner.get(name))
            .map(Rc::clone)
    }

    pub fn resolve_name(
        &self,
        symtab: &SymbolTable<'a>,
        node: &TypeNameNode<'a>,
    ) -> Option<Rc<TypeInfo<'a>>> {
        self.resolve_name_with(
            symtab.current_package_path(),
            symtab.current_file_named_imports(),
            symtab.current_file_wildcard_imports(),
            node,
        )
    }

    fn resolve_name_with(
        &self,
        current_package: Option<&FullPackagePath>,
        named_imports: &HashMap<String, FullPackagePath>,
        wildcard_imports: &[FullPackagePath],
        node: &TypeNameNode<'a>,
    ) -> Option<Rc<TypeInfo<'a>>> {
        if let Some(qualifier) = node.package {
            // qualified name: just do lookup directly

            let path = named_imports.get(qualifier.content())?;

            return self.lookup(path, node.id.content());
        }

        // try checking if type exists in the current package
        if let Some(current) = current_package
            && let Some(info) = self.lookup(current, node.id.content())
        {
            return Some(info);
        }

        if node
            .id
            .content()
            .chars()
            .next()
            .is_some_and(char::is_uppercase)
        {
            // this is an exported name, so we check wildcard imports for the
            // current file to see if the type exists there

            for path in wildcard_imports {
                if let Some(info) = self.lookup(path, node.id.content()) {
                    // if the type exists somewhere, Go spec says we can
                    // disregard all the other wildcard imports, since any
                    // duplicate names would fail to compile (and we assume that
                    // the input under analysis compiles)

                    return Some(info);
                }
            }
        }

        // we didn't find any type with this name, at least for now
        None
    }

    pub fn resolve(
        &self,
        symtab: &SymbolTable<'a>,
        node: &TypeNode<'a>,
    ) -> Option<Rc<TypeInfo<'a>>> {
        self.resolve_with(
            symtab.current_package_path(),
            symtab.current_file_named_imports(),
            symtab.current_file_wildcard_imports(),
            node,
        )
    }

    fn resolve_with(
        &self,
        current_package: Option<&FullPackagePath>,
        named_imports: &HashMap<String, FullPackagePath>,
        wildcard_imports: &[FullPackagePath],
        node: &TypeNode<'a>,
    ) -> Option<Rc<TypeInfo<'a>>> {
        match node {
            TypeNode::Name(name_node) => {
                self.resolve_name_with(current_package, named_imports, wildcard_imports, name_node)
            }
            TypeNode::Pointer { base } => {
                // we consider `T` and `*T` to have the same methods set
                self.resolve_with(current_package, named_imports, wildcard_imports, base)
            }
            // anonymous composites: no addressable method set by name dispatch
            TypeNode::Channel { .. }
            | TypeNode::Array { .. }
            | TypeNode::Slice { .. }
            | TypeNode::Map { .. }
            | TypeNode::Struct { .. }
            | TypeNode::Interface { .. }
            | TypeNode::Function { .. } => None,
        }
    }

    fn build_kind(&self, symtab: &SymbolTable<'a>, node: &TypeNode<'a>) -> TypeKind<'a> {
        match node {
            TypeNode::Name(_) => TypeKind::Opaque,
            TypeNode::Pointer { base } => match self.resolve(symtab, base) {
                Some(info) => TypeKind::Pointer(info),
                None => TypeKind::Opaque,
            },
            TypeNode::Struct { fields } => TypeKind::Struct {
                fields: self.build_struct_fields(symtab, fields),
            },
            TypeNode::Map { .. } => TypeKind::Map,
            TypeNode::Slice { .. } => TypeKind::Slice,
            TypeNode::Array { .. } => TypeKind::Array,
            TypeNode::Channel { .. } => TypeKind::Channel,
            TypeNode::Interface { .. } => TypeKind::Interface,
            TypeNode::Function { .. } => TypeKind::Function,
        }
    }

    fn build_struct_fields(
        &self,
        symtab: &SymbolTable<'a>,
        fields: &[FieldDeclNode<'a>],
    ) -> Vec<FieldInfo<'a>> {
        let mut result = Vec::new();

        for decl in fields {
            match decl {
                FieldDeclNode::Explicit(explicit) => {
                    let resolved = self.resolve(symtab, &explicit.r#type);

                    for id in &explicit.ids {
                        let Some(name) = id else {
                            // blank `_` field; skipped as per Go spec
                            continue;
                        };

                        result.push(FieldInfo::new(
                            name.content(),
                            resolved.clone(),
                            explicit.r#type.clone(),
                            false,
                        ));
                    }
                }
                FieldDeclNode::Embedded(embedded) => {
                    // per Go spec, the unqualified type name is the field name

                    let resolved = self.resolve_name(symtab, &embedded.r#type);

                    result.push(FieldInfo::new(
                        embedded.r#type.id.content(),
                        resolved,
                        TypeNode::Name(embedded.r#type.clone()),
                        true,
                    ));
                }
            }
        }

        result
    }

    pub fn record_method_name(&mut self, name: &'a str) {
        self.global_method_names.insert(name);
    }

    pub fn any_method_named(&self, name: &str) -> bool {
        self.global_method_names.contains(name)
    }

    pub fn queue_pending_alias(
        &mut self,
        symtab: &SymbolTable<'a>,
        package: FullPackagePath,
        name: &'a str,
        target: TypeNode<'a>,
    ) {
        let imports = self.current_file_imports(symtab);

        self.deferred.aliases.push(DeferredAlias {
            package,
            name,
            target,
            imports,
        });
    }

    pub fn queue_pending_method(
        &mut self,
        package: FullPackagePath,
        receiver_type_name: &'a str,
        method_name: &'a str,
        symbol: SymbolRef<'a>,
    ) {
        // per Go spec, a method's receiver type must be defined in the same
        // package as the method itself, so the receiver type name is always
        // unqualified and lives in the same package as the queue entry, meaning
        // that we do not need to capture imports here (or take &SymbolTable)

        self.deferred.methods.push(DeferredMethod {
            package,
            receiver_type_name,
            method_name,
            symbol,
        });
    }

    pub fn queue_pending_field_resolutions_for(
        &mut self,
        symtab: &SymbolTable<'a>,
        owner: &Rc<TypeInfo<'a>>,
    ) {
        let TypeKind::Struct { fields } = owner.underlying() else {
            return;
        };

        if fields.iter().all(FieldInfo::is_resolved) {
            return;
        }

        let imports = self.current_file_imports(symtab);

        self.deferred.fields.push(DeferredStructFields {
            owner: Rc::clone(owner),
            imports,
        });
    }

    pub fn run_deferred_resolutions(&mut self) {
        // termination is guaranteed because each iteration only ever pushes
        // back entries it failed to resolve, so `outstanding_count` is for sure
        // monotonically non-increasing
        loop {
            let before = self.deferred.outstanding_count();

            self.resolve_pending_aliases();
            self.resolve_pending_methods();
            self.resolve_pending_struct_fields();

            let after = self.deferred.outstanding_count();

            if after == 0 || after == before {
                // either we successfully completed all deferred resolutions, or
                // the ones remaining depend on type names that simply do not
                // exist in the analyzed program, so they stay unresolved

                break;
            }
        }

        // discard any survivors: permanently unresolvable
        self.deferred = DeferredQueues::default();
    }

    fn resolve_pending_aliases(&mut self) {
        // clear the queue and take ownership of currently deferred aliases
        let pending = mem::take(&mut self.deferred.aliases);

        for entry in pending {
            let resolved = self.resolve_with(
                Some(&entry.package),
                entry.imports.named(),
                entry.imports.wildcard(),
                &entry.target,
            );

            if let Some(info) = resolved {
                self.types
                    .entry(entry.package)
                    .or_default()
                    .entry(entry.name)
                    .or_insert(info);
            } else {
                // we could not resolve the alias, so add it back to the queue
                self.deferred.aliases.push(entry);
            }
        }
    }

    fn resolve_pending_methods(&mut self) {
        // clear the queue and take ownership of currently deferred methods
        let pending = mem::take(&mut self.deferred.methods);

        for entry in pending {
            if let Some(r#type) = self.lookup(&entry.package, entry.receiver_type_name) {
                r#type.register_method(entry.method_name, entry.symbol);
            } else {
                // we could not resolve the method receiver, so add it back
                self.deferred.methods.push(entry);
            }
        }
    }

    fn resolve_pending_struct_fields(&mut self) {
        // clear the queue and take ownership of currently deferred fields
        let pending = mem::take(&mut self.deferred.fields);

        for entry in pending {
            let TypeKind::Struct { fields } = entry.owner.underlying() else {
                continue; // supposedly unreachable
            };

            let mut any_unresolved = false;

            for field in fields {
                if field.is_resolved() {
                    continue;
                }

                let resolved = self.resolve_with(
                    Some(entry.owner.package()),
                    entry.imports.named(),
                    entry.imports.wildcard(),
                    field.declared_type_node(),
                );

                if let Some(info) = resolved {
                    field.set_resolved_type(info);
                } else {
                    any_unresolved = true;
                }
            }

            if any_unresolved {
                // we could not resolve at least one of the fields, so add the
                // struct back to the queue
                self.deferred.fields.push(entry);
            }
        }
    }

    fn current_file_imports(&mut self, symtab: &SymbolTable<'a>) -> Rc<FileImportsRecord> {
        if let Some(snapshot) = &self.current_file_imports_snapshot {
            // we already have this cached
            return Rc::clone(snapshot);
        }

        let snapshot = Rc::new(symtab.current_file_imports_record());

        // cache the result
        self.current_file_imports_snapshot = Some(Rc::clone(&snapshot));

        snapshot
    }

    pub fn invalidate_imports_snapshot(&mut self) {
        self.current_file_imports_snapshot = None;
    }
}

impl Default for TypeRegistry<'_> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Default)]
struct DeferredQueues<'a> {
    aliases: Vec<DeferredAlias<'a>>,
    methods: Vec<DeferredMethod<'a>>,
    fields: Vec<DeferredStructFields<'a>>,
}

impl DeferredQueues<'_> {
    fn outstanding_count(&self) -> usize {
        self.aliases.len() + self.methods.len() + self.fields.len()
    }
}

#[derive(Debug)]
struct DeferredAlias<'a> {
    package: FullPackagePath,
    name: &'a str,
    target: TypeNode<'a>,
    imports: Rc<FileImportsRecord>,
}

#[derive(Debug)]
struct DeferredMethod<'a> {
    package: FullPackagePath,
    receiver_type_name: &'a str,
    method_name: &'a str,
    symbol: SymbolRef<'a>,
}

#[derive(Debug)]
struct DeferredStructFields<'a> {
    owner: Rc<TypeInfo<'a>>,
    imports: Rc<FileImportsRecord>,
}
