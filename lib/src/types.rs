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
    cell::{OnceCell, RefCell},
    collections::{HashMap, HashSet},
    fmt, iter, mem,
    path::Path,
    ptr,
    rc::Rc,
    sync::LazyLock,
};

use indexmap::IndexMap;
use parser::{
    Location,
    ast::{
        FieldDeclNode, FunctionResultNode, InterfaceElementNode, TypeDeclSpecNode, TypeNameNode,
        TypeNode,
    },
};
pub use promotion::PromotedField;
use regex::Regex;

use crate::{
    FullPackagePath, Pinned,
    context::AnalysisContext,
    labels::{FunctionRef, Label, LabelBacktrace, LabelBacktraceKind},
    symbols::{FileImportsRecord, LexicalScope, Symbol, SymbolRef, SymbolTable},
    values::{FunctionValue, ReceiverKind, Value, ValueRef},
};

static FIELD_TAG_REGEX: LazyLock<Regex> = {
    LazyLock::new(|| {
        Regex::new(
            // glowy:"value, possibly with escaped \"quotes\""
            r#"glowy:"((?:\\.|[^"\\])*)""#,
        )
        .unwrap()
    })
};

mod promotion;

/// Identity and metadata of a Go defined type (named type).
///
/// Allocated once per `(package, name)` and shared via [`Rc`] from every
/// declared-type slot that references it. Identity is the wrapping [`Rc`]
/// (via [`Rc::ptr_eq`]).
///
/// Aliases (`type T = X`) do not allocate a separate [`TypeInfo`]: the alias
/// name maps to the same [`Rc`] as its target, matching Go's spec semantics.
///
/// A [`TypeInfo`] can be in one of two lifecycle states:
/// - Unresolved: an entry interned before its declaration is visited, or a
///   declared type whose underlying named type is still pending resolution. In
///   this state [`Self::underlying`] returns [`None`]. Entries whose
///   declarations are never visited represent external types and give
///   downstream dispatch (blanket directives, `Rc::ptr_eq` comparisons) a
///   stable identity.
/// - Known: the type declaration has been visited and the structure recorded.
///   [`Self::underlying`] returns [`Some`].
///
/// Note this means that a [`None`] underlying has different semantics to a
/// [`Some`] holding [`TypeKind::Opaque`]. After declaration resolution, the
/// first case means we never saw the declaration and the entry refers to an
/// external type; the latter means we saw its declaration but could not resolve
/// its shape.
///
/// A placeholder can be promoted to Known in place: [`Self::underlying`] is
/// backed by a [`OnceCell`], so filling it does not require reallocating the
/// [`Rc`], and every prior holder immediately observes the refined structure.
/// The transition is monotonic (Known cannot revert to placeholder), which
/// matches Go's rule that each package declares a given type at most once.
pub struct TypeInfo<'a> {
    package: FullPackagePath,
    name: &'a str,
    // OnceCell is empty for external placeholders, populated for known types.
    // We rely on OnceCell's write-once semantics to preserve soundness: even
    // if `declare` is invoked twice for the same (package, name) (which Go
    // rejects but we don't panic on), the second attempt is silently dropped.
    underlying: OnceCell<TypeKind<'a>>,
    // note that this is just an alternative index to what is already stored in
    // the respective package envelope, so both SymbolRefs point to the exact
    // same Symbol (these are merely two alternative lookup strategies)
    methods: RefCell<HashMap<&'a str, SymbolRef<'a>>>,
}

impl<'a> TypeInfo<'a> {
    fn new_known(package: FullPackagePath, name: &'a str, underlying: TypeKind<'a>) -> Self {
        Self {
            package,
            name,
            underlying: OnceCell::from(underlying),
            methods: RefCell::new(HashMap::new()),
        }
    }

    fn new_placeholder(package: FullPackagePath, name: &'a str) -> Self {
        Self {
            package,
            name,
            underlying: OnceCell::new(),
            methods: RefCell::new(HashMap::new()),
        }
    }

    pub fn package(&self) -> &FullPackagePath {
        &self.package
    }

    pub fn name(&self) -> &'a str {
        self.name
    }

    pub fn underlying(&self) -> Option<&TypeKind<'a>> {
        self.underlying.get()
    }

    pub fn is_external(&self) -> bool {
        self.underlying().is_none()
    }

    pub fn has_slice_underlying(&self) -> bool {
        let mut current = self;
        let mut visited = HashSet::new();

        loop {
            if !visited.insert(ptr::from_ref(current)) {
                // cycles are rejected conservatively
                return false;
            }

            match current.underlying() {
                Some(TypeKind::Slice) => return true,
                Some(TypeKind::Named(inner)) => current = inner,
                None
                | Some(
                    TypeKind::Opaque
                    | TypeKind::Struct { .. }
                    | TypeKind::Map
                    | TypeKind::Array
                    | TypeKind::Channel
                    | TypeKind::Interface
                    | TypeKind::Function
                    | TypeKind::Pointer(_),
                ) => return false,
            }
        }
    }

    pub fn may_have_struct_underlying(&self) -> bool {
        let mut current = self;
        let mut visited = HashSet::new();

        loop {
            if !visited.insert(ptr::from_ref(current)) {
                // cycles are rejected conservatively
                return false;
            }

            match current.underlying() {
                None | Some(TypeKind::Struct { .. }) => return true,
                Some(TypeKind::Named(inner) | TypeKind::Pointer(inner)) => current = inner,
                Some(
                    TypeKind::Opaque
                    | TypeKind::Map
                    | TypeKind::Slice
                    | TypeKind::Array
                    | TypeKind::Channel
                    | TypeKind::Interface
                    | TypeKind::Function,
                ) => return false,
            }
        }
    }

    fn promote(&self, underlying: TypeKind<'a>) {
        // we ignore the Result because this set would only fail if there was a
        // duplicate type declaration, but we assume the input program compiles
        let _: Result<_, _> = self.underlying.set(underlying);
    }

    pub fn strip_pointers(&self) -> &Self {
        let mut current = self;
        let mut visited = HashSet::new();

        loop {
            if !visited.insert(ptr::from_ref(current)) {
                // no non-pointer base type exists in this recursive chain;
                // this is a cycle, so proceeding would lead to a stack overflow
                return current;
            }

            match current.underlying() {
                Some(TypeKind::Pointer(inner)) => current = inner,
                _ => return current,
            }
        }
    }

    fn underlying_struct_fields(&self) -> Option<&IndexMap<&'a str, StructFieldInfo<'a>>> {
        let mut current = self;
        let mut visited = HashSet::new();

        loop {
            if !visited.insert(ptr::from_ref(current)) {
                // a recursive pointer chain cannot provide a struct shape
                return None;
            }

            match current.underlying()? {
                TypeKind::Named(inner) | TypeKind::Pointer(inner) => current = inner,
                TypeKind::Struct { fields } => return Some(fields),
                TypeKind::Opaque
                | TypeKind::Map
                | TypeKind::Slice
                | TypeKind::Array
                | TypeKind::Channel
                | TypeKind::Interface
                | TypeKind::Function => return None,
            }
        }
    }

    fn get_field(&self, name: &str) -> Option<&StructFieldInfo<'a>> {
        self.underlying_struct_fields()?.get(name)
    }

    fn get_method(&self, name: &str) -> Option<SymbolRef<'a>> {
        self.methods.borrow().get(name).cloned()
    }

    pub fn register_method(&self, name: &'a str, symbol: SymbolRef<'a>) -> Option<SymbolRef<'a>> {
        self.methods.borrow_mut().insert(name, symbol)
    }

    pub fn lookup_promoted_field(self: &Rc<Self>, name: &str) -> Option<PromotedField<'a>> {
        // Go allows promoted fields wherein accessors can access fields through
        // embedded fields directly on the outer object without having to go
        // through the implicit field (e.g. `x.F` is short-hand for `x.y.F`)
        promotion::lookup_promoted_field(name, self)
    }

    pub fn lookup_promoted_method(self: &Rc<Self>, name: &str) -> Option<SymbolRef<'a>> {
        // Go allows promoted methods wherein invokers can call methods from
        // embedded fields directly on the outer object without having to go
        // through the implicit field (e.g. `x.M` is short-hand for `x.y.M`)
        promotion::lookup_promoted_method(name, self)
    }

    pub fn register_direct_interface_methods(
        self: &Rc<Self>,
        ctx: &mut AnalysisContext<'a>,
        node: &TypeDeclSpecNode<'a>,
    ) {
        let TypeNode::Interface { elements } = &node.r#type else {
            return;
        };

        for element in elements {
            let InterfaceElementNode::Method { name, signature } = element else {
                continue;
            };

            let declared_result_types = resolve_result_types(ctx, &signature.result);

            let pinned_name = ctx.pin(*name);
            let location = pinned_name.pinned_location();

            let mut func = FunctionValue::new(
                FunctionRef::new_named(pinned_name),
                Some(signature.clone()),
                // the interface's dynamic value may hold a pointer receiver, so
                // retain the more conservative receiver semantics
                Some(ReceiverKind::Pointer),
                declared_result_types,
                None,
            );

            let directives =
                ctx.blanket_directives_for(self.package(), Some(self.name()), name.content());

            func.absorb_blanket_directives(directives.iter());

            let value = ValueRef::new(Value::Function(Box::new(func)), location, None);
            let symbol = Symbol::new_ref(pinned_name, false, value, None);

            self.register_method(name.content(), symbol);
            ctx.types_mut().record_method_name(name.content());
        }
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
            .field("underlying", &underlying.get())
            // intentionally omitting `methods` to avoid borrowing the RefCell,
            // since callers might already hold a borrow
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum TypeKind<'a> {
    // built-in types (`int`, `string`, ...), or otherwise anything with a shape
    // that could not be resolved (opaque to analysis)
    Opaque,
    // an underlying named type (`type Wrapper Other`); kept distinct from
    // Opaque so its recursively-defined underlying shape remains observable
    Named(Rc<TypeInfo<'a>>),
    Struct {
        // IndexMap preserves declaration order upon iteration
        fields: IndexMap<&'a str, StructFieldInfo<'a>>,
    },
    Map,
    Slice,
    Array,
    Channel,
    Interface, // no extra info stored: interface dispatch is not modeled
    Function,
    Pointer(Rc<TypeInfo<'a>>),
}

impl<'a> TypeKind<'a> {
    fn from_resolved_reference(node: &TypeNode<'a>, target: Rc<TypeInfo<'a>>) -> Self {
        match node {
            TypeNode::Name(_) => Self::Named(target),
            TypeNode::Pointer { .. } => Self::Pointer(target),
            TypeNode::Channel { .. }
            | TypeNode::Array { .. }
            | TypeNode::Slice { .. }
            | TypeNode::Map { .. }
            | TypeNode::Struct { .. }
            | TypeNode::Interface { .. }
            | TypeNode::Function { .. } => {
                unreachable!("only named and pointer types reference a resolved type")
            }
        }
    }
}

#[derive(Debug)]
pub struct StructFieldInfo<'a> {
    // we need interior mutability (via RefCell) since sometimes a field's
    // declared type may live in a sibling file or another package not yet seen
    // at the this struct's type declaration is first found
    r#type: RefCell<Option<Rc<TypeInfo<'a>>>>,
    embedded: bool,
    declared_type_node: TypeNode<'a>,
    tag_backtrace: Option<LabelBacktrace<'a>>,
}

impl<'a> StructFieldInfo<'a> {
    pub fn new(
        r#type: Option<Rc<TypeInfo<'a>>>,
        declared_type_node: TypeNode<'a>,
        embedded: bool,
        tag_backtrace: Option<LabelBacktrace<'a>>,
    ) -> Self {
        Self {
            r#type: RefCell::new(r#type),
            embedded,
            declared_type_node,
            tag_backtrace,
        }
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

    pub fn tag_backtrace(&self) -> Option<&LabelBacktrace<'a>> {
        self.tag_backtrace.as_ref()
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
        current_file: &'a Path,
    ) -> Rc<TypeInfo<'a>> {
        let underlying_kind = self.try_build_kind(symtab, underlying, current_file);
        let resolution_pending = underlying_kind.is_none();

        let inner = self.types.entry(package.clone()).or_default();

        let info = if let Some(existing) = inner.get(name) {
            if let Some(underlying_kind) = underlying_kind {
                existing.promote(underlying_kind); // in case this was a placeholder
            }

            Rc::clone(existing)
        } else {
            let info = Rc::new(match underlying_kind {
                Some(underlying_kind) => TypeInfo::new_known(package, name, underlying_kind),
                None => TypeInfo::new_placeholder(package, name),
            });

            inner.insert(name, Rc::clone(&info));

            info
        };

        if resolution_pending {
            let imports = self.current_file_imports(symtab);

            self.deferred.underlying_types.push(DeferredUnderlying {
                owner: Rc::clone(&info),
                underlying: underlying.clone(),
                imports,
            });
        }

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

    pub fn declare_local_placeholder(package: FullPackagePath, name: &'a str) -> Rc<TypeInfo<'a>> {
        Rc::new(TypeInfo::new_placeholder(package, name))
    }

    pub fn define_local(
        &mut self,
        symtab: &SymbolTable<'a>,
        info: &Rc<TypeInfo<'a>>,
        underlying: &TypeNode<'a>,
        current_file: &'a Path,
    ) {
        let underlying_kind = self.build_kind(symtab, underlying, current_file);

        info.promote(underlying_kind);
    }

    pub fn lookup(&self, package: &str, name: &str) -> Option<Rc<TypeInfo<'a>>> {
        self.types
            .get(package)
            .and_then(|inner| inner.get(name))
            .map(Rc::clone)
    }

    fn intern_placeholder(&mut self, package: FullPackagePath, name: &'a str) -> Rc<TypeInfo<'a>> {
        let inner = self.types.entry(package.clone()).or_default();

        if let Some(existing) = inner.get(name) {
            return Rc::clone(existing);
        }

        let info = Rc::new(TypeInfo::new_placeholder(package, name));

        inner.insert(name, Rc::clone(&info));

        info
    }

    // must be mut to allow interning a placeholder if unknown external type
    pub fn resolve_name(
        &mut self,
        symtab: &SymbolTable<'a>,
        node: &TypeNameNode<'a>,
    ) -> Option<Rc<TypeInfo<'a>>> {
        if node.package.is_none()
            && let Some(symbol) = symtab.get_symbol(node.id.content())
        {
            let value = symbol.borrow().value();
            let value = value.get();

            if !value.is_function() {
                return None;
            }

            let func = value.as_function()?;

            if !func.is_type_constructor() {
                return None;
            }

            return func.constructed_type();
        }

        self.resolve_name_with(
            symtab.current_package_path(),
            symtab.current_file_named_imports(),
            symtab.current_file_wildcard_imports(),
            node,
        )
    }

    // must be mut to allow interning a placeholder if unknown external type
    fn resolve_name_with(
        &mut self,
        current_package: Option<&FullPackagePath>,
        named_imports: &HashMap<String, FullPackagePath>,
        wildcard_imports: &[FullPackagePath],
        node: &TypeNameNode<'a>,
    ) -> Option<Rc<TypeInfo<'a>>> {
        if let Some(qualifier) = node.package {
            // qualified name: if we've never seen this type, fall through to
            // an external placeholder so it gets a stable identity for
            // downstream dispatch; a later `declare` for the same
            // (package, name) will promote this entry in place
            let path = named_imports.get(qualifier.content())?;

            return if let Some(existing) = self.lookup(path, node.id.content()) {
                Some(existing)
            } else {
                // lookup failed, so this is some unknown external type. we
                // don't want to return None because we still want foreign types
                // to have a stable identity, especially to allow blanket
                // directives to target foreign methods, so we use a placeholder
                // (and remember it in the registry, hence needing `&mut self`)
                let placeholder = self.intern_placeholder(path.clone(), node.id.content());

                Some(placeholder)
            };
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

    // must be mut to allow interning a placeholder if unknown external type
    pub fn resolve(
        &mut self,
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

    // must be mut to allow interning a placeholder if unknown external type
    fn resolve_with(
        &mut self,
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

    fn build_kind(
        &mut self,
        symtab: &SymbolTable<'a>,
        node: &TypeNode<'a>,
        current_file: &'a Path,
    ) -> TypeKind<'a> {
        self.try_build_kind(symtab, node, current_file)
            .unwrap_or(TypeKind::Opaque)
    }

    fn try_build_kind(
        &mut self,
        symtab: &SymbolTable<'a>,
        node: &TypeNode<'a>,
        current_file: &'a Path,
    ) -> Option<TypeKind<'a>> {
        match node {
            TypeNode::Name(_) | TypeNode::Pointer { .. } => self
                .resolve(symtab, node)
                .map(|target| TypeKind::from_resolved_reference(node, target)),
            TypeNode::Struct { fields } => Some(TypeKind::Struct {
                fields: self.build_struct_fields(symtab, fields, current_file),
            }),
            TypeNode::Map { .. } => Some(TypeKind::Map),
            TypeNode::Slice { .. } => Some(TypeKind::Slice),
            TypeNode::Array { .. } => Some(TypeKind::Array),
            TypeNode::Channel { .. } => Some(TypeKind::Channel),
            TypeNode::Interface { .. } => Some(TypeKind::Interface),
            TypeNode::Function { .. } => Some(TypeKind::Function),
        }
    }

    fn build_struct_fields(
        &mut self,
        symtab: &SymbolTable<'a>,
        fields: &[FieldDeclNode<'a>],
        current_file: &'a Path,
    ) -> IndexMap<&'a str, StructFieldInfo<'a>> {
        let mut result = IndexMap::new();

        for decl in fields {
            match decl {
                FieldDeclNode::Explicit(explicit) => {
                    let resolved = self.resolve(symtab, &explicit.r#type);

                    for id in &explicit.ids {
                        let Some(name) = id else {
                            // blank `_` field; skipped as per Go spec
                            continue;
                        };

                        let tag_backtrace = root_backtrace_from_field_tag(
                            name.content(),
                            explicit.tag.as_deref(),
                            // we cannot use `ctx.pin` since there is no way to
                            // get ctx all the way down here, as it has to be
                            // mutably-borrowed for us to have &mut self
                            || Pinned::new(current_file, explicit.location.clone()),
                        );

                        let field = StructFieldInfo::new(
                            resolved.clone(),
                            explicit.r#type.clone(),
                            false,
                            tag_backtrace,
                        );

                        result.insert(name.content(), field);
                    }
                }
                FieldDeclNode::Embedded(embedded) => {
                    // per Go spec, the unqualified type name is the field name
                    let field_name = embedded.r#type.id.content();

                    let resolved = self.resolve_name(symtab, &embedded.r#type);

                    let mut declared_type = TypeNode::Name(embedded.r#type.clone());

                    if embedded.pointer {
                        declared_type = TypeNode::Pointer {
                            base: Box::new(declared_type),
                        };
                    }

                    let tag_backtrace = root_backtrace_from_field_tag(
                        field_name,
                        embedded.tag.as_deref(),
                        // we cannot use `ctx.pin` since there is no way to
                        // get ctx all the way down here, as it has to be
                        // mutably-borrowed for us to have &mut self
                        || Pinned::new(current_file, embedded.location.clone()),
                    );

                    let field = StructFieldInfo::new(resolved, declared_type, true, tag_backtrace);

                    result.insert(field_name, field);
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
        let Some(TypeKind::Struct { fields }) = owner.underlying() else {
            return;
        };

        if fields.values().all(StructFieldInfo::is_resolved) {
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
            self.resolve_pending_underlying_types();
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

        // a surviving defined-type target is opaque (normally a predeclared
        // type); unlike aliases, the defined type itself must remain usable
        for entry in &self.deferred.underlying_types {
            entry.owner.promote(TypeKind::Opaque);
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

    fn resolve_pending_underlying_types(&mut self) {
        let pending = mem::take(&mut self.deferred.underlying_types);

        for entry in pending {
            let resolved = self
                .resolve_with(
                    Some(entry.owner.package()),
                    entry.imports.named(),
                    entry.imports.wildcard(),
                    &entry.underlying,
                )
                .map(|target| TypeKind::from_resolved_reference(&entry.underlying, target));

            if let Some(underlying) = resolved {
                entry.owner.promote(underlying);
            } else {
                self.deferred.underlying_types.push(entry);
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
            let Some(TypeKind::Struct { fields }) = entry.owner.underlying() else {
                continue; // supposedly unreachable
            };

            let mut any_unresolved = false;

            for field in fields.values() {
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

    pub fn current_declaration_context(
        &mut self,
        symtab: &SymbolTable<'a>,
    ) -> Option<TypeDeclarationContext<'a>> {
        Some(TypeDeclarationContext {
            package: symtab.current_package_path()?.clone(),
            imports: self.current_file_imports(symtab),
            scope: symtab.current_lexical_scope(),
        })
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeDeclarationContext<'a> {
    package: FullPackagePath,
    imports: Rc<FileImportsRecord>,
    scope: LexicalScope<'a>,
}

impl<'a> TypeDeclarationContext<'a> {
    pub fn package(&self) -> &FullPackagePath {
        &self.package
    }

    pub fn imports(&self) -> &FileImportsRecord {
        &self.imports
    }

    pub fn scope(&self) -> &LexicalScope<'a> {
        &self.scope
    }
}

fn root_backtrace_from_field_tag<'a>(
    field_name: &'a str,
    tag: Option<&str>,
    at_location: impl Fn() -> Pinned<'a, Location>,
) -> Option<LabelBacktrace<'a>> {
    let tag = tag?;

    let mut label = Label::Bottom;

    // we cannot use `split` because values between quotes might have spaces,
    // so we have to use regex to get all captures
    for (_, [value]) in FIELD_TAG_REGEX
        .captures_iter(tag)
        .map(|capture| capture.extract())
    {
        // the extracted `value` borrows from `tag`, which is not necessarily
        // `'a` (e.g., it may come from an owned `String` on an AST node whose
        // borrow is shorter than `'a`); we thus copy each tag name into an
        // owned `String` before feeding into a `Label<'a>`
        let label_tags: Vec<_> = value
            .split(',')
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_owned)
            .collect();

        label = label.union(&Label::from_tags(label_tags));
    }

    if label.is_bottom() {
        // avoid creating a location unnecessarily
        return None;
    }

    LabelBacktrace::new_root(
        LabelBacktraceKind::ExplicitFieldTag,
        label,
        Some(field_name),
        at_location(),
    )
}

#[derive(Debug, Default)]
struct DeferredQueues<'a> {
    aliases: Vec<DeferredAlias<'a>>,
    underlying_types: Vec<DeferredUnderlying<'a>>,
    methods: Vec<DeferredMethod<'a>>,
    fields: Vec<DeferredStructFields<'a>>,
}

impl DeferredQueues<'_> {
    fn outstanding_count(&self) -> usize {
        self.aliases.len() + self.underlying_types.len() + self.methods.len() + self.fields.len()
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
struct DeferredUnderlying<'a> {
    owner: Rc<TypeInfo<'a>>,
    underlying: TypeNode<'a>,
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

fn resolve_result_types<'a>(
    ctx: &mut AnalysisContext<'a>,
    result: &FunctionResultNode<'a>,
) -> Vec<Option<Rc<TypeInfo<'a>>>> {
    let mut resolve = |r#type| {
        let (types, symtab) = ctx.types_mut_with_symtab();

        types.resolve(symtab, r#type)
    };

    match result {
        FunctionResultNode::None => Vec::new(),
        FunctionResultNode::Single(r#type) => vec![resolve(r#type)],
        FunctionResultNode::Params(params) => params
            .iter()
            .flat_map(|param| iter::repeat_n(resolve(&param.r#type), param.ids.len().max(1)))
            .collect(),
    }
}
