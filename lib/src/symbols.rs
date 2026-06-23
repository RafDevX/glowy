// We support analyzing a single Go module, which contains one
// root package (with name = last segment of module path *) and
// possibly several more sub-packages. For example:
//
//     project-root-directory/
//         go.mod (<-- contains "module example.com/org/something")
//         puppies.go (<-- contains "package something" *)
//         auth/
//             login.go (<-- contains "package auth" *)
//
// In the example above, `puppies.go` can import `auth` with:
// `import "example.com/org/something/auth"` and access public
// symbols exported in `login.go` (i.e., Capitalized).
//
// reference: https://go.dev/doc/modules/layout#multiple-packages
//
// (*) Actually: despite convention, Go does not really require the
// package name to correspond to the last segment of the package
// path (which is what is used in imports). A file in `utils/ui.go`
// can state `package weird` instead of `package utils`, which then
// becomes the package name (and must be the same for all files in
// `utils/`). When another package imports "example.com/.../utils",
// the package comes into scope as `weird` and not `utils` (unless
// an alias is defined when importing).

// Note: when `import p "path"`, `p` can ONLY be used in qualified
// identifiers (`p.Func`) -- `k := p` and `fmt.Println(p)` fail.
// This means we don't need to keep track of `p` as a symbol, but
// can just resolve each qualified identifier individually.

// File scopes are not used because they would just complicate sharing symbols
// between different packages, but this means we need special handling to ensure
// analysis of a 2nd file doesn't overwrite/reuse children scopes created in a
// 1st file, so therefore we use [`PackageScopeEnvelope::saved_index`] to keep
// track of the last child index when switching from one file to the next within
// the same package. This also means that priming must support keeping track of
// which child to select (with `Option<usize>`) rather than a simple `bool`
// (where true would mean 0th).

// We can't use temporary scopes and push/pop them away, because
// analysis requires multiple iterations to stabilize, meaning we
// need to remember symbols even after leaving that branch.

use std::{
    cell::RefCell,
    collections::HashMap,
    fmt,
    path::Path,
    rc::{Rc, Weak},
};

use parser::Span;

use crate::{
    FullPackagePath, Pinned,
    snapshots::{AssumedImmutable, SymbolTableSnapshot, SymbolTableSnapshotItem},
    values::{FunctionRef, FunctionValue, Value, ValueRef},
};

#[derive(Debug)]
pub struct SymbolTable<'a> {
    /// Universe block with pre-declared identifiers.
    universe_scope: Scope<'a>,
    /// Root scopes associated with each package (None if blackbox).
    package_scopes: HashMap<FullPackagePath, Option<PackageScopeEnvelope<'a>>>,

    /// Other packages imported by the current file, with an assigned qualifier.
    current_file_named_imports: HashMap<String, FullPackagePath>,
    /// Other packages imported by the current file, via `import . "path"`.
    current_file_wildcard_imports: Vec<FullPackagePath>,

    /// Currently selected (package or sub-package) scope.
    current_scope: ScopeRef<'a>,
    /// Path of the package whose root the [`Self::current_scope`] is nested in.
    ///
    /// Tracked so that we can resolve methods (which live on the package
    /// envelope, not in the lexical scope chain) from any nested scope depth.
    current_package_path: Option<FullPackagePath>,
    /// Count of traversed children for each level (last value = current level).
    ///
    /// For example, a cursor of:
    ///   - `[0]` means that nothing has been declared yet in the package scope;
    ///   - `[2, 3]` means that we have seen 3 children in the 2nd package func.
    current_cursor: Vec<usize>,
}

impl<'a> SymbolTable<'a> {
    pub fn new() -> Self {
        Self {
            universe_scope: Scope::new_universe(),
            package_scopes: HashMap::from([("fmt".to_owned(), None)]),

            current_file_named_imports: HashMap::new(),
            current_file_wildcard_imports: Vec::new(),

            // For simplicity in the rest of the code, we don't use Option for
            // current_scope, but instead initialize it at a dead end not
            // actually corresponding to any package; this means SymbolTable is
            // only truly active after the first `enter_package` invocation.
            // This dead end will then be automatically deleted (by Rc).
            current_scope: Scope::new_root_ref(),
            current_package_path: None,
            current_cursor: Vec::new(),
        }
    }

    /// This function should be called upon starting analysis of each file.
    pub fn enter_package(
        &mut self,
        name: Pinned<'a, Span<'a>>,
        path: FullPackagePath,
    ) -> Pinned<'a, Span<'a>> {
        // note that we cannot automatically derive the name from the path!
        // (must be taken from package clause, may differ from dirname)

        let envelope = self
            .package_scopes
            .entry(path.clone())
            .or_insert_with(|| Some(PackageScopeEnvelope::new(name)));

        let envelope = envelope
            .as_ref()
            .expect("package to be entered should not be blackbox");

        self.current_file_named_imports.clear();
        self.current_file_wildcard_imports.clear();

        self.current_scope = Rc::clone(&envelope.scope);
        self.current_package_path = Some(path);
        self.current_cursor = vec![envelope.next_child_index];

        envelope.package_name
    }

    pub fn save_package_progress(&mut self, path: &FullPackagePath) {
        if let Some(&index) = self.current_cursor.first()
            && let Some(Some(envelope)) = self.package_scopes.get_mut(path)
        {
            envelope.next_child_index = index;
        }
    }

    pub fn clear_all_package_progress(&mut self) {
        for envelope in self.package_scopes.values_mut().flatten() {
            envelope.next_child_index = 0;
        }
    }

    fn current_package_envelope(&self) -> Option<&PackageScopeEnvelope<'a>> {
        let path = self.current_package_path.as_ref()?;

        self.package_scopes.get(path)?.as_ref()
    }

    fn current_package_envelope_mut(&mut self) -> Option<&mut PackageScopeEnvelope<'a>> {
        let path = self.current_package_path.as_ref()?;

        self.package_scopes.get_mut(path)?.as_mut()
    }

    pub fn select_next_child_scope(&mut self) {
        let Some(cursor) = self.current_cursor.last_mut() else {
            // the cursor vector is empty, which can only happen if
            // `enter_package` was never called, which should not be possible
            unreachable!()
        };

        let index = *cursor;
        *cursor += 1;

        let child = {
            let mut scope = self.current_scope.borrow_mut();

            if let Some(existing) = scope.children.get(index).cloned() {
                existing
            } else {
                let new_scope = Scope::new_ref(Rc::downgrade(&self.current_scope));
                scope.children.push(Rc::clone(&new_scope));

                new_scope
            }
        };

        self.current_scope = Rc::clone(&child);
        self.current_cursor.push(0);
    }

    pub fn select_parent_scope(&mut self) {
        if let Some(parent) = self.get_parent_scope() {
            self.current_scope = parent;
            self.current_cursor.pop();
        }
    }

    pub fn rewind_child_scope_cursor(&mut self) {
        if let Some(cursor) = self.current_cursor.last_mut()
            && *cursor > 0
        {
            *cursor -= 1;
        }
    }

    fn get_parent_scope(&self) -> Option<ScopeRef<'a>> {
        // None if already at the root (package scope)
        self.current_scope.borrow().parent()
    }

    fn get_symbol_from_scope_chain(
        &self,
        upwards_from: Option<ScopeRef<'a>>,
        name: &str,
    ) -> Option<SymbolRef<'a>> {
        let mut checking = upwards_from;

        while let Some(scope) = &checking {
            let borrowed = scope.borrow();

            if let Some(symbol) = borrowed.get_local_symbol(name) {
                return Some(symbol);
            }

            let parent = borrowed.parent();
            drop(borrowed);

            checking.clone_from(&parent);
        }

        if name.chars().next().is_some_and(char::is_uppercase) {
            for path in &self.current_file_wildcard_imports {
                if let Some(Some(envelope)) = self.package_scopes.get(path)
                    && let Some(symbol) = envelope.scope.borrow().get_local_symbol(name)
                {
                    return Some(symbol);
                }
            }
        }

        self.universe_scope.get_local_symbol(name)
    }

    pub fn get_symbol(&self, name: &str) -> Option<SymbolRef<'a>> {
        Self::get_symbol_from_scope_chain(self, Some(Rc::clone(&self.current_scope)), name)
    }

    pub fn get_symbol_above_current_scope(&self, name: &str) -> Option<SymbolRef<'a>> {
        Self::get_symbol_from_scope_chain(self, self.get_parent_scope(), name)
    }

    pub fn get_qualified_symbol(
        &self,
        qualifier: &str,
        name: &str,
    ) -> QualifiedSymbolResolutionResult<'a> {
        if let Some(path) = self.current_file_named_imports.get(qualifier) {
            if let Some(Some(envelope)) = self.package_scopes.get(path) {
                if name.chars().next().is_some_and(char::is_uppercase)
                    && let Some(symbol) = envelope.scope.borrow().get_local_symbol(name)
                {
                    QualifiedSymbolResolutionResult::Success(symbol)
                } else {
                    QualifiedSymbolResolutionResult::UnknownSymbol
                }
            } else {
                // we haven't visited the package (yet?)
                QualifiedSymbolResolutionResult::PendingAnalysis
            }
        } else {
            QualifiedSymbolResolutionResult::UnknownQualifier
        }
    }

    pub fn get_symbol_by_declaration(
        &self,
        declaration: Pinned<'a, Span<'a>>,
    ) -> Option<SymbolRef<'a>> {
        for envelope in self.package_scopes.values().flatten() {
            if let Some(symbol) = envelope
                .scope
                .borrow()
                .get_symbol_by_declaration(declaration)
            {
                return Some(symbol);
            }

            // methods aren't part of the lexical scope chain, but closures
            // captured inside method bodies may still need to resolve their
            // declaration sites (e.g. for self-referential method calls)
            for method in envelope.methods_by_name(declaration.content()) {
                if method.borrow().declared_name() == declaration {
                    return Some(Rc::clone(method));
                }
            }
        }

        self.universe_scope.get_symbol_by_declaration(declaration)
    }

    pub fn declare_new_symbol(
        &mut self,
        name: &'a str,
        symbol: SymbolRef<'a>,
    ) -> Option<SymbolRef<'a>> {
        // technically shouldn't allow declaring symbols at the package level
        // which are already declared in other packages imported via `import .`,
        // but we'll leave that kind of extensive checks for the actual Go
        // compiler to enforce

        self.current_scope
            .borrow_mut()
            .set_local_symbol(name, symbol)
    }

    pub fn declare_new_method(
        &mut self,
        receiver_type: &'a str,
        name: &'a str,
        symbol: SymbolRef<'a>,
    ) -> Option<SymbolRef<'a>> {
        let envelope = self
            .current_package_envelope_mut()
            .expect("a package should be active when declaring a method");

        envelope.set_method(receiver_type, name, symbol)
    }

    pub fn lookup_unique_method_in_current_package(&self, name: &str) -> Option<SymbolRef<'a>> {
        // note: cross-package is not supported here, since methods are
        // necessarily registered in the envelopes associated with their
        // receiver type, so we'd need to know `x`'s type (in `x.M`) statically
        // to know which other package envelope to look at

        let envelope = self.current_package_envelope()?;

        let mut iter = envelope.methods_by_name(name);
        let first = iter.next()?;

        if iter.next().is_some() {
            // ambiguous: fall back to blackbox (cannot disambiguate which type)
            return None;
        }

        Some(Rc::clone(first))
    }

    /// Returns None if no qualifier was specified but the package has not yet
    /// been analyzed, so its native name is not yet known. Otherwise, the
    /// return indicates whether the new spec conflicts with a previous spec
    /// (i.e., `Some(true)` means the same qualifier has been registered before
    /// and was now overwritten).
    ///
    /// If `infer_from_path` is true, this function will never return None,
    /// since if not found in any other way the qualifier will default to the
    /// last component of the path. This should be avoided since it is not
    /// guaranteed to be correct and can lead to unexpected problems if it leads
    /// to an incorrect qualifier being registered, but if necessary it should
    /// infer correctly most of the time.
    pub fn register_import_spec(
        &mut self,
        qualifier: Option<String>,
        path: FullPackagePath,
        infer_from_path: bool,
    ) -> Option<bool> {
        let qualifier = qualifier.or_else(|| {
            self.package_scopes
                .get(&path)
                .and_then(Option::as_ref)
                .map(|envelope| envelope.package_name.content().to_owned())
        });

        let qualifier = match qualifier {
            Some(qual) => qual,
            None if infer_from_path => Self::infer_qualifier_from_import_path(&path),
            None => return None,
        };

        let conflicted = if qualifier == "." {
            self.current_file_wildcard_imports.push(path);

            false
        } else {
            self.current_file_named_imports
                .insert(qualifier, path)
                .is_some()
        };

        Some(conflicted)
    }

    fn infer_qualifier_from_import_path(path: &FullPackagePath) -> String {
        let mut components = path.rsplit('/'); // rev. ordered

        if ["github.com", "bitbucket.com"]
            .iter()
            .any(|prefix| path.starts_with(prefix))
        {
            // special case: for Go-recognized remote git repositories, we can
            // mitigate the biggest pitfall of the general case's heuristic by
            // ignoring tag/branch/rev name if that's the last component of the
            // package's import path
            // see docs: https://pkg.go.dev/cmd/go#hdr-Remote_import_paths

            if components.clone().count() == 4 {
                // the last component is the rev ("sub"), so we need to skip
                // that and use the penultimate component instead
                // (e.g., `github.com/user/pkg/v3` should have its native name
                // inferred as `pkg` and not as `v3`)
                components.next();
            }
        }

        // general case: infer that the package's native name corresponds to the
        // last component of the path (e.g., `net/http` -> `http`)
        // [evidently, this is not a foolproof heuristic, but it should
        // work for the overwhelming majority of cases, including stdlib]
        components.next().unwrap().to_owned()
    }

    pub fn qualifier_exists(&self, qualifier: &str) -> bool {
        self.current_file_named_imports.contains_key(qualifier)
    }

    pub fn package_path_for_qualifier(&self, qualifier: &str) -> Option<&FullPackagePath> {
        self.current_file_named_imports.get(qualifier)
    }

    pub fn is_package_blackbox(&self, qualifier: &str) -> bool {
        if let Some(path) = self.current_file_named_imports.get(qualifier)
            && let Some(envelope) = self.package_scopes.get(path)
        {
            return envelope.is_none();
        }

        false
    }

    pub fn snapshot(&self) -> SymbolTableSnapshot<'a> {
        let mut items = vec![];

        // necessary because a HashMap has no defined order, which could lead to
        // inconsistent theoretically-identical snapshots
        let mut sorted: Vec<_> = self.package_scopes.iter().collect();
        sorted.sort_unstable_by_key(|(k, _)| *k);

        for (path, envelope) in sorted {
            // we use an Rc instead of cloning String every time since there'll
            // probably be many items with the exact same namespace, and &str
            // would not compile (lifetimes, this is being returned to outside
            // this function and would depend on &self.package_scopes)
            let namespace = Rc::from(path.as_str());

            if let Some(envelope) = envelope {
                items.extend(envelope.scope.borrow().partial_snapshot(&namespace));
                items.extend(envelope.partial_method_snapshot(path));
            }
        }

        SymbolTableSnapshot::from(items)
    }
}

impl Default for SymbolTable<'_> {
    fn default() -> Self {
        Self::new()
    }
}

pub enum QualifiedSymbolResolutionResult<'a> {
    /// Qualifier is unknown and so could not be resolved to any other package.
    UnknownQualifier,
    /// Qualifier recognized but no matching package has (yet?) been analyzed.
    ///
    /// This means that it is not possible at this point in time to determine if
    /// the symbol exists, since such determination will only be possible once
    /// the target package has been analyzed (assuming its source code is
    /// available and will eventually be queued).
    PendingAnalysis,
    /// Requested name is not exported by the referenced package.
    ///
    /// This might be because it is private, or simply because it does not exist
    /// within the target package.
    UnknownSymbol,
    /// Specified symbol was successfully found in the referenced package.
    Success(SymbolRef<'a>),
}

#[derive(Debug)]
struct PackageScopeEnvelope<'a> {
    /// Package name (!= package path's last component).
    package_name: Pinned<'a, Span<'a>>,
    /// The package's root scope.
    scope: ScopeRef<'a>,
    /// Method declarations, keyed by receiver type then method name.
    ///
    /// Methods live here (and not in [`Self::scope`]) so that several distinct
    /// receiver types may declare a method of the same name without colliding,
    /// as Go's spec namespaces methods under their receiver's defined type
    /// rather than under the package-block identifier namespace shared by free
    /// functions, vars, constants, and types.
    ///
    /// The outer key is the receiver's defined type name (after stripping any
    /// pointer indirection or generic type arguments); the inner key is the
    /// method's name.
    ///
    /// Per Go's spec, a method's receiver type must be defined in the same
    /// package as the method itself, so every entry here is owned by the
    /// enclosing envelope's package.
    methods: HashMap<&'a str, HashMap<&'a str, SymbolRef<'a>>>,
    /// Next child to be selected, for cross-file synergy/allow resuming count.
    next_child_index: usize,
}

impl<'a> PackageScopeEnvelope<'a> {
    fn new(package_name: Pinned<'a, Span<'a>>) -> Self {
        let scope = Scope::new_root_ref();

        Self {
            package_name,
            scope,
            methods: HashMap::new(),
            next_child_index: 0,
        }
    }

    fn set_method(
        &mut self,
        receiver_type: &'a str,
        name: &'a str,
        symbol: SymbolRef<'a>,
    ) -> Option<SymbolRef<'a>> {
        self.methods
            .entry(receiver_type)
            .or_default()
            .insert(name, symbol)
    }

    fn methods_by_name<'s>(&'s self, name: &'s str) -> impl Iterator<Item = &'s SymbolRef<'a>> {
        self.methods
            .values()
            .filter_map(move |inner| inner.get(name))
    }

    fn partial_method_snapshot(&self, package_path: &str) -> Vec<SymbolTableSnapshotItem<'a>> {
        let mut items = vec![];

        // sort for deterministic ordering (HashMap iteration is unordered)
        let mut sorted: Vec<_> = self.methods.iter().collect();
        sorted.sort_unstable_by_key(|(recv, _)| *recv);

        for (recv_type, methods) in sorted {
            let namespace = Rc::from(format!("{package_path}#{recv_type}").as_str());

            let mut sorted_methods: Vec<_> = methods.iter().collect();
            sorted_methods.sort_unstable_by_key(|(name, _)| *name);

            for (name, symbol) in sorted_methods {
                let borrowed = symbol.borrow();

                items.push(SymbolTableSnapshotItem::new(
                    Rc::clone(&namespace),
                    name,
                    borrowed.mutable(),
                    borrowed.value().get(),
                ));
            }
        }

        items
    }
}

type ScopeRef<'a> = Rc<RefCell<Scope<'a>>>;
type WeakScopeRef<'a> = Weak<RefCell<Scope<'a>>>;

// In the Go spec, this is called a block, but that's a bit confusing
// since blocks are lexical elements that don't necessarily exist for
// every scope (e.g., no AST node for "universe"). We also don't want
// AST nodes to be mutable and hold analysis metadata (separation of
// concerns), hence this separate Scope struct.
struct Scope<'a> {
    /// Mapping between name (identifier) and its corresponding symbol.
    symbols: HashMap<&'a str, SymbolRef<'a>>,

    /// Parent scope, unless this is the root scope (package block, & universe).
    ///
    /// This needs to be a [`Weak`] reference to break the cycle, as otherwise
    /// it would cause a (severe) memory leak, since Scopes would never be
    /// dropped (ref-count would never reach 0, since all parents point to their
    /// children and all children point to their parents) and thus no Symbol nor
    /// Value in the scope tree would be dropped even after analysis finished.
    parent: Option<WeakScopeRef<'a>>,
    /// Children scopes, if any.
    children: Vec<ScopeRef<'a>>,
}

impl<'a> Scope<'a> {
    fn new(parent: Option<WeakScopeRef<'a>>) -> Self {
        Self {
            symbols: HashMap::new(),

            parent,
            children: Vec::new(),
        }
    }

    fn new_ref(parent: WeakScopeRef<'a>) -> ScopeRef<'a> {
        Rc::new(RefCell::new(Self::new(Some(parent))))
    }

    fn new_root_ref() -> ScopeRef<'a> {
        // package scopes have no parent
        Rc::new(RefCell::new(Self::new(None)))
    }

    // https://go.dev/ref/spec#Predeclared_identifiers
    fn new_universe() -> Self {
        let mut scope = Self::new(None);

        // FIXME: handle this better, or at least check if pinned.file() is
        // empty everywhere this location could be reached and treat it as a
        // special case (should only happen for predeclared)
        // [note: cannot be `const` because MSRV would need to be raised to 1.91
        // just to support this -- not worth it]
        let predeclared_location = Pinned::new(Path::new(""), 0..1);

        macro_rules! predeclared_constant {
            ($id:expr, $value:expr) => {
                scope.set_local_symbol($id, Symbol::new_predeclared_ref($id, $value))
            };
            ($id:expr) => {
                predeclared_constant!($id, ValueRef::new_bottom(predeclared_location.clone()))
            };
        }

        macro_rules! predeclared_function {
            ($id:expr, $params:expr, $variadic:expr, $n_returned:expr) => {
                predeclared_constant!(
                    $id,
                    ValueRef::new(
                        Value::Function(Box::new(FunctionValue::new_builtin(
                            $id,
                            $params,
                            $variadic,
                            $n_returned
                        ))),
                        predeclared_location.clone(),
                    )
                )
            };
        }

        macro_rules! predeclared_type {
            ($id:expr) => {
                // we treat predeclared types as functions for now because the
                // only context it should matter for them to be defined is when
                // using their names in conversions (which should be almost
                // equivalent to invocations of blackbox functions).
                // however, instead of just deferring to predeclared_function!,
                // we actually flag them as type constructors so that later they
                // can be picked up in calls and routed not really through the
                // blackbox-call path, but through something a bit softer that
                // can preserve the current value shape

                predeclared_constant!(
                    $id,
                    ValueRef::new(
                        Value::Function(Box::new(FunctionValue::new_type_constructor(
                            FunctionRef::BuiltIn($id),
                            None, // predeclared types have no underlying type
                        ))),
                        predeclared_location.clone(),
                    )
                )
            };
        }

        predeclared_constant!("true");
        predeclared_constant!("false");
        predeclared_constant!("iota");
        predeclared_constant!("nil"); // not really a constant, but close enough

        predeclared_function!("len", &["s"], false, 1);
        predeclared_function!("cap", &["s"], false, 1);
        predeclared_function!("min", &["n"], true, 1);
        predeclared_function!("max", &["n"], true, 1);
        predeclared_function!("panic", &["value"], false, 0);
        predeclared_function!("recover", &[], false, 1);

        predeclared_function!("complex", &["realPart", "imaginaryPart"], false, 1);
        predeclared_function!("real", &["c"], false, 1);
        predeclared_function!("imag", &["c"], false, 1);

        predeclared_type!("any");
        predeclared_type!("bool");
        predeclared_type!("byte");
        predeclared_type!("comparable");
        predeclared_type!("complex64");
        predeclared_type!("complex128");
        predeclared_type!("error");
        predeclared_type!("float32");
        predeclared_type!("float64");
        predeclared_type!("int");
        predeclared_type!("int8");
        predeclared_type!("int16");
        predeclared_type!("int32");
        predeclared_type!("int64");
        predeclared_type!("rune");
        predeclared_type!("string");
        predeclared_type!("uint");
        predeclared_type!("uint8");
        predeclared_type!("uint16");
        predeclared_type!("uint32");
        predeclared_type!("uint64");
        predeclared_type!("uintptr");

        scope
    }

    fn parent(&self) -> Option<ScopeRef<'a>> {
        // returns None if there is no parent (i.e., universe scope), or also
        // technically if the parent has been deallocated since we only hold a
        // weak ref to it (but there is no reason why it should have been)
        self.parent.as_ref().and_then(Weak::upgrade)
    }

    fn get_local_symbol(&self, name: &str) -> Option<SymbolRef<'a>> {
        self.symbols.get(name).cloned()
    }

    fn set_local_symbol(&mut self, name: &'a str, symbol: SymbolRef<'a>) -> Option<SymbolRef<'a>> {
        self.symbols.insert(name, symbol)
    }

    fn get_symbol_by_declaration(
        &self,
        declaration: Pinned<'a, Span<'a>>,
    ) -> Option<SymbolRef<'a>> {
        if let Some(local) = self.symbols.get(declaration.content())
            && local.borrow().declared_name() == declaration
        {
            return Some(Rc::clone(local));
        }

        for child in &self.children {
            let symbol = child.borrow().get_symbol_by_declaration(declaration);

            if symbol.is_some() {
                return symbol;
            }
        }

        None
    }

    fn partial_snapshot(&self, namespace: &Rc<str>) -> Vec<SymbolTableSnapshotItem<'a>> {
        let mut items = vec![];

        // necessary because a HashMap has no defined order, which could lead to
        // inconsistent theoretically-identical snapshots
        let mut sorted: Vec<_> = self.symbols.iter().collect();
        sorted.sort_unstable_by_key(|(k, _)| *k);

        for (name, symbol) in sorted {
            let borrowed = symbol.borrow();

            let item = SymbolTableSnapshotItem::new(
                Rc::clone(namespace),
                name,
                borrowed.mutable(),
                borrowed.value().get(),
            );

            items.push(item);
        }

        for (i, child) in self.children.iter().enumerate() {
            let borrowed = child.borrow();
            let mut sub = borrowed.partial_snapshot(namespace);

            for item in &mut sub {
                item.push_to_path(i);
            }

            items.extend(sub);
        }

        items
    }
}

impl fmt::Debug for Scope<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[derive(Debug)]
        #[expect(dead_code, reason = "Fake struct not meant to be used")]
        struct Scope<'d, 'a> {
            symbols: &'d HashMap<&'a str, SymbolRef<'a>>,
            // no `parent` to avoid infinite loop
            children: &'d Vec<ScopeRef<'a>>,
        }

        #[expect(
            clippy::unneeded_field_pattern,
            reason = "Force revisiting this implementation if a field is added"
        )]
        let Self {
            symbols,
            children,
            parent: _,
        } = self;

        fmt::Debug::fmt(&Scope { symbols, children }, f)
    }
}

// Scopes cannot own Symbols directly because it would make the borrow checker
// very sad if symtab returned (non-Rc'd) &Symbol's, since to access them it's
// necessary to runtime-borrow from a ScopeRef and then that & reference points
// to the runtime-borrow that will be dropped before the symtab function returns
pub type SymbolRef<'a> = Rc<RefCell<Symbol<'a>>>;

#[derive(Debug)]
pub struct Symbol<'a> {
    /// Original symbol name within symbol declaration.
    declared_name: Pinned<'a, Span<'a>>,
    /// Whether the symbol can be mutated later (e.g., `var`) or not (`const`).
    mutable: bool,
    /// This symbol's current value, including its accumulated security label.
    value: ValueRef<'a>,
}

impl<'a> Symbol<'a> {
    fn new(declared_name: Pinned<'a, Span<'a>>, mutable: bool, value: ValueRef<'a>) -> Self {
        Self {
            declared_name,
            mutable,
            value,
        }
    }

    pub fn new_ref(
        declared_name: Pinned<'a, Span<'a>>,
        mutable: bool,
        value: ValueRef<'a>,
    ) -> SymbolRef<'a> {
        Rc::new(RefCell::new(Self::new(declared_name, mutable, value)))
    }

    fn new_predeclared_ref(name: &'a str, value: ValueRef<'a>) -> SymbolRef<'a> {
        Self::new_ref(
            // vv not very pretty, but it should never matter anyway
            Pinned::new(Path::new(""), Span::new(name, 0, 0)),
            false,
            value,
        )
    }

    pub fn declared_name(&self) -> Pinned<'a, Span<'a>> {
        self.declared_name
    }

    pub fn mutable(&self) -> bool {
        self.mutable
    }

    pub fn mark_immutable(&mut self) {
        self.mutable = false;
    }

    /// This method's return value MAY NOT be used for internal mutability.
    ///
    /// Any mutations MUST be made indirectly by passing [`Symbol::set_value`] a
    /// new [`ValueRef`] pointing to a DIFFERENT inner value, as otherwise this
    /// will break snapshot logic assumptions.
    pub fn value(&self) -> AssumedImmutable<ValueRef<'a>> {
        AssumedImmutable::new(self.value.clone())
    }

    pub fn set_value(&mut self, value: ValueRef<'a>) {
        self.value = value;
    }
}
