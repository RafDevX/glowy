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

use std::{cell::RefCell, collections::HashMap, fmt, path::PathBuf, rc::Rc};

use parser::Span;

use crate::{
    FullPackagePath, Pinned,
    values::{FunctionValue, Value, ValueRef},
};

#[derive(Debug)]
pub struct SymbolTable<'a> {
    /// Universe block with pre-declared identifiers
    universe_scope: Scope<'a>,
    /// Root scopes associated with each package (None if blackbox)
    package_scopes: HashMap<FullPackagePath, Option<PackageScopeEnvelope<'a>>>,

    /// Other packages imported by the current file, with an assigned qualifier
    current_file_named_imports: HashMap<String, FullPackagePath>,
    /// Other packages imported by the current file, via `import . "path"`
    current_file_wildcard_imports: Vec<FullPackagePath>,

    /// Currently selected (package or sub-package) scope
    current_scope: ScopeRef<'a>,
    /// Count of traversed children, for each level (last value = current level)
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
            current_cursor: Vec::new(),
        }
    }

    /// This function should be called upon starting analysis of each file.
    pub fn enter_package(
        &mut self,
        name: Pinned<Span<'a>>,
        path: FullPackagePath,
    ) -> &Pinned<Span<'a>> {
        // note that we cannot automatically derive the name from the path!
        // (must be taken from package clause, may differ from dirname)

        let envelope = self
            .package_scopes
            .entry(path)
            .or_insert_with(|| Some(PackageScopeEnvelope::new(name)));

        let envelope = envelope
            .as_ref()
            .expect("package to be entered should not be blackbox");

        self.current_file_named_imports.clear();
        self.current_file_wildcard_imports.clear();

        self.current_scope = envelope.scope.clone();
        self.current_cursor = vec![envelope.next_child_index];

        &envelope.package_name
    }

    pub fn save_package_progress(&mut self, path: &FullPackagePath) {
        if let Some(&index) = self.current_cursor.first() {
            if let Some(Some(envelope)) = self.package_scopes.get_mut(path) {
                envelope.next_child_index = index;
            }
        }
    }

    pub fn clear_all_package_progress(&mut self) {
        for envelope in self.package_scopes.values_mut().flatten() {
            envelope.next_child_index = 0;
        }
    }

    pub fn select_next_child_scope(&mut self) {
        let Some(cursor) = self.current_cursor.last_mut() else {
            // the cursor vector is empty, which can only happen if
            // `enter_package` was never called, so we just ignore this call
            return;
        };

        let index = *cursor;
        *cursor += 1;

        let child = {
            let mut scope = self.current_scope.borrow_mut();

            match scope.children.get(index).cloned() {
                Some(existing) => existing,
                None => {
                    let new_scope = Scope::new_ref(self.current_scope.clone());
                    scope.children.push(new_scope.clone());

                    new_scope
                }
            }
        };

        self.current_scope = child;
        self.current_cursor.push(0);
    }

    pub fn select_parent_scope(&mut self) {
        if let Some(parent) = self.get_parent_scope() {
            self.current_scope = parent;
            self.current_cursor.pop();
        }
    }

    fn get_parent_scope(&self) -> Option<ScopeRef<'a>> {
        // None if already at the root (package scope)
        self.current_scope.borrow().parent.clone()
    }

    pub fn get_symbol(&self, name: &str) -> Option<SymbolRef<'a>> {
        let mut checking = Some(self.current_scope.clone());

        while let Some(scope) = checking {
            let borrowed = scope.borrow();

            if let Some(symbol) = borrowed.get_local_symbol(name) {
                return Some(symbol);
            }

            checking = borrowed.parent.clone();
        }

        if name.chars().next().map(char::is_uppercase).unwrap_or(false) {
            for path in &self.current_file_wildcard_imports {
                if let Some(Some(envelope)) = self.package_scopes.get(path) {
                    if let Some(symbol) = envelope.scope.borrow().get_local_symbol(name) {
                        return Some(symbol);
                    }
                }
            }
        }

        self.universe_scope.get_local_symbol(name)
    }

    /// Returns None if qualifier cannot be resolved, Some(None) if the
    /// qualifier is recognized but no matching package has (yet?) been analyzed
    /// so it is not known if the symbol exists, Some(Some(None)) if name is not
    /// exported by the referenced package, or finally Some(Some(Some(symbol)))
    /// otherwise (if the symbol exists).
    pub fn get_qualified_symbol(
        &self,
        qualifier: &str,
        name: &str,
    ) -> Option<Option<Option<SymbolRef<'a>>>> {
        if let Some(path) = self.current_file_named_imports.get(qualifier) {
            if let Some(Some(envelope)) = self.package_scopes.get(path) {
                if name.chars().next().map(char::is_uppercase).unwrap_or(false) {
                    Some(Some(envelope.scope.borrow().get_local_symbol(name)))
                } else {
                    Some(Some(None))
                }
            } else {
                // we haven't visited the package (yet?)
                Some(None)
            }
        } else {
            None
        }
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

    pub fn is_symbol_in_current_scope(&self, symbol: SymbolRef<'a>) -> bool {
        self.current_scope.borrow().contains_local_symbol(symbol)
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
            None if infer_from_path => path.rsplit('/').next().unwrap().to_owned(),
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

    pub fn qualifier_exists(&self, qualifier: &str) -> bool {
        self.current_file_named_imports.contains_key(qualifier)
    }

    pub fn is_package_blackbox(&self, qualifier: &str) -> bool {
        if let Some(path) = self.current_file_named_imports.get(qualifier) {
            if let Some(envelope) = self.package_scopes.get(path) {
                return envelope.is_none();
            }
        }

        false
    }
}

impl Default for SymbolTable<'_> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
struct PackageScopeEnvelope<'a> {
    /// Package name (!= package path's last component)
    package_name: Pinned<Span<'a>>,
    /// The package's root scope
    scope: ScopeRef<'a>,
    /// Next child to be selected, for cross-file synergy (allow resuming count)
    next_child_index: usize,
}

impl<'a> PackageScopeEnvelope<'a> {
    fn new(package_name: Pinned<Span<'a>>) -> Self {
        let scope = Scope::new_root_ref();

        Self {
            package_name,
            scope,
            next_child_index: 0,
        }
    }
}

type ScopeRef<'a> = Rc<RefCell<Scope<'a>>>;

// In the Go spec, this is called a block, but that's a bit confusing
// since blocks are lexical elements that don't necessarily exist for
// every scope (e.g., no AST node for "universe"). We also don't want
// AST nodes to be mutable and hold analysis metadata (separation of
// concerns), hence this separate Scope struct.
struct Scope<'a> {
    /// Mapping between name (identifier) and its corresponding symbol
    symbols: HashMap<&'a str, SymbolRef<'a>>,

    /// Parent scope, unless this is the root scope (package block, & universe)
    parent: Option<ScopeRef<'a>>,
    /// Children scopes, if any
    children: Vec<ScopeRef<'a>>,
}

impl<'a> Scope<'a> {
    fn new(parent: Option<ScopeRef<'a>>) -> Self {
        Self {
            symbols: HashMap::new(),

            parent,
            children: Vec::new(),
        }
    }

    fn new_ref(parent: ScopeRef<'a>) -> ScopeRef<'a> {
        Rc::new(RefCell::new(Self::new(Some(parent))))
    }

    fn new_root_ref() -> ScopeRef<'a> {
        // package scopes have no parent
        Rc::new(RefCell::new(Self::new(None)))
    }

    // https://go.dev/ref/spec#Predeclared_identifiers
    fn new_universe() -> Self {
        let mut scope = Self::new(None);

        macro_rules! predeclared_constant {
            ($scope:expr, $id:expr, $value:expr) => {
                $scope.set_local_symbol($id, Symbol::new_predeclared_ref($id, $value))
            };
            ($scope:expr, $id:expr) => {
                predeclared_constant!($scope, $id, ValueRef::from(None))
            };
        }

        macro_rules! predeclared_function {
            ($scope:expr, $id:expr, $params:expr, $variadic:expr, $n_returned:expr) => {
                predeclared_constant!(
                    $scope,
                    $id,
                    ValueRef::from(Value::Function(FunctionValue::new_builtin(
                        $id,
                        $params,
                        $variadic,
                        $n_returned
                    )))
                )
            };
        }

        predeclared_constant!(scope, "true");
        predeclared_constant!(scope, "false");
        predeclared_constant!(scope, "iota");
        predeclared_constant!(scope, "nil"); // not really a constant, but close enough

        predeclared_function!(scope, "len", &["s"], false, 1);
        predeclared_function!(scope, "cap", &["s"], false, 1);
        predeclared_function!(scope, "min", &["n"], true, 1);
        predeclared_function!(scope, "max", &["n"], true, 1);
        predeclared_function!(scope, "panic", &["value"], false, 0);
        predeclared_function!(scope, "recover", &[], false, 1);

        predeclared_function!(scope, "complex", &["realPart", "imaginaryPart"], false, 1);
        predeclared_function!(scope, "real", &["c"], false, 1);
        predeclared_function!(scope, "imag", &["c"], false, 1);

        scope
    }

    fn get_local_symbol(&self, name: &str) -> Option<SymbolRef<'a>> {
        self.symbols.get(name).cloned()
    }

    fn set_local_symbol(&mut self, name: &'a str, symbol: SymbolRef<'a>) -> Option<SymbolRef<'a>> {
        self.symbols.insert(name, symbol)
    }

    fn contains_local_symbol(&self, symbol: SymbolRef<'a>) -> bool {
        self.symbols.values().any(|s| Rc::ptr_eq(s, &symbol))
    }
}

impl fmt::Debug for Scope<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[derive(Debug)]
        struct Scope<'d, 'a> {
            #[allow(dead_code)]
            symbols: &'d HashMap<&'a str, SymbolRef<'a>>,
            // no `parent` to avoid infinite loop
            #[allow(dead_code)]
            children: &'d Vec<ScopeRef<'a>>,
        }

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
    /// Original symbol name within symbol declaration
    declared_name: Pinned<Span<'a>>,
    /// Whether the symbol can be mutated later (e.g., `var`) or not (`const`)
    mutable: bool,
    /// This symbol's current value, including its accumulated security label
    value: ValueRef<'a>,
}

impl<'a> Symbol<'a> {
    fn new(declared_name: Pinned<Span<'a>>, mutable: bool, value: ValueRef<'a>) -> Self {
        Self {
            declared_name,
            mutable,
            value,
        }
    }

    pub fn new_ref(
        declared_name: Pinned<Span<'a>>,
        mutable: bool,
        value: ValueRef<'a>,
    ) -> SymbolRef<'a> {
        Rc::new(RefCell::new(Self::new(declared_name, mutable, value)))
    }

    fn new_predeclared_ref(name: &'a str, value: ValueRef<'a>) -> SymbolRef<'a> {
        Self::new_ref(
            // vv not very pretty, but it should never matter anyway
            Pinned::new(PathBuf::new(), Span::new(name, 0, 0)),
            false,
            value,
        )
    }

    pub fn declared_name(&self) -> &Pinned<Span<'a>> {
        &self.declared_name
    }

    pub fn mutable(&self) -> bool {
        self.mutable
    }

    pub fn value(&self) -> ValueRef<'a> {
        self.value.clone()
    }

    pub fn set_value(&mut self, value: ValueRef<'a>) {
        self.value = value
    }
}
