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

// We can't use temporary scopes and push/pop them away, because
// analysis requires multiple iterations to stabilize, meaning we
// need to remember symbols even after leaving that branch.

use std::{cell::RefCell, collections::HashMap, rc::Rc};

use crate::{FullPackagePath, ScopedSpan};

pub struct SymbolTable<'a> {
    /// Universe block with pre-declared identifiers
    universe_scope: Scope<'a>,
    /// Root scopes associated with each package
    package_scopes: HashMap<FullPackagePath, PackageScopeEnvelope<'a>>,

    /// Currently selected (package or sub-package) scope
    current_scope: ScopeRef<'a>,
    /// Index in parent scope's children array, for each level (last = current)
    current_cursor: Vec<usize>,
}

impl<'a> SymbolTable<'a> {
    pub fn new() -> Self {
        Self {
            universe_scope: Scope::new(None), // TODO: populate universe
            package_scopes: HashMap::new(),

            // For simplicity in the rest of the code, we don't use Option for
            // current_scope, but instead initialize it at a dead end not
            // actually corresponding to any package; this means SymbolTable is
            // only truly active after the first `enter_package` invocation.
            // This dead end will then be automatically deleted (by Rc).
            current_scope: Scope::new_root_ref(),
            current_cursor: Vec::new(),
        }
    }

    pub fn enter_package(
        &mut self,
        name: ScopedSpan<'a>,
        path: FullPackagePath,
    ) -> &ScopedSpan<'a> {
        // note that name cannot be derived from path!
        // (must be taken from package clause, may differ from dirname)

        let envelope = self
            .package_scopes
            .entry(path)
            .or_insert_with(|| PackageScopeEnvelope::new(name));

        self.current_scope = envelope.scope.clone();
        self.current_cursor = Vec::new();

        &envelope.package_name
    }

    pub fn select_first_child_scope(&mut self) {
        let child = if let Some(child) = self.current_scope.clone().borrow().children.first() {
            child.clone()
        } else {
            let new_scope = Scope::new_ref(self.current_scope.clone());
            self.current_scope
                .borrow_mut()
                .children
                .push(new_scope.clone());

            new_scope
        };

        self.current_scope = child;
        self.current_cursor.push(0);
    }

    fn get_parent_scope(&self) -> Option<ScopeRef<'a>> {
        // None if already at the root (package scope)
        self.current_scope.borrow().parent.clone()
    }

    pub fn select_parent_scope(&mut self) {
        if let Some(parent) = self.get_parent_scope() {
            self.current_scope = parent;
            self.current_cursor.pop();
        }
    }

    pub fn select_next_sibling_scope(&mut self) {
        if let Some(parent) = self.get_parent_scope() {
            if let Some(index) = self.current_cursor.last_mut() {
                let sibling = if let Some(sibling) = parent.borrow().children.get(*index + 1) {
                    sibling.clone()
                } else {
                    let new_scope = Scope::new_ref(parent.clone());
                    parent.borrow_mut().children.push(new_scope.clone());

                    new_scope
                };

                self.current_scope = sibling;
                *index += 1;
            }
        }
    }

    pub fn get_symbol(&self, name: &str) -> Option<SymbolRef> {
        let mut checking = Some(self.current_scope.clone());

        while let Some(scope) = checking {
            let borrowed = scope.borrow();

            if let Some(symbol) = borrowed.get_local_symbol(name) {
                return Some(symbol);
            }

            checking = borrowed.parent.clone();
        }

        if name.chars().next().map(char::is_uppercase).unwrap_or(false) {
            todo!()
        }

        self.universe_scope.get_local_symbol(name)
    }
}

struct PackageScopeEnvelope<'a> {
    /// Package name (!= package path's last component)
    package_name: ScopedSpan<'a>,
    /// The package's root scope
    scope: ScopeRef<'a>,
}

impl<'a> PackageScopeEnvelope<'a> {
    fn new(package_name: ScopedSpan<'a>) -> Self {
        let scope = Scope::new_root_ref();

        Self {
            package_name,
            scope,
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
    symbols: HashMap<&'a str, SymbolRef>,

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

    fn get_local_symbol(&self, name: &str) -> Option<SymbolRef> {
        self.symbols.get(name).cloned()
    }
}

// Scopes cannot own Symbols directly because multiple scopes may need to refer
// to the same symbol (e.g., a closure can refer to variables in the outer scope
// and both functions, inner and outer, share a reference to the same symbol)
pub type SymbolRef = Rc<RefCell<Symbol>>;

pub struct Symbol {
    /// Whether the symbol can be mutated later (e.g., `var`) or not (`const`)
    mutable: bool,
    // ... label_backtrace
}
