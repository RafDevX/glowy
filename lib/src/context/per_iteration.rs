//! Models the fresh variable created on each iteration of a Go range loop:
//!
//! ```go
//! for _, x := range xs {
//!     fs = append(fs, func() int { return x })
//! }
//! ```
//!
//! Each closure must capture its iteration's `x`, not the loop's merged symbol.
//! We retain one cell per binding/control-flow path, propagating or merging
//! writes only between paths that may represent the same iteration.

use std::{
    borrow::Cow,
    collections::{HashMap, hash_map::Entry},
    rc::Rc,
};

use parser::Span;

use crate::{
    Pinned,
    context::ControlFlowPath,
    labels::LabelBacktraceKind,
    snapshots::SnapshotAware,
    symbols::{Symbol, SymbolRef},
    values::Mergeable,
};

#[derive(Default)]
pub struct PerIterationBindings<'a>(HashMap<Pinned<'a, Span<'a>>, PerIterationBinding<'a>>);

impl<'a> PerIterationBindings<'a> {
    pub fn register(&mut self, symbol: &SymbolRef<'a>, path: ControlFlowPath<'a>) {
        let declaration = symbol.borrow().declared_name();

        match self.0.entry(declaration) {
            Entry::Occupied(mut entry) => {
                if entry.get().tracks(symbol) {
                    // a range body is revisited while its data-flow state
                    // converges; keep cells already retained by function
                    // values, but initialize them for the new iteration
                    entry.get_mut().record_value(&path);
                } else {
                    entry.insert(PerIterationBinding::new(symbol, path));
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(PerIterationBinding::new(symbol, path));
            }
        }
    }

    pub fn contains(&self, symbol: &SymbolRef<'a>) -> bool {
        let declaration = symbol.borrow().declared_name();

        self.0
            .get(&declaration)
            .is_some_and(|binding| binding.tracks(symbol))
    }

    pub fn capture_cell(
        &mut self,
        symbol: &SymbolRef<'a>,
        path: ControlFlowPath<'a>,
    ) -> Option<SymbolRef<'a>> {
        self.binding_mut(symbol)
            .map(|binding| binding.capture_cell(path))
    }

    pub fn record_value(&mut self, symbol: &SymbolRef<'a>, path: &ControlFlowPath<'a>) {
        if let Some(binding) = self.binding_mut(symbol) {
            binding.record_value(path);
        }
    }

    pub fn record_cell_value(&mut self, symbol: &SymbolRef<'a>) {
        let declaration = symbol.borrow().declared_name();

        if let Some(binding) = self.0.get_mut(&declaration) {
            binding.record_cell_value(symbol);
        }
    }

    fn binding_mut(&mut self, symbol: &SymbolRef<'a>) -> Option<&mut PerIterationBinding<'a>> {
        let declaration = symbol.borrow().declared_name();
        let binding = self.0.get_mut(&declaration)?;

        binding.tracks(symbol).then_some(binding)
    }
}

struct PerIterationBinding<'a> {
    source: SymbolRef<'a>,
    cells: Vec<IterationCell<'a>>,
}

impl<'a> PerIterationBinding<'a> {
    fn new(source: &SymbolRef<'a>, path: ControlFlowPath<'a>) -> Self {
        let initial_cell = IterationCell::new(path, copy_symbol(source));

        Self {
            source: Rc::clone(source),
            cells: vec![initial_cell],
        }
    }

    fn tracks(&self, symbol: &SymbolRef<'a>) -> bool {
        Rc::ptr_eq(&self.source, symbol)
    }

    fn capture_cell(&mut self, path: ControlFlowPath<'a>) -> SymbolRef<'a> {
        if let Some(cell) = self.cells.iter().find(|cell| cell.path == path) {
            // this cell is authoritative: a closure call may have written to
            // it since it was created, independently of the source symbol

            return Rc::clone(&cell.symbol);
        }

        let mut compatible = self
            .cells
            .iter()
            .filter(|cell| cell.is_path_compatible_with(&path));

        let first = compatible
            .next()
            .expect("a per-iteration binding always has an initial cell");

        let symbol = copy_symbol(&first.symbol);

        for cell in compatible {
            merge_symbol(&cell.symbol, &symbol);
        }

        let new_cell = IterationCell::new(path, Rc::clone(&symbol));

        self.cells.push(new_cell);

        symbol
    }

    fn record_value(&mut self, path: &ControlFlowPath<'a>) {
        let current = copy_symbol(&self.source);

        self.propagate_value(path, current);
    }

    fn record_cell_value(&mut self, symbol: &SymbolRef<'a>) {
        let Some(path) = self
            .cells
            .iter()
            .find(|cell| Rc::ptr_eq(&cell.symbol, symbol))
            .map(|cell| cell.path.clone())
        else {
            return;
        };

        let current = copy_symbol(symbol);

        self.propagate_value(&path, current);
    }

    fn propagate_value(&mut self, path: &ControlFlowPath<'a>, current: SymbolRef<'a>) {
        let mut found_exact = false;

        for cell in &self.cells {
            if cell.path == *path {
                found_exact = true;

                overwrite_symbol(&current, &cell.symbol);
            } else if cell.path.starts_with(path) {
                // a write before a split is observed on every descendant path
                overwrite_symbol(&current, &cell.symbol);
            } else if path.starts_with(&cell.path) {
                // a write inside a descendant branch may or may not execute
                // for a cell captured before that branch
                merge_symbol(&current, &cell.symbol);
            }
        }

        if !found_exact {
            let new_cell = IterationCell::new(path.clone(), current);

            self.cells.push(new_cell);
        }
    }
}

struct IterationCell<'a> {
    path: ControlFlowPath<'a>,
    symbol: SymbolRef<'a>,
}

impl<'a> IterationCell<'a> {
    fn new(path: ControlFlowPath<'a>, symbol: SymbolRef<'a>) -> Self {
        Self { path, symbol }
    }

    fn is_path_compatible_with(&self, other: &ControlFlowPath<'a>) -> bool {
        self.path.starts_with(other) || other.starts_with(&self.path)
    }
}

fn copy_symbol<'a>(symbol: &SymbolRef<'a>) -> SymbolRef<'a> {
    let symbol = symbol.borrow();

    Symbol::new_ref(
        symbol.declared_name(),
        symbol.mutable(),
        symbol.value().get().copy_by_value_semantics(),
        symbol.known_const().cloned(),
    )
}

fn overwrite_symbol<'a>(source: &SymbolRef<'a>, target: &SymbolRef<'a>) {
    let (value, known_const) = {
        let source = source.borrow();

        (
            source.value().get().copy_by_value_semantics(),
            source.known_const().cloned(),
        )
    };

    target.borrow_mut().set_value(value, known_const);
}

fn merge_symbol<'a>(source: &SymbolRef<'a>, target: &SymbolRef<'a>) {
    let (target_value, target_const) = {
        let target = target.borrow();

        (target.value().get(), target.known_const().cloned())
    };
    let (source_value, source_const) = {
        let source = source.borrow();

        (source.value().get(), source.known_const().cloned())
    };

    if target_value.snapshot_aware_eq(&source_value) && target_const == source_const {
        return;
    }

    let merged = target_value.merge_with(
        &source_value,
        LabelBacktraceKind::ClosureCaptureBinding,
        Cow::Borrowed(target_value.location()),
    );
    let known_const = if target_const == source_const {
        target_const
    } else {
        None
    };

    target.borrow_mut().set_value(merged, known_const);
}
