//! Used exclusively for Stage 1: `RecordDeclarations`
//! (visit top-level declarations).

use parser::ast::{
    BindingDeclSpecNode, DeclNode, FunctionDeclNode, SourceFileNode, TypeDeclSpecNode,
    TypeNameNode, TypeNode,
};

use crate::{
    FullPackagePath,
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    symbols::Symbol,
    values::{FunctionRef, FunctionValue, Value, ValueRef},
};

pub fn visit_source_file<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &SourceFileNode<'a>,
    package_path: FullPackagePath,
) {
    // note that Go doesn't require the package name to match the directory
    // name, it's just a convention, so we must extract the package name from
    // the first file's package clause (and enforce for all other files to use
    // the same name)

    let package_name = ctx.pin(node.package_clause.id);

    let original_name = ctx.symtab_mut().enter_package(package_name, package_path);

    if original_name.content() != node.package_clause.id.content() {
        // the scope already had a different native identifier, meaning that
        // another file has previously declared a different package name for
        // the same package path (which is invalid, so we report the error)

        let previous = original_name;

        ctx.report_error(AnalysisErrorKind::DistinctPackageName {
            previous,
            found: node.package_clause.id,
        });

        return; // skip the file
    }

    for decl in &node.top_level_decls {
        visit_decl(ctx, decl);
    }

    // there should be no package progress to save in the symtab, since
    // we didn't create any sub-package scopes
}

fn visit_decl<'a>(ctx: &mut AnalysisContext<'a>, node: &DeclNode<'a>) {
    match node {
        DeclNode::Const { specs, .. } => visit_binding_decl(ctx, specs, false),
        DeclNode::Var { specs, .. } => visit_binding_decl(ctx, specs, true),
        DeclNode::Type { specs, .. } => visit_type_decl(ctx, specs),
        DeclNode::Function(func_node) => visit_function_decl(ctx, func_node),
    }
}

fn visit_binding_decl<'a>(
    ctx: &mut AnalysisContext<'a>,
    specs: &[BindingDeclSpecNode<'a>],
    mutable: bool,
) {
    for spec in specs {
        visit_binding_decl_spec(ctx, spec, mutable);
    }
}

fn visit_binding_decl_spec<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &BindingDeclSpecNode<'a>,
    mutable: bool,
) {
    for &id in &node.ids {
        let name = ctx.pin(id);
        let value = ValueRef::new_bottom(name.pinned_location());

        let symbol = Symbol::new_ref(name, mutable, value);

        ctx.declare_new_symbol(symbol);
    }
}

fn visit_type_decl<'a>(ctx: &mut AnalysisContext<'a>, specs: &[TypeDeclSpecNode<'a>]) {
    for spec in specs {
        visit_type_decl_spec(ctx, spec);
    }
}

fn visit_type_decl_spec<'a>(ctx: &mut AnalysisContext<'a>, node: &TypeDeclSpecNode<'a>) {
    // every `type T X` (and `type T = X`) declaration registers `T` as a
    // package-scoped symbol whose value is a type-constructor function: this
    // makes `T(x)` at any later call site resolve to a function value, and
    // `visit_call` then detects the type-constructor flag and dispatches the
    // expression as a Go conversion (operand pass-through) rather than as an
    // ordinary call. for aliases (`type T = X`), the conversion semantics
    // collapse to the identity, which is exactly what we want for taint

    let name = ctx.pin(node.id);
    let location = name.pinned_location();

    let func_value = FunctionValue::new_type_constructor(
        FunctionRef::Named(name),
        Some(node.r#type.clone()), // used for composite literals
    );
    let value = ValueRef::new(Value::Function(Box::new(func_value)), location);

    let symbol = Symbol::new_ref(name, false, value);

    ctx.declare_new_symbol(symbol);
}

fn visit_function_decl<'a>(ctx: &mut AnalysisContext<'a>, node: &FunctionDeclNode<'a>) {
    if node.name.content() == "init" {
        // init functions are not actually declared (and there may be multiple
        // defined, even in the same file). note that this only applies for
        // top-level declarations (i.e., package scope), not anywhere else
        return;
    }

    let name = ctx.pin(node.name);
    let value = ValueRef::new_bottom(name.pinned_location());

    let symbol = Symbol::new_ref(name, false, value);

    ctx.declare_function_or_method(node.receiver.as_ref(), symbol);
}

pub fn receiver_base_type_name<'a>(r#type: &TypeNode<'a>) -> Option<&'a str> {
    // per the Go spec, a method receiver type must be either a defined type `T`
    // or a pointer to one (`*T`). generic methods take the form `(*T[K, V])`,
    // where the type parameter list does not affect identity for the purposes
    // of method-set membership: `methodName` is the same method on `T`
    // regardless of whether it's referred to as `T`, `*T`, `T[A]`, or `*T[A]`

    match r#type {
        TypeNode::Name(TypeNameNode {
            package: None, id, ..
        }) => Some(id.content()),
        TypeNode::Pointer { base } => receiver_base_type_name(base),
        TypeNode::Name(_)
        | TypeNode::Channel { .. }
        | TypeNode::Array { .. }
        | TypeNode::Slice { .. }
        | TypeNode::Map { .. }
        | TypeNode::Struct { .. }
        | TypeNode::Interface { .. }
        | TypeNode::Function { .. } => None, // invalid or unrecognized
    }
}
