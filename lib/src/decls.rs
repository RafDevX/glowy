//! Used exclusively for Stage 1: `RecordDeclarations`
//! (visit top-level declarations).

use std::rc::Rc;

use parser::ast::{
    BindingDeclSpecNode, DeclNode, FunctionDeclNode, ImportNode, ImportSpecNode, SourceFileNode,
    TypeDeclSpecNode, TypeNameNode, TypeNode,
};

use crate::{
    FullPackagePath,
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    symbols::Symbol,
    types::TypeInfo,
    values::{FunctionRef, FunctionValue, Value, ValueRef},
};

pub fn visit_source_file<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &SourceFileNode<'a>,
    package_path: &FullPackagePath,
) {
    // note that Go doesn't require the package name to match the directory
    // name, it's just a convention, so we must extract the package name from
    // the first file's package clause (and enforce for all other files to use
    // the same name)

    let package_name = ctx.pin(node.package_clause.id);

    let original_name = ctx.enter_package(package_name, package_path.clone());

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

    for import in &node.imports {
        visit_import(ctx, import);
    }

    for decl in &node.top_level_decls {
        visit_decl(ctx, decl);
    }

    // there should be no package progress to save in the symtab, since
    // we didn't create any sub-package scopes
}

fn visit_import<'a>(ctx: &mut AnalysisContext<'a>, node: &ImportNode<'a>) {
    for spec in &node.specs {
        visit_import_spec(ctx, spec);
    }
}

fn visit_import_spec<'a>(ctx: &mut AnalysisContext<'a>, node: &ImportSpecNode<'a>) {
    // discard the returned value: any potential errors are reported later in
    // the analysis process, for now we just want to try registering all imports

    let qualifier = node
        .identifier
        .as_ref()
        .map(parser::Span::content)
        .map(str::to_owned);

    if qualifier.as_deref() == Some("_") {
        // blank identifier; skip
        return;
    }

    let _ = ctx.register_import_spec(qualifier, node.path.clone(), true);
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
    let declared_type = if let Some(r#type) = &node.r#type {
        let (types, symtab) = ctx.types_mut_with_symtab();

        types.resolve(symtab, r#type)
    } else {
        None
    };

    for &id in &node.ids {
        if id.content() == "_" {
            // blank identifier
            continue;
        }

        let name = ctx.pin(id);
        let value = ValueRef::new_bottom(
            name.pinned_location(),
            declared_type.clone(), // cheap
        );

        let symbol = Symbol::new_ref(name, mutable, value, None);

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

    let target_type = register_type_in_registry(ctx, node);

    if let Some(target_type) = target_type.as_ref() {
        // we register methods to the interface type to help with discovery, as
        // otherwise I.f() would lead to an invalid selection error being
        // reported. however, this is really just a convenience because we do
        // not actually model interfaces, and it is not sound: any real
        // interface implementations might have insecure side-effects!
        target_type.register_direct_interface_methods(ctx, node);
    }

    let decl_context = {
        let (types, symtab) = ctx.types_mut_with_symtab();

        types.current_declaration_context(symtab).unwrap()
    };

    let func_value = FunctionValue::new_type_constructor(
        FunctionRef::new_named(name),
        // used for composite literals and resolved in its declaration context
        Some((node.r#type.clone(), decl_context)),
        target_type,
    );

    let value = ValueRef::new(Value::Function(Box::new(func_value)), location, None);

    let symbol = Symbol::new_ref(name, false, value, None);

    ctx.declare_new_symbol(symbol);
}

fn register_type_in_registry<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &TypeDeclSpecNode<'a>,
) -> Option<Rc<TypeInfo<'a>>> {
    let package = ctx.symtab().current_package_path()?.clone();
    let name = node.id.content();

    // we need to extract this before ctx becomes locked away when we &mut types
    let current_file = ctx
        .current_file()
        .expect("some file should be under analysis");

    let (types, symtab) = ctx.types_mut_with_symtab();

    if node.alias {
        types
            .declare_alias(symtab, package.clone(), name, &node.r#type)
            .or_else(|| {
                // target type chain is unresolvable for now, so just queue it
                // for later retry

                types.queue_pending_alias(symtab, package, name, node.r#type.clone());

                None
            })
    } else {
        let info = types.declare(symtab, package, name, &node.r#type, current_file);

        // just in case this is a struct with any unresolved field types
        types.queue_pending_field_resolutions_for(symtab, &info);

        Some(info)
    }
}

fn visit_function_decl<'a>(ctx: &mut AnalysisContext<'a>, node: &FunctionDeclNode<'a>) {
    if node.name.content() == "init" && node.receiver.is_none() {
        // init functions are not actually declared (and there may be multiple
        // defined, even in the same file). note that this only applies for
        // top-level declarations (i.e., package scope), not anywhere else
        return;
    }

    let name = ctx.pin(node.name);
    let value = ValueRef::new_bottom(name.pinned_location(), None);

    let symbol = Symbol::new_ref(name, false, value, None);

    // if this is a method (has a receiver), also register it on the receiver's
    // TypeInfo so typed dispatch can later look it up by name.
    // if the receiver type isn't yet registered (sibling file or import order),
    // queue for the deferred resolution.
    // we do this before `declare_function_or_method` to avoid cloning the
    // SymbolRef except when actually necessary
    if let Some(receiver) = node.receiver.as_ref()
        && let Some(receiver_type_name) = receiver_base_type_name(&receiver.r#type)
        && let Some(package) = ctx.symtab().current_package_path().cloned()
    {
        // remember this name unconditionally, so `InvalidSelectionBase` can
        // soften any later unresolved `s.X` into a sound blackbox-method
        // fallback whenever `X` is plausibly a method anywhere in the corpus
        ctx.types_mut().record_method_name(node.name.content());

        if let Some(r#type) = ctx.types().lookup(&package, receiver_type_name) {
            // receiver type was successfully resolved, so we can register the
            // method directly

            r#type.register_method(node.name.content(), Rc::clone(&symbol));
        } else {
            // receiver type chain is unresolvable for now, so just queue it for
            // later retry

            ctx.types_mut().queue_pending_method(
                package,
                receiver_type_name,
                node.name.content(),
                Rc::clone(&symbol),
            );
        }
    }

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
