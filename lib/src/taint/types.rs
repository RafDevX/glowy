use glowy_go_parser::{
    Span,
    ast::{TypeDeclSpecNode, TypeNode},
};

use crate::{
    context::AnalysisContext,
    labels::FunctionRef,
    symbols::{QualifiedSymbolResolutionResult, Symbol, SymbolRef},
    types::{TypeDeclarationContext, TypeRegistry},
    values::{FunctionValue, Value, ValueRef},
};

pub fn resolve_named_underlying<'a>(
    ctx: &AnalysisContext<'a>,
    r#type: &TypeNode<'a>,
) -> Option<TypeNode<'a>> {
    let TypeNode::Name(initial) = r#type else {
        // if the input is not a Name, it's already its own underlying type
        return Some(r#type.clone());
    };

    let (mut package, mut id) = (initial.package, initial.id);
    let mut decl_context = None;

    // this always converges since Go does not allow cyclic type defs
    loop {
        let symbol = lookup_symbol_for_type_resolution(
            ctx,
            decl_context.as_ref(), // if there is one
            package,
            id,
        )?;

        // cloning is necessary because of AssumedImmutable with as_function
        let (value, known_const) = {
            let borrowed = symbol.borrow();

            (
                symbol.borrow().value().get().clone_inner(),
                borrowed.known_const().cloned(),
            )
        };

        let (next, next_decl_context) = {
            // this might coerce, so it might mutate, hence the clone above
            let func = value.as_function()?;

            if !func.is_type_constructor() {
                // cannot resolve further
                return None;
            }

            let (underlying, underlying_decl_context) = func.declared_underlying_type()?;

            let TypeNode::Name(next) = underlying else {
                // anything other than another indirection (Name) is a success!
                return Some(underlying.clone());
            };

            (next.clone(), underlying_decl_context.clone())
        };

        // apply potential coercion
        symbol.borrow_mut().set_value(value, known_const);

        (package, id) = (next.package, next.id);
        decl_context = Some(next_decl_context);
    }
}

pub fn is_known_type<'a>(ctx: &mut AnalysisContext<'a>, r#type: &TypeNode<'a>) -> bool {
    if let TypeNode::Name(name) = r#type.strip_pointers()
        && name.package.is_none()
        && name.args.is_empty()
        && ctx.is_type_param_in_scope(name.id.content())
    {
        return true;
    }

    // type resolution below never really "fails" for qualified names since a
    // placeholder stable identity is generated, so before we do that we check
    // if there is a matching qualified symbol we can base off our assessment on
    if let TypeNode::Name(name) = r#type.strip_pointers()
        && name.package.is_some()
        && let Some(symbol) = lookup_symbol_for_type_resolution(ctx, None, name.package, name.id)
    {
        let value = symbol.borrow().value().get();

        return value.is_function()
            && value
                .as_function()
                // ^^^ it is safe to perform as_function without first doing
                // `value.clone_inner()` because we already checked is_function,
                // so an upgrade will never happen and we won't violate the
                // restrictions imposed by AssumedImmutable
                .is_some_and(|func| func.is_type_constructor());
    }

    let (types, symtab) = ctx.types_mut_with_symtab();

    types.resolve(symtab, r#type).is_some()
}

fn lookup_symbol_for_type_resolution<'a>(
    ctx: &AnalysisContext<'a>,
    declaration_context: Option<&TypeDeclarationContext<'a>>,
    package: Option<Span<'a>>,
    id: Span<'a>,
) -> Option<SymbolRef<'a>> {
    if let Some(context) = declaration_context {
        if package.is_none() {
            return ctx.symtab().get_symbol_from_lexical_scope(
                context.scope(),
                context.imports(),
                id.content(),
            );
        }

        return ctx.symtab().get_symbol_in_file_context(
            context.package(),
            context.imports(),
            package.as_ref().map(Span::content),
            id.content(),
        );
    }

    match package {
        None => ctx.symtab().get_symbol(id.content()),
        Some(pkg) => match ctx
            .symtab()
            .get_qualified_symbol(pkg.content(), id.content())
        {
            QualifiedSymbolResolutionResult::Success(symbol) => Some(symbol),
            QualifiedSymbolResolutionResult::UnknownQualifier
            | QualifiedSymbolResolutionResult::UnknownSymbol
            | QualifiedSymbolResolutionResult::PendingAnalysis => None,
        },
    }
}

pub fn visit_local_type_decl<'a>(ctx: &mut AnalysisContext<'a>, specs: &[TypeDeclSpecNode<'a>]) {
    for node in specs {
        visit_local_type_decl_spec(ctx, node);
    }
}

fn visit_local_type_decl_spec<'a>(ctx: &mut AnalysisContext<'a>, node: &TypeDeclSpecNode<'a>) {
    let name = ctx.pin(node.id);

    if ctx.symtab().get_symbol_by_declaration(name).is_some() {
        // the retained lexical scope already contains this declaration from a
        // previous stabilization pass
        return;
    }

    let package = ctx
        .symtab()
        .current_package_path()
        .expect("a local type must be declared inside a package")
        .clone();

    let target_type = if node.alias {
        let (types, symtab) = ctx.types_mut_with_symtab();

        types.resolve(symtab, &node.r#type)
    } else {
        let placeholder = TypeRegistry::declare_local_placeholder(package, node.id.content());

        Some(placeholder)
    };

    let decl_context = {
        let (types, symtab) = ctx.types_mut_with_symtab();

        types.current_declaration_context(symtab).unwrap()
    };

    let func_value = FunctionValue::new_type_constructor(
        FunctionRef::new_named(name),
        Some((node.r#type.clone(), decl_context)),
        target_type.clone(),
    );

    let value = ValueRef::new(
        Value::Function(Box::new(func_value)),
        name.pinned_location(),
        None,
    );

    ctx.declare_new_symbol(Symbol::new_ref(name, false, value, None));

    if !node.alias {
        let current_file = ctx
            .current_file()
            .expect("some file should be under analysis");

        let target_type = target_type.expect("defined local types have an identity");

        let (types, symtab) = ctx.types_mut_with_symtab();

        types.define_local(symtab, &target_type, &node.r#type, current_file);

        target_type.register_direct_interface_methods(ctx, node);
    }
}
