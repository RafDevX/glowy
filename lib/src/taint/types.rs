use parser::{Span, ast::TypeNode};

use crate::{
    context::AnalysisContext,
    symbols::{QualifiedSymbolResolutionResult, SymbolRef},
    types::TypeDeclarationContext,
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

fn lookup_symbol_for_type_resolution<'a>(
    ctx: &AnalysisContext<'a>,
    declaration_context: Option<&TypeDeclarationContext>,
    package: Option<Span<'a>>,
    id: Span<'a>,
) -> Option<SymbolRef<'a>> {
    if let Some(context) = declaration_context {
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
