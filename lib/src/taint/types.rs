use parser::{
    Span,
    ast::{TypeNameNode, TypeNode},
};

use crate::{
    context::AnalysisContext,
    symbols::{QualifiedSymbolResolutionResult, SymbolRef},
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

    // this always converges since Go does not allow cyclic type defs
    loop {
        let symbol = lookup_symbol_for_type_resolution(ctx, package, id)?;

        // cloning is necessary because of AssumedImmutable with as_function
        let value = symbol.borrow().value().get().clone_inner();

        let next: TypeNameNode<'a> = {
            // this might coerce, so it might mutate, hence the clone above
            let func = value.as_function()?;

            if !func.is_type_constructor() {
                // cannot resolve further
                return None;
            }

            let underlying = func.known_underlying_type()?;
            let TypeNode::Name(next) = underlying else {
                // anything other than another indirection (Name) is a success!
                return Some(underlying.clone());
            };

            next.clone()
        };

        symbol.borrow_mut().set_value(value); // apply potential coercion

        (package, id) = (next.package, next.id);
    }
}

fn lookup_symbol_for_type_resolution<'a>(
    ctx: &AnalysisContext<'a>,
    package: Option<Span<'a>>,
    id: Span<'a>,
) -> Option<SymbolRef<'a>> {
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
