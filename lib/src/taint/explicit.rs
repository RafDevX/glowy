use std::{borrow::Cow, cmp, rc::Rc};

use parser::{
    Annotation, Location, Span,
    ast::{
        AssignmentKind, AssignmentNode, BindingDeclSpecNode, ExprNode, LiteralNode,
        ShortVarDeclNode,
    },
};

use super::{annotations, exprs};
use crate::{
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{Label, LabelBacktrace, LabelBacktraceKind},
    policy::{SinkDescriptor, SinkKind},
    symbols::Symbol,
    taint::{enforcement, mutation::LeftValue},
    types::TypeInfo,
    values::{SimpleConstValue, ValueRef},
};

pub fn visit_binding_decl<'a>(
    ctx: &mut AnalysisContext<'a>,
    specs: &[BindingDeclSpecNode<'a>],
    mutable: bool,
    location: &Location,
    annotation: Option<&Annotation<'a>>,
) {
    let mut prev_with_exprs = None;

    for spec in specs {
        visit_binding_decl_spec(
            ctx,
            spec,
            mutable,
            false,
            location,
            annotation,
            prev_with_exprs,
        );

        if !spec.exprs.is_empty() {
            prev_with_exprs = Some(spec);
        }
    }
}

fn visit_binding_decl_spec<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &BindingDeclSpecNode<'a>,
    mutable: bool,
    short: bool, // allows redeclaration in some circumstances
    location: &Location,
    annotation: Option<&Annotation<'a>>,
    prev_with_exprs: Option<&BindingDeclSpecNode<'a>>,
) {
    let declared_type = if let Some(r#type) = &node.r#type {
        let (types, symtab) = ctx.types_mut_with_symtab();

        types.resolve(symtab, r#type)
    } else {
        None
    };

    if node.exprs.is_empty()
        && !short
        && let Some(r#type) = &node.r#type
    {
        // no initialization expression; zero-value is used;
        // for our purposes, we just need to remember the decl exists
        // (branch label is irrelevant in this case)

        for name in &node.ids {
            if name.content() == "_" {
                // blank identifier
                continue;
            }

            let pinned = ctx.pin(*name);
            let value = ValueRef::new_bottom(
                pinned.pinned_location(),
                declared_type.clone(), // cheap
            );

            let symbol = Symbol::new_ref(
                pinned,
                mutable,
                value,
                SimpleConstValue::zero_value_for_type(r#type),
            );

            ctx.declare_new_symbol(symbol);
        }

        return;
    }

    let spec_exprs = if node.exprs.is_empty()
        && node.r#type.is_none()
        && !short
        && !mutable // const
        && let Some(prev) = prev_with_exprs
    {
        // Go spec: "Within a parameterized const declaration list the
        // expression list may be omitted from any but the first ConstSpec. Such
        // an empty list is equivalent to the textual substitution of the first
        // preceding non-empty expression list and its type if any. Omitting the
        // list of expressions is therefore equivalent to repeating the previous
        // list. The number of identifiers must be equal to the number of
        // expressions in the previous list."
        &prev.exprs
    } else {
        &node.exprs
    };

    let mut rhs_values = expand_rhs_values(
        exprs::visit_multi_exprs_with_consts(ctx, spec_exprs),
        node.ids.len(),
    );

    // override the rhs values' declared_type with the spec's, if any: a typed
    // declaration necessarily produces a value of the specified type regardless
    // of the expr's own static type, per the Go spec
    if let Some(r#type) = &declared_type {
        for (rhs, _) in &mut rhs_values {
            rhs.set_declared_type(Rc::clone(r#type));
        }
    }

    visit_raw_binding_decl_spec(
        ctx,
        &node.ids,
        rhs_values.into_iter(),
        mutable,
        short,
        location,
        annotation,
        declared_type.as_ref(),
    );
}

// for declaration-like cases more generic than an actual declaration node
#[expect(clippy::too_many_arguments, reason = "No obvious arg aggregation")]
#[expect(
    clippy::too_many_lines,
    reason = "Very tight coupling means it would become more confusing if split up"
)]
pub fn visit_raw_binding_decl_spec<'a>(
    ctx: &mut AnalysisContext<'a>,
    ids: &[Span<'a>],
    rhs_values: impl ExactSizeIterator<Item = (ValueRef<'a>, Option<SimpleConstValue>)>,
    mutable: bool,
    short: bool, // allows redeclaration in some circumstances
    location: &Location,
    annotation: Option<&Annotation<'a>>,
    declared_type: Option<&Rc<TypeInfo<'a>>>,
) {
    if ids.len() != rhs_values.len() {
        ctx.report_error(AnalysisErrorKind::UnevenBindingDeclSpec {
            location: location.clone(),
            left: ids.len(),
            right: rhs_values.len(),
        });

        return;
    }

    let pinned = ctx.pin(location.clone());

    let mut redeclarations = vec![];
    let mut any_new = false;

    for (name, (rhs, known_const)) in ids.iter().copied().zip(rhs_values) {
        let mut explicit_backtrace = None;
        let mut subtract = Label::Bottom;

        if let Some(annotation) = annotation
            && let Some(directive) = annotations::parse_supported_directive(ctx, annotation)
        {
            match directive {
                annotations::DeclDirective::Label => {
                    explicit_backtrace = LabelBacktrace::new_root(
                        LabelBacktraceKind::ExplicitAnnotation,
                        Label::from_tags(&annotation.tags),
                        Some(name.content()),
                        pinned.clone(),
                    );
                }
                annotations::DeclDirective::Revoke => {
                    if let Some(label) = annotations::resolve_revocation_label(ctx, annotation) {
                        subtract = label;
                    }
                }
                annotations::DeclDirective::AllowSink | annotations::DeclDirective::DenySink => {
                    let sink = SinkDescriptor::new(
                        SinkKind::Declaration,
                        directive == annotations::DeclDirective::AllowSink,
                        &annotation.tags,
                        location.clone(), // spec, not annotation
                    );

                    if let Some(sink) = sink {
                        enforcement::trigger_sink(ctx, Cow::Owned(sink), rhs.backtrace());
                    } else {
                        ctx.report_error(AnalysisErrorKind::InvalidDenySinkSemantics {
                            location: annotation.location.clone(),
                        });
                    }
                }
                annotations::DeclDirective::Assert => {
                    enforcement::trigger_assertion(
                        ctx,
                        &Label::sequence_from_tags(&annotation.tags),
                        rhs.backtrace(),
                        location.clone(),
                    );
                }
            }
        }

        // only check here since `var _ = value` should still be accepted as a
        // valid sink/assertion point, otherwise user might misinterpret absence
        // of errors as "all good" (even though nothing was ever checked)
        if name.content() == "_" {
            // blank identifier, so we don't really need to do anything else
            // except visiting the expression to process e.g. function calls
            // (needed to detect insecure flows wrt integrity, for example),
            // but this was necessarily already done or we wouldn't have the
            // corresponding value

            continue;
        }

        let declaration = ctx.pin(name);

        let existing_declaration = if short {
            ctx.symtab()
                .get_declared_in_current_scope(name.content())
                .and_then(|existing| {
                    let existing = existing.borrow().declared_name();

                    matches!(
                        declaration
                            .pinned_location()
                            .partial_cmp(&existing.pinned_location()),
                        None | Some(cmp::Ordering::Greater)
                    )
                    .then_some(existing)
                })
        } else {
            None
        };

        let (backtrace_kind, declared_symbol) = if let Some(existing) = existing_declaration {
            // a short declaration may redeclare a variable from the same block
            // as long as another non-blank identifier is new. this is an
            // assignment to the existing variable, not a shadowing declaration
            redeclarations.push(AnalysisErrorKind::IllegalRedeclaration {
                previous: existing,
                found: name,
            });

            (LabelBacktraceKind::Assignment, None)
        } else {
            let initial_value = ValueRef::new_bottom(
                pinned.clone(),
                declared_type.cloned(), // cheap
            );

            let symbol = Symbol::new_ref(
                declaration,
                true, // initially mutable so initialization can assign to it
                initial_value,
                None,
            );

            any_new = true;

            ctx.declare_new_symbol(Rc::clone(&symbol));

            (LabelBacktraceKind::DeclarationInitialization, Some(symbol))
        };

        // all rhs expressions were evaluated before this loop, so assigning a
        // redeclared name here preserves Go's simultaneous assignment semantics

        name.assign(
            ctx,
            backtrace_kind,
            rhs,
            known_const,
            true,
            explicit_backtrace.as_ref(),
            &subtract,
            location,
        );

        // now, after assigning, we can set the symbol to immutable if that was
        // the case (before, we created it as mutable to allow the assignment)
        if !mutable && let Some(symbol) = declared_symbol {
            symbol.borrow_mut().mark_immutable();
        }
    }

    if !redeclarations.is_empty() && !any_new {
        // does not meet criteria for valid redeclaration
        // (at least 1 non-blank identifier must be new)
        for error in redeclarations {
            ctx.report_error(error);
        }
    }
}

pub fn visit_short_var_decl<'a>(ctx: &mut AnalysisContext<'a>, node: &ShortVarDeclNode<'a>) {
    // scope trees survive stabilization passes, so hide variables left behind
    // by an earlier visit to this declaration before evaluating its RHS: per
    // the Go spec, their scope begins only after the short var decl. the normal
    // declaration path below recreates them after the RHS has been evaluated
    for name in node.ids.iter().filter(|name| name.content() != "_") {
        let declaration = ctx.pin(*name);

        ctx.symtab_mut()
            .hide_current_symbol_declared_at(declaration);
    }

    let rhs_values = exprs::visit_multi_exprs_with_consts(ctx, &node.exprs);

    visit_short_var_decl_with(ctx, node, rhs_values);
}

pub fn visit_short_var_decl_with<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &ShortVarDeclNode<'a>,
    rhs_values: Vec<(ValueRef<'a>, Option<SimpleConstValue>)>,
) {
    let rhs_values = expand_rhs_values(rhs_values, node.ids.len());

    visit_raw_binding_decl_spec(
        ctx,
        &node.ids,
        rhs_values.into_iter(),
        true,
        true,
        &node.location,
        node.annotation.as_deref(),
        None,
    );
}

pub fn visit_assignment<'a>(ctx: &mut AnalysisContext<'a>, node: &AssignmentNode<'a>) {
    let rhs_values = exprs::visit_multi_exprs_with_consts(ctx, &node.rhs);

    visit_assignment_with(ctx, node, rhs_values);
}

pub fn visit_assignment_with<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &AssignmentNode<'a>,
    rhs_values: Vec<(ValueRef<'a>, Option<SimpleConstValue>)>,
) {
    if node.kind != AssignmentKind::Simple && node.lhs.len() != 1 {
        ctx.report_error(AnalysisErrorKind::MultiComplexAssignment {
            location: node.location.clone(),
            num: node.lhs.len(),
        });

        return;
    }

    let rhs_values = expand_rhs_values(rhs_values, node.lhs.len());

    let mut explicit_backtrace = None;
    let mut subtract = Label::Bottom;
    if let Some(annotation) = node.annotation.as_deref()
        && let Some(directive) = annotations::parse_supported_directive(ctx, annotation)
    {
        match directive {
            annotations::AssignmentDirective::Label => {
                explicit_backtrace = LabelBacktrace::new_root(
                    LabelBacktraceKind::ExplicitAnnotation,
                    Label::from_tags(&annotation.tags),
                    None,
                    ctx.pin(node.location.clone()),
                );
            }
            annotations::AssignmentDirective::Revoke => {
                if let Some(label) = annotations::resolve_revocation_label(ctx, annotation) {
                    subtract = label;
                }
            }
            annotations::AssignmentDirective::AllowSink
            | annotations::AssignmentDirective::DenySink => {
                let sink = SinkDescriptor::new(
                    SinkKind::Assignment,
                    directive == annotations::AssignmentDirective::AllowSink,
                    &annotation.tags,
                    node.location.clone(),
                );

                if let Some(sink) = sink {
                    for (rhs, _) in &rhs_values {
                        enforcement::trigger_sink(ctx, Cow::Borrowed(&sink), rhs.backtrace());
                    }
                } else {
                    ctx.report_error(AnalysisErrorKind::InvalidDenySinkSemantics {
                        location: annotation.location.clone(),
                    });
                }
            }
            annotations::AssignmentDirective::Assert => {
                let sequence = Label::sequence_from_tags(&annotation.tags);

                for (rhs, _) in &rhs_values {
                    enforcement::trigger_assertion(
                        ctx,
                        &sequence,
                        rhs.backtrace(),
                        node.location.clone(),
                    );
                }
            }
        }
    }

    visit_raw_assignment(
        ctx,
        node.kind,
        node.lhs.iter(),
        rhs_values.into_iter(),
        explicit_backtrace.as_ref(),
        &subtract,
        &node.location,
    );
}

// for assignment-like cases more generic than an actual assignment node
pub fn visit_raw_assignment<'a: 'b, 'b>(
    ctx: &mut AnalysisContext<'a>,
    kind: AssignmentKind,
    lhs_exprs: impl ExactSizeIterator<Item = &'b ExprNode<'a>>,
    rhs_values: impl ExactSizeIterator<Item = (ValueRef<'a>, Option<SimpleConstValue>)>,
    explicit_backtrace: Option<&LabelBacktrace<'a>>, // from annotation
    subtract: &Label<'a>,
    location: &Location,
) {
    if lhs_exprs.len() != rhs_values.len() {
        ctx.report_error(AnalysisErrorKind::UnevenAssignment {
            location: location.clone(),
            left: lhs_exprs.len(),
            right: rhs_values.len(),
        });

        return;
    }

    for (lhs, (rhs, known_const)) in lhs_exprs.zip(rhs_values) {
        lhs.assign(
            ctx,
            LabelBacktraceKind::Assignment,
            rhs,
            known_const,
            kind == AssignmentKind::Simple,
            explicit_backtrace,
            subtract,
            location,
        );
    }
}

pub fn visit_incdec<'a>(
    ctx: &mut AnalysisContext<'a>,
    operand: &ExprNode<'a>,
    location: &Location,
) {
    // for simplicity, we treat this as syntactic sugar for an assignment

    visit_assignment(
        ctx,
        &AssignmentNode {
            kind: AssignmentKind::Sum, // can be anything except Simple
            lhs: vec![operand.clone()],
            rhs: vec![ExprNode::Literal(LiteralNode::Int {
                value: 1,
                location: location.clone(),
            })],
            location: location.clone(),
            annotation: None,
        },
    );
}

fn expand_rhs_values(
    values: Vec<(ValueRef<'_>, Option<SimpleConstValue>)>,
    arity: usize,
) -> Vec<(ValueRef<'_>, Option<SimpleConstValue>)> {
    if let [(single, _)] = values.as_slice()
        && let Some(expanded) = single.try_expand_to(arity)
    {
        return expanded.into_iter().map(|value| (value, None)).collect();
    }

    values
}
