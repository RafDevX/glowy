use std::{borrow::Cow, cmp, rc::Rc};

use parser::{
    Annotation, Location, Span,
    ast::{
        AssignmentKind, AssignmentNode, BindingDeclSpecNode, ExprNode, LiteralNode,
        ShortVarDeclNode,
    },
};

use super::exprs;
use crate::{
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{Label, LabelBacktrace, LabelBacktraceKind},
    symbols::Symbol,
    taint::{SinkDescriptor, SinkKind, enforcement, mutation::LeftValue},
    values::ValueRef,
};

pub fn visit_binding_decl<'a>(
    ctx: &mut AnalysisContext<'a>,
    specs: &[BindingDeclSpecNode<'a>],
    mutable: bool,
    location: &Location,
    annotation: Option<&Annotation<'a>>,
) {
    for spec in specs {
        visit_binding_decl_spec(ctx, spec, mutable, false, location, annotation);
    }
}

fn visit_binding_decl_spec<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &BindingDeclSpecNode<'a>,
    mutable: bool,
    short: bool, // allows redeclaration in some circumstances
    location: &Location,
    annotation: Option<&Annotation<'a>>,
) {
    if node.exprs.is_empty() && node.r#type.is_some() && !short {
        // no initialization expression; zero-value is used;
        // for our purposes, we just need to remember the decl exists
        // (branch label is irrelevant in this case)

        for name in &node.ids {
            let pinned = ctx.pin(*name);
            let value = ValueRef::new_bottom(pinned.pinned_location());

            let symbol = Symbol::new_ref(pinned, mutable, value);

            ctx.declare_new_symbol(symbol);
        }

        return;
    }

    let mut rhs_values = exprs::visit_multi_exprs(ctx, &node.exprs);

    let mut expanded = None;
    if node.ids.len() > 1
        && let [single] = rhs_values.as_slice()
    {
        if let Some(expandable) = single.as_expandable() {
            // cannot assign directly to rhs_values here because the borrow
            // checker is very cool and awesome and does not allow it while
            // rhs_values is borrowed from the if-let, so we do this instead
            expanded = Some(expandable.expand());
        } else if let Some(mobius) = single.as_mobius() {
            expanded = Some(mobius.expand_to(node.ids.len()));
        }
    }

    if let Some(expanded) = expanded {
        rhs_values = expanded;
    }

    visit_raw_binding_decl_spec(
        ctx,
        &node.ids,
        rhs_values.into_iter(),
        mutable,
        short,
        location,
        annotation,
    );
}

// for declaration-like cases more generic than an actual declaration node
pub fn visit_raw_binding_decl_spec<'a>(
    ctx: &mut AnalysisContext<'a>,
    ids: &[Span<'a>],
    rhs_values: impl ExactSizeIterator<Item = ValueRef<'a>>,
    mutable: bool,
    short: bool, // allows redeclaration in some circumstances
    location: &Location,
    annotation: Option<&Annotation<'a>>,
) {
    if ids.len() != rhs_values.len() {
        ctx.report_error(AnalysisErrorKind::UnevenBindingDeclSpec {
            location: location.clone(),
            left: ids.len(),
            right: rhs_values.len(),
        });

        return;
    }

    let mut redeclarations = vec![];
    let mut any_new = false;

    for (name, rhs) in ids.iter().copied().zip(rhs_values) {
        let mut explicit_backtrace = None;
        let mut subtract = Label::Bottom;

        if let Some(annotation) = annotation {
            match annotation.directive {
                "label" => {
                    explicit_backtrace = Some(LabelBacktrace::new_root(
                        LabelBacktraceKind::ExplicitAnnotation,
                        Label::from_tags(&annotation.tags),
                        Some(name.content()),
                        ctx.pin(location.clone()),
                    ));
                }
                "declassify" => {
                    if annotation.tags.is_empty() {
                        ctx.report_error(AnalysisErrorKind::InvalidDeclassificationSemantics {
                            direct: true,
                            location: annotation.location.clone(),
                        });
                    } else {
                        subtract = Label::from_tags(&annotation.tags);
                    }
                }
                "sink" => {
                    let sink = SinkDescriptor::new(
                        SinkKind::Declaration,
                        &annotation.tags,
                        location.clone(), // spec, not annotation
                    );

                    enforcement::trigger_sink(ctx, Cow::Owned(sink), rhs.backtrace());
                }
                "assert" => {
                    enforcement::trigger_assertion(
                        ctx,
                        &Label::sequence_from_tags(&annotation.tags),
                        rhs.backtrace(),
                        location.clone(),
                    );
                }
                _ => ctx.report_error(AnalysisErrorKind::UnknownAnnotationDirective {
                    directive: annotation.directive,
                    location: annotation.location.clone(),
                }),
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

        let symbol = Symbol::new_ref(
            ctx.pin(name),
            true, // we initially always set the symbol as mutable
            ValueRef::new_bottom(ctx.pin(location.clone())),
        );
        let symbol2 = Rc::clone(&symbol); // for later use if needed

        if short {
            // declare manually to hold errors until we're sure
            if let Some(existing) = ctx.symtab_mut().declare_new_symbol(name.content(), symbol) {
                let borrowed = existing.borrow();

                if matches!(
                    ctx.pin(name)
                        .pinned_location()
                        .partial_cmp(&borrowed.declared_name().pinned_location()),
                    None | Some(cmp::Ordering::Greater)
                ) {
                    redeclarations.push(AnalysisErrorKind::IllegalRedeclaration {
                        previous: borrowed.declared_name(),
                        found: name,
                    });

                    continue;
                }
            }

            any_new = true;
        } else {
            // just report any errors
            ctx.declare_new_symbol(symbol);
        }

        // now that symbol is declared, we can assign a value to it

        name.assign(
            ctx,
            LabelBacktraceKind::DeclarationInitialization,
            rhs,
            true,
            explicit_backtrace.as_ref(),
            &subtract,
            location,
        );

        // now, after assigning, we can set the symbol to immutable if that was
        // the case (before we created it as mutable to allow the assignment)
        if !mutable {
            symbol2.borrow_mut().mark_immutable();
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
    // for simplicity, we treat this as if it was a binding decl spec

    visit_binding_decl_spec(
        ctx,
        &BindingDeclSpecNode {
            ids: node.ids.clone(),
            exprs: node.exprs.clone(),
            r#type: None,
        },
        true,
        true,
        &node.location,
        node.annotation.as_deref(),
    );
}

pub fn visit_assignment<'a>(ctx: &mut AnalysisContext<'a>, node: &AssignmentNode<'a>) {
    if node.kind != AssignmentKind::Simple && node.lhs.len() != 1 {
        ctx.report_error(AnalysisErrorKind::MultiComplexAssignment {
            location: node.location.clone(),
            num: node.lhs.len(),
        });

        return;
    }

    let mut rhs_values = exprs::visit_multi_exprs(ctx, &node.rhs);

    let mut expanded = None;
    if node.lhs.len() > 1
        && let [single] = rhs_values.as_slice()
    {
        if let Some(expandable) = single.as_expandable() {
            // cannot assign directly to rhs_values here because the borrow
            // checker is very cool and awesome and does not allow it while
            // rhs_values is borrowed from the if-let, so we do this instead
            expanded = Some(expandable.expand());
        } else if let Some(mobius) = single.as_mobius() {
            expanded = Some(mobius.expand_to(node.lhs.len()));
        }
    }

    if let Some(expanded) = expanded {
        rhs_values = expanded;
    }

    let mut explicit_backtrace = None;
    let mut subtract = Label::Bottom;
    if let Some(annotation) = node.annotation.as_deref() {
        match annotation.directive {
            "label" => {
                explicit_backtrace = Some(LabelBacktrace::new_root(
                    LabelBacktraceKind::ExplicitAnnotation,
                    Label::from_tags(&annotation.tags),
                    None,
                    ctx.pin(node.location.clone()),
                ));
            }
            "declassify" => {
                if annotation.tags.is_empty() {
                    ctx.report_error(AnalysisErrorKind::InvalidDeclassificationSemantics {
                        direct: true,
                        location: annotation.location.clone(),
                    });
                } else {
                    subtract = Label::from_tags(&annotation.tags);
                }
            }
            "sink" => {
                let sink = SinkDescriptor::new(
                    SinkKind::Assignment,
                    &annotation.tags,
                    node.location.clone(),
                );

                for rhs in &rhs_values {
                    enforcement::trigger_sink(ctx, Cow::Borrowed(&sink), rhs.backtrace());
                }
            }
            "assert" => {
                let sequence = Label::sequence_from_tags(&annotation.tags);

                for rhs in &rhs_values {
                    enforcement::trigger_assertion(
                        ctx,
                        &sequence,
                        rhs.backtrace(),
                        node.location.clone(),
                    );
                }
            }
            _ => ctx.report_error(AnalysisErrorKind::UnknownAnnotationDirective {
                directive: annotation.directive,
                location: annotation.location.clone(),
            }),
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
    rhs_values: impl ExactSizeIterator<Item = ValueRef<'a>>,
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

    for (lhs, rhs) in lhs_exprs.zip(rhs_values) {
        lhs.assign(
            ctx,
            LabelBacktraceKind::Assignment,
            rhs,
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
