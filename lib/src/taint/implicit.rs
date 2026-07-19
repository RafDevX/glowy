use std::{borrow::Cow, cell::Cell, iter};

use parser::{
    Location, Span,
    ast::{
        AssignmentKind, BlockNode, ElseNode, ExprNode, ExprSwitchNode, ForClauseNode,
        ForHeaderNode, ForNode, ForRangeNode, FunctionResultNode, FunctionSignatureNode, IfNode,
        LiteralNode, StatementNode, SwitchNode, TypeNameNode, TypeNode, TypeSwitchNode,
    },
};

use crate::{
    Pinned,
    context::{AnalysisContext, DeferTarget, SplitControlFlowArm},
    labels::{Label, LabelBacktrace, LabelBacktraceKind, SyntheticSlot},
    snapshots::SnapshotAware,
    symbols::{Symbol, SymbolRef},
    taint::{explicit, exprs, funcs, mutation::LeftValue},
    values::{FunctionRef, FunctionValue, Mergeable, SelfAwareBacktraceContainer, ValueRef},
};

struct EvaluatedRangeOperand<'a> {
    value: ValueRef<'a>,
    direct_map_symbol: Option<SymbolRef<'a>>,
}

pub fn visit_if<'a>(ctx: &mut AnalysisContext<'a>, node: &IfNode<'a>) {
    ctx.push_split_control_flow(node.location.clone());

    // Go spec: each if, for and switch is considered to be in its own
    // implicit block, so we select it here
    ctx.symtab_mut().select_next_child_scope();

    if let Some(statement) = &node.stmt {
        // simple statement to be executed before the condition is evaluated
        super::visit_statement(ctx, statement);
    }

    let pushed = if let Some(expr_backtrace) = exprs::get_expr_backtrace(ctx, &node.cond) {
        ctx.push_branch_backtrace(expr_backtrace.into_single_child(
            LabelBacktraceKind::Branch,
            None,
            ctx.pin(node.cond.location().into_owned()),
        ));

        true
    } else {
        false
    };

    ctx.set_current_split_arm(Some(SplitControlFlowArm::IfThen));

    // vvv this will create another scope for the if body, which is intended
    super::visit_block(ctx, &node.then);

    ctx.set_current_split_arm(node.otherwise.as_ref().map(|_| SplitControlFlowArm::IfElse));

    match &node.otherwise {
        Some(ElseNode::If(else_if)) => visit_if(ctx, else_if),
        Some(ElseNode::Block(r#else)) => super::visit_block(ctx, r#else),
        None => {} // nothing to do
    }

    ctx.set_current_split_arm(None);

    ctx.symtab_mut().select_parent_scope(); // pop implicit block

    if pushed {
        // only pop after visiting otherwise, since else is essentially an
        // implicit `if !cond`
        ctx.pop_branch_backtrace();
    }

    ctx.pop_split_control_flow();
}

pub fn visit_for<'a>(ctx: &mut AnalysisContext<'a>, node: &ForNode<'a>, label: Option<&'a str>) {
    // Go spec: each if, for and switch is considered to be in its own
    // implicit block, so we select it here
    ctx.symtab_mut().select_next_child_scope();

    // a for-clause's init statement and a range loop's range expression
    // are both evaluated exactly once, before control flow can split between
    // zero or more iterations. keep their side effects outside the split and,
    // for for-range, retain the evaluated operand for every abstract body visit

    if let ForHeaderNode::Clause(ForClauseNode {
        init: Some(init), ..
    }) = &node.header
    {
        // executed even if it later turns out that the loop iterates zero times
        super::visit_statement(ctx, init);
    }

    let range_operand = if let ForHeaderNode::Range(range) = &node.header {
        let range_expr = match range {
            ForRangeNode::Decl { range_expr, .. }
            | ForRangeNode::Assignment { range_expr, .. }
            | ForRangeNode::None { range_expr } => range_expr,
        };

        let location = ctx.pin(range_expr.location().into_owned());

        Some(visit_for_range_operand(ctx, range_expr, &location))
    } else {
        None
    };

    ctx.push_split_control_flow(node.location.clone());

    ctx.increase_branch_scope_depth();

    ctx.push_loop_convergence_context(label);

    match &node.header {
        ForHeaderNode::Clause(clause) => {
            visit_for_clause(ctx, clause, &node.body, &node.header_location);
        }
        ForHeaderNode::Range(range) => {
            visit_for_range(
                ctx,
                range,
                range_operand.as_ref().unwrap(),
                &node.body,
                &node.header_location,
            );
        }
    }

    ctx.pop_loop_convergence_context();

    // we decrease before triggering since that is also what happens for a
    // labeled target (triggering happens after visiting the labeled statement)
    ctx.decrease_branch_scope_depth();
    ctx.trigger_defer_target(DeferTarget::InnermostLoop);
    ctx.trigger_defer_target(DeferTarget::InnermostBreakable);

    ctx.symtab_mut().select_parent_scope(); // pop implicit block

    ctx.pop_split_control_flow();
}

fn visit_for_clause<'a>(
    ctx: &mut AnalysisContext<'a>,
    clause: &ForClauseNode<'a>,
    body: &BlockNode<'a>,
    header_location: &Location,
) {
    // body+post must be re-visited until labels stabilize because assignments
    // inside them can taint variables that the cond depends on, which then
    // widens the branch backtrace that guards subsequent iterations.
    // labels grow monotonically and finitely, so convergence is guaranteed.
    // we have to do independent speculative visits with error suppression
    // enabled until stabilization is reached, and then another separate visit
    // with errors unsuppressed at the end.
    // unlike `visit_for_range`, we cannot switch gears and declare an iteration
    // the final one when stability is determined mid-iteration, since error
    // suppression is relevant for condition evaluation here, as it can e.g.
    // be a function call with embedded enforcement checks that need to trigger,
    // meaning that we always need to do a separate final iteration at the end

    macro_rules! inner_visit {
        ($cond_backtrace:expr) => {{
            let pushed = if let Some(branch_backtrace) = LabelBacktrace::fold(
                $cond_backtrace.as_ref(),
                LabelBacktraceKind::Branch,
                None,
                ctx.pin(header_location.clone()),
            ) {
                ctx.push_branch_backtrace(branch_backtrace);

                true
            } else {
                false
            };

            // vvv this will create another scope for the for body (as intended)
            super::visit_block(ctx, body);

            // branch backtrace must remain in place while visiting post because
            // it is only executed if cond is not always false (info leakage)
            if let Some(post) = &clause.post {
                super::visit_statement(ctx, post);
            }

            if pushed {
                ctx.pop_branch_backtrace();
            }
        }};
    }

    // we need to remember deferred state before visiting the body+post, as all
    // deferral effects of speculative body+post visits (such as from break/
    // continue) must be rolled back before the next visit to prevent leakage
    let pre_body_deferred = ctx.checkpoint_deferred_state();

    let mut prev_cond_backtrace: Option<Option<LabelBacktrace<'a>>> = None;

    ctx.push_error_suppression();

    loop {
        // a conditional `continue` is a control-flow back-edge: mutations in
        // the next iteration may only happen because that branch was taken, so
        // we need to apply the previous iteration's contribution while
        // evaluating the repeated condition and body, then iterate until that
        // contribution stabilizes
        let iteration_pushed = if let Some(backtrace) = ctx.loop_iteration_backtrace().cloned() {
            ctx.push_branch_backtrace(backtrace);

            true
        } else {
            false
        };

        let cond_backtrace = clause
            .cond
            .as_ref()
            .and_then(|cond| exprs::get_expr_backtrace(ctx, cond));

        let stable = ctx.loop_iteration_has_converged()
            && prev_cond_backtrace
                .as_ref()
                .snapshot_aware_eq(&Some(&cond_backtrace));

        if stable {
            if iteration_pushed {
                ctx.pop_branch_backtrace();
            }

            break;
        }

        inner_visit!(cond_backtrace);

        if iteration_pushed {
            ctx.pop_branch_backtrace();
        }

        // the next iteration must re-enter the same body scope (and not a
        // sibling), so undo the cursor advance that `visit_block` performed
        ctx.symtab_mut().rewind_child_scope_cursor();

        ctx.restore_deferred_state(pre_body_deferred.clone());
        ctx.advance_loop_convergence_iteration();
        prev_cond_backtrace = Some(cond_backtrace);
    }

    ctx.pop_error_suppression();

    // final unsuppressed visit with stable labels. because labels never
    // shrink, the cond backtrace computed here is guaranteed to match the one
    // that broke the loop above, so the branch backtrace is the same as it
    // would have been on the (never-executed) stable iteration

    let iteration_pushed = if let Some(backtrace) = ctx.loop_iteration_backtrace().cloned() {
        ctx.push_branch_backtrace(backtrace);

        true
    } else {
        false
    };

    let cond_backtrace = clause
        .cond
        .as_ref()
        .and_then(|cond| exprs::get_expr_backtrace(ctx, cond));

    inner_visit!(cond_backtrace);

    if iteration_pushed {
        ctx.pop_branch_backtrace();
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "Very tight coupling means it would become more confusing if split up"
)]
fn visit_for_range<'a>(
    ctx: &mut AnalysisContext<'a>,
    range: &ForRangeNode<'a>,
    range_operand: &EvaluatedRangeOperand<'a>,
    body: &BlockNode<'a>,
    header_location: &Location,
) {
    let (lhs_len, range_expr) = match range {
        ForRangeNode::Decl {
            lhs, range_expr, ..
        } => (lhs.len(), range_expr),
        ForRangeNode::Assignment {
            lhs, range_expr, ..
        } => (lhs.len(), range_expr),
        ForRangeNode::None { range_expr } => (0, range_expr),
    };

    let rhs_location = ctx.pin(range_expr.location().into_owned());

    // the Go spec leaves map iteration order unspecified and explicitly allows
    // entries created during iteration to be observed by subsequent iterations
    // (see https://go.dev/ref/spec#For_range). for analysis soundness, the loop
    // variables must therefore reflect any mutations the body performs on the
    // ranged collection
    //
    // we model this by visiting the body more than once within a single
    // analysis pass: the first visits are speculative and run with errors
    // suppressed so they only contribute to label propagation; the final visit
    // runs with errors enabled, and uses loop variable bindings that already
    // account for everything the prior visits revealed
    //
    // loop termination relies on the lattice of labels being finite-height and
    // growing monotonically across visits (assignments only ever union new tags
    // into existing values); once a visit produces no new taint on the range
    // expr, the next visit's bindings match the previous one and the loop
    // exits. if this ever fails to converge, it is because of a soundness bug
    // elsewhere in the analysis

    let mut prev_rhs_backtrace: Option<Option<LabelBacktrace<'a>>> = None;

    // we need to remember deferred state before visiting the body, as all
    // deferral effects of speculative body visits (such as from break/continue)
    // must be rolled back before the next visit to prevent leakage
    let pre_body_deferred = ctx.checkpoint_deferred_state();

    loop {
        let current_operand = derive_current_for_range_operand(
            ctx,
            range_expr,
            range_operand, // already calc'd (visited exactly once)
            &rhs_location,
        );

        // need to do this every iteration as it might have changed
        let mut rhs_values = get_for_range_values(
            ctx,
            range_expr,
            &current_operand, // already calc'd (visited exactly once)
            rhs_location.clone(),
        );

        // every range shape uses its first abstract value to carry the
        // dependency of the loop's cardinality: length for arrays/slices, key
        // state for maps, and the operand/yield dependency for other shapes.
        // other later values just represent element payloads and do not
        // propagate information on whether the body executes
        let cardinality_backtrace = rhs_values.first().and_then(ValueRef::backtrace);
        let rhs_backtrace = LabelBacktrace::fold(
            cardinality_backtrace.as_ref(),
            LabelBacktraceKind::Expression,
            None,
            rhs_location.clone(),
        );

        rhs_values.truncate(lhs_len);

        let stable = ctx.loop_iteration_has_converged()
            && prev_rhs_backtrace
                .as_ref()
                .is_some_and(|prev| prev.snapshot_aware_eq(&rhs_backtrace));

        // unlike a three-clause loop condition, the range expression is not
        // evaluated again on each iteration, so install the continue back-edge
        // only after deriving its abstract iteration values
        let iteration_pushed = if let Some(backtrace) = ctx.loop_iteration_backtrace().cloned() {
            ctx.push_branch_backtrace(backtrace);

            true
        } else {
            false
        };

        // branch backtrace must come before assignment since it'll only take
        // place if the for loop actually iterates (i.e., range expr is
        // non-empty); e.g.
        // ```go
        // secretArr := [0]int{}
        // x := 7
        // for x = range secretArr {}
        // // if x still == 7, secretArr is empty
        // ```
        let pushed = if let Some(branch_backtrace) = LabelBacktrace::fold(
            rhs_backtrace.as_ref(),
            LabelBacktraceKind::Branch,
            None,
            ctx.pin(header_location.clone()),
        ) {
            // necessary because body only executes if range_expr is not empty
            ctx.push_branch_backtrace(branch_backtrace);

            true
        } else {
            false
        };

        if let ForRangeNode::Decl { lhs, .. } = range {
            explicit::visit_raw_binding_decl_spec(
                ctx,
                lhs,
                rhs_values.into_iter().map(|value| (value, None)),
                true,
                true,
                header_location,
                None,
                None,
            );

            // variables declared by a range clause (`:=`) are fresh on every
            // iteration, so we need to mark the abstract binding for closures
            // to retain the environment of the iteration in which they were
            // created, rather than being rebound through the declaration index
            // to a later iteration's symbol
            for name in lhs {
                if name.content() != "_"
                    && let Some(symbol) = ctx.symtab().get_symbol_in_current_scope(name.content())
                {
                    ctx.register_per_iteration_binding(&symbol);
                }
            }
        } else if let ForRangeNode::Assignment { lhs, .. } = range {
            explicit::visit_raw_assignment(
                ctx,
                AssignmentKind::Simple,
                lhs.iter(),
                rhs_values.into_iter().map(|value| (value, None)),
                None,
                &Label::Bottom,
                header_location,
            );
        }

        if !stable {
            ctx.push_error_suppression();
        }

        // vv this will create another scope for the for body, which is intended
        super::visit_block(ctx, body);

        if !stable {
            ctx.pop_error_suppression();
        }

        if pushed {
            ctx.pop_branch_backtrace();
        }

        if iteration_pushed {
            ctx.pop_branch_backtrace();
        }

        if stable {
            break;
        }

        // the next iteration must re-enter the same body scope (and not a
        // sibling), so undo the cursor advance that `visit_block` performed
        ctx.symtab_mut().rewind_child_scope_cursor();

        ctx.restore_deferred_state(pre_body_deferred.clone());
        ctx.advance_loop_convergence_iteration();
        prev_rhs_backtrace = Some(rhs_backtrace);
    }
}

fn derive_current_for_range_operand<'a>(
    ctx: &mut AnalysisContext<'a>,
    range_expr: &ExprNode<'a>,
    operand: &EvaluatedRangeOperand<'a>,
    location: &Pinned<'a, Location>,
) -> ValueRef<'a> {
    let Some(symbol) = &operand.direct_map_symbol else {
        return operand.value.clone();
    };

    // map mutations replace the symbol's ValueRef to preserve snapshot
    // immutability, so the saved operand would otherwise miss mutations made
    // directly through the ranged identifier. refresh that exact symbol
    // (rather than resolving its name again, which a range binding may shadow),
    // and merge it with the originally evaluated map so a variable rebind
    // cannot change which map is being ranged. calls and all other expressions
    // keep using their one-time result unchanged
    let ExprNode::Name(name) = range_expr else {
        unreachable!("a direct map symbol is only recorded for an operand name")
    };

    let current = exprs::visit_resolved_unqualified_operand_name(ctx, *name, symbol);

    operand.value.merge_with(
        &current,
        LabelBacktraceKind::Assignment,
        Cow::Borrowed(location),
    )
}

fn visit_for_range_operand<'a>(
    ctx: &mut AnalysisContext<'a>,
    range_expr: &ExprNode<'a>,
    location: &Pinned<'a, Location>,
) -> EvaluatedRangeOperand<'a> {
    // when there's an active branch backtrace and the operand is a mutable
    // left-value, we need special handling so that if the value turns out to
    // be a channel we can fold the current branch backtrace into the channel's
    // own label in the SAME visit (we can't visit range_expr twice, or it can
    // cause unsoundness if there are any side-effects).
    // folding is necessary in the case described above because ranging over a
    // channel depletes it, which is externally observable to any other holder.
    // we thus need to perform folding behavior matching `visit_receive` for
    // normal receive expressions.
    // we need to do this here because the current branch backtrace is still the
    // *outer* aggregate: `visit_for_range` only pushes the loop's own header
    // backtrace after this call returns, so we avoid tainting the channel with
    // its own label (complicating the tree).
    // we intentionally exclude immutable roots (Go consts) because they can't
    // be channels and the mutation would spuriously flag ImmutableLeftValue
    let should_fold = ctx.branch_backtrace().is_some()
        && range_expr.root_operand().is_some_and(|root| {
            ctx.symtab()
                .get_symbol(root.content())
                .is_none_or(|sym| sym.borrow().mutable())
        });

    let value = if should_fold {
        // we can only visit range_expr once, so we need to hijack the existing
        // `mutate_target` visit and extract the value it calculated so that we
        // can use it later during the main part of this function
        let extracted = Cell::new(None);

        #[expect(
            clippy::shadow_unrelated,
            reason = "Same context, just threaded through a closure"
        )]
        range_expr.mutate_target(ctx, location.inner(), &|ctx, mut operand| {
            extracted.set(Some(operand.clone()));

            // fold only for values that turn out to actually be channels, per
            // the rationale above: returning None aborts the entire mutation,
            // which is exactly what we want if the operand is not actually a
            // channel (which we could not have known in advance)
            if !operand.is_channel() {
                return None;
            }

            let mut channel = operand.as_channel_mut().unwrap();

            if let Some(branch_backtrace) = ctx.branch_backtrace().cloned() {
                channel.record_receive(branch_backtrace, location);
            }

            drop(channel);
            Some((operand, None))
        });

        extracted
            .into_inner()
            .unwrap_or_else(|| ValueRef::new_bottom(location.clone(), None))
    } else {
        // just visit the expression normally, no special handling required
        exprs::visit_single_expr(ctx, range_expr)
    };

    let direct_map_symbol = if value.is_map()
        && let ExprNode::Name(name) = range_expr
    {
        ctx.symtab().get_symbol(name.content())
    } else {
        None
    };

    EvaluatedRangeOperand {
        value,
        direct_map_symbol,
    }
}

fn get_for_range_values<'a>(
    ctx: &mut AnalysisContext<'a>,
    range_expr: &ExprNode<'a>,
    value: &ValueRef<'a>,
    location: Pinned<'a, Location>,
) -> Vec<ValueRef<'a>> {
    // see https://go.dev/ref/spec#For_range for the per-type cardinality table;
    // the order below matches that table, with the trailing string/unknown
    // branch acting as the conservative catch-all

    // channel: 1 value (received element).
    // we guard on `is_channel` (rather than `as_channel`) because for-range is
    // polymorphic over many types per the Go spec (channel, int, string, slice,
    // array, map, iter func), so an unshaped Simple here cannot be safely
    // coerced into a ChannelValue from the syntactic context alone
    if value.is_channel()
        && let Some(channel) = value.as_channel()
    {
        // the branch-folding was already applied above, if applicable
        return vec![channel.receive(&location).0];
    }

    // slice: 2 values (index, element i.e. coll[i])
    if value.is_slice()
        && let Some(slice) = value.as_slice()
    {
        let index_bt = slice.len_backtrace(location.clone());

        return vec![
            ValueRef::from_backtrace_or_bottom_at(index_bt, || location.clone()),
            slice.range_element(location),
        ];
    }

    // array: 2 values (index, element i.e. coll[index])
    if value.is_array()
        && let Some(array) = value.as_array()
    {
        let index_bt = array.len_backtrace(location.clone());

        return vec![
            ValueRef::from_backtrace_or_bottom_at(index_bt, || location.clone()),
            array.get_dyn(location),
        ];
    }

    // map: 2 values (key, element i.e. coll[key])
    if let Some(composite) = value.as_composite() {
        let index_bt = composite.backtrace_at_location(location.clone());

        return vec![
            ValueRef::from_backtrace_or_bottom_at(index_bt, || location.clone()),
            composite.get_at_unknown_key(location),
        ];
    }

    // iter function: cardinality determined by the yield signature
    if let Some(func) = value.as_function()
        && let Some(yield_signature) = extract_iter_yield_signature(&func)
    {
        return get_iter_function_range_values(ctx, &func, yield_signature, &location);
    }

    let downgraded = value.downgrade(|| location.clone());

    // integer: 1 value (the index, of the ranged integer type).
    // the iteration values themselves (0..n-1) carry no intrinsic label, but
    // the very *fact* that the loop iterates n times depends on n's label, so
    // we propagate the range_expr's overall backtrace into the loop var (and
    // through the invoker's fold, into the branch backtrace)
    if is_integer_range_expr(ctx, range_expr) {
        return vec![downgraded];
    }

    // remaining valid options: a string (2 values: index, rune) or a
    // non-literal integer we couldn't recognize syntactically (1 value).
    // we conservatively yield 2 - truncation to lhs_len downstream handles
    // the 1-ident case sound either way, and 2-ident strings are common.
    // for any other (unsupported) shape this also gives a safe fallback that
    // avoids spurious cardinality errors while keeping label propagation
    vec![downgraded.clone_inner(), downgraded]
}

fn extract_iter_yield_signature<'a, 'f>(
    func: &'f FunctionValue<'a>,
) -> Option<&'f FunctionSignatureNode<'a>> {
    let yield_type = func
        .signature()
        .and_then(|sig| sig.params.first())
        .filter(|param| param.ids.len() <= 1)
        .map(|param| &param.r#type)?;

    let TypeNode::Function { signature } = yield_type else {
        return None;
    };

    let FunctionResultNode::Single(TypeNode::Name(TypeNameNode {
        package: None, id, ..
    })) = &signature.result
    else {
        return None;
    };

    (id.content() == "bool").then_some(signature.as_ref())
}

fn get_iter_function_range_values<'a>(
    ctx: &AnalysisContext<'a>,
    func: &FunctionValue<'a>,
    yield_signature: &FunctionSignatureNode<'a>,
    location: &Pinned<'a, Location>,
) -> Vec<ValueRef<'a>> {
    let mut func = Cow::Borrowed(func);

    for (index, concrete) in funcs::derive_stable_capture_concretes(ctx, &func) {
        func = Cow::Owned(func.realize(
            func.r#ref(),
            SyntheticSlot::Capture(index),
            concrete.as_ref(),
        ));
    }

    let downgraded = func.downgrade_as_call(ctx, location.clone());

    let n_values: usize = yield_signature.count_inputs();

    if n_values == 0 {
        // note: this is wrong, we should return an empty Vec, but that would
        // lead to an incorrect branch backtrace being set, which would actually
        // be much worse -- branch must depend on the label of `value`, since a
        // function might have side effects, and anyway the for body executes
        // only when iter yields, which may be conditional on whatever taints
        // the iter value (e.g., closure captures, branch labels recorded via
        // `record_yield_call`)
        return vec![downgraded];
    }

    // map each yield argument position to the labels accumulated from
    // `yield(args)` calls inside the iter function body
    // (see `FunctionValue::record_yield_call`); fall back to the function
    // value's overall taint when nothing was recorded (e.g., on the first
    // stabilization iteration, or when the iter wasn't recognized as such)
    let yield_acc = func.yield_acc();

    if yield_acc.is_empty() {
        // function was never (previously) detected as being iter-shaped, but
        // this is likely because it has never been visited yet, or because it
        // has no known implementation for some other reason, so we still want
        // to match the correct lhs cardinality so that the binding is accepted
        // without reporting an error
        return iter::repeat_with(|| downgraded.clone_inner())
            .take(n_values)
            .collect();
    }

    let call_branch = funcs::calc_effective_call_site_branch_backtrace_for(ctx, &func, location);

    yield_acc
        .iter()
        .map(|yielded| {
            let realized = yielded.realize(
                func.r#ref(),
                SyntheticSlot::CallSiteBranch,
                call_branch.as_ref(),
            );

            match realized {
                Some(bt) => ValueRef::from(bt).with_location(location.clone()),
                None => downgraded.clone_inner(), // fallback
            }
        })
        .collect()
}

// best effort only; very conservative; only true if statically guaranteed
fn is_integer_range_expr<'a>(ctx: &AnalysisContext<'a>, expr: &ExprNode<'a>) -> bool {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "We explicitly want to detect only these variants"
    )]
    match expr {
        ExprNode::Literal(LiteralNode::Int { .. }) => true,
        ExprNode::Call(call) => {
            let ExprNode::Name(func_name) = call.func.as_ref() else {
                return false;
            };

            let func_name = func_name.content();
            if !matches!(func_name, "len" | "cap" | "min" | "max") {
                // not a known built-in function that would (in this context)
                // return an integer, so we cannot draw conclusions
                return false;
            }

            // must resolve to the predeclared builtin (not a user shadow)
            let Some(symbol) = ctx.symtab().get_symbol(func_name) else {
                // since we already whitelisted the function name above to
                // predeclared functions, symbol lookup failing means that this
                // is a (not shadowed) builtin with special handling
                return true;
            };

            let value = symbol.borrow().value().get();

            let Some(func) = value.as_function() else {
                return false;
            };

            matches!(func.r#ref(), FunctionRef::BuiltIn(name) if *name == func_name)
        }
        _ => false,
    }
}

pub fn visit_continue<'a>(
    ctx: &mut AnalysisContext<'a>,
    label: Option<Span<'a>>,
    location: &Location,
) {
    // record before deferring: the back-edge contribution is the branch context
    // at the continue itself, not the composite created for statements that
    // lexically follow it in this iteration
    ctx.record_continue_branch_backtrace(label.as_ref().map(Span::content), location.clone());

    let target = if let Some(label) = label {
        DeferTarget::LabeledLoop(label.content())
    } else {
        DeferTarget::InnermostLoop
    };

    ctx.defer_branch_backtrace(target, location.clone());
}

pub fn visit_break<'a>(
    ctx: &mut AnalysisContext<'a>,
    label: Option<Span<'a>>,
    location: &Location,
) {
    let target = if let Some(label) = label {
        DeferTarget::LabeledBreakable(label.content())
    } else {
        DeferTarget::InnermostBreakable
    };

    ctx.defer_branch_backtrace(target, location.clone());
}

pub fn visit_switch<'a>(ctx: &mut AnalysisContext<'a>, node: &SwitchNode<'a>) {
    let location = match node {
        SwitchNode::Expr(expr) => &expr.location,
        SwitchNode::Type(r#type) => &r#type.location,
    };

    ctx.push_split_control_flow(location.clone());

    // Go spec: each if, for and switch is considered to be in its own
    // implicit block, so we select it here
    ctx.symtab_mut().select_next_child_scope();

    ctx.increase_branch_scope_depth();

    match node {
        SwitchNode::Expr(expr) => visit_expr_switch(ctx, expr),
        SwitchNode::Type(r#type) => visit_type_switch(ctx, r#type),
    }

    ctx.decrease_branch_scope_depth();
    ctx.trigger_defer_target(DeferTarget::InnermostBreakable);

    ctx.symtab_mut().select_parent_scope(); // pop implicit block

    ctx.pop_split_control_flow();
}

fn visit_expr_switch<'a>(ctx: &mut AnalysisContext<'a>, node: &ExprSwitchNode<'a>) {
    if let Some(stmt) = &node.stmt {
        // simple statement to be executed before switch
        super::visit_statement(ctx, stmt);
    }

    // Branch backtraces for each clause cannot be popped at the end of each
    // case block because their negation is implicitly asserted for all other
    // clauses. For example,
    // ```go
    // switch {
    //     case secret % 2 == 0: // do nothing
    //     case true: fmt.Println("secret is odd") // (!)
    // }
    // ```
    // here we must remember the branch backtrace introduced by the first case
    // clause even when analyzing the second clause, otherwise information about
    // the secret can be leaked.
    // Note that this is distinct from node.clauses.len()+1? because some might
    // have no backtraces (e.g., `case 3:`).
    let mut n_pushes = 0_usize;

    if let Some(expr) = &node.expr
        && let Some(bt) = exprs::get_expr_backtrace(ctx, expr)
    {
        ctx.push_branch_backtrace(bt.into_single_child(
            LabelBacktraceKind::Branch,
            None,
            ctx.pin(expr.location().into_owned()),
        ));

        n_pushes += 1;
    }

    for clause in &node.clauses {
        let children: Vec<_> = clause
            .exprs
            .iter()
            .filter_map(|expr| exprs::get_expr_backtrace(ctx, expr))
            .collect();

        let start = clause
            .exprs
            .first()
            .map(ExprNode::location)
            .map(Cow::into_owned)
            .map_or(0, |l| l.start);
        let end = clause
            .exprs
            .last()
            .map(ExprNode::location)
            .map(Cow::into_owned)
            .map_or(usize::MAX, |l| l.end);

        let folded = LabelBacktrace::fold(
            children.iter(),
            LabelBacktraceKind::Branch,
            None,
            ctx.pin(start..end),
        );

        if let Some(bt) = folded {
            ctx.push_branch_backtrace(bt);

            n_pushes += 1;
        }

        let body = if let Some(StatementNode::Fallthrough { .. }) = clause.body.last() {
            // statement visitor will reject any fallthrough statement as
            // out of place, so we omit it here before passing on the block
            &clause.body[..clause.body.len() - 1]
        } else {
            &clause.body
        };

        // vvv this will create another scope for the clause body,
        // which is (probably?) intended? spec unclear at first glance
        super::visit_scoped_statements(ctx, body);
    }

    for _ in 0..n_pushes {
        ctx.pop_branch_backtrace();
    }
}

fn visit_type_switch<'a>(ctx: &mut AnalysisContext<'a>, node: &TypeSwitchNode<'a>) {
    if let Some(stmt) = &node.stmt {
        // simple statement to be executed before switch
        super::visit_statement(ctx, stmt);
    }

    let value = exprs::visit_single_expr(ctx, &node.expr);

    if let Some(id) = node.decl {
        ctx.declare_new_symbol(Symbol::new_ref(ctx.pin(id), true, value.clone(), None));
    }

    let expr_location = ctx.pin(node.expr.location().into_owned());
    let pushed = if let Some(bt) = value.backtrace() {
        ctx.push_branch_backtrace(bt.into_single_child(
            LabelBacktraceKind::Branch,
            None,
            expr_location,
        ));

        true
    } else {
        false
    };

    for clause in &node.clauses {
        // we don't actually care about clause.types because raw types aren't
        // values and so don't have labels

        // vvv this will create another scope for the clause body,
        // which is (probably?) intended? spec unclear at first glance
        super::visit_scoped_statements(ctx, &clause.body);
    }

    if pushed {
        ctx.pop_branch_backtrace();
    }
}
