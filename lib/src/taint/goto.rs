use std::{borrow::Cow, collections::HashMap, mem};

use parser::{
    Location, Span,
    ast::{BlockNode, ElseNode, IfNode, StatementNode, SwitchNode},
};

use crate::{
    context::AnalysisContext,
    labels::{LabelBacktrace, LabelBacktraceKind},
    snapshots::SnapshotAware,
};

#[derive(Default)]
pub struct GotoConvergenceState<'a> {
    /// Label-to-branch-backtrace mapping observed from the previous iteration.
    ///
    /// The map value is the folded branch backtrace from `goto` statements
    /// targeting the label in question (map key), as recorded during the
    /// previous convergence iteration (if any). None means Bottom, i.e., a
    /// label that has been targeted by a `goto` statement but with no implicit
    /// flow context to propagate.
    incoming: HashMap<&'a str, Option<LabelBacktrace<'a>>>,
    /// Label-to-branch-backtrace mapping observed from the current iteration.
    ///
    /// This represents the mapping current being built for the present
    /// convergence iteration, which will become the next iteration's
    /// [`Self::incoming`] (or signal stability when it matches the current
    /// `incoming`).
    outgoing: HashMap<&'a str, Option<LabelBacktrace<'a>>>,
    /// Number of branch-backtrace pushes that need to be popped on cleanup.
    n_pushes: usize,
}

impl GotoConvergenceState<'_> {
    fn advance(&mut self) -> bool {
        let stable = self.incoming.snapshot_aware_eq(&self.outgoing);

        self.incoming = mem::take(&mut self.outgoing);

        stable
    }
}

pub fn block_contains_goto(block: &BlockNode<'_>) -> bool {
    statements_contain_goto(&block.stmts)
}

fn statements_contain_goto(statements: &[StatementNode<'_>]) -> bool {
    statements.iter().any(statement_contains_goto)
}

fn statement_contains_goto(statement: &StatementNode<'_>) -> bool {
    match statement {
        StatementNode::Goto { .. } => true,

        StatementNode::Labeled { inner, .. } => statement_contains_goto(inner),
        StatementNode::Block(block) => block_contains_goto(block),
        StatementNode::If(r#if) => if_contains_goto(r#if),
        // syntactically impossible for a `for` header to have `goto`, only body
        StatementNode::For(r#for) => block_contains_goto(&r#for.body),
        StatementNode::Select(select) => select
            .clauses
            .iter()
            .any(|clause| statements_contain_goto(&clause.body)),
        StatementNode::Switch(SwitchNode::Expr(switch)) => {
            switch.stmt.as_deref().is_some_and(statement_contains_goto)
                || switch
                    .clauses
                    .iter()
                    .any(|clause| statements_contain_goto(&clause.body))
        }
        StatementNode::Switch(SwitchNode::Type(switch)) => {
            switch.stmt.as_deref().is_some_and(statement_contains_goto)
                || switch
                    .clauses
                    .iter()
                    .any(|clause| statements_contain_goto(&clause.body))
        }

        StatementNode::Empty { .. }
        | StatementNode::Expr { .. }
        | StatementNode::Send(_)
        | StatementNode::Inc { .. }
        | StatementNode::Dec { .. }
        | StatementNode::Assignment(_)
        | StatementNode::ShortVarDecl(_)
        | StatementNode::Decl(_)
        | StatementNode::Fallthrough { .. }
        | StatementNode::Continue { .. }
        | StatementNode::Break { .. }
        | StatementNode::Return { .. }
        | StatementNode::Go { .. }
        | StatementNode::Defer { .. } => false,
    }
}

fn if_contains_goto(node: &IfNode<'_>) -> bool {
    // node.stmt and node.cond cannot syntactically contain a goto, meaning that
    // only the bodies matter

    if block_contains_goto(&node.then) {
        return true;
    }

    match &node.otherwise {
        Some(ElseNode::If(else_if)) => if_contains_goto(else_if),
        Some(ElseNode::Block(block)) => block_contains_goto(block),
        None => false,
    }
}

#[must_use]
pub fn is_label_targeted(ctx: &AnalysisContext<'_>, label: &str) -> bool {
    ctx.current_goto_context()
        .is_some_and(|state| state.incoming.contains_key(label))
}

pub fn push_goto_convergence_context(ctx: &mut AnalysisContext<'_>) {
    ctx.push_goto_context(GotoConvergenceState::default());
}

pub fn pop_goto_convergence_context(ctx: &mut AnalysisContext<'_>) {
    ctx.pop_goto_context();
}

pub fn visit_goto<'a>(ctx: &mut AnalysisContext<'a>, label: Span<'a>, location: &Location) {
    ctx.record_range_exit_feedback(location); // be conservative

    let contribution = ctx.branch_backtrace().cloned();
    let location = ctx.pin(location.clone());

    let state = ctx
        .current_goto_context_mut()
        .expect("goto outside convergence context");

    let existing = state.outgoing.entry(label.content()).or_default();

    *existing = LabelBacktrace::combine_options(
        existing.take(),
        contribution,
        LabelBacktraceKind::Branch,
        Cow::Owned(location),
    );
}

pub fn visit_label_in_goto_context<'a>(ctx: &mut AnalysisContext<'a>, label: Span<'a>) {
    let Some(state) = ctx.current_goto_context_mut() else {
        // there is no active `goto` context, so there is necessarily nothing to
        // be done (this label cannot ever be targeted by a `goto` statement)
        return;
    };

    let Some(Some(backtrace)) = state.incoming.get(label.content()).cloned() else {
        // either this label has not (yet?) been targeted by a `goto` statement,
        // or there is currently no implicit flow context to propagate -- in
        // either case, there is nothing for us to do here
        return;
    };

    state.n_pushes += 1;
    ctx.push_branch_backtrace(backtrace);
}

pub fn pop_goto_branch_backtraces(ctx: &mut AnalysisContext<'_>) {
    let n_pushes = ctx
        .current_goto_context_mut()
        .map_or(0, |state| mem::take(&mut state.n_pushes));

    for _ in 0..n_pushes {
        ctx.pop_branch_backtrace();
    }
}

#[must_use]
pub fn advance_goto_convergence_iteration(ctx: &mut AnalysisContext<'_>) -> bool {
    ctx.current_goto_context_mut()
        .expect("iteration outside convergence context")
        .advance()
}
