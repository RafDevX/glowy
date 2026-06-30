use std::collections::HashSet;

use parser::{
    Span,
    ast::{
        AmbiguousBracketAccessNode, AssignmentKind, AssignmentNode, BindingDeclSpecNode, BlockNode,
        CallNode, CompositeLiteralElementListNode, CompositeLiteralElementNode, ConversionNode,
        DeclNode, ElseNode, ExprNode, ExprSwitchCaseClause, ExprSwitchNode, ForClauseNode,
        ForHeaderNode, ForNode, ForRangeNode, FunctionDeclNode, FunctionParamDeclNode,
        FunctionResultNode, FunctionSignatureNode, IfNode, IndexingNode, LiteralNode, MakeNode,
        SelectClauseNode, SelectNode, SelectionNode, SendNode, ShortVarDeclNode, SlicingNode,
        StatementNode, StructLiteralFieldsNode, SwitchNode, TypeAssertionNode,
        TypeInstantiationNode, TypeSwitchCaseClause, TypeSwitchNode,
    },
};

use crate::taint::mutation::LeftValue;

pub fn collect_captured_symbols<'a>(
    signature: &FunctionSignatureNode<'a>,
    receiver: Option<&FunctionParamDeclNode<'a>>,
    body: &BlockNode<'a>,
) -> HashSet<&'a str> {
    let mut declared = extract_names_from_signature(signature, receiver);

    let mut captured = HashSet::new();

    body.collect_captured_symbols(&mut captured, &mut declared);

    captured
}

fn extract_names_from_signature<'a>(
    signature: &FunctionSignatureNode<'a>,
    receiver: Option<&FunctionParamDeclNode<'a>>,
) -> HashSet<&'a str> {
    let receiver = receiver
        .map(|param| &param.ids)
        .filter(|ids| ids.len() == 1)
        .map(Vec::as_slice)
        .and_then(<[_]>::first);

    let result_ids = if let FunctionResultNode::Params(params) = &signature.result {
        Some(params.iter().flat_map(|param| &param.ids))
    } else {
        None
    };

    signature
        .params
        .iter()
        .flat_map(|param| &param.ids)
        .chain(receiver)
        .chain(result_ids.into_iter().flatten())
        .map(Span::content)
        .filter(|name| *name != "_")
        .collect()
}

trait SymbolCaptureCollector<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    );
}

impl<'a> SymbolCaptureCollector<'a> for BlockNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        let mut declared = declared.clone();

        for statement in self {
            statement.collect_captured_symbols(captured, &mut declared);
        }
    }
}

impl<'a> SymbolCaptureCollector<'a> for StatementNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        let sub: &dyn SymbolCaptureCollector = match self {
            StatementNode::Empty { .. }
            | StatementNode::Fallthrough { .. }
            | StatementNode::Continue { .. }
            | StatementNode::Break { .. }
            | StatementNode::Goto { .. } => return,
            StatementNode::Expr { expr, .. }
            | StatementNode::Go { expr, .. }
            | StatementNode::Defer { expr, .. } => expr,
            StatementNode::Send(send) => send,
            StatementNode::Inc { operand, .. } | StatementNode::Dec { operand, .. } => operand,
            StatementNode::Assignment(assignment) => assignment,
            StatementNode::ShortVarDecl(decl) => decl,
            StatementNode::Labeled { inner, .. } => &**inner,
            StatementNode::Block(block) => block,
            StatementNode::Decl(decl) => decl,
            StatementNode::If(r#if) => r#if,
            StatementNode::For(r#for) => r#for,
            StatementNode::Select(select) => select,
            StatementNode::Switch(switch) => switch,
            StatementNode::Return { exprs, .. } => exprs,
        };

        sub.collect_captured_symbols(captured, declared);
    }
}

impl<'a> SymbolCaptureCollector<'a> for SendNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        self.channel.collect_captured_symbols(captured, declared);
        self.expr.collect_captured_symbols(captured, declared);
    }
}

impl<'a> SymbolCaptureCollector<'a> for AssignmentNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        self.lhs.collect_captured_symbols(captured, declared);
        self.rhs.collect_captured_symbols(captured, declared);

        for root in self.lhs.iter().filter_map(LeftValue::root_operand) {
            let name = root.content();

            if name != "_" && !declared.contains(name) {
                // assigning to something not declared within this closure means
                // that we're capturing an outer symbol
                captured.insert(name);
            }
        }
    }
}

impl<'a> SymbolCaptureCollector<'a> for ShortVarDeclNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        self.exprs.collect_captured_symbols(captured, declared);

        for id in &self.ids {
            let name = id.content();

            if name != "_" {
                declared.insert(name);
            }
        }
    }
}

impl<'a> SymbolCaptureCollector<'a> for DeclNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        let sub: &dyn SymbolCaptureCollector = match self {
            DeclNode::Const { specs, .. } | DeclNode::Var { specs, .. } => specs,
            DeclNode::Function(decl) => &**decl,
            DeclNode::Type { .. } => return,
        };

        sub.collect_captured_symbols(captured, declared);
    }
}

impl<'a> SymbolCaptureCollector<'a> for Vec<BindingDeclSpecNode<'a>> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        for spec in self {
            spec.collect_captured_symbols(captured, declared);
        }
    }
}

impl<'a> SymbolCaptureCollector<'a> for BindingDeclSpecNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        // fake node to avoid repeating code
        let node = ShortVarDeclNode {
            ids: self.ids.clone(),
            exprs: self.exprs.clone(),
            location: 0..1,
            annotation: None,
        };

        node.collect_captured_symbols(captured, declared);
    }
}

impl<'a> SymbolCaptureCollector<'a> for FunctionDeclNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        if self.name.content() != "_" {
            declared.insert(self.name.content());
        }

        let Some(body) = &self.body else {
            // nothing else to do
            return;
        };

        let mut declared = declared.clone();

        declared.extend(extract_names_from_signature(
            &self.signature,
            self.receiver.as_ref(),
        ));

        body.collect_captured_symbols(captured, &mut declared);
    }
}

impl<'a> SymbolCaptureCollector<'a> for IfNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        let mut declared = declared.clone();

        if let Some(statement) = &self.stmt {
            statement.collect_captured_symbols(captured, &mut declared);
        }

        self.cond.collect_captured_symbols(captured, &mut declared);
        self.then.collect_captured_symbols(captured, &mut declared);

        if let Some(otherwise) = &self.otherwise {
            otherwise.collect_captured_symbols(captured, &mut declared);
        }
    }
}

impl<'a> SymbolCaptureCollector<'a> for ElseNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        let sub: &dyn SymbolCaptureCollector = match self {
            ElseNode::If(r#if) => &**r#if,
            ElseNode::Block(block) => block,
        };

        sub.collect_captured_symbols(captured, declared);
    }
}

impl<'a> SymbolCaptureCollector<'a> for ForNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        let mut declared = declared.clone();

        self.header
            .collect_captured_symbols(captured, &mut declared);

        self.body.collect_captured_symbols(captured, &mut declared);
    }
}

impl<'a> SymbolCaptureCollector<'a> for ForHeaderNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        let sub: &dyn SymbolCaptureCollector = match self {
            ForHeaderNode::Clause(clause) => clause,
            ForHeaderNode::Range(range) => range,
        };

        sub.collect_captured_symbols(captured, declared);
    }
}

impl<'a> SymbolCaptureCollector<'a> for ForClauseNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        if let Some(init) = &self.init {
            init.collect_captured_symbols(captured, declared);
        }

        if let Some(cond) = &self.cond {
            cond.collect_captured_symbols(captured, declared);
        }

        if let Some(post) = &self.post {
            post.collect_captured_symbols(captured, declared);
        }
    }
}

impl<'a> SymbolCaptureCollector<'a> for ForRangeNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        let sub: &dyn SymbolCaptureCollector = match self {
            // fake node so we can reuse impl
            ForRangeNode::Decl { lhs, range_expr } => &ShortVarDeclNode {
                ids: lhs.clone(),
                exprs: vec![range_expr.clone()],
                location: 0..1,
                annotation: None,
            },
            // fake node so we can reuse impl
            ForRangeNode::Assignment { lhs, range_expr } => &AssignmentNode {
                kind: AssignmentKind::Simple,
                lhs: lhs.clone(),
                rhs: vec![range_expr.clone()],
                location: 0..1,
                annotation: None,
            },
            ForRangeNode::None { range_expr } => range_expr,
        };

        sub.collect_captured_symbols(captured, declared);
    }
}

impl<'a> SymbolCaptureCollector<'a> for SelectNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        for clause in &self.clauses {
            clause.collect_captured_symbols(captured, declared);
        }
    }
}

impl<'a> SymbolCaptureCollector<'a> for SelectClauseNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        if let Some(case) = &self.case {
            case.collect_captured_symbols(captured, declared);
        }

        self.body.collect_captured_symbols(captured, declared);
    }
}

impl<'a> SymbolCaptureCollector<'a> for SwitchNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        let sub: &dyn SymbolCaptureCollector = match self {
            SwitchNode::Expr(node) => node,
            SwitchNode::Type(node) => node,
        };

        sub.collect_captured_symbols(captured, declared);
    }
}

impl<'a> SymbolCaptureCollector<'a> for ExprSwitchNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        let mut declared = declared.clone();

        if let Some(statement) = &self.stmt {
            statement.collect_captured_symbols(captured, &mut declared);
        }

        if let Some(expr) = &self.expr {
            expr.collect_captured_symbols(captured, &mut declared);
        }

        for clause in &self.clauses {
            clause.collect_captured_symbols(captured, &mut declared);
        }
    }
}

impl<'a> SymbolCaptureCollector<'a> for ExprSwitchCaseClause<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        self.exprs.collect_captured_symbols(captured, declared);
        self.body.collect_captured_symbols(captured, declared);
    }
}

impl<'a> SymbolCaptureCollector<'a> for TypeSwitchNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        let mut declared = declared.clone();

        if let Some(statement) = &self.stmt {
            statement.collect_captured_symbols(captured, &mut declared);
        }

        self.expr.collect_captured_symbols(captured, &mut declared);

        if let Some(decl) = &self.decl {
            let name = decl.content();

            if name != "_" {
                declared.insert(name);
            }
        }

        for clause in &self.clauses {
            clause.collect_captured_symbols(captured, &mut declared);
        }
    }
}

impl<'a> SymbolCaptureCollector<'a> for TypeSwitchCaseClause<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        self.body.collect_captured_symbols(captured, declared);
    }
}

impl<'a> SymbolCaptureCollector<'a> for Vec<ExprNode<'a>> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        for expr in self {
            expr.collect_captured_symbols(captured, declared);
        }
    }
}

impl<'a> SymbolCaptureCollector<'a> for ExprNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        let sub: &dyn SymbolCaptureCollector = match self {
            ExprNode::Name(span) => span,
            ExprNode::Literal(literal) => literal,
            ExprNode::Call(call) => call,
            ExprNode::Make(make) => make,
            ExprNode::Selection(selection) => selection,
            ExprNode::Indexing(indexing) => indexing,
            ExprNode::Slicing(slicing) => slicing,
            ExprNode::TypeInstantiation(instantiation) => instantiation,
            ExprNode::AmbiguousBracketAccess(ambiguous) => ambiguous,
            ExprNode::Conversion(conversion) => conversion,
            ExprNode::TypeAssertion(assertion) => assertion,
            ExprNode::UnaryOp { operand, .. } => &**operand,
            ExprNode::BinaryOp { left, right, .. } => {
                left.collect_captured_symbols(captured, declared);
                right.collect_captured_symbols(captured, declared);
                return;
            }
        };

        sub.collect_captured_symbols(captured, declared);
    }
}

// only for operand names, not any Span!
impl<'a> SymbolCaptureCollector<'a> for Span<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        let name = self.content();

        if !declared.contains(name) {
            captured.insert(name);
        }
    }
}

impl<'a> SymbolCaptureCollector<'a> for LiteralNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        let sub: &dyn SymbolCaptureCollector = match self {
            LiteralNode::Int { .. }
            | LiteralNode::Float { .. }
            | LiteralNode::Rune { .. }
            | LiteralNode::String { .. } => return,
            LiteralNode::Function {
                signature, body, ..
            } => {
                let mut declared = declared.clone();

                declared.extend(extract_names_from_signature(signature, None));

                body.collect_captured_symbols(captured, &mut declared);
                return;
            }
            LiteralNode::Array { length, values, .. } => {
                if let Some(length) = length {
                    length.collect_captured_symbols(captured, declared);
                }

                values
            }
            LiteralNode::Slice { values, .. }
            | LiteralNode::Map { values, .. }
            | LiteralNode::UnknownComposite { values, .. } => values,
            LiteralNode::Struct { fields, .. } => fields,
        };

        sub.collect_captured_symbols(captured, declared);
    }
}

impl<'a> SymbolCaptureCollector<'a> for CompositeLiteralElementNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        let sub: &dyn SymbolCaptureCollector = match self {
            CompositeLiteralElementNode::Expr(expr) => expr,
            CompositeLiteralElementNode::Nested(items) => items,
        };

        sub.collect_captured_symbols(captured, declared);
    }
}

impl<'a> SymbolCaptureCollector<'a> for CompositeLiteralElementListNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        for (index, value) in self {
            if let Some(index) = index {
                index.collect_captured_symbols(captured, declared);
            }

            value.collect_captured_symbols(captured, declared);
        }
    }
}

impl<'a> SymbolCaptureCollector<'a> for StructLiteralFieldsNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        match self {
            StructLiteralFieldsNode::Keyed(items) => {
                for (_, value) in items {
                    value.collect_captured_symbols(captured, declared);
                }
            }
            StructLiteralFieldsNode::Exhaustive(elements) => {
                for element in elements {
                    element.collect_captured_symbols(captured, declared);
                }
            }
        }
    }
}

impl<'a> SymbolCaptureCollector<'a> for CallNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        self.func.collect_captured_symbols(captured, declared);
        self.args.collect_captured_symbols(captured, declared);
    }
}

impl<'a> SymbolCaptureCollector<'a> for MakeNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        if let Some(n) = &self.n {
            n.collect_captured_symbols(captured, declared);
        }

        if let Some(m) = &self.m {
            m.collect_captured_symbols(captured, declared);
        }
    }
}

impl<'a> SymbolCaptureCollector<'a> for SelectionNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        self.base.collect_captured_symbols(captured, declared);
    }
}

impl<'a> SymbolCaptureCollector<'a> for IndexingNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        self.index.collect_captured_symbols(captured, declared);
        self.base.collect_captured_symbols(captured, declared);
    }
}

impl<'a> SymbolCaptureCollector<'a> for SlicingNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        if let Some(low) = &self.low {
            low.collect_captured_symbols(captured, declared);
        }

        if let Some(high) = &self.high {
            high.collect_captured_symbols(captured, declared);
        }

        if let Some(max) = &self.max {
            max.collect_captured_symbols(captured, declared);
        }

        self.base.collect_captured_symbols(captured, declared);
    }
}

impl<'a> SymbolCaptureCollector<'a> for TypeInstantiationNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        // type arguments live in the type namespace, not the value namespace,
        // so they capture no value-level symbols
        self.base.collect_captured_symbols(captured, declared);
    }
}

impl<'a> SymbolCaptureCollector<'a> for AmbiguousBracketAccessNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        // we don't know which interpretation will be chosen, so we have to be
        // conservative and consider both possible cases
        IndexingNode::from(self.clone()).collect_captured_symbols(captured, declared);
        TypeInstantiationNode::from(self.clone()).collect_captured_symbols(captured, declared);
    }
}

impl<'a> SymbolCaptureCollector<'a> for ConversionNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        self.expr.collect_captured_symbols(captured, declared);
    }
}

impl<'a> SymbolCaptureCollector<'a> for TypeAssertionNode<'a> {
    fn collect_captured_symbols(
        &self,
        captured: &mut HashSet<&'a str>,
        declared: &mut HashSet<&'a str>,
    ) {
        self.expr.collect_captured_symbols(captured, declared);
    }
}
