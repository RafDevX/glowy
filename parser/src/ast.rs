use std::cmp;

use crate::{Annotation, Location, Span};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceFileNode<'a> {
    pub package_clause: PackageClauseNode<'a>,
    pub imports: Vec<ImportNode<'a>>,
    pub top_level_decls: Vec<DeclNode<'a>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageClauseNode<'a> {
    pub id: Span<'a>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportNode<'a> {
    pub specs: Vec<ImportSpecNode<'a>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportSpecNode<'a> {
    pub identifier: Option<Span<'a>>,
    pub path: String,
    pub location: Location,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeclNode<'a> {
    Const {
        specs: Vec<BindingDeclSpecNode<'a>>,
        location: Location,
        annotation: Option<Box<Annotation<'a>>>,
    },
    Var {
        specs: Vec<BindingDeclSpecNode<'a>>,
        location: Location,
        annotation: Option<Box<Annotation<'a>>>,
    },
    Function(FunctionDeclNode<'a>),
}

impl<'a> From<FunctionDeclNode<'a>> for DeclNode<'a> {
    fn from(node: FunctionDeclNode<'a>) -> Self {
        Self::Function(node)
    }
}

// binding = const or var, since specs look the same for both
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingDeclSpecNode<'a> {
    pub ids: Vec<Span<'a>>,
    pub exprs: Vec<ExprNode<'a>>,
    pub r#type: Option<TypeNode<'a>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypeNode<'a> {
    Name {
        package: Option<Span<'a>>, // for qualified type names
        id: Span<'a>,
        args: Vec<TypeNode<'a>>,
    },
    Channel {
        r#type: Box<TypeNode<'a>>, // what values can be sent/received
        direction: Option<ChannelDirection>,
    },
    Array {
        length: Box<ExprNode<'a>>,
        element: Box<TypeNode<'a>>,
    },
    Slice {
        element: Box<TypeNode<'a>>,
    },
    Map {
        key: Box<TypeNode<'a>>,
        element: Box<TypeNode<'a>>,
    },
    Struct {
        fields: Vec<FieldDeclNode<'a>>,
    },
    Function {
        signature: Box<FunctionSignatureNode<'a>>,
    },
    // TODO: Literal
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelDirection {
    Send,
    Receive,
}

// TODO: support embedded fields (which are not this shape)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldDeclNode<'a> {
    pub ids: Vec<Option<Span<'a>>>, // None if just padding ("_" blank field)
    pub r#type: TypeNode<'a>,
    pub tag: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionDeclNode<'a> {
    pub name: Span<'a>,
    // TODO: pub type_params: Vec<___>,
    pub signature: FunctionSignatureNode<'a>,
    /// note: this parser intentionally does not support omitted bodies!
    /// (it would defeat the purpose of information flow control, and
    ///  make parsing much more complicated due to 2 optional elements
    ///  in a row, namely signature result and body)
    pub body: BlockNode<'a>,
    pub location: Location,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionSignatureNode<'a> {
    pub params: Vec<FunctionParamDeclNode<'a>>,
    pub result: Option<FunctionResultNode<'a>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FunctionResultNode<'a> {
    Single(TypeNode<'a>),
    Params(Vec<FunctionParamDeclNode<'a>>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionParamDeclNode<'a> {
    pub ids: Vec<Span<'a>>,
    pub variadic: bool, // whether type is ...T
    pub r#type: TypeNode<'a>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExprNode<'a> {
    Name(OperandNameNode<'a>),
    Literal(LiteralNode<'a>),
    Call(CallNode<'a>),
    Indexing(IndexingNode<'a>),
    // TODO: more primary expressions...
    UnaryOp {
        kind: UnaryOpKind,
        operand: Box<ExprNode<'a>>,
        location: Location, // for better error messages
    },
    BinaryOp {
        kind: BinaryOpKind,
        left: Box<ExprNode<'a>>,
        right: Box<ExprNode<'a>>,
        location: Location, // for better error messages
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnaryOpKind {
    Identity,   // +x is 0 + x
    Negation,   // -x is 0 - x
    Complement, // ^x is m ^ x for [m = 0b111..11 if x unsigned] or [m = -1 if x signed]
    Not,        //_!x
    Deref,      //_*x
    Address,    // &x
    Receive,    // <-x
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinaryOpKind {
    Eq,         // x == y
    NotEq,      // x != y
    Less,       // x < y
    LessEq,     // x <= y
    Greater,    // x > y
    GreaterEq,  // x >= y
    Sum,        // x + y
    Diff,       // x - y
    Product,    // x * y
    Quotient,   // x / y
    Remainder,  // x % y
    ShiftLeft,  // x << y
    ShiftRight, // x >> y
    BitwiseOr,  // x | y
    BitwiseAnd, // x & y
    BitwiseXor, // x ^ y
    BitClear,   // x &^ y (AND NOT)
    LogicalAnd, // x && y
    LogicalOr,  // x || y
}

impl<'a> From<OperandNameNode<'a>> for ExprNode<'a> {
    fn from(node: OperandNameNode<'a>) -> Self {
        Self::Name(node)
    }
}

impl<'a> From<LiteralNode<'a>> for ExprNode<'a> {
    fn from(node: LiteralNode<'a>) -> Self {
        Self::Literal(node)
    }
}

impl<'a> From<CallNode<'a>> for ExprNode<'a> {
    fn from(node: CallNode<'a>) -> Self {
        Self::Call(node)
    }
}

impl<'a> From<IndexingNode<'a>> for ExprNode<'a> {
    fn from(node: IndexingNode<'a>) -> Self {
        Self::Indexing(node)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperandNameNode<'a> {
    pub package: Option<Span<'a>>, // for qualified operand names
    pub id: Span<'a>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LiteralNode<'a> {
    Int {
        value: u64,
        location: Location,
    },
    Float {
        value: OrderedF64,
        location: Location,
    },
    Rune {
        value: char,
        location: Location,
    },
    String {
        value: String,
        location: Location,
    },
    // all below should in theory be one Composite { r#type, value }, but this
    // is simpler and works for now; nevertheless, it does not support arbitrary
    // type literals (where `LiteralType` is `TypeName [TypeArgs]`, per spec)
    Array {
        length: Option<Box<ExprNode<'a>>>, // None if [...]int
        element: TypeNode<'a>,
        values: CompositeLiteralElementListNode<'a>,
        location: Location,
    },
    Slice {
        element: TypeNode<'a>,
        values: CompositeLiteralElementListNode<'a>,
        location: Location,
    },
    Map {
        key: TypeNode<'a>,
        element: TypeNode<'a>,
        values: CompositeLiteralElementListNode<'a>,
        location: Location,
    },
    // Struct
}

/// Wrapper for f64 to support Eq and Ord
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct OrderedF64(pub f64);

impl Eq for OrderedF64 {}

impl Ord for OrderedF64 {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.0.total_cmp(&other.0)
    }
}

impl PartialOrd for OrderedF64 {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

pub type CompositeLiteralElementListNode<'a> =
    Vec<(Option<ExprNode<'a>>, CompositeLiteralElementNode<'a>)>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompositeLiteralElementNode<'a> {
    Expr(ExprNode<'a>),
    Nested(CompositeLiteralElementListNode<'a>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallNode<'a> {
    pub func: Box<ExprNode<'a>>,
    pub type_arg: Option<TypeNode<'a>>,
    pub args: Vec<ExprNode<'a>>,
    pub variadic: bool,     // whether the last argument is "x..."
    pub location: Location, // for better error messages
    pub annotation: Option<Box<Annotation<'a>>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexingNode<'a> {
    pub expr: Box<ExprNode<'a>>,
    pub index: Box<ExprNode<'a>>,
    pub location: Location, // for better error messages
}

pub type BlockNode<'a> = Vec<StatementNode<'a>>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatementNode<'a> {
    // simple
    Empty {
        location: Location, // for better error messages
    },
    Expr(ExprNode<'a>),
    Send(SendNode<'a>),
    Inc {
        operand: ExprNode<'a>,
        location: Location, // for better error messages
    },
    Dec {
        operand: ExprNode<'a>,
        location: Location, // for better error messages
    },
    Assignment(AssignmentNode<'a>),
    ShortVarDecl(ShortVarDeclNode<'a>),

    // non-simple
    Labeled {
        label: Span<'a>,
        inner: Box<StatementNode<'a>>,
    },
    Block(BlockNode<'a>),
    Decl(DeclNode<'a>),
    If(IfNode<'a>),
    For(ForNode<'a>),
    Switch(SwitchNode<'a>),
    Fallthrough {
        location: Location, // for better error messages
    },
    Continue {
        label: Option<Span<'a>>,
        location: Location, // for better error messages
    },
    Break {
        label: Option<Span<'a>>,
        location: Location, // for better error messages
    },
    Return {
        exprs: Vec<ExprNode<'a>>,
        location: Location, // for better error messages
    },
    Go {
        expr: ExprNode<'a>, // should be a Call, but hard for parser to ensure
        location: Location, // for better error messages
    },
}

impl<'a> From<ExprNode<'a>> for StatementNode<'a> {
    fn from(node: ExprNode<'a>) -> Self {
        Self::Expr(node)
    }
}

impl<'a> From<SendNode<'a>> for StatementNode<'a> {
    fn from(node: SendNode<'a>) -> Self {
        Self::Send(node)
    }
}

impl<'a> From<AssignmentNode<'a>> for StatementNode<'a> {
    fn from(node: AssignmentNode<'a>) -> Self {
        Self::Assignment(node)
    }
}

impl<'a> From<ShortVarDeclNode<'a>> for StatementNode<'a> {
    fn from(node: ShortVarDeclNode<'a>) -> Self {
        Self::ShortVarDecl(node)
    }
}

impl<'a> From<DeclNode<'a>> for StatementNode<'a> {
    fn from(node: DeclNode<'a>) -> Self {
        Self::Decl(node)
    }
}

impl<'a> From<IfNode<'a>> for StatementNode<'a> {
    fn from(node: IfNode<'a>) -> Self {
        Self::If(node)
    }
}

impl<'a> From<ForNode<'a>> for StatementNode<'a> {
    fn from(node: ForNode<'a>) -> Self {
        Self::For(node)
    }
}

impl<'a> From<SwitchNode<'a>> for StatementNode<'a> {
    fn from(node: SwitchNode<'a>) -> Self {
        Self::Switch(node)
    }
}

impl<'a> From<BlockNode<'a>> for StatementNode<'a> {
    fn from(node: BlockNode<'a>) -> Self {
        Self::Block(node)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendNode<'a> {
    pub channel: ExprNode<'a>,
    pub expr: ExprNode<'a>,
    pub location: Location, // for better error messages
    pub annotation: Option<Box<Annotation<'a>>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssignmentNode<'a> {
    pub kind: AssignmentKind,
    pub lhs: Vec<ExprNode<'a>>,
    pub rhs: Vec<ExprNode<'a>>,
    pub location: Location, // for better error messages
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssignmentKind {
    Simple,     //   =
    Sum,        //  +=
    Diff,       //  -=
    Product,    //_ *=
    Quotient,   //  /=
    Remainder,  //  %=
    ShiftLeft,  // <<=
    ShiftRight, // >>=
    BitwiseOr,  //  |=
    BitwiseAnd, //  &=
    BitwiseXor, //  ^=
    BitClear,   // &^=
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShortVarDeclNode<'a> {
    pub ids: Vec<Span<'a>>,
    pub exprs: Vec<ExprNode<'a>>,
    pub location: Location, // for better error messages
    pub annotation: Option<Box<Annotation<'a>>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IfNode<'a> {
    pub stmt: Option<Box<StatementNode<'a>>>, // run before cond is evaluated
    pub cond: ExprNode<'a>,
    pub then: BlockNode<'a>,
    pub otherwise: Option<ElseNode<'a>>,
    pub location: Location,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ElseNode<'a> {
    If(Box<IfNode<'a>>),
    Block(BlockNode<'a>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForNode<'a> {
    pub header: ForHeaderNode<'a>,
    pub header_location: Location,
    pub body: BlockNode<'a>,
    pub location: Location,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForHeaderNode<'a> {
    Clause(ForClauseNode<'a>),
    Range(ForRangeNode<'a>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForClauseNode<'a> {
    pub init: Option<Box<StatementNode<'a>>>,
    pub cond: Option<ExprNode<'a>>, // if omitted, same as "true"
    pub post: Option<Box<StatementNode<'a>>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForRangeNode<'a> {
    Decl {
        lhs: Vec<Span<'a>>,
        range_expr: ExprNode<'a>,
    },
    Assignment {
        lhs: Vec<ExprNode<'a>>,
        range_expr: ExprNode<'a>,
    },
    None {
        range_expr: ExprNode<'a>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SwitchNode<'a> {
    Expr(ExprSwitchNode<'a>),
    Type(TypeSwitchNode<'a>),
}

impl<'a> From<ExprSwitchNode<'a>> for SwitchNode<'a> {
    fn from(node: ExprSwitchNode<'a>) -> Self {
        Self::Expr(node)
    }
}

impl<'a> From<TypeSwitchNode<'a>> for SwitchNode<'a> {
    fn from(node: TypeSwitchNode<'a>) -> Self {
        Self::Type(node)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExprSwitchNode<'a> {
    pub stmt: Option<Box<StatementNode<'a>>>, // run before expr is executed
    pub expr: Option<ExprNode<'a>>,
    pub clauses: Vec<ExprSwitchCaseClause<'a>>,
    pub location: Location,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExprSwitchCaseClause<'a> {
    pub exprs: Vec<ExprNode<'a>>, // empty means "default"
    pub body: Vec<StatementNode<'a>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeSwitchNode<'a> {
    pub stmt: Option<Box<StatementNode<'a>>>, // run before expr is executed
    pub decl: Option<Span<'a>>,               // identifier for short var decl
    pub expr: ExprNode<'a>,
    pub clauses: Vec<TypeSwitchCaseClause<'a>>,
    pub location: Location,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeSwitchCaseClause<'a> {
    pub types: Vec<TypeNode<'a>>, // empty means "default"
    pub body: Vec<StatementNode<'a>>,
}
