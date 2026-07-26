use std::{borrow::Cow, cmp};

use crate::{Annotation, Location, Span};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceFileNode<'a> {
    pub package_clause: PackageClauseNode<'a>,
    pub imports: Vec<ImportNode<'a>>,
    pub top_level_decls: Vec<DeclNode<'a>>,
    pub build_constraint: Option<BuildConstraintNode<'a>>,
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
    Type {
        specs: Vec<TypeDeclSpecNode<'a>>,
        location: Location,
    },
    Function(Box<FunctionDeclNode<'a>>),
}

impl<'a> From<FunctionDeclNode<'a>> for DeclNode<'a> {
    #[inline]
    fn from(node: FunctionDeclNode<'a>) -> Self {
        Self::Function(Box::new(node))
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
pub struct TypeDeclSpecNode<'a> {
    pub alias: bool, // otherwise, typedef
    pub id: Span<'a>,
    pub params: Vec<TypeParam<'a>>,
    pub r#type: TypeNode<'a>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeParam<'a> {
    pub ids: Vec<Span<'a>>,
    pub constraint: Vec<InterfaceTypeTermNode<'a>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypeNode<'a> {
    Name(TypeNameNode<'a>),
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
    Interface {
        elements: Vec<InterfaceElementNode<'a>>,
    },
    Function {
        signature: Box<FunctionSignatureNode<'a>>,
    },
    Pointer {
        base: Box<TypeNode<'a>>,
    },
}

impl TypeNode<'_> {
    #[must_use]
    #[inline]
    pub fn strip_pointers(&self) -> &Self {
        if let Self::Pointer { base } = self {
            base
        } else {
            self
        }
    }
}

impl<'a> From<TypeNameNode<'a>> for TypeNode<'a> {
    #[inline]
    fn from(node: TypeNameNode<'a>) -> Self {
        Self::Name(node)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeNameNode<'a> {
    pub package: Option<Span<'a>>, // for qualified type names
    pub id: Span<'a>,
    // technically, args are not part of a TypeName per the spec, but they
    // always follow one, so it's easier to keep everything together
    pub args: Vec<TypeNode<'a>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelDirection {
    Send,
    Receive,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldDeclNode<'a> {
    Explicit(ExplicitFieldDeclNode<'a>),
    Embedded(EmbeddedFieldDeclNode<'a>),
}

impl<'a> From<ExplicitFieldDeclNode<'a>> for FieldDeclNode<'a> {
    #[inline]
    fn from(node: ExplicitFieldDeclNode<'a>) -> Self {
        Self::Explicit(node)
    }
}

impl<'a> From<EmbeddedFieldDeclNode<'a>> for FieldDeclNode<'a> {
    #[inline]
    fn from(node: EmbeddedFieldDeclNode<'a>) -> Self {
        Self::Embedded(node)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExplicitFieldDeclNode<'a> {
    pub ids: Vec<Option<Span<'a>>>, // None if just padding ("_" blank field)
    pub r#type: TypeNode<'a>,
    pub tag: Option<String>,
    pub location: Location, // for better error messages
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmbeddedFieldDeclNode<'a> {
    pub pointer: bool, // whether prefixed by `*`
    pub r#type: TypeNameNode<'a>,
    pub tag: Option<String>,
    pub location: Location, // for better error messages
}

/// This represents both function declarations and method declarations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionDeclNode<'a> {
    pub receiver: Option<FunctionParamDeclNode<'a>>, // if method
    pub name: Span<'a>,
    pub type_params: Vec<TypeParam<'a>>,
    pub signature: FunctionSignatureNode<'a>,
    pub body: Option<BlockNode<'a>>,
    pub location: Location,
    pub annotation: Option<Box<Annotation<'a>>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionSignatureNode<'a> {
    pub params: Vec<FunctionParamDeclNode<'a>>,
    pub result: FunctionResultNode<'a>,
}

impl FunctionSignatureNode<'_> {
    #[must_use]
    #[inline]
    pub fn count_inputs(&self) -> usize {
        self.params
            .iter()
            .map(|param| cmp::max(1, param.ids.len()))
            .sum()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FunctionResultNode<'a> {
    None,
    Single(TypeNode<'a>),
    Params(Vec<FunctionParamDeclNode<'a>>),
}

impl FunctionResultNode<'_> {
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Single(_) => 1,
            Self::Params(vec) => vec.iter().map(|param| cmp::max(1, param.ids.len())).sum(),
        }
    }

    // make clippy happy (clippy::len_without_is_empty)
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::None)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionParamDeclNode<'a> {
    pub ids: Vec<Span<'a>>,
    pub variadic: bool, // whether type is ...T
    pub r#type: TypeNode<'a>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InterfaceElementNode<'a> {
    Method {
        name: Span<'a>,
        signature: FunctionSignatureNode<'a>,
    },
    TypeUnion(Vec<InterfaceTypeTermNode<'a>>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InterfaceTypeTermNode<'a> {
    Simple(TypeNode<'a>),
    Underlying(TypeNode<'a>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExprNode<'a> {
    Name(Span<'a>),
    // ^ note: qualified operand names supported only via selection -- even
    // though technically they should just be a type of operand name, having it
    // as a separate super-expression greatly simplifies parsing and is
    // functionally equivalent (in some cases, the parser does not have enough
    // information to distinguish a qualified name `pkg.Exported` from a normal
    // struct-like selection `obj.Field`)
    Literal(LiteralNode<'a>),
    Call(CallNode<'a>),
    Make(MakeNode<'a>),
    New(NewNode<'a>),
    Selection(SelectionNode<'a>),
    Indexing(IndexingNode<'a>),
    Slicing(SlicingNode<'a>),
    Conversion(ConversionNode<'a>),
    TypeAssertion(TypeAssertionNode<'a>),
    // instantiation is not described/listed by the Go spec as a true kind of
    // expression, but it exists as a semantic concept that requires some form
    // of syntactic representation, and it behaves like an expression in all
    // relevant regards (e.g., `inst := myGenericFunc[int]; inst(2)` is valid)
    TypeInstantiation(TypeInstantiationNode<'a>),
    // this is not a real expression type, but rather represents something such
    // as `x[T]`, which is known to be either an indexing expression or a type
    // instantiation but the distinction requires contextual information that is
    // not available at parse time, so disambiguation is left to the consumer
    AmbiguousBracketAccess(AmbiguousBracketAccessNode<'a>),
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

impl ExprNode<'_> {
    #[must_use]
    #[inline]
    pub fn location(&self) -> Cow<'_, Location> {
        let r#ref = match self {
            ExprNode::Name(name) => return Cow::Owned(name.location()),
            ExprNode::Literal(
                LiteralNode::Int { location, .. }
                | LiteralNode::Float { location, .. }
                | LiteralNode::Rune { location, .. }
                | LiteralNode::String { location, .. }
                | LiteralNode::Function { location, .. }
                | LiteralNode::Array { location, .. }
                | LiteralNode::Slice { location, .. }
                | LiteralNode::Map { location, .. }
                | LiteralNode::Struct { location, .. }
                | LiteralNode::UnknownComposite { location, .. },
            )
            | ExprNode::UnaryOp { location, .. }
            | ExprNode::BinaryOp { location, .. } => location,
            ExprNode::Call(call) => &call.location,
            ExprNode::Make(make) => &make.location,
            ExprNode::New(new) => &new.location,
            ExprNode::Selection(selection) => &selection.location,
            ExprNode::Indexing(indexing) => &indexing.location,
            ExprNode::Slicing(slicing) => &slicing.location,
            ExprNode::Conversion(conversion) => &conversion.location,
            ExprNode::TypeAssertion(assertion) => &assertion.location,
            ExprNode::TypeInstantiation(instantiation) => &instantiation.location,
            ExprNode::AmbiguousBracketAccess(ambiguous) => &ambiguous.location,
        };

        Cow::Borrowed(r#ref)
    }
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

impl BinaryOpKind {
    #[must_use]
    #[inline]
    pub fn short_circuits(&self) -> bool {
        // Bitwise operators do not short-circuit, only Logical ones, per spec

        matches!(self, Self::LogicalAnd | Self::LogicalOr)
    }
}

impl<'a> From<LiteralNode<'a>> for ExprNode<'a> {
    #[inline]
    fn from(node: LiteralNode<'a>) -> Self {
        Self::Literal(node)
    }
}

impl<'a> From<CallNode<'a>> for ExprNode<'a> {
    #[inline]
    fn from(node: CallNode<'a>) -> Self {
        Self::Call(node)
    }
}

impl<'a> From<MakeNode<'a>> for ExprNode<'a> {
    #[inline]
    fn from(node: MakeNode<'a>) -> Self {
        Self::Make(node)
    }
}

impl<'a> From<NewNode<'a>> for ExprNode<'a> {
    #[inline]
    fn from(node: NewNode<'a>) -> Self {
        Self::New(node)
    }
}

impl<'a> From<SelectionNode<'a>> for ExprNode<'a> {
    #[inline]
    fn from(node: SelectionNode<'a>) -> Self {
        Self::Selection(node)
    }
}

impl<'a> From<IndexingNode<'a>> for ExprNode<'a> {
    #[inline]
    fn from(node: IndexingNode<'a>) -> Self {
        Self::Indexing(node)
    }
}

impl<'a> From<SlicingNode<'a>> for ExprNode<'a> {
    #[inline]
    fn from(node: SlicingNode<'a>) -> Self {
        Self::Slicing(node)
    }
}

impl<'a> From<ConversionNode<'a>> for ExprNode<'a> {
    #[inline]
    fn from(node: ConversionNode<'a>) -> Self {
        Self::Conversion(node)
    }
}

impl<'a> From<TypeAssertionNode<'a>> for ExprNode<'a> {
    #[inline]
    fn from(node: TypeAssertionNode<'a>) -> Self {
        Self::TypeAssertion(node)
    }
}

impl<'a> From<TypeInstantiationNode<'a>> for ExprNode<'a> {
    #[inline]
    fn from(node: TypeInstantiationNode<'a>) -> Self {
        Self::TypeInstantiation(node)
    }
}

impl<'a> From<AmbiguousBracketAccessNode<'a>> for ExprNode<'a> {
    #[inline]
    fn from(node: AmbiguousBracketAccessNode<'a>) -> Self {
        Self::AmbiguousBracketAccess(node)
    }
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
    Function {
        signature: FunctionSignatureNode<'a>,
        body: BlockNode<'a>,
        location: Location,
        annotation: Option<Box<Annotation<'a>>>,
    },
    // all below should in theory be one Composite { r#type, value }, but this
    // is simpler and works for now
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
    Struct {
        r#type: TypeNode<'a>,
        fields: StructLiteralFieldsNode<'a>,
        location: Location,
    },
    // we cannot know what this is at parse time (array/slice/map/struct)
    UnknownComposite {
        r#type: TypeNode<'a>,
        values: CompositeLiteralElementListNode<'a>,
        location: Location,
    },
}

/// Wrapper for f64 to support Eq and Ord
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct OrderedF64(pub f64);

impl Eq for OrderedF64 {}

impl Ord for OrderedF64 {
    #[inline]
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.0.total_cmp(&other.0)
    }
}

impl PartialOrd for OrderedF64 {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StructLiteralFieldsNode<'a> {
    Keyed(Vec<(Span<'a>, CompositeLiteralElementNode<'a>)>),
    Exhaustive(Vec<CompositeLiteralElementNode<'a>>), // no keys; ordered fields
}

#[rustfmt::skip]
pub type CompositeLiteralElementListNode<'a> = Vec<(
    Option<CompositeLiteralKeyNode<'a>>,
    CompositeLiteralElementNode<'a>
)>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompositeLiteralKeyNode<'a> {
    Expr(ExprNode<'a>),
    Nested {
        elements: CompositeLiteralElementListNode<'a>,
        location: Location, // for better error messages
    },
}

impl CompositeLiteralKeyNode<'_> {
    #[must_use]
    #[inline]
    pub fn location(&self) -> Cow<'_, Location> {
        match self {
            Self::Expr(expr) => expr.location(),
            Self::Nested { location, .. } => Cow::Borrowed(location),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompositeLiteralElementNode<'a> {
    Expr(ExprNode<'a>),
    Nested {
        elements: CompositeLiteralElementListNode<'a>,
        location: Location, // for better error messages
    },
}

impl CompositeLiteralElementNode<'_> {
    #[must_use]
    #[inline]
    pub fn location(&self) -> Cow<'_, Location> {
        match self {
            Self::Expr(expr) => expr.location(),
            Self::Nested { location, .. } => Cow::Borrowed(location),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallNode<'a> {
    pub func: Box<ExprNode<'a>>,
    pub args: Vec<ExprNode<'a>>,
    pub variadic: bool,     // whether the last argument is "x..."
    pub location: Location, // for better error messages
    pub annotation: Option<Box<Annotation<'a>>>,
}

// technically this should be a CallNode per the spec, but since the first
// argument is a type, and since this function has special implications, we just
// treat it as another kind of expression (not a function call)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MakeNode<'a> {
    pub r#type: TypeNode<'a>,
    pub n: Option<Box<ExprNode<'a>>>,
    pub m: Option<Box<ExprNode<'a>>>,
    pub location: Location, // for better error messages
}

// technically this should be a CallNode per the spec, but since the first
// argument can be a type, and since this function has special implications, we
// just treat it as another kind of expression (not a function call)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewNode<'a> {
    pub arg: NewArgNode<'a>,
    pub location: Location, // for better error messages
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NewArgNode<'a> {
    Type(TypeNode<'a>),
    Expr(Box<ExprNode<'a>>),
    // both `new(T)` and `new(expr)` are valid Go, and sometimes they are not
    // distinguishable at parse-time, so in the ambiguous case both a parsed
    // type and a parsed expression are provided: it is up to the consumer to
    // resolve the ambiguity and make the most appropriate decision available
    // according to contextual information (such as what types are defined)
    Ambiguous {
        if_type: TypeNode<'a>,
        if_expr: Box<ExprNode<'a>>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectionNode<'a> {
    pub base: Box<ExprNode<'a>>,
    pub selector: Span<'a>,
    pub location: Location, // for better error messages
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexingNode<'a> {
    pub base: Box<ExprNode<'a>>,
    pub index: Box<ExprNode<'a>>,
    pub location: Location, // for better error messages
}

impl<'a> From<AmbiguousBracketAccessNode<'a>> for IndexingNode<'a> {
    #[inline]
    fn from(ambiguous: AmbiguousBracketAccessNode<'a>) -> Self {
        let AmbiguousBracketAccessNode {
            base,
            index_if_indexing: index,
            type_arg_if_instantiation: _,
            location,
        } = ambiguous;

        Self {
            base,
            index,
            location,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlicingNode<'a> {
    pub base: Box<ExprNode<'a>>,
    pub low: Option<Box<ExprNode<'a>>>,
    pub high: Option<Box<ExprNode<'a>>>,
    pub max: Option<Box<ExprNode<'a>>>,
    pub location: Location, // for better error messages
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConversionNode<'a> {
    pub r#type: TypeNode<'a>,
    pub expr: Box<ExprNode<'a>>,
    pub location: Location, // for better error messages
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeAssertionNode<'a> {
    pub expr: Box<ExprNode<'a>>,
    pub r#type: TypeNode<'a>,
    pub location: Location, // for better error messages
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeInstantiationNode<'a> {
    pub base: Box<ExprNode<'a>>,
    pub type_args: Vec<TypeNode<'a>>,
    pub location: Location, // for better error messages
}

impl<'a> From<AmbiguousBracketAccessNode<'a>> for TypeInstantiationNode<'a> {
    #[inline]
    fn from(ambiguous: AmbiguousBracketAccessNode<'a>) -> Self {
        let AmbiguousBracketAccessNode {
            base,
            index_if_indexing: _,
            type_arg_if_instantiation,
            location,
        } = ambiguous;

        Self {
            base,
            type_args: vec![type_arg_if_instantiation],
            location,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AmbiguousBracketAccessNode<'a> {
    pub base: Box<ExprNode<'a>>,
    pub index_if_indexing: Box<ExprNode<'a>>,
    // if there were multiple args, there'd be no ambiguity
    pub type_arg_if_instantiation: TypeNode<'a>,
    pub location: Location, // for better error messages
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockNode<'a> {
    pub stmts: Vec<StatementNode<'a>>,
    pub location: Location, // for better error messages
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatementNode<'a> {
    // simple
    Empty {
        location: Location, // for better error messages
    },
    Expr {
        expr: ExprNode<'a>,
        annotation: Option<Box<Annotation<'a>>>,
    },
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
    Select(SelectNode<'a>),
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
    Goto {
        label: Span<'a>,
        location: Location, // for better error messages
    },
    Go {
        expr: ExprNode<'a>, // should be a Call, but hard for parser to ensure
        location: Location, // for better error messages
    },
    Defer {
        expr: ExprNode<'a>, // should be a Call, but hard for parser to ensure
        location: Location, // for better error messages
    },
}

impl StatementNode<'_> {
    #[must_use]
    #[inline]
    pub fn location(&self) -> Cow<'_, Location> {
        let r#ref = match self {
            StatementNode::Empty { location }
            | StatementNode::Block(BlockNode { location, .. })
            | StatementNode::Send(SendNode { location, .. })
            | StatementNode::Inc { location, .. }
            | StatementNode::Dec { location, .. }
            | StatementNode::Assignment(AssignmentNode { location, .. })
            | StatementNode::ShortVarDecl(ShortVarDeclNode { location, .. })
            | StatementNode::Decl(
                DeclNode::Const { location, .. }
                | DeclNode::Var { location, .. }
                | DeclNode::Type { location, .. },
            )
            | StatementNode::If(IfNode { location, .. })
            | StatementNode::For(ForNode { location, .. })
            | StatementNode::Select(SelectNode { location, .. })
            | StatementNode::Switch(
                SwitchNode::Expr(ExprSwitchNode { location, .. })
                | SwitchNode::Type(TypeSwitchNode { location, .. }),
            )
            | StatementNode::Fallthrough { location }
            | StatementNode::Continue { location, .. }
            | StatementNode::Break { location, .. }
            | StatementNode::Return { location, .. }
            | StatementNode::Goto { location, .. }
            | StatementNode::Go { location, .. }
            | StatementNode::Defer { location, .. } => location,
            StatementNode::Decl(DeclNode::Function(function)) => &function.location,
            StatementNode::Expr { expr, .. } => return expr.location(),
            StatementNode::Labeled { label, inner } => {
                let loc = inner.location();

                return Cow::Owned(label.location().start..loc.end);
            }
        };

        Cow::Borrowed(r#ref)
    }
}

impl<'a> From<SendNode<'a>> for StatementNode<'a> {
    #[inline]
    fn from(node: SendNode<'a>) -> Self {
        Self::Send(node)
    }
}

impl<'a> From<AssignmentNode<'a>> for StatementNode<'a> {
    #[inline]
    fn from(node: AssignmentNode<'a>) -> Self {
        Self::Assignment(node)
    }
}

impl<'a> From<ShortVarDeclNode<'a>> for StatementNode<'a> {
    #[inline]
    fn from(node: ShortVarDeclNode<'a>) -> Self {
        Self::ShortVarDecl(node)
    }
}

impl<'a> From<DeclNode<'a>> for StatementNode<'a> {
    #[inline]
    fn from(node: DeclNode<'a>) -> Self {
        Self::Decl(node)
    }
}

impl<'a> From<IfNode<'a>> for StatementNode<'a> {
    #[inline]
    fn from(node: IfNode<'a>) -> Self {
        Self::If(node)
    }
}

impl<'a> From<ForNode<'a>> for StatementNode<'a> {
    #[inline]
    fn from(node: ForNode<'a>) -> Self {
        Self::For(node)
    }
}

impl<'a> From<SelectNode<'a>> for StatementNode<'a> {
    #[inline]
    fn from(node: SelectNode<'a>) -> Self {
        Self::Select(node)
    }
}

impl<'a> From<SwitchNode<'a>> for StatementNode<'a> {
    #[inline]
    fn from(node: SwitchNode<'a>) -> Self {
        Self::Switch(node)
    }
}

impl<'a> From<BlockNode<'a>> for StatementNode<'a> {
    #[inline]
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
    pub annotation: Option<Box<Annotation<'a>>>,
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
pub struct SelectNode<'a> {
    pub clauses: Vec<SelectClauseNode<'a>>,
    pub location: Location,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectClauseNode<'a> {
    pub case: Option<StatementNode<'a>>, // None means `default`
    pub body: Vec<StatementNode<'a>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SwitchNode<'a> {
    Expr(ExprSwitchNode<'a>),
    Type(TypeSwitchNode<'a>),
}

impl<'a> From<ExprSwitchNode<'a>> for SwitchNode<'a> {
    #[inline]
    fn from(node: ExprSwitchNode<'a>) -> Self {
        Self::Expr(node)
    }
}

impl<'a> From<TypeSwitchNode<'a>> for SwitchNode<'a> {
    #[inline]
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
    pub types: Vec<Option<TypeNode<'a>>>, // empty means "default"; None = "nil"
    pub body: Vec<StatementNode<'a>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildConstraintNode<'a> {
    pub expr: BuildConstraintExprNode<'a>,
    pub location: Location,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuildConstraintExprNode<'a> {
    Tag(&'a str),
    Not(Box<Self>),
    And(Vec<Self>),
    Or(Vec<Self>),
}
