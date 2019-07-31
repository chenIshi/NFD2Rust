pub type Program = BlockStmt;

#[derive(PartialEq, Debug, Clone)]
pub enum Stmt {
    AssignStmt(Type, Ident, Expr),
    ExprStmt(Expr),
}

pub type BlockStmt = Vec<Stmt>;

#[derive(PartialEq, Debug, Clone)]
pub enum Expr {
    IdentExpr(Ident),
    LitExpr(Literal),
    PrefixExpr(Prefix, Box<Expr>),
    InfixExpr(Infix, Box<Expr>, Box<Expr>),
    ListExpr(Vec<Expr>),
    IndexExpr { array: Box<Expr>, index: Box<Expr>},
    MapExpr(Type, Type),
    MatchFlowExpr {control: MatchControl, rule: Box<Expr>},
    RuleExpr(PacketFlag, Literal),
    PacketFlagExpr(PacketFlag),
    ActionFlowExpr(ActionControl, BlockStmt),
    EntryExpr(BlockStmt),
}

#[derive(PartialEq, Debug, Clone)]
pub enum Type {
    IntType,
    IpType,
    RuleType,
}

#[derive(PartialEq, Debug, Clone)]
pub enum Literal {
    IntLiteral(i64),
    IpLiteral(String),
}

#[derive(PartialEq, Debug, Eq, Clone)]
pub struct Ident(pub String);

//* NFD match-flow control

#[derive(PartialEq, Debug, Clone)]
pub enum MatchControl {
    MatchFlow,
    MatchState,
}

#[derive(PartialEq, Debug, Clone)]
pub enum ActionControl {
    ActionFlow,
    ActionState,
}

#[derive(PartialEq, Debug, Clone)]
pub enum PacketFlag {
    Syn,
    Ack,
    Fin,
    Sip,
    Dip,
    Sport,
    Dport,
    Iplen,
}

#[derive(PartialEq, Debug, Clone)]
pub enum FlowAction {
    DropFlow,
    PassFlow,
}

//* numeric calculation

#[derive(PartialEq, Debug, Clone)]
pub enum Prefix {
    PrefixPlus,
    PrefixMinus,
    PrefixLogicNot,
}

#[derive(PartialEq, Debug, Clone)]
pub enum Infix {
    Plus,
    Minus,
    Divide,
    Multiply,
    Module,
    Equal,
    NotEqual,
    GreaterThanEqual,
    LessThanEqual,
    GreaterThan,
    LessThan,
    LogicAnd,
    LogicOr,
    RuleMatch,
    RuleMismatch,
    In,
}

#[derive(PartialEq, PartialOrd, Debug, Clone)]
pub enum Precedence {
    PLowest,
    PLogic,
    PRule,
    PEquals,
    PLessGreater,
    PSum,
    PProduct,
    PCall,
    PIndex,
}