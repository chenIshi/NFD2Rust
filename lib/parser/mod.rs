use nom::*;

pub mod ast;
use lexer::token::*;
use parser::ast::*;
use parser::ast::Literal::*;

macro_rules! tag_token (
    ($i: expr, $tag: expr) => ({
        use std::result::Result::*;
        use nom::{Err, ErrorKind};

        let (i1, t1) = try_parse!($i, take!(1));

        if t1.tok.is_empty() {
            Err(Err::Incomplete(Needed::Size(1)))
        } else {
            if t1.tok[0] == $tag {
                Ok((i1, t1))
            } else {
                Err(Err::Error(error_position!($i, ErrorKind::Count)))
            }
        }
    });
);

macro_rules! parse_ident (
  ($i: expr,) => (
    {
        use std::result::Result::*;
        use nom::{Err,ErrorKind};

        let (i1, t1) = try_parse!($i, take!(1));
        if t1.tok.is_empty() {
            Err(Err::Error(error_position!($i, ErrorKind::Tag)))
        } else {
            match t1.tok[0].clone() {
                Token::Ident(name) => Ok((i1, Ident(name))),
                _ => Err(Err::Error(error_position!($i, ErrorKind::Tag))),
            }
        }
    }
  );
);

macro_rules! parse_literal (
  ($i: expr,) => (
    {
        use std::result::Result::*;
        use nom::{Err,ErrorKind};

        let (i1, t1) = try_parse!($i, take!(1));
        if t1.tok.is_empty() {
            Err(Err::Error(error_position!($i, ErrorKind::Tag)))
        } else {
            match t1.tok[0].clone() {
                Token::IntLiteral(i) => Ok((i1, IntLiteral(i))),
                Token::IpLiteral(s) => Ok((i1, IpLiteral(s))),
                _ => Err(Err::Error(error_position!($i, ErrorKind::Tag))),
            }
        }
    }
  );
);

macro_rules! parse_type (
  ($i: expr,) => (
    {
        use std::result::Result::*;
        use nom::{Err,ErrorKind};

        let (i1, t1) = try_parse!($i, take!(1));
        if t1.tok.is_empty() {
            Err(Err::Error(error_position!($i, ErrorKind::Tag)))
        } else {
            match t1.tok[0].clone() {
                Token::Int => Ok((i1, Type::IntType)),
                Token::Ip => Ok((i1, Type::IpType)),
                Token::Rule => Ok((i1, Type::RuleType)),
                _ => Err(Err::Error(error_position!($i, ErrorKind::Tag))),
            }
        }
    }
  );
);

macro_rules! parse_match_control (
  ($i: expr,) => (
    {
        use std::result::Result::*;
        use nom::{Err,ErrorKind};

        let (i1, t1) = try_parse!($i, take!(1));
        if t1.tok.is_empty() {
            Err(Err::Error(error_position!($i, ErrorKind::Tag)))
        } else {
            match t1.tok[0].clone() {
                Token::Match_flow => Ok((i1, MatchControl::MatchFlow)),
                Token::Match_state => Ok((i1, MatchControl::MatchState)),
                _ => Err(Err::Error(error_position!($i, ErrorKind::Tag))),
            }
        }
    }
  );
);

macro_rules! parse_action_control (
  ($i: expr,) => (
    {
        use std::result::Result::*;
        use nom::{Err,ErrorKind};

        let (i1, t1) = try_parse!($i, take!(1));
        if t1.tok.is_empty() {
            Err(Err::Error(error_position!($i, ErrorKind::Tag)))
        } else {
            match t1.tok[0].clone() {
                Token::Action_flow => Ok((i1, ActionControl::ActionFlow)),
                Token::Action_state => Ok((i1, ActionControl::ActionState)),
                _ => Err(Err::Error(error_position!($i, ErrorKind::Tag))),
            }
        }
    }
  );
);

macro_rules! parse_flow_action (
  ($i: expr,) => (
    {
        use std::result::Result::*;
        use nom::{Err,ErrorKind};

        let (i1, t1) = try_parse!($i, take!(1));
        if t1.tok.is_empty() {
            Err(Err::Error(error_position!($i, ErrorKind::Tag)))
        } else {
            match t1.tok[0].clone() {
                Token::Drop_flow => Ok((i1, FlowAction::DropFlow)),
                Token::Pass_flow => Ok((i1, FlowAction::PassFlow)),
                _ => Err(Err::Error(error_position!($i, ErrorKind::Tag))),
            }
        }
    }
  );
);

macro_rules! parse_flag (
  ($i: expr,) => (
    {
        use std::result::Result::*;
        use nom::{Err,ErrorKind};

        let (i1, t1) = try_parse!($i, take!(1));
        if t1.tok.is_empty() {
            Err(Err::Error(error_position!($i, ErrorKind::Tag)))
        } else {
            match t1.tok[0].clone() {
                Token::Flag_syn => Ok((i1, PacketFlag::Syn)),
                Token::Flag_ack => Ok((i1, PacketFlag::Ack)),
                Token::Flag_fin => Ok((i1, PacketFlag::Fin)),
                Token::Sip => Ok((i1, PacketFlag::Sip)),
                Token::Dip => Ok((i1, PacketFlag::Dip)),
                Token::Sport => Ok((i1, PacketFlag::Sport)),
                Token::Dport => Ok((i1, PacketFlag::Dport)),
                Token::Iplen => Ok((i1, PacketFlag::Iplen)),
                _ => Err(Err::Error(error_position!($i, ErrorKind::Tag))),
            }
        }
    }
  );
);

//* end of macro parser

fn infix_op(t: &Token) -> (Precedence, Option<Infix>) {
    match *t {
        Token::LogicAnd => (Precedence::PLogic, Some(Infix::LogicAnd)),
        Token::LogicOr => (Precedence::PLogic, Some(Infix::LogicOr)),
        Token::Match => (Precedence::PRule, Some(Infix::RuleMatch)),
        Token::Mismatch => (Precedence::PRule, Some(Infix::RuleMismatch)),
        Token::In => (Precedence::PRule, Some(Infix::In)),
        Token::Equal => (Precedence::PEquals, Some(Infix::Equal)),
        Token::NotEqual => (Precedence::PEquals, Some(Infix::NotEqual)),
        Token::LessThanEqual => (Precedence::PLessGreater, Some(Infix::LessThanEqual)),
        Token::GreaterThanEqual => (Precedence::PLessGreater, Some(Infix::GreaterThanEqual)),
        Token::Plus => (Precedence::PSum, Some(Infix::Plus)),
        Token::Minus => (Precedence::PSum, Some(Infix::Minus)),
        Token::Multiply => (Precedence::PProduct, Some(Infix::Multiply)),
        Token::Divide => (Precedence::PProduct, Some(Infix::Divide)),
        Token::LParen => (Precedence::PCall, None),
        Token::LBracket => (Precedence::PIndex, None),
        _ => (Precedence::PLowest, None),
    }
}

named!(parse_program<Tokens, Program>,
    do_parse!(
        // tag_token!(Token::Program) >>
        // programID: parse_ident!() >>
        // tag_token!(Token::LBrace) >>
        prog: many0!(parse_stmt) >>
        // tag_token!(Token::RBrace) >>
        tag_token!(Token::EOF) >>
        (prog)
    )
);

named!(parse_expr<Tokens, Expr>,
    apply!(parse_pratt_expr, Precedence::PLowest)
);

named!(parse_stmt<Tokens, Stmt>, alt_complete!(
    parse_assign_stmt |
    parse_expr_stmt
));

named!(parse_assign_stmt<Tokens, Stmt>,
    do_parse!(
        t: parse_type!() >>
        id: parse_ident!() >>
        tag_token!(Token::Assign) >>
        e: parse_expr >>
        _o: opt!(tag_token!(Token::SemiColon)) >>
        (Stmt::AssignStmt(t, id, e))
    )
);

named!(parse_expr_stmt<Tokens, Stmt>,
    do_parse!(
        expr: parse_expr >>
        opt!(tag_token!(Token::SemiColon)) >>
        (Stmt::ExprStmt(expr))
    )
);

named!(parse_block_stmt<Tokens, BlockStmt>,
    do_parse!(
        tag_token!(Token::LBrace) >>
        ss: many0!(parse_stmt) >>
        tag_token!(Token::RBrace) >>
        (ss)
    )
);

/* fundamental expr non-tokens */

named!(parse_atom_expr<Tokens, Expr>, alt_complete!(
    parse_lit_expr |
    parse_ident_expr |
    parse_prefix_expr |
    parse_paren_expr |
    parse_map_expr |
    parse_list_expr |
    parse_match_flow_expr |
    parse_action_flow_expr |
    parse_rule_expr |
    parse_entry_expr |
    parse_flag_expr
));

named!(parse_paren_expr<Tokens, Expr>,
    do_parse!(
        tag_token!(Token::LParen) >>
        e: parse_expr >>
        tag_token!(Token::RParen) >>
        (e)
    )
);

named!(parse_lit_expr<Tokens, Expr>,
    do_parse!(
        lit: parse_literal!() >>
        (Expr::LitExpr(lit))
    )
);

named!(parse_ident_expr<Tokens, Expr>,
    do_parse!(
        id: parse_ident!() >>
        (Expr::IdentExpr(id))
    )
);

/* for list expr */

named!(parse_comma_exprs<Tokens, Expr>,
    do_parse!(
        tag_token!(Token::Comma) >>
        e: parse_expr >>
        (e)
    )
);

named!(parse_exprs<Tokens, Vec<Expr>>,
    do_parse!(
        e: parse_expr >>
        es: many0!(parse_comma_exprs) >>
        ([&vec!(e)[..], &es[..]].concat())
    )
);

fn empty_boxed_vec(i: Tokens) -> IResult<Tokens, Vec<Expr>> {
    Ok((i, vec![]))
}

named!(parse_list_expr<Tokens, Expr>,
    do_parse!(
        tag_token!(Token::LBrace) >>
        exprs: alt_complete!(parse_exprs | empty_boxed_vec) >>
        tag_token!(Token::RBrace) >>
        (Expr::ListExpr(exprs))
    )
);

/* NFD related expr */

named!(parse_entry_expr<Tokens, Expr>,
    do_parse!(
        tag_token!(Token::Entry) >>
        ss: parse_block_stmt >>
        (Expr::EntryExpr(ss))
    )
);

named!(parse_match_flow_expr<Tokens, Expr>,
    do_parse!(
        ctl: parse_match_control!() >>
        tag_token!(Token::LBrace) >>
        e: parse_expr >>
        tag_token!(Token::RBrace) >>
        (Expr::MatchFlowExpr { control: ctl, rule: Box::new(e)})
    )
);

named!(parse_action_flow_expr<Tokens, Expr>,
    do_parse!(
        ctl: parse_action_control!() >>
        ss: parse_block_stmt >>
        (Expr::ActionFlowExpr(ctl, ss))
    )
);

named!(parse_map_expr<Tokens, Expr>,
    do_parse!(
        tag_token!(Token::Map) >>
        tag_token!(Token::LAngleBracket) >>
        a: parse_type!() >>
        tag_token!(Token::Comma) >>
        b: parse_type!() >>
        tag_token!(Token::RAngleBracket) >>
        opt!(tag_token!(Token::SemiColon)) >>
        (Expr::MapExpr(a, b))
    )
);

named!(parse_rule_expr<Tokens, Expr>,
    do_parse!(
        flag: parse_flag!() >>
        tag_token!(Token::Colon) >>
        ip: parse_literal!() >>
        (Expr::RuleExpr(flag, ip))
    )
);

named!(parse_flag_expr<Tokens, Expr>,
    do_parse!(
        flag: parse_flag!() >>
        (Expr::PacketFlagExpr(flag))
    )
);

/* Numeric related expr */
fn parse_prefix_expr(input: Tokens) -> IResult<Tokens, Expr> {
    let (i1, t1) =
        try_parse!(
            input,
            alt_complete!(tag_token!(Token::Plus) | tag_token!(Token::Minus) | tag_token!(Token::LogicNot))
        );

    if t1.tok.is_empty() {
        Err(Err::Error(error_position!(input, ErrorKind::Tag)))
    } else {
        let (i2, e) = try_parse!(i1, parse_atom_expr);

        match t1.tok[0].clone() {
            Token::Plus => Ok((i2, Expr::PrefixExpr(Prefix::PrefixPlus, Box::new(e)))),
            Token::Minus => Ok((i2, Expr::PrefixExpr(Prefix::PrefixMinus, Box::new(e)))),
            Token::LogicNot => Ok((i2, Expr::PrefixExpr(Prefix::PrefixLogicNot, Box::new(e)))),
            _ => Err(Err::Error(error_position!(input, ErrorKind::Tag))),
        }
    }
}

fn parse_pratt_expr(input: Tokens, precedence: Precedence) -> IResult<Tokens, Expr> {
    do_parse!(input,
        left: parse_atom_expr >>
        i: apply!(go_parse_pratt_expr, precedence, left) >>
        (i)
    )
}

fn go_parse_pratt_expr(input: Tokens, precedence: Precedence, left: Expr) -> IResult<Tokens, Expr> {
    let (i1, t1) = try_parse!(input, take!(1));
    if t1.tok.is_empty() {
        Ok((i1, left))
    } else {
        let preview = t1.tok[0].clone();
        match infix_op(&preview) {
            (Precedence::PIndex, _) if precedence < Precedence::PIndex => {
                let (i2, left2) = try_parse!(input, apply!(parse_index_expr, left));
                go_parse_pratt_expr(i2, precedence, left2)
            }
            (ref peek_precedence, _) if precedence < *peek_precedence => {
                let (i2, left2) = try_parse!(input, apply!(parse_infix_expr, left));
                go_parse_pratt_expr(i2, precedence, left2)
            }
            _ => Ok((input, left)),
        }
    }
}

fn parse_infix_expr(input: Tokens, left: Expr) -> IResult<Tokens, Expr> {
    let (i1, t1) = try_parse!(input, take!(1));
    if t1.tok.is_empty() {
        Err(Err::Error(error_position!(input, ErrorKind::Tag)))
    } else {
        let next = t1.tok[0].clone();
        let (precedence, maybe_op) = infix_op(&next);
        match maybe_op {
            None => Err(Err::Error(error_position!(input, ErrorKind::Tag))),
            Some(op) => {
                let (i2, right) = try_parse!(i1, apply!(parse_pratt_expr, precedence));
                Ok((i2, Expr::InfixExpr(op, Box::new(left), Box::new(right))))
            }
        }
    }
}

fn parse_index_expr(input: Tokens, arr: Expr) -> IResult<Tokens, Expr> {
    do_parse!(
        input,
        tag_token!(Token::LBracket) >> idx: parse_expr >> tag_token!(Token::RBracket) >>
            (Expr::IndexExpr {
                array: Box::new(arr),
                index: Box::new(idx),
            })
    )
}

pub struct Parser;

impl Parser {
    pub fn parse_tokens(tokens: Tokens) -> IResult<Tokens, Program> {
        parse_program(tokens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lexer::*;

    fn assert_input_with_program(input: &[u8], expected_results: Program) {
        let (_, r) = Lexer::lex_tokens(input).unwrap();
        let tokens = Tokens::new(&r);
        let (_, result) = Parser::parse_tokens(tokens).unwrap();
        assert_eq!(result, expected_results);
    }

    fn compare_inputs(input: &[u8], input2: &[u8]) {
        let (_, r) = Lexer::lex_tokens(input).unwrap();
        let tokens = Tokens::new(&r);
        let (_, result) = Parser::parse_tokens(tokens).unwrap();

        let (_, r) = Lexer::lex_tokens(input2).unwrap();
        let tokens = Tokens::new(&r);
        let (_, expected_results) = Parser::parse_tokens(tokens).unwrap();

        assert_eq!(result, expected_results);
    }

    #[test]
    fn assign_parser() {
        let input = "rule R=sip:\"192.168.0.0/16\";
                    IP base=\"219.168.135.100/32\";
                    int port=8;".as_bytes();

        let program: Program =
            vec![
                Stmt::AssignStmt(Type::RuleType,
                                Ident("R".to_owned()),
                                Expr::LitExpr(Literal::IpLiteral("192.168.0.0/16".to_owned()))
                                ),
                Stmt::AssignStmt(Type::IpType,
                                Ident("base".to_owned()),
                                Expr::LitExpr(Literal::IpLiteral("219.168.135.100/32".to_owned()))
                                ),
                Stmt::AssignStmt(Type::IntType,
                                Ident("port".to_lowercase()),
                                Expr::LitExpr(Literal::IntLiteral(8))
                                ),
            ];

        assert_input_with_program(input, program);
    }

   
    #[test]
    fn calc_then_assign() {
        let input = "int port = 8 + 10;".as_bytes();

        let program: Program = 
            vec![
                Stmt::AssignStmt(Type::IntType,
                                Ident("port".to_owned()),
                                Expr::InfixExpr(
                                Infix::Plus,
                                Box::new(Expr::LitExpr(Literal::IntLiteral(8))),
                                Box::new(Expr::LitExpr(Literal::IntLiteral(10))),
                                )),
            ];
        assert_input_with_program(input, program);
    }
}