extern crate ipnet;

pub mod object;
pub mod environment;
pub mod builtins;

use std::cell::RefCell;
use std::rc::Rc;
use std::collections::HashMap;
// use std::mem::discriminant;
use parser::ast::*;
use evaluator::object::*;
use evaluator::environment::*;


pub struct Evaluator {
    env: Rc<RefCell<Environment>>,
}

impl Default for Evaluator {
    fn default() -> Self {
        Self::new()
    }
}

impl Evaluator {
    pub fn new() -> Self {
        Evaluator { env: Rc::new(RefCell::new(Environment::new())) }
    }

    fn returned(&mut self, object: Object) -> Object {
        match object {
            Object::ReturnValue(v) => *v,
            o => o,
        }
    }

    pub fn eval_program(&mut self, prog: &Program, packet_map: Object) -> Object {
        self.register_ident(Ident("f".to_owned()), packet_map);
        let return_data: Object;
        return_data = self.eval_blockstmt(prog);
        
        self.returned(return_data)
    }

    pub fn eval_blockstmt(&mut self, prog: &BlockStmt) -> Object {
        match prog.len() {
            0 => Object::Null,
            1 => self.eval_statement(prog[0].clone()),
            _ => {
                let s = prog[0].clone();
                let ss = &prog[1..];
                let object = self.eval_statement(s);
                if object.is_returned() {
                    object
                } else {
                    self.eval_blockstmt(&ss.to_vec())
                }
            }
        }
    }

    pub fn eval_statement(&mut self, stmt: Stmt) -> Object {
        match stmt {
            Stmt::ExprStmt(expr) => self.eval_expr(expr),
            Stmt::AssignStmt(_typeT, ident, expr) => {
                let object = self.eval_expr(expr);
                self.register_ident(ident, object)
            }
        }
    }

    pub fn register_ident(&mut self, ident: Ident, object: Object) -> Object {
        let Ident(name) = ident;
        self.env.borrow_mut().set(&name, &object);
        object
    }

    pub fn eval_expr(&mut self, expr: Expr) -> Object {
        match expr {
            Expr::IdentExpr(i) => self.eval_ident(i),
            Expr::LitExpr(l) => self.eval_literal(l),
            Expr::PrefixExpr(prefix, expr) => self.eval_prefix(&prefix, *expr),
            Expr::InfixExpr(infix, expr1, expr2) => self.eval_infix(&infix, *expr1, *expr2),
            Expr::ListExpr(exprs) => self.eval_list(&exprs),
            Expr::MapTypeExpr(type1, type2) => self.eval_map(type1, type2),
            Expr::IndexExpr { array, index } => self.eval_index(*array, *index),
            Expr::RuleExpr(packet_flag, ip_lit) => self.eval_rule(packet_flag, ip_lit),
            Expr::ActionExpr(action) => self.eval_action(&action),
            Expr::EntryExpr(exprs) => self.eval_entry(&exprs, true),
            Expr::MatchFlowExpr(ctl, expr) => self.eval_matchflow(&ctl, *expr),
            Expr::ActionFlowExpr(ctl, stmt) => self.eval_actionflow(&ctl, &stmt),
            /* 剩下的先看完他的實做再來模仿 */
            _ => {
                unimplemented!()
            }
        }
    }

    pub fn eval_entry(&mut self, exprs: &Vec<Expr>, eval_action: bool) -> Object {
        let mut entry = true;
        match exprs.len() {
            0 => Object::Null,
            _ => {
                let e = exprs[0].clone();
                let es = &exprs[1..];
                let object = self.eval_expr(e);
                if let Object::Bool(b) = object {
                    if !b {
                        entry = false;
                    }
                }
                self.eval_entry(&es.to_vec(), entry)
            }
        }
    }

    pub fn eval_matchflow(&mut self, ctl: &MatchControl, expr: Expr) -> Object {
        self.eval_expr(expr)
    }

    pub fn eval_actionflow(&mut self, ctl: &ActionControl, stmts: &BlockStmt) -> Object {
        self.eval_blockstmt(stmts)
    }

    pub fn eval_ident(&mut self, ident: Ident) -> Object {
        let Ident(name) = ident;
        let borrow_env = self.env.borrow();
        let var = borrow_env.get(&name);
        /* id registeration should be done in the AssignStmt level */
        match var {
            Some(o) => o,
            None => Object::Error(format!("identifier not found: {}", name)),
        }
    }

    pub fn eval_literal(&mut self, literal: Literal) -> Object {
        match literal {
            Literal::IntLiteral(i) => Object::Integer(i),
            Literal::IpLiteral(s) => {
                Object::IP(s.parse().unwrap())
            },
        }
    }

    pub fn eval_flag(&mut self, flag: PacketFlag) -> Object {
        match flag {
            PacketFlag::Tcp => Object::Flag(flag),
            PacketFlag::Udp => Object::Flag(flag),
            PacketFlag::Syn => Object::Flag(flag),
            PacketFlag::Ack => Object::Flag(flag),
            PacketFlag::Fin => Object::Flag(flag),
            PacketFlag::Sip => Object::Port(flag),
            PacketFlag::Dip => Object::Port(flag),
            PacketFlag::Sport => Object::Port(flag),
            PacketFlag::Dport => Object::Port(flag),
            PacketFlag::Iplen => Object::Flag(flag),
        }
    }

    pub fn eval_action(&mut self, action: &FlowAction) -> Object {
        match action {
            FlowAction::DropFlow => {
                println!("drop packet!");
                Object::Action(action.clone())
            },
            FlowAction::PassFlow => {
                println!("pass packet!");
                Object::Action(action.clone())
            }
        }
    }

    pub fn eval_rule(&mut self, flag: PacketFlag, literal: Literal) -> Object {
        let literal_ip = self.eval_literal(literal);
        match literal_ip {
            Object::IP(ip) => {
                Object::Rule(flag, Box::new(Object::IP(ip)))
            },
            _ => {
                Object::Error("rule should follow by a ip addr".to_owned())
            }
        }
    }

    pub fn eval_prefix(&mut self, prefix: &Prefix, expr: Expr) -> Object {
        let object = self.eval_expr(expr);
        match *prefix {
            Prefix::PrefixPlus => {
                match self.oti(object) {
                    Ok(i) => Object::Integer(i),
                    Err(err) => err,
                }
            },
            Prefix::PrefixMinus => {
                match self.oti(object) {
                    Ok(i) => Object::Integer(-i),
                    Err(err) => err,
                }
            },
            _ => {
                unimplemented!()
            }
        }
    }

    pub fn eval_infix(&mut self, infix: &Infix, expr1: Expr, expr2: Expr) -> Object {
        let object1 = self.eval_expr(expr1);
        let object2 = self.eval_expr(expr2);
        match *infix {
            Infix::Plus => self.object_add(object1, object2),
            Infix::Minus => {
                let i1 = self.oti(object1);
                let i2 = self.oti(object2);
                match (i1, i2) {
                    (Ok(i1), Ok(i2)) => Object::Integer(i1 - i2),
                    (Err(err), _) | (_, Err(err)) => err,
                }
            },
            /* 目前並沒有考慮到像是 0/0 */
            Infix::Divide => {
                let i1 = self.oti(object1);
                let i2 = self.oti(object2);
                match (i1, i2) {
                    (Ok(i1), Ok(i2)) => Object::Integer(i1 / i2),
                    (Err(err), _) | (_, Err(err)) => err,
                }
            },
            Infix::Multiply => {
                let i1 = self.oti(object1);
                let i2 = self.oti(object2);
                match (i1, i2) {
                    (Ok(i1), Ok(i2)) => Object::Integer(i1 * i2),
                    (Err(err), _) | (_, Err(err)) => err,
                }
            },
            Infix::Equal => {
                /* 目前只考虑 int 与 ip 间的 */
                match (object1, object2) {
                    (Object::Integer(i1), Object::Integer(i2)) => {
                        if i1 == i2 {
                            Object::Bool(true)
                        } else {
                            Object::Bool(false)
                        }
                    },
                    (Object::IP(ip1), Object::IP(ip2)) => {
                        if ip1.network() == ip2.network() {
                            Object::Bool(true)
                        } else {
                            Object::Bool(false)
                        }
                    },
                    _ => {
                        Object::Error("Only compare between int or IP types!".to_owned())
                    },
                }
            },
            Infix::NotEqual => {
                /* 也是一样参考 equal 实做 */
                match (object1, object2) {
                    (Object::Integer(i1), Object::Integer(i2)) => {
                        if i1 != i2 {
                            Object::Bool(true)
                        } else {
                            Object::Bool(false)
                        }
                    },
                    (Object::IP(ip1), Object::IP(ip2)) => {
                        if ip1.network() != ip2.network() {
                            Object::Bool(true)
                        } else {
                            Object::Bool(false)
                        }
                    },
                    _ => {
                        Object::Error("Only compare between int or IP types!".to_owned())
                    },
                }
            },
            /* 目前不知道要不要支援大小於
               要的話就要把回傳布林值考慮進來 */

            Infix::RuleMatch => {
                /* 目前只假设前面 expr 為 f ，后面為 rule 变数 */
                /* 第一个变量 f 经过查表应该是 Map 型态 */
                if let Object::Map(packet_table) = object1 {
                    if let Object::Rule(ref flag, ref rule_ctx) = object2 {
                        match **rule_ctx {
                            Object::Integer(rule_int) => {
                                if *flag != PacketFlag::Sip && *flag != PacketFlag::Dip {
                                    if let Object::Integer(i) = packet_table.get(&Object::Port(flag.clone())).unwrap() {
                                        if rule_int == *i {
                                            Object::Bool(true)
                                        } else {
                                            Object::Bool(false)
                                        }
                                    } else {
                                        Object::Error("Packet port info should be int type".to_owned())
                                    }
                                } else {
                                    Object::Error("IP rule can't have int content".to_owned())
                                }
                            },
                            Object::IP(rule_ip) => {
                                if *flag == PacketFlag::Sip || *flag == PacketFlag::Dip {
                                    if let Object::IP(i) = packet_table.get(&Object::Flag(flag.clone())).unwrap() {
                                        /* i is the packet's real IP, and rule_ip is actually a subnet */
                                        if rule_ip.network() == i.network() {
                                            Object::Bool(true)
                                        } else {
                                            Object::Bool(false)
                                        }
                                    } else {
                                        Object::Error("Packet ip info should be IP type".to_owned())
                                    }
                                } else {
                                    Object::Error("Port rule can't have ip content".to_owned())
                                }
                            },
                            _ => {
                                Object::Error("Not available rule content type in match condition".to_owned())
                            },
                        }
                    } else {
                        Object::Error("Match condition should end with rules".to_owned())
                    }
                } else {
                    Object::Error("Match condition should start with map like \"f\"".to_owned())
                }
            },
            Infix::RuleMismatch => {
                /* 参考 RuleMatch，只是逻辑相反 */
                if let Object::Map(packet_table) = object1 {
                    if let Object::Rule(ref flag, ref rule_ctx) = object2 {
                        match **rule_ctx {
                            Object::Integer(rule_int) => {
                                if *flag != PacketFlag::Sip && *flag != PacketFlag::Dip {
                                    if let Object::Integer(i) = packet_table.get(&Object::Port(flag.clone())).unwrap() {
                                        if rule_int != *i {
                                            Object::Bool(true)
                                        } else {
                                            Object::Bool(false)
                                        }
                                    } else {
                                        Object::Error("Packet port info should be int type".to_owned())
                                    }
                                } else {
                                    Object::Error("IP rule can't have int content".to_owned())
                                }
                            },
                            Object::IP(rule_ip) => {
                                if *flag == PacketFlag::Sip || *flag == PacketFlag::Dip {
                                    if let Object::IP(i) = packet_table.get(&Object::Flag(flag.clone())).unwrap() {
                                        /* i is the packet's real IP, and rule_ip is actually a subnet */
                                        if rule_ip.network() != i.network() {
                                            Object::Bool(true)
                                        } else {
                                            Object::Bool(false)
                                        }
                                    } else {
                                        Object::Error("Packet ip info should be IP type".to_owned())
                                    }
                                } else {
                                    Object::Error("Port rule can't have ip content".to_owned())
                                }
                            },
                            _ => {
                                Object::Error("Not available rule content type in match condition".to_owned())
                            },
                        }
                    } else {
                        Object::Error("Match condition should end with rules".to_owned())
                    }
                } else {
                    Object::Error("Match condition should start with map like \"f\"".to_owned())
                }
            },
            Infix::In => {
                /* 后面的假设只能接受 map/set */
                match object2 {
                    Object::Map(mapping) => {
                        Object::Bool(mapping.contains_key(&object1))
                    },
                    Object::List(list) => {
                        Object::Bool(list.contains(&object1))
                    },
                    _ => {
                        Object::Error("\"in\" operator only support on map or set type".to_owned())
                    }
                }
            },
            _ => {
                unimplemented!()
            }
        }
    }

    pub fn eval_index(&mut self, target_exp: Expr, id_exp: Expr) -> Object {
        let target = self.eval_expr(target_exp);
        let index = self.eval_expr(id_exp);
        match target {
            Object::List(list) => {
                match self.oti(index) {
                    Ok(index_number) => {
                        let null_obj = Object::Null;
                        let object = list.get(index_number as usize).unwrap_or(&null_obj);
                        object.clone()
                    },
                    Err(err) => err,
                }
            },
            /* NFD 實做 */
            Object::Map(map) => {
                match self.otflag(index) {
                    Ok(flag) => {
                        if flag == PacketFlag::Sip || flag == PacketFlag::Dip {
                            map.get(&Object::Port(flag)).unwrap().clone()
                        } else {
                            map.get(&Object::Flag(flag)).unwrap().clone()
                        }
                    },
                    Err(err) => err,
                }
            },
            o => Object::Error(format!("unexpected index target: {}", o)),
        }
    }

    pub fn eval_list(&mut self, exprs: &[Expr]) -> Object {
        let new_vec = exprs
                .iter()
                .map(|e| self.eval_expr(e.clone()))
                .collect::<Vec<_>>();
        Object::List(new_vec)
    }

    pub fn eval_map(&mut self, _type1: Type, _type2: Type) -> Object {
        let mapping = HashMap::new();
        Object::Map(mapping)
    }

    /* 目前我覺得對 int 的運算就足夠了，如果有需要可以再擴充 */
    pub fn object_add(&mut self, object1: Object, object2: Object) -> Object {
        match (object1, object2) {
            (Object::Integer(i1), Object::Integer(i2)) => Object::Integer(i1 + i2),
            (Object::Error(s), _) | (_, Object::Error(s)) => Object::Error(s),
            (x, y) => Object::Error(format!("{:?} and {:?} are not addable", x, y)),
        }
    }

    /* check if it is an integer token */
    pub fn oti(&mut self, object: Object) -> Result<i64, Object> {
        match object {
            Object::Integer(i) => Ok(i),
            Object::Error(s) => Err(Object::Error(s)),
            i => Err(Object::Error(format!("{} is not an integer", i))),
        }
    }

    /* check if it can be packet index */
    pub fn otflag(&mut self, object: Object) -> Result<PacketFlag, Object> {
        match object {
            Object::Flag(f) => Ok(f),
            Object::Port(f) => Ok(f),
            x => Err(Object::Error(format!("{} is not an available packet index", x))),
        }
    }

    pub fn otb(&mut self, object: Object) -> Result<bool, Object> {
        match object {
            Object::Bool(b) => Ok(b),
            Object::Error(s) => Err(Object::Error(s)),
            b => Err(Object::Error(format!("{} is not a bool", b))),
        }
    }
}

