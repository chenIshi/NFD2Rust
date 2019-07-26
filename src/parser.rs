//! Reference from s_expression.rs in nom crate

#![cfg(feature = "alloc")]

extern crate jemallocator;
extern crate nom;

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{alpha1, char, digit1, multispace0, multispace1, one_of},
    combinator::{cut, map, map_res, opt},
    error::{context, VerboseError},
    multi::many0,
    sequence::{delimited, preceded, terminated, tuple},
    IResult,
};

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Operator {
    Plus,
    Minus,
    Times,
    Divide,
    Equal,
    Not,
    Less,
    Greater,
}

#[derive(Debug, PartialEq, Clone)]
pub enum Atom {
    Num(i32),
    
}