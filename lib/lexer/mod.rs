use nom::*;
use nom::types::*;
use std::str;
use std::str::FromStr;
use std::str::Utf8Error;

pub mod token;
use lexer::token::*;

//* operators
named!(equal_operator<CompleteByteSlice, Token>,
  do_parse!(tag!("==") >> (Token::Equal))
);

named!(not_equal_operator<CompleteByteSlice, Token>,
  do_parse!(tag!("!=") >> (Token::NotEqual))
);

named!(assign_operator<CompleteByteSlice, Token>,
  do_parse!(tag!("=") >> (Token::Assign))
);

named!(plus_operator<CompleteByteSlice, Token>,
  do_parse!(tag!("+") >> (Token::Plus))
);

named!(minus_operator<CompleteByteSlice, Token>,
  do_parse!(tag!("-") >> (Token::Minus))
);

named!(multiply_operator<CompleteByteSlice, Token>,
  do_parse!(tag!("*") >> (Token::Multiply))
);

named!(divide_operator<CompleteByteSlice, Token>,
  do_parse!(tag!("/") >> (Token::Divide))
);

named!(module_operator<CompleteByteSlice, Token>,
  do_parse!(tag!("%") >> (Token::Module))
);

named!(greater_operator_equal<CompleteByteSlice, Token>,
  do_parse!(tag!(">=") >> (Token::GreaterThanEqual))
);

named!(lesser_operator_equal<CompleteByteSlice, Token>,
  do_parse!(tag!("<=") >> (Token::LessThanEqual))
);

/*
named!(greater_operator<CompleteByteSlice, Token>,
  do_parse!(tag!(">") >> (Token::GreaterThan))
);

named!(lesser_operator<CompleteByteSlice, Token>,
  do_parse!(tag!("<") >> (Token::LessThan))
);
*/

named!(logicNot_operator<CompleteByteSlice, Token>,
  do_parse!(tag!("~") >> (Token::LogicNot))
);

named!(logicAnd_operator<CompleteByteSlice, Token>,
  do_parse!(tag!("&&") >> (Token::LogicAnd))
);

named!(logicOr_operator<CompleteByteSlice, Token>,
  do_parse!(tag!("||") >> (Token::LogicOr))
);

named!(lex_operator<CompleteByteSlice, Token>, alt!(
    equal_operator |
    not_equal_operator |
    assign_operator |
    plus_operator |
    minus_operator |
    multiply_operator |
    divide_operator |
    module_operator |
    logicNot_operator |
    logicAnd_operator |
    logicOr_operator |
    greater_operator_equal |
    lesser_operator_equal
));

//* punctuations
named!(comma_punctuation<CompleteByteSlice, Token>,
  do_parse!(tag!(",") >> (Token::Comma))
);

named!(semicolon_punctuation<CompleteByteSlice, Token>,
  do_parse!(tag!(";") >> (Token::SemiColon))
);

named!(colon_punctuation<CompleteByteSlice, Token>,
  do_parse!(tag!(":") >> (Token::Colon))
);

named!(lparen_punctuation<CompleteByteSlice, Token>,
  do_parse!(tag!("(") >> (Token::LParen))
);

named!(rparen_punctuation<CompleteByteSlice, Token>,
  do_parse!(tag!(")") >> (Token::RParen))
);

named!(lbrace_punctuation<CompleteByteSlice, Token>,
  do_parse!(tag!("{") >> (Token::LBrace))
);

named!(rbrace_punctuation<CompleteByteSlice, Token>,
  do_parse!(tag!("}") >> (Token::RBrace))
);

named!(lbracket_punctuation<CompleteByteSlice, Token>,
  do_parse!(tag!("[") >> (Token::LBracket))
);

named!(rbracket_punctuation<CompleteByteSlice, Token>,
  do_parse!(tag!("]") >> (Token::RBracket))
);

named!(langlebracket_punctuation<CompleteByteSlice, Token>,
  do_parse!(tag!("<") >> (Token::LAngleBracket))
);

named!(ranglebracket_punctuation<CompleteByteSlice, Token>,
  do_parse!(tag!(">") >> (Token::RAngleBracket))
);

named!(lex_punctuations<CompleteByteSlice, Token>, alt!(
    comma_punctuation |
    semicolon_punctuation |
    colon_punctuation |
    lparen_punctuation |
    rparen_punctuation |
    lbrace_punctuation |
    rbrace_punctuation |
    lbracket_punctuation |
    rbracket_punctuation |
    langlebracket_punctuation |
    ranglebracket_punctuation
));

/* parse IP */
//* Strings
//* Weird to look, but should be fine now
fn pis(input: CompleteByteSlice) -> IResult<CompleteByteSlice, Vec<u8>> {
    use std::result::Result::*;

    let (i1, c1) = try_parse!(input, take!(1));
    match c1.as_bytes() {
        b"\"" => Ok((input, vec![])),
        b"\\" => {
            let (i2, c2) = try_parse!(i1, take!(1));
            pis(i2).map(|(slice, done)| (slice, concat_slice_vec(c2.0, done)))
        }
        c => {
            pis(i1).map(|(slice, done)| (slice, concat_slice_vec(c, done)))
        },
    }
}

fn concat_slice_vec(c: &[u8], done: Vec<u8>) -> Vec<u8> {
    let mut new_vec = c.to_vec();
    new_vec.extend(&done);
    new_vec
}

fn convert_vec_utf8(v: Vec<u8>) -> Result<String, Utf8Error> {
    let slice = v.as_slice();
    str::from_utf8(slice).map(|s| s.to_owned())
}

/* modified IP spec with "IP" requirement */
named!(IP<CompleteByteSlice, String>,
  delimited!(
    tag!("\""),
    map_res!(pis, convert_vec_utf8),
    tag!("\"")
  )
);

named!(lex_IP<CompleteByteSlice, Token>,
    do_parse!(
        s: IP >>
        (Token::IpLiteral(s))
    )
);

macro_rules! check(
    ($input:expr, $submac:ident!( $($args:tt)* )) => (
       {
          use std::result::Result::*;
          use nom::{Err,ErrorKind};

          let mut failed = false;
          for &idx in $input.0 {
          if !$submac!(idx, $($args)*) {
              failed = true;
              break;
          }
        }
      if failed {
        let e: ErrorKind<u32> = ErrorKind::Tag;
        Err(Err::Error(error_position!($input, e)))
      } else {
        Ok((&b""[..], $input))
      }
    }
  );
  ($input:expr, $f:expr) => (
    check!($input, call!($f));
  );
);

fn parse_reserved(c: CompleteStr, rest: Option<CompleteStr>) -> Token {
    let mut string = c.0.to_owned();
    string.push_str(rest.unwrap_or(CompleteStr("")).0);
    match string.as_ref() {
        "int" => Token::Int,
        "IP" => Token::Ip,
        "program" => Token::Program,
        "rule" => Token::Rule,
        "map" => Token::Map,
        "in" => Token::In,
        "entry" => Token::Entry,
        "matchFlow" => Token::Match_flow,
        "matchState" => Token::Match_state,
        "matches" => Token::Match,
        "mismatches" => Token::Mismatch,
        "actionFlow" => Token::Action_flow,
        "actionState" => Token::Action_state,
        "DROP" => Token::Drop_flow,
        "pass" => Token::Pass_flow,
        "TCP" => Token::Tcp,
        "UDP" => Token::Udp,
        "sip" => Token::Sip,
        "dip" => Token::Dip,
        "sport" => Token::Sport,
        "dport" => Token::Dport,
        "iplen" => Token::Iplen,
        "flag_syn" => Token::Flag_syn,
        "flag_ack" => Token::Flag_ack,
        "flag_fin" => Token::Flag_fin,
        _ => Token::Ident(string),
    }
}

fn complete_byte_slice_str_from_utf8(c: CompleteByteSlice) -> Result<CompleteStr, Utf8Error> {
    str::from_utf8(c.0).map(|s| CompleteStr(s))
}

named!(take_1_char<CompleteByteSlice, CompleteByteSlice>,
    flat_map!(take!(1), check!(is_alphabetic))
);

named!(lex_reserved_ident<CompleteByteSlice, Token>,
    do_parse!(
        c: map_res!(call!(take_1_char), complete_byte_slice_str_from_utf8) >>
        rest: opt!(complete!(map_res!(alphanumeric, complete_byte_slice_str_from_utf8))) >>
        (parse_reserved(c, rest))
    )
);

fn complete_str_from_str<F: FromStr>(c: CompleteStr) -> Result<F, F::Err> {
    FromStr::from_str(c.0)
}

//* Integers parsing
named!(lex_integer<CompleteByteSlice, Token>,
    do_parse!(
        i: map_res!(map_res!(digit, complete_byte_slice_str_from_utf8), complete_str_from_str) >>
        (Token::IntLiteral(i))
    )
);

//* Illegal tokens
named!(lex_illegal<CompleteByteSlice, Token>,
    do_parse!(take!(1) >> (Token::Illegal))
);

named!(lex_token<CompleteByteSlice, Token>, alt_complete!(
    lex_operator |
    lex_punctuations |
    lex_IP |
    lex_reserved_ident |
    lex_integer |
    lex_illegal
));

named!(lex_tokens<CompleteByteSlice, Vec<Token>>, ws!(many0!(lex_token)));

pub struct Lexer;

impl Lexer {
  pub fn lex_tokens(bytes: &[u8]) -> IResult<CompleteByteSlice, Vec<Token>> {
      lex_tokens(CompleteByteSlice(bytes)).map(|(slice, result)|
            (slice, [&result[..], &vec![Token::EOF][..]].concat())
      )
  }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lexer1() {
        let input = &b"=+(){},;"[..];
        let (_, result) = Lexer::lex_tokens(input).unwrap();

        let expected_results = vec![
            Token::Assign,
           Token::Plus,
            Token::LParen,
            Token::RParen,
            Token::LBrace,
            Token::RBrace,
            Token::Comma,
            Token::SemiColon,
            Token::EOF,
        ];

        assert_eq!(result, expected_results);
    }

    #[test]
    fn test_lexer2() {
        let input = "entry {
                matchFlow { f mismatches ALLOW }
                matchState { f[sip] in seen }
            }".as_bytes();

        let (_, result) = Lexer::lex_tokens(input).unwrap();
        let expected_results = vec![
          Token::Entry,
          Token::LBrace,
          Token::Match_flow,
          Token::LBrace,
          Token::Ident("f".to_owned()),
          Token::Mismatch,
          Token::Ident("ALLOW".to_owned()),
          Token::RBrace,
          Token::Match_state,
          Token::LBrace,
          Token::Ident("f".to_owned()),
          Token::LBracket,
          Token::Sip,
          Token::RBracket,
          Token::In,
          Token::Ident("seen".to_owned()),
          Token::RBrace,
          Token::RBrace,
          Token::EOF,
        ];

        assert_eq!(result, expected_results);
    }

    #[test]
    fn assign_lexer() {
        let input = "IP base =\"219.168.135.100/32\";".as_bytes();
        let (_, result) = Lexer::lex_tokens(input).unwrap();
        let expected_results = vec![
          Token::Ip,
          Token::Ident("base".to_owned()),
          Token::Assign,
          Token::IpLiteral("219.168.135.100/32".to_owned()),
          Token::SemiColon,
          Token::EOF,
        ];
        assert_eq!(result, expected_results);
    }

    #[test]
    fn match_lexer() {
        let input = "entry {
                        matchFlow{f matches R}
                        matchState{f[dport] in listIP}
                    }
                    ".as_bytes();
        let (_, result) = Lexer::lex_tokens(input).unwrap();
        let expected_results = vec![
          Token::Entry,
          Token::LBrace,
          Token::Match_flow,
          Token::LBrace,
          Token::Ident("f".to_owned()),
          Token::Match,
          Token::Ident("R".to_owned()),
          Token::RBrace,
          Token::Match_state,
          Token::LBrace,
          Token::Ident("f".to_owned()),
          Token::LBracket,
          Token::Dport,
          Token::RBracket,
          Token::In,
          Token::Ident("listIP".to_owned()),
          Token::RBrace,
          Token::RBrace,
          Token::EOF,
        ];
  
        assert_eq!(result, expected_results);
    }

    #[test]
    fn action_lexer() {
      let input = "entry {
                        actionFlow{pass;}
                        actionState{hh[f[sip]]=1;}
                    }
                    ".as_bytes();
      let (_, result) = Lexer::lex_tokens(input).unwrap();
      let expected_results = vec![
        Token::Entry,
        Token::LBrace,
        Token::Action_flow,
        Token::LBrace,
        Token::Pass_flow,
        Token::SemiColon,
        Token::RBrace,
        Token::Action_state,
        Token::LBrace,
        Token::Ident("hh".to_owned()),
        Token::LBracket,
        Token::Ident("f".to_owned()),
        Token::LBracket,
        Token::Sip,
        Token::RBracket,
        Token::RBracket,
        Token::Assign,
        Token::IntLiteral(1),
        Token::SemiColon,
        Token::RBrace,
        Token::RBrace,
        Token::EOF,
      ];

      assert_eq!(result, expected_results);
    }
}