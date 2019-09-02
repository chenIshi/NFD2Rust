extern crate nfd2rust_lib;
#[macro_use]
extern crate clap;
extern crate nom;
extern crate pnet;
extern crate ipnet;

use std::fs::File;
use std::io::prelude::*;
use nom::*;
use nfd2rust_lib::lexer::*;
use nfd2rust_lib::lexer::token::*;
use nfd2rust_lib::parser::*;
use nfd2rust_lib::parser::ast::{PacketFlag};
use nfd2rust_lib::evaluator::*;
use nfd2rust_lib::evaluator::object::{PacketMap, Object};

use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::{Packet, MutablePacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use ipnet::{Ipv4Net, IpBitAnd};
use std::collections::{HashMap, BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::env;

use cmd::*;
mod cmd;

fn read_file(file_path: String) -> Result<String, ::std::io::Error> {
    let mut file = File::open(file_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

fn create_file(file_path: String) -> Result<File, ::std::io::Error> {
    let mut file = File::create(file_path)?;
    Ok((file))
}

fn main() {
    let mut host_interface_name = "wlp2s0".to_owned();
    let code_string = match cmd::read_command() {
        Command::FileReadCommand(file_path, net_interface) => {
            if let Some(n) = net_interface {
                host_interface_name = n;
            }
            read_file(file_path).ok()
        },
        Command::RunInlineCode(code, net_interface) => {
            if let Some(n) = net_interface {
                host_interface_name = n;
            }
            Some(code)
        },
        Command::Noop => None,
    };

    if code_string.is_some() {

        let code_string = code_string.unwrap();
        let mut evaluator = Evaluator::new();
        let lex_tokens = Lexer::lex_tokens(code_string.as_bytes());
        match lex_tokens {
            Ok((_, r)) => {
                let tokens = Tokens::new(&r);
                let parsed = Parser::parse_tokens(tokens);
                match parsed {
                    Ok((_, program)) => {
                        
                        // let host_interface_name = env::args().nth(1).unwrap();
                        let host_interface_match = | iface: &NetworkInterface | iface.name == host_interface_name;

                        let host_interface = datalink::interfaces().into_iter()
                                            .filter(host_interface_match)
                                            .next()
                                            .unwrap();

                        let (mut tx, mut rx) = match datalink::channel(&host_interface, Default::default()) {
                            Ok(Ethernet(tx, rx)) => (tx, rx),
                            Ok(_) => panic!("Unhandled channel type"),
                            Err(e) => panic!("An error occurred when creating the datalink channel: {}", e),
                        };

                        loop {
                            match rx.next() {
                                Ok(packet) => {
                                    let ethpacket = EthernetPacket::new(packet).unwrap();
                                     /* init packet info lookup table */

                                    let mut packet_table = PacketMap::new();
                                    /* fetch the program field data in the packet */
                                    let init_success = extract_packet_info(&ethpacket, &mut packet_table);
                                    if !init_success {
                                        println!("Not a supported packet type, Skip!");
                                        continue;
                                    }

                                    let _eval = evaluator.eval_program(&program, Object::Map(packet_table));
                                },
                                Err(e) => {
                                    /* If an error occurs, we can handle it here */
                                    panic!("An error occurred while reading: {}", e);
                                },
                            }
                        }
                    }
                    Err(Err::Error(_)) => panic!("Parser error"),
                    Err(Err::Failure(_)) => panic!("Parser failure"),
                    Err(Err::Incomplete(_)) => panic!("Incomplete parsing"),
                }
            }
            Err(Err::Error(_)) => panic!("Lexer error"),
            Err(Err::Failure(_)) => panic!("Lexer failure"),
            Err(Err::Incomplete(_)) => panic!("Incomplete lexing"),
        }
    } else {
        panic!("Can't find NFD program");
    }
}

fn extract_packet_info (ethpacket: &EthernetPacket, packet_table: &mut PacketMap) -> bool {
    match ethpacket.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ipv4_header = Ipv4Packet::new(ethpacket.payload());

            if let Some(ipv4_header) = ipv4_header {
                /* insert source/destination IP to table */
                /* while IP info resides in layer 3 (ex: ipv4/ipv6) */
                packet_table.insert(Object::Flag(PacketFlag::Sip), Object::IP(Ipv4Net::new(ipv4_header.get_source(), 32).unwrap()));
                packet_table.insert(Object::Flag(PacketFlag::Dip), Object::IP(Ipv4Net::new(ipv4_header.get_destination(), 32).unwrap()));
                match ipv4_header.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        let tcp_header = TcpPacket::new(ipv4_header.payload());
                        if let Some(tcp_header) = tcp_header {
                            /* now we are in layer 4, which contains port and flag info */
                            packet_table.insert(Object::Port(PacketFlag::Sport), Object::Integer(tcp_header.get_source() as i64));
                            packet_table.insert(Object::Port(PacketFlag::Dport), Object::Integer(tcp_header.get_destination() as i64));
                            packet_table.insert(Object::Flag(PacketFlag::Tcp), Object::Bool(true));
                            packet_table.insert(Object::Flag(PacketFlag::Udp), Object::Bool(false));
                            packet_table.insert(Object::Flag(PacketFlag::Ack), Object::Bool((tcp_header.get_flags() & 0b0001_0000) != 0));
                            packet_table.insert(Object::Flag(PacketFlag::Syn), Object::Bool((tcp_header.get_flags() & 0b0000_0010) != 0));
                            packet_table.insert(Object::Flag(PacketFlag::Fin), Object::Bool((tcp_header.get_flags() & 0b0000_0001) != 0));
                            return true;
                        }
                    },
                    IpNextHeaderProtocols::Udp => {
                        let udp_header = UdpPacket::new(ipv4_header.payload());
                        if let Some(udp_header) = udp_header {
                            packet_table.insert(Object::Port(PacketFlag::Sport), Object::Integer(udp_header.get_source() as i64));
                            packet_table.insert(Object::Port(PacketFlag::Dport), Object::Integer(udp_header.get_destination() as i64));
                            packet_table.insert(Object::Flag(PacketFlag::Tcp), Object::Bool(false));
                            packet_table.insert(Object::Flag(PacketFlag::Udp), Object::Bool(true));
                            /* UDP packets have no tcp flags */
                            packet_table.insert(Object::Flag(PacketFlag::Ack), Object::Bool(false));
                            packet_table.insert(Object::Flag(PacketFlag::Syn), Object::Bool(false));
                            packet_table.insert(Object::Flag(PacketFlag::Fin), Object::Bool(false));
                            /* udp packet doesn't have flags */
                            return true;
                        }
                    },
                    _ => {
                        packet_table.insert(Object::Port(PacketFlag::Sport), Object::Integer(0));
                        packet_table.insert(Object::Port(PacketFlag::Dport), Object::Integer(0));
                        packet_table.insert(Object::Flag(PacketFlag::Tcp), Object::Bool(false));
                        packet_table.insert(Object::Flag(PacketFlag::Udp), Object::Bool(false));
                        packet_table.insert(Object::Flag(PacketFlag::Ack), Object::Bool(false));
                        packet_table.insert(Object::Flag(PacketFlag::Syn), Object::Bool(false));
                        packet_table.insert(Object::Flag(PacketFlag::Fin), Object::Bool(false));
                    }
                }
            }
            /* if execute til here, it means that tcp packet isn't captured */
            return false;
        },
        EtherTypes::Ipv6 => {
            /* TODO: add support for ipv6 */
            unimplemented!();
        },
        _ => return false,
    }
}
