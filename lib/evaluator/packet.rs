extern crate ipnet;

use std::collections::{HashMap, BTreeMap};
use std::collections::{BTreeSet};
use std::mem::discriminant;
use std::net::{Ipv4Addr, Ipv6Addr};
use self::ipnet::{Ipv4Net};

/* express the relationship between [ID] and [Type] with hashmap */
// pub type SymbolTable = HashMap<String, Variable>;

/* Specify field like source IP, source port to look for */
#[derive(PartialEq, Eq, Hash, Clone, Ord, PartialOrd)]
pub enum PacketField {
    /* Source IP */
    Sip,
    /* Destination IP */
    Dip,
    /* Source port */
    Sport,
    /* Destination port*/
    Dport,
    FlagTcp,
    FlagUdp,
    /* Syn in tcp flag */
    FlagSyn,
    /* Ack in tcp flag */
    FlagAck,
    /* Fin in tcp flag */
    FlagFin,
    IpLen,
}

/* C union like enum structure  */
#[derive(Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub enum PacketInfo {
    IP(Option<Ipv4Addr>),
    Port(Option<u32>),
    Flag(bool),
}