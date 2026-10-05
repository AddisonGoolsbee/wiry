//! Ethernet II, IEEE 802.3 clause 3. EtherType values follow the IANA "ETHER
//! TYPES" registry.

use crate::field::FieldDesc;
use crate::names::Host;
use crate::proto::{ethertype, Next, ProtoDesc, ProtoId};

pub static FIELDS: &[FieldDesc] = &[
    FieldDesc::mac("dst", 0).defaulting_to(&[0xff; 6]),
    // Zero rather than the host's address: the engine does no interface
    // lookup (DEVIATIONS.md S2).
    FieldDesc::mac("src", 48),
    FieldDesc::uint("type", 96, 16, ethertype::LOOP as u64).host_named(Host::EtherTypes),
];

fn header_len(_: &[u8]) -> usize {
    14
}

/// The layer an EtherType names, for every layer whose next-header field is
/// one. SNAP uses it too: under OUI 0x000000 the protocol id is an EtherType
/// (RFC 1042).
pub fn from_ethertype(t: u16) -> Next {
    match t {
        ethertype::IPV4 => Next::Proto(ProtoId::Ipv4),
        ethertype::IPV6 => Next::Proto(ProtoId::Ipv6),
        ethertype::ARP => Next::Proto(ProtoId::Arp),
        ethertype::DOT1Q => Next::Proto(ProtoId::Dot1Q),
        ethertype::TEB => Next::Proto(ProtoId::Ether),
        ethertype::MPLS_UNICAST | ethertype::MPLS_MULTICAST => Next::Proto(ProtoId::Mpls),
        ethertype::PPPOE_DISCOVERY => Next::Proto(ProtoId::PppoeDisc),
        ethertype::PPPOE_SESSION => Next::Proto(ProtoId::Pppoe),
        ethertype::PPP_LINK => Next::Proto(ProtoId::Ppp),
        _ => match crate::layers::dispatch::by_ethertype(t) {
            Some(p) => Next::Proto(p),
            None => Next::Raw,
        },
    }
}

/// The inverse of [`from_ethertype`], except that `Ether` yields nothing:
/// Transparent Ethernet Bridging means a tunnel carries a whole frame, so only
/// a tunnel writes it (`gre`, `geneve`). A link layer that did would claim to
/// carry itself.
pub fn to_ethertype(p: ProtoId) -> Option<u16> {
    Some(match p {
        ProtoId::Ipv4 => ethertype::IPV4,
        ProtoId::Ipv6 => ethertype::IPV6,
        ProtoId::Arp => ethertype::ARP,
        ProtoId::Dot1Q => ethertype::DOT1Q,
        ProtoId::Mpls => ethertype::MPLS_UNICAST,
        ProtoId::PppoeDisc => ethertype::PPPOE_DISCOVERY,
        ProtoId::Pppoe => ethertype::PPPOE_SESSION,
        ProtoId::Ppp => ethertype::PPP_LINK,
        // Never an 802.3 length: that is the payload's size, which is unknown
        // while the header is being bound.
        _ => return crate::layers::dispatch::by_ethertype_of(p),
    })
}

/// Writes `t` big-endian at `at`. A header too short to hold it is left alone.
pub fn bind_ethertype(hdr: &mut [u8], at: usize, t: Option<u16>) {
    if let (Some(t), Some(dst)) = (t, hdr.get_mut(at..at + 2)) {
        dst.copy_from_slice(&t.to_be_bytes());
    }
}

fn next(hdr: &[u8]) -> Next {
    if hdr.len() < 14 {
        return Next::Raw;
    }
    let t = u16::from_be_bytes([hdr[12], hdr[13]]);
    // IEEE 802.3 clause 3.2.6: at or below 1500 the field is a length and an
    // 802.2 LLC header follows.
    if t <= 1500 {
        return Next::Proto(ProtoId::Llc);
    }
    from_ethertype(t)
}

fn bind_next(hdr: &mut [u8], p: ProtoId) {
    bind_ethertype(hdr, 12, to_ethertype(p));
}

pub static DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Ether,
    name: "Ether",
    fields: FIELDS,
    min_len: 14,
    header_len,
    next,
    build_len: 14,
    parse_options: None,
    opt_table: None,
    set_hlen: None,
    bind_next: Some(bind_next),
    bind_next_bytes: None,
    content_len: None,
};
