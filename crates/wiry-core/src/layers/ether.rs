//! Ethernet II framing from IEEE 802.3 clause 3; EtherType values from the
//! IANA "ETHER TYPES" registry.

use crate::field::FieldDesc;
use crate::proto::{ethertype, Next, ProtoDesc, ProtoId};

pub static FIELDS: &[FieldDesc] = &[
    FieldDesc::mac("dst", 0).defaulting_to(&[0xff; 6]),
    // `src` stays zero: filling it from the host interface needs interface
    // introspection, out of scope for the offline build (DEVIATIONS.md S2).
    FieldDesc::mac("src", 48),
    FieldDesc::uint("type", 96, 16, ethertype::LOOP as u64),
];

fn header_len(_: &[u8]) -> usize {
    14
}

/// The IANA registry, shared by every layer whose next-header field is an
/// EtherType.
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
        _ => Next::Raw,
    }
}

/// The inverse, minus `Ether`: Transparent Ethernet Bridging says a *tunnel*
/// carries a whole frame, so only a tunnel writes it (`gre`, `geneve`). A link
/// layer that stacked it would claim to carry itself.
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
        _ => return None,
    })
}

/// Writes an EtherType at `at`, which is where every layer that carries one
/// differs.
pub fn bind_ethertype(hdr: &mut [u8], at: usize, t: Option<u16>) {
    if let (Some(t), Some(dst)) = (t, hdr.get_mut(at..at + 2)) {
        dst.copy_from_slice(&t.to_be_bytes());
    }
}

fn next(hdr: &[u8]) -> Next {
    if hdr.len() < 14 {
        return Next::Raw;
    }
    from_ethertype(u16::from_be_bytes([hdr[12], hdr[13]]))
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
