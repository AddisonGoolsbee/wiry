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

/// Shared with SNAP (RFC 1042), whose protocol id under OUI 0x000000 is an
/// EtherType.
pub fn ethertype_next(t: u16) -> Next {
    match t {
        ethertype::IPV4 => Next::Proto(ProtoId::Ipv4),
        ethertype::IPV6 => Next::Proto(ProtoId::Ipv6),
        ethertype::ARP => Next::Proto(ProtoId::Arp),
        ethertype::DOT1Q => Next::Proto(ProtoId::Dot1Q),
        _ => match crate::layers::dispatch::by_ethertype(t) {
            Some(p) => Next::Proto(p),
            None => Next::Raw,
        },
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
    ethertype_next(t)
}

fn bind_next(hdr: &mut [u8], p: ProtoId) {
    let t = match p {
        ProtoId::Ipv4 => ethertype::IPV4,
        ProtoId::Ipv6 => ethertype::IPV6,
        ProtoId::Arp => ethertype::ARP,
        ProtoId::Dot1Q => ethertype::DOT1Q,
        // An 802.3 length cannot be written here: it is the payload's size,
        // which nothing knows while the header is being bound.
        _ => match crate::layers::dispatch::by_ethertype_of(p) {
            Some(t) => t,
            None => return,
        },
    };
    if hdr.len() >= 14 {
        hdr[12..14].copy_from_slice(&t.to_be_bytes());
    }
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
