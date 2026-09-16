//! Ethernet II framing. Layout from IEEE 802.3 clause 3; EtherType values from
//! the IANA "ETHER TYPES" registry.

use crate::field::FieldDesc;
use crate::proto::{ethertype, Next, ProtoDesc, ProtoId};

pub static FIELDS: &[FieldDesc] = &[
    // Defaults to the broadcast address. `src` stays zero: filling it from the
    // host interface would need interface introspection, which is out of scope
    // for the offline build (see DEVIATIONS.md S2).
    FieldDesc {
        name: "dst",
        bit_off: 0,
        bit_len: 48,
        kind: crate::field::FieldKind::MacAddr,
        default: 0xffff_ffff_ffff,
        flags: &[],
        computed: false,
    },
    FieldDesc::mac("src", 48),
    FieldDesc::uint("type", 96, 16, ethertype::IPV4 as u64),
];

fn header_len(_: &[u8]) -> usize {
    14
}

fn next(hdr: &[u8]) -> Next {
    if hdr.len() < 14 {
        return Next::Raw;
    }
    match u16::from_be_bytes([hdr[12], hdr[13]]) {
        ethertype::IPV4 => Next::Proto(ProtoId::Ipv4),
        ethertype::IPV6 => Next::Proto(ProtoId::Ipv6),
        ethertype::ARP => Next::Proto(ProtoId::Arp),
        ethertype::DOT1Q => Next::Proto(ProtoId::Dot1Q),
        _ => Next::Raw,
    }
}

/// Stacking a layer under Ethernet sets the EtherType to match it.
fn bind_next(hdr: &mut [u8], p: ProtoId) {
    let t = match p {
        ProtoId::Ipv4 => ethertype::IPV4,
        ProtoId::Ipv6 => ethertype::IPV6,
        ProtoId::Arp => ethertype::ARP,
        ProtoId::Dot1Q => ethertype::DOT1Q,
        _ => return,
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
    bind_next: Some(bind_next),
};
