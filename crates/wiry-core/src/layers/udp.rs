//! UDP header layout from RFC 768.

use crate::field::FieldDesc;
use crate::proto::{ports, Next, ProtoDesc, ProtoId};

pub static FIELDS: &[FieldDesc] = &[
    FieldDesc::uint("sport", 0, 16, 53),
    FieldDesc::uint("dport", 16, 16, 53),
    FieldDesc::computed_uint("len", 32, 16),
    FieldDesc::computed_uint("chksum", 48, 16),
];

fn header_len(_: &[u8]) -> usize {
    8
}

fn next(hdr: &[u8]) -> Next {
    if hdr.len() < 4 {
        return Next::Raw;
    }
    let sport = u16::from_be_bytes([hdr[0], hdr[1]]);
    let dport = u16::from_be_bytes([hdr[2], hdr[3]]);
    if sport == ports::DNS || dport == ports::DNS {
        return Next::Proto(ProtoId::Dns);
    }
    if matches!(sport, ports::BOOTPS | ports::BOOTPC)
        || matches!(dport, ports::BOOTPS | ports::BOOTPC)
    {
        return Next::Proto(ProtoId::Bootp);
    }
    // RFC 6762 §18 and RFC 4795 §2: mDNS and LLMNR carry RFC 1035 messages, so
    // they are the DNS layer reached on another port, not a layer of their own.
    if matches!(sport, ports::MDNS | ports::LLMNR) || matches!(dport, ports::MDNS | ports::LLMNR) {
        return Next::Proto(ProtoId::Dns);
    }
    match crate::layers::dispatch::by_udp_port(sport, dport, hdr.get(8..).unwrap_or(&[])) {
        Some(p) => Next::Proto(p),
        None => Next::Raw,
    }
}

/// RFC 768: Length covers the header and its data.
fn content_len(hdr: &[u8]) -> usize {
    if hdr.len() < 6 {
        return 0;
    }
    u16::from_be_bytes([hdr[4], hdr[5]]) as usize
}

/// RFC 951 §3 ports: the default 53/53 would otherwise dissect back as DNS.
fn bind_next(hdr: &mut [u8], p: ProtoId) {
    if hdr.len() < 4 {
        return;
    }
    if p == ProtoId::Bootp {
        hdr[0..2].copy_from_slice(&ports::BOOTPS.to_be_bytes());
        hdr[2..4].copy_from_slice(&ports::BOOTPC.to_be_bytes());
        return;
    }
    if let Some(port) = crate::layers::dispatch::by_udp_port_of(p) {
        // Both halves: the default 53/53 would otherwise still read back as DNS.
        hdr[0..2].copy_from_slice(&port.to_be_bytes());
        hdr[2..4].copy_from_slice(&port.to_be_bytes());
    }
}

pub static DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Udp,
    name: "UDP",
    fields: FIELDS,
    min_len: 8,
    header_len,
    next,
    build_len: 8,
    parse_options: None,
    opt_table: None,
    set_hlen: None,
    bind_next: Some(bind_next),
    bind_next_bytes: None,
    content_len: Some(content_len),
};
