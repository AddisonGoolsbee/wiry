//! TCP. Header layout from RFC 9293 section 3.1. Control-bit names follow the
//! conventional single-letter abbreviations used across packet tooling.

use crate::field::FieldDesc;
use crate::proto::{ports, Next, ProtoDesc, ProtoId};

/// Control bits, least significant first: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR.
pub static FLAG_NAMES: &[&str] = &["F", "S", "R", "P", "A", "U", "E", "C"];

pub static FIELDS: &[FieldDesc] = &[
    FieldDesc::uint("sport", 0, 16, 20),
    FieldDesc::uint("dport", 16, 16, 80),
    FieldDesc::uint("seq", 32, 32, 0),
    FieldDesc::uint("ack", 64, 32, 0),
    FieldDesc::uint("dataofs", 96, 4, 5),
    FieldDesc::uint("reserved", 100, 4, 0),
    // Defaults to SYN, matching the long-standing convention for a freshly
    // constructed TCP header in packet-crafting tools.
    FieldDesc {
        name: "flags",
        bit_off: 104,
        bit_len: 8,
        kind: crate::field::FieldKind::Flags,
        default: 0b0000_0010,
        flags: FLAG_NAMES,
        computed: false,
    },
    FieldDesc::uint("window", 112, 16, 8192),
    FieldDesc::computed_uint("chksum", 128, 16),
    FieldDesc::uint("urgptr", 144, 16, 0),
    FieldDesc::var_bytes("options", 160),
];

fn header_len(hdr: &[u8]) -> usize {
    if hdr.len() < 13 {
        return 20;
    }
    // Data Offset counts 32-bit words and must be at least 5 (RFC 9293 §3.1).
    (((hdr[12] >> 4) & 0x0f) as usize * 4).max(20)
}

fn next(hdr: &[u8]) -> Next {
    if hdr.len() < 4 {
        return Next::Raw;
    }
    let sport = u16::from_be_bytes([hdr[0], hdr[1]]);
    let dport = u16::from_be_bytes([hdr[2], hdr[3]]);
    if sport == ports::DNS || dport == ports::DNS {
        // DNS over TCP is length-prefixed, which the DNS layer does not yet
        // handle, so leave it opaque rather than mis-dissect it.
        return Next::Raw;
    }
    Next::Raw
}

pub static DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Tcp,
    name: "TCP",
    fields: FIELDS,
    min_len: 20,
    header_len,
    next,
    build_len: 20,
    bind_next: None,
};
