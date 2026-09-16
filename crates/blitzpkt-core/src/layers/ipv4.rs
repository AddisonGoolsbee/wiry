//! IPv4. Header layout from RFC 791 section 3.1; protocol numbers from the
//! IANA "Protocol Numbers" registry.

use crate::field::FieldDesc;
use crate::proto::{ipproto, Next, ProtoDesc, ProtoId};

/// Fragment-offset field flag bits, most significant first within the 3-bit group:
/// bit 0 reserved, bit 1 Don't Fragment, bit 2 More Fragments (RFC 791 §3.1).
pub static FLAG_NAMES: &[&str] = &["MF", "DF", "evil"];

pub static FIELDS: &[FieldDesc] = &[
    FieldDesc::uint("version", 0, 4, 4),
    FieldDesc::uint("ihl", 4, 4, 5),
    FieldDesc::uint("tos", 8, 8, 0),
    FieldDesc::computed_uint("len", 16, 16),
    FieldDesc::uint("id", 32, 16, 1),
    FieldDesc::flags("flags", 48, 3, FLAG_NAMES),
    FieldDesc::uint("frag", 51, 13, 0),
    FieldDesc::uint("ttl", 64, 8, 64),
    FieldDesc::uint("proto", 72, 8, ipproto::TCP as u64),
    FieldDesc::computed_uint("chksum", 80, 16),
    FieldDesc::ipv4("src", 96, 0),
    FieldDesc::ipv4("dst", 128, 0),
    FieldDesc::var_bytes("options", 160),
];

fn header_len(hdr: &[u8]) -> usize {
    if hdr.is_empty() {
        return 20;
    }
    // IHL counts 32-bit words and must be at least 5 (RFC 791 §3.1).
    ((hdr[0] & 0x0f) as usize * 4).max(20)
}

fn next(hdr: &[u8]) -> Next {
    if hdr.len() < 20 {
        return Next::Raw;
    }
    // A non-zero fragment offset means this is not the first fragment, so the
    // transport header is not present here.
    let frag_off = u16::from_be_bytes([hdr[6], hdr[7]]) & 0x1fff;
    if frag_off != 0 {
        return Next::Raw;
    }
    match hdr[9] {
        ipproto::TCP => Next::Proto(ProtoId::Tcp),
        ipproto::UDP => Next::Proto(ProtoId::Udp),
        ipproto::ICMP => Next::Proto(ProtoId::Icmp),
        _ => Next::Raw,
    }
}

/// Stacking a transport layer under IPv4 sets the Protocol field to match it.
fn bind_next(hdr: &mut [u8], p: ProtoId) {
    let v = match p {
        ProtoId::Tcp => ipproto::TCP,
        ProtoId::Udp => ipproto::UDP,
        ProtoId::Icmp => ipproto::ICMP,
        _ => return,
    };
    if hdr.len() >= 20 {
        hdr[9] = v;
    }
}

pub static DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Ipv4,
    name: "IP",
    fields: FIELDS,
    min_len: 20,
    header_len,
    next,
    build_len: 20,
    bind_next: Some(bind_next),
};
