//! IPv6. Header layout from RFC 8200 section 3; Next Header values from the
//! IANA "Protocol Numbers" registry.

use crate::field::FieldDesc;
use crate::proto::{ipproto, Next, ProtoDesc, ProtoId};

/// Next Header value meaning the payload ends here (RFC 8200 §4.7).
pub const NO_NEXT_HEADER: u8 = 59;

/// Extension headers are not walked (DEVIATIONS.md E6); they dissect as `Raw`
/// rather than being mis-read as a transport header.
const EXT_HOP_BY_HOP: u8 = 0;
const EXT_ROUTING: u8 = 43;
const EXT_FRAGMENT: u8 = 44;
const EXT_DEST_OPTS: u8 = 60;

pub static FIELDS: &[FieldDesc] = &[
    FieldDesc::uint("version", 0, 4, 6),
    FieldDesc::uint("tc", 4, 8, 0),
    FieldDesc::uint("fl", 12, 20, 0),
    FieldDesc::computed_uint("plen", 32, 16),
    FieldDesc::uint("nh", 48, 8, NO_NEXT_HEADER as u64),
    FieldDesc::uint("hlim", 56, 8, 64),
    FieldDesc::ipv6("src", 64),
    FieldDesc::ipv6("dst", 192),
];

/// RFC 8200 §3: the IPv6 header is a fixed 40 octets. Anything further is an
/// extension header and belongs to the payload, not to this layer.
fn header_len(_: &[u8]) -> usize {
    40
}

fn next(hdr: &[u8]) -> Next {
    if hdr.len() < 40 {
        return Next::Raw;
    }
    match hdr[6] {
        ipproto::TCP => Next::Proto(ProtoId::Tcp),
        ipproto::UDP => Next::Proto(ProtoId::Udp),
        ipproto::IPV6_ICMP => Next::Proto(ProtoId::Icmpv6),
        EXT_HOP_BY_HOP | EXT_ROUTING | EXT_FRAGMENT | EXT_DEST_OPTS => Next::Raw,
        _ => Next::Raw,
    }
}

/// Stacking a transport layer under IPv6 sets the Next Header field to match it.
fn bind_next(hdr: &mut [u8], p: ProtoId) {
    let v = match p {
        ProtoId::Tcp => ipproto::TCP,
        ProtoId::Udp => ipproto::UDP,
        ProtoId::Icmpv6 => ipproto::IPV6_ICMP,
        _ => return,
    };
    if hdr.len() >= 40 {
        hdr[6] = v;
    }
}

pub static DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Ipv6,
    name: "IPv6",
    fields: FIELDS,
    min_len: 40,
    header_len,
    next,
    build_len: 40,
    parse_options: None,
    bind_next: Some(bind_next),
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldValue;
    use crate::packet::Packet;
    use crate::show::render_ipv6;

    const SRC: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    const DST: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
    ];

    /// Hand-built from the RFC 8200 §3 field order:
    /// version 6, tc 0x12, fl 0x34567 packs as 0110 00010010 00110100010101100111.
    fn header() -> Vec<u8> {
        let mut v = vec![0x61, 0x23, 0x45, 0x67];
        v.extend_from_slice(&[0x00, 0x08]); // plen = 8
        v.push(ipproto::IPV6_ICMP); // nh = 58
        v.push(0x40); // hlim = 64
        v.extend_from_slice(&SRC);
        v.extend_from_slice(&DST);
        v
    }

    fn frame() -> Vec<u8> {
        let mut v = header();
        v.extend_from_slice(&[0x80, 0x00, 0x12, 0x13, 0x12, 0x34, 0x00, 0x01]);
        v
    }

    #[test]
    fn dissects_hand_built_header() {
        let p = Packet::dissect(frame(), ProtoId::Ipv6);
        let ip = p.find_layer(ProtoId::Ipv6).unwrap();
        assert_eq!(p.get(ip, "version").unwrap(), FieldValue::Uint(6));
        assert_eq!(p.get(ip, "tc").unwrap(), FieldValue::Uint(0x12));
        assert_eq!(p.get(ip, "fl").unwrap(), FieldValue::Uint(0x34567));
        assert_eq!(p.get(ip, "plen").unwrap(), FieldValue::Uint(8));
        assert_eq!(p.get(ip, "nh").unwrap(), FieldValue::Uint(58));
        assert_eq!(p.get(ip, "hlim").unwrap(), FieldValue::Uint(64));
        assert_eq!(p.get(ip, "src").unwrap(), FieldValue::Ipv6(SRC));
        assert_eq!(p.get(ip, "dst").unwrap(), FieldValue::Ipv6(DST));
        assert_eq!(render_ipv6(&SRC), "2001:db8::1");
        assert_eq!(render_ipv6(&DST), "2001:db8::2");
        assert_eq!(p.header(ip).len(), 40);
    }

    #[test]
    fn roundtrips_bytes_and_edits() {
        let bytes = frame();
        let mut p = Packet::dissect(bytes.clone(), ProtoId::Ipv6);
        assert_eq!(p.raw_bytes(), &bytes[..]);

        let ip = p.find_layer(ProtoId::Ipv6).unwrap();
        assert!(p.set_uint(ip, "hlim", 255));
        assert!(p.set_uint(ip, "fl", 0xfffff));
        assert_eq!(p.get(ip, "hlim").unwrap(), FieldValue::Uint(255));
        assert_eq!(p.get(ip, "fl").unwrap(), FieldValue::Uint(0xfffff));
        // Writing a sub-byte field must not disturb its neighbours.
        assert_eq!(p.get(ip, "version").unwrap(), FieldValue::Uint(6));
        assert_eq!(p.get(ip, "tc").unwrap(), FieldValue::Uint(0x12));
    }

    #[test]
    fn short_input_does_not_panic() {
        for n in 0..40usize {
            let p = Packet::dissect(header()[..n].to_vec(), ProtoId::Ipv6);
            assert!(p.layers().iter().all(|s| s.proto == ProtoId::Raw));
            assert_eq!(next(&header()[..n]), Next::Raw);
            assert_eq!(header_len(&header()[..n]), 40);
        }
        // A full header with a truncated payload still dissects cleanly.
        let mut short = header();
        short.extend_from_slice(&[0x80, 0x00]);
        let p = Packet::dissect(short, ProtoId::Ipv6);
        assert_eq!(p.layers()[0].proto, ProtoId::Ipv6);
    }

    #[test]
    fn next_dispatches_on_next_header() {
        let mut h = header();
        let cases: &[(u8, Next)] = &[
            (ipproto::TCP, Next::Proto(ProtoId::Tcp)),
            (ipproto::UDP, Next::Proto(ProtoId::Udp)),
            (ipproto::IPV6_ICMP, Next::Proto(ProtoId::Icmpv6)),
            (NO_NEXT_HEADER, Next::Raw),
            (EXT_HOP_BY_HOP, Next::Raw),
            (EXT_ROUTING, Next::Raw),
            (EXT_FRAGMENT, Next::Raw),
            (EXT_DEST_OPTS, Next::Raw),
            (132, Next::Raw),
        ];
        for &(nh, want) in cases {
            h[6] = nh;
            assert_eq!(next(&h), want, "nh={nh}");
        }
    }

    #[test]
    fn build_uses_rfc_defaults_and_binds() {
        let p = Packet::build(&[ProtoId::Ipv6]);
        let ip = p.find_layer(ProtoId::Ipv6).unwrap();
        assert_eq!(p.get(ip, "version").unwrap(), FieldValue::Uint(6));
        assert_eq!(p.get(ip, "hlim").unwrap(), FieldValue::Uint(64));
        assert_eq!(
            p.get(ip, "nh").unwrap(),
            FieldValue::Uint(NO_NEXT_HEADER as u64)
        );
        assert_eq!(p.raw_bytes().len(), 40);

        let p = Packet::build(&[ProtoId::Ipv6, ProtoId::Udp]);
        let ip = p.find_layer(ProtoId::Ipv6).unwrap();
        assert_eq!(
            p.get(ip, "nh").unwrap(),
            FieldValue::Uint(ipproto::UDP as u64)
        );
    }

    #[test]
    fn plen_is_recomputed_over_payload() {
        let mut p = Packet::build(&[ProtoId::Ipv6, ProtoId::Icmpv6]);
        p.set_payload(1, b"abcdefghij");
        let _ = p.to_bytes();
        let ip = p.find_layer(ProtoId::Ipv6).unwrap();
        // 4-byte ICMPv6 header + 10 payload bytes.
        assert_eq!(p.get(ip, "plen").unwrap(), FieldValue::Uint(14));
    }
}
