//! ICMPv6. Common header layout from RFC 4443 section 2.1; the checksum covers
//! the IPv6 pseudo-header per RFC 4443 section 2.3. Type values from the IANA
//! "ICMPv6 Parameters" registry.

use crate::field::FieldDesc;
use crate::proto::{Next, ProtoDesc, ProtoId};

/// Echo Request (RFC 4443 §4.1).
pub const ECHO_REQUEST: u8 = 128;

pub static FIELDS: &[FieldDesc] = &[
    FieldDesc::uint("type", 0, 8, ECHO_REQUEST as u64),
    FieldDesc::uint("code", 8, 8, 0),
    FieldDesc::computed_uint("cksum", 16, 16),
];

/// RFC 4443 §2.1: every ICMPv6 message opens with the same 4 octets. The
/// message body beyond that is type-specific and stays in the payload.
fn header_len(_: &[u8]) -> usize {
    4
}

fn next(_: &[u8]) -> Next {
    Next::Raw
}

pub static DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Icmpv6,
    name: "ICMPv6",
    fields: FIELDS,
    min_len: 4,
    header_len,
    next,
    build_len: 4,
    bind_next: None,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum as ck;
    use crate::field::FieldValue;
    use crate::packet::Packet;

    const SRC: [u8; 16] =
        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
    const DST: [u8; 16] =
        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];

    /// Echo Request with identifier 0x1234 and sequence 1. The checksum 0x1213
    /// is the one's complement of the pseudo-header sum (0x5bb7) plus the
    /// message sum (0x9235), worked by hand from RFC 4443 §2.3.
    fn echo() -> Vec<u8> {
        vec![0x80, 0x00, 0x12, 0x13, 0x12, 0x34, 0x00, 0x01]
    }

    fn ipv6_echo() -> Vec<u8> {
        let mut v = vec![0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 58, 0x40];
        v.extend_from_slice(&SRC);
        v.extend_from_slice(&DST);
        v.extend_from_slice(&echo());
        v
    }

    #[test]
    fn dissects_echo_request() {
        let p = Packet::dissect(echo(), ProtoId::Icmpv6);
        let ic = p.find_layer(ProtoId::Icmpv6).unwrap();
        assert_eq!(p.get(ic, "type").unwrap(), FieldValue::Uint(128));
        assert_eq!(p.get(ic, "code").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(ic, "cksum").unwrap(), FieldValue::Uint(0x1213));
        assert_eq!(p.payload(ic), &[0x12, 0x34, 0x00, 0x01]);
    }

    #[test]
    fn roundtrips_bytes_and_edits() {
        let bytes = ipv6_echo();
        let mut p = Packet::dissect(bytes.clone(), ProtoId::Ipv6);
        assert_eq!(
            p.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![ProtoId::Ipv6, ProtoId::Icmpv6, ProtoId::Raw]
        );
        assert_eq!(p.raw_bytes(), &bytes[..]);

        let ic = p.find_layer(ProtoId::Icmpv6).unwrap();
        // 129 = Echo Reply (RFC 4443 §4.2).
        assert!(p.set_uint(ic, "type", 129));
        assert!(p.set_uint(ic, "code", 3));
        assert_eq!(p.get(ic, "type").unwrap(), FieldValue::Uint(129));
        assert_eq!(p.get(ic, "code").unwrap(), FieldValue::Uint(3));
    }

    #[test]
    fn short_input_does_not_panic() {
        for n in 0..4usize {
            let p = Packet::dissect(echo()[..n].to_vec(), ProtoId::Icmpv6);
            assert!(p.layers().iter().all(|s| s.proto == ProtoId::Raw));
            assert_eq!(header_len(&echo()[..n]), 4);
            assert_eq!(next(&echo()[..n]), Next::Raw);
        }
        // Truncated inside an IPv6 frame: the trailing 2 octets fall back to Raw.
        let mut v = ipv6_echo();
        v.truncate(42);
        let p = Packet::dissect(v, ProtoId::Ipv6);
        assert_eq!(
            p.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![ProtoId::Ipv6, ProtoId::Raw]
        );
    }

    #[test]
    fn next_is_always_raw() {
        let mut m = echo();
        for t in [1u8, 2, 3, 4, 128, 129, 133, 135, 136] {
            m[0] = t;
            assert_eq!(next(&m), Next::Raw, "type={t}");
        }
        // Trailing bytes after the 4-octet header become an opaque payload.
        let p = Packet::dissect(echo(), ProtoId::Icmpv6);
        assert_eq!(
            p.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![ProtoId::Icmpv6, ProtoId::Raw]
        );
    }

    #[test]
    fn checksum_matches_hand_computed_vector() {
        let mut p = Packet::build(&[ProtoId::Ipv6, ProtoId::Icmpv6]);
        let ip = p.find_layer(ProtoId::Ipv6).unwrap();
        let ic = p.find_layer(ProtoId::Icmpv6).unwrap();
        assert!(p.set_bytes(ip, "src", &SRC));
        assert!(p.set_bytes(ip, "dst", &DST));
        p.set_payload(ic, &[0x12, 0x34, 0x00, 0x01]);
        let bytes = p.to_bytes().to_vec();
        assert_eq!(&bytes[40..], &echo()[..]);

        // And it is self-verifying: summing the message with the field in place
        // over the pseudo-header yields zero.
        let seed = ck::pseudo_v6(&SRC, &DST, 58, 8);
        assert_eq!(ck::finish(ck::sum16(&bytes[40..], seed)), 0);
    }
}
