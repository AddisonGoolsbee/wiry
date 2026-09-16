//! DNS. Fixed 12-byte message header from RFC 1035 section 4.1.1:
//!
//! ```text
//!                                 1  1  1  1  1  1
//!   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                      ID                       |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                    QDCOUNT                    |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                    ANCOUNT                    |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                    NSCOUNT                    |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                    ARCOUNT                    |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! ```
//!
//! The question and resource-record sections that follow are variable length and
//! use name compression (RFC 1035 §4.1.4); they are not parsed yet and stay as an
//! opaque payload. See DEVIATIONS.md E8.

use crate::field::FieldDesc;
use crate::proto::{Next, ProtoDesc, ProtoId};

pub static FIELDS: &[FieldDesc] = &[
    FieldDesc::uint("id", 0, 16, 0),
    FieldDesc::uint("qr", 16, 1, 0),
    FieldDesc::uint("opcode", 17, 4, 0),
    FieldDesc::uint("aa", 21, 1, 0),
    FieldDesc::uint("tc", 22, 1, 0),
    FieldDesc::uint("rd", 23, 1, 1),
    FieldDesc::uint("ra", 24, 1, 0),
    FieldDesc::uint("z", 25, 3, 0),
    FieldDesc::uint("rcode", 28, 4, 0),
    FieldDesc::uint("qdcount", 32, 16, 1),
    FieldDesc::uint("ancount", 48, 16, 0),
    FieldDesc::uint("nscount", 64, 16, 0),
    FieldDesc::uint("arcount", 80, 16, 0),
];

fn header_len(_: &[u8]) -> usize {
    12
}

fn next(_: &[u8]) -> Next {
    Next::Raw
}

pub static DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Dns,
    name: "DNS",
    fields: FIELDS,
    min_len: 12,
    header_len,
    next,
    build_len: 12,
    bind_next: None,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldValue;
    use crate::packet::Packet;

    /// Standard recursive query for "a.com" A/IN, hand-built from RFC 1035 §4.1.
    /// Flags 0x0100: QR=0, OPCODE=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0.
    fn query() -> Vec<u8> {
        let mut v = vec![
            0xab, 0xcd, // id
            0x01, 0x00, // flags
            0x00, 0x01, // qdcount
            0x00, 0x00, // ancount
            0x00, 0x00, // nscount
            0x00, 0x00, // arcount
        ];
        // Question section: 1 "a" 3 "com" 0, QTYPE=1 (A), QCLASS=1 (IN).
        v.extend_from_slice(b"\x01a\x03com\x00");
        v.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        v
    }

    #[test]
    fn dissects_query_header() {
        let p = Packet::dissect(query(), ProtoId::Dns);
        let d = p.find_layer(ProtoId::Dns).unwrap();
        assert_eq!(p.header(d).len(), 12);
        assert_eq!(p.get(d, "id").unwrap(), FieldValue::Uint(0xabcd));
        assert_eq!(p.get(d, "qr").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(d, "opcode").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(d, "rd").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(d, "qdcount").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(d, "ancount").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(d, "nscount").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(d, "arcount").unwrap(), FieldValue::Uint(0));
    }

    #[test]
    fn record_sections_stay_raw() {
        let p = Packet::dissect(query(), ProtoId::Dns);
        let got: Vec<_> = p.layers().iter().map(|s| s.proto).collect();
        assert_eq!(got, vec![ProtoId::Dns, ProtoId::Raw]);
        let d = p.find_layer(ProtoId::Dns).unwrap();
        assert_eq!(p.payload(d), b"\x01a\x03com\x00\x00\x01\x00\x01");
    }

    #[test]
    fn subbyte_flags_decode_at_rfc_bit_offsets() {
        // Byte 2 = 0x85 = 1 0000 1 0 1 -> QR=1, OPCODE=0, AA=1, TC=0, RD=1
        // Byte 3 = 0x83 = 1 000 0011   -> RA=1, Z=0, RCODE=3 (name error)
        let mut a = vec![0x00, 0x00, 0x85, 0x83];
        a.extend_from_slice(&[0; 8]);
        let p = Packet::dissect(a, ProtoId::Dns);
        assert_eq!(p.get(0, "qr").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(0, "opcode").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(0, "aa").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(0, "tc").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(0, "rd").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(0, "ra").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(0, "z").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(0, "rcode").unwrap(), FieldValue::Uint(3));

        // A second pattern where every field differs, so no two offsets can be
        // swapped and still pass.
        // Byte 2 = 0x13 = 0 0010 0 1 1 -> QR=0, OPCODE=2 (STATUS), AA=0, TC=1, RD=1
        // Byte 3 = 0x5f = 0 101 1111   -> RA=0, Z=5, RCODE=15
        let mut b = vec![0x00, 0x00, 0x13, 0x5f];
        b.extend_from_slice(&[0; 8]);
        let p = Packet::dissect(b, ProtoId::Dns);
        assert_eq!(p.get(0, "qr").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(0, "opcode").unwrap(), FieldValue::Uint(2));
        assert_eq!(p.get(0, "aa").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(0, "tc").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(0, "rd").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(0, "ra").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(0, "z").unwrap(), FieldValue::Uint(5));
        assert_eq!(p.get(0, "rcode").unwrap(), FieldValue::Uint(15));
    }

    #[test]
    fn flag_writes_land_in_the_right_bits() {
        let mut p = Packet::dissect(query(), ProtoId::Dns);
        assert!(p.set_uint(0, "qr", 1));
        assert!(p.set_uint(0, "opcode", 0b0101));
        assert!(p.set_uint(0, "rcode", 0b1001));
        assert!(p.set_uint(0, "ancount", 2));
        // 1 0101 0 0 1 = 0xa9, 0 000 1001 = 0x09
        assert_eq!(&p.raw_bytes()[2..4], &[0xa9, 0x09]);
        assert_eq!(p.get(0, "rd").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(0, "ancount").unwrap(), FieldValue::Uint(2));
    }

    #[test]
    fn roundtrips_unchanged_bytes() {
        let orig = query();
        let p = Packet::dissect(orig.clone(), ProtoId::Dns);
        assert_eq!(p.raw_bytes(), &orig[..]);
        assert_eq!(p.layer_bytes(0), &orig[..]);
    }

    #[test]
    fn short_input_does_not_panic() {
        for n in 0..12usize {
            let p = Packet::dissect(query()[..n].to_vec(), ProtoId::Dns);
            assert!(p.layers().iter().all(|s| s.proto == ProtoId::Raw));
            assert_eq!(p.get(0, "qdcount"), None);
        }
    }

    #[test]
    fn dissects_under_udp_port_53() {
        let mut v = vec![0x30, 0x39, 0x00, 0x35, 0x00, 0x00, 0x00, 0x00];
        v.extend_from_slice(&query());
        let p = Packet::dissect(v, ProtoId::Udp);
        let d = p.find_layer(ProtoId::Dns).expect("dns layer");
        assert_eq!(p.get(d, "id").unwrap(), FieldValue::Uint(0xabcd));
    }

    #[test]
    fn build_defaults_match_a_recursive_query() {
        let p = Packet::build(&[ProtoId::Dns]);
        assert_eq!(p.raw_bytes().len(), 12);
        assert_eq!(p.get(0, "rd").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(0, "qdcount").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(0, "qr").unwrap(), FieldValue::Uint(0));
        assert_eq!(&p.raw_bytes()[0..6], &[0x00, 0x00, 0x01, 0x00, 0x00, 0x01]);
    }
}
