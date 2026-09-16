//! ICMPv4. Header layout from RFC 792 (Echo / Echo Reply message format, and the
//! common Type / Code / Checksum prefix shared by every ICMP message).
//! Type numbers from the IANA "ICMP Type Numbers" registry.

use crate::field::FieldDesc;
use crate::proto::{Next, ProtoDesc, ProtoId};

pub mod types {
    pub const ECHO_REPLY: u8 = 0;
    pub const DEST_UNREACH: u8 = 3;
    pub const ECHO_REQUEST: u8 = 8;
    pub const TIME_EXCEEDED: u8 = 11;
}

/// `id` and `seq` carry those meanings only for Echo/Echo Reply, Timestamp and
/// Information Request messages. For error messages (type 3, 11) RFC 792 gives
/// the same four bytes to unused/pointer/gateway fields. The field table is flat
/// and cannot yet express type-dependent layouts (DEVIATIONS.md E1), so the bytes
/// are always named id/seq; for error types read them as raw offsets 4..8.
pub static FIELDS: &[FieldDesc] = &[
    FieldDesc::uint("type", 0, 8, types::ECHO_REQUEST as u64),
    FieldDesc::uint("code", 8, 8, 0),
    FieldDesc::computed_uint("chksum", 16, 16),
    FieldDesc::uint("id", 32, 16, 0),
    FieldDesc::uint("seq", 48, 16, 0),
];

fn header_len(_: &[u8]) -> usize {
    8
}

fn next(_: &[u8]) -> Next {
    // Error messages quote the offending datagram; quoted-packet dissection is
    // out of scope, so every payload stays opaque.
    Next::Raw
}

pub static DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Icmp,
    name: "ICMP",
    fields: FIELDS,
    min_len: 8,
    header_len,
    next,
    build_len: 8,
    bind_next: None,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldValue;
    use crate::packet::Packet;

    /// Echo Request, id 0x1234, seq 1, with a 4-byte payload. Hand-built from the
    /// RFC 792 Echo message diagram.
    fn echo_request() -> Vec<u8> {
        vec![
            0x08, 0x00, // type 8, code 0
            0x48, 0x2d, // checksum over the whole message
            0x12, 0x34, // identifier
            0x00, 0x01, // sequence number
            0xde, 0xad, 0xbe, 0xef, // payload
        ]
    }

    #[test]
    fn dissects_echo_request_fields() {
        let p = Packet::dissect(echo_request(), ProtoId::Icmp);
        let i = p.find_layer(ProtoId::Icmp).unwrap();
        assert_eq!(p.get(i, "type").unwrap(), FieldValue::Uint(8));
        assert_eq!(p.get(i, "code").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(i, "chksum").unwrap(), FieldValue::Uint(0x482d));
        // The hand-computed vector is a valid ICMP message.
        assert_eq!(crate::checksum::ones_complement(p.layer_bytes(i)), 0);
        assert_eq!(p.get(i, "id").unwrap(), FieldValue::Uint(0x1234));
        assert_eq!(p.get(i, "seq").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.header(i).len(), 8);
        assert_eq!(p.payload(i), &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn payload_after_header_is_raw() {
        let p = Packet::dissect(echo_request(), ProtoId::Icmp);
        let got: Vec<_> = p.layers().iter().map(|s| s.proto).collect();
        assert_eq!(got, vec![ProtoId::Icmp, ProtoId::Raw]);
    }

    #[test]
    fn roundtrips_bytes_and_edits() {
        let orig = echo_request();
        let mut p = Packet::dissect(orig.clone(), ProtoId::Icmp);
        assert_eq!(p.raw_bytes(), &orig[..]);

        let i = p.find_layer(ProtoId::Icmp).unwrap();
        assert!(p.set_uint(i, "type", types::ECHO_REPLY as u64));
        assert!(p.set_uint(i, "seq", 0xbeef));
        assert_eq!(p.get(i, "type").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(i, "seq").unwrap(), FieldValue::Uint(0xbeef));
        assert_eq!(p.get(i, "id").unwrap(), FieldValue::Uint(0x1234));
    }

    #[test]
    fn error_message_type_and_code_decode() {
        // Destination Unreachable, code 3 (port unreachable). RFC 792 makes the
        // next four bytes "unused"; the flat table still names them id/seq.
        let bytes = vec![0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let p = Packet::dissect(bytes, ProtoId::Icmp);
        let i = p.find_layer(ProtoId::Icmp).unwrap();
        assert_eq!(p.get(i, "type").unwrap(), FieldValue::Uint(types::DEST_UNREACH as u64));
        assert_eq!(p.get(i, "code").unwrap(), FieldValue::Uint(3));
        assert_eq!(p.get(i, "id").unwrap(), FieldValue::Uint(0));
    }

    #[test]
    fn short_input_does_not_panic() {
        for n in 0..8usize {
            let p = Packet::dissect(echo_request()[..n].to_vec(), ProtoId::Icmp);
            // Below min_len the bytes fall back to Raw rather than being decoded.
            assert!(p.layers().iter().all(|s| s.proto == ProtoId::Raw));
            assert_eq!(p.get(0, "type"), None);
        }
    }

    #[test]
    fn dissects_under_ipv4() {
        let mut v = vec![
            0x45, 0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00,
        ];
        v.extend_from_slice(&[10, 0, 0, 1]);
        v.extend_from_slice(&[10, 0, 0, 2]);
        v.extend_from_slice(&echo_request());
        let p = Packet::dissect(v, ProtoId::Ipv4);
        let i = p.find_layer(ProtoId::Icmp).expect("icmp layer");
        assert_eq!(p.get(i, "id").unwrap(), FieldValue::Uint(0x1234));
    }

    #[test]
    fn checksum_recomputes_to_a_valid_header() {
        let mut p = Packet::build(&[ProtoId::Ipv4, ProtoId::Icmp]);
        p.set_payload(1, b"abcdefgh");
        let bytes = p.to_bytes().to_vec();
        // A correct ICMP message sums to zero over header plus payload (RFC 792).
        assert_eq!(crate::checksum::ones_complement(&bytes[20..]), 0);
        assert_eq!(bytes[20], types::ECHO_REQUEST);
    }
}
