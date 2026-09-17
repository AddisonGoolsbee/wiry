//! RFC 792 gives every ICMPv4 message the same Type / Code / Checksum prefix;
//! what the four octets after it mean depends on the type, so those fields are
//! conditional:
//!
//! | Type          | Octets 4..8                          | Source        |
//! |---------------|--------------------------------------|---------------|
//! | 0, 8, 15, 16  | id, seq                              | RFC 792       |
//! | 13, 14        | id, seq, then 12 octets of timestamps | RFC 792 §3    |
//! | 17, 18        | id, seq, then a 4-octet address mask  | RFC 950 §2    |
//! | 5             | gw (gateway internet address)        | RFC 792       |
//! | 12            | ptr, length                          | RFC 792, 4884 |
//! | 3, 11         | reserved, length                     | RFC 792, 4884 |
//! | 3             | nexthopmtu at octets 6..8            | RFC 1191 §4   |
//! | 37, 38        | id, seq                              | RFC 1788 §3   |
//!
//! Type numbers from the IANA "ICMP Type Numbers" registry.

use crate::field::FieldDesc;
use crate::proto::{Next, ProtoDesc, ProtoId};

pub mod types {
    pub const ECHO_REPLY: u8 = 0;
    pub const DEST_UNREACH: u8 = 3;
    /// Deprecated by RFC 6633, still quoted back by older routers.
    pub const SOURCE_QUENCH: u8 = 4;
    pub const REDIRECT: u8 = 5;
    pub const ECHO_REQUEST: u8 = 8;
    pub const TIME_EXCEEDED: u8 = 11;
    pub const PARAM_PROBLEM: u8 = 12;
    pub const TIMESTAMP: u8 = 13;
    pub const TIMESTAMP_REPLY: u8 = 14;
    pub const INFO_REQUEST: u8 = 15;
    pub const INFO_REPLY: u8 = 16;
    pub const ADDR_MASK_REQUEST: u8 = 17;
    pub const ADDR_MASK_REPLY: u8 = 18;
    pub const DOMAIN_NAME_REQUEST: u8 = 37;
    pub const DOMAIN_NAME_REPLY: u8 = 38;
}

use types::*;

fn msg_type(hdr: &[u8]) -> u8 {
    hdr.first().copied().unwrap_or(ECHO_REQUEST)
}

/// Types RFC 792 and its successors give an identifier and sequence number.
const QUERY_TYPES: &[u8] = &[
    ECHO_REPLY,
    ECHO_REQUEST,
    TIMESTAMP,
    TIMESTAMP_REPLY,
    INFO_REQUEST,
    INFO_REPLY,
    ADDR_MASK_REQUEST,
    ADDR_MASK_REPLY,
    DOMAIN_NAME_REQUEST,
    DOMAIN_NAME_REPLY,
];

fn has_id_seq(hdr: &[u8]) -> bool {
    QUERY_TYPES.contains(&msg_type(hdr))
}

fn is_timestamp(hdr: &[u8]) -> bool {
    matches!(msg_type(hdr), TIMESTAMP | TIMESTAMP_REPLY)
}

fn is_addr_mask(hdr: &[u8]) -> bool {
    matches!(msg_type(hdr), ADDR_MASK_REQUEST | ADDR_MASK_REPLY)
}

fn is_redirect(hdr: &[u8]) -> bool {
    msg_type(hdr) == REDIRECT
}

fn is_param_problem(hdr: &[u8]) -> bool {
    msg_type(hdr) == PARAM_PROBLEM
}

/// Reserve octet 4 (RFC 792) and use octet 5 as the RFC 4884 extension length.
fn is_error(hdr: &[u8]) -> bool {
    matches!(msg_type(hdr), DEST_UNREACH | TIME_EXCEEDED)
}

fn has_ext_length(hdr: &[u8]) -> bool {
    is_error(hdr) || is_param_problem(hdr)
}

fn is_unreach(hdr: &[u8]) -> bool {
    msg_type(hdr) == DEST_UNREACH
}

fn is_unstructured(hdr: &[u8]) -> bool {
    !(has_id_seq(hdr) || is_redirect(hdr) || is_param_problem(hdr) || is_error(hdr))
}

/// RFC 4884 §7 puts the extension structure after the quoted datagram, which
/// this model treats as payload. The names are interface only.
fn never(_: &[u8]) -> bool {
    false
}

pub static FIELDS: &[FieldDesc] = &[
    FieldDesc::uint("type", 0, 8, ECHO_REQUEST as u64),
    FieldDesc::uint("code", 8, 8, 0),
    FieldDesc::computed_uint("chksum", 16, 16),
    FieldDesc::uint("id", 32, 16, 0).when(has_id_seq),
    FieldDesc::uint("seq", 48, 16, 0).when(has_id_seq),
    FieldDesc::uint("ts_ori", 64, 32, 0).when(is_timestamp),
    FieldDesc::uint("ts_rx", 96, 32, 0).when(is_timestamp),
    FieldDesc::uint("ts_tx", 128, 32, 0).when(is_timestamp),
    FieldDesc::ipv4("gw", 32, 0).when(is_redirect),
    FieldDesc::uint("ptr", 32, 8, 0).when(is_param_problem),
    FieldDesc::uint("reserved", 32, 8, 0).when(is_error),
    FieldDesc::uint("length", 40, 8, 0).when(has_ext_length),
    FieldDesc::ipv4("addr_mask", 64, 0).when(is_addr_mask),
    FieldDesc::uint("nexthopmtu", 48, 16, 0).when(is_unreach),
    FieldDesc::uint("unused", 32, 32, 0).when(is_unstructured),
    FieldDesc::var_bytes("extpad", 64).when(never),
    FieldDesc::var_bytes("ext", 64).when(never),
];

/// RFC 792 §3, RFC 950 §2: only timestamp and address-mask messages carry more
/// than the common eight octets.
fn header_len(hdr: &[u8]) -> usize {
    match msg_type(hdr) {
        TIMESTAMP | TIMESTAMP_REPLY => 20,
        ADDR_MASK_REQUEST | ADDR_MASK_REPLY => 12,
        _ => 8,
    }
}

/// Error messages quote the offending datagram, which is not dissected.
fn next(_: &[u8]) -> Next {
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
    parse_options: None,
    opt_table: None,
    set_hlen: None,
    bind_next: None,
    bind_next_bytes: None,
    content_len: None,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldValue;
    use crate::packet::Packet;

    /// RFC 792 Echo: id 0x1234, seq 1, 4-byte payload.
    fn echo_request() -> Vec<u8> {
        vec![
            0x08, 0x00, 0x48, 0x2d, 0x12, 0x34, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef,
        ]
    }

    #[test]
    fn dissects_echo_request_fields() {
        let p = Packet::dissect(echo_request(), ProtoId::Icmp);
        let i = p.find_layer(ProtoId::Icmp).unwrap();
        assert_eq!(p.get(i, "type").unwrap(), FieldValue::Uint(8));
        assert_eq!(p.get(i, "code").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(i, "chksum").unwrap(), FieldValue::Uint(0x482d));
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

    fn active(p: &Packet, layer: usize) -> Vec<&'static str> {
        crate::proto::active_fields(ProtoId::Icmp, p.header(layer))
            .map(|f| f.name)
            .collect()
    }

    #[test]
    fn echo_request_has_id_and_seq_only() {
        let p = Packet::dissect(echo_request(), ProtoId::Icmp);
        let i = p.find_layer(ProtoId::Icmp).unwrap();
        assert_eq!(active(&p, i), ["type", "code", "chksum", "id", "seq"]);
        for absent in [
            "gw",
            "ptr",
            "reserved",
            "length",
            "unused",
            "ts_ori",
            "addr_mask",
        ] {
            assert_eq!(p.get(i, absent), None, "{absent} should be absent");
        }
    }

    #[test]
    fn redirect_names_the_gateway() {
        // RFC 792 Redirect, code 1.
        let bytes = vec![0x05, 0x01, 0x00, 0x00, 10, 0, 0, 1];
        let p = Packet::dissect(bytes, ProtoId::Icmp);
        let i = p.find_layer(ProtoId::Icmp).unwrap();
        assert_eq!(active(&p, i), ["type", "code", "chksum", "gw"]);
        assert_eq!(p.get(i, "gw").unwrap(), FieldValue::Ipv4([10, 0, 0, 1]));
        assert_eq!(p.get(i, "id"), None);
        assert_eq!(p.get(i, "seq"), None);
        assert_eq!(p.header(i).len(), 8);
    }

    #[test]
    fn dest_unreach_names_length_and_nexthopmtu() {
        // Code 4: RFC 1191 puts the next-hop MTU in octets 6..8, RFC 4884 makes
        // octet 5 the extension length.
        let bytes = vec![0x03, 0x04, 0x00, 0x00, 0x00, 0x05, 0x05, 0xdc];
        let p = Packet::dissect(bytes, ProtoId::Icmp);
        let i = p.find_layer(ProtoId::Icmp).unwrap();
        assert_eq!(
            active(&p, i),
            ["type", "code", "chksum", "reserved", "length", "nexthopmtu"]
        );
        assert_eq!(p.get(i, "length").unwrap(), FieldValue::Uint(5));
        assert_eq!(p.get(i, "nexthopmtu").unwrap(), FieldValue::Uint(1500));
        assert_eq!(p.get(i, "id"), None);
        assert_eq!(p.get(i, "gw"), None);
        assert_eq!(p.get(i, "ptr"), None);
    }

    #[test]
    fn time_exceeded_has_no_nexthopmtu() {
        let bytes = vec![0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let p = Packet::dissect(bytes, ProtoId::Icmp);
        let i = p.find_layer(ProtoId::Icmp).unwrap();
        assert_eq!(
            active(&p, i),
            ["type", "code", "chksum", "reserved", "length"]
        );
        assert_eq!(p.get(i, "nexthopmtu"), None);
    }

    #[test]
    fn parameter_problem_names_the_pointer() {
        let bytes = vec![0x0c, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00];
        let p = Packet::dissect(bytes, ProtoId::Icmp);
        let i = p.find_layer(ProtoId::Icmp).unwrap();
        assert_eq!(active(&p, i), ["type", "code", "chksum", "ptr", "length"]);
        assert_eq!(p.get(i, "ptr").unwrap(), FieldValue::Uint(20));
        assert_eq!(p.get(i, "reserved"), None);
    }

    /// RFC 792 Timestamp: identifier, sequence, then three 32-bit timestamps.
    fn timestamp_message() -> Vec<u8> {
        let mut v = vec![0x0d, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x09];
        v.extend_from_slice(&0x0000_1000u32.to_be_bytes());
        v.extend_from_slice(&0x0000_2000u32.to_be_bytes());
        v.extend_from_slice(&0x0000_3000u32.to_be_bytes());
        v
    }

    #[test]
    fn timestamp_message_has_three_timestamps() {
        let p = Packet::dissect(timestamp_message(), ProtoId::Icmp);
        let i = p.find_layer(ProtoId::Icmp).unwrap();
        assert_eq!(p.header(i).len(), 20);
        assert_eq!(
            active(&p, i),
            ["type", "code", "chksum", "id", "seq", "ts_ori", "ts_rx", "ts_tx"]
        );
        assert_eq!(p.get(i, "id").unwrap(), FieldValue::Uint(7));
        assert_eq!(p.get(i, "seq").unwrap(), FieldValue::Uint(9));
        assert_eq!(p.get(i, "ts_ori").unwrap(), FieldValue::Uint(0x1000));
        assert_eq!(p.get(i, "ts_rx").unwrap(), FieldValue::Uint(0x2000));
        assert_eq!(p.get(i, "ts_tx").unwrap(), FieldValue::Uint(0x3000));
        assert_eq!(p.get(i, "gw"), None);
        assert_eq!(p.get(i, "addr_mask"), None);
        assert!(p.payload(i).is_empty());
    }

    #[test]
    fn address_mask_message_carries_a_mask() {
        // RFC 950 §2.
        let bytes = vec![
            0x11, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0xff, 0xff, 0xff, 0x00,
        ];
        let p = Packet::dissect(bytes, ProtoId::Icmp);
        let i = p.find_layer(ProtoId::Icmp).unwrap();
        assert_eq!(p.header(i).len(), 12);
        assert_eq!(
            p.get(i, "addr_mask").unwrap(),
            FieldValue::Ipv4([255, 255, 255, 0])
        );
        assert_eq!(p.get(i, "ts_ori"), None);
    }

    #[test]
    fn unstructured_type_names_the_four_octets_unused() {
        let bytes = vec![0x09, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04];
        let p = Packet::dissect(bytes, ProtoId::Icmp);
        let i = p.find_layer(ProtoId::Icmp).unwrap();
        assert_eq!(active(&p, i), ["type", "code", "chksum", "unused"]);
        assert_eq!(p.get(i, "unused").unwrap(), FieldValue::Uint(0x0102_0304));
    }

    #[test]
    fn extension_fields_never_decode_as_header_fields() {
        let bytes = vec![0x03, 0x04, 0x00, 0x00, 0x00, 0x05, 0x05, 0xdc];
        let p = Packet::dissect(bytes, ProtoId::Icmp);
        let i = p.find_layer(ProtoId::Icmp).unwrap();
        assert_eq!(p.get(i, "ext"), None);
        assert_eq!(p.get(i, "extpad"), None);
    }

    #[test]
    fn writing_an_absent_field_is_refused() {
        let mut p = Packet::dissect(echo_request(), ProtoId::Icmp);
        let i = p.find_layer(ProtoId::Icmp).unwrap();
        assert!(!p.set_uint(i, "gw", 0x0a00_0001));
        assert_eq!(p.get(i, "id").unwrap(), FieldValue::Uint(0x1234));
    }

    #[test]
    fn changing_type_changes_which_fields_exist() {
        let mut p = Packet::dissect(echo_request(), ProtoId::Icmp);
        let i = p.find_layer(ProtoId::Icmp).unwrap();
        assert!(p.set_uint(i, "type", types::REDIRECT as u64));
        assert_eq!(p.get(i, "id"), None);
        assert_eq!(
            p.get(i, "gw").unwrap(),
            FieldValue::Ipv4([0x12, 0x34, 0, 1])
        );
    }

    #[test]
    fn building_a_timestamp_grows_the_header() {
        let mut p = Packet::build(&[ProtoId::Icmp]);
        let i = 0;
        assert!(p.set_uint(i, "type", types::TIMESTAMP as u64));
        p.refit_headers();
        assert!(p.set_uint(i, "ts_ori", 0x1234_5678));
        assert_eq!(p.to_bytes().len(), 20);
        assert_eq!(p.get(i, "ts_ori").unwrap(), FieldValue::Uint(0x1234_5678));
    }

    #[test]
    fn short_input_does_not_panic() {
        for n in 0..8usize {
            let p = Packet::dissect(echo_request()[..n].to_vec(), ProtoId::Icmp);
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
        // RFC 792: a correct message sums to zero over header plus payload.
        assert_eq!(crate::checksum::ones_complement(&bytes[20..]), 0);
        assert_eq!(bytes[20], types::ECHO_REQUEST);
    }
}
