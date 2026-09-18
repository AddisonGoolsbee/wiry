//! Geneve from RFC 8926 §3.1: an 8-octet header over UDP port 6081 followed by
//! a variable option block, then a payload named by an EtherType from the IANA
//! "ETHER TYPES" registry.

use crate::field::FieldDesc;
use crate::proto::{ethertype, Next, ProtoDesc, ProtoId};

pub static FIELDS: &[FieldDesc] = &[
    FieldDesc::uint("version", 0, 2, 0),
    FieldDesc::computed_uint("optionlen", 2, 6),
    FieldDesc::uint("oam", 8, 1, 0),
    FieldDesc::uint("critical", 9, 1, 0),
    FieldDesc::uint("reserved", 10, 6, 0),
    FieldDesc::uint("proto", 16, 16, ethertype::TEB as u64),
    FieldDesc::uint("vni", 32, 24, 0),
    FieldDesc::uint("reserved2", 56, 8, 0),
    FieldDesc::var_bytes("options", 64),
];

/// RFC 8926 §3.1: Opt Len counts 4-octet units of the option block alone.
fn header_len(hdr: &[u8]) -> usize {
    match hdr.first() {
        Some(b) => 8 + (b & 0x3f) as usize * 4,
        None => 8,
    }
}

fn next(hdr: &[u8]) -> Next {
    if hdr.len() < 8 {
        return Next::Raw;
    }
    super::ether::from_ethertype(u16::from_be_bytes([hdr[2], hdr[3]]))
}

fn to_ethertype(p: ProtoId) -> Option<u16> {
    match p {
        ProtoId::Ether => Some(ethertype::TEB),
        other => super::ether::to_ethertype(other),
    }
}

fn bind_next(hdr: &mut [u8], p: ProtoId) {
    super::ether::bind_ethertype(hdr, 2, to_ethertype(p));
}

pub static DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Geneve,
    name: "GENEVE",
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
    content_len: None,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldValue;
    use crate::packet::Packet;
    use crate::proto::ports;

    fn over_udp(payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0x45, 0x00];
        v.extend_from_slice(&((28 + payload.len()) as u16).to_be_bytes());
        v.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x40, 17, 0x00, 0x00]);
        v.extend_from_slice(&[10, 0, 0, 1]);
        v.extend_from_slice(&[10, 0, 0, 2]);
        v.extend_from_slice(&[0xc0, 0x00]);
        v.extend_from_slice(&ports::GENEVE.to_be_bytes());
        v.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        v.extend_from_slice(&[0x00, 0x00]);
        v.extend_from_slice(payload);
        v
    }

    fn inner_frame() -> Vec<u8> {
        let mut v = vec![0xaa; 6];
        v.extend_from_slice(&[0xbb; 6]);
        v.extend_from_slice(&[0x08, 0x00]);
        v.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x14, 0x00, 0x02, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 192, 168, 1, 1,
            192, 168, 1, 2,
        ]);
        v
    }

    #[test]
    fn walks_past_a_variable_option_block() {
        // Opt Len 2 words: one option class 0x0102, type 1, 4 octets of data.
        let mut payload = vec![0x02, 0x00, 0x65, 0x58, 0x00, 0x0a, 0xbc, 0x00];
        payload.extend_from_slice(&[0x01, 0x02, 0x01, 0x01, 0xde, 0xad, 0xbe, 0xef]);
        payload.extend_from_slice(&inner_frame());
        let p = Packet::dissect(over_udp(&payload), ProtoId::Ipv4);
        assert_eq!(
            p.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![
                ProtoId::Ipv4,
                ProtoId::Udp,
                ProtoId::Geneve,
                ProtoId::Ether,
                ProtoId::Ipv4
            ]
        );
        assert_eq!(p.layers()[2].hlen, 16);
        assert_eq!(p.get(2, "optionlen").unwrap(), FieldValue::Uint(2));
        assert_eq!(p.get(2, "vni").unwrap(), FieldValue::Uint(0x000abc));
        assert_eq!(
            p.get(2, "options").unwrap(),
            FieldValue::Bytes(vec![0x01, 0x02, 0x01, 0x01, 0xde, 0xad, 0xbe, 0xef])
        );
        assert_eq!(p.get(4, "src").unwrap(), FieldValue::Ipv4([192, 168, 1, 1]));
    }

    #[test]
    fn a_datagram_payload_needs_no_inner_frame() {
        let mut payload = vec![0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00];
        payload.extend_from_slice(&inner_frame()[14..]);
        let p = Packet::dissect(over_udp(&payload), ProtoId::Ipv4);
        assert_eq!(
            p.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![ProtoId::Ipv4, ProtoId::Udp, ProtoId::Geneve, ProtoId::Ipv4]
        );
    }

    #[test]
    fn truncated_input_does_not_panic() {
        let mut payload = vec![0x02, 0x00, 0x65, 0x58, 0x00, 0x0a, 0xbc, 0x00];
        payload.extend_from_slice(&[0x01, 0x02, 0x01, 0x01, 0xde, 0xad, 0xbe, 0xef]);
        payload.extend_from_slice(&inner_frame());
        let full = over_udp(&payload);
        for cut in 0..full.len() {
            let mut p = Packet::dissect(full[..cut].to_vec(), ProtoId::Ipv4);
            assert_eq!(p.to_bytes(), &full[..cut]);
        }
        assert_eq!(next(&[0; 4]), Next::Raw);
        assert_eq!(header_len(&[]), 8);
    }

    #[test]
    fn an_option_block_resizes_the_header_and_its_length_field() {
        let mut p = Packet::build(&[
            ProtoId::Ipv4,
            ProtoId::Udp,
            ProtoId::Geneve,
            ProtoId::Ether,
            ProtoId::Ipv4,
        ]);
        assert_eq!(
            p.get(1, "dport").unwrap(),
            FieldValue::Uint(ports::GENEVE as u64)
        );
        assert_eq!(p.get(2, "proto").unwrap(), FieldValue::Uint(0x6558));
        assert!(p.set_bytes(
            2,
            "options",
            &[0x01, 0x02, 0x01, 0x01, 0xde, 0xad, 0xbe, 0xef]
        ));
        let bytes = p.to_bytes().to_vec();

        let back = Packet::dissect(bytes, ProtoId::Ipv4);
        assert_eq!(back.get(2, "optionlen").unwrap(), FieldValue::Uint(2));
        assert_eq!(back.layers()[2].hlen, 16);
        assert_eq!(
            back.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![
                ProtoId::Ipv4,
                ProtoId::Udp,
                ProtoId::Geneve,
                ProtoId::Ether,
                ProtoId::Ipv4
            ]
        );
    }
}
