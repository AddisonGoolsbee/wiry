//! GTP-U from 3GPP TS 29.281 §5: an 8-octet header over UDP port 2152, which
//! grows by four octets when any of the E, S or PN flags is set and by a chain
//! of extension headers after that.

use crate::field::FieldDesc;
use crate::proto::{Next, ProtoDesc, ProtoId};

/// TS 29.281 §5.1: the sequence number, N-PDU number and next-extension octets
/// are present together or not at all, whichever of the three flags asked for
/// them.
fn has_opt(hdr: &[u8]) -> bool {
    hdr.first().is_some_and(|b| b & 0x07 != 0)
}

/// TS 29.281 §5.1 table 5.1-1: G-PDU carries the user's datagram; every other
/// message type is signalling.
const G_PDU: u8 = 0xff;

pub static FIELDS: &[FieldDesc] = &[
    FieldDesc::uint("version", 0, 3, 1),
    FieldDesc::uint("PT", 3, 1, 1),
    FieldDesc::uint("reserved", 4, 1, 0),
    FieldDesc::uint("E", 5, 1, 0),
    FieldDesc::uint("S", 6, 1, 0),
    FieldDesc::uint("PN", 7, 1, 0),
    FieldDesc::uint("gtp_type", 8, 8, G_PDU as u64),
    FieldDesc::computed_uint("length", 16, 16),
    FieldDesc::uint("teid", 32, 32, 0),
    FieldDesc::uint("seq", 64, 16, 0).when(has_opt),
    FieldDesc::uint("npdu", 80, 8, 0).when(has_opt),
    FieldDesc::uint("next_ex", 88, 8, 0).when(has_opt),
];

/// Bounds the extension-header walk; TS 29.281 §5.2 defines no limit, so an
/// adversarial chain is only stopped by the buffer running out.
const MAX_EXT: usize = 32;

fn header_len(hdr: &[u8]) -> usize {
    if !has_opt(hdr) {
        return 8;
    }
    let mut at = 12;
    // TS 29.281 §5.2.1: an extension header opens with a length in 4-octet
    // units covering that octet, the content, and the type of the one that
    // follows, which is its last octet.
    let mut next = hdr.get(11).copied().unwrap_or(0);
    for _ in 0..MAX_EXT {
        if next == 0 {
            break;
        }
        let Some(&units) = hdr.get(at) else { break };
        if units == 0 {
            break;
        }
        let end = at + units as usize * 4;
        if end > hdr.len() {
            // Clipped mid-chain: the rest of what arrived is this header, so
            // nothing after it is read as a datagram that is not there.
            return hdr.len();
        }
        next = hdr[end - 1];
        at = end;
    }
    at
}

/// TS 29.281 §5.1: Length counts everything after the first eight octets, the
/// optional fields and extension headers included.
fn content_len(hdr: &[u8]) -> usize {
    match hdr.get(2..4) {
        Some(b) => 8 + u16::from_be_bytes([b[0], b[1]]) as usize,
        None => 0,
    }
}

/// A T-PDU is an IP datagram with nothing naming its version but the first
/// nibble, the same signal MPLS has to rely on.
fn next(hdr: &[u8]) -> Next {
    if hdr.get(1) != Some(&G_PDU) {
        return Next::Raw;
    }
    super::ipv4::from_ip_version(hdr.get(header_len(hdr))).unwrap_or(Next::Raw)
}

pub static DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::GtpU,
    name: "GTP_U_Header",
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
    content_len: Some(content_len),
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldValue;
    use crate::packet::Packet;
    use crate::proto::ports;

    const IP20: &[u8] = &[
        0x45, 0x00, 0x00, 0x14, 0x00, 0x02, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 192, 168, 1, 1,
        192, 168, 1, 2,
    ];

    fn over_udp(dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0x45, 0x00];
        v.extend_from_slice(&((28 + payload.len()) as u16).to_be_bytes());
        v.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x40, 17, 0x00, 0x00]);
        v.extend_from_slice(&[10, 0, 0, 1]);
        v.extend_from_slice(&[10, 0, 0, 2]);
        v.extend_from_slice(&[0xc0, 0x00]);
        v.extend_from_slice(&dport.to_be_bytes());
        v.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        v.extend_from_slice(&[0x00, 0x00]);
        v.extend_from_slice(payload);
        v
    }

    /// Version 1, PT 1 (GTP), no optional fields: flags 0x30.
    fn gpdu(flags: u8, extra: &[u8]) -> Vec<u8> {
        let mut v = vec![0x30 | flags, G_PDU];
        v.extend_from_slice(&((extra.len() + IP20.len()) as u16).to_be_bytes());
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x05]);
        v.extend_from_slice(extra);
        v.extend_from_slice(IP20);
        v
    }

    #[test]
    fn a_bare_g_pdu_reaches_the_datagram() {
        let p = Packet::dissect(over_udp(ports::GTP_U, &gpdu(0, &[])), ProtoId::Ipv4);
        assert_eq!(
            p.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![ProtoId::Ipv4, ProtoId::Udp, ProtoId::GtpU, ProtoId::Ipv4]
        );
        assert_eq!(p.layers()[2].hlen, 8);
        assert_eq!(p.get(2, "teid").unwrap(), FieldValue::Uint(5));
        assert_eq!(p.get(2, "version").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(2, "seq"), None, "no flag asked for it");
        assert_eq!(p.get(3, "src").unwrap(), FieldValue::Ipv4([192, 168, 1, 1]));
    }

    #[test]
    fn a_sequence_number_adds_four_octets() {
        // S set; sequence 0x1234, no N-PDU number, no extension.
        let p = Packet::dissect(
            over_udp(ports::GTP_U, &gpdu(0x02, &[0x12, 0x34, 0x00, 0x00])),
            ProtoId::Ipv4,
        );
        assert_eq!(p.layers()[2].hlen, 12);
        assert_eq!(p.get(2, "seq").unwrap(), FieldValue::Uint(0x1234));
        assert_eq!(p.layers()[3].proto, ProtoId::Ipv4);
    }

    #[test]
    fn extension_headers_are_walked_to_the_datagram() {
        // E set, next extension 0x85 (PDU session container), one 4-octet unit
        // whose own next-extension octet is 0.
        let extra = [0x00, 0x00, 0x00, 0x85, 0x01, 0x00, 0x00, 0x00];
        let p = Packet::dissect(over_udp(ports::GTP_U, &gpdu(0x04, &extra)), ProtoId::Ipv4);
        assert_eq!(p.layers()[2].hlen, 16);
        assert_eq!(p.get(2, "next_ex").unwrap(), FieldValue::Uint(0x85));
        assert_eq!(p.layers()[3].proto, ProtoId::Ipv4);
        assert_eq!(p.get(3, "src").unwrap(), FieldValue::Ipv4([192, 168, 1, 1]));
    }

    #[test]
    fn a_self_referential_extension_chain_terminates() {
        let mut extra = vec![0x00, 0x00, 0x00, 0x85];
        for _ in 0..200 {
            extra.extend_from_slice(&[0x01, 0x00, 0x00, 0x85]);
        }
        let full = over_udp(ports::GTP_U, &gpdu(0x04, &extra));
        let mut p = Packet::dissect(full.clone(), ProtoId::Ipv4);
        assert!(p.layers()[2].hlen <= p.layers()[2].total);
        assert_eq!(p.to_bytes(), &full[..]);
    }

    #[test]
    fn a_signalling_message_is_not_a_datagram() {
        // Echo Request, type 1, carrying a two-octet Recovery IE.
        let mut msg = vec![0x30, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00];
        msg.extend_from_slice(&[0x0e, 0x00]);
        let p = Packet::dissect(over_udp(ports::GTP_U, &msg), ProtoId::Ipv4);
        assert_eq!(p.layers()[2].proto, ProtoId::GtpU);
        assert_eq!(p.layers()[3].proto, ProtoId::Raw);
        assert_eq!(p.get(2, "gtp_type").unwrap(), FieldValue::Uint(1));
    }

    #[test]
    fn truncated_input_does_not_panic() {
        let extra = [0x00, 0x00, 0x00, 0x85, 0x01, 0x00, 0x00, 0x00];
        let full = over_udp(ports::GTP_U, &gpdu(0x04, &extra));
        for cut in 0..full.len() {
            let mut p = Packet::dissect(full[..cut].to_vec(), ProtoId::Ipv4);
            assert_eq!(p.to_bytes(), &full[..cut]);
        }
        assert_eq!(next(&[0x30]), Next::Raw);
        assert_eq!(header_len(&[]), 8);
        assert_eq!(content_len(&[0x30]), 0);
    }

    #[test]
    fn builds_a_tunnel_whose_length_field_is_recomputed() {
        let mut p = Packet::build(&[
            ProtoId::Ipv4,
            ProtoId::Udp,
            ProtoId::GtpU,
            ProtoId::Ipv4,
            ProtoId::Udp,
        ]);
        assert_eq!(
            p.get(1, "dport").unwrap(),
            FieldValue::Uint(ports::GTP_U as u64)
        );
        assert!(p.set_uint(2, "teid", 0xdead_beef));
        let bytes = p.to_bytes().to_vec();

        let back = Packet::dissect(bytes, ProtoId::Ipv4);
        assert_eq!(
            back.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![
                ProtoId::Ipv4,
                ProtoId::Udp,
                ProtoId::GtpU,
                ProtoId::Ipv4,
                ProtoId::Udp
            ]
        );
        assert_eq!(back.get(2, "length").unwrap(), FieldValue::Uint(28));
        assert_eq!(back.get(2, "teid").unwrap(), FieldValue::Uint(0xdead_beef));
    }
}
