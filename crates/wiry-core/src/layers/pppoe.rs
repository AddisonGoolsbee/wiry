//! PPPoE from RFC 2516 §4 and PPP framing from RFC 1661 §2. EtherType values
//! 0x8863 (Discovery) and 0x8864 (Session) come from the IANA "ETHER TYPES"
//! registry; PPP protocol numbers from the IANA "PPP DLL PROTOCOL NUMBERS"
//! registry.

use crate::field::FieldDesc;
use crate::proto::{fixed_len, raw_next, Next, ProtoDesc, ProtoId};

pub static FIELDS: &[FieldDesc] = &[
    FieldDesc::uint("version", 0, 4, 1),
    FieldDesc::uint("type", 4, 4, 1),
    FieldDesc::uint("code", 8, 8, 0),
    FieldDesc::uint("sessionid", 16, 16, 0),
    FieldDesc::computed_uint("len", 32, 16),
];

/// RFC 2516 §4: LENGTH covers the payload alone, so the datagram ends six
/// octets further on than it claims.
fn content_len(hdr: &[u8]) -> usize {
    match hdr.get(4..6) {
        Some(b) => 6 + u16::from_be_bytes([b[0], b[1]]) as usize,
        None => 0,
    }
}

/// RFC 2516 §4: a Session stage packet carries PPP; every other code is a
/// Discovery packet whose payload is a tag list.
fn session_next(hdr: &[u8]) -> Next {
    match hdr.get(1) {
        Some(0) => Next::Proto(ProtoId::Ppp),
        _ => Next::Raw,
    }
}

fn bind_next(hdr: &mut [u8], p: ProtoId) {
    if let (ProtoId::Ppp, Some(b)) = (p, hdr.get_mut(1)) {
        *b = 0;
    }
}

pub static DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Pppoe,
    name: "PPPoE",
    fields: FIELDS,
    min_len: 6,
    header_len: fixed_len,
    next: session_next,
    build_len: 6,
    parse_options: None,
    opt_table: None,
    set_hlen: None,
    bind_next: Some(bind_next),
    bind_next_bytes: None,
    content_len: Some(content_len),
};

pub static DISC_DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::PppoeDisc,
    name: "PPPoED",
    fields: FIELDS,
    min_len: 6,
    header_len: fixed_len,
    next: raw_next,
    build_len: 6,
    parse_options: None,
    opt_table: None,
    set_hlen: None,
    bind_next: None,
    bind_next_bytes: None,
    content_len: Some(content_len),
};

pub mod pppproto {
    pub const IPV4: u16 = 0x0021;
    pub const IPV6: u16 = 0x0057;
    pub const MPLS_UNICAST: u16 = 0x0281;
    pub const MPLS_MULTICAST: u16 = 0x0283;
}

/// RFC 1661 §2 allows a one-octet Protocol field, but RFC 2516 §4 forbids that
/// compression over PPPoE, which is the only framing this build reaches PPP
/// through, so the field is always two octets here.
pub static PPP_FIELDS: &[FieldDesc] = &[FieldDesc::uint("proto", 0, 16, pppproto::IPV4 as u64)];

fn ppp_next(hdr: &[u8]) -> Next {
    if hdr.len() < 2 {
        return Next::Raw;
    }
    match u16::from_be_bytes([hdr[0], hdr[1]]) {
        pppproto::IPV4 => Next::Proto(ProtoId::Ipv4),
        pppproto::IPV6 => Next::Proto(ProtoId::Ipv6),
        pppproto::MPLS_UNICAST | pppproto::MPLS_MULTICAST => Next::Proto(ProtoId::Mpls),
        _ => Next::Raw,
    }
}

fn ppp_bind_next(hdr: &mut [u8], p: ProtoId) {
    let v = match p {
        ProtoId::Ipv4 => pppproto::IPV4,
        ProtoId::Ipv6 => pppproto::IPV6,
        ProtoId::Mpls => pppproto::MPLS_UNICAST,
        _ => return,
    };
    if let Some(dst) = hdr.get_mut(0..2) {
        dst.copy_from_slice(&v.to_be_bytes());
    }
}

pub static PPP_DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Ppp,
    name: "PPP",
    fields: PPP_FIELDS,
    min_len: 2,
    header_len: fixed_len,
    next: ppp_next,
    build_len: 2,
    parse_options: None,
    opt_table: None,
    set_hlen: None,
    bind_next: Some(ppp_bind_next),
    bind_next_bytes: None,
    content_len: None,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldValue;
    use crate::packet::Packet;

    const IP20: &[u8] = &[
        0x45, 0x00, 0x00, 0x14, 0x00, 0x02, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 192, 168, 1, 1,
        192, 168, 1, 2,
    ];

    fn frame(etype: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        v.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        v.extend_from_slice(&etype.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    /// RFC 2516 §4: VER 1, TYPE 1, CODE 0x00 for a session packet.
    fn session(payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0x11, 0x00, 0x00, 0x07];
        v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn a_session_packet_reaches_the_datagram() {
        let mut ppp = vec![0x00, 0x21];
        ppp.extend_from_slice(IP20);
        let p = Packet::dissect(frame(0x8864, &session(&ppp)), ProtoId::Ether);
        assert_eq!(
            p.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![ProtoId::Ether, ProtoId::Pppoe, ProtoId::Ppp, ProtoId::Ipv4]
        );
        assert_eq!(p.get(1, "version").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(1, "sessionid").unwrap(), FieldValue::Uint(7));
        assert_eq!(p.get(1, "len").unwrap(), FieldValue::Uint(22));
        assert_eq!(p.get(2, "proto").unwrap(), FieldValue::Uint(0x0021));
        assert_eq!(p.get(3, "src").unwrap(), FieldValue::Ipv4([192, 168, 1, 1]));
    }

    #[test]
    fn a_discovery_packet_keeps_its_tag_list_as_raw() {
        // PADI, code 0x09, one Service-Name tag of zero length.
        let mut disc = vec![0x11, 0x09, 0x00, 0x00, 0x00, 0x04];
        disc.extend_from_slice(&[0x01, 0x01, 0x00, 0x00]);
        let p = Packet::dissect(frame(0x8863, &disc), ProtoId::Ether);
        assert_eq!(
            p.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![ProtoId::Ether, ProtoId::PppoeDisc, ProtoId::Raw]
        );
        assert_eq!(p.get(1, "code").unwrap(), FieldValue::Uint(9));
    }

    #[test]
    fn a_length_shorter_than_the_frame_leaves_a_trailer() {
        let mut ppp = vec![0x00, 0x21];
        ppp.extend_from_slice(IP20);
        let mut payload = session(&ppp);
        payload.extend_from_slice(&[0u8; 8]);
        let p = Packet::dissect(frame(0x8864, &payload), ProtoId::Ether);
        assert_eq!(p.layers().last().unwrap().proto, ProtoId::Padding);
        assert_eq!(p.layers().last().unwrap().hlen, 8);
    }

    #[test]
    fn truncated_input_does_not_panic() {
        let mut ppp = vec![0x00, 0x21];
        ppp.extend_from_slice(IP20);
        let full = frame(0x8864, &session(&ppp));
        for cut in 0..full.len() {
            let mut p = Packet::dissect(full[..cut].to_vec(), ProtoId::Ether);
            assert_eq!(p.to_bytes(), &full[..cut]);
        }
        assert_eq!(ppp_next(&[0x00]), Next::Raw);
        assert_eq!(session_next(&[]), Next::Raw);
        assert_eq!(content_len(&[0x11]), 0);
    }

    #[test]
    fn builds_a_session_that_dissects_back() {
        let mut p = Packet::build(&[
            ProtoId::Ether,
            ProtoId::Pppoe,
            ProtoId::Ppp,
            ProtoId::Ipv4,
            ProtoId::Udp,
        ]);
        assert_eq!(p.get(0, "type").unwrap(), FieldValue::Uint(0x8864));
        assert_eq!(p.get(1, "code").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(2, "proto").unwrap(), FieldValue::Uint(0x0021));
        let bytes = p.to_bytes().to_vec();

        let back = Packet::dissect(bytes, ProtoId::Ether);
        assert_eq!(
            back.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![
                ProtoId::Ether,
                ProtoId::Pppoe,
                ProtoId::Ppp,
                ProtoId::Ipv4,
                ProtoId::Udp
            ]
        );
        // RFC 2516 §4: the PPP header and everything under it.
        assert_eq!(back.get(1, "len").unwrap(), FieldValue::Uint(2 + 20 + 8));
    }
}
