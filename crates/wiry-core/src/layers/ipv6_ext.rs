//! IPv6 extension headers from RFC 8200 §4: Hop-by-Hop Options (§4.3),
//! Routing (§4.4), Fragment (§4.5) and Destination Options (§4.6). Next Header
//! values come from the IANA "Protocol Numbers" registry, option types from
//! "Destination Options and Hop-by-Hop Options".
//!
//! Each header carries the next one's protocol number, so the chain is walked
//! exactly the way the fixed header is: one span per header, ending at a
//! transport protocol. §4.1 recommends an order but does not require it, so
//! nothing here depends on the order it lists.

use crate::field::FieldDesc;
use crate::options::{Item, LenRule, OptDesc, OptTable, Shape};
use crate::proto::{Next, ProtoDesc, ProtoId};

use super::ipv6::next_header;
use crate::proto::fixed_len;

/// RFC 8200 §4.3: two fixed octets, then options out to the length the second
/// declares. Destination Options (§4.6) is the same layout under another
/// protocol number.
static OPT_FIELDS: &[FieldDesc] = &[
    FieldDesc::uint("nh", 0, 8, 59),
    FieldDesc::computed_uint("len", 8, 8),
    FieldDesc::var_bytes("options", 16),
];

/// RFC 8200 §4.3: Hdr Ext Len counts 8-octet units, not counting the first 8.
fn opt_header_len(hdr: &[u8]) -> usize {
    match hdr.get(1) {
        Some(n) => (*n as usize + 1) * 8,
        None => 8,
    }
}

fn nh_next(hdr: &[u8]) -> Next {
    match hdr.first() {
        Some(v) => next_header(*v),
        None => Next::Raw,
    }
}

fn nh_bind(hdr: &mut [u8], p: ProtoId) {
    if let (Some(v), Some(b)) = (super::ipv6::to_next_header(p), hdr.first_mut()) {
        *b = v;
    }
}

/// IANA "Destination Options and Hop-by-Hop Options" registry. RFC 8200 §4.2:
/// Pad1 is a lone octet; every other type carries a length octet counting only
/// its data.
pub static OPTIONS: OptTable = OptTable {
    proto: "IPv6ExtHdr",
    rule: LenRule::PayloadOnly,
    end: None,
    opts: &[
        OptDesc::new("Pad1", 0x00, Shape::Bare),
        OptDesc::new("PadN", 0x01, Shape::Bytes),
        // RFC 2675 §2.
        OptDesc::new("JumboPayload", 0xC2, Shape::Uint(4)),
        // RFC 2711 §2.1.
        OptDesc::new("RouterAlert", 0x05, Shape::Uint(2)),
        // RFC 6275 §6.3.
        OptDesc::new("HAO", 0xC9, Shape::Bytes),
        // RFC 7837 §3.
        OptDesc::new("PDM", 0x0F, Shape::Bytes),
    ],
};

fn parse_options(hdr: &[u8]) -> Vec<Item> {
    let end = opt_header_len(hdr).min(hdr.len());
    if end <= 2 {
        return Vec::new();
    }
    OPTIONS.walk(&hdr[2..end])
}

pub static HOP_BY_HOP_DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::HopByHop,
    name: "IPv6ExtHdrHopByHop",
    fields: OPT_FIELDS,
    min_len: 8,
    header_len: opt_header_len,
    next: nh_next,
    build_len: 8,
    parse_options: Some(parse_options),
    opt_table: Some(&OPTIONS),
    set_hlen: None,
    bind_next: Some(nh_bind),
    bind_next_bytes: None,
    content_len: None,
};

pub static DEST_OPT_DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::DestOpt,
    name: "IPv6ExtHdrDestOpt",
    fields: OPT_FIELDS,
    min_len: 8,
    header_len: opt_header_len,
    next: nh_next,
    build_len: 8,
    parse_options: Some(parse_options),
    opt_table: Some(&OPTIONS),
    set_hlen: None,
    bind_next: Some(nh_bind),
    bind_next_bytes: None,
    content_len: None,
};

/// RFC 8200 §4.4. Past Segments Left the layout is routing-type specific; the
/// names here are Type 0's, the only one the RFC itself lays out.
static ROUTING_FIELDS: &[FieldDesc] = &[
    FieldDesc::uint("nh", 0, 8, 59),
    FieldDesc::computed_uint("len", 8, 8),
    FieldDesc::uint("type", 16, 8, 0),
    FieldDesc::uint("segleft", 24, 8, 0),
    FieldDesc::uint("reserved", 32, 32, 0),
    FieldDesc::var_bytes("addresses", 64),
];

pub static ROUTING_DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Routing,
    name: "IPv6ExtHdrRouting",
    fields: ROUTING_FIELDS,
    min_len: 8,
    header_len: opt_header_len,
    next: nh_next,
    build_len: 8,
    parse_options: None,
    opt_table: None,
    set_hlen: None,
    bind_next: Some(nh_bind),
    bind_next_bytes: None,
    content_len: None,
};

/// RFC 8200 §4.5: a fixed 8 octets.
static FRAGMENT_FIELDS: &[FieldDesc] = &[
    FieldDesc::uint("nh", 0, 8, 59),
    FieldDesc::uint("res1", 8, 8, 0),
    FieldDesc::uint("offset", 16, 13, 0),
    FieldDesc::uint("res2", 29, 2, 0),
    FieldDesc::uint("m", 31, 1, 0),
    FieldDesc::uint("id", 32, 32, 0),
];

fn fragment_next(hdr: &[u8]) -> Next {
    if hdr.len() < 8 {
        return Next::Raw;
    }
    // Only the first fragment carries the header Next Header names; the rest is
    // payload, as it is for a fragmented IPv4 datagram.
    if u16::from_be_bytes([hdr[2], hdr[3]]) & 0xfff8 != 0 {
        return Next::Raw;
    }
    next_header(hdr[0])
}

pub static FRAGMENT_DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Fragment,
    name: "IPv6ExtHdrFragment",
    fields: FRAGMENT_FIELDS,
    min_len: 8,
    header_len: fixed_len,
    next: fragment_next,
    build_len: 8,
    parse_options: None,
    opt_table: None,
    set_hlen: None,
    bind_next: Some(nh_bind),
    bind_next_bytes: None,
    content_len: None,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldValue;
    use crate::options::ItemValue;
    use crate::packet::Packet;
    use crate::proto::ipproto;

    const SRC: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    const DST: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
    ];

    fn ipv6(nh: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0x60, 0, 0, 0];
        v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        v.push(nh);
        v.push(64);
        v.extend_from_slice(&SRC);
        v.extend_from_slice(&DST);
        v.extend_from_slice(payload);
        v
    }

    const UDP8: &[u8] = &[0x30, 0x39, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00];

    /// RFC 2711 §2.1 Router Alert (value 0, MLD), then PadN to fill the
    /// 8-octet unit RFC 8200 §4.3 requires.
    fn hop_by_hop(nh: u8) -> Vec<u8> {
        vec![nh, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x00]
    }

    #[test]
    fn walks_a_hop_by_hop_header_to_the_transport() {
        let mut payload = hop_by_hop(ipproto::UDP);
        payload.extend_from_slice(UDP8);
        let p = Packet::dissect(ipv6(ipproto::HOPOPT, &payload), ProtoId::Ipv6);
        assert_eq!(
            p.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![ProtoId::Ipv6, ProtoId::HopByHop, ProtoId::Udp]
        );
        assert_eq!(p.get(1, "nh").unwrap(), FieldValue::Uint(17));
        assert_eq!(p.get(1, "len").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.layers()[1].hlen, 8);
        assert_eq!(p.get(2, "dport").unwrap(), FieldValue::Uint(53));
        assert_eq!(
            p.options(1).unwrap(),
            vec![
                Item::uint("RouterAlert", 5, 0),
                Item::named("PadN", 1, ItemValue::Bytes(vec![])),
            ]
        );
    }

    #[test]
    fn walks_a_chain_of_four_headers() {
        let mut payload = hop_by_hop(ipproto::IPV6_ROUTE);
        // RFC 8200 §4.4 Type 0, one address, segments left 1.
        payload.extend_from_slice(&[ipproto::IPV6_FRAG, 0x02, 0x00, 0x01, 0, 0, 0, 0]);
        payload.extend_from_slice(&SRC);
        // RFC 8200 §4.5: offset 0, M set, so the transport header is here.
        payload.extend_from_slice(&[ipproto::IPV6_OPTS, 0x00, 0x00, 0x01, 0, 0, 0, 7]);
        payload.extend_from_slice(&[ipproto::UDP, 0x00, 0x01, 0x04, 0, 0, 0, 0]);
        payload.extend_from_slice(UDP8);

        let p = Packet::dissect(ipv6(ipproto::HOPOPT, &payload), ProtoId::Ipv6);
        assert_eq!(
            p.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![
                ProtoId::Ipv6,
                ProtoId::HopByHop,
                ProtoId::Routing,
                ProtoId::Fragment,
                ProtoId::DestOpt,
                ProtoId::Udp,
            ]
        );
        assert_eq!(p.get(2, "type").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(2, "segleft").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.layers()[2].hlen, 24);
        assert_eq!(p.get(3, "m").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(3, "id").unwrap(), FieldValue::Uint(7));
        assert_eq!(p.get(4, "nh").unwrap(), FieldValue::Uint(17));
    }

    #[test]
    fn a_later_fragment_carries_no_transport_header() {
        // Offset 185 octets (23 eight-octet units), M clear.
        let mut payload = vec![ipproto::UDP, 0x00, 0x00, 0xb8, 0, 0, 0, 7];
        payload.extend_from_slice(UDP8);
        let p = Packet::dissect(ipv6(ipproto::IPV6_FRAG, &payload), ProtoId::Ipv6);
        assert_eq!(
            p.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![ProtoId::Ipv6, ProtoId::Fragment, ProtoId::Raw]
        );
        assert_eq!(p.get(1, "offset").unwrap(), FieldValue::Uint(23));
    }

    #[test]
    fn a_self_referential_chain_terminates() {
        let mut payload = Vec::new();
        for _ in 0..200 {
            payload.extend_from_slice(&[ipproto::IPV6_OPTS, 0, 0, 0, 0, 0, 0, 0]);
        }
        let p = Packet::dissect(ipv6(ipproto::IPV6_OPTS, &payload), ProtoId::Ipv6);
        assert!(p.layers().len() <= 33, "{} layers", p.layers().len());
        assert!(p.layers().iter().all(|s| s.total > 0));
    }

    #[test]
    fn truncated_headers_do_not_panic() {
        let mut payload = hop_by_hop(ipproto::UDP);
        payload.extend_from_slice(UDP8);
        let full = ipv6(ipproto::HOPOPT, &payload);
        for cut in 0..full.len() {
            let mut p = Packet::dissect(full[..cut].to_vec(), ProtoId::Ipv6);
            assert_eq!(p.to_bytes(), &full[..cut]);
        }
        assert_eq!(nh_next(&[]), Next::Raw);
        assert_eq!(fragment_next(&[1, 2, 3]), Next::Raw);
        assert_eq!(opt_header_len(&[]), 8);
    }

    #[test]
    fn builds_a_chain_and_reads_it_back() {
        let mut p = Packet::build(&[
            ProtoId::Ipv6,
            ProtoId::HopByHop,
            ProtoId::Fragment,
            ProtoId::Udp,
        ]);
        assert_eq!(
            p.get(0, "nh").unwrap(),
            FieldValue::Uint(ipproto::HOPOPT as u64)
        );
        assert_eq!(
            p.get(1, "nh").unwrap(),
            FieldValue::Uint(ipproto::IPV6_FRAG as u64)
        );
        assert_eq!(
            p.get(2, "nh").unwrap(),
            FieldValue::Uint(ipproto::UDP as u64)
        );
        let bytes = p.to_bytes().to_vec();
        assert_eq!(bytes.len(), 40 + 8 + 8 + 8);

        let back = Packet::dissect(bytes, ProtoId::Ipv6);
        assert_eq!(
            back.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![
                ProtoId::Ipv6,
                ProtoId::HopByHop,
                ProtoId::Fragment,
                ProtoId::Udp
            ]
        );
        // RFC 8200 §3: everything after the fixed header, extension headers
        // included.
        assert_eq!(back.get(0, "plen").unwrap(), FieldValue::Uint(24));
    }

    #[test]
    fn an_option_block_resizes_the_header_and_its_length_field() {
        let mut p = Packet::build(&[ProtoId::Ipv6, ProtoId::DestOpt, ProtoId::Udp]);
        // Router Alert plus PadN, filling a second 8-octet unit.
        let opts = OPTIONS
            .build(&[
                ("RouterAlert", crate::options::OptArg::Uint(0)),
                ("PadN", crate::options::OptArg::Bytes(vec![0; 8])),
            ])
            .unwrap();
        assert_eq!(opts.len(), 14);
        assert!(p.set_bytes(1, "options", &opts));
        let bytes = p.to_bytes().to_vec();
        assert_eq!(bytes.len(), 40 + 16 + 8);

        let back = Packet::dissect(bytes, ProtoId::Ipv6);
        assert_eq!(back.get(1, "len").unwrap(), FieldValue::Uint(1));
        assert_eq!(back.layers()[1].hlen, 16);
        assert_eq!(back.layers()[2].proto, ProtoId::Udp);
    }
}
