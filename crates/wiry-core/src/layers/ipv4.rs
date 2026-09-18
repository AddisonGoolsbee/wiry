//! IPv4 header layout from RFC 791 §3.1; protocol numbers from the IANA
//! "Protocol Numbers" registry.

use crate::field::FieldDesc;
use crate::options::{Item, LenRule, OptDesc, OptTable, Shape};
use crate::proto::{ipproto, Next, ProtoDesc, ProtoId};

/// RFC 791 §3.1 lists the 3 bits most significant first; this table is
/// least-significant first, as `FieldDesc::flags` expects.
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
    FieldDesc::uint("proto", 72, 8, 0),
    FieldDesc::computed_uint("chksum", 80, 16),
    FieldDesc::ipv4("src", 96, 0x7f00_0001),
    FieldDesc::ipv4("dst", 128, 0x7f00_0001),
    FieldDesc::var_bytes("options", 160),
];

fn header_len(hdr: &[u8]) -> usize {
    if hdr.is_empty() {
        return 20;
    }
    // RFC 791 §3.1: IHL counts 32-bit words and is at least 5.
    ((hdr[0] & 0x0f) as usize * 4).max(20)
}

/// RFC 791 §3.1: Total Length covers the header and its data, so anything
/// beyond it is a trailer, not part of this datagram.
fn content_len(hdr: &[u8]) -> usize {
    if hdr.len() < 4 {
        return 0;
    }
    u16::from_be_bytes([hdr[2], hdr[3]]) as usize
}

/// The protocol numbers both IP versions share. The IPv6 extension headers are
/// added on top of this by `ipv6::next_header` and `ipv6::to_next_header`;
/// protocol 0 is HOPOPT, which is IPv6-only and also the value an unbound IPv4
/// header carries, so reading it here would give every such datagram a header
/// it does not have.
pub fn from_ipproto(v: u8) -> Next {
    match v {
        ipproto::TCP => Next::Proto(ProtoId::Tcp),
        ipproto::UDP => Next::Proto(ProtoId::Udp),
        ipproto::ICMP => Next::Proto(ProtoId::Icmp),
        ipproto::IPV6_ICMP => Next::Proto(ProtoId::Icmpv6),
        ipproto::IPV4 => Next::Proto(ProtoId::Ipv4),
        ipproto::IPV6 => Next::Proto(ProtoId::Ipv6),
        ipproto::GRE => Next::Proto(ProtoId::Gre),
        n => match crate::layers::dispatch::by_ipproto(n) {
            Some(p) => Next::Proto(p),
            None => Next::Raw,
        },
    }
}

/// The inverse, symmetric with it: the extension headers `from_ipproto` refuses
/// to read are added back by `ipv6::to_next_header`, for the headers entitled to
/// name one. RFC 2003 §3 tunnels IPv4 and RFC 4213 §3 tunnels IPv6, whichever
/// version encloses them.
pub fn to_ipproto(p: ProtoId) -> Option<u8> {
    Some(match p {
        ProtoId::Tcp => ipproto::TCP,
        ProtoId::Udp => ipproto::UDP,
        ProtoId::Icmp => ipproto::ICMP,
        ProtoId::Icmpv6 => ipproto::IPV6_ICMP,
        ProtoId::Ipv4 => ipproto::IPV4,
        ProtoId::Ipv6 => ipproto::IPV6,
        ProtoId::Gre => ipproto::GRE,
        _ => return crate::layers::dispatch::by_ipproto_of(p),
    })
}

/// RFC 4385 §3: where nothing names the payload's protocol, an IP version in
/// the first nibble is the only signal, and it is one precisely because a
/// pseudowire control word is defined never to look like it. `None` means "not
/// an IP datagram", which each tunnel resolves its own way.
pub fn from_ip_version(first: Option<&u8>) -> Option<Next> {
    match first? >> 4 {
        4 => Some(Next::Proto(ProtoId::Ipv4)),
        6 => Some(Next::Proto(ProtoId::Ipv6)),
        _ => None,
    }
}

fn next(hdr: &[u8]) -> Next {
    if hdr.len() < 20 {
        return Next::Raw;
    }
    // A later fragment carries no transport header.
    let frag_off = u16::from_be_bytes([hdr[6], hdr[7]]) & 0x1fff;
    if frag_off != 0 {
        return Next::Raw;
    }
    from_ipproto(hdr[9])
}

fn bind_next(hdr: &mut [u8], p: ProtoId) {
    if let (Some(v), Some(b)) = (to_ipproto(p), hdr.get_mut(9)) {
        *b = v;
    }
}

/// IANA "IP OPTION NUMBERS" registry. RFC 791 §3.1 packs the type octet as
/// copied(1) | class(2) | number(5), but the registry — and this table — index
/// by the whole octet, so Router Alert is 148, not class 0 number 20.
pub mod opttype {
    pub const EOL: u8 = 0;
    pub const NOP: u8 = 1;
    pub const RR: u8 = 7;
    pub const TIMESTAMP: u8 = 68;
    pub const SECURITY: u8 = 130;
    pub const LSRR: u8 = 131;
    pub const SID: u8 = 136;
    pub const SSRR: u8 = 137;
    pub const RA: u8 = 148;
}

/// RFC 791 §3.1: types 0 and 1 are a single octet with no length field.
pub static OPTIONS: OptTable = OptTable {
    proto: "IP",
    rule: LenRule::WithHeader,
    end: Some(opttype::EOL),
    opts: &[
        OptDesc::new("EOL", opttype::EOL, Shape::Bare),
        OptDesc::new("NOP", opttype::NOP, Shape::Bare),
        OptDesc::new("RR", opttype::RR, Shape::Bytes),
        OptDesc::new("Timestamp", opttype::TIMESTAMP, Shape::Bytes),
        OptDesc::new("Security", opttype::SECURITY, Shape::Bytes),
        OptDesc::new("LSRR", opttype::LSRR, Shape::Bytes),
        OptDesc::new("SID", opttype::SID, Shape::Uint(2)),
        OptDesc::new("SSRR", opttype::SSRR, Shape::Bytes),
        OptDesc::new("RA", opttype::RA, Shape::Uint(2)),
    ],
};

fn parse_options(hdr: &[u8]) -> Vec<Item> {
    let end = header_len(hdr).min(hdr.len());
    if end <= 20 {
        return Vec::new();
    }
    OPTIONS.walk(&hdr[20..end])
}

/// RFC 791 §3.1: IHL counts 32-bit words.
fn set_hlen(hdr: &mut [u8], len: usize) {
    if !hdr.is_empty() {
        hdr[0] = (hdr[0] & 0xf0) | (((len / 4) as u8) & 0x0f);
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
    parse_options: Some(parse_options),
    opt_table: Some(&OPTIONS),
    set_hlen: Some(set_hlen),
    bind_next: Some(bind_next),
    bind_next_bytes: None,
    content_len: Some(content_len),
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldValue;
    use crate::options::{ItemValue, OptArg};
    use crate::packet::Packet;

    /// RFC 2113 §2.1 Router Alert, padded to a word with EOL.
    const RA_OPTS: &[u8] = &[0x94, 0x04, 0x00, 0x00];

    /// RFC 791 §3.1 Record Route: type, length 11, pointer 8, route data, EOL.
    const RR_OPTS: &[u8] = &[0x07, 0x0b, 0x08, 10, 0, 0, 1, 0, 0, 0, 0, 0x00];

    fn ip_hdr(opts: &[u8], payload_len: usize) -> Vec<u8> {
        assert_eq!(opts.len() % 4, 0, "option block must fill whole words");
        let ihl = ((20 + opts.len()) / 4) as u8;
        let total = (20 + opts.len() + payload_len) as u16;
        let mut v = vec![0x40 | ihl, 0x00];
        v.extend_from_slice(&total.to_be_bytes());
        v.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        v.extend_from_slice(&[0x40, ipproto::TCP, 0x00, 0x00]);
        v.extend_from_slice(&[10, 0, 0, 1]);
        v.extend_from_slice(&[10, 0, 0, 2]);
        v.extend_from_slice(opts);
        v
    }

    const TCP20: &[u8] = &[
        0x1f, 0x90, 0x00, 0x50, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0x20, 0x00, 0, 0, 0, 0,
    ];

    fn frame(opts: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        v.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        v.extend_from_slice(&[0x08, 0x00]);
        v.extend_from_slice(&ip_hdr(opts, TCP20.len()));
        v.extend_from_slice(TCP20);
        v
    }

    #[test]
    fn decodes_router_alert() {
        let p = Packet::dissect(frame(RA_OPTS), ProtoId::Ether);
        let ip = p.find_layer(ProtoId::Ipv4).expect("ipv4 layer");
        assert_eq!(p.get(ip, "ihl").unwrap(), FieldValue::Uint(6));
        assert_eq!(p.header(ip).len(), 24);
        let items = p.options(ip).expect("ipv4 has an option region");
        assert_eq!(items, vec![Item::uint("RA", 148, 0)]);
        assert_eq!(
            p.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![ProtoId::Ether, ProtoId::Ipv4, ProtoId::Tcp]
        );
    }

    #[test]
    fn decodes_record_route() {
        let p = Packet::dissect(frame(RR_OPTS), ProtoId::Ether);
        let ip = p.find_layer(ProtoId::Ipv4).unwrap();
        assert_eq!(p.get(ip, "ihl").unwrap(), FieldValue::Uint(8));
        assert_eq!(p.header(ip).len(), 32);
        let items = p.options(ip).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name.as_ref(), "RR");
        assert_eq!(items[0].code, 7);
        assert_eq!(
            items[0].value,
            ItemValue::Bytes(vec![0x08, 10, 0, 0, 1, 0, 0, 0, 0])
        );
        let tcp = p.find_layer(ProtoId::Tcp).expect("tcp still found");
        assert_eq!(p.get(tcp, "dport").unwrap(), FieldValue::Uint(80));
    }

    #[test]
    fn decodes_the_remaining_named_types() {
        let opts = &[
            0x83, 0x07, 0x04, 10, 0, 0, 9, 0x89, 0x07, 0x04, 10, 0, 0, 8, 0x82, 0x0b, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0x88, 0x04, 0x12, 0x34, 0x44, 0x08, 0x05, 0x00, 0xaa, 0xbb, 0xcc, 0xdd,
            0x01, 0x01, 0x01,
        ];
        let items = parse_options(&ip_hdr(opts, 0));
        let got: Vec<_> = items.iter().map(|i| (i.name.as_ref(), i.code)).collect();
        assert_eq!(
            got,
            vec![
                ("LSRR", 131),
                ("SSRR", 137),
                ("Security", 130),
                ("SID", 136),
                ("Timestamp", 68),
                ("NOP", 1),
                ("NOP", 1),
                ("NOP", 1),
            ]
        );
        assert_eq!(items[0].value, ItemValue::Bytes(vec![0x04, 10, 0, 0, 9]));
        assert_eq!(items[3].value, ItemValue::Uint(0x1234));
        assert_eq!(
            items[4].value,
            ItemValue::Bytes(vec![0x05, 0x00, 0xaa, 0xbb, 0xcc, 0xdd])
        );
    }

    #[test]
    fn encodes_router_alert_and_record_route() {
        assert_eq!(
            OPTIONS.build(&[("RA", OptArg::Uint(0))]).unwrap(),
            vec![0x94, 0x04, 0x00, 0x00]
        );
        let rr = OPTIONS
            .build(&[("RR", OptArg::Bytes(vec![0x08, 10, 0, 0, 1, 0, 0, 0, 0]))])
            .unwrap();
        assert_eq!(rr, RR_OPTS[..11]);
    }

    #[test]
    fn single_byte_types_carry_no_length_octet() {
        let got = OPTIONS
            .build(&[("NOP", OptArg::Flag), ("EOL", OptArg::Flag)])
            .unwrap();
        assert_eq!(got, vec![1, 0]);
    }

    #[test]
    fn a_decimal_name_encodes_as_that_type() {
        let got = OPTIONS
            .build(&[("82", OptArg::Bytes(vec![0xaa, 0xbb]))])
            .unwrap();
        assert_eq!(got, vec![0x52, 0x04, 0xaa, 0xbb]);
        assert!(OPTIONS.build(&[("NoSuchOption", OptArg::Uint(1))]).is_err());
    }

    #[test]
    fn unknown_type_does_not_abort_the_walk() {
        let opts = &[
            0x1e, 0x04, 0xde, 0xad, // unassigned type 30
            0x94, 0x04, 0x00, 0x00,
        ];
        let items = parse_options(&ip_hdr(opts, 0));
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].code, 30);
        assert_eq!(items[0].name.as_ref(), "30");
        assert_eq!(items[0].value, ItemValue::Bytes(vec![0xde, 0xad]));
        assert_eq!(items[1].name.as_ref(), "RA");
    }

    #[test]
    fn truncated_option_region_stops_cleanly() {
        let full = frame(RR_OPTS);
        for cut in 0..full.len() {
            let p = Packet::dissect(full[..cut].to_vec(), ProtoId::Ether);
            if let Some(ip) = p.find_layer(ProtoId::Ipv4) {
                let items = p.options(ip).expect("ipv4 has an option region");
                assert!(items.len() <= 1, "cut {cut} produced {items:?}");
            }
        }
        let mut hdr = ip_hdr(RA_OPTS, 0);
        hdr.truncate(22);
        assert!(parse_options(&hdr).is_empty());
        let bad = ip_hdr(&[0x94, 0x08, 0x00, 0x00], 0);
        assert!(parse_options(&bad).is_empty());
    }

    #[test]
    fn no_options_is_an_empty_list_not_none() {
        let p = Packet::dissect(frame(&[]), ProtoId::Ether);
        let ip = p.find_layer(ProtoId::Ipv4).unwrap();
        assert_eq!(p.header(ip).len(), 20);
        assert_eq!(p.options(ip), Some(Vec::new()));
        let built = Packet::build(&[ProtoId::Ipv4, ProtoId::Tcp]);
        assert_eq!(built.options(0), Some(Vec::new()));
    }

    #[test]
    fn ihl_below_five_yields_no_options() {
        let mut hdr = ip_hdr(RA_OPTS, 0);
        for ihl in 0..5u8 {
            hdr[0] = 0x40 | ihl;
            assert!(parse_options(&hdr).is_empty(), "ihl {ihl}");
        }
    }
}
