//! BOOTP header layout from RFC 951 §3, with the field interpretation of
//! RFC 2131 §2 and figure 1: the 16-bit field at offset 10, unused in RFC 951,
//! carries the BROADCAST flag. Hardware types from the IANA "Hardware Types"
//! registry. DHCP options follow RFC 2132; the magic cookie that introduces
//! them is RFC 2131 §3 and RFC 1497.

use crate::field::FieldDesc;
use crate::options::{Item, LenRule, OptDesc, OptTable, Shape};
use crate::proto::{Next, ProtoDesc, ProtoId};

/// RFC 951 §3: `file` ends at 108 + 128.
const BOOTP_LEN: usize = 236;

/// RFC 2131 §3 / RFC 1497: 99.130.83.99 in network order.
pub const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// RFC 2131 figure 2, least significant bit first. Only the top bit of the
/// 16-bit field is assigned (BROADCAST); the rest are MBZ.
pub static FLAG_NAMES: &[&str] = &[
    "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "B",
];

pub static FIELDS: &[FieldDesc] = &[
    FieldDesc::uint("op", 0, 8, 1),
    FieldDesc::uint("htype", 8, 8, 1),
    FieldDesc::uint("hlen", 16, 8, 6),
    FieldDesc::uint("hops", 24, 8, 0),
    FieldDesc::uint("xid", 32, 32, 0),
    FieldDesc::uint("secs", 64, 16, 0),
    FieldDesc::flags("flags", 80, 16, FLAG_NAMES),
    FieldDesc::ipv4("ciaddr", 96, 0),
    FieldDesc::ipv4("yiaddr", 128, 0),
    FieldDesc::ipv4("siaddr", 160, 0),
    FieldDesc::ipv4("giaddr", 192, 0),
    FieldDesc::bytes("chaddr", 224, 128),
    FieldDesc::bytes("sname", 352, 512),
    FieldDesc::bytes("file", 864, 1024),
    // RFC 2131 §3: the magic cookie opens the option area, which belongs to
    // BOOTP. The DHCP layer starts at the first option.
    FieldDesc::var_bytes("options", (BOOTP_LEN * 8) as u16),
];

fn has_cookie(hdr: &[u8]) -> bool {
    hdr.len() >= BOOTP_LEN + 4 && hdr[BOOTP_LEN..BOOTP_LEN + 4] == MAGIC_COOKIE
}

fn header_len(hdr: &[u8]) -> usize {
    if has_cookie(hdr) {
        BOOTP_LEN + MAGIC_COOKIE.len()
    } else {
        BOOTP_LEN
    }
}

fn next(hdr: &[u8]) -> Next {
    if has_cookie(hdr) {
        Next::Proto(ProtoId::Dhcp)
    } else {
        Next::Raw
    }
}

fn bind_next_bytes(p: ProtoId) -> &'static [u8] {
    match p {
        ProtoId::Dhcp => &MAGIC_COOKIE,
        _ => &[],
    }
}

pub static DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Bootp,
    name: "BOOTP",
    fields: FIELDS,
    min_len: BOOTP_LEN,
    header_len,
    next,
    build_len: BOOTP_LEN,
    parse_options: None,
    opt_table: None,
    set_hlen: None,
    bind_next: None,
    bind_next_bytes: Some(bind_next_bytes),
    content_len: None,
};

pub static DHCP_FIELDS: &[FieldDesc] = &[FieldDesc::var_bytes_to_end("options", 0)];

fn dhcp_header_len(hdr: &[u8]) -> usize {
    hdr.len()
}

fn dhcp_next(_: &[u8]) -> Next {
    Next::End
}

/// RFC 2132 §9.6, option 53.
pub mod msgtype {
    pub const DISCOVER: u64 = 1;
    pub const OFFER: u64 = 2;
    pub const REQUEST: u64 = 3;
    pub const DECLINE: u64 = 4;
    pub const ACK: u64 = 5;
    pub const NAK: u64 = 6;
    pub const RELEASE: u64 = 7;
    pub const INFORM: u64 = 8;
}

static MSGTYPE_NAMES: &[(&str, u64)] = &[
    ("discover", msgtype::DISCOVER),
    ("offer", msgtype::OFFER),
    ("request", msgtype::REQUEST),
    ("decline", msgtype::DECLINE),
    ("ack", msgtype::ACK),
    ("nak", msgtype::NAK),
    ("release", msgtype::RELEASE),
    ("inform", msgtype::INFORM),
];

/// RFC 2132 §3.1: Pad carries no length octet; §3.2: End terminates the region.
const PAD: u8 = 0;
const END: u8 = 255;

/// The option area itself; the cookie belongs to BOOTP.
pub static DHCP_OPTIONS: OptTable = OptTable {
    proto: "DHCP",
    rule: LenRule::PayloadOnly,
    end: Some(END),
    opts: &[
        OptDesc::new("pad", PAD, Shape::Bare),
        OptDesc::new("subnet_mask", 1, Shape::Ipv4List),
        OptDesc::new("router", 3, Shape::Ipv4List),
        OptDesc::new("name_server", 6, Shape::Ipv4List),
        OptDesc::new("hostname", 12, Shape::Text),
        OptDesc::new("domain", 15, Shape::Text),
        OptDesc::new("broadcast_address", 28, Shape::Ipv4List),
        OptDesc::new("requested_addr", 50, Shape::Ipv4List),
        OptDesc::new("lease_time", 51, Shape::LooseUint(4)),
        OptDesc::new("message-type", 53, Shape::LooseUint(1)).with_names(MSGTYPE_NAMES),
        OptDesc::new("server_id", 54, Shape::Ipv4List),
        OptDesc::new("param_req_list", 55, Shape::Bytes),
        OptDesc::new("max_dhcp_size", 57, Shape::LooseUint(2)),
        OptDesc::new("renewal_time", 58, Shape::LooseUint(4)),
        OptDesc::new("rebinding_time", 59, Shape::LooseUint(4)),
        OptDesc::new("client_id", 61, Shape::Bytes),
        OptDesc::new("relay_agent_information", 82, Shape::Bytes),
        OptDesc::new("end", END, Shape::Bare),
    ],
};

fn parse_options(data: &[u8]) -> Vec<Item> {
    DHCP_OPTIONS.walk(data)
}

pub static DHCP_DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Dhcp,
    name: "DHCP",
    fields: DHCP_FIELDS,
    min_len: 1,
    header_len: dhcp_header_len,
    next: dhcp_next,
    build_len: 0,
    parse_options: Some(parse_options),
    opt_table: Some(&DHCP_OPTIONS),
    set_hlen: None,
    bind_next: None,
    bind_next_bytes: None,
    content_len: None,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldValue;
    use crate::options::{ItemValue, OptArg};
    use crate::packet::Packet;

    const CHADDR: [u8; 6] = [0x00, 0x0c, 0x29, 0x1a, 0x2b, 0x3c];

    /// Client to server, ports 68 -> 67.
    fn udp_bootpc_to_bootps() -> Vec<u8> {
        vec![0x00, 0x44, 0x00, 0x43, 0x00, 0x00, 0x00, 0x00]
    }

    /// RFC 951 §3 BOOTREQUEST.
    fn bootp_header() -> Vec<u8> {
        let mut v = vec![0u8; BOOTP_LEN];
        v[0] = 1;
        v[1] = 1;
        v[2] = 6;
        v[3] = 0;
        v[4..8].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        v[8..10].copy_from_slice(&[0x00, 0x04]);
        v[10..12].copy_from_slice(&[0x80, 0x00]);
        v[12..16].copy_from_slice(&[0, 0, 0, 0]);
        v[16..20].copy_from_slice(&[192, 168, 1, 50]);
        v[20..24].copy_from_slice(&[192, 168, 1, 1]);
        v[24..28].copy_from_slice(&[0, 0, 0, 0]);
        v[28..34].copy_from_slice(&CHADDR);
        v
    }

    /// Cookie plus an RFC 2132 DISCOVER and END.
    fn dhcp_options() -> Vec<u8> {
        let mut v = MAGIC_COOKIE.to_vec();
        v.extend_from_slice(&[53, 1, 1, 255]);
        v
    }

    fn udp_bootp(with_options: bool) -> Vec<u8> {
        let mut v = udp_bootpc_to_bootps();
        v.extend_from_slice(&bootp_header());
        if with_options {
            v.extend_from_slice(&dhcp_options());
        }
        v
    }

    #[test]
    fn dissects_bootp_fields() {
        let p = Packet::dissect(udp_bootp(true), ProtoId::Udp);
        let b = p.find_layer(ProtoId::Bootp).expect("bootp layer");
        assert_eq!(p.get(b, "op").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(b, "htype").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(b, "hlen").unwrap(), FieldValue::Uint(6));
        assert_eq!(p.get(b, "xid").unwrap(), FieldValue::Uint(0xdead_beef));
        assert_eq!(p.get(b, "secs").unwrap(), FieldValue::Uint(4));
        assert_eq!(
            p.get(b, "yiaddr").unwrap(),
            FieldValue::Ipv4([192, 168, 1, 50])
        );
        assert_eq!(
            p.get(b, "siaddr").unwrap(),
            FieldValue::Ipv4([192, 168, 1, 1])
        );
        assert_eq!(p.get(b, "ciaddr").unwrap(), FieldValue::Ipv4([0, 0, 0, 0]));

        let mut want = vec![0u8; 16];
        want[..6].copy_from_slice(&CHADDR);
        assert_eq!(p.get(b, "chaddr").unwrap(), FieldValue::Bytes(want));

        match p.get(b, "flags").unwrap() {
            FieldValue::Flags { bits, .. } => assert_eq!(bits, 0x8000),
            other => panic!("expected flags, got {other:?}"),
        }
    }

    #[test]
    fn magic_cookie_yields_dhcp_layer() {
        let p = Packet::dissect(udp_bootp(true), ProtoId::Udp);
        let got: Vec<_> = p.layers().iter().map(|s| s.proto).collect();
        assert_eq!(got, vec![ProtoId::Udp, ProtoId::Bootp, ProtoId::Dhcp]);

        // RFC 2131 §3: the cookie closes BOOTP's option area.
        let b = p.find_layer(ProtoId::Bootp).unwrap();
        assert_eq!(
            p.get(b, "options").unwrap(),
            FieldValue::Bytes(MAGIC_COOKIE.to_vec())
        );
        let d = p.find_layer(ProtoId::Dhcp).unwrap();
        assert_eq!(
            p.get(d, "options").unwrap(),
            FieldValue::Bytes(vec![53, 1, 1, 255])
        );
    }

    #[test]
    fn without_cookie_there_is_no_dhcp_layer() {
        let mut buf = udp_bootp(false);
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 53, 1, 1, 255]);
        let p = Packet::dissect(buf, ProtoId::Udp);
        assert!(!p.has_layer(ProtoId::Dhcp));
        let got: Vec<_> = p.layers().iter().map(|s| s.proto).collect();
        assert_eq!(got, vec![ProtoId::Udp, ProtoId::Bootp, ProtoId::Raw]);

        let p = Packet::dissect(udp_bootp(false), ProtoId::Udp);
        assert!(!p.has_layer(ProtoId::Dhcp));
        assert_eq!(p.layers().len(), 2);
    }

    #[test]
    fn truncated_input_does_not_panic() {
        for cut in [0usize, 1, 8, 9, 100, 235, 236, 237, 239] {
            let full = udp_bootp(true);
            let p = Packet::dissect(full[..cut.min(full.len())].to_vec(), ProtoId::Udp);
            for (i, s) in p.layers().iter().enumerate() {
                for f in crate::proto::desc(s.proto).fields {
                    let _ = p.get_desc(i, f);
                }
            }
        }
        assert_eq!(next(&[]), Next::Raw);
        assert_eq!(next(&[0u8; 238]), Next::Raw);
        assert_eq!(header_len(&[]), BOOTP_LEN);
    }

    #[test]
    fn fixed_header_is_236_bytes() {
        assert_eq!(header_len(&bootp_header()), 236);
        assert_eq!(DESC.min_len, 236);
        assert_eq!(DESC.build_len, 236);
        let last = FIELDS.last().unwrap();
        assert_eq!((last.bit_off as usize + last.bit_len as usize) / 8, 236);
        let mut bit = 0u32;
        for f in FIELDS {
            assert_eq!(f.bit_off as u32, bit, "gap or overlap before {}", f.name);
            bit += f.bit_len as u32;
        }
        assert_eq!(bit, 236 * 8);
    }

    fn names(items: &[Item]) -> Vec<&str> {
        items.iter().map(|i| i.name.as_ref()).collect()
    }

    /// RFC 2132 §9.6, §9.14, §9.8: message type, type-1 client identifier
    /// holding the MAC, parameter request list, End.
    fn discover_block() -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&[53, 1, 1]);
        v.extend_from_slice(&[61, 7, 1]);
        v.extend_from_slice(&CHADDR);
        v.extend_from_slice(&[55, 4, 1, 3, 6, 15]);
        v.push(255);
        v
    }

    /// A server ACK: mask, router, two name servers, lease time, server id.
    fn ack_block() -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&[53, 1, 5]);
        v.extend_from_slice(&[1, 4, 255, 255, 255, 0]);
        v.extend_from_slice(&[3, 4, 192, 168, 1, 1]);
        v.extend_from_slice(&[6, 8, 8, 8, 8, 8, 8, 8, 4, 4]);
        v.extend_from_slice(&[51, 4, 0, 0, 0x0e, 0x10]);
        v.extend_from_slice(&[54, 4, 192, 168, 1, 1]);
        v.push(255);
        v
    }

    #[test]
    fn parses_a_discover_option_block() {
        let items = parse_options(&discover_block());
        assert_eq!(
            names(&items),
            vec!["message-type", "client_id", "param_req_list", "end"]
        );
        assert_eq!(items[0].value, ItemValue::Uint(msgtype::DISCOVER));
        let mut id = vec![1u8];
        id.extend_from_slice(&CHADDR);
        assert_eq!(items[1].value, ItemValue::Bytes(id));
        assert_eq!(items[2].value, ItemValue::Bytes(vec![1, 3, 6, 15]));
        assert_eq!(items[3].value, ItemValue::Flag);
    }

    #[test]
    fn parses_an_ack_option_block() {
        let items = parse_options(&ack_block());
        assert_eq!(
            names(&items),
            vec![
                "message-type",
                "subnet_mask",
                "router",
                "name_server",
                "lease_time",
                "server_id",
                "end"
            ]
        );
        assert_eq!(items[0].value, ItemValue::Uint(msgtype::ACK));
        assert_eq!(
            items[1].value,
            ItemValue::Ipv4List(vec![[255, 255, 255, 0]])
        );
        assert_eq!(items[2].value, ItemValue::Ipv4List(vec![[192, 168, 1, 1]]));
        assert_eq!(
            items[3].value,
            ItemValue::Ipv4List(vec![[8, 8, 8, 8], [8, 8, 4, 4]])
        );
        assert_eq!(items[4].value, ItemValue::Uint(3600));
        assert_eq!(items[5].value, ItemValue::Ipv4List(vec![[192, 168, 1, 1]]));
    }

    #[test]
    fn options_are_reachable_through_dissect() {
        let mut buf = udp_bootpc_to_bootps();
        buf.extend_from_slice(&bootp_header());
        buf.extend_from_slice(&MAGIC_COOKIE);
        buf.extend_from_slice(&discover_block());
        let p = Packet::dissect(buf, ProtoId::Udp);
        let d = p.find_layer(ProtoId::Dhcp).expect("dhcp layer");
        let items = p.options(d).expect("dhcp options");
        assert_eq!(items[0], Item::uint("message-type", 53, msgtype::DISCOVER));
        assert_eq!(items.last().unwrap().name, "end");

        let b = p.find_layer(ProtoId::Bootp).unwrap();
        assert!(p.options(b).is_none());
    }

    #[test]
    fn truncated_option_region_stops_cleanly() {
        let full = ack_block();
        for cut in 0..=full.len() {
            let items = parse_options(&full[..cut]);
            let whole = parse_options(&full);
            assert!(items.len() <= whole.len(), "cut {cut} produced extra items");
            for (a, b) in items.iter().zip(whole.iter()) {
                assert_eq!(a, b, "cut {cut} decoded differently");
            }
        }
        assert!(parse_options(&[]).is_empty());
    }

    #[test]
    fn unknown_code_does_not_stop_the_walk() {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&[53, 1, 3]);
        v.extend_from_slice(&[224, 1, 0xaa]); // unassigned in RFC 2132
        v.extend_from_slice(&[51, 4, 0, 0, 0x0e, 0x10]);
        v.push(255);
        let items = parse_options(&v);
        assert_eq!(
            names(&items),
            vec!["message-type", "224", "lease_time", "end"]
        );
        assert_eq!(items[1], Item::unknown(224, &[0xaa]));
        assert_eq!(items[2].value, ItemValue::Uint(3600));
    }

    #[test]
    fn pad_bytes_do_not_desynchronise_the_walk() {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&[0, 0]);
        v.extend_from_slice(&[53, 1, 2]);
        v.push(0);
        v.extend_from_slice(&[58, 4, 0, 0, 0x07, 0x08]);
        v.extend_from_slice(&[59, 4, 0, 0, 0x0c, 0x4e]);
        v.push(255);
        v.extend_from_slice(&[0, 0, 0]);
        let items = parse_options(&v);
        assert_eq!(
            names(&items),
            vec![
                "pad",
                "pad",
                "message-type",
                "pad",
                "renewal_time",
                "rebinding_time",
                "end"
            ]
        );
        assert_eq!(items[2].value, ItemValue::Uint(msgtype::OFFER));
        assert_eq!(items[4].value, ItemValue::Uint(1800));
        assert_eq!(items[5].value, ItemValue::Uint(3150));
    }

    #[test]
    fn missing_end_returns_what_was_parsed() {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&[53, 1, 3]);
        v.extend_from_slice(&[50, 4, 192, 168, 1, 50]);
        v.extend_from_slice(&[12, 3, b'p', b'c', b'1']);
        v.extend_from_slice(&[57, 2, 0x05, 0xdc]);
        let items = parse_options(&v);
        assert_eq!(
            names(&items),
            vec![
                "message-type",
                "requested_addr",
                "hostname",
                "max_dhcp_size"
            ]
        );
        assert_eq!(items[0].value, ItemValue::Uint(msgtype::REQUEST));
        assert_eq!(items[1].value, ItemValue::Ipv4List(vec![[192, 168, 1, 50]]));
        assert_eq!(items[2].value, ItemValue::Text("pc1".into()));
        assert_eq!(items[3].value, ItemValue::Uint(1500));
    }

    #[test]
    fn address_lists_drop_a_trailing_partial_address() {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&[3, 6, 10, 0, 0, 1, 10, 0]);
        v.extend_from_slice(&[15, 7, b'l', b'a', b'n', b'.', b'c', b'o', b'm']);
        v.extend_from_slice(&[28, 4, 10, 0, 0, 255]);
        v.push(255);
        let items = parse_options(&v);
        assert_eq!(items[0].value, ItemValue::Ipv4List(vec![[10, 0, 0, 1]]));
        assert_eq!(items[1].value, ItemValue::Text("lan.com".into()));
        assert_eq!(items[2].value, ItemValue::Ipv4List(vec![[10, 0, 0, 255]]));
    }

    #[test]
    fn encodes_a_discover_option_block() {
        let got = DHCP_OPTIONS
            .build(&[
                ("message-type", OptArg::Uint(msgtype::DISCOVER)),
                (
                    "client_id",
                    OptArg::Bytes([&[1u8][..], &CHADDR[..]].concat()),
                ),
                (
                    "param_req_list",
                    OptArg::List(vec![
                        OptArg::Uint(1),
                        OptArg::Uint(3),
                        OptArg::Uint(6),
                        OptArg::Uint(15),
                    ]),
                ),
                ("end", OptArg::Flag),
            ])
            .unwrap();
        assert_eq!(got, discover_block());
    }

    #[test]
    fn encodes_an_ack_option_block() {
        let got = DHCP_OPTIONS
            .build(&[
                ("message-type", OptArg::Text("ack".into())),
                ("subnet_mask", OptArg::Text("255.255.255.0".into())),
                ("router", OptArg::Text("192.168.1.1".into())),
                (
                    "name_server",
                    OptArg::List(vec![
                        OptArg::Text("8.8.8.8".into()),
                        OptArg::Text("8.8.4.4".into()),
                    ]),
                ),
                ("lease_time", OptArg::Uint(3600)),
                ("server_id", OptArg::Text("192.168.1.1".into())),
                ("end", OptArg::Flag),
            ])
            .unwrap();
        assert_eq!(got, ack_block());
    }

    #[test]
    fn the_length_octet_counts_only_the_payload() {
        // RFC 2132 §2, against the TCP/IPv4 rule: three octets carry a
        // two-octet option, not four.
        let got = DHCP_OPTIONS
            .build(&[("message-type", OptArg::Uint(1))])
            .unwrap();
        assert_eq!(got, vec![53, 1, 1]);
    }

    #[test]
    fn pad_and_end_carry_no_length_octet() {
        let got = DHCP_OPTIONS
            .build(&[("pad", OptArg::Flag), ("end", OptArg::Flag)])
            .unwrap();
        assert_eq!(got, vec![PAD, END]);
    }

    #[test]
    fn a_decimal_name_encodes_as_that_code() {
        // RFC 2132 §9.13 vendor class, unnamed here.
        let got = DHCP_OPTIONS
            .build(&[("60", OptArg::Bytes(b"MSFT 5.0".to_vec()))])
            .unwrap();
        assert_eq!(got, [&[60u8, 8][..], b"MSFT 5.0"].concat());
        assert!(DHCP_OPTIONS
            .build(&[("no_such_option", OptArg::Flag)])
            .is_err());
    }

    #[test]
    fn built_bootp_carries_rfc_defaults() {
        let p = Packet::build(&[ProtoId::Bootp]);
        assert_eq!(p.len(), 236);
        assert_eq!(p.get(0, "op").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(0, "htype").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(0, "hlen").unwrap(), FieldValue::Uint(6));
    }
}
