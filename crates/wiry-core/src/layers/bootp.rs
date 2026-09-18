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

/// RFC 951 §3 field positions, which RFC 2131 §4.1 lets options take over.
const SNAME_AT: usize = 44;
const SNAME_LEN: usize = 64;
const FILE_AT: usize = 108;
const FILE_LEN: usize = 128;

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
    FieldDesc::bytes("sname", (SNAME_AT * 8) as u16, (SNAME_LEN * 8) as u16),
    FieldDesc::bytes("file", (FILE_AT * 8) as u16, (FILE_LEN * 8) as u16),
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

/// RFC 2132 §9.3.
const OVERLOAD: u8 = 52;

/// RFC 2131 §4.1: `file` holds options, `sname` does, or both do.
mod overload {
    pub const FILE: u8 = 1;
    pub const SNAME: u8 = 2;
}

/// RFC 3046 §2. Sub-options count only their own data, as RFC 2132 options do,
/// and the region ends with the enclosing option rather than with a code.
pub static RELAY_OPTIONS: OptTable = OptTable {
    proto: "DHCP relay agent",
    rule: LenRule::PayloadOnly,
    end: None,
    opts: &[
        OptDesc::new("agent_circuit_id", 1, Shape::Bytes),
        OptDesc::new("agent_remote_id", 2, Shape::Bytes),
        // RFC 3993 §4, RFC 3527 §4, RFC 4243 §4, RFC 5010 §2.
        OptDesc::new("subscriber_id", 6, Shape::Text),
        OptDesc::new("link_selection", 5, Shape::Ipv4List),
        OptDesc::new("vendor_specific", 9, Shape::Bytes),
        OptDesc::new("relay_agent_flags", 10, Shape::LooseUint(1)),
        OptDesc::new("server_id_override", 11, Shape::Ipv4List),
    ],
};

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
        OptDesc::new("overload", OVERLOAD, Shape::LooseUint(1)),
        OptDesc::new("message-type", 53, Shape::LooseUint(1)).with_names(MSGTYPE_NAMES),
        OptDesc::new("server_id", 54, Shape::Ipv4List),
        OptDesc::new("param_req_list", 55, Shape::Bytes),
        OptDesc::new("max_dhcp_size", 57, Shape::LooseUint(2)),
        OptDesc::new("renewal_time", 58, Shape::LooseUint(4)),
        OptDesc::new("rebinding_time", 59, Shape::LooseUint(4)),
        OptDesc::new("client_id", 61, Shape::Bytes),
        OptDesc::new("relay_agent_information", 82, Shape::Bytes).nesting(&RELAY_OPTIONS),
        OptDesc::new("end", END, Shape::Bare),
    ],
};

fn parse_options(data: &[u8]) -> Vec<Item> {
    DHCP_OPTIONS.walk(data)
}

/// RFC 3396 §4 puts `file` before `sname`, which is the order a split value is
/// joined in.
pub fn overload_regions(tlvs: &[(u8, &[u8])]) -> Vec<(usize, usize)> {
    let Some(&v) = tlvs
        .iter()
        .find_map(|(c, p)| (*c == OVERLOAD).then_some(p).and_then(|p| p.first()))
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if v & overload::FILE != 0 {
        out.push((FILE_AT, FILE_AT + FILE_LEN));
    }
    if v & overload::SNAME != 0 {
        out.push((SNAME_AT, SNAME_AT + SNAME_LEN));
    }
    out
}

/// RFC 3396 §5: a value too long for one option is split over repeated
/// appearances of its code. Joining the octets before anything decodes them is
/// the only order that can join halves which do not each decode alone — half an
/// address list, or half a nested region. Pad and End repeat by design.
pub fn decode_joined(t: &OptTable, tlvs: &[(u8, &[u8])]) -> Vec<Item> {
    let mut count = [0u8; 256];
    for (code, _) in tlvs {
        let n = &mut count[*code as usize];
        *n = n.saturating_add(1);
    }
    let mut joined = [false; 256];
    let mut out = Vec::with_capacity(tlvs.len());
    for (code, p) in tlvs {
        let split = *code != PAD && *code != END && count[*code as usize] > 1;
        if !split {
            out.push(t.decode(*code, p));
        } else if !std::mem::replace(&mut joined[*code as usize], true) {
            let all: Vec<u8> = tlvs
                .iter()
                .filter(|(c, _)| c == code)
                .flat_map(|(_, v)| v.iter().copied())
                .collect();
            out.push(t.decode(*code, &all));
        }
    }
    out
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

    /// RFC 3046 §2: Agent Circuit ID then Agent Remote ID, each a sub-option
    /// whose length counts only its own data.
    const RELAY: &[u8] = &[82, 10, 1, 4, b'e', b't', b'h', b'0', 2, 2, 0xab, 0xcd];

    #[test]
    fn relay_agent_sub_options_are_parsed_and_re_encoded() {
        let items = parse_options(&[RELAY, &[255]].concat());
        assert_eq!(names(&items), vec!["relay_agent_information", "end"]);
        let nested = vec![
            Item::bytes("agent_circuit_id", 1, b"eth0"),
            Item::bytes("agent_remote_id", 2, &[0xab, 0xcd]),
        ];
        assert_eq!(items[0].value, ItemValue::Items(nested.clone()));
        assert_eq!(DHCP_OPTIONS.encode(&items[..1]), Ok(RELAY.to_vec()));

        let rebuilt = DHCP_OPTIONS
            .build(&[(
                "relay_agent_information",
                OptArg::List(vec![
                    OptArg::List(vec![
                        OptArg::Text("agent_circuit_id".into()),
                        OptArg::Bytes(b"eth0".to_vec()),
                    ]),
                    OptArg::List(vec![
                        OptArg::Text("agent_remote_id".into()),
                        OptArg::Bytes(vec![0xab, 0xcd]),
                    ]),
                ]),
            )])
            .unwrap();
        assert_eq!(rebuilt, RELAY);

        let raw = DHCP_OPTIONS
            .build(&[("relay_agent_information", OptArg::Bytes(vec![9, 1, 7]))])
            .unwrap();
        assert_eq!(raw, vec![82, 3, 9, 1, 7]);
        let items = parse_options(&raw);
        assert_eq!(
            items[0].value,
            ItemValue::Items(vec![Item::bytes("vendor_specific", 9, &[7])])
        );
    }

    #[test]
    fn a_truncated_sub_option_region_stops_cleanly() {
        for cut in 0..RELAY.len() {
            let mut v = RELAY.to_vec();
            v[1] = (cut as u8).saturating_sub(2);
            v.truncate(cut);
            let items = parse_options(&v);
            assert!(items.len() <= 1, "cut {cut} produced {items:?}");
            if let Some(ItemValue::Items(sub)) = items.first().map(|i| &i.value) {
                assert!(sub.len() <= 2, "cut {cut} produced {sub:?}");
            }
        }
    }

    #[test]
    fn a_value_split_across_repeated_codes_is_joined() {
        // RFC 3396 §5: two appearances of option 12 are one hostname.
        let mut v: Vec<u8> = vec![53, 1, 5];
        v.extend_from_slice(&[12, 3, b'p', b'c', b'-']);
        v.extend_from_slice(&[3, 4, 10, 0, 0, 1]);
        v.extend_from_slice(&[12, 2, b'0', b'1']);
        v.extend_from_slice(&[3, 4, 10, 0, 0, 2]);
        v.push(255);
        let items = decode_joined(&DHCP_OPTIONS, &DHCP_OPTIONS.walk_raw(&v));
        assert_eq!(
            names(&items),
            vec!["message-type", "hostname", "router", "end"]
        );
        assert_eq!(items[1].value, ItemValue::Text("pc-01".into()));
        assert_eq!(
            items[2].value,
            ItemValue::Ipv4List(vec![[10, 0, 0, 1], [10, 0, 0, 2]])
        );

        let pads = [0u8, 0, 53, 1, 1, 255, 0, 0];
        assert_eq!(
            names(&decode_joined(&DHCP_OPTIONS, &DHCP_OPTIONS.walk_raw(&pads))),
            names(&parse_options(&pads))
        );

        // A half of a nested region does not decode alone, so joining the
        // decoded halves would lose it; joining the octets does not.
        let split = [
            82u8, 4, 1, 4, b'e', b't', 82, 6, b'h', b'0', 2, 2, 0xab, 0xcd, 255,
        ];
        let got = decode_joined(&DHCP_OPTIONS, &DHCP_OPTIONS.walk_raw(&split));
        assert_eq!(
            got[0].value,
            ItemValue::Items(vec![
                Item::bytes("agent_circuit_id", 1, b"eth0"),
                Item::bytes("agent_remote_id", 2, &[0xab, 0xcd]),
            ])
        );

        // An address list split between two of its addresses keeps both.
        let mid = [3u8, 2, 10, 0, 3, 2, 0, 1, 255];
        let got = decode_joined(&DHCP_OPTIONS, &DHCP_OPTIONS.walk_raw(&mid));
        assert_eq!(got[0].value, ItemValue::Ipv4List(vec![[10, 0, 0, 1]]));
    }

    #[test]
    fn overloaded_fields_are_read_as_option_regions() {
        let mut hdr = bootp_header();
        // RFC 2131 §4.1: option 52 value 3 gives both fields over to options.
        hdr[SNAME_AT..SNAME_AT + 5].copy_from_slice(&[12, 3, b'p', b'c', b'1']);
        hdr[SNAME_AT + 5] = END;
        hdr[FILE_AT..FILE_AT + 6].copy_from_slice(&[54, 4, 192, 168, 1, 1]);
        hdr[FILE_AT + 6] = END;

        let mut buf = udp_bootpc_to_bootps();
        buf.extend_from_slice(&hdr);
        buf.extend_from_slice(&MAGIC_COOKIE);
        buf.extend_from_slice(&[53, 1, 5, 52, 1, 3, 255]);
        let p = Packet::dissect(buf, ProtoId::Udp);
        let d = p.find_layer(ProtoId::Dhcp).expect("dhcp layer");
        let items = p.options(d).expect("dhcp options");

        // RFC 3396 §4 fixes the order: the options field, then file, then sname.
        assert_eq!(
            names(&items),
            vec![
                "message-type",
                "overload",
                "end",
                "server_id",
                "end",
                "hostname",
                "end"
            ]
        );
        assert_eq!(items[3].value, ItemValue::Ipv4List(vec![[192, 168, 1, 1]]));
        assert_eq!(items[5].value, ItemValue::Text("pc1".into()));
    }

    #[test]
    fn without_option_52_the_fields_keep_their_own_content() {
        let mut hdr = bootp_header();
        hdr[FILE_AT..FILE_AT + 8].copy_from_slice(b"boot.img");
        let mut buf = udp_bootpc_to_bootps();
        buf.extend_from_slice(&hdr);
        buf.extend_from_slice(&MAGIC_COOKIE);
        buf.extend_from_slice(&[53, 1, 5, 255]);
        let p = Packet::dissect(buf, ProtoId::Udp);
        let d = p.find_layer(ProtoId::Dhcp).unwrap();
        assert_eq!(names(&p.options(d).unwrap()), vec!["message-type", "end"]);
        assert!(overload_regions(&[]).is_empty());
        assert_eq!(overload_regions(&[(OVERLOAD, &[1])]).len(), 1);
        assert_eq!(overload_regions(&[(OVERLOAD, &[3])]).len(), 2);
        assert_eq!(overload_regions(&[(OVERLOAD, &[])]).len(), 0);
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
