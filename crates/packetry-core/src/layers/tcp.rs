//! TCP header layout from RFC 9293 §3.1.

use crate::field::FieldDesc;
use crate::options::{be, walk_tlv, Item};
use crate::proto::{Next, ProtoDesc, ProtoId};

/// Control bits, least significant first. The ninth, NS (RFC 3540), takes the
/// low bit of the field RFC 9293 §3.1 otherwise reserves.
pub static FLAG_NAMES: &[&str] = &["F", "S", "R", "P", "A", "U", "E", "C", "N"];

pub static FIELDS: &[FieldDesc] = &[
    FieldDesc::uint("sport", 0, 16, 20),
    FieldDesc::uint("dport", 16, 16, 80),
    FieldDesc::uint("seq", 32, 32, 0),
    FieldDesc::uint("ack", 64, 32, 0),
    FieldDesc::uint("dataofs", 96, 4, 5),
    FieldDesc::uint("reserved", 100, 3, 0),
    // Defaults to SYN, as packet-crafting tools conventionally do.
    FieldDesc {
        name: "flags",
        bit_off: 103,
        bit_len: 9,
        kind: crate::field::FieldKind::Flags,
        default: 0b0000_0010,
        flags: FLAG_NAMES,
        computed: false,
        cond: None,
        default_bytes: None,
        to_end: false,
    },
    FieldDesc::uint("window", 112, 16, 8192),
    FieldDesc::computed_uint("chksum", 128, 16),
    FieldDesc::uint("urgptr", 144, 16, 0),
    FieldDesc::var_bytes("options", 160),
];

fn header_len(hdr: &[u8]) -> usize {
    if hdr.len() < 13 {
        return 20;
    }
    // RFC 9293 §3.1: Data Offset counts 32-bit words and is at least 5.
    (((hdr[12] >> 4) & 0x0f) as usize * 4).max(20)
}

/// Always opaque: DNS over TCP is length-prefixed, which the DNS layer does not
/// handle, and nothing else is dispatched on a TCP port.
fn next(_: &[u8]) -> Next {
    Next::Raw
}

/// IANA "TCP Option Kind Numbers" registry.
pub mod optkind {
    pub const EOL: u8 = 0;
    pub const NOP: u8 = 1;
    pub const MSS: u8 = 2;
    pub const WSCALE: u8 = 3;
    pub const SACKOK: u8 = 4;
    pub const SACK: u8 = 5;
    pub const TIMESTAMP: u8 = 8;
    pub const UTO: u8 = 28;
    pub const AO: u8 = 29;
    pub const TFO: u8 = 34;
}

/// RFC 9293 §3.1: kinds 0 and 1 are a single octet with no length field.
const SINGLE_BYTE: &[u8] = &[optkind::EOL, optkind::NOP];

/// Falls back to the raw payload when the capture disagrees with the registry.
fn fixed_uint(name: &'static str, kind: u8, payload: &[u8], width: usize) -> Item {
    if payload.len() == width {
        Item::uint(name, kind as u32, be(payload))
    } else {
        Item::bytes(name, kind as u32, payload)
    }
}

fn decode(kind: u8, payload: &[u8]) -> Item {
    match kind {
        // Unreachable while EOL is the walk's end code.
        optkind::EOL => Item::flag("EOL", optkind::EOL as u32),
        optkind::NOP => Item::flag("NOP", optkind::NOP as u32),
        optkind::MSS => fixed_uint("MSS", kind, payload, 2),
        optkind::WSCALE => fixed_uint("WScale", kind, payload, 1),
        optkind::SACKOK => Item::flag("SAckOK", optkind::SACKOK as u32),
        // RFC 2018 §3 edge pairs, left unstructured.
        optkind::SACK => Item::bytes("SAck", kind as u32, payload),
        optkind::TIMESTAMP if payload.len() == 8 => Item::pair(
            "Timestamp",
            kind as u32,
            be(&payload[..4]),
            be(&payload[4..]),
        ),
        optkind::TIMESTAMP => Item::bytes("Timestamp", kind as u32, payload),
        optkind::UTO => fixed_uint("UTO", kind, payload, 2),
        optkind::AO => Item::bytes("AO", kind as u32, payload),
        optkind::TFO => Item::bytes("TFO", kind as u32, payload),
        _ => Item::unknown(kind as u32, payload),
    }
}

fn parse_options(hdr: &[u8]) -> Vec<Item> {
    let end = header_len(hdr).min(hdr.len());
    if end <= 20 {
        return Vec::new();
    }
    walk_tlv(&hdr[20..end], SINGLE_BYTE, Some(optkind::EOL), decode)
}

/// RFC 9293 §3.1: Data Offset counts 32-bit words.
fn set_hlen(hdr: &mut [u8], len: usize) {
    if hdr.len() > 12 {
        hdr[12] = (hdr[12] & 0x0f) | ((((len / 4) as u8) & 0x0f) << 4);
    }
}

pub static DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Tcp,
    name: "TCP",
    fields: FIELDS,
    min_len: 20,
    header_len,
    next,
    build_len: 20,
    parse_options: Some(parse_options),
    set_hlen: Some(set_hlen),
    bind_next: None,
    bind_next_bytes: None,
    content_len: None,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldValue;
    use crate::options::ItemValue;
    use crate::packet::Packet;

    /// MSS, SAckOK, Timestamp, NOP, Window Scale, hand-built from RFC 9293
    /// §3.1, RFC 2018 §2 and RFC 7323 §3-4.
    const SYN_OPTS: &[u8] = &[
        0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x02, 0x01, 0x03, 0x03, 0x07,
    ];

    fn tcp_hdr(opts: &[u8]) -> Vec<u8> {
        assert_eq!(opts.len() % 4, 0, "option block must fill whole words");
        let dataofs = ((20 + opts.len()) / 4) as u8;
        let mut v = vec![0x1f, 0x90, 0x00, 0x50];
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        v.push(dataofs << 4);
        v.push(0x02);
        v.extend_from_slice(&[0x20, 0x00]);
        v.extend_from_slice(&[0x00, 0x00]);
        v.extend_from_slice(&[0x00, 0x00]);
        v.extend_from_slice(opts);
        v
    }

    fn frame(opts: &[u8]) -> Vec<u8> {
        let tcp = tcp_hdr(opts);
        let mut v = Vec::new();
        v.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        v.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        v.extend_from_slice(&[0x08, 0x00]);
        let total = (20 + tcp.len()) as u16;
        v.extend_from_slice(&[0x45, 0x00]);
        v.extend_from_slice(&total.to_be_bytes());
        v.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        v.extend_from_slice(&[0x40, 0x06, 0x00, 0x00]);
        v.extend_from_slice(&[10, 0, 0, 1]);
        v.extend_from_slice(&[10, 0, 0, 2]);
        v.extend_from_slice(&tcp);
        v
    }

    #[test]
    fn decodes_a_syn_option_block_in_order() {
        let items = parse_options(&tcp_hdr(SYN_OPTS));
        let got: Vec<_> = items.iter().map(|i| (i.name.as_ref(), i.code)).collect();
        assert_eq!(
            got,
            vec![
                ("MSS", 2),
                ("SAckOK", 4),
                ("Timestamp", 8),
                ("NOP", 1),
                ("WScale", 3),
            ]
        );
        assert_eq!(items[0].value, ItemValue::Uint(1460));
        assert_eq!(items[1].value, ItemValue::Flag);
        assert_eq!(items[2].value, ItemValue::Pair(1, 2));
        assert_eq!(items[3].value, ItemValue::Flag);
        assert_eq!(items[4].value, ItemValue::Uint(7));
    }

    #[test]
    fn dissects_options_end_to_end() {
        let p = Packet::dissect(frame(SYN_OPTS), ProtoId::Ether);
        let t = p.find_layer(ProtoId::Tcp).expect("tcp layer");
        assert_eq!(p.get(t, "dataofs").unwrap(), FieldValue::Uint(10));
        assert_eq!(p.header(t).len(), 40);
        assert_eq!(p.layers()[t].hlen, 40);
        assert!(p.payload(t).is_empty());
        let items = p.options(t).expect("tcp has an option region");
        assert_eq!(items.len(), 5);
        assert_eq!(items[0].value, ItemValue::Uint(1460));
        assert_eq!(items[4].value, ItemValue::Uint(7));
        assert_eq!(
            p.get(t, "options").unwrap(),
            FieldValue::Bytes(SYN_OPTS.to_vec())
        );
    }

    #[test]
    fn truncated_option_region_stops_cleanly() {
        let full = frame(SYN_OPTS);
        for cut in 0..full.len() {
            let p = Packet::dissect(full[..cut].to_vec(), ProtoId::Ether);
            if let Some(t) = p.find_layer(ProtoId::Tcp) {
                let items = p.options(t).expect("tcp has an option region");
                assert!(items.len() <= 5, "cut {cut} produced {items:?}");
            }
        }
        // Data Offset over-claims the bytes present.
        let mut hdr = tcp_hdr(&[0x02, 0x04, 0x05, 0xb4]);
        hdr.truncate(22);
        assert!(parse_options(&hdr).is_empty());
        // Length octet runs past the option region.
        let bad = tcp_hdr(&[0x02, 0x08, 0x05, 0xb4]);
        assert!(parse_options(&bad).is_empty());
    }

    #[test]
    fn unknown_kind_does_not_abort_the_walk() {
        // Kind 253 is an RFC 3692 experiment code, deliberately unnamed here.
        let opts = &[0xfd, 0x04, 0xde, 0xad, 0x03, 0x03, 0x07, 0x01];
        let items = parse_options(&tcp_hdr(opts));
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].code, 253);
        assert_eq!(items[0].name.as_ref(), "253");
        assert_eq!(items[0].value, ItemValue::Bytes(vec![0xde, 0xad]));
        assert_eq!(items[1].value, ItemValue::Uint(7));
        assert_eq!(items[2].value, ItemValue::Flag);
    }

    #[test]
    fn no_options_is_an_empty_list_not_none() {
        let p = Packet::dissect(frame(&[]), ProtoId::Ether);
        let t = p.find_layer(ProtoId::Tcp).unwrap();
        assert_eq!(p.header(t).len(), 20);
        assert_eq!(p.options(t), Some(Vec::new()));
        let built = Packet::build(&[ProtoId::Ipv4, ProtoId::Tcp]);
        assert_eq!(built.options(1), Some(Vec::new()));
    }

    #[test]
    fn eol_ends_the_walk_and_short_dataofs_yields_nothing() {
        // RFC 9293 §3.1: EOL terminates and the padding after it is not decoded.
        let opts = &[0x03, 0x03, 0x07, 0x00, 0x02, 0x04, 0x05, 0xb4];
        let items = parse_options(&tcp_hdr(opts));
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name.as_ref(), "WScale");

        let mut hdr = tcp_hdr(SYN_OPTS);
        hdr[12] = 0x40;
        assert!(parse_options(&hdr).is_empty());
        hdr[12] = 0x00;
        assert!(parse_options(&hdr).is_empty());
    }

    #[test]
    fn decodes_the_remaining_named_kinds() {
        let opts = &[
            0x05, 0x0a, 0, 0, 0, 1, 0, 0, 0, 2, 0x1c, 0x04, 0x80, 0x0a, 0x1d, 0x04, 0xaa, 0xbb,
            0x22, 0x04, 0xc0, 0xff, 0x00, 0x00,
        ];
        let items = parse_options(&tcp_hdr(opts));
        assert_eq!(items.len(), 4);
        assert_eq!(items[0].name.as_ref(), "SAck");
        assert_eq!(
            items[0].value,
            ItemValue::Bytes(vec![0, 0, 0, 1, 0, 0, 0, 2])
        );
        assert_eq!(items[1], Item::uint("UTO", 28, 0x800a));
        assert_eq!(items[2], Item::bytes("AO", 29, &[0xaa, 0xbb]));
        assert_eq!(items[3], Item::bytes("TFO", 34, &[0xc0, 0xff]));
    }

    #[test]
    fn wrong_length_keeps_the_name_and_the_bytes() {
        // A 4-byte MSS is malformed; the option is still reported, unparsed.
        let opts = &[0x02, 0x06, 0x05, 0xb4, 0x00, 0x00, 0x01, 0x01];
        let items = parse_options(&tcp_hdr(opts));
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].name.as_ref(), "MSS");
        assert_eq!(
            items[0].value,
            ItemValue::Bytes(vec![0x05, 0xb4, 0x00, 0x00])
        );
    }
}
