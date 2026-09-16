//! IPv4. Header layout from RFC 791 section 3.1; protocol numbers from the
//! IANA "Protocol Numbers" registry.

use crate::field::FieldDesc;
use crate::options::{be, walk_tlv, Item};
use crate::proto::{ipproto, Next, ProtoDesc, ProtoId};

/// Fragment-offset field flag bits, most significant first within the 3-bit group:
/// bit 0 reserved, bit 1 Don't Fragment, bit 2 More Fragments (RFC 791 §3.1).
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
    FieldDesc::uint("proto", 72, 8, ipproto::TCP as u64),
    FieldDesc::computed_uint("chksum", 80, 16),
    FieldDesc::ipv4("src", 96, 0),
    FieldDesc::ipv4("dst", 128, 0),
    FieldDesc::var_bytes("options", 160),
];

fn header_len(hdr: &[u8]) -> usize {
    if hdr.is_empty() {
        return 20;
    }
    // IHL counts 32-bit words and must be at least 5 (RFC 791 §3.1).
    ((hdr[0] & 0x0f) as usize * 4).max(20)
}

fn next(hdr: &[u8]) -> Next {
    if hdr.len() < 20 {
        return Next::Raw;
    }
    // A non-zero fragment offset means this is not the first fragment, so the
    // transport header is not present here.
    let frag_off = u16::from_be_bytes([hdr[6], hdr[7]]) & 0x1fff;
    if frag_off != 0 {
        return Next::Raw;
    }
    match hdr[9] {
        ipproto::TCP => Next::Proto(ProtoId::Tcp),
        ipproto::UDP => Next::Proto(ProtoId::Udp),
        ipproto::ICMP => Next::Proto(ProtoId::Icmp),
        _ => Next::Raw,
    }
}

/// Stacking a transport layer under IPv4 sets the Protocol field to match it.
fn bind_next(hdr: &mut [u8], p: ProtoId) {
    let v = match p {
        ProtoId::Tcp => ipproto::TCP,
        ProtoId::Udp => ipproto::UDP,
        ProtoId::Icmp => ipproto::ICMP,
        _ => return,
    };
    if hdr.len() >= 20 {
        hdr[9] = v;
    }
}

/// Option types from the IANA "IP OPTION NUMBERS" registry.
///
/// RFC 791 §3.1 packs the option-type octet as copied(1) | class(2) | number(5),
/// but the registry lists options by the value of the whole octet and that is what
/// is matched here, so e.g. Router Alert is 148 rather than class 0 number 20.
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

/// Types 0 and 1 are a single octet with no length field (RFC 791 §3.1).
const SINGLE_BYTE: &[u8] = &[opttype::EOL, opttype::NOP];

fn fixed_uint(name: &'static str, ty: u8, payload: &[u8], width: usize) -> Item {
    if payload.len() == width {
        Item::uint(name, ty as u32, be(payload))
    } else {
        Item::bytes(name, ty as u32, payload)
    }
}

fn decode(ty: u8, payload: &[u8]) -> Item {
    match ty {
        // Unreachable while EOL is the walk's end code; kept so the decoder is
        // total over the types it names.
        opttype::EOL => Item::flag("EOL", opttype::EOL as u32),
        opttype::NOP => Item::flag("NOP", opttype::NOP as u32),
        // Route and timestamp options carry a pointer octet plus a variable
        // record area; both stay unstructured.
        opttype::RR => Item::bytes("RR", ty as u32, payload),
        opttype::TIMESTAMP => Item::bytes("Timestamp", ty as u32, payload),
        opttype::SECURITY => Item::bytes("Security", ty as u32, payload),
        opttype::LSRR => Item::bytes("LSRR", ty as u32, payload),
        opttype::SID => fixed_uint("SID", ty, payload, 2),
        opttype::SSRR => Item::bytes("SSRR", ty as u32, payload),
        opttype::RA => fixed_uint("RA", ty, payload, 2),
        _ => Item::unknown(ty as u32, payload),
    }
}

/// Options occupy the header past the fixed 20 bytes, up to IHL * 4.
fn parse_options(hdr: &[u8]) -> Vec<Item> {
    let end = header_len(hdr).min(hdr.len());
    if end <= 20 {
        return Vec::new();
    }
    walk_tlv(&hdr[20..end], SINGLE_BYTE, Some(opttype::EOL), decode)
}

/// Write the IHL field, which counts 32-bit words (RFC 791 s3.1).
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
    set_hlen: Some(set_hlen),
    bind_next: Some(bind_next),
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldValue;
    use crate::options::ItemValue;
    use crate::packet::Packet;

    /// Router Alert, "every router examines this packet" (RFC 2113 §2.1),
    /// padded to a word with EOL.
    const RA_OPTS: &[u8] = &[0x94, 0x04, 0x00, 0x00];

    /// Record Route with room for two addresses, one already recorded
    /// (RFC 791 §3.1): type, length 11, pointer 8, then the route data.
    const RR_OPTS: &[u8] = &[
        0x07, 0x0b, 0x08, 10, 0, 0, 1, 0, 0, 0, 0,    // RR
        0x00, // EOL pad to a word boundary
    ];

    /// An IPv4 header carrying `opts`, with IHL and Total Length set to match.
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

    /// A minimal TCP header, so the option-bearing IPv4 header has something under it.
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
        // The option did not displace the transport header.
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
        // The trailing EOL ends the walk and is not reported.
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
            0x83, 0x07, 0x04, 10, 0, 0, 9, // LSRR, one gateway
            0x89, 0x07, 0x04, 10, 0, 0, 8, // SSRR, one gateway
            0x82, 0x0b, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Security, RFC 791 length 11
            0x88, 0x04, 0x12, 0x34, // SID
            0x44, 0x08, 0x05, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, // Timestamp
            0x01, 0x01, 0x01, // NOP padding to a word boundary
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
    fn unknown_type_does_not_abort_the_walk() {
        let opts = &[
            0x1e, 0x04, 0xde, 0xad, // unassigned type 30
            0x94, 0x04, 0x00, 0x00, // Router Alert still decodes after it
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
        // IHL claims more bytes than the buffer holds.
        let mut hdr = ip_hdr(RA_OPTS, 0);
        hdr.truncate(22);
        assert!(parse_options(&hdr).is_empty());
        // An option whose length octet overruns the option region.
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
