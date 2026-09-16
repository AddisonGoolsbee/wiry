//! BOOTP and DHCP.
//!
//! BOOTP header layout from RFC 951 section 3 ("Packet Format"), with the field
//! interpretation of RFC 2131 section 2 ("Protocol Summary") and figure 1: the
//! 16-bit field at offset 10, unused in RFC 951, carries the BROADCAST flag.
//! Hardware type values come from the IANA "Hardware Types" registry.
//!
//! DHCP options follow RFC 2132. The four-octet magic cookie 99.130.83.99 that
//! introduces them is specified in RFC 2131 section 3 and RFC 1497.

use crate::field::FieldDesc;
use crate::proto::{Next, ProtoDesc, ProtoId};

/// Fixed BOOTP header size in bytes: `file` ends at 108 + 128 (RFC 951 §3).
const BOOTP_LEN: usize = 236;

/// RFC 2131 §3 / RFC 1497: 99.130.83.99 in network order.
pub const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// RFC 2131 figure 2, least significant bit first. Only the most significant
/// bit of the 16-bit field is assigned (BROADCAST); the rest are MBZ.
pub static FLAG_NAMES: &[&str] =
    &["", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "B"];

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
];

fn header_len(_: &[u8]) -> usize {
    BOOTP_LEN
}

fn next(hdr: &[u8]) -> Next {
    if hdr.len() >= BOOTP_LEN + 4 && hdr[BOOTP_LEN..BOOTP_LEN + 4] == MAGIC_COOKIE {
        Next::Proto(ProtoId::Dhcp)
    } else {
        Next::Raw
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
    bind_next: None,
};

pub static DHCP_FIELDS: &[FieldDesc] = &[
    FieldDesc::uint("magic", 0, 32, 0x6382_5363),
    FieldDesc::var_bytes("options", 32),
];

/// The options blob runs to the end of the packet; it is not parsed into a TLV
/// list (see DEVIATIONS.md E7).
fn dhcp_header_len(hdr: &[u8]) -> usize {
    hdr.len()
}

fn dhcp_next(_: &[u8]) -> Next {
    Next::End
}

pub static DHCP_DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Dhcp,
    name: "DHCP",
    fields: DHCP_FIELDS,
    min_len: 4,
    header_len: dhcp_header_len,
    next: dhcp_next,
    build_len: 4,
    bind_next: None,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldValue;
    use crate::packet::Packet;

    const CHADDR: [u8; 6] = [0x00, 0x0c, 0x29, 0x1a, 0x2b, 0x3c];

    /// UDP header, client to server (ports 68 -> 67), length left at zero.
    fn udp_bootpc_to_bootps() -> Vec<u8> {
        vec![0x00, 0x44, 0x00, 0x43, 0x00, 0x00, 0x00, 0x00]
    }

    /// A BOOTREQUEST built by hand from the RFC 951 §3 layout.
    fn bootp_header() -> Vec<u8> {
        let mut v = vec![0u8; BOOTP_LEN];
        v[0] = 1; // op = BOOTREQUEST
        v[1] = 1; // htype = Ethernet
        v[2] = 6; // hlen
        v[3] = 0; // hops
        v[4..8].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // xid
        v[8..10].copy_from_slice(&[0x00, 0x04]); // secs
        v[10..12].copy_from_slice(&[0x80, 0x00]); // flags: BROADCAST
        v[12..16].copy_from_slice(&[0, 0, 0, 0]); // ciaddr
        v[16..20].copy_from_slice(&[192, 168, 1, 50]); // yiaddr
        v[20..24].copy_from_slice(&[192, 168, 1, 1]); // siaddr
        v[24..28].copy_from_slice(&[0, 0, 0, 0]); // giaddr
        v[28..34].copy_from_slice(&CHADDR); // chaddr, padded to 16
        v
    }

    /// Cookie plus a minimal RFC 2132 option list: 53 (message type) = 1
    /// DISCOVER, then END.
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
        assert_eq!(p.get(b, "yiaddr").unwrap(), FieldValue::Ipv4([192, 168, 1, 50]));
        assert_eq!(p.get(b, "siaddr").unwrap(), FieldValue::Ipv4([192, 168, 1, 1]));
        assert_eq!(p.get(b, "ciaddr").unwrap(), FieldValue::Ipv4([0, 0, 0, 0]));

        let mut want = vec![0u8; 16];
        want[..6].copy_from_slice(&CHADDR);
        assert_eq!(p.get(b, "chaddr").unwrap(), FieldValue::Bytes(want));

        // Broadcast flag is the most significant bit of the 16-bit field.
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

        let d = p.find_layer(ProtoId::Dhcp).unwrap();
        assert_eq!(p.get(d, "magic").unwrap(), FieldValue::Uint(0x6382_5363));
        assert_eq!(
            p.get(d, "options").unwrap(),
            FieldValue::Bytes(vec![53, 1, 1, 255])
        );
    }

    #[test]
    fn without_cookie_there_is_no_dhcp_layer() {
        // Trailing bytes that are not the cookie must stay opaque.
        let mut buf = udp_bootp(false);
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 53, 1, 1, 255]);
        let p = Packet::dissect(buf, ProtoId::Udp);
        assert!(!p.has_layer(ProtoId::Dhcp));
        let got: Vec<_> = p.layers().iter().map(|s| s.proto).collect();
        assert_eq!(got, vec![ProtoId::Udp, ProtoId::Bootp, ProtoId::Raw]);

        // A bare 236-byte BOOTP with nothing after it ends at BOOTP.
        let p = Packet::dissect(udp_bootp(false), ProtoId::Udp);
        assert!(!p.has_layer(ProtoId::Dhcp));
        assert_eq!(p.layers().len(), 2);
    }

    #[test]
    fn truncated_input_does_not_panic() {
        for cut in [0usize, 1, 8, 9, 100, 235, 236, 237, 239] {
            let full = udp_bootp(true);
            let p = Packet::dissect(full[..cut.min(full.len())].to_vec(), ProtoId::Udp);
            // Reading every field of every layer must stay in bounds.
            for (i, s) in p.layers().iter().enumerate() {
                for f in crate::proto::desc(s.proto).fields {
                    let _ = p.get_desc(i, f);
                }
            }
        }
        // Short header bytes handed straight to the dispatch helpers.
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
        // Fields tile the header with no gaps or overlaps.
        let mut bit = 0u32;
        for f in FIELDS {
            assert_eq!(f.bit_off as u32, bit, "gap or overlap before {}", f.name);
            bit += f.bit_len as u32;
        }
        assert_eq!(bit, 236 * 8);
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
