//! ARP packet format from RFC 826. Hardware type values from the IANA "Address
//! Resolution Protocol (ARP) Parameters" registry; ptype shares the EtherType
//! space.

use crate::field::FieldDesc;
use crate::proto::{ethertype, Next, ProtoDesc, ProtoId};

/// IANA ARP Parameters: 1 = Ethernet (10Mb).
pub const HWTYPE_ETHER: u64 = 1;
/// RFC 826 opcodes.
pub const OP_WHO_HAS: u64 = 1;
pub const OP_IS_AT: u64 = 2;

/// The address fields are sized by hwlen/plen, so these offsets hold only for
/// the IPv4-over-Ethernet case (hwlen 6, plen 4).
pub static FIELDS: &[FieldDesc] = &[
    FieldDesc::uint("hwtype", 0, 16, HWTYPE_ETHER),
    FieldDesc::uint("ptype", 16, 16, ethertype::IPV4 as u64),
    FieldDesc::uint("hwlen", 32, 8, 6),
    FieldDesc::uint("plen", 40, 8, 4),
    FieldDesc::uint("op", 48, 16, OP_WHO_HAS),
    FieldDesc::mac("hwsrc", 64),
    FieldDesc::ipv4("psrc", 112, 0),
    FieldDesc::mac("hwdst", 144),
    FieldDesc::ipv4("pdst", 192, 0),
];

fn header_len(_: &[u8]) -> usize {
    28
}

fn next(_: &[u8]) -> Next {
    Next::End
}

pub static DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Arp,
    name: "ARP",
    fields: FIELDS,
    min_len: 28,
    header_len,
    next,
    build_len: 28,
    parse_options: None,
    opt_table: None,
    set_hlen: None,
    bind_next: None,
    bind_next_bytes: None,
    content_len: None,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldValue;
    use crate::packet::Packet;

    /// RFC 826 who-has 10.0.0.2, tell 10.0.0.1.
    fn who_has() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0x00, 0x01]);
        v.extend_from_slice(&[0x08, 0x00]);
        v.push(6);
        v.push(4);
        v.extend_from_slice(&[0x00, 0x01]);
        v.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        v.extend_from_slice(&[10, 0, 0, 1]);
        v.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        v.extend_from_slice(&[10, 0, 0, 2]);
        v
    }

    #[test]
    fn dissects_rfc826_request() {
        let buf = who_has();
        assert_eq!(buf.len(), 28);
        let p = Packet::dissect(buf, ProtoId::Arp);
        assert_eq!(p.layers()[0].proto, ProtoId::Arp);
        assert_eq!(p.get(0, "hwtype").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(0, "ptype").unwrap(), FieldValue::Uint(0x0800));
        assert_eq!(p.get(0, "hwlen").unwrap(), FieldValue::Uint(6));
        assert_eq!(p.get(0, "plen").unwrap(), FieldValue::Uint(4));
        assert_eq!(p.get(0, "op").unwrap(), FieldValue::Uint(1));
        assert_eq!(
            p.get(0, "hwsrc").unwrap(),
            FieldValue::Mac([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
        assert_eq!(p.get(0, "psrc").unwrap(), FieldValue::Ipv4([10, 0, 0, 1]));
        assert_eq!(p.get(0, "hwdst").unwrap(), FieldValue::Mac([0; 6]));
        assert_eq!(p.get(0, "pdst").unwrap(), FieldValue::Ipv4([10, 0, 0, 2]));
    }

    #[test]
    fn build_defaults_then_read_back() {
        let mut p = Packet::build(&[ProtoId::Ether, ProtoId::Arp]);
        assert_eq!(p.get(0, "type").unwrap(), FieldValue::Uint(0x0806));
        assert_eq!(p.get(1, "hwtype").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(1, "ptype").unwrap(), FieldValue::Uint(0x0800));
        assert_eq!(p.get(1, "hwlen").unwrap(), FieldValue::Uint(6));
        assert_eq!(p.get(1, "plen").unwrap(), FieldValue::Uint(4));
        assert_eq!(p.get(1, "op").unwrap(), FieldValue::Uint(1));

        assert!(p.set_uint(1, "op", OP_IS_AT));
        assert!(p.set_bytes(1, "hwsrc", &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        assert!(p.set_bytes(1, "psrc", &[192, 168, 1, 1]));
        assert!(p.set_bytes(1, "pdst", &[192, 168, 1, 2]));

        let bytes = p.to_bytes().to_vec();
        assert_eq!(bytes.len(), 14 + 28);
        let q = Packet::dissect(bytes, ProtoId::Ether);
        assert_eq!(q.layers()[1].proto, ProtoId::Arp);
        assert_eq!(q.get(1, "op").unwrap(), FieldValue::Uint(2));
        assert_eq!(
            q.get(1, "hwsrc").unwrap(),
            FieldValue::Mac([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(
            q.get(1, "psrc").unwrap(),
            FieldValue::Ipv4([192, 168, 1, 1])
        );
        assert_eq!(
            q.get(1, "pdst").unwrap(),
            FieldValue::Ipv4([192, 168, 1, 2])
        );
    }

    #[test]
    fn truncated_input_is_raw_not_panic() {
        for n in 0..28usize {
            let p = Packet::dissect(who_has()[..n].to_vec(), ProtoId::Arp);
            assert!(p.layers().iter().all(|s| s.proto == ProtoId::Raw));
            assert_eq!(header_len(&who_has()[..n]), 28);
            assert_eq!(next(&who_has()[..n]), Next::End);
        }
    }

    #[test]
    fn carries_no_payload() {
        assert_eq!(next(&who_has()), Next::End);
        let mut framed = who_has();
        framed.extend_from_slice(&[0u8; 18]);
        let p = Packet::dissect(framed, ProtoId::Arp);
        assert_eq!(p.layers().len(), 1);
        assert_eq!(p.layers()[0].hlen, 28);
    }
}
