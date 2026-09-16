//! IEEE 802.1Q VLAN tag. Layout from IEEE Std 802.1Q clause 9 (VLAN Tag):
//! a 16-bit Tag Protocol Identifier, carried in the frame as the EtherType
//! 0x8100, followed by the 16-bit Tag Control Information — 3-bit Priority Code
//! Point, 1-bit Drop Eligible Indicator (the Canonical Format Indicator of
//! 802.1Q-1998), and 12-bit VLAN Identifier. The inner EtherType follows.
//! EtherType values from the IANA "ETHER TYPES" registry.
//!
//! The TPID belongs to the enclosing Ethernet header's type field, so this
//! layer starts at the TCI and is 4 bytes long: TCI plus inner EtherType.

use crate::field::FieldDesc;
use crate::proto::{ethertype, Next, ProtoDesc, ProtoId};

pub static FIELDS: &[FieldDesc] = &[
    FieldDesc::uint("prio", 0, 3, 0),
    FieldDesc::uint("id", 3, 1, 0),
    FieldDesc::uint("vlan", 4, 12, 1),
    FieldDesc::uint("type", 16, 16, ethertype::IPV4 as u64),
];

fn header_len(_: &[u8]) -> usize {
    4
}

fn next(hdr: &[u8]) -> Next {
    if hdr.len() < 4 {
        return Next::Raw;
    }
    match u16::from_be_bytes([hdr[2], hdr[3]]) {
        ethertype::IPV4 => Next::Proto(ProtoId::Ipv4),
        ethertype::IPV6 => Next::Proto(ProtoId::Ipv6),
        ethertype::ARP => Next::Proto(ProtoId::Arp),
        // 0x8100 inside a tag is a second tag: QinQ / 802.1ad stacking.
        ethertype::DOT1Q => Next::Proto(ProtoId::Dot1Q),
        _ => Next::Raw,
    }
}

/// Stacking a layer under a VLAN tag sets the inner EtherType to match it.
fn bind_next(hdr: &mut [u8], p: ProtoId) {
    let t = match p {
        ProtoId::Ipv4 => ethertype::IPV4,
        ProtoId::Ipv6 => ethertype::IPV6,
        ProtoId::Arp => ethertype::ARP,
        ProtoId::Dot1Q => ethertype::DOT1Q,
        _ => return,
    };
    if hdr.len() >= 4 {
        hdr[2..4].copy_from_slice(&t.to_be_bytes());
    }
}

pub static DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Dot1Q,
    name: "Dot1Q",
    fields: FIELDS,
    min_len: 4,
    header_len,
    next,
    build_len: 4,
    parse_options: None,
    bind_next: Some(bind_next),
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldValue;
    use crate::packet::Packet;

    /// Ethernet frame carrying one VLAN tag: PCP 3, DEI 0, VID 100, inner IPv4.
    /// TCI = 011 0 0000 0110 0100 = 0x6064.
    fn tagged() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst mac
        v.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // src mac
        v.extend_from_slice(&[0x81, 0x00]); // TPID
        v.extend_from_slice(&[0x60, 0x64]); // TCI
        v.extend_from_slice(&[0x08, 0x00]); // inner EtherType: IPv4
                                            // Minimal IPv4 header, 20 bytes, ihl 5.
        v.extend_from_slice(&[0x45, 0x00, 0x00, 0x14]);
        v.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        v.extend_from_slice(&[0x40, 0x06, 0x00, 0x00]);
        v.extend_from_slice(&[10, 0, 0, 1]);
        v.extend_from_slice(&[10, 0, 0, 2]);
        v
    }

    #[test]
    fn dissects_hand_built_tag() {
        let p = Packet::dissect(tagged(), ProtoId::Ether);
        let got: Vec<_> = p.layers().iter().map(|s| s.proto).collect();
        assert_eq!(got, vec![ProtoId::Ether, ProtoId::Dot1Q, ProtoId::Ipv4]);
        assert_eq!(p.layers()[1].hlen, 4);
        assert_eq!(p.get(1, "prio").unwrap(), FieldValue::Uint(3));
        assert_eq!(p.get(1, "id").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(1, "vlan").unwrap(), FieldValue::Uint(100));
        assert_eq!(p.get(1, "type").unwrap(), FieldValue::Uint(0x0800));
        assert_eq!(p.get(2, "src").unwrap(), FieldValue::Ipv4([10, 0, 0, 1]));
    }

    #[test]
    fn build_then_read_back() {
        let mut p = Packet::build(&[ProtoId::Ether, ProtoId::Dot1Q, ProtoId::Ipv4]);
        assert_eq!(p.get(0, "type").unwrap(), FieldValue::Uint(0x8100));
        assert_eq!(p.get(1, "type").unwrap(), FieldValue::Uint(0x0800));

        assert!(p.set_uint(1, "prio", 7));
        assert!(p.set_uint(1, "id", 1));
        assert!(p.set_uint(1, "vlan", 4095));

        let bytes = p.to_bytes().to_vec();
        assert_eq!(bytes[14..16], [0xff, 0xff]); // 111 1 1111 1111 1111
        let q = Packet::dissect(bytes, ProtoId::Ether);
        assert_eq!(q.get(1, "prio").unwrap(), FieldValue::Uint(7));
        assert_eq!(q.get(1, "id").unwrap(), FieldValue::Uint(1));
        assert_eq!(q.get(1, "vlan").unwrap(), FieldValue::Uint(4095));
        assert_eq!(q.layers()[2].proto, ProtoId::Ipv4);
    }

    #[test]
    fn next_dispatches_on_inner_ethertype() {
        let hdr = |t: [u8; 2]| [0x60, 0x64, t[0], t[1]];
        assert_eq!(next(&hdr([0x08, 0x00])), Next::Proto(ProtoId::Ipv4));
        assert_eq!(next(&hdr([0x86, 0xdd])), Next::Proto(ProtoId::Ipv6));
        assert_eq!(next(&hdr([0x08, 0x06])), Next::Proto(ProtoId::Arp));
        assert_eq!(next(&hdr([0x81, 0x00])), Next::Proto(ProtoId::Dot1Q));
        assert_eq!(next(&hdr([0x88, 0x47])), Next::Raw); // MPLS: unimplemented
    }

    #[test]
    fn stacked_tags_nest() {
        let mut v = Vec::new();
        v.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        v.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        v.extend_from_slice(&[0x81, 0x00]);
        v.extend_from_slice(&[0x20, 0x0a, 0x81, 0x00]); // outer: PCP 1, VID 10
        v.extend_from_slice(&[0x00, 0x14, 0x08, 0x06]); // inner: PCP 0, VID 20
        v.extend_from_slice(&[0u8; 28]); // ARP body, contents irrelevant here
        let p = Packet::dissect(v, ProtoId::Ether);
        let got: Vec<_> = p.layers().iter().map(|s| s.proto).collect();
        assert_eq!(
            got,
            vec![ProtoId::Ether, ProtoId::Dot1Q, ProtoId::Dot1Q, ProtoId::Arp]
        );
        assert_eq!(p.get(1, "vlan").unwrap(), FieldValue::Uint(10));
        assert_eq!(p.get(2, "vlan").unwrap(), FieldValue::Uint(20));
    }

    #[test]
    fn truncated_tag_is_raw_not_panic() {
        assert_eq!(next(&[]), Next::Raw);
        assert_eq!(next(&[0x60, 0x64, 0x08]), Next::Raw);
        assert_eq!(header_len(&[0x60]), 4);
        for n in 14..18usize {
            let p = Packet::dissect(tagged()[..n].to_vec(), ProtoId::Ether);
            assert_eq!(p.layers()[0].proto, ProtoId::Ether);
            assert!(p.layers()[1..].iter().all(|s| s.proto == ProtoId::Raw));
        }
    }
}
