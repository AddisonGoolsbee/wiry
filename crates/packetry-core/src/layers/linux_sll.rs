//! LINKTYPE_LINUX_SLL (113) and LINKTYPE_LINUX_SLL2 (276) from the tcpdump
//! link-layer header type registry: the cooked headers libpcap synthesises for
//! a capture on the Linux `any` device, where frames from interfaces with
//! different link layers share one file. Both are big-endian.
//!
//! SLL is 16 octets: packet type, ARPHRD_ type, address length, an 8-octet
//! address field padded to that width, then a protocol type. SLL2 is 20 and
//! leads with the protocol type instead.

use crate::field::FieldDesc;
use crate::proto::{ethertype, Next, ProtoDesc, ProtoId};

pub static FIELDS: &[FieldDesc] = &[
    FieldDesc::uint("pkttype", 0, 16, 0),
    FieldDesc::uint("lladdrtype", 16, 16, 1),
    FieldDesc::uint("lladdrlen", 32, 16, 6),
    FieldDesc::bytes("src", 48, 64),
    FieldDesc::uint("proto", 112, 16, ethertype::IPV4 as u64),
];

pub static FIELDS_V2: &[FieldDesc] = &[
    FieldDesc::uint("proto", 0, 16, ethertype::IPV4 as u64),
    FieldDesc::uint("reserved", 16, 16, 0),
    FieldDesc::uint("ifindex", 32, 32, 0),
    FieldDesc::uint("lladdrtype", 64, 16, 1),
    FieldDesc::uint("pkttype", 80, 8, 0),
    FieldDesc::uint("lladdrlen", 88, 8, 6),
    FieldDesc::bytes("src", 96, 64),
];

/// Values below 1536 are not EtherTypes but the LINUX_SLL_P_* selectors for
/// 802.2/802.3 framing, which this build does not dissect.
fn proto_next(v: u16) -> Next {
    match v {
        ethertype::IPV4 => Next::Proto(ProtoId::Ipv4),
        ethertype::IPV6 => Next::Proto(ProtoId::Ipv6),
        ethertype::ARP => Next::Proto(ProtoId::Arp),
        ethertype::DOT1Q => Next::Proto(ProtoId::Dot1Q),
        _ => Next::Raw,
    }
}

fn ethertype_of(p: ProtoId) -> Option<u16> {
    match p {
        ProtoId::Ipv4 => Some(ethertype::IPV4),
        ProtoId::Ipv6 => Some(ethertype::IPV6),
        ProtoId::Arp => Some(ethertype::ARP),
        ProtoId::Dot1Q => Some(ethertype::DOT1Q),
        _ => None,
    }
}

fn header_len(_: &[u8]) -> usize {
    16
}

fn next(hdr: &[u8]) -> Next {
    match hdr.get(14..16) {
        Some(b) => proto_next(u16::from_be_bytes([b[0], b[1]])),
        None => Next::Raw,
    }
}

fn bind_next(hdr: &mut [u8], p: ProtoId) {
    if let (Some(t), true) = (ethertype_of(p), hdr.len() >= 16) {
        hdr[14..16].copy_from_slice(&t.to_be_bytes());
    }
}

fn header_len_v2(_: &[u8]) -> usize {
    20
}

fn next_v2(hdr: &[u8]) -> Next {
    match hdr.get(0..2) {
        Some(b) => proto_next(u16::from_be_bytes([b[0], b[1]])),
        None => Next::Raw,
    }
}

fn bind_next_v2(hdr: &mut [u8], p: ProtoId) {
    if let (Some(t), true) = (ethertype_of(p), hdr.len() >= 20) {
        hdr[0..2].copy_from_slice(&t.to_be_bytes());
    }
}

pub static DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::LinuxSll,
    name: "CookedLinux",
    fields: FIELDS,
    min_len: 16,
    header_len,
    next,
    build_len: 16,
    parse_options: None,
    opt_table: None,
    set_hlen: None,
    bind_next: Some(bind_next),
    bind_next_bytes: None,
    content_len: None,
};

pub static DESC_V2: ProtoDesc = ProtoDesc {
    id: ProtoId::LinuxSll2,
    name: "CookedLinuxV2",
    fields: FIELDS_V2,
    min_len: 20,
    header_len: header_len_v2,
    next: next_v2,
    build_len: 20,
    parse_options: None,
    opt_table: None,
    set_hlen: None,
    bind_next: Some(bind_next_v2),
    bind_next_bytes: None,
    content_len: None,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldValue;
    use crate::packet::Packet;

    /// IPv4/UDP, 10.0.0.1:1024 -> 10.0.0.2:53, no payload.
    const IPV4_UDP: &[u8] = &[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 17, 0x00, 0x00, 10, 0, 0, 1, 10, 0,
        0, 2, 0x04, 0x00, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00,
    ];

    /// Packet type 0 (host), ARPHRD_ETHER, 6-octet address 00:11:22:33:44:55.
    fn sll(proto: u16) -> Vec<u8> {
        let mut v = vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x06];
        v.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00]);
        v.extend_from_slice(&proto.to_be_bytes());
        v
    }

    fn sll2(proto: u16) -> Vec<u8> {
        let mut v = proto.to_be_bytes().to_vec();
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x06]);
        v.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00]);
        v
    }

    #[test]
    fn dissects_a_cooked_ipv4_frame() {
        let mut v = sll(ethertype::IPV4);
        v.extend_from_slice(IPV4_UDP);
        let p = Packet::dissect(v, ProtoId::LinuxSll);
        assert_eq!(
            p.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![ProtoId::LinuxSll, ProtoId::Ipv4, ProtoId::Udp]
        );
        assert_eq!(p.get(0, "pkttype").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(0, "lladdrtype").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(0, "lladdrlen").unwrap(), FieldValue::Uint(6));
        assert_eq!(
            p.get(0, "src").unwrap(),
            FieldValue::Bytes(vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00])
        );
        assert_eq!(p.get(0, "proto").unwrap(), FieldValue::Uint(0x0800));
        assert_eq!(p.get(2, "dport").unwrap(), FieldValue::Uint(53));
    }

    #[test]
    fn dissects_a_cooked_v2_ipv4_frame() {
        let mut v = sll2(ethertype::IPV4);
        v.extend_from_slice(IPV4_UDP);
        let p = Packet::dissect(v, ProtoId::LinuxSll2);
        assert_eq!(
            p.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![ProtoId::LinuxSll2, ProtoId::Ipv4, ProtoId::Udp]
        );
        assert_eq!(p.get(0, "ifindex").unwrap(), FieldValue::Uint(2));
        assert_eq!(p.get(0, "lladdrlen").unwrap(), FieldValue::Uint(6));
        assert_eq!(p.get(1, "dst").unwrap(), FieldValue::Ipv4([10, 0, 0, 2]));
    }

    #[test]
    fn dispatches_on_the_protocol_field() {
        for (t, want) in [
            (ethertype::IPV6, ProtoId::Ipv6),
            (ethertype::ARP, ProtoId::Arp),
            (ethertype::DOT1Q, ProtoId::Dot1Q),
            // LINUX_SLL_P_802_2, not an EtherType.
            (0x0004, ProtoId::Raw),
        ] {
            let mut v = sll(t);
            v.extend_from_slice(&[0u8; 40]);
            assert_eq!(
                Packet::dissect(v, ProtoId::LinuxSll).layers()[1].proto,
                want
            );
            let mut v = sll2(t);
            v.extend_from_slice(&[0u8; 40]);
            assert_eq!(
                Packet::dissect(v, ProtoId::LinuxSll2).layers()[1].proto,
                want
            );
        }
    }

    #[test]
    fn a_clipped_cooked_header_does_not_panic() {
        for n in 0..16 {
            let p = Packet::dissect(sll(ethertype::IPV4)[..n].to_vec(), ProtoId::LinuxSll);
            assert!(p.layers().iter().all(|s| s.proto == ProtoId::Raw));
        }
        for n in 0..20 {
            let p = Packet::dissect(sll2(ethertype::IPV4)[..n].to_vec(), ProtoId::LinuxSll2);
            assert!(p.layers().iter().all(|s| s.proto == ProtoId::Raw));
        }
    }

    #[test]
    fn stacking_writes_the_protocol_back() {
        for (link, want) in [(ProtoId::LinuxSll, 16usize), (ProtoId::LinuxSll2, 20)] {
            let mut p = Packet::build(&[link, ProtoId::Ipv6]);
            assert_eq!(p.layers()[0].hlen as usize, want);
            let bytes = p.to_bytes().to_vec();
            let back = Packet::dissect(bytes, link);
            assert_eq!(back.layers()[1].proto, ProtoId::Ipv6);
        }
    }

    #[test]
    fn the_registry_link_types_map_to_these_layers() {
        use crate::pcap::{link_to_proto, linktype};
        assert_eq!(link_to_proto(linktype::LINUX_SLL), ProtoId::LinuxSll);
        assert_eq!(link_to_proto(linktype::LINUX_SLL2), ProtoId::LinuxSll2);
    }
}
