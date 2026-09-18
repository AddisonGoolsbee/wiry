//! VXLAN from RFC 7348 §5: an 8-octet header over UDP whose payload is a whole
//! Ethernet frame. The destination port is the IANA-assigned 4789; the source
//! port is a flow hash, so it names nothing.

use crate::field::FieldDesc;
use crate::proto::{fixed_len, frame_next, ProtoDesc, ProtoId};

/// RFC 7348 §5 defines only the I bit (0x08) of `flags`, and the VNI means
/// nothing unless it is set; the rest is reserved and must be transmitted zero.
pub static FIELDS: &[FieldDesc] = &[
    FieldDesc::uint("flags", 0, 8, 0x08),
    FieldDesc::uint("reserved0", 8, 24, 0),
    FieldDesc::uint("vni", 32, 24, 0),
    FieldDesc::uint("reserved1", 56, 8, 0),
];

pub static DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Vxlan,
    name: "VXLAN",
    fields: FIELDS,
    min_len: 8,
    header_len: fixed_len,
    next: frame_next,
    build_len: 8,
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
    use crate::proto::ports;

    fn udp_frame(dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        v.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        v.extend_from_slice(&[0x08, 0x00]);
        let total = (20 + 8 + payload.len()) as u16;
        v.extend_from_slice(&[0x45, 0x00]);
        v.extend_from_slice(&total.to_be_bytes());
        v.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x40, 17, 0x00, 0x00]);
        v.extend_from_slice(&[10, 0, 0, 1]);
        v.extend_from_slice(&[10, 0, 0, 2]);
        v.extend_from_slice(&[0xc0, 0x00]);
        v.extend_from_slice(&dport.to_be_bytes());
        v.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        v.extend_from_slice(&[0x00, 0x00]);
        v.extend_from_slice(payload);
        v
    }

    fn inner() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0xaa; 6]);
        v.extend_from_slice(&[0xbb; 6]);
        v.extend_from_slice(&[0x08, 0x00]);
        v.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x14, 0x00, 0x02, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 192, 168, 1, 1,
            192, 168, 1, 2,
        ]);
        v
    }

    #[test]
    fn a_tunnelled_frame_reaches_the_inner_addresses() {
        let mut payload = vec![0x08, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00];
        payload.extend_from_slice(&inner());
        let p = Packet::dissect(udp_frame(ports::VXLAN, &payload), ProtoId::Ether);
        assert_eq!(
            p.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![
                ProtoId::Ether,
                ProtoId::Ipv4,
                ProtoId::Udp,
                ProtoId::Vxlan,
                ProtoId::Ether,
                ProtoId::Ipv4,
            ]
        );
        assert_eq!(p.get(3, "vni").unwrap(), FieldValue::Uint(0x1234));
        assert_eq!(p.get(3, "flags").unwrap(), FieldValue::Uint(0x08));
        assert_eq!(p.get(1, "src").unwrap(), FieldValue::Ipv4([10, 0, 0, 1]));
        assert_eq!(p.get(5, "src").unwrap(), FieldValue::Ipv4([192, 168, 1, 1]));
    }

    #[test]
    fn another_port_is_not_a_tunnel() {
        let mut payload = vec![0x08, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00];
        payload.extend_from_slice(&inner());
        let p = Packet::dissect(udp_frame(9999, &payload), ProtoId::Ether);
        assert_eq!(p.layers()[3].proto, ProtoId::Raw);
    }

    #[test]
    fn truncated_input_does_not_panic() {
        let mut payload = vec![0x08, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00];
        payload.extend_from_slice(&inner());
        let full = udp_frame(ports::VXLAN, &payload);
        for cut in 0..full.len() {
            let mut p = Packet::dissect(full[..cut].to_vec(), ProtoId::Ether);
            assert_eq!(p.to_bytes(), &full[..cut]);
        }
    }

    #[test]
    fn builds_a_tunnel_that_dissects_back() {
        let mut p = Packet::build(&[
            ProtoId::Ether,
            ProtoId::Ipv4,
            ProtoId::Udp,
            ProtoId::Vxlan,
            ProtoId::Ether,
            ProtoId::Ipv4,
            ProtoId::Udp,
        ]);
        assert_eq!(
            p.get(2, "dport").unwrap(),
            FieldValue::Uint(ports::VXLAN as u64)
        );
        assert!(p.set_uint(3, "vni", 4095));
        let bytes = p.to_bytes().to_vec();

        let back = Packet::dissect(bytes, ProtoId::Ether);
        assert_eq!(
            back.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![
                ProtoId::Ether,
                ProtoId::Ipv4,
                ProtoId::Udp,
                ProtoId::Vxlan,
                ProtoId::Ether,
                ProtoId::Ipv4,
                ProtoId::Udp,
            ]
        );
        assert_eq!(back.get(3, "vni").unwrap(), FieldValue::Uint(4095));
        // RFC 791 §3.1: the inner header's length covers only what it encloses.
        assert_eq!(back.get(5, "len").unwrap(), FieldValue::Uint(28));
        assert_eq!(
            back.get(1, "len").unwrap(),
            FieldValue::Uint(20 + 8 + 8 + 42)
        );
    }
}
