//! MPLS label stack entries from RFC 3032 §2.1: a 20-bit label, 3 bits RFC 3032
//! called Experimental Use and RFC 5462 renamed Traffic Class, the
//! bottom-of-stack bit, and a TTL. EtherType values 0x8847 and 0x8848 come from
//! the IANA "ETHER TYPES" registry.

use crate::field::FieldDesc;
use crate::proto::{fixed_len, Next, ProtoDesc, ProtoId};

use super::ipv4::from_ip_version;

pub static FIELDS: &[FieldDesc] = &[
    FieldDesc::uint("label", 0, 20, 3),
    FieldDesc::uint("cos", 20, 3, 0),
    FieldDesc::uint("s", 23, 1, 1),
    FieldDesc::uint("ttl", 24, 8, 0),
];

/// RFC 3032 carries no protocol field: what follows the bottom of the stack is
/// agreed out of band, so there is nothing in the packet that names it. The
/// first nibble is the only signal, and RFC 4385 §3 is what makes it one — a
/// pseudowire control word starts with four zero bits precisely so that 4 and 6
/// can mean an IP version. Everything else is read as an Ethernet pseudowire
/// (RFC 4448 §4.6) with no control word, which is a guess, not a reading; a
/// zero nibble is the control word itself, which has no layer here, so it stays
/// `Raw` rather than becoming a frame shifted by four octets.
fn next(hdr: &[u8]) -> Next {
    if hdr.len() < 4 {
        return Next::Raw;
    }
    if hdr[2] & 0x01 == 0 {
        return Next::Proto(ProtoId::Mpls);
    }
    match (from_ip_version(hdr.get(4)), hdr.get(4)) {
        (Some(n), _) => n,
        (None, Some(0..=0x0f) | None) => Next::Raw,
        (None, Some(_)) => Next::Proto(ProtoId::Ether),
    }
}

fn bind_next(hdr: &mut [u8], p: ProtoId) {
    if let Some(b) = hdr.get_mut(2) {
        *b = (*b & 0xfe) | u8::from(p != ProtoId::Mpls);
    }
}

pub static DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Mpls,
    name: "MPLS",
    fields: FIELDS,
    min_len: 4,
    header_len: fixed_len,
    next,
    build_len: 4,
    parse_options: None,
    opt_table: None,
    set_hlen: None,
    bind_next: Some(bind_next),
    bind_next_bytes: None,
    content_len: None,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldValue;
    use crate::packet::Packet;

    const IP20: &[u8] = &[
        0x45, 0x00, 0x00, 0x14, 0x00, 0x02, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 192, 168, 1, 1,
        192, 168, 1, 2,
    ];

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        v.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        v.extend_from_slice(&[0x88, 0x47]);
        v.extend_from_slice(payload);
        v
    }

    /// RFC 3032 §2.1: the label occupies the top 20 bits, so label 16 with TC 0
    /// and the bottom-of-stack bit set is 00 01 01.
    #[test]
    fn a_single_label_reaches_the_datagram() {
        let mut v = frame(&[0x00, 0x01, 0x01, 0x40]);
        v.extend_from_slice(IP20);
        let p = Packet::dissect(v, ProtoId::Ether);
        assert_eq!(
            p.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![ProtoId::Ether, ProtoId::Mpls, ProtoId::Ipv4]
        );
        assert_eq!(p.get(1, "label").unwrap(), FieldValue::Uint(16));
        assert_eq!(p.get(1, "s").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(1, "ttl").unwrap(), FieldValue::Uint(64));
        assert_eq!(p.get(2, "src").unwrap(), FieldValue::Ipv4([192, 168, 1, 1]));
    }

    #[test]
    fn a_stack_is_walked_to_its_bottom() {
        let mut v = frame(&[0x00, 0x01, 0x00, 0x40]);
        v.extend_from_slice(&[0x00, 0x02, 0x00, 0x40]);
        v.extend_from_slice(&[0x00, 0x03, 0x01, 0x40]);
        v.extend_from_slice(IP20);
        let p = Packet::dissect(v, ProtoId::Ether);
        assert_eq!(
            p.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![
                ProtoId::Ether,
                ProtoId::Mpls,
                ProtoId::Mpls,
                ProtoId::Mpls,
                ProtoId::Ipv4
            ]
        );
        assert_eq!(p.get(3, "label").unwrap(), FieldValue::Uint(48));
    }

    #[test]
    fn a_pseudowire_frame_is_read_as_ethernet() {
        let mut v = frame(&[0x00, 0x01, 0x01, 0x40]);
        v.extend_from_slice(&[0x33; 6]);
        v.extend_from_slice(&[0x44; 6]);
        v.extend_from_slice(&[0x08, 0x00]);
        v.extend_from_slice(IP20);
        let p = Packet::dissect(v, ProtoId::Ether);
        assert_eq!(
            p.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![ProtoId::Ether, ProtoId::Mpls, ProtoId::Ether, ProtoId::Ipv4]
        );
        assert_eq!(p.get(2, "type").unwrap(), FieldValue::Uint(0x0800));
    }

    #[test]
    fn a_payload_that_names_no_version_stays_raw() {
        let mut v = frame(&[0x00, 0x01, 0x01, 0x40]);
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0xde, 0xad]);
        let p = Packet::dissect(v, ProtoId::Ether);
        assert_eq!(p.layers()[2].proto, ProtoId::Raw);
    }

    #[test]
    fn truncated_input_does_not_panic() {
        let mut full = frame(&[0x00, 0x01, 0x00, 0x40]);
        full.extend_from_slice(&[0x00, 0x02, 0x01, 0x40]);
        full.extend_from_slice(IP20);
        for cut in 0..full.len() {
            let mut p = Packet::dissect(full[..cut].to_vec(), ProtoId::Ether);
            assert_eq!(p.to_bytes(), &full[..cut]);
        }
        assert_eq!(next(&[0x00, 0x01, 0x01]), Next::Raw);
        assert_eq!(next(&[0x00, 0x01, 0x01, 0x40]), Next::Raw);
    }

    #[test]
    fn building_a_stack_sets_the_bottom_bit_only_on_the_last_entry() {
        let mut p = Packet::build(&[
            ProtoId::Ether,
            ProtoId::Mpls,
            ProtoId::Mpls,
            ProtoId::Ipv4,
            ProtoId::Udp,
        ]);
        assert_eq!(p.get(0, "type").unwrap(), FieldValue::Uint(0x8847));
        assert_eq!(p.get(1, "s").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(2, "s").unwrap(), FieldValue::Uint(1));
        assert!(p.set_uint(1, "label", 16));
        assert!(p.set_uint(2, "label", 100));

        let back = Packet::dissect(p.to_bytes().to_vec(), ProtoId::Ether);
        assert_eq!(
            back.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![
                ProtoId::Ether,
                ProtoId::Mpls,
                ProtoId::Mpls,
                ProtoId::Ipv4,
                ProtoId::Udp
            ]
        );
        assert_eq!(back.get(2, "label").unwrap(), FieldValue::Uint(100));
    }
}
