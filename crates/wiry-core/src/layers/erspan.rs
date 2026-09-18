//! ERSPAN Type II and Type III from draft-foschiano-erspan-03 §4 and §5: a GRE
//! tunnel carrying a mirrored Ethernet frame, reached through EtherType 0x88BE
//! or 0x22EB.
//!
//! Type I has no header of its own — GRE 0x88BE with the sequence bit clear is
//! the mirrored frame directly — so there is no layer here for it; `gre::next`
//! stacks `Ether` instead (DEVIATIONS.md E6).

use crate::field::FieldDesc;
use crate::proto::{fixed_len, frame_next, ProtoDesc, ProtoId};

pub static FIELDS_II: &[FieldDesc] = &[
    FieldDesc::uint("ver", 0, 4, 1),
    FieldDesc::uint("vlan", 4, 12, 0),
    FieldDesc::uint("cos", 16, 3, 0),
    FieldDesc::uint("en", 19, 2, 0),
    FieldDesc::uint("t", 21, 1, 0),
    FieldDesc::uint("session_id", 22, 10, 0),
    FieldDesc::uint("reserved", 32, 12, 0),
    FieldDesc::uint("index", 44, 20, 0),
];

pub static DESC_II: ProtoDesc = ProtoDesc {
    id: ProtoId::ErspanII,
    name: "ERSPAN_II",
    fields: FIELDS_II,
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

/// draft-foschiano-erspan-03 §5: the O bit brings an 8-octet platform-specific
/// subheader that the flat field table cannot name field by field, so it is
/// carried whole.
fn has_subheader(hdr: &[u8]) -> bool {
    hdr.get(11).is_some_and(|b| b & 0x01 != 0)
}

pub static FIELDS_III: &[FieldDesc] = &[
    FieldDesc::uint("ver", 0, 4, 2),
    FieldDesc::uint("vlan", 4, 12, 0),
    FieldDesc::uint("cos", 16, 3, 0),
    FieldDesc::uint("bso", 19, 2, 0),
    FieldDesc::uint("t", 21, 1, 0),
    FieldDesc::uint("session_id", 22, 10, 0),
    FieldDesc::uint("timestamp", 32, 32, 0),
    FieldDesc::uint("sgt", 64, 16, 0),
    FieldDesc::uint("p", 80, 1, 0),
    FieldDesc::uint("ft", 81, 5, 0),
    FieldDesc::uint("hwid", 86, 6, 0),
    FieldDesc::uint("d", 92, 1, 0),
    FieldDesc::uint("gra", 93, 2, 0),
    FieldDesc::uint("o", 95, 1, 0),
    FieldDesc::bytes("platform", 96, 64).when(has_subheader),
];

fn header_len_iii(hdr: &[u8]) -> usize {
    if has_subheader(hdr) {
        20
    } else {
        12
    }
}

pub static DESC_III: ProtoDesc = ProtoDesc {
    id: ProtoId::ErspanIII,
    name: "ERSPAN_III",
    fields: FIELDS_III,
    min_len: 12,
    header_len: header_len_iii,
    next: frame_next,
    build_len: 12,
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
    use crate::proto::{ethertype, ipproto};

    fn mirrored() -> Vec<u8> {
        let mut v = vec![0xaa; 6];
        v.extend_from_slice(&[0xbb; 6]);
        v.extend_from_slice(&[0x08, 0x00]);
        v.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x14, 0x00, 0x02, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 192, 168, 1, 1,
            192, 168, 1, 2,
        ]);
        v
    }

    fn over_gre(etype: u16, seq: bool, payload: &[u8]) -> Vec<u8> {
        let mut gre = vec![if seq { 0x10 } else { 0x00 }, 0x00];
        gre.extend_from_slice(&etype.to_be_bytes());
        if seq {
            gre.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        }
        gre.extend_from_slice(payload);

        let mut v = vec![0x45, 0x00];
        v.extend_from_slice(&((20 + gre.len()) as u16).to_be_bytes());
        v.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x40, ipproto::GRE, 0x00, 0x00]);
        v.extend_from_slice(&[10, 0, 0, 1]);
        v.extend_from_slice(&[10, 0, 0, 2]);
        v.extend_from_slice(&gre);
        v
    }

    #[test]
    fn type_two_carries_the_mirrored_frame() {
        let mut hdr = vec![0x10, 0x64, 0x00, 0x05];
        hdr.extend_from_slice(&[0x00, 0x00, 0x00, 0x09]);
        hdr.extend_from_slice(&mirrored());
        let p = Packet::dissect(over_gre(ethertype::ERSPAN_II, true, &hdr), ProtoId::Ipv4);
        assert_eq!(
            p.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![
                ProtoId::Ipv4,
                ProtoId::Gre,
                ProtoId::ErspanII,
                ProtoId::Ether,
                ProtoId::Ipv4
            ]
        );
        assert_eq!(p.get(2, "ver").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(2, "vlan").unwrap(), FieldValue::Uint(100));
        assert_eq!(p.get(2, "session_id").unwrap(), FieldValue::Uint(5));
        assert_eq!(p.get(2, "index").unwrap(), FieldValue::Uint(9));
        assert_eq!(p.get(4, "src").unwrap(), FieldValue::Ipv4([192, 168, 1, 1]));
    }

    #[test]
    fn type_one_has_no_header_of_its_own() {
        let p = Packet::dissect(
            over_gre(ethertype::ERSPAN_II, false, &mirrored()),
            ProtoId::Ipv4,
        );
        assert_eq!(
            p.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![ProtoId::Ipv4, ProtoId::Gre, ProtoId::Ether, ProtoId::Ipv4]
        );
    }

    #[test]
    fn the_o_bit_brings_a_platform_subheader() {
        for (o, want) in [(0u8, 12u32), (1, 20)] {
            let mut hdr = vec![0x20, 0x64, 0x00, 0x05];
            hdr.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
            hdr.extend_from_slice(&[0x00, 0x00, 0x00, o]);
            if o == 1 {
                hdr.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0]);
            }
            hdr.extend_from_slice(&mirrored());
            let p = Packet::dissect(over_gre(ethertype::ERSPAN_III, false, &hdr), ProtoId::Ipv4);
            assert_eq!(p.layers()[2].proto, ProtoId::ErspanIII);
            assert_eq!(p.layers()[2].hlen, want, "o={o}");
            assert_eq!(
                p.get(2, "timestamp").unwrap(),
                FieldValue::Uint(0x1122_3344)
            );
            assert_eq!(p.get(2, "o").unwrap(), FieldValue::Uint(o as u64));
            assert_eq!(p.layers()[3].proto, ProtoId::Ether);
        }
    }

    #[test]
    fn truncated_input_does_not_panic() {
        let mut hdr = vec![0x10, 0x64, 0x00, 0x05, 0x00, 0x00, 0x00, 0x09];
        hdr.extend_from_slice(&mirrored());
        let full = over_gre(ethertype::ERSPAN_II, true, &hdr);
        for cut in 0..full.len() {
            let mut p = Packet::dissect(full[..cut].to_vec(), ProtoId::Ipv4);
            assert_eq!(p.to_bytes(), &full[..cut]);
        }
        assert_eq!(header_len_iii(&[]), 12);
    }

    #[test]
    fn builds_a_session_that_dissects_back() {
        let mut p = Packet::build(&[
            ProtoId::Ipv4,
            ProtoId::Gre,
            ProtoId::ErspanII,
            ProtoId::Ether,
            ProtoId::Ipv4,
        ]);
        assert_eq!(
            p.get(1, "proto").unwrap(),
            FieldValue::Uint(ethertype::ERSPAN_II as u64)
        );
        // §4: Type II is told from Type I by GRE's sequence bit, so stacking one
        // sets it; without that the frame dissects back as a bare Type I.
        assert_eq!(p.get(1, "seqnum_present").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.layers()[1].hlen, 8);
        assert!(p.set_uint(2, "session_id", 1023));
        let bytes = p.to_bytes().to_vec();

        let back = Packet::dissect(bytes, ProtoId::Ipv4);
        assert_eq!(
            back.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![
                ProtoId::Ipv4,
                ProtoId::Gre,
                ProtoId::ErspanII,
                ProtoId::Ether,
                ProtoId::Ipv4
            ]
        );
        assert_eq!(back.get(2, "session_id").unwrap(), FieldValue::Uint(1023));
    }
}
