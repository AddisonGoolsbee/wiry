//! GRE from RFC 2784 §2.1, with the Key and Sequence Number extensions of
//! RFC 2890 §2. Protocol Type values come from the IANA "ETHER TYPES"
//! registry; the flag bits RFC 2784 reserves are the ones RFC 1701 §1 defined,
//! and a capture may still carry them set.
//!
//! The header is 4 octets plus one 4-octet word per flag that is set, so the
//! optional fields have no single offset: each is declared once per offset it
//! can land on, gated so that exactly one is ever live.

use crate::field::FieldDesc;
use crate::proto::{ethertype, Next, ProtoDesc, ProtoId};

fn flag(hdr: &[u8], bit: u8) -> bool {
    hdr.first().is_some_and(|b| b & (0x80 >> bit) != 0)
}

/// RFC 2784 §2.1: Checksum Present. RFC 1701's Routing Present bit brings the
/// same two octets with it, so the two are one condition everywhere.
fn has_sum(hdr: &[u8]) -> bool {
    flag(hdr, 0) || flag(hdr, 1)
}

fn has_key(hdr: &[u8]) -> bool {
    flag(hdr, 2)
}

fn has_seq(hdr: &[u8]) -> bool {
    flag(hdr, 3)
}

fn key_off(hdr: &[u8]) -> usize {
    4 + 4 * usize::from(has_sum(hdr))
}

fn seq_off(hdr: &[u8]) -> usize {
    key_off(hdr) + 4 * usize::from(has_key(hdr))
}

fn key_at_4(hdr: &[u8]) -> bool {
    has_key(hdr) && key_off(hdr) == 4
}

fn key_at_8(hdr: &[u8]) -> bool {
    has_key(hdr) && key_off(hdr) == 8
}

fn seq_at_4(hdr: &[u8]) -> bool {
    has_seq(hdr) && seq_off(hdr) == 4
}

fn seq_at_8(hdr: &[u8]) -> bool {
    has_seq(hdr) && seq_off(hdr) == 8
}

fn seq_at_12(hdr: &[u8]) -> bool {
    has_seq(hdr) && seq_off(hdr) == 12
}

pub static FIELDS: &[FieldDesc] = &[
    FieldDesc::uint("chksum_present", 0, 1, 0),
    FieldDesc::uint("routing_present", 1, 1, 0),
    FieldDesc::uint("key_present", 2, 1, 0),
    FieldDesc::uint("seqnum_present", 3, 1, 0),
    FieldDesc::uint("strict_route_source", 4, 1, 0),
    FieldDesc::uint("recursion_control", 5, 3, 0),
    FieldDesc::uint("flags", 8, 5, 0),
    FieldDesc::uint("version", 13, 3, 0),
    FieldDesc::uint("proto", 16, 16, ethertype::IPV4 as u64),
    FieldDesc::computed_uint("chksum", 32, 16).when(has_sum),
    FieldDesc::uint("offset", 48, 16, 0).when(has_sum),
    FieldDesc::uint("key", 32, 32, 0).when(key_at_4),
    FieldDesc::uint("key", 64, 32, 0).when(key_at_8),
    FieldDesc::uint("seqnum", 32, 32, 0).when(seq_at_4),
    FieldDesc::uint("seqnum", 64, 32, 0).when(seq_at_8),
    FieldDesc::uint("seqnum", 96, 32, 0).when(seq_at_12),
];

fn header_len(hdr: &[u8]) -> usize {
    seq_off(hdr) + 4 * usize::from(has_seq(hdr))
}

fn next(hdr: &[u8]) -> Next {
    if hdr.len() < 4 {
        return Next::Raw;
    }
    match u16::from_be_bytes([hdr[2], hdr[3]]) {
        // draft-foschiano-erspan-03 §4: Type II always sets the sequence bit,
        // Type I never does and carries no ERSPAN header of its own.
        ethertype::ERSPAN_II if has_seq(hdr) => Next::Proto(ProtoId::ErspanII),
        ethertype::ERSPAN_II => Next::Proto(ProtoId::Ether),
        ethertype::ERSPAN_III => Next::Proto(ProtoId::ErspanIII),
        t => super::ether::from_ethertype(t),
    }
}

fn to_ethertype(p: ProtoId) -> Option<u16> {
    Some(match p {
        ProtoId::ErspanII => ethertype::ERSPAN_II,
        ProtoId::ErspanIII => ethertype::ERSPAN_III,
        ProtoId::Ether => ethertype::TEB,
        other => return super::ether::to_ethertype(other),
    })
}

/// draft-foschiano-erspan-03 §4: the sequence bit is what tells Type II from
/// Type I, so stacking a Type II header has to set it. The word it brings is
/// appended here because `bind_next` cannot grow the header it is handed.
fn bind_next_bytes(p: ProtoId) -> &'static [u8] {
    match p {
        ProtoId::ErspanII => &[0; 4],
        _ => &[],
    }
}

fn bind_next(hdr: &mut [u8], p: ProtoId) {
    if p == ProtoId::ErspanII {
        if let Some(b) = hdr.first_mut() {
            *b |= 0x10;
        }
    }
    super::ether::bind_ethertype(hdr, 2, to_ethertype(p));
}

pub static DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Gre,
    name: "GRE",
    fields: FIELDS,
    min_len: 4,
    header_len,
    next,
    build_len: 4,
    parse_options: None,
    opt_table: None,
    set_hlen: None,
    bind_next: Some(bind_next),
    bind_next_bytes: Some(bind_next_bytes),
    content_len: None,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum;
    use crate::field::FieldValue;
    use crate::packet::Packet;
    use crate::proto::ipproto;

    fn ip(proto: u8, payload: &[u8]) -> Vec<u8> {
        let total = (20 + payload.len()) as u16;
        let mut v = vec![0x45, 0x00];
        v.extend_from_slice(&total.to_be_bytes());
        v.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x40, proto, 0x00, 0x00]);
        v.extend_from_slice(&[10, 0, 0, 1]);
        v.extend_from_slice(&[10, 0, 0, 2]);
        v.extend_from_slice(payload);
        v
    }

    const INNER_IP: &[u8] = &[
        0x45, 0x00, 0x00, 0x14, 0x00, 0x02, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 192, 168, 1, 1,
        192, 168, 1, 2,
    ];

    #[test]
    fn a_bare_header_is_four_octets() {
        let mut gre = vec![0x00, 0x00, 0x08, 0x00];
        gre.extend_from_slice(INNER_IP);
        let p = Packet::dissect(ip(ipproto::GRE, &gre), ProtoId::Ipv4);
        assert_eq!(
            p.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![ProtoId::Ipv4, ProtoId::Gre, ProtoId::Ipv4]
        );
        assert_eq!(p.layers()[1].hlen, 4);
        assert_eq!(p.get(1, "proto").unwrap(), FieldValue::Uint(0x0800));
        assert_eq!(p.get(2, "src").unwrap(), FieldValue::Ipv4([192, 168, 1, 1]));
        assert_eq!(p.get(1, "chksum"), None, "the C bit is clear");
    }

    #[test]
    fn every_flag_combination_places_its_own_fields() {
        for bits in 0u8..8 {
            let (c, k, s) = (bits & 1 != 0, bits & 2 != 0, bits & 4 != 0);
            let mut gre = vec![
                (u8::from(c) << 7) | (u8::from(k) << 5) | (u8::from(s) << 4),
                0x00,
                0x08,
                0x00,
            ];
            if c {
                gre.extend_from_slice(&[0xab, 0xcd, 0x00, 0x00]);
            }
            if k {
                gre.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
            }
            if s {
                gre.extend_from_slice(&[0x00, 0x00, 0x00, 0x09]);
            }
            let want = gre.len();
            gre.extend_from_slice(INNER_IP);

            let p = Packet::dissect(ip(ipproto::GRE, &gre), ProtoId::Ipv4);
            assert_eq!(p.layers()[1].hlen as usize, want, "bits {bits}");
            assert_eq!(p.layers()[2].proto, ProtoId::Ipv4, "bits {bits}");
            assert_eq!(
                p.get(1, "chksum"),
                c.then_some(FieldValue::Uint(0xabcd)),
                "bits {bits}"
            );
            assert_eq!(
                p.get(1, "key"),
                k.then_some(FieldValue::Uint(0x1122_3344)),
                "bits {bits}"
            );
            assert_eq!(
                p.get(1, "seqnum"),
                s.then_some(FieldValue::Uint(9)),
                "bits {bits}"
            );
        }
    }

    /// `key` is declared twice and `seqnum` three times, under conditions the
    /// type system does not check for disjointness. Two live at once and a read
    /// silently returns whichever the field table lists first; none live and it
    /// aliases the octets of whatever is really there. The flags octet is eight
    /// bits wide, so the whole space is enumerable — enumerate it.
    #[test]
    fn exactly_one_declaration_of_each_field_is_live_for_every_flags_octet() {
        for flags in 0u8..=255 {
            let hdr = [flags, 0, 0x08, 0x00];
            let (sum, key, seq) = (has_sum(&hdr), has_key(&hdr), has_seq(&hdr));
            let want = [
                ("chksum", sum.then_some(4)),
                ("offset", sum.then_some(6)),
                ("key", key.then_some(4 + 4 * usize::from(sum))),
                (
                    "seqnum",
                    seq.then_some(4 + 4 * usize::from(sum) + 4 * usize::from(key)),
                ),
            ];
            assert_eq!(
                header_len(&hdr),
                4 + 4 * (usize::from(sum) + usize::from(key) + usize::from(seq)),
                "flags {flags:#04x}"
            );
            for (name, at) in want {
                let live: Vec<_> = FIELDS
                    .iter()
                    .filter(|f| f.name == name && f.is_active(&hdr))
                    .map(|f| (f.bit_off / 8) as usize)
                    .collect();
                match at {
                    Some(at) => assert_eq!(live, vec![at], "{name} at flags {flags:#04x}"),
                    None => assert!(live.is_empty(), "{name} at flags {flags:#04x}: {live:?}"),
                }
            }
        }
    }

    /// The enumeration above proves the declarations disjoint; this proves each
    /// live one reads the octets its offset names, out of a header where every
    /// word is different.
    #[test]
    fn no_flags_octet_makes_a_field_alias_anothers_octets() {
        for flags in 0u8..=255 {
            let mut gre = vec![flags, 0x00, 0x08, 0x00];
            gre.extend_from_slice(&[0xa1, 0xa2, 0xa3, 0xa4]);
            gre.extend_from_slice(&[0xb1, 0xb2, 0xb3, 0xb4]);
            gre.extend_from_slice(&[0xc1, 0xc2, 0xc3, 0xc4]);
            gre.extend_from_slice(INNER_IP);
            let p = Packet::dissect(ip(ipproto::GRE, &gre), ProtoId::Ipv4);
            let hdr = &gre[..4 + 12];
            let word = |at: usize| u32::from_be_bytes(hdr[at..at + 4].try_into().unwrap()) as u64;
            let half = |at: usize| u16::from_be_bytes([hdr[at], hdr[at + 1]]) as u64;

            let (sum, key, seq) = (has_sum(hdr), has_key(hdr), has_seq(hdr));
            let key_at = 4 + 4 * usize::from(sum);
            let seq_at = key_at + 4 * usize::from(key);
            assert_eq!(
                p.get(1, "chksum"),
                sum.then(|| FieldValue::Uint(half(4))),
                "flags {flags:#04x}"
            );
            assert_eq!(
                p.get(1, "offset"),
                sum.then(|| FieldValue::Uint(half(6))),
                "flags {flags:#04x}"
            );
            assert_eq!(
                p.get(1, "key"),
                key.then(|| FieldValue::Uint(word(key_at))),
                "flags {flags:#04x}"
            );
            assert_eq!(
                p.get(1, "seqnum"),
                seq.then(|| FieldValue::Uint(word(seq_at))),
                "flags {flags:#04x}"
            );
        }
    }

    #[test]
    fn carries_a_whole_frame_under_transparent_ethernet_bridging() {
        let mut inner = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        inner.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        inner.extend_from_slice(&[0x08, 0x00]);
        inner.extend_from_slice(INNER_IP);
        let mut gre = vec![0x00, 0x00, 0x65, 0x58];
        gre.extend_from_slice(&inner);
        let p = Packet::dissect(ip(ipproto::GRE, &gre), ProtoId::Ipv4);
        assert_eq!(
            p.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![ProtoId::Ipv4, ProtoId::Gre, ProtoId::Ether, ProtoId::Ipv4]
        );
    }

    #[test]
    fn truncated_input_does_not_panic() {
        let mut gre = vec![0xb0, 0x00, 0x08, 0x00];
        gre.extend_from_slice(&[0; 12]);
        gre.extend_from_slice(INNER_IP);
        let full = ip(ipproto::GRE, &gre);
        for cut in 0..full.len() {
            let mut p = Packet::dissect(full[..cut].to_vec(), ProtoId::Ipv4);
            assert_eq!(p.to_bytes(), &full[..cut]);
        }
        assert_eq!(next(&[0x00]), Next::Raw);
        assert_eq!(header_len(&[]), 4);
    }

    #[test]
    fn builds_a_tunnel_and_checksums_it() {
        let mut p = Packet::build(&[ProtoId::Ipv4, ProtoId::Gre, ProtoId::Ipv4, ProtoId::Tcp]);
        assert_eq!(
            p.get(0, "proto").unwrap(),
            FieldValue::Uint(ipproto::GRE as u64)
        );
        assert_eq!(p.get(1, "proto").unwrap(), FieldValue::Uint(0x0800));
        assert!(p.set_uint(1, "chksum_present", 1));
        p.refit_headers();
        let bytes = p.to_bytes().to_vec();
        assert_eq!(bytes.len(), 20 + 8 + 20 + 20);
        // RFC 2784 §2.5: the checksum covers the GRE header and its payload.
        assert_eq!(checksum::ones_complement(&bytes[20..]), 0);

        let back = Packet::dissect(bytes, ProtoId::Ipv4);
        assert_eq!(
            back.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![ProtoId::Ipv4, ProtoId::Gre, ProtoId::Ipv4, ProtoId::Tcp]
        );
    }
}
