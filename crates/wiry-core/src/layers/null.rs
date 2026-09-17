//! DLT_NULL (LINKTYPE_NULL, 0) and DLT_LOOP (LINKTYPE_LOOP, 108) from the
//! tcpdump link-layer header type registry: four octets holding the address
//! family of the datagram that follows.
//!
//! DLT_NULL writes that value in the **host** byte order of the machine that
//! captured, DLT_LOOP in network byte order. One layer serves both: `type` is
//! declared twice under disjoint conditions, little-endian when that order
//! yields a known address family and big-endian otherwise, so the field read
//! reaches the same decision the dispatcher does. A DLT_NULL capture written on
//! a big-endian host is still ambiguous with DLT_LOOP and stays logged as
//! DEVIATIONS.md C3.

use crate::field::FieldDesc;
use crate::proto::{Next, ProtoDesc, ProtoId};

/// `AF_INET` is 2 everywhere. `AF_INET6` is not: 24 on NetBSD and OpenBSD, 28
/// on FreeBSD, 30 on macOS, and a capture carries whichever its writer used.
pub mod af {
    pub const INET: u32 = 2;
    pub const INET6_BSD: u32 = 24;
    pub const INET6_FREEBSD: u32 = 28;
    pub const INET6_DARWIN: u32 = 30;
}

pub static FIELDS: &[FieldDesc] = &[
    FieldDesc::le_uint("type", 0, 32, af::INET as u64).when(host_order),
    FieldDesc::uint("type", 0, 32, af::INET as u64).when(network_order),
];

fn known(v: u32) -> bool {
    matches!(
        v,
        af::INET | af::INET6_BSD | af::INET6_FREEBSD | af::INET6_DARWIN
    )
}

/// True when reading the four octets little-endian names an address family we
/// recognise, which is what makes this a host-order DLT_NULL header.
fn host_order(hdr: &[u8]) -> bool {
    hdr.get(..4)
        .is_some_and(|b| known(u32::from_le_bytes([b[0], b[1], b[2], b[3]])))
}

fn network_order(hdr: &[u8]) -> bool {
    !host_order(hdr)
}

fn family(hdr: &[u8]) -> u32 {
    let Some(b) = hdr.get(..4) else {
        return 0;
    };
    if host_order(hdr) {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    } else {
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    }
}

fn header_len(_: &[u8]) -> usize {
    4
}

fn next(hdr: &[u8]) -> Next {
    match family(hdr) {
        af::INET => Next::Proto(ProtoId::Ipv4),
        af::INET6_BSD | af::INET6_FREEBSD | af::INET6_DARWIN => Next::Proto(ProtoId::Ipv6),
        _ => Next::Raw,
    }
}

fn bind_next(hdr: &mut [u8], p: ProtoId) {
    let v = match p {
        ProtoId::Ipv4 => af::INET,
        ProtoId::Ipv6 => af::INET6_DARWIN,
        _ => return,
    };
    if hdr.len() >= 4 {
        hdr[0..4].copy_from_slice(&v.to_le_bytes());
    }
}

pub static DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Null,
    name: "Loopback",
    fields: FIELDS,
    min_len: 4,
    header_len,
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

    /// A 20-octet IPv4 header carrying nothing, src 10.0.0.1 dst 10.0.0.2.
    const IPV4: &[u8] = &[
        0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 1, 10, 0,
        0, 2,
    ];

    /// RFC 8200 §3, payload length 0, next header 59 (no next header).
    const IPV6: &[u8] = &[
        0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 59, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 1, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
    ];

    fn frame(af: &[u8], rest: &[u8]) -> Vec<u8> {
        let mut v = af.to_vec();
        v.extend_from_slice(rest);
        v
    }

    #[test]
    fn a_host_order_af_inet_header_reaches_ipv4() {
        let p = Packet::dissect(frame(&[2, 0, 0, 0], IPV4), ProtoId::Null);
        assert_eq!(
            p.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![ProtoId::Null, ProtoId::Ipv4]
        );
        assert_eq!(p.get(0, "type").unwrap(), FieldValue::Uint(2));
        assert_eq!(p.get(1, "src").unwrap(), FieldValue::Ipv4([10, 0, 0, 1]));
    }

    #[test]
    fn a_big_endian_af_inet_header_reaches_ipv4_too() {
        // DLT_LOOP, and equally a little-endian file written on a big-endian host.
        let p = Packet::dissect(frame(&[0, 0, 0, 2], IPV4), ProtoId::Null);
        assert_eq!(
            p.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![ProtoId::Null, ProtoId::Ipv4]
        );
    }

    /// The dispatcher always tried both byte orders; the field read did not, so
    /// every DLT_LOOP capture reported a byte-swapped `type`.
    #[test]
    fn the_family_reads_in_the_order_the_dispatcher_chose() {
        for af in [af::INET, af::INET6_BSD, af::INET6_FREEBSD, af::INET6_DARWIN] {
            let le = Packet::dissect(frame(&af.to_le_bytes(), IPV6), ProtoId::Null);
            assert_eq!(
                le.get(0, "type").unwrap(),
                FieldValue::Uint(af as u64),
                "host order, af {af}"
            );
            let be = Packet::dissect(frame(&af.to_be_bytes(), IPV6), ProtoId::Null);
            assert_eq!(
                be.get(0, "type").unwrap(),
                FieldValue::Uint(af as u64),
                "network order, af {af}"
            );
        }
    }

    /// An unrecognised family has no byte order to infer, so it reads as the
    /// network-order field and must still round-trip its octets.
    #[test]
    fn an_unknown_family_still_reads_one_consistent_value() {
        let p = Packet::dissect(frame(&[0x00, 0x00, 0x00, 0x77], IPV4), ProtoId::Null);
        assert_eq!(p.get(0, "type").unwrap(), FieldValue::Uint(0x77));
    }

    #[test]
    fn every_af_inet6_spelling_reaches_ipv6() {
        for af in [24u32, 28, 30] {
            let p = Packet::dissect(frame(&af.to_le_bytes(), IPV6), ProtoId::Null);
            assert_eq!(
                p.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
                vec![ProtoId::Null, ProtoId::Ipv6],
                "af {af}"
            );
            let be = Packet::dissect(frame(&af.to_be_bytes(), IPV6), ProtoId::Null);
            assert_eq!(be.layers()[1].proto, ProtoId::Ipv6, "af {af} big-endian");
        }
    }

    #[test]
    fn an_unknown_family_falls_back_to_raw() {
        let p = Packet::dissect(frame(&[0x77, 0, 0, 0], IPV4), ProtoId::Null);
        assert_eq!(
            p.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![ProtoId::Null, ProtoId::Raw]
        );
    }

    #[test]
    fn a_header_alone_or_clipped_does_not_panic() {
        assert_eq!(
            Packet::dissect(vec![2, 0, 0, 0], ProtoId::Null).layers()[0].proto,
            ProtoId::Null
        );
        assert_eq!(
            Packet::dissect(vec![2, 0, 0], ProtoId::Null).layers()[0].proto,
            ProtoId::Raw
        );
    }

    #[test]
    fn stacking_writes_the_family_back() {
        let mut p = Packet::build(&[ProtoId::Null, ProtoId::Ipv4]);
        assert_eq!(p.get(0, "type").unwrap(), FieldValue::Uint(af::INET as u64));
        let bytes = p.to_bytes().to_vec();
        assert_eq!(&bytes[..4], &[2, 0, 0, 0]);
        let back = Packet::dissect(bytes, ProtoId::Null);
        assert_eq!(back.layers()[1].proto, ProtoId::Ipv4);

        let mut six = Packet::build(&[ProtoId::Null, ProtoId::Ipv6]);
        let bytes = six.to_bytes().to_vec();
        let back = Packet::dissect(bytes, ProtoId::Null);
        assert_eq!(back.layers()[1].proto, ProtoId::Ipv6);
    }

    #[test]
    fn dlt_null_and_dlt_loop_both_map_to_this_layer() {
        use crate::pcap::{link_to_proto, linktype};
        assert_eq!(link_to_proto(linktype::NULL), ProtoId::Null);
        assert_eq!(link_to_proto(linktype::LOOP), ProtoId::Null);
    }
}
