//! Recomputation of derived fields (lengths, checksums) during serialisation.
//! Runs innermost layer outward, because a transport checksum depends on the
//! payload beneath it and the addresses above it.

use crate::checksum as ck;
use crate::packet::Packet;
use crate::proto::{ipproto, ProtoId};

/// Recompute every derived field that the user has not pinned.
pub fn recompute(pkt: &mut Packet) {
    let n = pkt.spans.len();
    if n == 0 {
        return;
    }
    // Innermost first: transport checksums need a settled payload.
    for i in (0..n).rev() {
        match pkt.spans[i].proto {
            ProtoId::Ipv4 => fix_ipv4(pkt, i),
            ProtoId::Ipv6 => fix_ipv6(pkt, i),
            ProtoId::Udp => fix_udp(pkt, i),
            ProtoId::Tcp => fix_tcp(pkt, i),
            ProtoId::Icmp => fix_icmp(pkt, i),
            ProtoId::Icmpv6 => fix_icmpv6(pkt, i),
            _ => {}
        }
    }
}

fn span_bounds(pkt: &Packet, i: usize) -> (usize, usize, usize) {
    let s = pkt.spans[i];
    let off = s.off as usize;
    let hlen = (s.hlen as usize).min(pkt.buf.len().saturating_sub(off));
    let end = pkt.buf.len();
    (off, hlen, end)
}

fn fix_ipv4(pkt: &mut Packet, i: usize) {
    let (off, hlen, end) = span_bounds(pkt, i);
    if off + 20 > end {
        return;
    }
    // Total Length: this header plus everything after it (RFC 791 §3.1).
    let total = (end - off) as u16;
    pkt.buf[off + 2] = (total >> 8) as u8;
    pkt.buf[off + 3] = (total & 0xff) as u8;

    // Header Checksum is computed with the field zeroed.
    pkt.buf[off + 10] = 0;
    pkt.buf[off + 11] = 0;
    let c = ck::ones_complement(&pkt.buf[off..off + hlen]);
    pkt.buf[off + 10] = (c >> 8) as u8;
    pkt.buf[off + 11] = (c & 0xff) as u8;
}

fn fix_ipv6(pkt: &mut Packet, i: usize) {
    let (off, _, end) = span_bounds(pkt, i);
    if off + 40 > end {
        return;
    }
    // Payload Length excludes the fixed 40-octet header (RFC 8200 §3).
    let plen = (end - off - 40) as u16;
    pkt.buf[off + 4] = (plen >> 8) as u8;
    pkt.buf[off + 5] = (plen & 0xff) as u8;
}

/// Find the IPv4/IPv6 addresses enclosing layer `i`, if any.
fn enclosing_addrs(pkt: &Packet, i: usize) -> Option<(Vec<u8>, Vec<u8>, bool)> {
    for j in (0..i).rev() {
        let s = pkt.spans[j];
        let off = s.off as usize;
        match s.proto {
            ProtoId::Ipv4 if off + 20 <= pkt.buf.len() => {
                return Some((
                    pkt.buf[off + 12..off + 16].to_vec(),
                    pkt.buf[off + 16..off + 20].to_vec(),
                    false,
                ));
            }
            ProtoId::Ipv6 if off + 40 <= pkt.buf.len() => {
                return Some((
                    pkt.buf[off + 8..off + 24].to_vec(),
                    pkt.buf[off + 24..off + 40].to_vec(),
                    true,
                ));
            }
            _ => {}
        }
    }
    None
}

fn transport_seed(pkt: &Packet, i: usize, proto: u8, tlen: usize) -> Option<u32> {
    let (src, dst, v6) = enclosing_addrs(pkt, i)?;
    if v6 {
        let s: [u8; 16] = src.try_into().ok()?;
        let d: [u8; 16] = dst.try_into().ok()?;
        Some(ck::pseudo_v6(&s, &d, proto, tlen as u32))
    } else {
        let s: [u8; 4] = src.try_into().ok()?;
        let d: [u8; 4] = dst.try_into().ok()?;
        Some(ck::pseudo_v4(&s, &d, proto, tlen as u16))
    }
}

fn fix_udp(pkt: &mut Packet, i: usize) {
    let (off, _, end) = span_bounds(pkt, i);
    if off + 8 > end {
        return;
    }
    let tlen = end - off;
    // Length covers header plus data (RFC 768).
    pkt.buf[off + 4] = (tlen >> 8) as u8;
    pkt.buf[off + 5] = (tlen & 0xff) as u8;

    pkt.buf[off + 6] = 0;
    pkt.buf[off + 7] = 0;
    let Some(seed) = transport_seed(pkt, i, ipproto::UDP, tlen) else {
        return;
    };
    let sum = ck::sum16(&pkt.buf[off..end], seed);
    let mut c = ck::finish(sum);
    // RFC 768: an all-zero checksum means "not computed", so send all ones.
    if c == 0 {
        c = 0xffff;
    }
    pkt.buf[off + 6] = (c >> 8) as u8;
    pkt.buf[off + 7] = (c & 0xff) as u8;
}

fn fix_tcp(pkt: &mut Packet, i: usize) {
    let (off, _, end) = span_bounds(pkt, i);
    if off + 20 > end {
        return;
    }
    let tlen = end - off;
    pkt.buf[off + 16] = 0;
    pkt.buf[off + 17] = 0;
    let Some(seed) = transport_seed(pkt, i, ipproto::TCP, tlen) else {
        return;
    };
    let sum = ck::sum16(&pkt.buf[off..end], seed);
    let c = ck::finish(sum);
    pkt.buf[off + 16] = (c >> 8) as u8;
    pkt.buf[off + 17] = (c & 0xff) as u8;
}

fn fix_icmp(pkt: &mut Packet, i: usize) {
    let (off, _, end) = span_bounds(pkt, i);
    if off + 4 > end {
        return;
    }
    // ICMPv4 has no pseudo-header (RFC 792).
    pkt.buf[off + 2] = 0;
    pkt.buf[off + 3] = 0;
    let c = ck::ones_complement(&pkt.buf[off..end]);
    pkt.buf[off + 2] = (c >> 8) as u8;
    pkt.buf[off + 3] = (c & 0xff) as u8;
}

fn fix_icmpv6(pkt: &mut Packet, i: usize) {
    let (off, _, end) = span_bounds(pkt, i);
    if off + 4 > end {
        return;
    }
    let tlen = end - off;
    pkt.buf[off + 2] = 0;
    pkt.buf[off + 3] = 0;
    // Unlike ICMPv4, ICMPv6 covers the IPv6 pseudo-header (RFC 4443 §2.3),
    // so without an enclosing IPv6 layer the checksum is left zeroed.
    let Some(seed) = transport_seed(pkt, i, ipproto::IPV6_ICMP, tlen) else {
        return;
    };
    let c = ck::finish(ck::sum16(&pkt.buf[off..end], seed));
    pkt.buf[off + 2] = (c >> 8) as u8;
    pkt.buf[off + 3] = (c & 0xff) as u8;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldValue;

    #[test]
    fn ipv4_checksum_verifies_after_build() {
        let mut p = Packet::build(&[ProtoId::Ipv4, ProtoId::Tcp]);
        p.mark_all_dirty();
        let bytes = p.to_bytes().to_vec();
        // A correct IPv4 header checksums to zero when summed including the field.
        assert_eq!(ck::ones_complement(&bytes[0..20]), 0);
    }

    #[test]
    fn ipv4_total_length_tracks_payload() {
        let mut p = Packet::build(&[ProtoId::Ipv4, ProtoId::Udp]);
        p.mark_all_dirty();
        let n = p.to_bytes().len();
        let ip = p.find_layer(ProtoId::Ipv4).unwrap();
        assert_eq!(p.get(ip, "len").unwrap(), FieldValue::Uint(n as u64));
    }

    #[test]
    fn udp_length_tracks_payload() {
        let mut p = Packet::build(&[ProtoId::Ipv4, ProtoId::Udp]);
        p.set_payload(1, b"hello");
        let _ = p.to_bytes();
        let udp = p.find_layer(ProtoId::Udp).unwrap();
        assert_eq!(p.get(udp, "len").unwrap(), FieldValue::Uint(8 + 5));
    }
}
