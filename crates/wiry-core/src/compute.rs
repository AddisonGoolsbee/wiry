use crate::checksum as ck;
use crate::packet::Packet;
use crate::proto::{ipproto, ProtoId};

pub fn recompute(pkt: &mut Packet) {
    let n = pkt.spans.len();
    if n == 0 {
        return;
    }
    // Read before anything is written, so every layer sees the same answer.
    let clipped = is_clipped(pkt);
    // Innermost first: transport checksums need a settled payload.
    for i in (0..n).rev() {
        match pkt.spans[i].proto {
            ProtoId::Ipv4 => fix_ipv4(pkt, i, clipped),
            ProtoId::Ipv6 => fix_ipv6(pkt, i, clipped),
            ProtoId::Udp => fix_udp(pkt, i, clipped),
            ProtoId::Tcp if !clipped => fix_tcp(pkt, i),
            ProtoId::Icmp if !clipped => fix_icmp(pkt, i),
            ProtoId::Icmpv6 if !clipped => fix_icmpv6(pkt, i),
            _ => {}
        }
    }
}

/// The field `content_len` reads, so a length the user wrote there can be told
/// apart from one the wire gave.
fn len_field(proto: ProtoId) -> Option<&'static str> {
    match proto {
        ProtoId::Ipv4 | ProtoId::Udp => Some("len"),
        ProtoId::Ipv6 => Some("plen"),
        _ => None,
    }
}

/// With `content_end`, this gates three behaviours at once: clipped captures,
/// deliberate resizes, and oversize detection.
///
/// True when a length field describes more bytes than the buffer holds, i.e. a
/// snaplen-clipped capture, where nothing derived from the missing bytes can be
/// recomputed. A resized packet is not clipped: its lengths describe the extent
/// before the write, and they are exactly what is being recomputed. Neither is
/// a length the user assigned: a value pinned by hand says nothing about what
/// the capture holds, and reading it as a clipped capture would stop every
/// checksum in the packet from being computed.
fn is_clipped(pkt: &Packet) -> bool {
    !pkt.resized
        && pkt.spans.iter().enumerate().any(|(i, s)| {
            if len_field(s.proto).is_some_and(|n| pkt.is_pinned(i, n)) {
                return false;
            }
            crate::proto::desc(s.proto)
                .content_len
                .is_some_and(|f| s.off as usize + f(pkt.header(i)) > pkt.buf.len())
        })
}

/// Trailing `Padding` counts towards no enclosing length or checksum.
fn content_end(pkt: &Packet) -> usize {
    pkt.spans
        .iter()
        .find(|s| s.proto == ProtoId::Padding)
        .map_or(pkt.buf.len(), |s| (s.off as usize).min(pkt.buf.len()))
}

/// Every length recomputed here is sixteen bits wide (RFC 791 §3.1, RFC 8200
/// §3, RFC 768), as is the one in TCP's and UDP's pseudo-header, so a larger
/// frame has no representation and emitting it modulo 65536 would be a lie.
pub fn oversize(pkt: &Packet) -> Option<String> {
    if pkt.len() <= u16::MAX as usize || is_clipped(pkt) {
        return None;
    }
    let end = content_end(pkt);
    for s in pkt.spans.iter() {
        let n = end.saturating_sub(s.off as usize);
        let (what, n) = match s.proto {
            ProtoId::Ipv4 => ("IP.len", n),
            ProtoId::Ipv6 => ("IPv6.plen", n.saturating_sub(40)),
            ProtoId::Udp => ("UDP.len", n),
            ProtoId::Tcp => ("the TCP pseudo-header length", n),
            _ => continue,
        };
        if n > u16::MAX as usize {
            return Some(format!("{what} cannot hold {n} bytes"));
        }
    }
    None
}

fn put16(buf: &mut [u8], at: usize, v: u16) {
    buf[at..at + 2].copy_from_slice(&v.to_be_bytes());
}

fn span_bounds(pkt: &Packet, i: usize) -> (usize, usize, usize) {
    let s = pkt.spans[i];
    let off = s.off as usize;
    let hlen = (s.hlen as usize).min(pkt.buf.len().saturating_sub(off));
    (off, hlen, content_end(pkt))
}

fn fix_ipv4(pkt: &mut Packet, i: usize, clipped: bool) {
    let (off, hlen, end) = span_bounds(pkt, i);
    if off + 20 > end {
        return;
    }
    if !clipped && !pkt.is_pinned(i, "len") {
        // RFC 791 §3.1: header plus everything after it.
        put16(&mut pkt.buf, off + 2, (end - off) as u16);
    }
    if pkt.is_pinned(i, "chksum") {
        return;
    }

    put16(&mut pkt.buf, off + 10, 0);
    let c = ck::ones_complement(&pkt.buf[off..off + hlen]);
    put16(&mut pkt.buf, off + 10, c);
}

fn fix_ipv6(pkt: &mut Packet, i: usize, clipped: bool) {
    let (off, _, end) = span_bounds(pkt, i);
    if clipped || off + 40 > end || pkt.is_pinned(i, "plen") {
        return;
    }
    // RFC 8200 §3: excludes the fixed 40-octet header.
    put16(&mut pkt.buf, off + 4, (end - off - 40) as u16);
}

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

fn fix_udp(pkt: &mut Packet, i: usize, clipped: bool) {
    let (off, _, end) = span_bounds(pkt, i);
    if clipped || off + 8 > end {
        return;
    }
    let tlen = end - off;
    if !pkt.is_pinned(i, "len") {
        // RFC 768: header plus data.
        put16(&mut pkt.buf, off + 4, tlen as u16);
    }
    if pkt.is_pinned(i, "chksum") {
        return;
    }

    put16(&mut pkt.buf, off + 6, 0);
    let Some(seed) = transport_seed(pkt, i, ipproto::UDP, tlen) else {
        return;
    };
    let mut c = ck::finish(ck::sum16(&pkt.buf[off..end], seed));
    // RFC 768: an all-zero checksum means "not computed", so send all ones.
    if c == 0 {
        c = 0xffff;
    }
    put16(&mut pkt.buf, off + 6, c);
}

fn fix_tcp(pkt: &mut Packet, i: usize) {
    let (off, _, end) = span_bounds(pkt, i);
    if off + 20 > end || pkt.is_pinned(i, "chksum") {
        return;
    }
    let tlen = end - off;
    put16(&mut pkt.buf, off + 16, 0);
    let Some(seed) = transport_seed(pkt, i, ipproto::TCP, tlen) else {
        return;
    };
    let c = ck::finish(ck::sum16(&pkt.buf[off..end], seed));
    put16(&mut pkt.buf, off + 16, c);
}

fn fix_icmp(pkt: &mut Packet, i: usize) {
    let (off, _, end) = span_bounds(pkt, i);
    if off + 4 > end || pkt.is_pinned(i, "chksum") {
        return;
    }
    // RFC 792: no pseudo-header.
    put16(&mut pkt.buf, off + 2, 0);
    let c = ck::ones_complement(&pkt.buf[off..end]);
    put16(&mut pkt.buf, off + 2, c);
}

fn fix_icmpv6(pkt: &mut Packet, i: usize) {
    let (off, _, end) = span_bounds(pkt, i);
    if off + 4 > end || pkt.is_pinned(i, "cksum") {
        return;
    }
    let tlen = end - off;
    put16(&mut pkt.buf, off + 2, 0);
    // RFC 4443 §2.3: unlike ICMPv4 this covers the IPv6 pseudo-header, so with
    // no enclosing IPv6 layer the checksum stays zeroed.
    let Some(seed) = transport_seed(pkt, i, ipproto::IPV6_ICMP, tlen) else {
        return;
    };
    let c = ck::finish(ck::sum16(&pkt.buf[off..end], seed));
    put16(&mut pkt.buf, off + 2, c);
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

    #[test]
    fn a_trailer_is_counted_into_no_length_after_a_write() {
        let mut p = Packet::build(&[ProtoId::Ipv4, ProtoId::Udp]);
        let mut bytes = p.to_bytes().to_vec();
        bytes.extend_from_slice(&[0u8; 18]);

        let mut back = Packet::dissect(bytes, ProtoId::Ipv4);
        assert!(back.set_uint(0, "ttl", 33));
        assert_eq!(back.to_bytes().len(), 46);
        assert_eq!(back.get(0, "len").unwrap(), FieldValue::Uint(28));
        assert_eq!(back.get(1, "len").unwrap(), FieldValue::Uint(8));
    }

    #[test]
    fn a_length_field_too_narrow_is_reported_rather_than_wrapped() {
        let mut p = Packet::build(&[ProtoId::Ipv4, ProtoId::Udp]);
        p.set_payload(1, &[0u8; 65507]);
        assert_eq!(p.oversize(), None);
        assert_eq!(p.to_bytes().len(), 65535);

        let mut p = Packet::build(&[ProtoId::Ipv4, ProtoId::Udp]);
        p.set_payload(1, &[0u8; 65508]);
        assert_eq!(
            p.oversize().as_deref(),
            Some("IP.len cannot hold 65536 bytes")
        );
    }

    #[test]
    fn a_capture_larger_than_a_length_field_still_round_trips_untouched() {
        let mut p = Packet::dissect(vec![0u8; 70000], ProtoId::Raw);
        assert_eq!(p.oversize(), None);
        assert_eq!(p.to_bytes().len(), 70000);
    }

    #[test]
    fn a_length_the_user_wrote_is_not_a_clipped_capture() {
        let mut p = Packet::build(&[ProtoId::Ipv4, ProtoId::Tcp]);
        p.set_payload(1, b"hello!");
        let bytes = p.to_bytes().to_vec();

        let mut back = Packet::dissect(bytes, ProtoId::Ipv4);
        assert!(back.set_uint(0, "len", 999));
        assert!(back.set_uint(1, "sport", 1234));
        let out = back.to_bytes().to_vec();

        assert_eq!(back.get(0, "len").unwrap(), FieldValue::Uint(999));
        assert_eq!(ck::ones_complement(&out[..20]), 0);
        let seed = ck::pseudo_v4(
            &[127, 0, 0, 1],
            &[127, 0, 0, 1],
            ipproto::TCP,
            (out.len() - 20) as u16,
        );
        assert_eq!(ck::finish(ck::sum16(&out[20..], seed)), 0);
    }

    #[test]
    fn a_pinned_length_is_honoured_and_moves_no_other_field() {
        let mut p = Packet::build(&[ProtoId::Ipv4, ProtoId::Udp]);
        assert!(p.set_uint(1, "len", 999));
        let out = p.to_bytes().to_vec();

        assert_eq!(p.get(1, "len").unwrap(), FieldValue::Uint(999));
        assert_eq!(p.get(0, "len").unwrap(), FieldValue::Uint(28));
        assert_eq!(ck::ones_complement(&out[..20]), 0);
        // RFC 768: the pseudo-header covers the datagram that is really there.
        let seed = ck::pseudo_v4(&[127, 0, 0, 1], &[127, 0, 0, 1], ipproto::UDP, 8);
        assert_eq!(ck::finish(ck::sum16(&out[20..], seed)), 0);
    }

    #[test]
    fn a_pinned_checksum_is_kept_rather_than_recomputed() {
        let mut p = Packet::build(&[ProtoId::Ipv4, ProtoId::Tcp]);
        assert!(p.set_uint(0, "chksum", 0x1234));
        assert!(p.set_uint(1, "chksum", 0x5678));
        let _ = p.to_bytes();
        assert_eq!(p.get(0, "chksum").unwrap(), FieldValue::Uint(0x1234));
        assert_eq!(p.get(1, "chksum").unwrap(), FieldValue::Uint(0x5678));

        assert!(p.set_uint(1, "sport", 4444));
        let _ = p.to_bytes();
        assert_eq!(p.get(1, "chksum").unwrap(), FieldValue::Uint(0x5678));
    }

    #[test]
    fn a_pinned_checksum_is_honoured_for_udp_icmp_and_icmpv6() {
        let mut u = Packet::build(&[ProtoId::Ipv4, ProtoId::Udp]);
        assert!(u.set_uint(1, "chksum", 0xdead));
        let _ = u.to_bytes();
        assert_eq!(u.get(1, "chksum").unwrap(), FieldValue::Uint(0xdead));
        assert_eq!(u.get(1, "len").unwrap(), FieldValue::Uint(8));

        let mut i = Packet::build(&[ProtoId::Ipv4, ProtoId::Icmp]);
        assert!(i.set_uint(1, "chksum", 0xbeef));
        let _ = i.to_bytes();
        assert_eq!(i.get(1, "chksum").unwrap(), FieldValue::Uint(0xbeef));

        let mut v6 = Packet::build(&[ProtoId::Ipv6, ProtoId::Icmpv6]);
        assert!(v6.set_uint(1, "cksum", 0xcafe));
        assert!(v6.set_uint(0, "plen", 40));
        let _ = v6.to_bytes();
        assert_eq!(v6.get(1, "cksum").unwrap(), FieldValue::Uint(0xcafe));
        assert_eq!(v6.get(0, "plen").unwrap(), FieldValue::Uint(40));
    }

    #[test]
    fn an_unpinned_checksum_is_still_recomputed_beside_a_pinned_one() {
        let mut p = Packet::build(&[ProtoId::Ipv4, ProtoId::Tcp]);
        assert!(p.set_uint(0, "chksum", 0x1234));
        let out = p.to_bytes().to_vec();
        assert_eq!(p.get(0, "chksum").unwrap(), FieldValue::Uint(0x1234));
        let seed = ck::pseudo_v4(
            &[127, 0, 0, 1],
            &[127, 0, 0, 1],
            ipproto::TCP,
            (out.len() - 20) as u16,
        );
        assert_eq!(ck::finish(ck::sum16(&out[20..], seed)), 0);
    }

    #[test]
    fn a_clipped_capture_keeps_the_lengths_the_wire_gave() {
        let mut p = Packet::build(&[ProtoId::Ipv4, ProtoId::Udp]);
        p.set_payload(1, &[0u8; 40]);
        let bytes = p.to_bytes().to_vec();

        let mut back = Packet::dissect(bytes[..40].to_vec(), ProtoId::Ipv4);
        assert!(back.set_uint(0, "ttl", 33));
        let out = back.to_bytes().to_vec();
        assert_eq!(out.len(), 40);
        assert_eq!(back.get(0, "len").unwrap(), FieldValue::Uint(68));
        assert_eq!(back.get(1, "len").unwrap(), FieldValue::Uint(48));
        assert_eq!(ck::ones_complement(&out[..20]), 0);
    }
}
