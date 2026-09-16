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

/// True when a length field describes more bytes than the buffer holds, which
/// is what a capture clipped by the snaplen looks like. Nothing derived from
/// the missing bytes can be recomputed, so what the wire said stands.
fn is_clipped(pkt: &Packet) -> bool {
    pkt.spans.iter().enumerate().any(|(i, s)| {
        crate::proto::desc(s.proto)
            .content_len
            .is_some_and(|f| s.off as usize + f(pkt.header(i)) > pkt.buf.len())
    })
}

/// Trailing `Padding` counts towards no enclosing length or checksum, so every
/// computation stops where it starts.
fn content_end(pkt: &Packet) -> usize {
    pkt.spans
        .iter()
        .find(|s| s.proto == ProtoId::Padding)
        .map_or(pkt.buf.len(), |s| (s.off as usize).min(pkt.buf.len()))
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
    if !clipped {
        // RFC 791 §3.1: header plus everything after it.
        let total = (end - off) as u16;
        pkt.buf[off + 2] = (total >> 8) as u8;
        pkt.buf[off + 3] = (total & 0xff) as u8;
    }

    // Computed with the field zeroed.
    pkt.buf[off + 10] = 0;
    pkt.buf[off + 11] = 0;
    let c = ck::ones_complement(&pkt.buf[off..off + hlen]);
    pkt.buf[off + 10] = (c >> 8) as u8;
    pkt.buf[off + 11] = (c & 0xff) as u8;
}

fn fix_ipv6(pkt: &mut Packet, i: usize, clipped: bool) {
    let (off, _, end) = span_bounds(pkt, i);
    if clipped || off + 40 > end {
        return;
    }
    // RFC 8200 §3: excludes the fixed 40-octet header.
    let plen = (end - off - 40) as u16;
    pkt.buf[off + 4] = (plen >> 8) as u8;
    pkt.buf[off + 5] = (plen & 0xff) as u8;
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
    // RFC 768: header plus data.
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
    // RFC 792: no pseudo-header.
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
    // RFC 4443 §2.3: unlike ICMPv4 this covers the IPv6 pseudo-header, so with
    // no enclosing IPv6 layer the checksum stays zeroed.
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
        // The header is all there, so its own checksum still holds.
        assert_eq!(ck::ones_complement(&out[..20]), 0);
    }
}
