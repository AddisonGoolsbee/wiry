//! Deciding whether a received packet answers a sent one, for `sr`/`sr1`.
//!
//! Pure: [`reply_key`] distils a sent packet into a small key and [`answers`]
//! tests a candidate against it, with no socket, clock or privilege involved.
//!
//! | Sent | Recognised reply |
//! |---|---|
//! | ICMP echo request (RFC 792 type 8) | type 0, same id and seq, swapped address pair |
//! | ICMPv6 echo request (RFC 4443 type 128) | type 129, same id and seq, swapped address pair |
//! | any IPv4 datagram | an ICMP error (RFC 792 types 3, 4, 5, 11, 12) quoting it: same quoted addresses, protocol, IP id and first 8 transport octets |
//! | TCP | swapped address pair and swapped port pair |
//! | UDP | swapped address pair and swapped port pair |
//! | DNS query over UDP | that, and a response (QR set) carrying an equal DNS id |
//! | ARP request (RFC 826 op 1) | op 2 whose psrc is the pdst asked about |
//!
//! Nothing else matches, and in particular a shared address pair alone never
//! does. The two failure modes are not symmetric: a wrong match silently
//! corrupts the user's results, while a missed one shows up in `unanswered`
//! where it can be seen and investigated. Every rule therefore pins the
//! addresses down, on the quoted header as well as the outer one: `sr` opens
//! the handle promiscuously, so an error or a reply meant for a third party is
//! on the wire to be mismatched.

use crate::layers::icmp::types;
use crate::packet::{dissect_spans, LayerSpan};
use crate::proto::ProtoId;

/// Every ICMPv4 message that quotes the datagram which provoked it (RFC 792,
/// RFC 1812 §4.3.2.3). ICMPv6 errors quote an IPv6 datagram and are not
/// matched: the table above recognises these five types only.
const ERROR_TYPES: [u8; 5] = [
    types::DEST_UNREACH,
    types::SOURCE_QUENCH,
    types::REDIRECT,
    types::TIME_EXCEEDED,
    types::PARAM_PROBLEM,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyKind {
    IcmpEcho {
        id: u16,
        seq: u16,
    },
    Icmpv6Echo {
        id: u16,
        seq: u16,
    },
    Tcp {
        sport: u16,
        dport: u16,
        /// What a reply's ack would be if it acknowledged everything sent.
        expect_ack: u32,
    },
    Udp {
        sport: u16,
        dport: u16,
        dns: Option<DnsAsk>,
    },
    Arp {
        pdst: [u8; 4],
    },
    /// An IP datagram with no reply rule of its own; only an ICMP error
    /// quoting it counts as an answer.
    Ip,
}

/// RFC 1035 §4.1.1: the id a response has to echo, and whether what was sent
/// was a query at all. Only a query can be answered by a response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DnsAsk {
    pub id: u16,
    pub query: bool,
}

/// Addresses are held widest-first: an IPv4 address occupies the low 4 octets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplyKey {
    pub kind: ReplyKind,
    src: [u8; 16],
    dst: [u8; 16],
    v6: bool,
    quote: Option<Quote>,
}

/// What an ICMP error would echo back: RFC 792 quotes the internet header plus
/// at least the first 64 bits of what followed it. The addresses and the
/// protocol are inside that guaranteed header, so they are as available as the
/// id, and they are what tells two probes of one `sr` batch apart: wiry builds
/// every datagram with `id = 1`, and a default `ICMP()` payload is the same
/// eight octets every time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Quote {
    src: [u8; 4],
    dst: [u8; 4],
    proto: u8,
    ip_id: u16,
    head: [u8; 8],
    len: u8,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Pair {
    src: [u8; 16],
    dst: [u8; 16],
    v6: bool,
}

fn find(spans: &[LayerSpan], p: ProtoId) -> Option<&LayerSpan> {
    spans.iter().find(|s| s.proto == p)
}

fn hdr<'a>(buf: &'a [u8], s: &LayerSpan) -> &'a [u8] {
    s.header(buf)
}

/// From the layer's first octet to the end of the buffer, for a field the
/// layer's own header stops short of.
fn body<'a>(buf: &'a [u8], s: &LayerSpan) -> &'a [u8] {
    &buf[(s.off as usize).min(buf.len())..]
}

fn payload<'a>(buf: &'a [u8], s: &LayerSpan) -> &'a [u8] {
    &buf[((s.off + s.hlen) as usize).min(buf.len())..]
}

fn be16(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2)
        .map(|x| u16::from_be_bytes([x[0], x[1]]))
}

fn be32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .map(|x| u32::from_be_bytes([x[0], x[1], x[2], x[3]]))
}

fn wide(b: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let n = b.len().min(16);
    out[16 - n..].copy_from_slice(&b[..n]);
    out
}

/// RFC 791 §3.1 puts the addresses at octets 12 and 16; RFC 8200 §3 at 8 and 24.
fn ip_pair(buf: &[u8], spans: &[LayerSpan]) -> Option<Pair> {
    if let Some(s) = find(spans, ProtoId::Ipv4) {
        let h = hdr(buf, s);
        return Some(Pair {
            src: wide(h.get(12..16)?),
            dst: wide(h.get(16..20)?),
            v6: false,
        });
    }
    let s = find(spans, ProtoId::Ipv6)?;
    let h = hdr(buf, s);
    Some(Pair {
        src: wide(h.get(8..24)?),
        dst: wide(h.get(24..40)?),
        v6: true,
    })
}

fn four(b: &[u8], off: usize) -> Option<[u8; 4]> {
    let x = b.get(off..off + 4)?;
    Some([x[0], x[1], x[2], x[3]])
}

fn ipv4_quote(buf: &[u8], spans: &[LayerSpan]) -> Option<Quote> {
    let s = find(spans, ProtoId::Ipv4)?;
    let h = hdr(buf, s);
    let ip_id = be16(h, 4)?;
    let after = payload(buf, s);
    let len = after.len().min(8);
    let mut head = [0u8; 8];
    head[..len].copy_from_slice(&after[..len]);
    Some(Quote {
        src: four(h, 12)?,
        dst: four(h, 16)?,
        proto: *h.get(9)?,
        ip_id,
        head,
        len: len as u8,
    })
}

/// `None` for anything the table has no rule for, which is also what a caller
/// should treat as "this packet can never be answered".
pub fn reply_key(buf: &[u8], spans: &[LayerSpan]) -> Option<ReplyKey> {
    if let Some(s) = find(spans, ProtoId::Arp) {
        let h = hdr(buf, s);
        if be16(h, 6)? != crate::layers::arp::OP_WHO_HAS as u16 {
            return None;
        }
        let pdst = h.get(24..28)?;
        return Some(ReplyKey {
            kind: ReplyKind::Arp {
                pdst: [pdst[0], pdst[1], pdst[2], pdst[3]],
            },
            src: [0; 16],
            dst: [0; 16],
            v6: false,
            quote: None,
        });
    }

    let pair = ip_pair(buf, spans)?;
    let kind = sent_kind(buf, spans);
    let quote = ipv4_quote(buf, spans);
    // An IPv6 datagram with no rule of its own cannot be quoted back by any
    // error this matches, so nothing could ever answer it.
    if kind == ReplyKind::Ip && quote.is_none() {
        return None;
    }
    Some(ReplyKey {
        kind,
        src: pair.src,
        dst: pair.dst,
        v6: pair.v6,
        quote,
    })
}

/// RFC 1035 §4.1.1 puts QR in the top bit of the octet after the id.
fn dns_ask(h: &[u8]) -> Option<DnsAsk> {
    Some(DnsAsk {
        id: be16(h, 0)?,
        query: h.get(2)? & 0x80 == 0,
    })
}

fn sent_kind(buf: &[u8], spans: &[LayerSpan]) -> ReplyKind {
    if let Some(s) = find(spans, ProtoId::Icmp) {
        let h = hdr(buf, s);
        if let (Some(&types::ECHO_REQUEST), Some(id), Some(seq)) =
            (h.first(), be16(h, 4), be16(h, 6))
        {
            return ReplyKind::IcmpEcho { id, seq };
        }
        return ReplyKind::Ip;
    }
    if let Some(s) = find(spans, ProtoId::Icmpv6) {
        // RFC 4443 §4.1 puts id and seq past the 4 octets common to every
        // message, which is all this layer's header covers.
        let b = body(buf, s);
        if let (Some(&crate::layers::icmpv6::ECHO_REQUEST), Some(id), Some(seq)) =
            (b.first(), be16(b, 4), be16(b, 6))
        {
            return ReplyKind::Icmpv6Echo { id, seq };
        }
        return ReplyKind::Ip;
    }
    if let Some(s) = find(spans, ProtoId::Tcp) {
        let h = hdr(buf, s);
        let (Some(sport), Some(dport), Some(seq)) = (be16(h, 0), be16(h, 2), be32(h, 4)) else {
            return ReplyKind::Ip;
        };
        // RFC 9293 §3.4: a SYN and a FIN each occupy one sequence number.
        let ctl = h.get(13).copied().unwrap_or(0);
        let phantom = u32::from(ctl & 0b11 != 0);
        let payload_len = s.total.saturating_sub(s.hlen);
        return ReplyKind::Tcp {
            sport,
            dport,
            expect_ack: seq.wrapping_add(payload_len).wrapping_add(phantom),
        };
    }
    if let Some(s) = find(spans, ProtoId::Udp) {
        let h = hdr(buf, s);
        let (Some(sport), Some(dport)) = (be16(h, 0), be16(h, 2)) else {
            return ReplyKind::Ip;
        };
        let dns = find(spans, ProtoId::Dns).and_then(|d| dns_ask(hdr(buf, d)));
        return ReplyKind::Udp { sport, dport, dns };
    }
    ReplyKind::Ip
}

pub fn answers(sent: &ReplyKey, recv_buf: &[u8], recv_spans: &[LayerSpan]) -> bool {
    match sent.kind {
        ReplyKind::Arp { pdst } => arp_answers(pdst, recv_buf, recv_spans),
        _ => direct_answer(sent, recv_buf, recv_spans) || quoted_back(sent, recv_buf, recv_spans),
    }
}

/// Advisory, and deliberately not part of [`answers`]: a RST answering a SYN
/// carries no meaningful ack, yet it is the reply the sender is waiting for.
/// `None` where the relation does not apply at all.
pub fn ack_consistent(sent: &ReplyKey, recv_buf: &[u8], recv_spans: &[LayerSpan]) -> Option<bool> {
    let ReplyKind::Tcp { expect_ack, .. } = sent.kind else {
        return None;
    };
    let s = find(recv_spans, ProtoId::Tcp)?;
    let h = hdr(recv_buf, s);
    // RFC 9293 §3.1: the ack field means nothing unless ACK is set.
    if h.get(13).copied().unwrap_or(0) & 0b1_0000 == 0 {
        return None;
    }
    Some(be32(h, 8)? == expect_ack)
}

fn swapped(sent: &ReplyKey, pair: &Pair) -> bool {
    pair.v6 == sent.v6 && pair.src == sent.dst && pair.dst == sent.src
}

fn direct_answer(sent: &ReplyKey, buf: &[u8], spans: &[LayerSpan]) -> bool {
    let Some(pair) = ip_pair(buf, spans) else {
        return false;
    };
    match sent.kind {
        ReplyKind::IcmpEcho { id, seq } => {
            let Some(s) = find(spans, ProtoId::Icmp) else {
                return false;
            };
            let h = hdr(buf, s);
            h.first() == Some(&types::ECHO_REPLY)
                && be16(h, 4) == Some(id)
                && be16(h, 6) == Some(seq)
                && !sent.v6
                && swapped(sent, &pair)
        }
        ReplyKind::Icmpv6Echo { id, seq } => {
            let Some(s) = find(spans, ProtoId::Icmpv6) else {
                return false;
            };
            let b = body(buf, s);
            b.first() == Some(&ECHO_REPLY_V6)
                && be16(b, 4) == Some(id)
                && be16(b, 6) == Some(seq)
                && sent.v6
                && swapped(sent, &pair)
        }
        ReplyKind::Tcp { sport, dport, .. } => {
            let Some(s) = find(spans, ProtoId::Tcp) else {
                return false;
            };
            let h = hdr(buf, s);
            swapped(sent, &pair) && be16(h, 0) == Some(dport) && be16(h, 2) == Some(sport)
        }
        ReplyKind::Udp { sport, dport, dns } => {
            let Some(s) = find(spans, ProtoId::Udp) else {
                return false;
            };
            let h = hdr(buf, s);
            if !(swapped(sent, &pair) && be16(h, 0) == Some(dport) && be16(h, 2) == Some(sport)) {
                return false;
            }
            match dns {
                None => true,
                // A query answers nothing, and a response is an answer only to
                // a query: scapy's `self.qr == 1 and other.qr == 0`.
                Some(ask) => {
                    ask.query
                        && find(spans, ProtoId::Dns).is_some_and(|d| {
                            dns_ask(hdr(buf, d))
                                == Some(DnsAsk {
                                    id: ask.id,
                                    query: false,
                                })
                        })
                }
            }
        }
        ReplyKind::Arp { .. } | ReplyKind::Ip => false,
    }
}

/// RFC 4443 §4.2.
const ECHO_REPLY_V6: u8 = 129;

/// How traceroute works: the reply is an error from a router that never saw
/// the datagram's payload, so the quoted header is the only thing tying the
/// two together.
fn quoted_back(sent: &ReplyKey, buf: &[u8], spans: &[LayerSpan]) -> bool {
    let Some(q) = sent.quote else {
        return false;
    };
    let Some(s) = find(spans, ProtoId::Icmp) else {
        return false;
    };
    if !hdr(buf, s).first().is_some_and(|t| ERROR_TYPES.contains(t)) {
        return false;
    }
    let inner = payload(buf, s);
    let inner_spans = dissect_spans(inner, ProtoId::Ipv4);
    let Some(ip) = inner_spans.first().filter(|s| s.proto == ProtoId::Ipv4) else {
        return false;
    };
    let h = hdr(inner, ip);
    // The addresses first: the id and the eight octets are both constant
    // across a batch of wiry's own probes, so on their own they pair a reply
    // with whichever probe happens to come first.
    if four(h, 12) != Some(q.src) || four(h, 16) != Some(q.dst) {
        return false;
    }
    if h.get(9) != Some(&q.proto) || be16(h, 4) != Some(q.ip_id) {
        return false;
    }
    let n = q.len as usize;
    payload(inner, ip).get(..n) == Some(&q.head[..n])
}

fn arp_answers(pdst: [u8; 4], buf: &[u8], spans: &[LayerSpan]) -> bool {
    let Some(s) = find(spans, ProtoId::Arp) else {
        return false;
    };
    let h = hdr(buf, s);
    be16(h, 6) == Some(crate::layers::arp::OP_IS_AT as u16) && h.get(14..18) == Some(&pdst[..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Packet;

    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    const C: [u8; 4] = [10, 0, 0, 3];
    const A6: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    const B6: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

    /// RFC 791 §3.1, no options, DF clear.
    fn ip4(proto: u8, id: u16, src: [u8; 4], dst: [u8; 4], rest: &[u8]) -> Vec<u8> {
        let mut v = vec![0x45, 0x00];
        v.extend_from_slice(&((20 + rest.len()) as u16).to_be_bytes());
        v.extend_from_slice(&id.to_be_bytes());
        v.extend_from_slice(&[0x00, 0x00, 0x40, proto, 0x00, 0x00]);
        v.extend_from_slice(&src);
        v.extend_from_slice(&dst);
        v.extend_from_slice(rest);
        v
    }

    /// RFC 8200 §3.
    fn ip6(nh: u8, src: [u8; 16], dst: [u8; 16], rest: &[u8]) -> Vec<u8> {
        let mut v = vec![0x60, 0x00, 0x00, 0x00];
        v.extend_from_slice(&(rest.len() as u16).to_be_bytes());
        v.extend_from_slice(&[nh, 0x40]);
        v.extend_from_slice(&src);
        v.extend_from_slice(&dst);
        v.extend_from_slice(rest);
        v
    }

    /// RFC 792 echo or echo reply, checksum left zero.
    fn echo(ty: u8, id: u16, seq: u16) -> Vec<u8> {
        let mut v = vec![ty, 0x00, 0x00, 0x00];
        v.extend_from_slice(&id.to_be_bytes());
        v.extend_from_slice(&seq.to_be_bytes());
        v.extend_from_slice(b"abcdefgh");
        v
    }

    /// RFC 792: type, code, checksum, four unused octets, then the datagram
    /// that provoked the error.
    fn icmp_error(ty: u8, quoted: &[u8]) -> Vec<u8> {
        let mut v = vec![ty, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        v.extend_from_slice(quoted);
        v
    }

    /// RFC 9293 §3.1, no options.
    fn tcp(sport: u16, dport: u16, seq: u32, ack: u32, flags: u8, data: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&sport.to_be_bytes());
        v.extend_from_slice(&dport.to_be_bytes());
        v.extend_from_slice(&seq.to_be_bytes());
        v.extend_from_slice(&ack.to_be_bytes());
        v.extend_from_slice(&[0x50, flags]);
        v.extend_from_slice(&[0x20, 0x00, 0x00, 0x00, 0x00, 0x00]);
        v.extend_from_slice(data);
        v
    }

    /// RFC 768, checksum left zero.
    fn udp(sport: u16, dport: u16, data: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&sport.to_be_bytes());
        v.extend_from_slice(&dport.to_be_bytes());
        v.extend_from_slice(&((8 + data.len()) as u16).to_be_bytes());
        v.extend_from_slice(&[0x00, 0x00]);
        v.extend_from_slice(data);
        v
    }

    /// RFC 1035 §4.1.1 header, RD set, one question counted.
    fn dns(id: u16) -> Vec<u8> {
        let mut v = id.to_be_bytes().to_vec();
        v.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        v
    }

    /// The same header with QR and RA set, which is what a resolver sends back.
    fn dns_response(id: u16) -> Vec<u8> {
        let mut v = dns(id);
        v[2] = 0x81;
        v[3] = 0x80;
        v
    }

    /// RFC 826 packet format over Ethernet and IPv4.
    fn arp(op: u16, psrc: [u8; 4], pdst: [u8; 4]) -> Vec<u8> {
        let mut v = vec![0x00, 0x01, 0x08, 0x00, 0x06, 0x04];
        v.extend_from_slice(&op.to_be_bytes());
        v.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        v.extend_from_slice(&psrc);
        v.extend_from_slice(&[0x00; 6]);
        v.extend_from_slice(&pdst);
        v
    }

    fn key(buf: Vec<u8>, link: ProtoId) -> ReplyKey {
        let p = Packet::dissect(buf, link);
        reply_key(p.raw_bytes(), p.layers()).expect("a key for this packet")
    }

    fn replies(sent: &ReplyKey, buf: Vec<u8>, link: ProtoId) -> bool {
        let p = Packet::dissect(buf, link);
        answers(sent, p.raw_bytes(), p.layers())
    }

    fn ip4_key(proto: u8, id: u16, rest: &[u8]) -> ReplyKey {
        key(ip4(proto, id, A, B, rest), ProtoId::Ipv4)
    }

    #[test]
    fn an_echo_reply_answers_its_request() {
        let sent = ip4_key(1, 0x1234, &echo(types::ECHO_REQUEST, 0xbeef, 7));
        assert_eq!(sent.kind, ReplyKind::IcmpEcho { id: 0xbeef, seq: 7 });
        let reply = ip4(1, 9, B, A, &echo(types::ECHO_REPLY, 0xbeef, 7));
        assert!(replies(&sent, reply, ProtoId::Ipv4));
    }

    #[test]
    fn an_echo_reply_with_another_id_seq_or_source_does_not() {
        let sent = ip4_key(1, 0x1234, &echo(types::ECHO_REQUEST, 0xbeef, 7));
        for (wrong, why) in [
            (
                ip4(1, 9, B, A, &echo(types::ECHO_REPLY, 0xbeee, 7)),
                "another id",
            ),
            (
                ip4(1, 9, B, A, &echo(types::ECHO_REPLY, 0xbeef, 8)),
                "another seq",
            ),
            (
                ip4(1, 9, C, A, &echo(types::ECHO_REPLY, 0xbeef, 7)),
                "a third host answering for one it was never asked about",
            ),
            (
                ip4(1, 9, B, A, &echo(types::ECHO_REQUEST, 0xbeef, 7)),
                "someone pinging us at the same time",
            ),
        ] {
            assert!(!replies(&sent, wrong, ProtoId::Ipv4), "{why}");
        }
    }

    #[test]
    fn an_icmpv6_echo_reply_answers_its_request() {
        let sent = key(ip6(58, A6, B6, &echo(128, 0x4242, 3)), ProtoId::Ipv6);
        assert_eq!(sent.kind, ReplyKind::Icmpv6Echo { id: 0x4242, seq: 3 });
        assert!(replies(
            &sent,
            ip6(58, B6, A6, &echo(129, 0x4242, 3)),
            ProtoId::Ipv6
        ));
        for wrong in [
            ip6(58, B6, A6, &echo(129, 0x4242, 4)),
            ip6(58, B6, A6, &echo(129, 0x4243, 3)),
            ip6(58, B6, A6, &echo(128, 0x4242, 3)),
        ] {
            assert!(!replies(&sent, wrong, ProtoId::Ipv6));
        }
    }

    #[test]
    fn a_time_exceeded_quoting_the_probe_answers_it() {
        let probe = udp(33434, 33435, b"hop");
        let sent = ip4_key(17, 0xabcd, &probe);
        let quoted = ip4(17, 0xabcd, A, B, &probe);
        let err = ip4(1, 1, C, A, &icmp_error(types::TIME_EXCEEDED, &quoted));
        assert!(replies(&sent, err, ProtoId::Ipv4));
    }

    #[test]
    fn every_error_type_that_quotes_a_datagram_answers_it() {
        let probe = tcp(1000, 80, 5, 0, 0b0000_0010, b"");
        let sent = ip4_key(6, 0x0101, &probe);
        let quoted = ip4(6, 0x0101, A, B, &probe);
        for ty in ERROR_TYPES {
            let err = ip4(1, 1, C, A, &icmp_error(ty, &quoted));
            assert!(replies(&sent, err, ProtoId::Ipv4), "type {ty}");
        }
        let not_an_error = ip4(1, 1, C, A, &icmp_error(types::ECHO_REPLY, &quoted));
        assert!(!replies(&sent, not_an_error, ProtoId::Ipv4));
    }

    #[test]
    fn an_error_quoting_another_datagram_does_not_answer() {
        let probe = udp(33434, 33435, b"hop");
        let sent = ip4_key(17, 0xabcd, &probe);
        let other_id = ip4(17, 0xabce, A, B, &probe);
        let other_ports = ip4(17, 0xabcd, A, B, &udp(33434, 33436, b"hop"));
        for quoted in [other_id, other_ports] {
            let err = ip4(1, 1, C, A, &icmp_error(types::TIME_EXCEEDED, &quoted));
            assert!(!replies(&sent, err, ProtoId::Ipv4));
        }
    }

    #[test]
    fn an_error_quoting_a_datagram_answers_whatever_it_carried() {
        // DEVIATIONS.md S1 stops at the layers this build knows; the quote does not.
        let sent = ip4_key(47, 0x7777, &[0x30, 0x00, 0x88, 0xbe, 0, 0, 0, 1, 0xff]);
        assert_eq!(sent.kind, ReplyKind::Ip);
        let quoted = ip4(
            47,
            0x7777,
            A,
            B,
            &[0x30, 0x00, 0x88, 0xbe, 0, 0, 0, 1, 0xff],
        );
        let err = ip4(1, 1, C, A, &icmp_error(types::DEST_UNREACH, &quoted));
        assert!(replies(&sent, err, ProtoId::Ipv4));
        let echoed = ip4(
            47,
            0x7777,
            B,
            A,
            &[0x30, 0x00, 0x88, 0xbe, 0, 0, 0, 1, 0xff],
        );
        assert!(
            !replies(&sent, echoed, ProtoId::Ipv4),
            "the same datagram coming back the other way"
        );
    }

    #[test]
    fn a_tcp_reply_is_the_swapped_pair_of_addresses_and_ports() {
        let sent = ip4_key(6, 1, &tcp(1000, 80, 5, 0, 0b0000_0010, b""));
        let synack = ip4(6, 2, B, A, &tcp(80, 1000, 99, 6, 0b0001_0010, b""));
        assert!(replies(&sent, synack, ProtoId::Ipv4));
    }

    #[test]
    fn a_tcp_packet_of_another_conversation_does_not_answer() {
        let sent = ip4_key(6, 1, &tcp(1000, 80, 5, 0, 0b0000_0010, b""));
        for (wrong, why) in [
            (
                ip4(6, 2, A, B, &tcp(1000, 80, 6, 0, 0b0001_0000, b"")),
                "same direction, not a reply",
            ),
            (
                ip4(6, 2, B, A, &tcp(443, 1000, 99, 6, 0b0001_0010, b"")),
                "right hosts, wrong sport",
            ),
            (
                ip4(6, 2, B, A, &tcp(80, 1001, 99, 6, 0b0001_0010, b"")),
                "right hosts, wrong dport",
            ),
            (
                ip4(6, 2, C, A, &tcp(80, 1000, 99, 6, 0b0001_0010, b"")),
                "right ports, wrong host",
            ),
            (
                ip4(17, 2, B, A, &udp(80, 1000, b"")),
                "same pair, different protocol: no fallback on the pair alone",
            ),
        ] {
            assert!(!replies(&sent, wrong, ProtoId::Ipv4), "{why}");
        }
    }

    #[test]
    fn a_rst_answering_a_syn_is_a_reply_though_its_ack_is_not_the_expected_one() {
        let sent = ip4_key(6, 1, &tcp(1000, 80, 5, 0, 0b0000_0010, b""));
        let ReplyKind::Tcp { expect_ack, .. } = sent.kind else {
            panic!("expected a TCP key");
        };
        // RFC 9293 §3.4: the SYN occupies sequence number 5, so 6 is expected.
        assert_eq!(expect_ack, 6);

        let rst = ip4(6, 2, B, A, &tcp(80, 1000, 0, 0, 0b0000_0100, b""));
        let p = Packet::dissect(rst, ProtoId::Ipv4);
        assert!(answers(&sent, p.raw_bytes(), p.layers()));
        assert_eq!(ack_consistent(&sent, p.raw_bytes(), p.layers()), None);

        let synack = Packet::dissect(
            ip4(6, 2, B, A, &tcp(80, 1000, 99, 6, 0b0001_0010, b"")),
            ProtoId::Ipv4,
        );
        assert_eq!(
            ack_consistent(&sent, synack.raw_bytes(), synack.layers()),
            Some(true)
        );
        let stale = Packet::dissect(
            ip4(6, 2, B, A, &tcp(80, 1000, 99, 4, 0b0001_0000, b"")),
            ProtoId::Ipv4,
        );
        assert!(answers(&sent, stale.raw_bytes(), stale.layers()));
        assert_eq!(
            ack_consistent(&sent, stale.raw_bytes(), stale.layers()),
            Some(false)
        );
    }

    #[test]
    fn the_expected_ack_counts_the_payload_and_a_fin() {
        let sent = ip4_key(6, 1, &tcp(1000, 80, 100, 1, 0b0001_1000, b"hello"));
        assert!(matches!(
            sent.kind,
            ReplyKind::Tcp {
                expect_ack: 105,
                ..
            }
        ));
        let fin = ip4_key(6, 1, &tcp(1000, 80, 100, 1, 0b0001_0001, b"hello"));
        assert!(matches!(
            fin.kind,
            ReplyKind::Tcp {
                expect_ack: 106,
                ..
            }
        ));
    }

    #[test]
    fn a_udp_reply_is_the_swapped_pair_of_addresses_and_ports() {
        let sent = ip4_key(17, 1, &udp(4000, 9999, b"ping"));
        assert!(replies(
            &sent,
            ip4(17, 2, B, A, &udp(9999, 4000, b"pong")),
            ProtoId::Ipv4
        ));
        for wrong in [
            ip4(17, 2, B, A, &udp(9998, 4000, b"pong")),
            ip4(17, 2, C, A, &udp(9999, 4000, b"pong")),
            ip4(17, 2, A, B, &udp(4000, 9999, b"ping")),
        ] {
            assert!(!replies(&sent, wrong, ProtoId::Ipv4));
        }
    }

    #[test]
    fn a_dns_response_must_also_carry_the_same_id() {
        let mut q = udp(5300, 53, &dns(0x1a2b));
        q.truncate(8 + 12);
        let sent = ip4_key(17, 1, &q);
        assert_eq!(
            sent.kind,
            ReplyKind::Udp {
                sport: 5300,
                dport: 53,
                dns: Some(DnsAsk {
                    id: 0x1a2b,
                    query: true
                })
            }
        );
        let good = ip4(17, 2, B, A, &udp(53, 5300, &dns_response(0x1a2b)));
        assert!(replies(&sent, good, ProtoId::Ipv4));
        let wrong_id = ip4(17, 2, B, A, &udp(53, 5300, &dns_response(0x1a2c)));
        assert!(!replies(&sent, wrong_id, ProtoId::Ipv4));
        let another_query = ip4(17, 2, B, A, &udp(53, 5300, &dns(0x1a2b)));
        assert!(
            !replies(&sent, another_query, ProtoId::Ipv4),
            "a second query with the same id is not the response to the first"
        );
    }

    #[test]
    fn a_dns_response_is_answered_by_nothing() {
        // Once paired wrong pairs in a capture of ordinary traffic: a query
        // flowing the other way matches on addresses, ports and id alone.
        let sent = key(
            ip4(17, 1, A, B, &udp(53, 5300, &dns_response(0x1a2b))),
            ProtoId::Ipv4,
        );
        assert_eq!(
            sent.kind,
            ReplyKind::Udp {
                sport: 53,
                dport: 5300,
                dns: Some(DnsAsk {
                    id: 0x1a2b,
                    query: false
                })
            }
        );
        for wrong in [
            ip4(17, 2, B, A, &udp(5300, 53, &dns(0x1a2b))),
            ip4(17, 2, B, A, &udp(5300, 53, &dns_response(0x1a2b))),
        ] {
            assert!(!replies(&sent, wrong, ProtoId::Ipv4));
        }
    }

    #[test]
    fn udp_that_is_not_dns_still_needs_only_the_swapped_pair() {
        let sent = ip4_key(17, 1, &udp(4000, 9999, b"ping"));
        assert_eq!(
            sent.kind,
            ReplyKind::Udp {
                sport: 4000,
                dport: 9999,
                dns: None
            }
        );
    }

    #[test]
    fn an_arp_reply_answers_the_request_for_its_own_address() {
        let sent = key(arp(1, A, B), ProtoId::Arp);
        assert_eq!(sent.kind, ReplyKind::Arp { pdst: B });
        assert!(replies(&sent, arp(2, B, A), ProtoId::Arp));
        for (wrong, why) in [
            (arp(2, C, A), "someone else's address"),
            (arp(1, B, A), "a request, not a reply"),
        ] {
            assert!(!replies(&sent, wrong, ProtoId::Arp), "{why}");
        }
        let p = Packet::dissect(arp(2, B, A), ProtoId::Arp);
        assert!(reply_key(p.raw_bytes(), p.layers()).is_none());
    }

    #[test]
    fn a_packet_nothing_could_answer_has_no_key() {
        for buf in [b"not a packet".to_vec(), Vec::new()] {
            let p = Packet::dissect(buf, ProtoId::Ether);
            assert!(reply_key(p.raw_bytes(), p.layers()).is_none());
        }
        let six = Packet::dissect(ip6(47, A6, B6, &[0x30, 0x00, 0x88, 0xbe]), ProtoId::Ipv6);
        assert!(
            reply_key(six.raw_bytes(), six.layers()).is_none(),
            "IPv6 carrying neither a transport this knows nor an echo request"
        );
    }

    #[test]
    fn an_error_quoting_a_probe_to_another_host_does_not_answer_ours() {
        // The multi-target sr() case: with id and payload identical across the
        // batch, the quoted addresses are the only thing telling probes apart.
        let probe = echo(types::ECHO_REQUEST, 0, 0);
        let sent = key(ip4(1, 1, A, B, &probe), ProtoId::Ipv4);
        let theirs = ip4(1, 1, A, C, &probe);
        let err = ip4(1, 55, C, A, &icmp_error(types::TIME_EXCEEDED, &theirs));
        assert!(!replies(&sent, err, ProtoId::Ipv4));
        let ours = ip4(1, 1, A, B, &probe);
        let good = ip4(1, 55, C, A, &icmp_error(types::TIME_EXCEEDED, &ours));
        assert!(replies(&sent, good, ProtoId::Ipv4));
    }

    #[test]
    fn an_error_quoting_someone_elses_datagram_does_not_answer_ours() {
        let probe = udp(33434, 33435, b"hop");
        let sent = ip4_key(17, 0xabcd, &probe);
        let strangers = ip4(17, 0xabcd, C, B, &probe);
        let err = ip4(1, 1, C, A, &icmp_error(types::TIME_EXCEEDED, &strangers));
        assert!(!replies(&sent, err, ProtoId::Ipv4));
    }

    #[test]
    fn an_error_quoting_an_empty_datagram_still_needs_the_right_addresses() {
        // `head` is empty here and matches anything, leaving the addresses as
        // the whole of the discrimination.
        let sent = key(ip4(1, 1, A, B, &[]), ProtoId::Ipv4);
        let ours = ip4(1, 1, A, B, &[]);
        let theirs = ip4(1, 1, A, C, &[]);
        assert!(replies(
            &sent,
            ip4(1, 9, C, A, &icmp_error(types::DEST_UNREACH, &ours)),
            ProtoId::Ipv4
        ));
        assert!(!replies(
            &sent,
            ip4(1, 9, C, A, &icmp_error(types::DEST_UNREACH, &theirs)),
            ProtoId::Ipv4
        ));
    }

    #[test]
    fn an_error_quoting_another_protocol_does_not_answer() {
        let probe = udp(33434, 33435, b"hop");
        let sent = ip4_key(17, 0xabcd, &probe);
        let mut quoted = ip4(6, 0xabcd, A, B, &probe);
        quoted[9] = 6;
        let err = ip4(1, 1, C, A, &icmp_error(types::TIME_EXCEEDED, &quoted));
        assert!(!replies(&sent, err, ProtoId::Ipv4));
    }

    #[test]
    fn an_echo_reply_addressed_to_a_third_party_does_not_answer_ours() {
        let sent = ip4_key(1, 0x1234, &echo(types::ECHO_REQUEST, 0, 0));
        let overheard = ip4(1, 9, B, C, &echo(types::ECHO_REPLY, 0, 0));
        assert!(!replies(&sent, overheard, ProtoId::Ipv4));
    }

    #[test]
    fn an_icmpv6_echo_reply_addressed_elsewhere_does_not_answer_ours() {
        const C6: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3];
        let sent = key(ip6(58, A6, B6, &echo(128, 0x4242, 3)), ProtoId::Ipv6);
        for (wrong, why) in [
            (
                ip6(58, B6, C6, &echo(129, 0x4242, 3)),
                "addressed to a third party, overheard promiscuously",
            ),
            (
                ip6(58, C6, A6, &echo(129, 0x4242, 3)),
                "from a host we never asked",
            ),
        ] {
            assert!(!replies(&sent, wrong, ProtoId::Ipv6), "{why}");
        }
    }

    #[test]
    fn an_ipv4_echo_reply_never_answers_an_ipv6_request_or_the_other_way() {
        let four = ip4_key(1, 1, &echo(types::ECHO_REQUEST, 1, 1));
        assert!(!replies(
            &four,
            ip6(58, B6, A6, &echo(129, 1, 1)),
            ProtoId::Ipv6
        ));
        let six = key(ip6(58, A6, B6, &echo(128, 1, 1)), ProtoId::Ipv6);
        assert!(!replies(
            &six,
            ip4(1, 9, B, A, &echo(0, 1, 1)),
            ProtoId::Ipv4
        ));
    }

    #[test]
    fn truncation_anywhere_neither_panics_nor_matches_by_accident() {
        let sent = ip4_key(1, 0x1234, &echo(types::ECHO_REQUEST, 0xbeef, 7));
        let reply = ip4(1, 9, B, A, &echo(types::ECHO_REPLY, 0xbeef, 7));
        // The ICMP id and seq end at octet 28, so that is where a clipped
        // capture starts identifying the reply.
        for cut in 0..=reply.len() {
            let p = Packet::dissect(reply[..cut].to_vec(), ProtoId::Ipv4);
            assert_eq!(
                answers(&sent, p.raw_bytes(), p.layers()),
                cut >= 28,
                "cut {cut}"
            );
            let _ = reply_key(p.raw_bytes(), p.layers());
        }
        // RFC 792 quotes the header plus 64 bits: octet 28 again.
        let probe = udp(33434, 33435, b"hop");
        let quoted = ip4(17, 0xabcd, A, B, &probe);
        let sent_udp = ip4_key(17, 0xabcd, &probe);
        for cut in 0..=quoted.len() {
            let err = ip4(
                1,
                1,
                C,
                A,
                &icmp_error(types::TIME_EXCEEDED, &quoted[..cut]),
            );
            let p = Packet::dissect(err, ProtoId::Ipv4);
            assert_eq!(
                answers(&sent_udp, p.raw_bytes(), p.layers()),
                cut >= 28,
                "cut {cut}"
            );
        }
    }
}
