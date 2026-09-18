//! Fragmentation and reassembly. IPv4 from RFC 791 §3.2, IPv6 from RFC 8200
//! §4.5.
//!
//! Overlapping bytes are resolved first-writer-wins: the earliest fragment to
//! claim a byte range owns it, and a later fragment overwrites nothing. That
//! choice is deliberate and visible, because operating systems resolve overlap
//! differently and the difference is the whole basis of fragmentation-based
//! IDS evasion.

use crate::checksum::ones_complement;
use crate::packet::dissect_spans;
use crate::proto::ProtoId;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};

/// RFC 791 §3.1: Total Length is 16 bits, so nothing reassembles larger.
pub const MAX_DATAGRAM: usize = 65535;

/// Unfinished datagrams held at once.
pub const MAX_INFLIGHT: usize = 1024;

/// Bytes held across all unfinished datagrams.
pub const MAX_BUFFERED: usize = 16 << 20;

/// Fragments one datagram may be fed. Offsets count 8-octet units, so a real
/// datagram needs at most 8,192 of them.
pub const MAX_FRAGS: usize = 8192;

/// Extension headers walked before the chain is called hostile.
const MAX_EXT: usize = 8;

const EXT_HOP_BY_HOP: u8 = 0;
const EXT_ROUTING: u8 = 43;
const EXT_FRAGMENT: u8 = 44;
const EXT_DEST_OPTS: u8 = 60;

/// What one input frame turned into. `Whole` and `Incomplete` carry only a
/// position; the caller still holds those bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Piece {
    /// Carried no fragment.
    Whole(u32),
    /// Reassembled, at the position of its first fragment.
    Complete(u32, Vec<u8>),
    /// A fragment whose datagram never completed.
    Incomplete(u32),
}

impl Piece {
    pub fn at(&self) -> u32 {
        match self {
            Piece::Whole(i) | Piece::Complete(i, _) | Piece::Incomplete(i) => *i,
        }
    }
}

fn ip_layer(buf: &[u8], link: ProtoId) -> Option<(ProtoId, usize)> {
    dissect_spans(buf, link)
        .iter()
        .find(|s| s.proto == ProtoId::Ipv4 || s.proto == ProtoId::Ipv6)
        .map(|s| (s.proto, s.off as usize))
}

/// A Total Length shorter than the header or past the capture describes
/// nothing, so the frame's own end stands in, as the dissector does.
fn v4_extent(buf: &[u8], off: usize) -> Option<(usize, usize)> {
    let hdr = buf.get(off..)?;
    if hdr.len() < 20 {
        return None;
    }
    let ihl = ((hdr[0] & 0x0f) as usize * 4).max(20);
    if hdr.len() < ihl {
        return None;
    }
    let total = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
    let end = if total >= ihl && off + total <= buf.len() {
        off + total
    } else {
        buf.len()
    };
    Some((ihl, end))
}

fn v6_end(buf: &[u8], off: usize) -> Option<usize> {
    let hdr = buf.get(off..)?;
    if hdr.len() < 40 {
        return None;
    }
    let plen = u16::from_be_bytes([hdr[4], hdr[5]]) as usize;
    let end = off + 40 + plen;
    Some(if plen > 0 && end <= buf.len() {
        end
    } else {
        buf.len()
    })
}

/// RFC 791 §3.1: the high bit of the type octet says whether the option is
/// copied into every fragment; types 0 and 1 are a single octet with no length.
fn copied_options(opts: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < opts.len() {
        let t = opts[i];
        if t == 0 {
            break;
        }
        if t == 1 {
            i += 1;
            continue;
        }
        let Some(&len) = opts.get(i + 1) else { break };
        let len = len as usize;
        if len < 2 || i + len > opts.len() {
            break;
        }
        if t & 0x80 != 0 {
            out.extend_from_slice(&opts[i..i + len]);
        }
        i += len;
    }
    // IHL counts 32-bit words, so the region pads out with End of Option List.
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

fn is_ext(nh: u8) -> bool {
    matches!(nh, EXT_HOP_BY_HOP | EXT_ROUTING | EXT_DEST_OPTS)
}

/// Every position in the extension-header chain as
/// `(next-header value, this header's offset, offset of the octet naming it)`.
/// The walk stops after `MAX_EXT` positions, so nothing downstream may assume
/// it reached the payload.
fn ext_chain(buf: &[u8], off: usize, end: usize) -> impl Iterator<Item = (u8, usize, usize)> + '_ {
    let (mut at, mut nh_at) = (off + 40, off + 6);
    let (mut left, mut done) = (MAX_EXT, false);
    std::iter::from_fn(move || {
        if done || left == 0 {
            return None;
        }
        left -= 1;
        let &nh = buf.get(nh_at)?;
        let here = (nh, at, nh_at);
        match buf.get(at + 1) {
            Some(&l) if is_ext(nh) && at + (l as usize + 1) * 8 <= end => {
                nh_at = at;
                at += (l as usize + 1) * 8;
            }
            _ => done = true,
        }
        Some(here)
    })
}

/// End of the unfragmentable part (RFC 8200 §4.5), the offset of the Next
/// Header octet that points past it, and how many chain positions it spans. A
/// Destination Options header counts as unfragmentable only when a Routing
/// header follows it, which is the one case RFC 8200 §4.1 says it is processed
/// en route.
fn v6_unfragmentable(buf: &[u8], off: usize, end: usize) -> (usize, usize, usize) {
    let (mut fixed_at, mut fixed_nh) = (off + 40, off + 6);
    let (mut prev, mut depth) = (None, 0);
    for (nh, at, nh_at) in ext_chain(buf, off, end) {
        if prev.is_some_and(|p| p != EXT_DEST_OPTS) {
            (fixed_at, fixed_nh) = (at, nh_at);
        }
        if !is_ext(nh) {
            break;
        }
        prev = Some(nh);
        depth += 1;
    }
    (fixed_at, fixed_nh, depth)
}

/// Offset of the Fragment header and of the Next Header octet pointing at it.
fn v6_frag_header(buf: &[u8], off: usize, end: usize) -> Option<(usize, usize)> {
    ext_chain(buf, off, end)
        .find(|&(nh, ..)| nh == EXT_FRAGMENT)
        .filter(|&(_, at, _)| at + 8 <= end)
        .map(|(_, at, nh_at)| (at, nh_at))
}

/// RFC 8200 §4.5 only asks the Identification differ from other in-flight
/// datagrams between the same pair; deriving it from content keeps `fragment6`
/// reproducible across runs.
fn derived_id(unfrag: &[u8], payload: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in unfrag.iter().chain(payload.iter()) {
        h ^= *b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

/// Split a datagram per RFC 791 §3.2 or RFC 8200 §4.5. `fragsize` is the
/// payload octets per fragment, rounded down to the 8-octet unit an offset
/// counts. A packet that must not or need not be split comes back whole.
pub fn fragment(buf: &[u8], link: ProtoId, fragsize: usize) -> Vec<Vec<u8>> {
    match ip_layer(buf, link) {
        Some((ProtoId::Ipv4, off)) => fragment_v4(buf, off, fragsize),
        Some((ProtoId::Ipv6, off)) => fragment_v6(buf, off, fragsize),
        _ => vec![buf.to_vec()],
    }
}

fn unit_of(fragsize: usize) -> usize {
    (fragsize / 8).max(1) * 8
}

fn fragment_v4(buf: &[u8], off: usize, fragsize: usize) -> Vec<Vec<u8>> {
    let whole = || vec![buf.to_vec()];
    let Some((ihl, end)) = v4_extent(buf, off) else {
        return whole();
    };
    let word = u16::from_be_bytes([buf[off + 6], buf[off + 7]]);
    // RFC 791 §2.3: Don't Fragment forbids the split outright.
    if word & 0x4000 != 0 {
        return whole();
    }
    // Total Length has to describe the header and the chunk together, so the
    // chunk cannot be as large as a caller asks for.
    let unit = unit_of(fragsize).min(MAX_DATAGRAM.saturating_sub(ihl) / 8 * 8);
    let payload = &buf[off + ihl..end];
    if unit == 0 || payload.len() <= unit {
        return whole();
    }
    let base = (word & 0x1fff) as usize;
    // A fragment offset is 13 bits; a wider one cannot be described.
    if base + (payload.len() - 1) / 8 > 0x1fff {
        return whole();
    }
    let opts = &buf[off + 20..off + ihl];
    let later = copied_options(opts);
    let more = word & 0x2000 != 0;

    let mut out = Vec::new();
    let mut at = 0usize;
    while at < payload.len() {
        let n = unit.min(payload.len() - at);
        let first = at == 0;
        let tail: &[u8] = if first { opts } else { &later };
        let hlen = 20 + tail.len();
        let mut frame = Vec::with_capacity(off + hlen + n);
        frame.extend_from_slice(&buf[..off + 20]);
        frame.extend_from_slice(tail);
        frame[off] = (frame[off] & 0xf0) | ((hlen / 4) as u8);
        frame[off + 2..off + 4].copy_from_slice(&((hlen + n) as u16).to_be_bytes());
        let mf = at + n < payload.len() || more;
        let w = (word & 0xc000) | if mf { 0x2000 } else { 0 } | ((base + at / 8) as u16 & 0x1fff);
        frame[off + 6..off + 8].copy_from_slice(&w.to_be_bytes());
        frame[off + 10] = 0;
        frame[off + 11] = 0;
        let ck = ones_complement(&frame[off..off + hlen]);
        frame[off + 10..off + 12].copy_from_slice(&ck.to_be_bytes());
        frame.extend_from_slice(&payload[at..at + n]);
        out.push(frame);
        at += n;
    }
    out
}

fn fragment_v6(buf: &[u8], off: usize, fragsize: usize) -> Vec<Vec<u8>> {
    let whole = || vec![buf.to_vec()];
    let Some(end) = v6_end(buf, off) else {
        return whole();
    };
    // Re-fragmenting a fragment would need a source Identification we do not
    // own; RFC 8200 §4.5 gives that to the originating node.
    if v6_frag_header(buf, off, end).is_some() {
        return whole();
    }
    let (fixed, nh_at, depth) = v6_unfragmentable(buf, off, end);
    // The Fragment header would land at chain position `depth`, and reassembly
    // walks only `MAX_EXT` of them. Splitting a chain that deep would produce
    // fragments this same module could not put back.
    if fixed >= end || nh_at >= buf.len() || depth >= MAX_EXT {
        return whole();
    }
    // Payload Length has to describe the unfragmentable extension headers, the
    // Fragment header and the chunk together.
    let room = MAX_DATAGRAM.saturating_sub(fixed - (off + 40) + 8);
    let unit = unit_of(fragsize).min(room / 8 * 8);
    let payload = &buf[fixed..end];
    if unit == 0 || payload.len() <= unit {
        return whole();
    }
    if (payload.len() - 1) / 8 > 0x1fff {
        return whole();
    }
    let nh = buf[nh_at];
    let id = derived_id(&buf[off..fixed], payload);

    let mut out = Vec::new();
    let mut at = 0usize;
    while at < payload.len() {
        let n = unit.min(payload.len() - at);
        let mf = at + n < payload.len();
        let mut frame = Vec::with_capacity(fixed + 8 + n);
        frame.extend_from_slice(&buf[..fixed]);
        frame[nh_at] = EXT_FRAGMENT;
        let w = ((at / 8) as u16) << 3 | u16::from(mf);
        frame.extend_from_slice(&[nh, 0]);
        frame.extend_from_slice(&w.to_be_bytes());
        frame.extend_from_slice(&id.to_be_bytes());
        let plen = fixed - (off + 40) + 8 + n;
        frame[off + 4..off + 6].copy_from_slice(&(plen as u16).to_be_bytes());
        frame.extend_from_slice(&payload[at..at + n]);
        out.push(frame);
        at += n;
    }
    out
}

/// RFC 791 §3.2 keys reassembly on source, destination, identification and
/// protocol; RFC 8200 §4.5 drops the protocol. Both fit here, with the
/// addresses left-aligned in 16 octets.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    src: [u8; 16],
    dst: [u8; 16],
    id: u32,
    proto: u8,
    v6: bool,
}

/// Frame bytes through the header the reassembled datagram keeps, taken from
/// the fragment at offset zero.
struct Head {
    frame: Vec<u8>,
    ip_off: usize,
    v6: bool,
}

#[derive(Default)]
struct Group {
    seq: u64,
    at: Vec<u32>,
    head: Option<Head>,
    data: Vec<u8>,
    /// Merged, disjoint, sorted byte ranges already received.
    got: Vec<(usize, usize)>,
    total: Option<usize>,
}

impl Group {
    fn complete(&self) -> bool {
        self.head.is_some() && self.total.is_some_and(|t| self.got.as_slice() == [(0, t)])
    }

    /// First writer wins: only the parts of `[start, end)` no earlier fragment
    /// claimed are written, so an overlapping fragment cannot rewrite bytes an
    /// upstream stack has already seen.
    ///
    /// `got` stays sorted and disjoint across calls, so the claim goes in by
    /// binary search. Re-sorting it per fragment made a datagram fed thousands
    /// of non-adjacent fragments cost quadratic time.
    fn absorb(&mut self, start: usize, src: &[u8]) {
        let end = start + src.len();
        if end > self.data.len() {
            self.data.resize(end, 0);
        }
        let first = self.got.partition_point(|&(_, b)| b < start);
        let mut at = start;
        for &(a, b) in &self.got[first..] {
            if a >= end {
                break;
            }
            if a > at {
                self.data[at..a].copy_from_slice(&src[at - start..a - start]);
            }
            at = at.max(b);
            if at >= end {
                break;
            }
        }
        if at < end {
            self.data[at..end].copy_from_slice(&src[at - start..]);
        }
        let last = self.got.partition_point(|&(a, _)| a <= end);
        if first < last {
            self.got[first] = (start.min(self.got[first].0), end.max(self.got[last - 1].1));
            self.got.drain(first + 1..last);
        } else {
            self.got.insert(first, (start, end));
        }
    }

    fn assemble(&mut self) -> Option<Vec<u8>> {
        let Head {
            mut frame,
            ip_off: off,
            v6,
        } = self.head.take()?;
        if v6 {
            let plen = frame.len().checked_sub(off + 40)? + self.data.len();
            if plen > MAX_DATAGRAM {
                return None;
            }
            frame[off + 4..off + 6].copy_from_slice(&(plen as u16).to_be_bytes());
        } else {
            let ihl = frame.len().checked_sub(off)?;
            let total = ihl + self.data.len();
            if total > MAX_DATAGRAM {
                return None;
            }
            frame[off + 2..off + 4].copy_from_slice(&(total as u16).to_be_bytes());
            let word = u16::from_be_bytes([frame[off + 6], frame[off + 7]]) & 0xc000;
            frame[off + 6..off + 8].copy_from_slice(&word.to_be_bytes());
            frame[off + 10] = 0;
            frame[off + 11] = 0;
            let ck = ones_complement(&frame[off..off + ihl]);
            frame[off + 10..off + 12].copy_from_slice(&ck.to_be_bytes());
        }
        frame.append(&mut self.data);
        Some(frame)
    }
}

struct Found {
    key: Key,
    at: usize,
    more: bool,
    head: Option<Head>,
    data_at: usize,
    data_end: usize,
}

fn wide(addr: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let n = addr.len().min(16);
    out[..n].copy_from_slice(&addr[..n]);
    out
}

/// `None` when the frame carries no fragment at all.
fn inspect(buf: &[u8], link: ProtoId) -> Option<Found> {
    match ip_layer(buf, link)? {
        (ProtoId::Ipv4, off) => {
            let (ihl, end) = v4_extent(buf, off)?;
            let word = u16::from_be_bytes([buf[off + 6], buf[off + 7]]);
            let at = (word & 0x1fff) as usize * 8;
            let more = word & 0x2000 != 0;
            if at == 0 && !more {
                return None;
            }
            let key = Key {
                src: wide(&buf[off + 12..off + 16]),
                dst: wide(&buf[off + 16..off + 20]),
                id: u16::from_be_bytes([buf[off + 4], buf[off + 5]]) as u32,
                proto: buf[off + 9],
                v6: false,
            };
            Some(Found {
                key,
                at,
                more,
                head: (at == 0).then(|| Head {
                    frame: buf[..off + ihl].to_vec(),
                    ip_off: off,
                    v6: false,
                }),
                data_at: off + ihl,
                data_end: end,
            })
        }
        (ProtoId::Ipv6, off) => {
            let end = v6_end(buf, off)?;
            let (fh, nh_at) = v6_frag_header(buf, off, end)?;
            let word = u16::from_be_bytes([buf[fh + 2], buf[fh + 3]]);
            let at = (word >> 3) as usize * 8;
            let more = word & 1 != 0;
            let key = Key {
                src: wide(&buf[off + 8..off + 24]),
                dst: wide(&buf[off + 24..off + 40]),
                id: u32::from_be_bytes([buf[fh + 4], buf[fh + 5], buf[fh + 6], buf[fh + 7]]),
                proto: 0,
                v6: true,
            };
            let head = (at == 0).then(|| {
                let mut frame = buf[..fh].to_vec();
                frame[nh_at] = buf[fh];
                Head {
                    frame,
                    ip_off: off,
                    v6: true,
                }
            });
            Some(Found {
                key,
                at,
                more,
                head,
                data_at: fh + 8,
                data_end: end,
            })
        }
        _ => None,
    }
}

fn spill(out: &mut Vec<Piece>, g: &Group) {
    out.extend(g.at.iter().copied().map(Piece::Incomplete));
}

#[derive(Default)]
struct Reassembler {
    groups: HashMap<Key, Group>,
    /// One entry per group, stamped so an entry left behind by a group that
    /// finished cannot evict the live group that later reclaimed its key.
    order: VecDeque<(u64, Key)>,
    seq: u64,
    buffered: usize,
    out: Vec<Piece>,
}

impl Reassembler {
    fn push(&mut self, pos: u32, buf: &[u8], link: ProtoId) {
        let Some(f) = inspect(buf, link) else {
            self.out.push(Piece::Whole(pos));
            return;
        };
        // An offset past the 16-bit Total Length cannot belong to any datagram
        // this reassembles; teardrop lives here.
        if f.at >= MAX_DATAGRAM || f.data_end - f.data_at > MAX_DATAGRAM - f.at {
            self.out.push(Piece::Incomplete(pos));
            return;
        }
        let g = match self.groups.entry(f.key) {
            Entry::Occupied(o) => o.into_mut(),
            Entry::Vacant(v) => {
                self.order.push_back((self.seq, f.key));
                self.seq += 1;
                v.insert(Group {
                    seq: self.seq - 1,
                    ..Group::default()
                })
            }
        };
        if g.at.len() >= MAX_FRAGS {
            self.out.push(Piece::Incomplete(pos));
            return;
        }
        g.at.push(pos);
        // Head and layout come from the offset-zero fragment, in any order.
        if g.head.is_none() {
            g.head = f.head;
        }
        let held = g.data.len();
        g.absorb(f.at, &buf[f.data_at..f.data_end]);
        if !f.more && g.total.is_none() {
            g.total = Some(f.at + (f.data_end - f.data_at));
        }
        self.buffered += g.data.len() - held;
        if g.complete() {
            let mut g = self.groups.remove(&f.key).expect("just looked it up");
            self.buffered -= g.data.len();
            let first = g.at[0];
            match g.assemble() {
                Some(frame) => self.out.push(Piece::Complete(first, frame)),
                None => spill(&mut self.out, &g),
            }
        }
        self.evict();
    }

    /// Oldest first, so a flood of never-completing datagrams cannot push out
    /// the one that was about to finish.
    fn evict(&mut self) {
        while self.groups.len() > MAX_INFLIGHT || self.buffered > MAX_BUFFERED {
            let Some((seq, key)) = self.order.pop_front() else {
                break;
            };
            if self.groups.get(&key).is_some_and(|g| g.seq == seq) {
                let g = self.groups.remove(&key).expect("just looked it up");
                self.buffered -= g.data.len();
                spill(&mut self.out, &g);
            }
        }
        // Every group that finished leaves its entry behind. Dropping the ones
        // no live group answers to bounds `order` at one entry per group, which
        // is what keeps this sweep amortised rather than per-fragment.
        if self.order.len() > 4 * MAX_INFLIGHT {
            let live = &self.groups;
            self.order
                .retain(|(s, k)| live.get(k).is_some_and(|g| g.seq == *s));
        }
    }

    fn finish(mut self) -> Vec<Piece> {
        for (_, g) in self.groups.drain() {
            spill(&mut self.out, &g);
        }
        self.out.sort_by_key(|p| p.at());
        self.out
    }
}

/// Reassemble every datagram the frames carry, in input order. A reassembled
/// datagram takes the position of its first fragment.
pub fn defragment<'a, I>(frames: I, link: ProtoId) -> Vec<Piece>
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let mut r = Reassembler::default();
    for (i, f) in frames.into_iter().enumerate() {
        r.push(u32::try_from(i).unwrap_or(u32::MAX), f, link);
    }
    r.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Packet;

    fn ether() -> Vec<u8> {
        let mut v = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        v.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        v.extend_from_slice(&[0x08, 0x00]);
        v
    }

    /// Ether/IPv4/payload, with the header checksum filled in.
    fn datagram(opts: &[u8], payload: &[u8]) -> Vec<u8> {
        assert_eq!(opts.len() % 4, 0);
        let mut v = ether();
        let ihl = 20 + opts.len();
        v.push(0x40 | (ihl / 4) as u8);
        v.push(0);
        v.extend_from_slice(&((ihl + payload.len()) as u16).to_be_bytes());
        v.extend_from_slice(&[0x12, 0x34, 0x00, 0x00, 0x40, 17, 0x00, 0x00]);
        v.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        v.extend_from_slice(opts);
        let ck = ones_complement(&v[14..14 + ihl]);
        v[14 + 10..14 + 12].copy_from_slice(&ck.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    fn body(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    fn v6_datagram(payload: &[u8]) -> Vec<u8> {
        v6_chained(&[], payload)
    }

    /// Ether/IPv6 with `chain` extension headers ahead of a UDP payload. Each
    /// entry names the header's own type; every one is eight octets wide.
    fn v6_chained(chain: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut body = payload.to_vec();
        let mut nh = 17u8;
        for &t in chain.iter().rev() {
            let mut hdr = vec![nh, 0, 1, 4, 0, 0, 0, 0];
            hdr.extend_from_slice(&body);
            body = hdr;
            nh = t;
        }
        let mut v = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        v.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        v.extend_from_slice(&[0x86, 0xdd]);
        v.extend_from_slice(&[0x60, 0, 0, 0]);
        v.extend_from_slice(&(body.len() as u16).to_be_bytes());
        v.extend_from_slice(&[nh, 64]);
        let payload = &body[..];
        v.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        v.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        v.extend_from_slice(payload);
        v
    }

    fn reassemble(frames: &[Vec<u8>]) -> Vec<Piece> {
        let refs: Vec<&[u8]> = frames.iter().map(|f| f.as_slice()).collect();
        defragment(refs, ProtoId::Ether)
    }

    #[test]
    fn a_short_datagram_is_not_split() {
        let d = datagram(&[], &body(100));
        assert_eq!(fragment(&d, ProtoId::Ether, 1480), vec![d]);
    }

    #[test]
    fn the_last_fragment_alone_clears_more_fragments() {
        let frames = fragment(&datagram(&[], &body(100)), ProtoId::Ether, 40);
        assert_eq!(frames.len(), 3);
        for (i, f) in frames.iter().enumerate() {
            let word = u16::from_be_bytes([f[14 + 6], f[14 + 7]]);
            assert_eq!(word & 0x2000 != 0, i < 2, "fragment {i}");
            assert_eq!((word & 0x1fff) as usize, i * 5, "fragment {i}");
            let total = u16::from_be_bytes([f[14 + 2], f[14 + 3]]) as usize;
            assert_eq!(total, f.len() - 14);
            assert_eq!(ones_complement(&f[14..14 + 20]), 0, "checksum {i}");
        }
    }

    #[test]
    fn a_fragment_size_is_rounded_down_to_the_offset_unit() {
        let frames = fragment(&datagram(&[], &body(64)), ProtoId::Ether, 23);
        // 23 rounds to 16, so 64 octets take four fragments.
        assert_eq!(frames.len(), 4);
        assert!(frames[..3].iter().all(|f| f.len() == 14 + 20 + 16));
    }

    #[test]
    fn a_size_below_the_unit_still_splits_by_one_unit() {
        let frames = fragment(&datagram(&[], &body(20)), ProtoId::Ether, 1);
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].len(), 14 + 20 + 8);
        assert_eq!(frames[2].len(), 14 + 20 + 4);
    }

    /// Total Length describes nothing, so the payload is everything after the
    /// header.
    #[test]
    fn a_chunk_too_wide_for_the_length_field_is_cut_down() {
        let mut d = datagram(&[], &body(65529));
        d[14 + 2] = 0;
        d[14 + 3] = 0;
        let frames = fragment(&d, ProtoId::Ether, usize::MAX);
        assert_eq!(frames.len(), 2);
        for f in &frames {
            let total = u16::from_be_bytes([f[14 + 2], f[14 + 3]]) as usize;
            assert_eq!(total, f.len() - 14);
        }
        let mut v6 = v6_datagram(&body(65529));
        v6[14 + 4] = 0;
        v6[14 + 5] = 0;
        for f in fragment(&v6, ProtoId::Ether, usize::MAX) {
            let plen = u16::from_be_bytes([f[14 + 4], f[14 + 5]]) as usize;
            assert_eq!(plen, f.len() - 14 - 40);
        }
    }

    #[test]
    fn dont_fragment_is_honoured() {
        let mut d = datagram(&[], &body(100));
        d[14 + 6] |= 0x40;
        assert_eq!(fragment(&d, ProtoId::Ether, 8), vec![d]);
    }

    #[test]
    fn only_the_copied_options_reach_the_later_fragments() {
        // Loose Source Route (131, copied) and Record Route (7, not copied).
        let opts = [
            0x83, 0x07, 0x04, 10, 0, 0, 9, 0x07, 0x07, 0x04, 0, 0, 0, 0, 0x00, 0x00,
        ];
        let frames = fragment(&datagram(&opts, &body(64)), ProtoId::Ether, 32);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0][14] & 0x0f, ((20 + opts.len()) / 4) as u8);
        assert_eq!(&frames[0][14 + 20..14 + 20 + opts.len()], &opts[..]);
        // The copied option is 7 octets, padded to 8.
        assert_eq!(frames[1][14] & 0x0f, 7);
        assert_eq!(
            &frames[1][14 + 20..14 + 28],
            &[0x83, 0x07, 0x04, 10, 0, 0, 9, 0x00]
        );
        assert_eq!(ones_complement(&frames[1][14..14 + 28]), 0);
    }

    /// First-writer-wins, checked against the rule written out longhand: a byte
    /// belongs to the first fragment that claimed it, whatever order and
    /// overlap the claims arrive in. `got` must stay sorted, disjoint and
    /// merged, since the fast path binary-searches it.
    #[test]
    fn absorbing_overlapping_claims_matches_the_rule_spelled_out() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 0..120 {
            let mut g = Group::default();
            let mut model: Vec<Option<u8>> = vec![None; 4096];
            for _ in 0..40 {
                let start = (next() as usize) % 4000;
                let len = (next() as usize) % 96;
                let fill = next() as u8;
                let src = vec![fill; len];
                g.absorb(start, &src);
                for (i, b) in src.iter().enumerate() {
                    model[start + i].get_or_insert(*b);
                }
                assert!(
                    g.got.windows(2).all(|w| w[0].1 < w[1].0),
                    "round {round}: ranges are not sorted and disjoint: {:?}",
                    g.got
                );
                for (i, want) in model.iter().enumerate() {
                    let held = g.got.iter().any(|&(a, b)| i >= a && i < b);
                    assert_eq!(held, want.is_some(), "round {round}: coverage at {i}");
                    if let Some(w) = want {
                        assert_eq!(g.data[i], *w, "round {round}: byte {i} was rewritten");
                    }
                }
            }
        }
    }

    #[test]
    fn round_trips_through_reassembly() {
        for opts in [&[][..], &[0x83, 0x07, 0x04, 10, 0, 0, 9, 0][..]] {
            for len in [9usize, 64, 100, 1500, 3000] {
                for size in [1, 8, 9, 16, 300, 1480] {
                    let d = datagram(opts, &body(len));
                    let frames = fragment(&d, ProtoId::Ether, size);
                    match reassemble(&frames).as_slice() {
                        [Piece::Complete(0, f)] => assert_eq!(f, &d, "len {len} size {size}"),
                        [Piece::Whole(0)] => assert_eq!(frames, vec![d.clone()]),
                        other => panic!("len {len} size {size}: {other:?}"),
                    }
                }
            }
        }
    }

    #[test]
    fn fragments_reassemble_out_of_order() {
        let d = datagram(&[], &body(200));
        let mut frames = fragment(&d, ProtoId::Ether, 24);
        frames.reverse();
        match reassemble(&frames).as_slice() {
            [Piece::Complete(0, f)] => assert_eq!(f, &d),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_overlapping_fragment_never_rewrites_what_arrived_first() {
        let d = datagram(&[], &body(64));
        let mut frames = fragment(&d, ProtoId::Ether, 16);
        let mut evil = frames[1].clone();
        for b in evil[14 + 20..].iter_mut() {
            *b = 0xff;
        }
        frames.insert(2, evil);
        match reassemble(&frames).as_slice() {
            [Piece::Complete(0, f)] => assert_eq!(f, &d),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_datagram_that_never_completes_yields_its_fragments() {
        let frames = fragment(&datagram(&[], &body(64)), ProtoId::Ether, 16);
        let missing: Vec<Vec<u8>> = frames[..3].to_vec();
        let got = reassemble(&missing);
        assert_eq!(
            got,
            vec![
                Piece::Incomplete(0),
                Piece::Incomplete(1),
                Piece::Incomplete(2)
            ]
        );
    }

    #[test]
    fn a_first_fragment_that_never_arrives_completes_nothing() {
        let frames = fragment(&datagram(&[], &body(64)), ProtoId::Ether, 16);
        let got = reassemble(&frames[1..]);
        assert!(got.iter().all(|p| matches!(p, Piece::Incomplete(_))));
    }

    #[test]
    fn unfragmented_packets_pass_through_in_place() {
        let plain = datagram(&[], &body(10));
        let mut frames = vec![plain.clone()];
        frames.extend(fragment(&datagram(&[], &body(64)), ProtoId::Ether, 16));
        frames.push(plain.clone());
        let got = reassemble(&frames);
        assert_eq!(got.len(), 3);
        assert_eq!(got[0], Piece::Whole(0));
        assert!(matches!(got[1], Piece::Complete(1, _)));
        assert_eq!(got[2], Piece::Whole(5));
    }

    #[test]
    fn two_interleaved_datagrams_stay_apart() {
        let a = datagram(&[], &body(64));
        let mut b = datagram(&[], &body(48));
        b[14 + 4] = 0x99;
        b[14 + 10] = 0;
        b[14 + 11] = 0;
        let ck = ones_complement(&b[14..14 + 20]);
        b[14 + 10..14 + 12].copy_from_slice(&ck.to_be_bytes());
        let fa = fragment(&a, ProtoId::Ether, 16);
        let fb = fragment(&b, ProtoId::Ether, 16);
        let mut mixed = Vec::new();
        for i in 0..4 {
            if let Some(f) = fa.get(i) {
                mixed.push(f.clone());
            }
            if let Some(f) = fb.get(i) {
                mixed.push(f.clone());
            }
        }
        let got = reassemble(&mixed);
        let done: Vec<&Vec<u8>> = got
            .iter()
            .filter_map(|p| match p {
                Piece::Complete(_, f) => Some(f),
                _ => None,
            })
            .collect();
        assert_eq!(done.len(), 2);
        assert!(done.contains(&&a) && done.contains(&&b));
    }

    #[test]
    fn a_flood_of_unfinished_datagrams_is_bounded() {
        let mut frames = Vec::new();
        for i in 0..(MAX_INFLIGHT + 64) {
            let mut f = fragment(&datagram(&[], &body(64)), ProtoId::Ether, 16).swap_remove(0);
            f[14 + 4..14 + 6].copy_from_slice(&(i as u16).to_be_bytes());
            frames.push(f);
        }
        let got = reassemble(&frames);
        assert_eq!(got.len(), frames.len());
        assert!(got.iter().all(|p| matches!(p, Piece::Incomplete(_))));
    }

    /// `MAX_BUFFERED` caps what unfinished datagrams may hold between them.
    /// Each of these claims 64 KB and none of them finishes.
    #[test]
    fn the_bytes_unfinished_datagrams_hold_are_bounded() {
        let mut frames = Vec::new();
        for i in 0..1400u16 {
            for at in [0u16, 8000] {
                let mut f = datagram(&[], &body(1400));
                f[14 + 4..14 + 6].copy_from_slice(&i.to_be_bytes());
                f[14 + 6..14 + 8].copy_from_slice(&(0x2000 | at).to_be_bytes());
                f[14 + 10] = 0;
                f[14 + 11] = 0;
                let ck = ones_complement(&f[14..14 + 20]);
                f[14 + 10..14 + 12].copy_from_slice(&ck.to_be_bytes());
                frames.push(f);
            }
        }
        let got = reassemble(&frames);
        assert_eq!(got.len(), frames.len());
        assert!(got.iter().all(|p| matches!(p, Piece::Incomplete(_))));
    }

    #[test]
    fn an_offset_past_the_total_length_is_refused() {
        let mut f = fragment(&datagram(&[], &body(64)), ProtoId::Ether, 16).swap_remove(1);
        f[14 + 6] = 0x3f;
        f[14 + 7] = 0xff;
        assert_eq!(reassemble(&[f]), vec![Piece::Incomplete(0)]);
    }

    #[test]
    fn a_reassembled_datagram_still_dissects() {
        let d = datagram(&[], &body(64));
        let frames = fragment(&d, ProtoId::Ether, 16);
        let Piece::Complete(_, f) = reassemble(&frames).swap_remove(0) else {
            panic!("not reassembled")
        };
        let p = Packet::dissect(f, ProtoId::Ether);
        let got: Vec<_> = p.layers().iter().map(|s| s.proto).collect();
        assert_eq!(
            got,
            vec![ProtoId::Ether, ProtoId::Ipv4, ProtoId::Udp, ProtoId::Raw]
        );
    }

    #[test]
    fn ipv6_round_trips_through_reassembly() {
        for len in [9usize, 64, 1500] {
            for size in [8, 16, 1280] {
                let d = v6_datagram(&body(len));
                let frames = fragment(&d, ProtoId::Ether, size);
                match reassemble(&frames).as_slice() {
                    [Piece::Complete(0, f)] => assert_eq!(f, &d, "len {len} size {size}"),
                    [Piece::Whole(0)] => assert_eq!(frames, vec![d.clone()]),
                    other => panic!("len {len} size {size}: {other:?}"),
                }
            }
        }
    }

    #[test]
    fn an_ipv6_fragment_header_carries_the_next_header_it_displaced() {
        let frames = fragment(&v6_datagram(&body(64)), ProtoId::Ether, 16);
        assert_eq!(frames.len(), 4);
        for (i, f) in frames.iter().enumerate() {
            assert_eq!(f[14 + 6], EXT_FRAGMENT);
            assert_eq!(f[14 + 40], 17);
            let w = u16::from_be_bytes([f[14 + 42], f[14 + 43]]);
            assert_eq!((w >> 3) as usize * 8, i * 16);
            assert_eq!(w & 1 != 0, i < 3);
            let plen = u16::from_be_bytes([f[14 + 4], f[14 + 5]]) as usize;
            assert_eq!(plen, f.len() - 14 - 40);
        }
        let ids: Vec<&[u8]> = frames.iter().map(|f| &f[14 + 44..14 + 48]).collect();
        assert!(ids.windows(2).all(|w| w[0] == w[1]));
    }

    /// RFC 8200 §4.1 puts Destination Options before a Routing header where the
    /// routers named in it are meant to read them, so that pair is
    /// unfragmentable and the same header alone is not.
    #[test]
    fn where_destination_options_sit_decides_what_is_unfragmentable() {
        for (chain, unfrag_headers) in [
            (&[][..], 0usize),
            (&[EXT_HOP_BY_HOP][..], 1),
            (&[EXT_DEST_OPTS][..], 0),
            (&[EXT_DEST_OPTS, EXT_ROUTING][..], 2),
            (&[EXT_ROUTING, EXT_DEST_OPTS][..], 1),
            (&[EXT_HOP_BY_HOP, EXT_DEST_OPTS, EXT_ROUTING][..], 3),
        ] {
            let d = v6_chained(chain, &body(200));
            let frames = fragment(&d, ProtoId::Ether, 64);
            assert!(frames.len() > 1, "{chain:?}");
            // The Fragment header lands right after the unfragmentable part.
            assert_eq!(
                frames[0][14 + 40 + unfrag_headers * 8],
                if unfrag_headers == chain.len() {
                    17
                } else {
                    chain[unfrag_headers]
                },
                "{chain:?}"
            );
            match reassemble(&frames).as_slice() {
                [Piece::Complete(0, f)] => assert_eq!(f, &d, "{chain:?}"),
                other => panic!("{chain:?}: {other:?}"),
            }
        }
    }

    /// `fragment` may not split what `defragment` cannot walk back: the
    /// Fragment header would sit past the bound on the chain walk, so
    /// reassembly would never find it.
    #[test]
    fn a_chain_too_deep_to_walk_back_is_not_split() {
        for n in 1..=MAX_EXT + 2 {
            let chain = vec![EXT_HOP_BY_HOP; n];
            let d = v6_chained(&chain, &body(200));
            let frames = fragment(&d, ProtoId::Ether, 64);
            if n >= MAX_EXT {
                assert_eq!(frames, vec![d], "{n} headers");
                continue;
            }
            match reassemble(&frames).as_slice() {
                [Piece::Complete(0, f)] => assert_eq!(f, &d, "{n} headers"),
                other => panic!("{n} headers: {other:?}"),
            }
        }
    }

    /// A key whose datagram finished leaves an entry behind in the eviction
    /// queue; the group that later reclaims that key must not die in its place.
    #[test]
    fn a_reclaimed_key_is_not_evicted_by_the_entry_its_predecessor_left() {
        let d = datagram(&[], &body(64));
        let halves = fragment(&d, ProtoId::Ether, 32);
        let mut frames = halves.clone();
        for i in 1..=MAX_INFLIGHT as u16 {
            let mut f = halves[0].clone();
            f[14 + 4..14 + 6].copy_from_slice(&i.to_be_bytes());
            frames.push(f);
        }
        // Reopening the key tips the in-flight count over its cap, so the next
        // eviction runs while the stale entry is still at the head of the queue.
        frames.push(halves[0].clone());
        frames.push(halves[1].clone());
        let reopened = frames.len() - 2;
        match reassemble(&frames).as_slice() {
            [Piece::Complete(0, a), rest @ ..] => {
                assert_eq!(a, &d);
                assert!(
                    rest.iter().any(
                        |p| matches!(p, Piece::Complete(i, f) if *i as usize == reopened && f == &d)
                    ),
                    "the reopened datagram was evicted in its predecessor's place"
                );
            }
            other => panic!("{:?}", &other[..4]),
        }
    }

    #[test]
    fn a_frame_with_no_ip_layer_comes_back_whole() {
        let mut v = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        v.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        v.extend_from_slice(&[0x08, 0x06]);
        v.extend_from_slice(&body(40));
        assert_eq!(fragment(&v, ProtoId::Ether, 8), vec![v.clone()]);
        assert_eq!(reassemble(&[v]), vec![Piece::Whole(0)]);
    }

    #[test]
    fn a_truncated_frame_is_not_a_panic() {
        let d = datagram(&[0x83, 0x07, 0x04, 10, 0, 0, 9, 0], &body(64));
        for cut in 0..d.len() {
            let short = d[..cut].to_vec();
            let frames = fragment(&short, ProtoId::Ether, 16);
            assert!(!frames.is_empty());
            let _ = reassemble(&frames);
        }
        let v6 = v6_datagram(&body(64));
        for cut in 0..v6.len() {
            let _ = fragment(&v6[..cut], ProtoId::Ether, 16);
            let _ = reassemble(&[v6[..cut].to_vec()]);
        }
    }
}
