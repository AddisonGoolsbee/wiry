//! TCP stream reassembly. RFC 9293 §3.1 gives the header, §3.4 the sequence
//! space and §3.7 the reassembly a receiver must do; the sequence number is 32
//! bits and wraps, so every comparison here is made on a 64-bit line derived
//! from the frontier rather than on the wire value.
//!
//! Overlapping bytes are resolved first-writer-wins: the earliest segment to
//! claim a stream offset owns it, and a later segment overwrites nothing. That
//! is the same choice `frag.rs` made and it is made for the same reason —
//! operating systems disagree about overlap and the disagreement is the basis
//! of stream-based IDS evasion — but TCP is the worse case, because a sender
//! also controls the window, the segment size and when it retransmits. What
//! this reassembles is therefore *a* reading of the stream, not necessarily the
//! one a given target host would have assembled.
//!
//! Nothing here is filled in for bytes that never arrived. A gap is recorded as
//! a gap and the bytes either side of it are adjacent in `data`, so the octets
//! a half holds are octets that were actually captured and the output of a run
//! can never be larger than its input. That is what keeps a crafted capture
//! from turning a few small segments into a large allocation.
//!
//! Every bound is named and stated here:
//!
//! - `MAX_STREAMS` concurrent streams. Past that the least recently active is
//!   evicted, finished, and reported with `EVICTED` set rather than dropped.
//! - `MAX_STREAM` delivered octets per direction. Past that the direction stops
//!   accepting and reports `TRUNCATED`.
//! - `MAX_HELD_SEGS` out-of-order segments and `MAX_HELD_BYTES` octets held per
//!   direction, and `MAX_HELD_TOTAL` octets held across every direction at once.
//!   Past any of those the frontier is forced forward over the missing bytes,
//!   which records a `Gap` and delivers what was waiting behind it.
//! - `MAX_AHEAD` octets past the frontier a segment may claim. A segment
//!   further out than that is refused and sets `LOSSY`; no window advertised by
//!   a real stack reaches it, and without the bound one 32-bit sequence number
//!   would decide how much a capture may allocate.
//!
//! Inserting a segment costs O(log h) in the segments already held plus the
//! octets it actually contributes, and h is bounded by `MAX_HELD_SEGS`, so no
//! arrival is linear in the stream reassembled so far.

use crate::layers::dispatch;
use crate::layers::{http, tls};
use crate::packet::dissect_spans;
use crate::proto::ProtoId;
use std::collections::{BTreeMap, HashMap, VecDeque};

/// Concurrent streams tracked at once.
pub const MAX_STREAMS: usize = 65_536;

/// Delivered octets one direction may reassemble to.
pub const MAX_STREAM: usize = 16 << 20;

/// Out-of-order segments one direction may hold behind a gap.
pub const MAX_HELD_SEGS: usize = 64;

/// Octets one direction may hold behind a gap.
pub const MAX_HELD_BYTES: usize = 256 << 10;

/// Octets held behind gaps across every direction at once.
pub const MAX_HELD_TOTAL: usize = 32 << 20;

/// How far past the frontier a segment may claim before it is refused.
pub const MAX_AHEAD: u64 = 1 << 20;

/// Segments a direction may hold before its origin is fixed. A capture can
/// start mid-stream and its first segments can be reordered, so the earliest
/// sequence number in this window becomes offset zero rather than whichever
/// segment happened to be captured first.
const ORIGIN_WINDOW: usize = 8;

/// Octets of an HTTP message's header section that are walked looking for the
/// blank line that ends it.
const MAX_HEAD: usize = 64 << 10;

/// Chunks walked in one chunked body (RFC 9112 §7.1).
const MAX_CHUNKS: usize = 1 << 16;

pub const SAW_SYN: u8 = 1;
pub const SAW_FIN: u8 = 2;
pub const SAW_RST: u8 = 4;
/// Octets were refused by a bound, so the stream has a hole `gaps` may not name.
pub const LOSSY: u8 = 8;
/// The direction reached `MAX_STREAM` and stopped accepting.
pub const TRUNCATED: u8 = 16;

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;

/// Where one packet's octets landed in the reassembled direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seg {
    pub at: u32,
    pub len: u32,
    pub pkt: u32,
}

/// Octets that never arrived. `at` is the offset in `data` where they would
/// have been; the octets either side of it are adjacent, because nothing is
/// invented to stand in for what is missing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gap {
    pub at: u32,
    pub len: u64,
}

#[derive(Default)]
struct Held {
    bytes: Vec<u8>,
    pkt: u32,
}

/// One direction of one stream, as it is handed back.
#[derive(Default, Debug)]
pub struct Half {
    pub data: Vec<u8>,
    /// Sorted by `at`, disjoint: the provenance a caller maps an offset through.
    pub segs: Vec<Seg>,
    pub gaps: Vec<Gap>,
    pub flags: u8,
    /// Octets a bound refused.
    pub dropped: u64,
}

impl Half {
    /// The segment the octet at `off` came from.
    pub fn seg_at(&self, off: u32) -> Option<Seg> {
        let i = self.segs.partition_point(|s| s.at <= off).checked_sub(1)?;
        let s = self.segs[i];
        (off < s.at + s.len).then_some(s)
    }

    /// The packet the octet at `off` came from.
    pub fn packet_at(&self, off: u32) -> Option<u32> {
        self.seg_at(off).map(|s| s.pkt)
    }

    /// The segments overlapping `[at, at + len)`. `segs` is sorted and
    /// disjoint, so this is two searches and not a scan: asking once per
    /// message with a scan costs the whole direction per message, which is
    /// quadratic on a direction carrying many small records.
    pub fn segs_in(&self, at: u32, len: u32) -> &[Seg] {
        let end = at.saturating_add(len);
        let lo = self.segs.partition_point(|s| s.at + s.len <= at);
        let hi = self.segs.partition_point(|s| s.at < end);
        &self.segs[lo..hi]
    }
}

#[derive(Default)]
struct Build {
    half: Half,
    held: BTreeMap<u64, Held>,
    held_bytes: usize,
    /// Sequence of the next octet to deliver, and the reference every 32-bit
    /// sequence number is read against. Before `open` there is no frontier and
    /// it holds the first sequence number seen instead. It only ever moves
    /// forward, which is what keeps a segment at the frontier expressible: a
    /// second reference that lagged behind it would, after 2^31 of advance,
    /// map arriving octets to the wrong side of the line and the direction
    /// would go deaf without saying so.
    next: u64,
    /// The lowest offset this direction can ever deliver. Octets below it are
    /// not a retransmission of anything, so refusing them is a loss to report.
    origin: u64,
    started: bool,
    open: bool,
}

impl Build {
    fn absolute(&self, seq: u32) -> u64 {
        let d = seq.wrapping_sub(self.next as u32) as i32 as i64;
        (self.next as i64 + d) as u64
    }

    fn feed(&mut self, seq: u32, flags: u8, data: &[u8], pkt: u32) {
        if !self.started {
            // The line starts one wrap in, so a segment that arrives before the
            // first one seen still has somewhere to sit and the reference plus
            // a 32-bit delta stays positive.
            self.next = seq as u64 + (1u64 << 32);
            self.origin = self.next;
            self.started = true;
        }
        let mut at = self.absolute(seq);
        if flags & SYN != 0 {
            self.half.flags |= SAW_SYN;
            if !self.open {
                self.origin = at;
                self.next = at.saturating_add(1);
                self.open = true;
            }
            // RFC 9293 §3.4: SYN occupies one sequence number, so any octets
            // riding with it start one past it.
            at = at.saturating_add(1);
        }
        if flags & FIN != 0 {
            self.half.flags |= SAW_FIN;
        }
        if flags & RST != 0 {
            self.half.flags |= SAW_RST;
        }
        if data.is_empty() {
            return;
        }
        if !self.open {
            // Before the origin is fixed there is no frontier to measure
            // against, so the first sequence number seen stands in for one.
            if at.abs_diff(self.next) > MAX_AHEAD {
                self.half.flags |= LOSSY;
                self.half.dropped += data.len() as u64;
                return;
            }
            self.hold(at, data, pkt);
            if self.held.len() >= ORIGIN_WINDOW {
                self.fix_origin();
                self.drain();
            }
            return;
        }
        if at < self.origin {
            self.half.flags |= LOSSY;
            self.half.dropped += (self.origin - at).min(data.len() as u64);
        }
        let end = at.saturating_add(data.len() as u64);
        if end <= self.next {
            return;
        }
        let (at, data) = if at < self.next {
            let cut = (self.next - at) as usize;
            (self.next, &data[cut.min(data.len())..])
        } else {
            (at, data)
        };
        if at > self.next {
            if at - self.next > MAX_AHEAD {
                self.half.flags |= LOSSY;
                self.half.dropped += data.len() as u64;
                return;
            }
            self.hold(at, data, pkt);
            self.relieve();
            return;
        }
        self.append(data, pkt);
        self.drain();
    }

    fn fix_origin(&mut self) {
        let Some((&first, _)) = self.held.first_key_value() else {
            return;
        };
        self.next = first;
        self.origin = first;
        self.open = true;
    }

    /// First writer wins, so only the parts of `[at, at + src.len())` that no
    /// held segment already claims are kept. The pieces go in as their own
    /// entries rather than being concatenated onto a neighbour: concatenating
    /// would let a sender who sends descending, overlapping segments pay one
    /// small segment for one whole-buffer copy.
    fn hold(&mut self, at: u64, src: &[u8], pkt: u32) {
        let end = at.saturating_add(src.len() as u64);
        let mut cur = at;
        if let Some((&ps, h)) = self.held.range(..=at).next_back() {
            let pe = ps + h.bytes.len() as u64;
            if pe >= end {
                return;
            }
            cur = cur.max(pe);
        }
        while cur < end {
            let stop = match self.held.range(cur..).next() {
                Some((&ks, h)) if ks < end => (ks, ks + h.bytes.len() as u64),
                _ => (end, end),
            };
            if stop.0 > cur {
                let a = (cur - at) as usize;
                let b = (stop.0 - at) as usize;
                let bytes = src[a..b].to_vec();
                self.held_bytes += bytes.len();
                self.held.insert(cur, Held { bytes, pkt });
            }
            // Held entries are never empty, so `stop.1` already passes `cur`;
            // the floor is what makes that an invariant rather than a trust,
            // on a loop whose shape the sender chooses.
            cur = stop.1.max(cur.saturating_add(1));
        }
    }

    /// Give up on the octets in front of what is held: record the gap, never
    /// guess at it, and deliver what was waiting behind it. `false` when there
    /// is nothing left to wait for.
    fn give_up_on_front(&mut self) -> bool {
        let Some((&first, _)) = self.held.first_key_value() else {
            return false;
        };
        if first > self.next {
            self.half.gaps.push(Gap {
                at: self.half.data.len() as u32,
                len: first - self.next,
            });
            self.next = first;
        }
        self.drain();
        true
    }

    /// Bring the held set back under its bounds.
    fn relieve(&mut self) {
        while (self.held.len() > MAX_HELD_SEGS || self.held_bytes > MAX_HELD_BYTES)
            && self.give_up_on_front()
        {}
    }

    fn drain(&mut self) {
        while let Some((&ks, _)) = self.held.first_key_value() {
            if ks > self.next {
                break;
            }
            let h = self.held.remove(&ks).expect("just looked it up");
            self.held_bytes -= h.bytes.len();
            let ke = ks + h.bytes.len() as u64;
            if ke <= self.next {
                continue;
            }
            let skip = (self.next - ks) as usize;
            self.append(&h.bytes[skip..], h.pkt);
        }
    }

    fn append(&mut self, data: &[u8], pkt: u32) {
        let room = MAX_STREAM - self.half.data.len();
        if room == 0 {
            self.half.flags |= TRUNCATED;
            self.half.dropped += data.len() as u64;
            self.next = self.next.saturating_add(data.len() as u64);
            return;
        }
        let n = data.len().min(room);
        if n < data.len() {
            self.half.flags |= TRUNCATED;
            self.half.dropped += (data.len() - n) as u64;
        }
        match self.half.segs.last_mut() {
            Some(s) if s.pkt == pkt && s.at + s.len == self.half.data.len() as u32 => {
                s.len += n as u32
            }
            _ => self.half.segs.push(Seg {
                at: self.half.data.len() as u32,
                len: n as u32,
                pkt,
            }),
        }
        self.half.data.extend_from_slice(&data[..n]);
        self.next = self.next.saturating_add(data.len() as u64);
    }

    /// Everything still held is delivered, each run behind the gap in front of
    /// it, so a stream that never became contiguous still hands back its octets.
    fn finish(mut self) -> Half {
        if !self.open {
            self.fix_origin();
        }
        while self.give_up_on_front() {}
        self.half
    }
}

/// A stream is keyed on the address pair and the port pair without direction,
/// so both halves of one connection meet here. Direction 0 is the side that
/// opened it where a SYN says so, and otherwise the side the first captured
/// packet came from.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    a: [u8; 16],
    b: [u8; 16],
    pa: u16,
    pb: u16,
    v6: bool,
}

/// One reassembled connection. `halves[0]` runs `src:sport > dst:dport`.
#[derive(Debug)]
pub struct Stream {
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    pub v6: bool,
    /// Position of the first packet seen on this stream.
    pub first: u32,
    /// The stream was given up on to stay inside `MAX_STREAMS`; packets on the
    /// same addresses after that point start another stream.
    pub evicted: bool,
    pub halves: [Half; 2],
}

impl Stream {
    /// The spelling `PacketList.sessions()` uses for the same flow, so a stream
    /// and a session name the same connection the same way.
    pub fn key(&self) -> String {
        format!(
            "TCP {}:{} > {}:{}",
            addr(&self.src, self.v6),
            self.sport,
            addr(&self.dst, self.v6),
            self.dport
        )
    }

    /// Positions of every packet that contributed octets, in order.
    pub fn packets(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self.halves[0]
            .segs
            .iter()
            .chain(self.halves[1].segs.iter())
            .map(|s| s.pkt)
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }
}

fn addr(a: &[u8; 16], v6: bool) -> String {
    let v = if v6 {
        crate::field::FieldValue::Ipv6(*a)
    } else {
        crate::field::FieldValue::Ipv4([a[0], a[1], a[2], a[3]])
    };
    crate::show::render_value(&v)
}

struct Live {
    key_src: [u8; 16],
    key_dst: [u8; 16],
    sport: u16,
    dport: u16,
    v6: bool,
    first: u32,
    seq: u64,
    build: [Build; 2],
}

/// What one frame carries, as far as this module cares.
struct Segment {
    key: Key,
    src: [u8; 16],
    dst: [u8; 16],
    sport: u16,
    dport: u16,
    v6: bool,
    seq: u32,
    flags: u8,
    at: usize,
    end: usize,
}

fn wide(a: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let n = a.len().min(16);
    out[..n].copy_from_slice(&a[..n]);
    out
}

/// `None` when the frame carries no TCP segment this can key.
fn inspect(buf: &[u8], link: ProtoId) -> Option<Segment> {
    let spans = dissect_spans(buf, link);
    let tcp = spans.iter().find(|s| s.proto == ProtoId::Tcp)?;
    let ip = spans
        .iter()
        .find(|s| s.proto == ProtoId::Ipv4 || s.proto == ProtoId::Ipv6)?;
    let v6 = ip.proto == ProtoId::Ipv6;
    let o = ip.off as usize;
    let (src, dst) = if v6 {
        (
            wide(buf.get(o + 8..o + 24)?),
            wide(buf.get(o + 24..o + 40)?),
        )
    } else {
        (
            wide(buf.get(o + 12..o + 16)?),
            wide(buf.get(o + 16..o + 20)?),
        )
    };
    let t = tcp.off as usize;
    let hdr = buf.get(t..)?;
    if hdr.len() < 20 {
        return None;
    }
    let sport = u16::from_be_bytes([hdr[0], hdr[1]]);
    let dport = u16::from_be_bytes([hdr[2], hdr[3]]);
    let seq = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
    let flags = hdr[13];
    // The payload extent is the dissector's, not a second reading of Data
    // Offset, so a segment and the stream it joins cannot disagree about which
    // octets are payload.
    let at = (t + tcp.hlen as usize).min(buf.len());
    let end = (t + tcp.total as usize).min(buf.len()).max(at);
    let key = if (src, sport) <= (dst, dport) {
        Key {
            a: src,
            b: dst,
            pa: sport,
            pb: dport,
            v6,
        }
    } else {
        Key {
            a: dst,
            b: src,
            pa: dport,
            pb: sport,
            v6,
        }
    };
    Some(Segment {
        key,
        src,
        dst,
        sport,
        dport,
        v6,
        seq,
        flags,
        at,
        end,
    })
}

#[derive(Default)]
pub struct Reassembler {
    live: HashMap<Key, Live>,
    /// One entry per live stream, stamped so an entry left behind by an evicted
    /// stream cannot evict the one that later reclaimed its key. A stamp is
    /// pushed on every touch, which makes eviction least-recently-active.
    order: VecDeque<(u64, Key)>,
    seq: u64,
    held: usize,
    out: Vec<Stream>,
}

impl Reassembler {
    pub fn push(&mut self, pos: u32, buf: &[u8], link: ProtoId) {
        let Some(s) = inspect(buf, link) else {
            return;
        };
        let stamp = self.seq;
        self.seq += 1;
        let live = self.live.entry(s.key).or_insert_with(|| {
            // A SYN with no ACK is the side that opened the connection; with no
            // SYN in the capture the first packet's own direction stands.
            let client = s.flags & SYN != 0 && s.flags & ACK != 0;
            Live {
                key_src: if client { s.dst } else { s.src },
                key_dst: if client { s.src } else { s.dst },
                sport: if client { s.dport } else { s.sport },
                dport: if client { s.sport } else { s.dport },
                v6: s.v6,
                first: pos,
                seq: stamp,
                build: [Build::default(), Build::default()],
            }
        });
        live.seq = stamp;
        let dir = usize::from(live.key_src != s.src || live.sport != s.sport);
        let before = live.build[dir].held_bytes;
        live.build[dir].feed(s.seq, s.flags, &buf[s.at..s.end], pos);
        self.held = self.held + live.build[dir].held_bytes - before;
        self.order.push_back((stamp, s.key));
        self.evict();
    }

    fn evict(&mut self) {
        while self.live.len() > MAX_STREAMS || self.held > MAX_HELD_TOTAL {
            let Some((stamp, key)) = self.order.pop_front() else {
                break;
            };
            if self.live.get(&key).is_some_and(|l| l.seq == stamp) {
                let l = self.live.remove(&key).expect("just looked it up");
                self.retire(l, true);
            }
        }
        // Every touch and every eviction leaves a stale entry behind. Dropping
        // the ones no live stream answers to bounds `order` at one entry per
        // stream, which is what keeps this sweep amortised rather than
        // per-packet.
        if self.order.len() > 4 * self.live.len() + 4 * ORIGIN_WINDOW {
            let live = &self.live;
            self.order
                .retain(|(s, k)| live.get(k).is_some_and(|l| l.seq == *s));
        }
    }

    fn retire(&mut self, l: Live, evicted: bool) {
        self.held -= l.build[0].held_bytes + l.build[1].held_bytes;
        let [a, b] = l.build;
        let halves = [a.finish(), b.finish()];
        self.out.push(Stream {
            src: l.key_src,
            dst: l.key_dst,
            sport: l.sport,
            dport: l.dport,
            v6: l.v6,
            first: l.first,
            evicted,
            halves,
        });
    }

    pub fn finish(mut self) -> Vec<Stream> {
        let keys: Vec<Key> = self.live.keys().copied().collect();
        for k in keys {
            let l = self.live.remove(&k).expect("just listed it");
            self.retire(l, false);
        }
        self.out.sort_by_key(|s| s.first);
        self.out
    }
}

/// Reassemble every TCP stream the frames carry. Streams come back ordered by
/// the position of their first packet.
pub fn reassemble<'a, I>(frames: I, link: ProtoId) -> Vec<Stream>
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let mut r = Reassembler::default();
    for (i, f) in frames.into_iter().enumerate() {
        r.push(u32::try_from(i).unwrap_or(u32::MAX), f, link);
    }
    r.finish()
}

/// Octets of framing the message splice may add to the capture it was given.
/// Each message costs one frame of headers, and a message can be as short as a
/// five-octet TLS record, so without a ceiling a crafted capture comes back
/// about twelve times its own size. Past it, messages are left unframed and
/// their packets pass through as captured. The framing that keeps a partly
/// consumed packet whole is outside this bound and inside the input's: it is
/// at most two frames per contributing segment.
pub const MAX_REFRAME_GROWTH: usize = 64 << 20;

/// Where a frame's own headers end and its TCP payload begins.
pub struct Splice {
    pub ip: usize,
    pub tcp: usize,
    pub payload: usize,
    pub v6: bool,
}

pub fn splice(buf: &[u8], link: ProtoId) -> Option<Splice> {
    let spans = dissect_spans(buf, link);
    let tcp = spans.iter().find(|s| s.proto == ProtoId::Tcp)?;
    let ip = spans
        .iter()
        .find(|s| s.proto == ProtoId::Ipv4 || s.proto == ProtoId::Ipv6)?;
    let payload = (tcp.off + tcp.hlen) as usize;
    (payload <= buf.len()).then(|| Splice {
        ip: ip.off as usize,
        tcp: tcp.off as usize,
        payload,
        v6: ip.proto == ProtoId::Ipv6,
    })
}

/// Octets of reassembled payload one frame's headers can describe. RFC 791
/// §3.1's Total Length and RFC 8200 §3's Payload Length are both 16 bits, so a
/// longer message has to be handed back in more than one frame.
pub fn room(s: &Splice) -> usize {
    let hdrs = s.payload.saturating_sub(s.ip);
    if s.v6 {
        0xffff_usize.saturating_sub(hdrs.saturating_sub(40))
    } else {
        0xffff_usize.saturating_sub(hdrs)
    }
}

/// `src`'s own headers carrying `data` as their TCP payload, with `skip` octets
/// of that frame's payload ahead of where `data` starts. Lengths are
/// recomputed and so is the IPv4 header checksum; the TCP checksum is not,
/// because a reassembled message was never one segment and no checksum covers
/// it.
pub fn reframe(src: &[u8], link: ProtoId, skip: u32, data: &[u8]) -> Option<Vec<u8>> {
    reframe_with(src, &splice(src, link)?, skip, data)
}

/// `reframe` for a caller that already holds the frame's `Splice`, so a frame
/// carrying many messages is dissected once rather than once per message.
pub fn reframe_with(src: &[u8], s: &Splice, skip: u32, data: &[u8]) -> Option<Vec<u8>> {
    // A snaplen-clipped frame can end inside the headers this rewrites, and a
    // frame that cannot describe its own headers cannot be given new ones.
    let ip_min = if s.v6 { 40 } else { 20 };
    if s.payload < s.tcp + 20 || s.tcp < s.ip + ip_min || data.len() > room(s) {
        return None;
    }
    let mut f = Vec::with_capacity(s.payload + data.len());
    f.extend_from_slice(&src[..s.payload]);
    let seq = u32::from_be_bytes([f[s.tcp + 4], f[s.tcp + 5], f[s.tcp + 6], f[s.tcp + 7]])
        .wrapping_add(skip);
    f[s.tcp + 4..s.tcp + 8].copy_from_slice(&seq.to_be_bytes());
    f.extend_from_slice(data);
    if s.v6 {
        let plen = (f.len() - s.ip - 40) as u16;
        f[s.ip + 4..s.ip + 6].copy_from_slice(&plen.to_be_bytes());
    } else {
        let total = (f.len() - s.ip) as u16;
        f[s.ip + 2..s.ip + 4].copy_from_slice(&total.to_be_bytes());
        let ihl = (f[s.ip] & 0x0f) as usize * 4;
        if s.ip + ihl <= f.len() {
            f[s.ip + 10] = 0;
            f[s.ip + 11] = 0;
            let ck = crate::checksum::ones_complement(&f[s.ip..s.ip + ihl]);
            f[s.ip + 10..s.ip + 12].copy_from_slice(&ck.to_be_bytes());
        }
    }
    Some(f)
}

/// Which application protocol a reassembled direction speaks, decided by the
/// same port table and the same content guards a single segment goes through,
/// so a stream and a segment cannot disagree about what they are.
pub fn app_of(sport: u16, dport: u16, data: &[u8]) -> Option<ProtoId> {
    dispatch::by_tcp_port(sport, dport, data)
}

/// Octets the first complete application message in `data` occupies, or `None`
/// when the message is not all there yet. This is the whole reason reassembly
/// pays: a message that crossed a segment boundary is one message here.
pub fn message_len(app: ProtoId, data: &[u8]) -> Option<usize> {
    match app {
        ProtoId::Http => http_len(data),
        ProtoId::Tls => tls_len(data),
        _ => None,
    }
}

/// One complete application message found in a reassembled direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message {
    pub stream: u32,
    pub dir: u8,
    pub app: ProtoId,
    /// Extent in the direction's `data`.
    pub at: u32,
    pub len: u32,
    /// The packet the message starts in, and how much of that packet's payload
    /// runs ahead of it.
    pub pkt: u32,
    pub skip: u32,
}

/// Every complete application message in every stream, in capture order. A
/// message that crossed a segment boundary appears once here and in no single
/// packet, which is the whole point of reassembling.
pub fn app_messages(streams: &[Stream]) -> Vec<Message> {
    let mut out = Vec::new();
    for (i, s) in streams.iter().enumerate() {
        for (d, h) in s.halves.iter().enumerate() {
            let (sp, dp) = if d == 0 {
                (s.sport, s.dport)
            } else {
                (s.dport, s.sport)
            };
            let Some(app) = app_of(sp, dp, &h.data) else {
                continue;
            };
            for (at, len) in messages(app, &h.data) {
                let Some(seg) = h.seg_at(at as u32) else {
                    continue;
                };
                out.push(Message {
                    stream: i as u32,
                    dir: d as u8,
                    app,
                    at: at as u32,
                    len: len as u32,
                    pkt: seg.pkt,
                    skip: at as u32 - seg.at,
                });
            }
        }
    }
    out.sort_by_key(|m| (m.pkt, m.skip));
    out
}

/// Every complete message in `data`, as `(offset, length)`.
pub fn messages(app: ProtoId, data: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < data.len() {
        match message_len(app, &data[at..]) {
            Some(n) if n > 0 => {
                out.push((at, n));
                at += n;
            }
            _ => break,
        }
    }
    out
}

fn tls_len(d: &[u8]) -> Option<usize> {
    if !tls::looks_like(d) {
        return None;
    }
    let n = 5 + u16::from_be_bytes([*d.get(3)?, *d.get(4)?]) as usize;
    (d.len() >= n).then_some(n)
}

/// RFC 9112 §2.1: the header section ends at the first empty line. The walk is
/// bounded because the line it looks for is under the sender's control.
fn head_end(d: &[u8]) -> Option<usize> {
    let lim = d.len().min(MAX_HEAD);
    let mut i = 0usize;
    while i < lim {
        let nl = i + d[i..lim].iter().position(|c| *c == b'\n')?;
        let blank = nl == i || (nl == i + 1 && d[i] == b'\r');
        if blank {
            return Some(nl + 1);
        }
        i = nl + 1;
    }
    None
}

fn header_value<'a>(head: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let start = head
        .iter()
        .position(|c| *c == b'\n')
        .map_or(head.len(), |n| n + 1);
    for line in head.get(start..)?.split(|c| *c == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(c) = line.iter().position(|b| *b == b':') else {
            continue;
        };
        if line[..c].eq_ignore_ascii_case(name) {
            let v = &line[c + 1..];
            let a = v.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(0);
            return Some(&v[a..]);
        }
    }
    None
}

/// RFC 9112 §7.1: `<size in hex> CRLF <data> CRLF`, ending with a zero size and
/// a trailer section.
fn chunked_len(body: &[u8]) -> Option<usize> {
    let mut i = 0usize;
    for _ in 0..MAX_CHUNKS {
        let nl = i + body.get(i..)?.iter().position(|c| *c == b'\n')?;
        let line = &body[i..nl];
        let digits = line
            .iter()
            .take_while(|c| c.is_ascii_hexdigit())
            .count()
            .min(8);
        if digits == 0 {
            return None;
        }
        let n = std::str::from_utf8(&line[..digits])
            .ok()
            .and_then(|s| usize::from_str_radix(s, 16).ok())?;
        i = nl + 1;
        if n == 0 {
            return head_end(body.get(i..)?).map(|e| i + e);
        }
        i = i.checked_add(n)?.checked_add(2)?;
        if i > body.len() {
            return None;
        }
    }
    None
}

fn http_len(d: &[u8]) -> Option<usize> {
    if !http::looks_like(d) {
        return None;
    }
    let head = head_end(d)?;
    let body = &d[head..];
    if let Some(v) = header_value(&d[..head], b"transfer-encoding") {
        if v.to_ascii_lowercase().windows(7).any(|w| w == b"chunked") {
            return chunked_len(body).map(|n| head + n);
        }
    }
    if let Some(v) = header_value(&d[..head], b"content-length") {
        let digits = v.iter().take_while(|c| c.is_ascii_digit()).count().min(19);
        let n: usize = std::str::from_utf8(&v[..digits]).ok()?.parse().ok()?;
        return (body.len() >= n).then_some(head + n);
    }
    // RFC 9112 §6.3: with no length and no chunking a request has no body, and
    // a response runs to the close of the stream, which no arriving octet can
    // announce.
    if d.starts_with(b"HTTP/") {
        return None;
    }
    Some(head)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ether() -> Vec<u8> {
        let mut v = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        v.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        v.extend_from_slice(&[0x08, 0x00]);
        v
    }

    /// Ether/IPv4/TCP with the given sequence number, flags and payload.
    fn seg(a: u8, b: u8, sport: u16, dport: u16, seq: u32, flags: u8, data: &[u8]) -> Vec<u8> {
        let mut v = ether();
        let total = 20 + 20 + data.len();
        v.push(0x45);
        v.push(0);
        v.extend_from_slice(&(total as u16).to_be_bytes());
        v.extend_from_slice(&[0x12, 0x34, 0x00, 0x00, 0x40, 6, 0x00, 0x00]);
        v.extend_from_slice(&[10, 0, 0, a, 10, 0, 0, b]);
        let ck = crate::checksum::ones_complement(&v[14..34]);
        v[14 + 10..14 + 12].copy_from_slice(&ck.to_be_bytes());
        v.extend_from_slice(&sport.to_be_bytes());
        v.extend_from_slice(&dport.to_be_bytes());
        v.extend_from_slice(&seq.to_be_bytes());
        v.extend_from_slice(&[0, 0, 0, 0]);
        v.push(0x50);
        v.push(flags);
        v.extend_from_slice(&[0x20, 0x00, 0x00, 0x00, 0x00, 0x00]);
        v.extend_from_slice(data);
        v
    }

    fn c2s(seq: u32, data: &[u8]) -> Vec<u8> {
        seg(1, 2, 1234, 80, seq, 0x18, data)
    }

    fn s2c(seq: u32, data: &[u8]) -> Vec<u8> {
        seg(2, 1, 80, 1234, seq, 0x18, data)
    }

    fn run(frames: &[Vec<u8>]) -> Vec<Stream> {
        let refs: Vec<&[u8]> = frames.iter().map(|f| f.as_slice()).collect();
        reassemble(refs, ProtoId::Ether)
    }

    fn body(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn segments_in_order_become_one_stream() {
        let s = run(&[c2s(1000, b"GET "), c2s(1004, b"/ HTTP/1.1\r\n\r\n")]);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].halves[0].data, b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(s[0].key(), "TCP 10.0.0.1:1234 > 10.0.0.2:80");
        assert!(s[0].halves[0].gaps.is_empty());
    }

    #[test]
    fn the_two_directions_stay_apart() {
        let s = run(&[c2s(10, b"ping"), s2c(90, b"pong"), c2s(14, b"!")]);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].halves[0].data, b"ping!");
        assert_eq!(s[0].halves[1].data, b"pong");
    }

    #[test]
    fn a_syn_ack_first_still_names_the_client_as_direction_zero() {
        let s = run(&[seg(2, 1, 80, 1234, 500, SYN | ACK, b""), c2s(10, b"hi")]);
        assert_eq!(s[0].sport, 1234);
        assert_eq!(s[0].dport, 80);
        assert_eq!(s[0].halves[0].data, b"hi");
    }

    #[test]
    fn out_of_order_segments_are_put_back_in_order() {
        let s = run(&[c2s(100, b"ccc"), c2s(94, b"aaa"), c2s(97, b"bbb")]);
        assert_eq!(s[0].halves[0].data, b"aaabbbccc");
        assert!(s[0].halves[0].gaps.is_empty());
    }

    #[test]
    fn a_retransmission_is_delivered_once() {
        let s = run(&[c2s(5, b"hello"), c2s(5, b"hello"), c2s(10, b" there")]);
        assert_eq!(s[0].halves[0].data, b"hello there");
    }

    /// First writer wins, so the bytes an overlapping retransmission carries
    /// never displace the ones already delivered.
    #[test]
    fn an_overlapping_retransmission_never_rewrites_what_arrived_first() {
        let s = run(&[c2s(0, b"AAAA"), c2s(2, b"XXXXBB")]);
        assert_eq!(s[0].halves[0].data, b"AAAAXXBB");
        // The overlap [2,4) kept the first writer's octets; only [4,8) is new.
        let s = run(&[c2s(0, b"AAAA"), c2s(2, b"xxbbbb"), c2s(0, b"ZZZZZZZZZZ")]);
        assert_eq!(s[0].halves[0].data, b"AAAAbbbbZZ");
    }

    /// An out-of-order segment that overlaps one already held keeps the held
    /// octets, which is the same rule applied ahead of the frontier.
    #[test]
    fn overlap_between_two_held_segments_keeps_the_first() {
        let s = run(&[c2s(10, b"BBBB"), c2s(12, b"xxCC"), c2s(0, &body(10))]);
        assert_eq!(&s[0].halves[0].data[10..], b"BBBBCC");
    }

    #[test]
    fn a_gap_is_reported_and_never_filled_in() {
        let mut frames = vec![c2s(0, b"head")];
        // Enough held segments to force the frontier over the missing octets.
        for i in 0..(MAX_HELD_SEGS + 2) as u32 {
            frames.push(c2s(1000 + i * 4, b"tail"));
        }
        let s = run(&frames);
        let h = &s[0].halves[0];
        assert!(h.data.starts_with(b"head"));
        assert!(h.data.ends_with(b"tail"));
        assert_eq!(h.data.len(), 4 + 4 * (MAX_HELD_SEGS + 2));
        assert_eq!(h.gaps.len(), 1);
        assert_eq!(h.gaps[0], Gap { at: 4, len: 996 });
    }

    #[test]
    fn a_stream_that_never_becomes_contiguous_still_hands_back_its_octets() {
        let s = run(&[c2s(0, b"aa"), c2s(100, b"bb"), c2s(200, b"cc")]);
        let h = &s[0].halves[0];
        assert_eq!(h.data, b"aabbcc");
        assert_eq!(h.gaps, vec![Gap { at: 2, len: 98 }, Gap { at: 4, len: 98 }]);
    }

    /// The sequence space is 32 bits and a capture can span the wrap.
    #[test]
    fn a_stream_reassembles_across_the_sequence_wrap() {
        let s = run(&[
            c2s(0xffff_fff8, b"before"),
            c2s(0xffff_fffe, b"after"),
            c2s(3, b"!"),
        ]);
        assert_eq!(s[0].halves[0].data, b"beforeafter!");
        assert!(s[0].halves[0].gaps.is_empty());
    }

    /// RFC 9293 §3.4: the SYN occupies the initial sequence number, so the
    /// first octet of data is at ISN + 1 and an octet claiming the ISN itself
    /// is behind the frontier.
    #[test]
    fn a_syn_consumes_one_sequence_number() {
        let s = run(&[
            seg(1, 2, 1234, 80, 99, SYN, b""),
            c2s(99, b"X"),
            c2s(100, b"data"),
        ]);
        assert_eq!(s[0].halves[0].data, b"data");
        assert!(s[0].halves[0].gaps.is_empty());
        assert_eq!(s[0].halves[0].flags & SAW_SYN, SAW_SYN);
    }

    /// A capture that starts mid-stream with its first segments reordered must
    /// not lose the earlier one to whichever arrived first.
    #[test]
    fn the_origin_is_the_earliest_segment_in_the_opening_window() {
        let s = run(&[c2s(2000, b"second"), c2s(1994, b"first!")]);
        assert_eq!(s[0].halves[0].data, b"first!second");
    }

    #[test]
    fn provenance_maps_an_offset_back_to_its_packet() {
        let s = run(&[c2s(0, b"aaaa"), s2c(0, b"zz"), c2s(4, b"bbbb")]);
        let h = &s[0].halves[0];
        assert_eq!(h.packet_at(0), Some(0));
        assert_eq!(h.packet_at(3), Some(0));
        assert_eq!(h.packet_at(4), Some(2));
        assert_eq!(h.packet_at(7), Some(2));
        assert_eq!(h.packet_at(8), None);
        assert_eq!(s[0].packets(), vec![0, 1, 2]);
    }

    /// The frontier can advance entirely through `relieve`, never through an
    /// in-order arrival. A reference that only followed the in-order path would
    /// lag it without bound, and once the two were 2^31 apart every arriving
    /// segment would map to the wrong side of the line and be discarded as
    /// already delivered — a direction going deaf with nothing said about it.
    #[test]
    fn the_reference_follows_the_frontier_however_it_advances() {
        let mut b = Build::default();
        b.feed(1000, SYN, b"", 0);
        let mut next: u32 = 1001;
        // Each round holds one more than the bound allows, forcing the frontier
        // the maximum distance a segment may claim.
        for _ in 0..2100 {
            for k in 0..=MAX_HELD_SEGS as u32 {
                b.feed(next.wrapping_add(MAX_AHEAD as u32 - 64 + k), 0, b"y", 0);
            }
            next = next.wrapping_add(MAX_AHEAD as u32 + 1);
        }
        assert!(
            (next as u64).abs_diff(1001) > (1 << 31),
            "the frontier has to cross 2^31 for this to test anything"
        );
        b.feed(next, 0, b"HEARD", 0);
        let h = b.finish();
        assert!(h.data.ends_with(b"HEARD"), "the direction went deaf");
    }

    /// The origin heuristic can be wrong: a segment earlier than the earliest
    /// of the opening window, arriving later still, cannot be delivered. What
    /// it must not do is vanish without saying so.
    #[test]
    fn octets_before_the_origin_are_refused_out_loud() {
        let mut frames: Vec<Vec<u8>> = (0..ORIGIN_WINDOW as u32)
            .map(|i| c2s(1000 + i * 4, b"late"))
            .collect();
        frames.push(c2s(900, b"EARLY!"));
        let h = &run(&frames)[0].halves[0];
        assert!(!h.data.starts_with(b"EARLY!"));
        assert_eq!(h.flags & LOSSY, LOSSY);
        assert_eq!(h.dropped, 6);
        // A retransmission of octets the stream did deliver is not a loss.
        let h = &run(&[c2s(0, b"abcd"), c2s(4, b"efgh"), c2s(0, b"abcd")])[0].halves[0];
        assert_eq!(h.flags & LOSSY, 0);
        assert_eq!(h.dropped, 0);
        // Nor is an octet claiming the SYN's own sequence number.
        let h = &run(&[
            seg(1, 2, 1234, 80, 99, SYN, b""),
            c2s(99, b"X"),
            c2s(100, b"ok"),
        ])[0]
            .halves[0];
        assert_eq!(h.flags & LOSSY, 0);
    }

    #[test]
    fn a_segment_far_past_the_frontier_is_refused() {
        let s = run(&[c2s(0, b"hi"), c2s(2 + MAX_AHEAD as u32 + 1, b"far")]);
        let h = &s[0].halves[0];
        assert_eq!(h.data, b"hi");
        assert_eq!(h.flags & LOSSY, LOSSY);
        assert_eq!(h.dropped, 3);
    }

    #[test]
    fn what_one_direction_holds_is_bounded() {
        let mut frames = vec![c2s(0, b"x")];
        let chunk = body(4096);
        for i in 0..200u32 {
            frames.push(c2s(100_000 + i * 8192, &chunk));
        }
        let s = run(&frames);
        let h = &s[0].halves[0];
        assert_eq!(h.data.len(), 1 + 200 * 4096);
        assert!(!h.gaps.is_empty());
    }

    #[test]
    fn a_flood_of_streams_is_bounded_and_every_one_still_comes_back() {
        let mut frames = Vec::new();
        for i in 0..(MAX_STREAMS / 512 + 32) as u32 {
            frames.push(seg(1, 2, (10000 + i) as u16, 80, 1, 0x18, b"hello"));
        }
        let s = run(&frames);
        assert_eq!(s.len(), frames.len());
        assert!(s.iter().all(|s| s.halves[0].data == b"hello"));
    }

    /// A snaplen-clipped frame can end inside the headers `reframe` rewrites.
    #[test]
    fn reframing_a_truncated_frame_is_not_a_panic() {
        let full = c2s(7, &body(120));
        for cut in 0..full.len() {
            let src = &full[..cut];
            if let Some(sp) = splice(src, ProtoId::Ether) {
                let n = room(&sp).min(64);
                if let Some(f) = reframe(src, ProtoId::Ether, 3, &body(n)) {
                    assert_eq!(f.len(), sp.payload + n);
                }
            }
        }
        // A message too wide for the length fields comes back as None, so a
        // caller has to chunk rather than get a frame that lies about itself.
        let sp = splice(&full, ProtoId::Ether).expect("a whole frame splices");
        assert!(reframe(&full, ProtoId::Ether, 0, &body(room(&sp) + 1)).is_none());
        let f = reframe(&full, ProtoId::Ether, 0, &body(room(&sp))).expect("fits");
        assert_eq!(
            u16::from_be_bytes([f[14 + 2], f[14 + 3]]) as usize,
            f.len() - 14
        );
        assert_eq!(crate::checksum::ones_complement(&f[14..14 + 20]), 0);
    }

    #[test]
    fn a_frame_that_carries_no_tcp_is_ignored() {
        let mut arp = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        arp.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        arp.extend_from_slice(&[0x08, 0x06]);
        arp.extend_from_slice(&body(40));
        assert!(run(&[arp]).is_empty());
    }

    #[test]
    fn a_truncated_frame_is_not_a_panic() {
        let full = c2s(7, &body(120));
        for cut in 0..full.len() {
            let _ = run(&[full[..cut].to_vec()]);
        }
        let mut pair = vec![c2s(7, &body(60))];
        for cut in 0..full.len() {
            pair.push(full[..cut].to_vec());
            let _ = run(&pair);
            pair.pop();
        }
    }

    #[test]
    fn the_incremental_and_bulk_paths_agree() {
        let frames = [
            c2s(100, b"ccc"),
            s2c(9, b"ZZ"),
            c2s(94, b"aaa"),
            c2s(97, b"bbb"),
            c2s(94, b"AAA"),
            s2c(11, b"YY"),
        ];
        let bulk = run(&frames);
        let mut r = Reassembler::default();
        for (i, f) in frames.iter().enumerate() {
            r.push(i as u32, f, ProtoId::Ether);
        }
        let inc = r.finish();
        assert_eq!(inc.len(), bulk.len());
        for (a, b) in inc.iter().zip(bulk.iter()) {
            assert_eq!(a.halves[0].data, b.halves[0].data);
            assert_eq!(a.halves[1].data, b.halves[1].data);
            assert_eq!(a.halves[0].segs, b.halves[0].segs);
        }
    }

    #[test]
    fn an_http_message_split_over_segments_is_one_message() {
        let msg = b"GET /a HTTP/1.1\r\nHost: x.io\r\n\r\n";
        let s = run(&[c2s(0, &msg[..8]), c2s(8, &msg[8..20]), c2s(20, &msg[20..])]);
        let d = &s[0].halves[0].data;
        assert_eq!(d, msg);
        assert_eq!(app_of(1234, 80, d), Some(ProtoId::Http));
        assert_eq!(messages(ProtoId::Http, d), vec![(0, msg.len())]);
        // No one segment of it is a message on its own.
        assert_eq!(message_len(ProtoId::Http, &msg[..8]), None);
    }

    #[test]
    fn a_content_length_body_is_part_of_the_message() {
        let msg = b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd";
        assert_eq!(http_len(msg), Some(msg.len()));
        assert_eq!(http_len(&msg[..msg.len() - 1]), None);
        let two = b"GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\n";
        assert_eq!(messages(ProtoId::Http, two), vec![(0, 19), (19, 19)]);
    }

    #[test]
    fn a_chunked_body_ends_at_its_last_chunk() {
        let msg = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n";
        assert_eq!(http_len(msg), Some(msg.len()));
        assert_eq!(http_len(&msg[..msg.len() - 3]), None);
    }

    /// A response with neither a length nor chunking runs to the close, which
    /// no arriving octet announces, so it is never a complete message.
    #[test]
    fn a_response_with_no_length_is_never_complete() {
        assert_eq!(http_len(b"HTTP/1.1 200 OK\r\n\r\nbody"), None);
    }

    #[test]
    fn a_header_section_longer_than_the_bound_is_not_a_message() {
        let mut msg = b"GET / HTTP/1.1\r\n".to_vec();
        while msg.len() < MAX_HEAD + 1024 {
            msg.extend_from_slice(b"X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
        }
        msg.extend_from_slice(b"\r\n");
        assert_eq!(http_len(&msg), None);
    }

    #[test]
    fn a_tls_record_split_over_segments_is_one_record() {
        let mut rec = vec![0x16, 0x03, 0x01, 0x00, 0x20];
        rec.extend_from_slice(&body(0x20));
        let s = run(&[
            seg(1, 2, 1234, 443, 0, 0x18, &rec[..3]),
            seg(1, 2, 1234, 443, 3, 0x18, &rec[3..]),
        ]);
        let d = &s[0].halves[0].data;
        assert_eq!(d, &rec);
        assert_eq!(messages(ProtoId::Tls, d), vec![(0, rec.len())]);
        assert_eq!(message_len(ProtoId::Tls, &rec[..3]), None);
    }

    #[test]
    fn a_message_walk_over_arbitrary_bytes_terminates() {
        for app in [ProtoId::Http, ProtoId::Tls, ProtoId::Raw] {
            for n in [0usize, 1, 5, 64, 300] {
                let _ = messages(app, &body(n));
                let mut noisy = body(n);
                noisy.iter_mut().for_each(|b| *b = b'\r');
                let _ = messages(app, &noisy);
            }
        }
        // A chunk size that claims more than is there must not loop.
        assert_eq!(
            http_len(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffff\r\n"),
            None
        );
    }
}
