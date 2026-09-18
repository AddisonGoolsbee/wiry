use crate::field::{self, FieldDesc, FieldKind, FieldValue};
use crate::proto::{desc, Next, ProtoId};
use smallvec::SmallVec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayerSpan {
    pub proto: ProtoId,
    pub off: u32,
    pub hlen: u32,
    /// Header plus payload.
    pub total: u32,
}

impl LayerSpan {
    /// This layer's header, clamped to what the buffer holds. Every read of a
    /// span-addressed field clamps here, so the bulk and per-packet paths
    /// cannot disagree about a truncated header.
    #[inline]
    pub fn hdr_range(&self, len: usize) -> (usize, usize) {
        let a = (self.off as usize).min(len);
        (a, (a + self.hlen as usize).min(len))
    }

    #[inline]
    pub fn header<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        let (a, b) = self.hdr_range(buf.len());
        &buf[a..b]
    }
}

pub type Spans = SmallVec<[LayerSpan; 8]>;

/// Bounds the dissection walk on malformed input.
const MAX_LAYERS: usize = 32;

#[derive(Clone, Debug)]
pub struct Packet {
    pub buf: Vec<u8>,
    pub spans: Spans,
    /// Bitmask of layers whose computed fields need recomputing.
    dirty: u32,
    /// A write changed the byte count, so the length fields still describe the
    /// old extent.
    pub(crate) resized: bool,
    /// Computed fields the user wrote by hand. A value supplied for a length or
    /// a checksum is honoured, never recomputed over: only an unset one is
    /// filled in.
    pinned: Vec<(u32, ProtoId, &'static str)>,
}

impl Packet {
    pub fn dissect(buf: Vec<u8>, link: ProtoId) -> Self {
        let spans = dissect_spans(&buf, link);
        Self {
            buf,
            spans,
            dirty: 0,
            resized: false,
            pinned: Vec::new(),
        }
    }

    pub fn build(stack: &[ProtoId]) -> Self {
        let owned: Vec<(ProtoId, Option<Vec<u8>>)> = stack.iter().map(|p| (*p, None)).collect();
        Self::build_with(&owned)
    }

    /// Only a layer with a header-length field pads its extra bytes to a 4-byte
    /// boundary; DHCP (RFC 2132) and `Raw` take theirs verbatim, and padding
    /// them would corrupt the option walk or the payload.
    pub fn build_with(stack: &[(ProtoId, Option<Vec<u8>>)]) -> Self {
        let mut buf = Vec::new();
        let mut spans = Spans::new();
        for (i, (p, opts)) in stack.iter().enumerate() {
            let p = *p;
            let d = desc(p);
            // A layer can gain header bytes from what is stacked under it, so
            // the previous header is only finished now.
            if i > 0 {
                let prev = spans[i - 1];
                if let Some(extra) = desc(prev.proto).bind_next_bytes.map(|f| f(p)) {
                    buf.extend_from_slice(extra);
                    spans[i - 1].hlen += extra.len() as u32;
                }
            }
            let off = buf.len();
            buf.resize(off + d.build_len, 0);
            let mut hlen = d.build_len;
            if let Some(o) = opts {
                if !o.is_empty() {
                    buf.extend_from_slice(o);
                    hlen = d.build_len + o.len();
                    if d.set_hlen.is_some() {
                        let pad = (4 - (o.len() % 4)) % 4;
                        buf.extend(std::iter::repeat(0u8).take(pad));
                        hlen += pad;
                    }
                }
            }
            let hdr_end = (off + hlen).min(buf.len());
            for f in d.fields {
                if !f.is_active(&buf[off..hdr_end]) {
                    continue;
                }
                if let Some(b) = f.default_bytes {
                    let a = off + (f.bit_off / 8) as usize;
                    let n = b.len().min(hdr_end.saturating_sub(a));
                    buf[a..a + n].copy_from_slice(&b[..n]);
                } else if f.default != 0 {
                    let v = field::wire_uint(f, f.default);
                    field::write_bits(&mut buf[off..hdr_end], f.bit_off, f.bit_len, v);
                }
            }
            if i > 0 {
                let prev = spans[i - 1];
                let a = prev.off as usize;
                let b = (a + prev.hlen as usize).min(buf.len());
                if let Some(bind) = desc(prev.proto).bind_next {
                    bind(&mut buf[a..b], p);
                }
                crate::proto::apply_bind(&mut buf[a..b], prev.proto, p);
            }
            if let Some(setter) = d.set_hlen {
                setter(&mut buf[off..hdr_end], hlen);
            }
            spans.push(LayerSpan {
                proto: p,
                off: off as u32,
                hlen: hlen as u32,
                total: hlen as u32,
            });
        }
        let mut pkt = Self {
            buf,
            spans,
            dirty: u32::MAX,
            resized: false,
            pinned: Vec::new(),
        };
        pkt.refresh_totals();
        pkt
    }

    pub fn layers(&self) -> &[LayerSpan] {
        &self.spans
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    #[inline]
    pub fn find_layer(&self, proto: ProtoId) -> Option<usize> {
        self.spans.iter().position(|s| s.proto == proto)
    }

    #[inline]
    pub fn has_layer(&self, proto: ProtoId) -> bool {
        self.spans.iter().any(|s| s.proto == proto)
    }

    #[inline]
    fn hdr_range(&self, s: &LayerSpan) -> (usize, usize) {
        s.hdr_range(self.buf.len())
    }

    #[inline]
    pub fn header(&self, layer: usize) -> &[u8] {
        match self.spans.get(layer) {
            Some(s) => s.header(&self.buf),
            None => &[],
        }
    }

    /// Everything from this layer to the end of the packet.
    #[inline]
    pub fn layer_bytes(&self, layer: usize) -> &[u8] {
        let Some(s) = self.spans.get(layer) else {
            return &[];
        };
        let a = (s.off as usize).min(self.buf.len());
        &self.buf[a..]
    }

    #[inline]
    pub fn payload(&self, layer: usize) -> &[u8] {
        let Some(s) = self.spans.get(layer) else {
            return &[];
        };
        let a = ((s.off + s.hlen) as usize).min(self.buf.len());
        &self.buf[a..]
    }

    pub fn get(&self, layer: usize, name: &str) -> Option<FieldValue> {
        let proto = self.spans.get(layer)?.proto;
        let f = crate::proto::active_field_of(proto, self.header(layer), name)?;
        Some(self.get_desc(layer, f))
    }

    /// VarBytes runs to the end of the header, not the buffer: exactly what
    /// `header` reports.
    #[inline]
    pub fn get_desc(&self, layer: usize, f: &FieldDesc) -> FieldValue {
        field::decode(self.header(layer), f)
    }

    /// Refuses a value too wide for the field rather than writing its low bits:
    /// a truncated value emitted under a recomputed checksum is undetectable.
    pub fn set_uint(&mut self, layer: usize, name: &str, val: u64) -> bool {
        let Some(s) = self.spans.get(layer).copied() else {
            return false;
        };
        let Some(f) = crate::proto::active_field_of(s.proto, self.header(layer), name) else {
            return false;
        };
        if !field::fits(f, val) {
            return false;
        }
        let (a, b) = self.hdr_range(&s);
        let wire = field::wire_uint(f, val);
        field::write_bits(&mut self.buf[a..b], f.bit_off, f.bit_len, wire);
        // `write_bits` drops a write past the end of a clipped header, and a
        // value that never landed is not one the user pinned.
        if f.computed && (f.bit_off as usize + f.bit_len as usize) <= (b - a) * 8 {
            self.pin(layer, s.proto, f.name);
        }
        self.mark_dirty(layer);
        true
    }

    /// Whether `set_uint` would accept this value, so a caller can tell a field
    /// that does not exist from one that cannot hold what it was given.
    pub fn uint_fits(&self, layer: usize, name: &str, val: u64) -> bool {
        let f = self
            .spans
            .get(layer)
            .and_then(|s| crate::proto::active_field_of(s.proto, self.header(layer), name));
        match f {
            Some(f) => field::fits(f, val),
            None => true,
        }
    }

    fn pin(&mut self, layer: usize, proto: ProtoId, name: &'static str) {
        if !self.is_pinned(layer, name) {
            self.pinned.push((layer as u32, proto, name));
        }
    }

    /// A computed field the user assigned; `compute` leaves those alone.
    pub(crate) fn is_pinned(&self, layer: usize, name: &str) -> bool {
        let Some(s) = self.spans.get(layer) else {
            return false;
        };
        self.pinned
            .iter()
            .any(|(l, p, n)| *l == layer as u32 && *p == s.proto && *n == name)
    }

    pub fn set_bytes(&mut self, layer: usize, name: &str, val: &[u8]) -> bool {
        let Some(s) = self.spans.get(layer).copied() else {
            return false;
        };
        let Some(f) = crate::proto::active_field_of(s.proto, self.header(layer), name) else {
            return false;
        };
        // A conditional field can be declared past the end of a header this short
        // (ICMP timestamps at byte 16 of an 8-octet message), so clamp rather than
        // panic, as `write_bits` does.
        let a = (s.off as usize + (f.bit_off / 8) as usize).min(self.buf.len());
        // A variable-length field has no width of its own, so writing one
        // resizes its region rather than running over what follows.
        if f.kind == FieldKind::VarBytes {
            self.replace_region(layer, a, val);
            return true;
        }
        let room = self
            .buf
            .len()
            .saturating_sub(a)
            .min((f.bit_len / 8) as usize);
        let n = val.len().min(room);
        self.buf[a..a + n].copy_from_slice(&val[..n]);
        // A fixed-width field is replaced, not partly overwritten, or a short
        // value leaves the tail of the previous one behind.
        if f.bit_len > 0 {
            let end = (a + (f.bit_len / 8) as usize).min(self.buf.len());
            if end > a + n {
                self.buf[a + n..end].fill(0);
            }
        }
        self.mark_dirty(layer);
        true
    }

    /// A variable-length field owns the rest of its layer, so the frame resizes
    /// with it: an option region grows or shrinks and the header length that
    /// governs it (`ihl`, `dataofs`) follows, as construction does. What comes
    /// after the layer, `Padding` included, stays where it is.
    fn replace_region(&mut self, layer: usize, at: usize, val: &[u8]) {
        let s = self.spans[layer];
        let d = desc(s.proto);
        let end = ((s.off + s.hlen) as usize).min(self.buf.len());
        let at = at.min(end);
        // A header length counted in 32-bit words can only describe a padded
        // region, so construction's padding rule applies to a rewrite too.
        let pad = if d.set_hlen.is_some() {
            (4 - (val.len() % 4)) % 4
        } else {
            0
        };
        // Bytes a stacked layer contributed (BOOTP's magic cookie) are appended
        // after the field at build time, so they follow the new content.
        let tail: &'static [u8] = match (d.bind_next_bytes, self.spans.get(layer + 1)) {
            (Some(f), Some(n)) => f(n.proto),
            _ => &[],
        };
        let keep: &'static [u8] = if !tail.is_empty()
            && end - at > tail.len()
            && self.buf[end - tail.len()..end] == *tail
        {
            tail
        } else {
            &[]
        };
        let grown = val.len() + pad + keep.len();
        let delta = grown as isize - (end - at) as isize;
        self.buf.splice(
            at..end,
            val.iter()
                .copied()
                .chain(std::iter::repeat(0u8).take(pad))
                .chain(keep.iter().copied()),
        );
        let hlen = (at + grown).saturating_sub(s.off as usize);
        self.spans[layer].hlen = hlen as u32;
        for later in self.spans[layer + 1..].iter_mut() {
            later.off = (later.off as isize + delta).max(0) as u32;
        }
        if let Some(setter) = d.set_hlen {
            let grown = self.spans[layer];
            let (a, b) = self.hdr_range(&grown);
            setter(&mut self.buf[a..b], hlen);
        }
        self.dirty = u32::MAX;
        self.resized = true;
        self.refresh_totals();
    }

    pub fn set_payload(&mut self, layer: usize, data: &[u8]) -> bool {
        let Some(s) = self.spans.get(layer).copied() else {
            return false;
        };
        let cut = (s.off + s.hlen) as usize;
        self.buf.truncate(cut.min(self.buf.len()));
        self.buf.extend_from_slice(data);
        let link = self.spans[0].proto;
        self.spans = spans_of(&self.buf, link, false);
        self.dirty = u32::MAX;
        self.resized = true;
        true
    }

    /// Construction lays down the fixed part first, so a header whose length
    /// depends on one of its own fields (ICMP, by type) stays short until that
    /// field is written.
    pub fn refit_headers(&mut self) {
        for i in 0..self.spans.len() {
            let s = self.spans[i];
            let d = desc(s.proto);
            if d.set_hlen.is_some() {
                continue;
            }
            let want = (d.header_len)(self.header(i));
            let have = s.hlen as usize;
            if want <= have {
                continue;
            }
            let at = (s.off as usize + have).min(self.buf.len());
            self.buf
                .splice(at..at, std::iter::repeat(0u8).take(want - have));
            self.spans[i].hlen = want as u32;
            for later in self.spans[i + 1..].iter_mut() {
                later.off += (want - have) as u32;
            }
            self.dirty = u32::MAX;
        }
        self.refresh_totals();
    }

    #[inline]
    fn mark_dirty(&mut self, layer: usize) {
        // Lengths and checksums propagate outward, so enclosing layers go too.
        for i in 0..=layer.min(31) {
            self.dirty |= 1 << i;
        }
    }

    fn refresh_totals(&mut self) {
        let end = self.buf.len() as u32;
        for s in self.spans.iter_mut() {
            s.total = end.saturating_sub(s.off);
        }
    }

    /// Names a length field too narrow to describe this packet. An untouched
    /// capture keeps the lengths the wire gave, so it is never rejected.
    pub fn oversize(&self) -> Option<String> {
        (self.dirty != 0)
            .then(|| crate::compute::oversize(self))
            .flatten()
    }

    pub fn to_bytes(&mut self) -> &[u8] {
        if self.dirty != 0 {
            self.refresh_totals();
            crate::compute::recompute(self);
            self.dirty = 0;
            self.resized = false;
        }
        &self.buf
    }

    /// `None` means the protocol has no option region at all, unlike
    /// `Some(vec![])`, which means it has an empty one.
    pub fn options(&self, layer: usize) -> Option<Vec<crate::options::Item>> {
        let s = self.spans.get(layer)?;
        let parse = desc(s.proto).parse_options?;
        let (a, b) = self.hdr_range(s);
        Some(parse(&self.buf[a..b]))
    }

    pub fn raw_bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn mark_all_dirty(&mut self) {
        self.dirty = u32::MAX;
    }
}

pub fn dissect_spans(buf: &[u8], link: ProtoId) -> Spans {
    spans_of(buf, link, true)
}

/// `bound` is false when rebuilding after the buffer changed under us: the
/// length fields still describe the old extent, so they bound nothing yet.
fn spans_of(buf: &[u8], link: ProtoId, bound: bool) -> Spans {
    let mut spans = Spans::new();
    let mut off = 0usize;
    // End of the innermost declared length. A frame padded to Ethernet's
    // 60-octet minimum carries bytes past it.
    let mut end = buf.len();
    let mut proto = link;

    for _ in 0..MAX_LAYERS {
        let d = desc(proto);
        let remaining = end.saturating_sub(off);

        if remaining < d.min_len {
            if remaining > 0 {
                spans.push(LayerSpan {
                    proto: ProtoId::Raw,
                    off: off as u32,
                    hlen: remaining as u32,
                    total: remaining as u32,
                });
            }
            break;
        }

        let hdr = &buf[off..end];
        let hlen = (d.header_len)(hdr).max(d.min_len).min(remaining);

        spans.push(LayerSpan {
            proto,
            off: off as u32,
            hlen: hlen as u32,
            total: remaining as u32,
        });

        // A length claiming more than was captured means a clipped capture, not
        // a trailer, so the bound only ever tightens.
        if let Some(f) = d.content_len.filter(|_| bound) {
            let claimed = f(hdr);
            if claimed >= hlen && off + claimed < end {
                end = off + claimed;
            }
        }

        // A declared binding outranks the layer's own guess: it is the only way
        // a user layer can be reached.
        let next = match crate::proto::bound_next(proto, hdr) {
            Some(p) => Next::Proto(p),
            None => (d.next)(hdr),
        };
        off += hlen;

        match next {
            Next::Proto(p) if off < end => proto = p,
            Next::Raw if off < end => proto = ProtoId::Raw,
            _ => break,
        }
    }

    if end < buf.len() {
        spans.push(LayerSpan {
            proto: ProtoId::Padding,
            off: end as u32,
            hlen: (buf.len() - end) as u32,
            total: (buf.len() - end) as u32,
        });
    }

    spans
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ether/IPv4/TCP frame from the RFC 791 and RFC 9293 layouts.
    fn sample() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        v.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        v.extend_from_slice(&[0x08, 0x00]);
        v.extend_from_slice(&[0x45, 0x00, 0x00, 0x28]);
        v.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        v.extend_from_slice(&[0x40, 0x06, 0x00, 0x00]);
        v.extend_from_slice(&[10, 0, 0, 1]);
        v.extend_from_slice(&[10, 0, 0, 2]);
        v.extend_from_slice(&[0x1f, 0x90, 0x00, 0x50]);
        v.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0]);
        v.extend_from_slice(&[0x50, 0x02, 0x20, 0x00]);
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        v
    }

    #[test]
    fn walks_the_expected_layer_chain() {
        let p = Packet::dissect(sample(), ProtoId::Ether);
        let got: Vec<_> = p.layers().iter().map(|s| s.proto).collect();
        assert_eq!(got, vec![ProtoId::Ether, ProtoId::Ipv4, ProtoId::Tcp]);
    }

    #[test]
    fn reads_fields_lazily() {
        let p = Packet::dissect(sample(), ProtoId::Ether);
        let ip = p.find_layer(ProtoId::Ipv4).unwrap();
        assert_eq!(p.get(ip, "ttl").unwrap(), FieldValue::Uint(64));
        assert_eq!(p.get(ip, "src").unwrap(), FieldValue::Ipv4([10, 0, 0, 1]));
        let tcp = p.find_layer(ProtoId::Tcp).unwrap();
        assert_eq!(p.get(tcp, "sport").unwrap(), FieldValue::Uint(8080));
        assert_eq!(p.get(tcp, "dport").unwrap(), FieldValue::Uint(80));
    }

    #[test]
    fn set_then_read_roundtrips() {
        let mut p = Packet::dissect(sample(), ProtoId::Ether);
        let tcp = p.find_layer(ProtoId::Tcp).unwrap();
        assert!(p.set_uint(tcp, "dport", 443));
        assert_eq!(p.get(tcp, "dport").unwrap(), FieldValue::Uint(443));
    }

    #[test]
    fn short_input_becomes_raw_not_panic() {
        let p = Packet::dissect(vec![0x00, 0x11], ProtoId::Ether);
        assert_eq!(p.layers()[0].proto, ProtoId::Raw);
    }

    #[test]
    fn a_bound_registered_layer_is_built_and_dissected_again() {
        use crate::proto::{bind, field_of, register};
        let id = register("PktDemo".into(), vec![FieldDesc::uint("v", 0, 8, 7)], 1).unwrap();
        bind(
            ProtoId::Udp,
            id,
            vec![(field_of(ProtoId::Udp, "dport").unwrap(), 4242)],
        )
        .unwrap();

        let mut built = Packet::build(&[ProtoId::Ipv4, ProtoId::Udp, id]);
        assert_eq!(built.get(1, "dport").unwrap(), FieldValue::Uint(4242));
        let bytes = built.to_bytes().to_vec();

        let back = Packet::dissect(bytes, ProtoId::Ipv4);
        let got: Vec<_> = back.layers().iter().map(|s| s.proto).collect();
        assert_eq!(got, vec![ProtoId::Ipv4, ProtoId::Udp, id]);
        assert_eq!(back.get(2, "v").unwrap(), FieldValue::Uint(7));
    }

    #[test]
    fn a_short_value_replaces_a_fixed_width_field_rather_than_part_of_it() {
        let mut p = Packet::build(&[ProtoId::Bootp]);
        assert!(p.set_bytes(0, "chaddr", &[1, 2, 3, 4, 5, 6, 7, 8]));
        assert!(p.set_bytes(0, "chaddr", &[9, 9]));
        assert_eq!(
            p.get(0, "chaddr").unwrap(),
            FieldValue::Bytes(vec![9, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        );
    }

    #[test]
    fn an_ethernet_trailer_dissects_as_padding() {
        // IEEE 802.3 clause 4: 60-octet minimum frame.
        let mut v = sample();
        v.extend_from_slice(&[0u8; 6]);
        let p = Packet::dissect(v, ProtoId::Ether);
        let got: Vec<_> = p.layers().iter().map(|s| s.proto).collect();
        assert_eq!(
            got,
            vec![
                ProtoId::Ether,
                ProtoId::Ipv4,
                ProtoId::Tcp,
                ProtoId::Padding
            ]
        );
        assert_eq!(p.layers()[3].hlen, 6);
    }

    #[test]
    fn a_length_claiming_more_than_was_captured_bounds_nothing() {
        let mut v = sample();
        v[16] = 0xff;
        let p = Packet::dissect(v, ProtoId::Ether);
        assert!(!p.has_layer(ProtoId::Padding));
    }

    #[test]
    fn a_length_shorter_than_its_own_header_bounds_nothing() {
        // Segmentation offload leaves a zero total length in real captures.
        for len in [0u16, 5] {
            let mut v = sample();
            v[16..18].copy_from_slice(&len.to_be_bytes());
            let p = Packet::dissect(v.clone(), ProtoId::Ether);
            assert!(!p.has_layer(ProtoId::Padding), "len {len}");
            let got: Vec<_> = p.layers().iter().map(|s| s.proto).collect();
            assert_eq!(got, vec![ProtoId::Ether, ProtoId::Ipv4, ProtoId::Tcp]);
        }
    }

    #[test]
    fn an_oversized_value_is_truncated_to_the_field() {
        let mut p = Packet::build(&[ProtoId::Ipv4]);
        assert!(p.set_bytes(0, "src", &[1, 2, 3, 4, 5, 6, 7, 8]));
        assert_eq!(p.get(0, "src").unwrap(), FieldValue::Ipv4([1, 2, 3, 4]));
        assert_eq!(p.get(0, "dst").unwrap(), FieldValue::Ipv4([127, 0, 0, 1]));

        let mut e = Packet::build(&[ProtoId::Ether, ProtoId::Ipv4]);
        let (ty, dst) = (e.get(0, "type").unwrap(), e.get(0, "dst").unwrap());
        assert!(e.set_bytes(0, "src", &[0xaa; 12]));
        assert_eq!(e.get(0, "src").unwrap(), FieldValue::Mac([0xaa; 6]));
        assert_eq!(e.get(0, "dst").unwrap(), dst);
        assert_eq!(e.get(0, "type").unwrap(), ty);
    }

    #[test]
    fn a_field_running_to_the_end_of_its_layer_resizes_the_packet() {
        let mut p = Packet::build(&[ProtoId::Ipv4, ProtoId::Udp]);
        p.set_payload(1, b"12345678");
        let bytes = p.to_bytes().to_vec();

        for (val, len) in [(&b"ABCDEFGHIJKLMNOP"[..], 16usize), (&b"XY"[..], 2)] {
            let mut back = Packet::dissect(bytes.clone(), ProtoId::Ipv4);
            let raw = back.find_layer(ProtoId::Raw).unwrap();
            assert!(back.set_bytes(raw, "load", val));
            assert_eq!(
                back.get(raw, "load").unwrap(),
                FieldValue::Bytes(val.into())
            );
            assert_eq!(back.to_bytes().len(), 28 + len);
            assert_eq!(
                back.get(0, "len").unwrap(),
                FieldValue::Uint(28 + len as u64)
            );
            assert_eq!(
                back.get(1, "len").unwrap(),
                FieldValue::Uint(8 + len as u64)
            );
        }
    }

    #[test]
    fn writing_an_option_region_resizes_it_instead_of_the_next_layer() {
        let before = sample();
        let mut p = Packet::dissect(before.clone(), ProtoId::Ether);
        let (ip, tcp) = (1, 2);
        let ports = (p.get(tcp, "sport").unwrap(), p.get(tcp, "dport").unwrap());

        // RFC 791 §3.1 Router Alert (IANA option 148), one 4-octet word.
        assert!(p.set_bytes(ip, "options", &[0x94, 0x04, 0x00, 0x00]));
        assert_eq!(
            p.get(ip, "options").unwrap(),
            FieldValue::Bytes(vec![0x94, 0x04, 0x00, 0x00])
        );
        assert_eq!(p.get(ip, "ihl").unwrap(), FieldValue::Uint(6));
        assert_eq!(p.get(tcp, "sport").unwrap(), ports.0);
        assert_eq!(p.get(tcp, "dport").unwrap(), ports.1);
        assert_eq!(p.len(), before.len() + 4);
        assert_eq!(p.to_bytes().len(), before.len() + 4);
        assert_eq!(p.get(ip, "len").unwrap(), FieldValue::Uint(44));

        assert!(p.set_bytes(ip, "options", &[]));
        assert_eq!(p.get(ip, "ihl").unwrap(), FieldValue::Uint(5));
        assert_eq!(p.get(tcp, "sport").unwrap(), ports.0);
        assert_eq!(p.to_bytes().len(), before.len());
        // Everything but the two checksums the rewrite made stale.
        assert_eq!(p.raw_bytes()[..24], before[..24]);
        assert_eq!(p.raw_bytes()[26..50], before[26..50]);
    }

    #[test]
    fn an_option_region_pads_to_the_word_its_length_field_counts() {
        let mut p = Packet::dissect(sample(), ProtoId::Ether);
        // RFC 791 §3.1: IHL counts 32-bit words, so a 3-octet option is padded.
        assert!(p.set_bytes(1, "options", &[0x94, 0x04, 0x00]));
        assert_eq!(p.get(1, "ihl").unwrap(), FieldValue::Uint(6));
        assert_eq!(
            p.get(1, "options").unwrap(),
            FieldValue::Bytes(vec![0x94, 0x04, 0x00, 0x00])
        );
    }

    #[test]
    fn writing_tcp_options_leaves_the_payload_where_it_was() {
        let mut p = Packet::build(&[ProtoId::Ipv4, ProtoId::Tcp]);
        p.set_payload(1, b"GET / HTTP");
        let bytes = p.to_bytes().to_vec();

        let mut back = Packet::dissect(bytes, ProtoId::Ipv4);
        // RFC 9293 §3.2: MSS 1460.
        assert!(back.set_bytes(1, "options", &[2, 4, 0x05, 0xb4]));
        assert_eq!(back.get(1, "dataofs").unwrap(), FieldValue::Uint(6));
        assert_eq!(
            back.get(1, "options").unwrap(),
            FieldValue::Bytes(vec![2, 4, 0x05, 0xb4])
        );
        assert_eq!(back.payload(1), b"GET / HTTP");
        assert_eq!(back.to_bytes().len(), 20 + 24 + 10);
    }

    #[test]
    fn writing_bootp_options_leaves_the_dhcp_layer_alone() {
        let mut p = Packet::build(&[ProtoId::Bootp, ProtoId::Dhcp]);
        // RFC 2132 §9.6: message type 3 (DHCPREQUEST), then End.
        assert!(p.set_bytes(1, "options", &[53, 1, 3, 255]));
        let bytes = p.to_bytes().to_vec();

        let mut back = Packet::dissect(bytes, ProtoId::Bootp);
        assert_eq!(back.layers()[1].proto, ProtoId::Dhcp);
        let opts = [99, 130, 83, 99, 53, 1, 8, 255];
        assert!(back.set_bytes(0, "options", &opts));
        assert_eq!(
            back.get(0, "options").unwrap(),
            FieldValue::Bytes(opts.to_vec())
        );
        assert_eq!(
            back.get(1, "options").unwrap(),
            FieldValue::Bytes(vec![53, 1, 3, 255])
        );
        assert_eq!(back.to_bytes().len(), 236 + opts.len() + 4);
    }

    #[test]
    fn a_value_too_wide_for_a_whole_octet_field_is_refused_not_truncated() {
        let mut p = Packet::build(&[ProtoId::Ipv4, ProtoId::Tcp]);
        assert!(!p.set_uint(0, "ttl", 300));
        assert_eq!(p.get(0, "ttl").unwrap(), FieldValue::Uint(64));
        assert!(!p.set_uint(0, "id", 70000));
        assert_eq!(p.get(0, "id").unwrap(), FieldValue::Uint(1));
        assert!(!p.set_uint(1, "sport", 70000));
        assert_eq!(p.get(1, "sport").unwrap(), FieldValue::Uint(20));

        assert!(p.set_uint(0, "ttl", 255));
        assert_eq!(p.get(0, "ttl").unwrap(), FieldValue::Uint(255));
        assert!(p.uint_fits(0, "ttl", 255));
        assert!(!p.uint_fits(0, "ttl", 256));
        assert!(
            p.uint_fits(0, "nosuchfield", u64::MAX),
            "a name the layer does not carry is not a range failure"
        );
    }

    #[test]
    fn a_sub_octet_field_still_takes_the_bits_that_fit() {
        // IEEE 802.1Q clause 9.6: a 12-bit VID, masked rather than refused, as
        // the API being matched does.
        let mut p = Packet::build(&[ProtoId::Ether, ProtoId::Dot1Q]);
        assert!(p.set_uint(1, "vlan", 5000));
        assert_eq!(p.get(1, "vlan").unwrap(), FieldValue::Uint(5000 & 0xfff));
    }

    #[test]
    fn a_field_declared_past_a_clipped_header_is_refused_not_written() {
        // RFC 792 Timestamp: ts_tx sits at byte 16 of a message clipped to 8.
        let mut p = Packet::dissect(vec![13, 0, 0, 0, 0, 0, 0, 0], ProtoId::Icmp);
        assert!(p.set_bytes(0, "ts_tx", &[1, 2, 3, 4]));
        assert_eq!(p.len(), 8);
    }

    #[test]
    fn rewriting_an_option_region_with_what_it_holds_changes_nothing() {
        // Construction appends the blob then writes the field: the second write
        // must land on exactly what the first one built.
        let opts = vec![0x94u8, 4, 0, 0];
        let stack = [(ProtoId::Ipv4, Some(opts.clone())), (ProtoId::Tcp, None)];
        let built = Packet::build_with(&stack).to_bytes().to_vec();
        let mut again = Packet::build_with(&stack);
        assert!(again.set_bytes(0, "options", &opts));
        assert_eq!(again.to_bytes(), &built[..]);

        // BOOTP's magic cookie (RFC 2131 §3) is appended after the field when
        // DHCP is stacked, and survives a rewrite of the field itself.
        let stack = [(ProtoId::Bootp, Some(opts.clone())), (ProtoId::Dhcp, None)];
        let built = Packet::build_with(&stack).to_bytes().to_vec();
        let mut again = Packet::build_with(&stack);
        assert!(again.set_bytes(0, "options", &opts));
        assert_eq!(again.to_bytes(), &built[..]);
    }

    #[test]
    fn empty_input_is_handled() {
        let p = Packet::dissect(vec![], ProtoId::Ether);
        assert!(p.layers().is_empty());
    }
}
