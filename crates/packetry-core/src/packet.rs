use crate::field::{self, FieldDesc, FieldValue};
use crate::proto::{desc, Next, ProtoId};
use smallvec::SmallVec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayerSpan {
    pub proto: ProtoId,
    /// Byte offset of the header from the start of the buffer.
    pub off: u32,
    pub hlen: u32,
    /// Header plus payload.
    pub total: u32,
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
    /// Set when a write changed how many bytes the packet holds, so the length
    /// fields still describe the old extent.
    pub(crate) resized: bool,
}

impl Packet {
    pub fn dissect(buf: Vec<u8>, link: ProtoId) -> Self {
        let spans = dissect_spans(&buf, link);
        Self {
            buf,
            spans,
            dirty: 0,
            resized: false,
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
            // the previous header is finished only now.
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
                let end = (off + hlen).min(buf.len());
                setter(&mut buf[off..end], hlen);
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
    pub fn header(&self, layer: usize) -> &[u8] {
        let s = self.spans[layer];
        let a = s.off as usize;
        let b = (a + s.hlen as usize).min(self.buf.len());
        &self.buf[a..b]
    }

    /// Everything from this layer to the end of the packet.
    #[inline]
    pub fn layer_bytes(&self, layer: usize) -> &[u8] {
        let s = self.spans[layer];
        let a = (s.off as usize).min(self.buf.len());
        &self.buf[a..]
    }

    #[inline]
    pub fn payload(&self, layer: usize) -> &[u8] {
        let s = self.spans[layer];
        let a = ((s.off + s.hlen) as usize).min(self.buf.len());
        &self.buf[a..]
    }

    /// `None` when the layer has no such field, including a conditional field
    /// this header does not carry.
    pub fn get(&self, layer: usize, name: &str) -> Option<FieldValue> {
        let proto = self.spans.get(layer)?.proto;
        let f = crate::proto::active_field_of(proto, self.header(layer), name)?;
        Some(self.get_desc(layer, f))
    }

    #[inline]
    pub fn get_desc(&self, layer: usize, f: &FieldDesc) -> FieldValue {
        let s = self.spans[layer];
        let a = s.off as usize;
        // VarBytes fields run to the end of the header, not the buffer.
        let b = (a + s.hlen as usize).min(self.buf.len());
        field::decode(&self.buf[a..b], f)
    }

    /// False when the field is unknown for this layer, or conditional and
    /// absent from this header.
    pub fn set_uint(&mut self, layer: usize, name: &str, val: u64) -> bool {
        let Some(s) = self.spans.get(layer).copied() else {
            return false;
        };
        let Some(f) = crate::proto::active_field_of(s.proto, self.header(layer), name) else {
            return false;
        };
        let a = s.off as usize;
        let b = (a + s.hlen as usize).min(self.buf.len());
        let val = field::wire_uint(f, val);
        field::write_bits(&mut self.buf[a..b], f.bit_off, f.bit_len, val);
        self.mark_dirty(layer);
        true
    }

    pub fn set_bytes(&mut self, layer: usize, name: &str, val: &[u8]) -> bool {
        let Some(s) = self.spans.get(layer).copied() else {
            return false;
        };
        let Some(f) = crate::proto::active_field_of(s.proto, self.header(layer), name) else {
            return false;
        };
        let a = s.off as usize + (f.bit_off / 8) as usize;
        if f.to_end {
            self.replace_to_end(layer, a, val);
            return true;
        }
        let mut room = self.buf.len().saturating_sub(a);
        // An oversized value is truncated to the field, never spilled into the
        // next one. A variable-length field has no width of its own.
        if f.bit_len > 0 {
            room = room.min((f.bit_len / 8) as usize);
        }
        let n = val.len().min(room);
        self.buf[a..a + n].copy_from_slice(&val[..n]);
        // A fixed-width field is replaced, not overwritten in part: a short
        // value would otherwise leave the tail of the previous one behind. A
        // variable-length one has no end of its own, so it keeps what follows.
        if f.bit_len > 0 {
            let end = (a + (f.bit_len / 8) as usize).min(self.buf.len());
            if end > a + n {
                self.buf[a + n..end].fill(0);
            }
        }
        self.mark_dirty(layer);
        true
    }

    /// A field with no end of its own takes the whole tail of its layer, so the
    /// frame grows or shrinks with it and every enclosing length follows. What
    /// comes after the layer, a trailing `Padding` included, stays put.
    fn replace_to_end(&mut self, layer: usize, at: usize, val: &[u8]) {
        let s = self.spans[layer];
        let end = ((s.off + s.hlen) as usize).min(self.buf.len());
        let at = at.min(end);
        let delta = val.len() as isize - (end - at) as isize;
        self.buf.splice(at..end, val.iter().copied());
        self.spans[layer].hlen = (at + val.len() - s.off as usize) as u32;
        for later in self.spans[layer + 1..].iter_mut() {
            later.off = (later.off as isize + delta) as u32;
        }
        self.dirty = u32::MAX;
        self.resized = true;
        self.refresh_totals();
    }

    pub fn set_payload(&mut self, layer: usize, data: &[u8]) {
        let s = self.spans[layer];
        let cut = (s.off + s.hlen) as usize;
        self.buf.truncate(cut.min(self.buf.len()));
        self.buf.extend_from_slice(data);
        let link = self.spans[0].proto;
        self.spans = spans_of(&self.buf, link, false);
        self.dirty = u32::MAX;
        self.resized = true;
    }

    /// Construction lays down the fixed part first, so a header whose length
    /// depends on one of its own fields (ICMP, by type) stays short until that
    /// field is written. Grow those to their real length.
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
        // Lengths and checksums propagate outward, so every enclosing layer goes too.
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
        let a = s.off as usize;
        let b = (a + s.hlen as usize).min(self.buf.len());
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

/// `bound` is false only when rebuilding after the buffer changed under us: the
/// length fields still describe the old extent, so they bound nothing yet.
fn spans_of(buf: &[u8], link: ProtoId, bound: bool) -> Spans {
    let mut spans = Spans::new();
    let mut off = 0usize;
    // Where the content of the innermost layer that declared a length ends. A
    // frame padded to Ethernet's 60-octet minimum carries bytes past it.
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

        // A length that claims more than was captured means a clipped capture,
        // not a trailer, so the bound only ever tightens.
        if let Some(f) = d.content_len.filter(|_| bound) {
            let claimed = f(hdr);
            if claimed >= hlen && off + claimed < end {
                end = off + claimed;
            }
        }

        // A declared binding outranks the layer's own guess: it is the only way
        // a user layer can be reached, and it was asked for explicitly.
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

    // Ether/IPv4/TCP frame hand-built from RFC 791 and RFC 9293 layouts.
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
        // IEEE 802.3 clause 4 sets a 60-octet minimum frame.
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
    fn empty_input_is_handled() {
        let p = Packet::dissect(vec![], ProtoId::Ether);
        assert!(p.layers().is_empty());
    }
}
