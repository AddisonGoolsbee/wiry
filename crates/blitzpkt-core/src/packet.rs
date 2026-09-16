//! The packet representation: one contiguous byte buffer plus a small table of
//! layer spans. Fields are decoded on demand; nothing is materialised eagerly.
//! This is the design that buys the speedup, so keep the hot paths allocation-free.

use crate::field::{self, FieldDesc, FieldValue};
use crate::proto::{desc, Next, ProtoId};
use smallvec::SmallVec;

/// Where one protocol header sits inside the packet buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayerSpan {
    pub proto: ProtoId,
    /// Byte offset of the header from the start of the buffer.
    pub off: u32,
    /// Header length in bytes.
    pub hlen: u32,
    /// Total length of this layer including its payload.
    pub total: u32,
}

pub type Spans = SmallVec<[LayerSpan; 8]>;

/// Upper bound on nesting, to stop malformed input causing unbounded work.
const MAX_LAYERS: usize = 32;

#[derive(Clone, Debug)]
pub struct Packet {
    pub buf: Vec<u8>,
    pub spans: Spans,
    /// Layers whose computed fields (checksums, lengths) need recomputing.
    dirty: u32,
}

impl Packet {
    /// Dissect raw bytes starting from a known link-layer protocol.
    pub fn dissect(buf: Vec<u8>, link: ProtoId) -> Self {
        let spans = dissect_spans(&buf, link);
        Self {
            buf,
            spans,
            dirty: 0,
        }
    }

    /// Build a packet from a stack of protocols using each field's default value.
    pub fn build(stack: &[ProtoId]) -> Self {
        let owned: Vec<(ProtoId, Option<Vec<u8>>)> = stack.iter().map(|p| (*p, None)).collect();
        Self::build_with(&owned)
    }

    /// Build a stack where some layers carry extra header bytes: IPv4/TCP
    /// options, a DHCP option region, a `Raw` load.
    ///
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
                    field::write_bits(&mut buf[off..hdr_end], f.bit_off, f.bit_len, f.default);
                }
            }
            // Point the previous layer's demux field at this one, the way
            // stacking layers does automatically.
            if i > 0 {
                let prev = spans[i - 1];
                if let Some(bind) = desc(prev.proto).bind_next {
                    let a = prev.off as usize;
                    let b = (a + prev.hlen as usize).min(buf.len());
                    bind(&mut buf[a..b], p);
                }
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

    /// Index of the first layer matching `proto`, searching outward in.
    #[inline]
    pub fn find_layer(&self, proto: ProtoId) -> Option<usize> {
        self.spans.iter().position(|s| s.proto == proto)
    }

    #[inline]
    pub fn has_layer(&self, proto: ProtoId) -> bool {
        self.spans.iter().any(|s| s.proto == proto)
    }

    /// Header bytes of one layer.
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

    /// Payload of a layer: bytes after its header.
    #[inline]
    pub fn payload(&self, layer: usize) -> &[u8] {
        let s = self.spans[layer];
        let a = ((s.off + s.hlen) as usize).min(self.buf.len());
        &self.buf[a..]
    }

    /// Read a field from a layer. Decodes only this field. Returns `None` when
    /// the layer has no such field, including a conditional field this header
    /// does not carry.
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

    /// Write a field in place. Widths are preserved, so this never reallocates.
    /// Returns false when the field is unknown for this layer, or conditional
    /// and absent from this header.
    pub fn set_uint(&mut self, layer: usize, name: &str, val: u64) -> bool {
        let Some(s) = self.spans.get(layer).copied() else {
            return false;
        };
        let Some(f) = crate::proto::active_field_of(s.proto, self.header(layer), name) else {
            return false;
        };
        let a = s.off as usize;
        let b = (a + s.hlen as usize).min(self.buf.len());
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
        let n = val.len().min(self.buf.len().saturating_sub(a));
        self.buf[a..a + n].copy_from_slice(&val[..n]);
        self.mark_dirty(layer);
        true
    }

    /// Replace everything after `layer`'s header with `data`.
    pub fn set_payload(&mut self, layer: usize, data: &[u8]) {
        let s = self.spans[layer];
        let cut = (s.off + s.hlen) as usize;
        self.buf.truncate(cut.min(self.buf.len()));
        self.buf.extend_from_slice(data);
        // Payload shape changed, so re-dissect from this layer down.
        let link = self.spans[0].proto;
        self.spans = dissect_spans(&self.buf, link);
        self.dirty = u32::MAX;
    }

    /// Grow any header that is shorter than its own bytes say it should be.
    /// Construction lays down the fixed part first, so a header whose length
    /// depends on one of its own fields (ICMP, by type) is short until that
    /// field has been written. Protocols that write their own length field are
    /// already consistent and are left alone.
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
        // Any change invalidates computed fields at this layer and every layer
        // enclosing it, since lengths and checksums propagate outward.
        for i in 0..=layer.min(31) {
            self.dirty |= 1 << i;
        }
    }

    /// Recompute `total` for every span from the buffer length inward.
    fn refresh_totals(&mut self) {
        let end = self.buf.len() as u32;
        for s in self.spans.iter_mut() {
            s.total = end.saturating_sub(s.off);
        }
    }

    /// Serialise to bytes, recomputing lengths and checksums for dirty layers.
    pub fn to_bytes(&mut self) -> &[u8] {
        if self.dirty != 0 {
            self.refresh_totals();
            crate::compute::recompute(self);
            self.dirty = 0;
        }
        &self.buf
    }

    /// Serialise without recomputation, for callers that know nothing changed.
    /// Parse a layer's variable-length option region, when it has one.
    /// Returns `None` for protocols with no options, which is different from
    /// `Some(vec![])` meaning "has an option region, and it is empty".
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

/// Walk the layer chain, recording spans. This is the hot loop for pcap reading:
/// it touches only the bytes needed to find each next header.
pub fn dissect_spans(buf: &[u8], link: ProtoId) -> Spans {
    let mut spans = Spans::new();
    let mut off = 0usize;
    let mut proto = link;

    for _ in 0..MAX_LAYERS {
        let d = desc(proto);
        let remaining = buf.len().saturating_sub(off);

        // Too short to be this protocol: record what is left as opaque bytes.
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

        let hdr = &buf[off..];
        let hlen = (d.header_len)(hdr).max(d.min_len).min(remaining);

        spans.push(LayerSpan {
            proto,
            off: off as u32,
            hlen: hlen as u32,
            total: remaining as u32,
        });

        let next = (d.next)(hdr);
        off += hlen;

        match next {
            Next::Proto(p) if off < buf.len() => proto = p,
            Next::Raw if off < buf.len() => proto = ProtoId::Raw,
            _ => break,
        }
    }

    spans
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal Ether/IPv4/TCP frame, hand-built from RFC 791 and RFC 9293 layouts.
    fn sample() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst mac
        v.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // src mac
        v.extend_from_slice(&[0x08, 0x00]); // ethertype ipv4
                                            // IPv4, ihl=5, total len 40
        v.extend_from_slice(&[0x45, 0x00, 0x00, 0x28]);
        v.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        v.extend_from_slice(&[0x40, 0x06, 0x00, 0x00]); // ttl 64, proto tcp
        v.extend_from_slice(&[10, 0, 0, 1]); // src
        v.extend_from_slice(&[10, 0, 0, 2]); // dst
                                             // TCP, data offset 5
        v.extend_from_slice(&[0x1f, 0x90, 0x00, 0x50]); // sport 8080 dport 80
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
    fn empty_input_is_handled() {
        let p = Packet::dissect(vec![], ProtoId::Ether);
        assert!(p.layers().is_empty());
    }
}
