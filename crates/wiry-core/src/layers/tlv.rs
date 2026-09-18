//! One bounded walk over a tag/length/value region, parameterised by the shape
//! the protocol gives its tag and length octets.
//!
//! `options.rs` serves the three protocols whose options are an octet of code
//! and an octet of length. The regions here are the same idea at other widths:
//! LLDP packs a 7-bit type and a 9-bit length into one word (IEEE 802.1AB
//! §8.1), DHCPv6 uses two 16-bit words (RFC 8415 §21.1), an NDP option counts
//! its length in 8-octet units (RFC 4861 §4.6) and an SCTP chunk puts a flags
//! octet between the two (RFC 9260 §3.2). Getting that rule wrong mis-decodes
//! every item after the first rather than failing, so it is stated per
//! protocol and never guessed.

use crate::field::read_bits;
use crate::options::{Item, ItemValue};

#[derive(Clone, Copy)]
pub struct TlvFmt {
    pub tag_bits: u16,
    /// Bits between tag and length that belong to neither (SCTP chunk flags).
    pub mid_bits: u16,
    pub len_bits: u16,
    /// Units the length counts, in octets.
    pub len_scale: usize,
    /// Whether the length already counts the tag and length octets.
    pub len_covers_header: bool,
    /// Item sizes are rounded up to this; 1 means no padding.
    pub align: usize,
    /// Tag that closes the region.
    pub end_tag: Option<u32>,
}

impl TlvFmt {
    pub const fn new(tag_bits: u16, len_bits: u16) -> Self {
        Self {
            tag_bits,
            mid_bits: 0,
            len_bits,
            len_scale: 1,
            len_covers_header: false,
            align: 1,
            end_tag: None,
        }
    }

    pub const fn covering_header(mut self) -> Self {
        self.len_covers_header = true;
        self
    }

    pub const fn scaled(mut self, n: usize) -> Self {
        self.len_scale = n;
        self
    }

    pub const fn with_mid(mut self, bits: u16) -> Self {
        self.mid_bits = bits;
        self
    }

    pub const fn aligned(mut self, n: usize) -> Self {
        self.align = n;
        self
    }

    pub const fn ending_at(mut self, tag: u32) -> Self {
        self.end_tag = Some(tag);
        self
    }

    const fn header_len(&self) -> usize {
        ((self.tag_bits + self.mid_bits + self.len_bits) as usize).div_ceil(8)
    }
}

/// One decoded item, before it is given a name.
pub struct Raw<'a> {
    pub tag: u32,
    pub mid: u64,
    pub value: &'a [u8],
}

/// Malformed input stops the walk rather than erroring: a snaplen-clipped
/// capture truncates option regions routinely. The guard bounds a region whose
/// length octets claim zero.
pub fn walk<'a>(data: &'a [u8], f: &TlvFmt) -> Vec<Raw<'a>> {
    let hdr = f.header_len();
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut guard = 0;
    while i + hdr <= data.len() && guard < 512 {
        guard += 1;
        let w = &data[i..i + hdr];
        let tag = read_bits(w, 0, f.tag_bits) as u32;
        let mid = read_bits(w, f.tag_bits, f.mid_bits);
        let len = read_bits(w, f.tag_bits + f.mid_bits, f.len_bits) as usize;
        let claimed = len.saturating_mul(f.len_scale);
        let total = if f.len_covers_header {
            claimed.max(hdr)
        } else {
            hdr + claimed
        };
        let padded = total.div_ceil(f.align) * f.align;
        if i + total > data.len() {
            break;
        }
        out.push(Raw {
            tag,
            mid,
            value: &data[i + hdr..i + total],
        });
        if Some(tag) == f.end_tag {
            break;
        }
        i += padded.max(hdr);
    }
    out
}

pub type Namer = fn(u32) -> Option<&'static str>;

/// Bytes by default; a name table decides nothing about the shape, because a
/// wrong shape is worse than an opaque one.
pub fn items(data: &[u8], f: &TlvFmt, name: Namer) -> Vec<Item> {
    walk(data, f)
        .into_iter()
        .map(|r| match name(r.tag) {
            Some(n) => Item::bytes(n, r.tag, r.value),
            None => Item::unknown(r.tag, r.value),
        })
        .collect()
}

/// A region whose named items are printable text (LLDP's port and system
/// descriptions, DHCPv6's FQDN).
pub fn text_item(name: &'static str, code: u32, b: &[u8]) -> Item {
    Item::named(
        name,
        code,
        ItemValue::Text(String::from_utf8_lossy(b).into_owned()),
    )
}

pub fn be(b: &[u8]) -> u64 {
    b.iter().take(8).fold(0u64, |a, x| (a << 8) | *x as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// IEEE 802.1AB §8.1: 7-bit type, 9-bit length, no padding.
    const LLDP: TlvFmt = TlvFmt::new(7, 9).ending_at(0);

    #[test]
    fn a_seven_nine_split_reads_both_halves() {
        // type 1 (chassis id), length 3.
        let data = [0x02, 0x03, 0x04, 0x05, 0x06, 0x04, 0x02, 0xaa, 0xbb];
        let got = walk(&data, &LLDP);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].tag, 1);
        assert_eq!(got[0].value, &[0x04, 0x05, 0x06]);
        assert_eq!(got[1].tag, 2);
        assert_eq!(got[1].value, &[0xaa, 0xbb]);
    }

    #[test]
    fn an_end_tag_stops_the_walk() {
        let data = [0x02, 0x01, 0xff, 0x00, 0x00, 0x02, 0x01, 0xee];
        let got = walk(&data, &LLDP);
        assert_eq!(got.len(), 2);
        assert_eq!(got[1].tag, 0);
    }

    #[test]
    fn a_length_covering_its_header_does_not_double_count() {
        // RADIUS attribute: type 1, length 4 counts both header octets.
        let f = TlvFmt::new(8, 8).covering_header();
        let data = [1, 4, 0xaa, 0xbb, 2, 3, 0xcc];
        let got = walk(&data, &f);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].value, &[0xaa, 0xbb]);
        assert_eq!(got[1].value, &[0xcc]);
    }

    #[test]
    fn a_scaled_length_counts_units_not_octets() {
        // RFC 4861 §4.6: length is in 8-octet units and covers the header.
        let f = TlvFmt::new(8, 8).covering_header().scaled(8);
        let mut data = vec![1u8, 1];
        data.extend_from_slice(&[0xaa; 6]);
        let got = walk(&data, &f);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].value.len(), 6);
    }

    #[test]
    fn padding_and_flags_are_both_honoured() {
        // RFC 9260 §3.2: type, flags, 16-bit length covering the header, and
        // the next chunk starts on a 4-octet boundary.
        let f = TlvFmt::new(8, 16).with_mid(8).covering_header().aligned(4);
        let data = [1u8, 0x05, 0, 5, 0xaa, 0, 0, 0, 2, 0, 0, 4];
        let got = walk(&data, &f);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].tag, 1);
        assert_eq!(got[0].mid, 5);
        assert_eq!(got[0].value, &[0xaa]);
        assert_eq!(got[1].tag, 2);
    }

    #[test]
    fn a_zero_length_region_terminates() {
        let f = TlvFmt::new(8, 8).covering_header();
        let data = [0u8; 64];
        assert!(walk(&data, &f).len() <= 64);
    }

    #[test]
    fn truncation_stops_rather_than_panicking() {
        let full = [0x02, 0x03, 0x04, 0x05, 0x06];
        for n in 0..full.len() {
            let _ = walk(&full[..n], &LLDP);
        }
    }
}
