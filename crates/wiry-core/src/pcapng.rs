//! Layout from the IETF draft "PCAP Next Generation (pcapng) Capture File
//! Format" (draft-ietf-opsawg-pcapng).
//!
//! Every block is `block type (4) | total length (4) | body | total length (4)`,
//! the length covering all four parts and a multiple of 4. The trailing copy is
//! an integrity check here, and a mismatch stops the walk.

pub use crate::pcap::{link_to_proto, Record};

/// A palindrome, so it reads the same in either byte order.
pub const BLOCK_SHB: u32 = 0x0A0D_0D0A;
pub const BLOCK_IDB: u32 = 0x0000_0001;
pub const BLOCK_SPB: u32 = 0x0000_0003;
pub const BLOCK_EPB: u32 = 0x0000_0006;

pub const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;

const OPT_IF_TSRESOL: u16 = 9;
const OPT_END: u16 = 0;

const DEFAULT_TSRESOL: u64 = 1_000_000;

#[derive(Debug)]
pub enum PcapngError {
    TooShort,
    NotPcapng(u32),
    BadByteOrder(u32),
    BadSectionHeader,
}

impl std::fmt::Display for PcapngError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PcapngError::TooShort => write!(f, "file too short to contain a section header block"),
            PcapngError::NotPcapng(t) => write!(f, "not a pcapng file (block type {t:#010x})"),
            PcapngError::BadByteOrder(m) => write!(f, "bad pcapng byte-order magic ({m:#010x})"),
            PcapngError::BadSectionHeader => write!(f, "malformed pcapng section header block"),
        }
    }
}

impl std::error::Error for PcapngError {}

pub fn is_pcapng(buf: &[u8]) -> bool {
    matches!(rd32(buf, 0, false), Some(BLOCK_SHB))
}

#[derive(Clone, Copy, Debug)]
pub struct FileHeader {
    pub swapped: bool,
    pub linktype: u32,
    /// Ticks per second, from `if_tsresol`.
    pub tsresol: u64,
}

impl FileHeader {
    /// Whether [`Record::ts_frac`] carries nanoseconds rather than microseconds.
    pub fn nanos(&self) -> bool {
        self.tsresol == 1_000_000_000
    }
}

#[derive(Clone, Copy, Debug)]
struct Iface {
    linktype: u32,
    tsresol: u64,
}

#[inline]
fn rd16(buf: &[u8], o: usize, swapped: bool) -> Option<u16> {
    let b = buf.get(o..o + 2)?;
    let v = u16::from_le_bytes([b[0], b[1]]);
    Some(if swapped { v.swap_bytes() } else { v })
}

#[inline]
fn rd32(buf: &[u8], o: usize, swapped: bool) -> Option<u32> {
    let b = buf.get(o..o + 4)?;
    let v = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    Some(if swapped { v.swap_bytes() } else { v })
}

#[inline]
fn rd64(buf: &[u8], o: usize, swapped: bool) -> Option<u64> {
    let lo = rd32(buf, o, swapped)? as u64;
    let hi = rd32(buf, o + 4, swapped)? as u64;
    Some(if swapped {
        (lo << 32) | hi
    } else {
        (hi << 32) | lo
    })
}

#[inline]
fn pad4(n: usize) -> usize {
    (n + 3) & !3
}

/// High bit clear means 10^value ticks per second, set means 2^(value & 0x7f).
/// An exponent that overflows u64 falls back to microsecond resolution.
fn decode_tsresol(v: u8) -> u64 {
    let (base, exp) = if v & 0x80 != 0 {
        (2u64, (v & 0x7f) as u32)
    } else {
        (10u64, v as u32)
    };
    base.checked_pow(exp).unwrap_or(DEFAULT_TSRESOL)
}

/// Borrows from the buffer; packet bytes are never copied.
pub struct Reader<'a> {
    buf: &'a [u8],
    off: usize,
    /// Buffer end, or the declared section length (-1 means unknown).
    end: usize,
    swapped: bool,
    ifaces: Vec<Iface>,
    done: bool,
    pub header: FileHeader,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Result<Self, PcapngError> {
        if buf.len() < 28 {
            return Err(PcapngError::TooShort);
        }
        let btype = rd32(buf, 0, false).ok_or(PcapngError::TooShort)?;
        if btype != BLOCK_SHB {
            return Err(PcapngError::NotPcapng(btype));
        }
        let raw_magic = rd32(buf, 8, false).ok_or(PcapngError::TooShort)?;
        let swapped = match raw_magic {
            BYTE_ORDER_MAGIC => false,
            x if x.swap_bytes() == BYTE_ORDER_MAGIC => true,
            other => return Err(PcapngError::BadByteOrder(other)),
        };

        let mut r = Reader {
            buf,
            off: 0,
            end: buf.len(),
            swapped,
            ifaces: Vec::new(),
            done: false,
            header: FileHeader {
                swapped,
                linktype: 0,
                tsresol: DEFAULT_TSRESOL,
            },
        };
        r.off = r.enter_section(0).ok_or(PcapngError::BadSectionHeader)?;

        // Consume the leading interface descriptions so the file header can
        // report a link type before the first packet.
        while let Some((btype, total)) = r.read_block_at(r.off) {
            if btype != BLOCK_IDB {
                break;
            }
            let iface = r.parse_idb(r.off, total);
            r.ifaces.push(iface);
            r.off += total;
        }
        if let Some(first) = r.ifaces.first() {
            r.header.linktype = first.linktype;
            r.header.tsresol = first.tsresol;
        }
        Ok(r)
    }

    /// Adopts the block's endianness and section length; returns the offset
    /// just past it.
    fn enter_section(&mut self, off: usize) -> Option<usize> {
        let raw_magic = rd32(self.buf, off + 8, false)?;
        self.swapped = match raw_magic {
            BYTE_ORDER_MAGIC => false,
            x if x.swap_bytes() == BYTE_ORDER_MAGIC => true,
            _ => return None,
        };
        // The total length needs this section's endianness, so the block check
        // runs only after the magic is decoded.
        self.end = self.buf.len();
        let (btype, total) = self.read_block_at(off)?;
        if btype != BLOCK_SHB || total < 28 {
            return None;
        }
        let next = off + total;
        let section_len = rd64(self.buf, off + 16, self.swapped)? as i64;
        self.end = if section_len < 0 {
            self.buf.len()
        } else {
            next.saturating_add(section_len as usize)
                .min(self.buf.len())
        };
        self.ifaces.clear();
        Some(next)
    }

    fn read_block_at(&self, off: usize) -> Option<(u32, usize)> {
        if off + 12 > self.end {
            return None;
        }
        let btype = rd32(self.buf, off, self.swapped)?;
        let total = rd32(self.buf, off + 4, self.swapped)? as usize;
        if total < 12 || total % 4 != 0 || off + total > self.end {
            return None;
        }
        let trailing = rd32(self.buf, off + total - 4, self.swapped)? as usize;
        if trailing != total {
            return None;
        }
        Some((btype, total))
    }

    fn parse_idb(&self, off: usize, total: usize) -> Iface {
        let mut iface = Iface {
            linktype: rd16(self.buf, off + 8, self.swapped).unwrap_or(0) as u32,
            tsresol: DEFAULT_TSRESOL,
        };
        let body_end = off + total - 4;
        // Body starts at +8; linktype(2) reserved(2) snaplen(4) precede the options.
        let mut o = off + 16;
        while o + 4 <= body_end {
            let (Some(code), Some(len)) = (
                rd16(self.buf, o, self.swapped),
                rd16(self.buf, o + 2, self.swapped),
            ) else {
                break;
            };
            if code == OPT_END {
                break;
            }
            let len = len as usize;
            if o + 4 + len > body_end {
                break;
            }
            if code == OPT_IF_TSRESOL && len >= 1 {
                if let Some(&v) = self.buf.get(o + 4) {
                    iface.tsresol = decode_tsresol(v);
                }
            }
            o += 4 + pad4(len);
        }
        iface
    }

    fn tsresol_for(&self, iface_id: u32) -> u64 {
        self.ifaces
            .get(iface_id as usize)
            .map(|i| i.tsresol)
            .unwrap_or(self.header.tsresol)
    }

    /// `ts_frac` is microseconds, or nanoseconds at exactly 10^-9 resolution —
    /// the two classic pcap can express. Anything else truncates to
    /// microseconds rather than misreporting the scale.
    fn split_ts(&self, ticks: u64, tsresol: u64) -> (u32, u32) {
        if tsresol == 0 {
            return (0, 0);
        }
        let secs = ticks / tsresol;
        let rem = ticks % tsresol;
        let frac = if tsresol == 1_000_000_000 {
            rem
        } else {
            (rem as u128 * 1_000_000 / tsresol as u128) as u64
        };
        (secs as u32, frac as u32)
    }
}

impl<'a> Iterator for Reader<'a> {
    type Item = Record<'a>;

    /// The first `None` ends the walk for good: anything the reader could not
    /// make sense of leaves `off` pointing into the middle of a block.
    fn next(&mut self) -> Option<Record<'a>> {
        if self.done {
            return None;
        }
        let rec = self.next_record();
        self.done = rec.is_none();
        rec
    }
}

impl<'a> Reader<'a> {
    /// Each pass advances `off` by at least 12 bytes or stops, so the walk is
    /// bounded by the buffer length.
    fn next_record(&mut self) -> Option<Record<'a>> {
        loop {
            if self.off + 12 > self.end {
                return None;
            }
            if rd32(self.buf, self.off, self.swapped)? == BLOCK_SHB {
                self.off = self.enter_section(self.off)?;
                continue;
            }
            let (btype, total) = self.read_block_at(self.off)?;
            let start = self.off;
            self.off += total;

            match btype {
                BLOCK_IDB => {
                    let iface = self.parse_idb(start, total);
                    self.ifaces.push(iface);
                }
                BLOCK_EPB => {
                    // iface(4) ts_high(4) ts_low(4) caplen(4) origlen(4) then data.
                    if total < 32 {
                        return None;
                    }
                    let iface_id = rd32(self.buf, start + 8, self.swapped)?;
                    // No IDB for this id means no link type for the frame, so
                    // there is nothing it could honestly be decoded as.
                    if self.ifaces.get(iface_id as usize).is_none() {
                        continue;
                    }
                    let hi = rd32(self.buf, start + 12, self.swapped)?;
                    let lo = rd32(self.buf, start + 16, self.swapped)?;
                    let caplen = rd32(self.buf, start + 20, self.swapped)?;
                    let origlen = rd32(self.buf, start + 24, self.swapped)?;
                    let n = caplen as usize;
                    // Data is padded to 4 bytes and options may follow, so the
                    // body only has to be big enough.
                    if pad4(n) > total - 32 {
                        return None;
                    }
                    let data = self.buf.get(start + 28..start + 28 + n)?;
                    let tsresol = self.tsresol_for(iface_id);
                    let (ts_sec, ts_frac) = self.split_ts(((hi as u64) << 32) | lo as u64, tsresol);
                    return Some(Record {
                        ts_sec,
                        ts_frac,
                        caplen,
                        origlen,
                        data,
                    });
                }
                BLOCK_SPB => {
                    // No captured length: the bytes present are whatever fits in
                    // the block, capped at the original length.
                    if total < 16 {
                        return None;
                    }
                    let origlen = rd32(self.buf, start + 8, self.swapped)?;
                    let n = (origlen as usize).min(total - 16);
                    let data = self.buf.get(start + 12..start + 12 + n)?;
                    return Some(Record {
                        ts_sec: 0,
                        ts_frac: 0,
                        caplen: n as u32,
                        origlen,
                        data,
                    });
                }
                _ => {}
            }
        }
    }
}

pub fn count(buf: &[u8]) -> Result<usize, PcapngError> {
    Ok(Reader::new(buf)?.count())
}

/// The captured length has to fit the block's own 32-bit total length, framing
/// and the fixed part of the body included.
pub const MAX_CAPLEN: usize = (u32::MAX - 36) as usize & !3;

/// Little-endian throughout: the byte-order magic tells the reader, so there is
/// nothing to gain from writing a section in the other order.
fn open_block(out: &mut Vec<u8>, btype: u32, body_len: usize) -> u32 {
    let total = (12 + pad4(body_len)) as u32;
    out.extend_from_slice(&btype.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    total
}

/// The body pads to four octets and the total length repeats at the end, which
/// is what lets a reader walk the file backwards.
fn close_block(out: &mut Vec<u8>, body_len: usize, total: u32) {
    out.resize(out.len() + pad4(body_len) - body_len, 0);
    out.extend_from_slice(&total.to_le_bytes());
}

fn write_block(out: &mut Vec<u8>, btype: u32, body: &[u8]) {
    let total = open_block(out, btype, body.len());
    out.extend_from_slice(body);
    close_block(out, body.len(), total);
}

pub fn write_shb(out: &mut Vec<u8>) {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&BYTE_ORDER_MAGIC.to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    // Section length unknown: a stream writer does not know it yet, and a
    // reader that trusted a stale one would stop early.
    body.extend_from_slice(&(-1i64).to_le_bytes());
    write_block(out, BLOCK_SHB, &body);
}

/// The link type is 16 bits here, unlike pcap's 32.
pub fn write_idb(out: &mut Vec<u8>, linktype: u32, snaplen: u32, nanos: bool) {
    let mut body = Vec::with_capacity(24);
    body.extend_from_slice(&(linktype as u16).to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&snaplen.to_le_bytes());
    // 10^-6 is the default, so only the other resolution needs saying.
    if nanos {
        body.extend_from_slice(&OPT_IF_TSRESOL.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&[9, 0, 0, 0]);
        body.extend_from_slice(&OPT_END.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
    }
    write_block(out, BLOCK_IDB, &body);
}

pub fn write_epb(
    out: &mut Vec<u8>,
    iface: u32,
    ts_sec: u32,
    ts_frac: u32,
    data: &[u8],
    origlen: u32,
    nanos: bool,
) {
    let data = &data[..data.len().min(MAX_CAPLEN)];
    let caplen = data.len() as u32;
    let tsresol = if nanos {
        1_000_000_000u64
    } else {
        DEFAULT_TSRESOL
    };
    let ticks = (ts_sec as u64)
        .saturating_mul(tsresol)
        .saturating_add(ts_frac as u64);
    let body_len = 20 + data.len();
    let total = open_block(out, BLOCK_EPB, body_len);
    out.extend_from_slice(&iface.to_le_bytes());
    out.extend_from_slice(&((ticks >> 32) as u32).to_le_bytes());
    out.extend_from_slice(&(ticks as u32).to_le_bytes());
    out.extend_from_slice(&caplen.to_le_bytes());
    out.extend_from_slice(&origlen.max(caplen).to_le_bytes());
    out.extend_from_slice(data);
    close_block(out, body_len, total);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcap::linktype;

    fn w16(v: u16, be: bool) -> [u8; 2] {
        if be {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    }

    fn w32(v: u32, be: bool) -> [u8; 4] {
        if be {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    }

    fn w64(v: u64, be: bool) -> [u8; 8] {
        if be {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    }

    fn block(btype: u32, body: &[u8], be: bool) -> Vec<u8> {
        let padded = pad4(body.len());
        let total = 12 + padded;
        let mut v = Vec::with_capacity(total);
        v.extend_from_slice(&w32(btype, be));
        v.extend_from_slice(&w32(total as u32, be));
        v.extend_from_slice(body);
        v.resize(8 + padded, 0);
        v.extend_from_slice(&w32(total as u32, be));
        v
    }

    fn shb(be: bool) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&w32(BYTE_ORDER_MAGIC, be));
        b.extend_from_slice(&w16(1, be));
        b.extend_from_slice(&w16(0, be));
        b.extend_from_slice(&w64(u64::MAX, be)); // section length -1 (unknown)
        block(BLOCK_SHB, &b, be)
    }

    fn idb(lt: u32, tsresol: Option<u8>, be: bool) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&w16(lt as u16, be));
        b.extend_from_slice(&w16(0, be));
        b.extend_from_slice(&w32(65535, be));
        if let Some(r) = tsresol {
            b.extend_from_slice(&w16(OPT_IF_TSRESOL, be));
            b.extend_from_slice(&w16(1, be));
            b.extend_from_slice(&[r, 0, 0, 0]);
        }
        b.extend_from_slice(&w16(OPT_END, be));
        b.extend_from_slice(&w16(0, be));
        block(BLOCK_IDB, &b, be)
    }

    fn epb(iface: u32, ts: u64, data: &[u8], origlen: u32, be: bool) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&w32(iface, be));
        b.extend_from_slice(&w32((ts >> 32) as u32, be));
        b.extend_from_slice(&w32(ts as u32, be));
        b.extend_from_slice(&w32(data.len() as u32, be));
        b.extend_from_slice(&w32(origlen, be));
        b.extend_from_slice(data);
        b.resize(20 + pad4(data.len()), 0);
        block(BLOCK_EPB, &b, be)
    }

    fn spb(data: &[u8], origlen: u32, be: bool) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&w32(origlen, be));
        b.extend_from_slice(data);
        b.resize(4 + pad4(data.len()), 0);
        block(BLOCK_SPB, &b, be)
    }

    fn minimal(be: bool, tsresol: Option<u8>, ts: u64) -> Vec<u8> {
        let mut v = shb(be);
        v.extend_from_slice(&idb(linktype::ETHERNET, tsresol, be));
        v.extend_from_slice(&epb(0, ts, &[0xaa; 60], 60, be));
        v
    }

    #[test]
    fn reads_minimal_little_endian_file() {
        let data = minimal(false, None, 1_000_002);
        let r = Reader::new(&data).unwrap();
        assert!(!r.header.swapped);
        assert_eq!(r.header.linktype, linktype::ETHERNET);
        assert_eq!(r.header.tsresol, 1_000_000);
        assert_eq!(
            link_to_proto(r.header.linktype),
            crate::proto::ProtoId::Ether
        );

        let recs: Vec<_> = Reader::new(&data).unwrap().collect();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].ts_sec, 1);
        assert_eq!(recs[0].ts_frac, 2);
        assert_eq!(recs[0].caplen, 60);
        assert_eq!(recs[0].origlen, 60);
        assert_eq!(recs[0].data, &[0xaa; 60]);
    }

    #[test]
    fn big_endian_reads_identically() {
        let le = minimal(false, None, 1_000_002);
        let be = minimal(true, None, 1_000_002);
        assert_ne!(le, be);

        let rb = Reader::new(&be).unwrap();
        assert!(rb.header.swapped);
        assert_eq!(rb.header.linktype, linktype::ETHERNET);

        let a: Vec<_> = Reader::new(&le).unwrap().collect();
        let b: Vec<_> = Reader::new(&be).unwrap().collect();
        assert_eq!(a.len(), b.len());
        assert_eq!(a[0].ts_sec, b[0].ts_sec);
        assert_eq!(a[0].ts_frac, b[0].ts_frac);
        assert_eq!(a[0].caplen, b[0].caplen);
        assert_eq!(a[0].data, b[0].data);
    }

    #[test]
    fn nanosecond_tsresol_keeps_nanoseconds() {
        let data = minimal(false, Some(9), 1_000_000_123);
        let r = Reader::new(&data).unwrap();
        assert_eq!(r.header.tsresol, 1_000_000_000);
        assert!(r.header.nanos());
        let rec = Reader::new(&data).unwrap().next().unwrap();
        assert_eq!(rec.ts_sec, 1);
        assert_eq!(rec.ts_frac, 123);
        assert!((rec.time(true) - 1.000000123).abs() < 1e-12);
    }

    #[test]
    fn power_of_two_tsresol_rescales_to_microseconds() {
        let data = minimal(false, Some(0x8a), 1024 + 512);
        let r = Reader::new(&data).unwrap();
        assert_eq!(r.header.tsresol, 1024);
        assert!(!r.header.nanos());
        let rec = Reader::new(&data).unwrap().next().unwrap();
        assert_eq!(rec.ts_sec, 1);
        assert_eq!(rec.ts_frac, 500_000);
    }

    #[test]
    fn packet_data_padding_is_handled() {
        let mut v = shb(false);
        v.extend_from_slice(&idb(linktype::ETHERNET, None, false));
        v.extend_from_slice(&epb(0, 0, &[0x11; 13], 13, false));
        v.extend_from_slice(&epb(0, 0, &[0x22; 7], 9, false));
        let recs: Vec<_> = Reader::new(&v).unwrap().collect();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].caplen, 13);
        assert_eq!(recs[0].data, &[0x11; 13]);
        assert_eq!(recs[1].caplen, 7);
        assert_eq!(recs[1].origlen, 9);
        assert_eq!(recs[1].data, &[0x22; 7]);
    }

    #[test]
    fn unknown_block_is_skipped() {
        let mut v = shb(false);
        v.extend_from_slice(&idb(linktype::ETHERNET, None, false));
        v.extend_from_slice(&epb(0, 1_000_000, &[0x01; 4], 4, false));
        v.extend_from_slice(&block(0x0000_0004, &[0xde; 20], false));
        v.extend_from_slice(&block(0x0000_BEEF, &[0xad; 9], false));
        v.extend_from_slice(&epb(0, 2_000_000, &[0x02; 4], 4, false));
        let recs: Vec<_> = Reader::new(&v).unwrap().collect();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].ts_sec, 1);
        assert_eq!(recs[1].ts_sec, 2);
        assert_eq!(recs[1].data, &[0x02; 4]);
    }

    #[test]
    fn reads_simple_packet_block() {
        let mut v = shb(false);
        v.extend_from_slice(&idb(linktype::ETHERNET, None, false));
        v.extend_from_slice(&spb(&[0x77; 14], 14, false));
        v.extend_from_slice(&epb(0, 5_000_000, &[0x88; 4], 4, false));
        let recs: Vec<_> = Reader::new(&v).unwrap().collect();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].caplen, 14);
        assert_eq!(recs[0].origlen, 14);
        assert_eq!(recs[0].ts_sec, 0);
        assert_eq!(recs[0].ts_frac, 0);
        assert_eq!(recs[0].data, &[0x77; 14]);
        assert_eq!(recs[1].ts_sec, 5);
    }

    #[test]
    fn trailing_length_mismatch_stops_walk() {
        let mut v = shb(false);
        v.extend_from_slice(&idb(linktype::ETHERNET, None, false));
        let good = epb(0, 1_000_000, &[0x01; 4], 4, false);
        let first = v.len();
        v.extend_from_slice(&good);
        v.extend_from_slice(&epb(0, 2_000_000, &[0x02; 4], 4, false));

        let recs: Vec<_> = Reader::new(&v).unwrap().collect();
        assert_eq!(recs.len(), 2);

        let tail = first + good.len() - 4;
        v[tail..tail + 4].copy_from_slice(&w32(0xffff_fff0, false));
        let recs: Vec<_> = Reader::new(&v).unwrap().collect();
        assert!(recs.is_empty());
    }

    #[test]
    fn truncation_stops_cleanly_at_every_cut_point() {
        let mut full = shb(false);
        full.extend_from_slice(&idb(linktype::ETHERNET, Some(9), false));
        full.extend_from_slice(&epb(0, 1_000_000_000, &[0x01; 18], 18, false));
        full.extend_from_slice(&spb(&[0x02; 6], 6, false));
        full.extend_from_slice(&epb(0, 3_000_000_000, &[0x03; 4], 4, false));
        assert_eq!(Reader::new(&full).unwrap().count(), 3);

        for cut in 0..full.len() {
            let part = &full[..cut];
            match Reader::new(part) {
                Ok(r) => {
                    let n = r.take(64).count();
                    assert!(n <= 3, "cut {cut} yielded {n} records");
                }
                Err(_) => continue,
            }
        }
    }

    #[test]
    fn is_pcapng_discriminates() {
        let ng = minimal(false, None, 0);
        assert!(is_pcapng(&ng));
        assert!(is_pcapng(&minimal(true, None, 0)));

        let mut classic = Vec::new();
        crate::pcap::write_header(&mut classic, linktype::ETHERNET, 65535, false);
        assert!(!is_pcapng(&classic));
        assert!(!is_pcapng(&[0u8; 64]));
        assert!(!is_pcapng(&[0x0a, 0x0d, 0x0d]));
        assert!(!is_pcapng(&[]));

        assert!(Reader::new(&classic).is_err());
        assert!(Reader::new(&[0u8; 4]).is_err());
    }

    #[test]
    fn rejects_bad_byte_order_magic() {
        let mut v = minimal(false, None, 0);
        v[8..12].copy_from_slice(&[0, 0, 0, 0]);
        assert!(matches!(Reader::new(&v), Err(PcapngError::BadByteOrder(0))));
    }

    /// scapy's own regression suite covers this, and scapy 2.7.0 fails it: the
    /// file names interface 1 where only interface 0 was described.
    #[test]
    fn a_packet_block_naming_an_undescribed_interface_is_skipped() {
        let blob: Vec<u8> = (0..)
            .step_by(2)
            .take_while(|i| *i < BLOB.len())
            .map(|i| u8::from_str_radix(&BLOB[i..i + 2], 16).unwrap())
            .collect();
        let got: Vec<_> = Reader::new(&blob).unwrap().collect();
        assert_eq!(got.len(), 1, "the block naming interface 1 must be skipped");
        assert_eq!(got[0].data[..6], [0, 0, 0, 0, 0, 2]);
    }

    const BLOB: &str = "0a0d0d0a1c0000004d3c2b1a01000000ffffffffffffffff1c000000\
010000001400000001000000ffff0000140000000600000034000000\
01000000000000000000000011000000110000000000000000010000\
00000000900042414400000034000000060000003400000000000000\
00000000000000001300000013000000000000000002000000000000\
900041465445520034000000";

    #[test]
    fn multiple_interfaces_use_their_own_resolution() {
        let mut v = shb(false);
        v.extend_from_slice(&idb(linktype::ETHERNET, None, false));
        v.extend_from_slice(&idb(linktype::RAW, Some(9), false));
        v.extend_from_slice(&epb(0, 2_000_500, &[0xa1; 4], 4, false));
        v.extend_from_slice(&epb(1, 2_000_000_500, &[0xa2; 4], 4, false));
        v.extend_from_slice(&epb(9, 3_000_000, &[0xa3; 4], 4, false));

        let r = Reader::new(&v).unwrap();
        assert_eq!(r.header.linktype, linktype::ETHERNET);
        assert_eq!(r.header.tsresol, 1_000_000);

        let recs: Vec<_> = Reader::new(&v).unwrap().collect();
        assert_eq!(recs.len(), 2);
        assert_eq!((recs[0].ts_sec, recs[0].ts_frac), (2, 500));
        assert_eq!((recs[1].ts_sec, recs[1].ts_frac), (2, 500));
        assert!(
            recs.iter().all(|r| r.data[0] != 0xa3),
            "interface 9 was never described, so its block cannot be decoded"
        );
    }

    #[test]
    fn second_section_header_is_followed() {
        let mut v = minimal(false, None, 1_000_000);
        v.extend_from_slice(&shb(true));
        v.extend_from_slice(&idb(linktype::ETHERNET, None, true));
        v.extend_from_slice(&epb(0, 7_000_000, &[0x5a; 8], 8, true));
        let recs: Vec<_> = Reader::new(&v).unwrap().collect();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].ts_sec, 1);
        assert_eq!(recs[1].ts_sec, 7);
        assert_eq!(recs[1].data, &[0x5a; 8]);
    }

    fn written(nanos: bool, recs: &[(u32, u32, &[u8], u32)]) -> Vec<u8> {
        let mut v = Vec::new();
        write_shb(&mut v);
        write_idb(&mut v, linktype::ETHERNET, 65535, nanos);
        for (s, f, d, o) in recs {
            write_epb(&mut v, 0, *s, *f, d, *o, nanos);
        }
        v
    }

    #[test]
    fn what_we_write_our_own_reader_reads_back() {
        let v = written(
            false,
            &[(1, 2, &[0xaa; 60], 60), (3, 400_000, &[0xbb; 13], 20)],
        );
        let r = Reader::new(&v).unwrap();
        assert!(!r.header.swapped);
        assert_eq!(r.header.linktype, linktype::ETHERNET);
        assert_eq!(r.header.tsresol, DEFAULT_TSRESOL);

        let recs: Vec<_> = Reader::new(&v).unwrap().collect();
        assert_eq!(recs.len(), 2);
        assert_eq!((recs[0].ts_sec, recs[0].ts_frac), (1, 2));
        assert_eq!(recs[0].data, &[0xaa; 60]);
        assert_eq!((recs[1].ts_sec, recs[1].ts_frac), (3, 400_000));
        assert_eq!((recs[1].caplen, recs[1].origlen), (13, 20));
        assert_eq!(recs[1].data, &[0xbb; 13]);
    }

    #[test]
    fn every_block_is_padded_to_four_bytes_and_ends_with_its_length() {
        for n in 0..9usize {
            let v = written(false, &[(0, 0, &vec![0x5a; n], n as u32)]);
            assert_eq!(v.len() % 4, 0, "{n}-byte packet left an unpadded file");
            // SHB(28) + IDB(20) + EPB(32 + padded data).
            assert_eq!(v.len(), 28 + 20 + 32 + pad4(n));
            let recs: Vec<_> = Reader::new(&v).unwrap().collect();
            assert_eq!(recs.len(), 1);
            assert_eq!(recs[0].data, &vec![0x5a; n][..]);
        }
    }

    #[test]
    fn nanosecond_resolution_is_declared_and_survives() {
        let v = written(true, &[(7, 123_456_789, &[0xcc; 4], 4)]);
        let r = Reader::new(&v).unwrap();
        assert_eq!(r.header.tsresol, 1_000_000_000);
        assert!(r.header.nanos());
        let rec = Reader::new(&v).unwrap().next().unwrap();
        assert_eq!((rec.ts_sec, rec.ts_frac), (7, 123_456_789));
    }

    #[test]
    fn the_largest_timestamp_the_record_fields_hold_still_round_trips() {
        let v = written(true, &[(u32::MAX, 999_999_999, &[0x01; 4], 4)]);
        let rec = Reader::new(&v).unwrap().next().unwrap();
        assert_eq!((rec.ts_sec, rec.ts_frac), (u32::MAX, 999_999_999));
    }

    #[test]
    fn count_matches_iteration() {
        let mut v = shb(false);
        v.extend_from_slice(&idb(linktype::ETHERNET, None, false));
        for i in 0..5u32 {
            v.extend_from_slice(&epb(0, i as u64 * 1_000_000, &[0xcc; 10], 10, false));
        }
        assert_eq!(count(&v).unwrap(), 5);
    }
}
