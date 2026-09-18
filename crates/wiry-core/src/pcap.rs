//! pcap savefile layout per libpcap-savefile(5): a 24-byte file header followed
//! by 16-byte record headers.

use crate::proto::ProtoId;

pub const MAGIC_LE_USEC: u32 = 0xa1b2c3d4;
pub const MAGIC_LE_NSEC: u32 = 0xa1b23c4d;

/// tcpdump.org link-layer header type registry.
pub mod linktype {
    pub const NULL: u32 = 0;
    pub const ETHERNET: u32 = 1;
    pub const RAW: u32 = 101;
    /// DLT_NULL with the address family in network byte order.
    pub const LOOP: u32 = 108;
    pub const LINUX_SLL: u32 = 113;
    pub const IEEE802_11: u32 = 105;
    /// 802.11 frames behind a radiotap header.
    pub const IEEE802_11_RADIO: u32 = 127;
    pub const IPV4: u32 = 228;
    pub const IPV6: u32 = 229;
    pub const LINUX_SLL2: u32 = 276;
}

pub fn link_to_proto(lt: u32) -> ProtoId {
    match lt {
        linktype::ETHERNET => ProtoId::Ether,
        linktype::NULL | linktype::LOOP => ProtoId::Null,
        linktype::LINUX_SLL => ProtoId::LinuxSll,
        linktype::LINUX_SLL2 => ProtoId::LinuxSll2,
        linktype::IPV4 | linktype::RAW => ProtoId::Ipv4,
        linktype::IPV6 => ProtoId::Ipv6,
        linktype::IEEE802_11 => ProtoId::Dot11,
        linktype::IEEE802_11_RADIO => ProtoId::RadioTap,
        _ => ProtoId::Raw,
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FileHeader {
    pub swapped: bool,
    pub nanos: bool,
    pub snaplen: u32,
    pub linktype: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct Record<'a> {
    pub ts_sec: u32,
    /// Microseconds, or nanoseconds when the file uses the nanosecond magic.
    pub ts_frac: u32,
    pub caplen: u32,
    pub origlen: u32,
    pub data: &'a [u8],
}

impl Record<'_> {
    pub fn time(&self, nanos: bool) -> f64 {
        let div = if nanos { 1e9 } else { 1e6 };
        self.ts_sec as f64 + self.ts_frac as f64 / div
    }
}

#[derive(Debug)]
pub enum PcapError {
    TooShort,
    BadMagic(u32),
}

impl std::fmt::Display for PcapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PcapError::TooShort => write!(f, "file too short to contain a pcap header"),
            PcapError::BadMagic(m) => write!(f, "not a pcap file (magic {m:#010x})"),
        }
    }
}

impl std::error::Error for PcapError {}

pub fn parse_header(buf: &[u8]) -> Result<FileHeader, PcapError> {
    if buf.len() < 24 {
        return Err(PcapError::TooShort);
    }
    let raw = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let (swapped, nanos) = match raw {
        MAGIC_LE_USEC => (false, false),
        MAGIC_LE_NSEC => (false, true),
        x if x.swap_bytes() == MAGIC_LE_USEC => (true, false),
        x if x.swap_bytes() == MAGIC_LE_NSEC => (true, true),
        other => return Err(PcapError::BadMagic(other)),
    };
    let rd = |o: usize| {
        let v = u32::from_le_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]);
        if swapped {
            v.swap_bytes()
        } else {
            v
        }
    };
    Ok(FileHeader {
        swapped,
        nanos,
        snaplen: rd(16),
        linktype: rd(20),
    })
}

/// Borrows from the buffer; packet bytes are never copied.
pub struct Reader<'a> {
    buf: &'a [u8],
    off: usize,
    pub header: FileHeader,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Result<Self, PcapError> {
        let header = parse_header(buf)?;
        Ok(Self {
            buf,
            off: 24,
            header,
        })
    }

    #[inline]
    fn rd32(&self, o: usize) -> u32 {
        let v = u32::from_le_bytes([
            self.buf[o],
            self.buf[o + 1],
            self.buf[o + 2],
            self.buf[o + 3],
        ]);
        if self.header.swapped {
            v.swap_bytes()
        } else {
            v
        }
    }
}

impl<'a> Iterator for Reader<'a> {
    type Item = Record<'a>;

    #[inline]
    fn next(&mut self) -> Option<Record<'a>> {
        if self.off + 16 > self.buf.len() {
            return None;
        }
        let ts_sec = self.rd32(self.off);
        let ts_frac = self.rd32(self.off + 4);
        let caplen = self.rd32(self.off + 8);
        let origlen = self.rd32(self.off + 12);
        let start = self.off + 16;
        let n = caplen as usize;
        if start + n > self.buf.len() {
            return None;
        }
        self.off = start + n;
        Some(Record {
            ts_sec,
            ts_frac,
            caplen,
            origlen,
            data: &self.buf[start..start + n],
        })
    }
}

pub fn count(buf: &[u8]) -> Result<usize, PcapError> {
    Ok(Reader::new(buf)?.count())
}

pub fn write_header(out: &mut Vec<u8>, linktype: u32, snaplen: u32, nanos: bool) {
    let magic = if nanos { MAGIC_LE_NSEC } else { MAGIC_LE_USEC };
    out.extend_from_slice(&magic.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&snaplen.to_le_bytes());
    out.extend_from_slice(&linktype.to_le_bytes());
}

/// `origlen` below the captured length would describe a frame shorter than its
/// own bytes, so it is raised rather than written.
pub fn write_record(out: &mut Vec<u8>, ts_sec: u32, ts_frac: u32, data: &[u8], origlen: u32) {
    let data = &data[..data.len().min(u32::MAX as usize)];
    let caplen = data.len() as u32;
    out.extend_from_slice(&ts_sec.to_le_bytes());
    out.extend_from_slice(&ts_frac.to_le_bytes());
    out.extend_from_slice(&caplen.to_le_bytes());
    out.extend_from_slice(&origlen.max(caplen).to_le_bytes());
    out.extend_from_slice(data);
}

/// Splits a POSIX timestamp into the two fields a capture record carries.
/// Anything the fields cannot hold — a negative time, one past 2106, a NaN —
/// clamps, because a wrapped timestamp is a lie the reader cannot detect.
pub fn split_time(t: f64, nanos: bool) -> (u32, u32) {
    let scale = if nanos { 1e9 } else { 1e6 };
    // Also the NaN case, which compares false against everything.
    if t.partial_cmp(&0.0) != Some(std::cmp::Ordering::Greater) {
        return (0, 0);
    }
    let secs = t.floor();
    if secs >= u32::MAX as f64 {
        return (u32::MAX, scale as u32 - 1);
    }
    let frac = ((t - secs) * scale).round() as u32;
    if frac >= scale as u32 {
        (secs as u32 + 1, 0)
    } else {
        (secs as u32, frac)
    }
}

pub fn rescale_frac(frac: u32, from_nanos: bool, to_nanos: bool) -> u32 {
    match (from_nanos, to_nanos) {
        (false, true) => frac.saturating_mul(1000),
        (true, false) => frac / 1000,
        _ => frac,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny_pcap() -> Vec<u8> {
        let mut v = Vec::new();
        write_header(&mut v, linktype::ETHERNET, 65535, false);
        write_record(&mut v, 1, 2, &[0xaa; 60], 60);
        write_record(&mut v, 3, 4, &[0xbb; 14], 14);
        v
    }

    #[test]
    fn reads_records_back() {
        let data = tiny_pcap();
        let r = Reader::new(&data).unwrap();
        assert_eq!(r.header.linktype, linktype::ETHERNET);
        let recs: Vec<_> = Reader::new(&data).unwrap().collect();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].ts_sec, 1);
        assert_eq!(recs[0].data.len(), 60);
        assert_eq!(recs[1].ts_sec, 3);
        assert_eq!(recs[1].data[0], 0xbb);
    }

    #[test]
    fn a_dlt_null_file_dissects_from_its_link_type() {
        let mut v = Vec::new();
        write_header(&mut v, linktype::NULL, 65535, false);
        let mut frame = vec![2, 0, 0, 0];
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 127, 0, 0, 1,
            127, 0, 0, 1,
        ]);
        write_record(&mut v, 1, 0, &frame, frame.len() as u32);

        let r = Reader::new(&v).unwrap();
        let link = link_to_proto(r.header.linktype);
        assert_eq!(link, ProtoId::Null);
        let rec = Reader::new(&v).unwrap().next().unwrap();
        let pkt = crate::packet::Packet::dissect(rec.data.to_vec(), link);
        assert_eq!(
            pkt.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![ProtoId::Null, ProtoId::Ipv4]
        );
    }

    #[test]
    fn an_unregistered_link_type_still_falls_back_to_raw() {
        assert_eq!(link_to_proto(999), ProtoId::Raw);
    }

    #[test]
    fn rejects_non_pcap() {
        let junk = vec![0u8; 64];
        assert!(Reader::new(&junk).is_err());
    }

    #[test]
    fn truncated_record_stops_cleanly() {
        let mut data = tiny_pcap();
        data.truncate(data.len() - 5);
        let recs: Vec<_> = Reader::new(&data).unwrap().collect();
        assert_eq!(recs.len(), 1);
    }

    #[test]
    fn handles_short_file() {
        assert!(Reader::new(&[0u8; 4]).is_err());
    }

    #[test]
    fn the_nanosecond_magic_round_trips() {
        let mut v = Vec::new();
        write_header(&mut v, linktype::ETHERNET, 65535, true);
        write_record(&mut v, 7, 123_456_789, &[0xaa; 4], 4);
        let r = Reader::new(&v).unwrap();
        assert!(r.header.nanos);
        let rec = Reader::new(&v).unwrap().next().unwrap();
        assert_eq!((rec.ts_sec, rec.ts_frac), (7, 123_456_789));
        assert!((rec.time(true) - 7.123456789).abs() < 1e-12);
    }

    #[test]
    fn split_time_clamps_what_the_fields_cannot_hold() {
        assert_eq!(split_time(1.5, false), (1, 500_000));
        assert_eq!(split_time(1.5, true), (1, 500_000_000));
        assert_eq!(split_time(0.0, false), (0, 0));
        assert_eq!(split_time(-1.0, false), (0, 0));
        assert_eq!(split_time(f64::NAN, false), (0, 0));
        assert_eq!(split_time(f64::NEG_INFINITY, true), (0, 0));
        assert_eq!(split_time(f64::INFINITY, false), (u32::MAX, 999_999));
        assert_eq!(split_time(1e30, false), (u32::MAX, 999_999));
        // Rounding the fraction up must carry, not report a 1_000_000th usec.
        assert_eq!(split_time(2.9999999, false), (3, 0));
    }

    #[test]
    fn a_record_never_claims_fewer_wire_bytes_than_it_carries() {
        let mut v = Vec::new();
        write_header(&mut v, linktype::ETHERNET, 64, false);
        write_record(&mut v, 0, 0, &[0x11; 100], 4);
        write_record(&mut v, 0, 0, &[], 0);
        let recs: Vec<_> = Reader::new(&v).unwrap().collect();
        assert_eq!((recs[0].caplen, recs[0].origlen), (100, 100));
        assert_eq!((recs[1].caplen, recs[1].origlen), (0, 0));
    }
}
