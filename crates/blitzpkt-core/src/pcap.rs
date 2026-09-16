//! pcap file format (libpcap savefile). Layout per the libpcap-savefile(5)
//! description: a 24-byte file header followed by 16-byte record headers.
//!
//! The reader borrows from one buffer and never copies packet bytes, which is
//! what makes bulk reading cheap.

use crate::proto::ProtoId;

pub const MAGIC_LE_USEC: u32 = 0xa1b2c3d4;
pub const MAGIC_LE_NSEC: u32 = 0xa1b23c4d;

/// LINKTYPE_ values from the tcpdump.org link-layer header type registry.
pub mod linktype {
    pub const NULL: u32 = 0;
    pub const ETHERNET: u32 = 1;
    pub const RAW: u32 = 101;
    pub const LINUX_SLL: u32 = 113;
    pub const IPV4: u32 = 228;
    pub const IPV6: u32 = 229;
}

pub fn link_to_proto(lt: u32) -> ProtoId {
    match lt {
        linktype::ETHERNET => ProtoId::Ether,
        linktype::IPV4 | linktype::RAW => ProtoId::Ipv4,
        linktype::IPV6 => ProtoId::Ipv6,
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
    /// Timestamp as floating seconds, matching the conventional pcap reader API.
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
        if swapped { v.swap_bytes() } else { v }
    };
    Ok(FileHeader { swapped, nanos, snaplen: rd(16), linktype: rd(20) })
}

/// Zero-copy iterator over the records in a pcap buffer.
pub struct Reader<'a> {
    buf: &'a [u8],
    off: usize,
    pub header: FileHeader,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Result<Self, PcapError> {
        let header = parse_header(buf)?;
        Ok(Self { buf, off: 24, header })
    }

    #[inline]
    fn rd32(&self, o: usize) -> u32 {
        let v = u32::from_le_bytes([
            self.buf[o], self.buf[o + 1], self.buf[o + 2], self.buf[o + 3],
        ]);
        if self.header.swapped { v.swap_bytes() } else { v }
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
        Some(Record { ts_sec, ts_frac, caplen, origlen, data: &self.buf[start..start + n] })
    }
}

/// Count records without dissecting. Useful as a benchmark floor.
pub fn count(buf: &[u8]) -> Result<usize, PcapError> {
    Ok(Reader::new(buf)?.count())
}

/// Serialise a pcap file header.
pub fn write_header(out: &mut Vec<u8>, linktype: u32, snaplen: u32) {
    out.extend_from_slice(&MAGIC_LE_USEC.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes()); // version major
    out.extend_from_slice(&4u16.to_le_bytes()); // version minor
    out.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    out.extend_from_slice(&snaplen.to_le_bytes());
    out.extend_from_slice(&linktype.to_le_bytes());
}

/// Append one record.
pub fn write_record(out: &mut Vec<u8>, ts_sec: u32, ts_usec: u32, data: &[u8], origlen: u32) {
    out.extend_from_slice(&ts_sec.to_le_bytes());
    out.extend_from_slice(&ts_usec.to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&origlen.to_le_bytes());
    out.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny_pcap() -> Vec<u8> {
        let mut v = Vec::new();
        write_header(&mut v, linktype::ETHERNET, 65535);
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
}
