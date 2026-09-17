use packetry_core::pcap;

/// What the caller wants after seeing a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Continue,
    Stop,
}

/// Owned metadata for one captured frame. Deliberately owns nothing borrowed
/// from the backend: libpcap reuses its ring slot on the next read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketMeta {
    pub ts_sec: u32,
    pub ts_frac: u32,
    pub caplen: u32,
    pub origlen: u32,
}

pub trait PacketSink {
    fn on_packet(&mut self, meta: &PacketMeta, data: &[u8]) -> Flow;
}

impl<F: FnMut(&PacketMeta, &[u8]) -> Flow> PacketSink for F {
    fn on_packet(&mut self, meta: &PacketMeta, data: &[u8]) -> Flow {
        self(meta, data)
    }
}

/// Accumulates captured frames as a valid pcap file image plus the same record
/// index a read file produces, so a live capture and a read one are the same
/// bytes and share every bulk path.
pub struct CaptureBuf {
    buf: Vec<u8>,
    index: Vec<(usize, u32, u32, u32)>,
    linktype: u32,
}

impl CaptureBuf {
    pub fn new(linktype: u32, snaplen: u32) -> Self {
        let mut buf = Vec::new();
        pcap::write_header(&mut buf, linktype, snaplen);
        Self {
            buf,
            index: Vec::new(),
            linktype,
        }
    }

    pub fn push(&mut self, meta: &PacketMeta, data: &[u8]) {
        // write_record emits a 16-byte record header before the data.
        let off = self.buf.len() + 16;
        pcap::write_record(&mut self.buf, meta.ts_sec, meta.ts_frac, data, meta.origlen);
        self.index
            .push((off, data.len() as u32, meta.ts_sec, meta.ts_frac));
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    pub fn linktype(&self) -> u32 {
        self.linktype
    }

    pub fn as_pcap_bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn into_parts(self) -> (Vec<u8>, Vec<(usize, u32, u32, u32)>, u32) {
        (self.buf, self.index, self.linktype)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(n: u32, len: u32) -> PacketMeta {
        PacketMeta {
            ts_sec: n,
            ts_frac: n * 1000,
            caplen: len,
            origlen: len,
        }
    }

    #[test]
    fn image_reads_back_through_the_pcap_reader() {
        let mut cb = CaptureBuf::new(pcap::linktype::ETHERNET, 65535);
        cb.push(&meta(1, 4), &[1, 2, 3, 4]);
        cb.push(&meta(2, 3), &[9, 9, 9]);
        let recs: Vec<_> = pcap::Reader::new(cb.as_pcap_bytes()).unwrap().collect();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].data, &[1, 2, 3, 4]);
        assert_eq!(recs[0].ts_sec, 1);
        assert_eq!(recs[1].data, &[9, 9, 9]);
    }

    #[test]
    fn index_offsets_point_at_the_data() {
        let mut cb = CaptureBuf::new(pcap::linktype::ETHERNET, 65535);
        cb.push(&meta(1, 4), &[0xaa, 0xbb, 0xcc, 0xdd]);
        cb.push(&meta(2, 2), &[0xee, 0xff]);
        let (buf, index, _) = cb.into_parts();
        let expected: [&[u8]; 2] = [&[0xaa, 0xbb, 0xcc, 0xdd], &[0xee, 0xff]];
        for (i, (off, len, _, _)) in index.iter().enumerate() {
            assert_eq!(&buf[*off..*off + *len as usize], expected[i]);
        }
    }

    #[test]
    fn empty_capture_is_still_a_valid_file() {
        let cb = CaptureBuf::new(pcap::linktype::ETHERNET, 65535);
        assert!(cb.is_empty());
        assert_eq!(pcap::Reader::new(cb.as_pcap_bytes()).unwrap().count(), 0);
    }
}
