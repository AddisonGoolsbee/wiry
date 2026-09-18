#![no_main]

use libfuzzer_sys::fuzz_target;
use wiry_core::packet::Packet;
use wiry_core::{pcap, pcapng};

const LINKS: [u32; 6] = [0, 1, 101, 108, 113, 229];

/// Chops the input into (timestamp, wire length, bytes) triples. The timestamp
/// comes from raw bits, so NaNs and infinities reach the writer.
fn records(mut data: &[u8]) -> Vec<(f64, u32, &[u8])> {
    let mut out = Vec::new();
    while data.len() >= 12 {
        let (head, rest) = data.split_at(12);
        let bits = u64::from_le_bytes(head[..8].try_into().unwrap());
        let wirelen = u16::from_le_bytes([head[8], head[9]]) as u32;
        let len = (u16::from_le_bytes([head[10], head[11]]) as usize).min(rest.len());
        let (body, tail) = rest.split_at(len);
        out.push((f64::from_bits(bits), wirelen, body));
        data = tail;
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let Some((sel, body)) = data.split_first() else {
        return;
    };
    let nanos = sel & 1 != 0;
    let link = LINKS[(*sel >> 1) as usize % LINKS.len()];
    let scale = if nanos { 1_000_000_000 } else { 1_000_000 };
    let recs = records(body);

    let mut pc = Vec::new();
    pcap::write_header(&mut pc, link, 65535, nanos);
    let mut ng = Vec::new();
    pcapng::write_shb(&mut ng);
    pcapng::write_idb(&mut ng, link, 65535, nanos);
    let mut want = Vec::with_capacity(recs.len());
    for (time, wirelen, bytes) in &recs {
        let (sec, frac) = pcap::split_time(*time, nanos);
        assert!(frac < scale, "fraction is not a fraction of a second");
        pcap::write_record(&mut pc, sec, frac, bytes, *wirelen);
        pcapng::write_epb(&mut ng, 0, sec, frac, bytes, *wirelen, nanos);
        want.push((sec, frac, *bytes, (*wirelen).max(bytes.len() as u32)));
    }
    // Every block is a whole number of 4-byte words, framing included.
    assert_eq!(ng.len() % 4, 0, "a pcapng block was left unpadded");

    let proto = pcap::link_to_proto(link);
    let read_pc = pcap::Reader::new(&pc).expect("what we wrote is not a pcap file");
    assert_eq!(read_pc.header.linktype, link);
    assert_eq!(read_pc.header.nanos, nanos);
    let read_ng = pcapng::Reader::new(&ng).expect("what we wrote is not a pcapng file");
    assert_eq!(read_ng.header.linktype, link);
    assert_eq!(read_ng.header.nanos(), nanos);

    for (got, expect) in read_pc.zip(read_ng).zip(&want) {
        let (a, b) = got;
        for rec in [a, b] {
            assert_eq!((rec.ts_sec, rec.ts_frac), (expect.0, expect.1));
            assert_eq!(rec.data, expect.2);
            assert_eq!(rec.caplen as usize, rec.data.len());
            assert_eq!(rec.origlen, expect.3);
            let mut pkt = Packet::dissect(rec.data.to_vec(), proto);
            wiry_fuzz::exercise(&mut pkt);
        }
    }
    assert_eq!(pcap::count(&pc).unwrap(), want.len());
    assert_eq!(pcapng::count(&ng).unwrap(), want.len());
});
