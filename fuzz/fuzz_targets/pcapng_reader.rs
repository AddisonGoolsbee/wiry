#![no_main]

use blitzpkt_core::packet::Packet;
use blitzpkt_core::{pcap, pcapng};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(reader) = pcapng::Reader::new(data) else {
        return;
    };
    let link = pcap::link_to_proto(reader.header.linktype);
    let nanos = reader.header.nanos();
    let mut seen = 0usize;
    for rec in reader {
        seen += 1;
        assert!(rec.data.len() <= data.len());
        assert_eq!(rec.data.len(), rec.caplen as usize);
        let _ = rec.time(nanos);
        let mut pkt = Packet::dissect(rec.data.to_vec(), link);
        blitzpkt_fuzz::exercise(&mut pkt);
    }
    // The smallest packet block is 12 bytes of framing, so the block count is
    // bounded by the file: an unbounded walk would blow this assertion.
    assert!(seen <= data.len() / 12 + 1);
    assert_eq!(pcapng::count(data).unwrap(), seen);
});
