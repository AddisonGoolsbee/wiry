#![no_main]

use libfuzzer_sys::fuzz_target;
use packetry_core::packet::Packet;
use packetry_core::pcap;

fuzz_target!(|data: &[u8]| {
    let Ok(reader) = pcap::Reader::new(data) else {
        return;
    };
    let link = pcap::link_to_proto(reader.header.linktype);
    let nanos = reader.header.nanos;
    let mut seen = 0usize;
    for rec in reader {
        seen += 1;
        assert!(rec.data.len() <= data.len());
        assert_eq!(rec.data.len(), rec.caplen as usize);
        let _ = rec.time(nanos);
        let mut pkt = Packet::dissect(rec.data.to_vec(), link);
        packetry_fuzz::exercise(&mut pkt);
    }
    // Each record costs a 16-byte header.
    assert!(seen <= data.len() / 16 + 1);
    assert_eq!(pcap::count(data).unwrap(), seen);
});
