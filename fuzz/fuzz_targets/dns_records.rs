#![no_main]

use libfuzzer_sys::fuzz_target;
use std::time::Instant;
use wiry_core::layers::dns;
use wiry_core::packet::Packet;
use wiry_core::proto::ProtoId;

fuzz_target!(|data: &[u8]| {
    let start = Instant::now();
    let r = dns::parse_records(data);
    // Name compression lets the input point anywhere in the message, so
    // returning at all is the defence against a decompression bomb.
    assert!(
        start.elapsed().as_secs() < 2,
        "parse_records took too long on {} bytes",
        data.len()
    );

    // Record count is the wrong quantity: 65,535 two-octet pointers stay under
    // the input size while decoding hundreds of MB. Owned bytes are the only
    // quantity the message has no other bound on, and a type bit map or a
    // signature is as unbounded as a name.
    let names: usize = r.qd.iter().map(|q| q.qname.len()).sum::<usize>()
        + r.an
            .iter()
            .chain(&r.ns)
            .chain(&r.ar)
            .map(dns::decoded_name_bytes)
            .sum::<usize>();
    assert!(
        names <= dns::MAX_DECODED_NAME_BYTES,
        "decoded {names} name bytes from {} input bytes",
        data.len()
    );

    for q in &r.qd {
        assert!(q.qname.len() <= 1024);
    }
    for rr in r.an.iter().chain(&r.ns).chain(&r.ar) {
        assert!(rr.rrname.len() <= 1024);
        let _ = format!("{:?}", rr.rdata);
        let _ = rr.edns();
    }

    // RFC 1035 §4.2.2 framing: the header the fields are read from, the length
    // recomputed over it, and the whole write half of the engine.
    let mut tcp = vec![0x00, 0x35, 0x00, 0x35, 0, 0, 0, 1, 0, 0, 0, 0];
    tcp.extend_from_slice(&[0x50, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00]);
    tcp.extend_from_slice(data);
    let mut pkt = Packet::dissect(tcp, ProtoId::Tcp);
    if let Some(d) = pkt.find_layer(ProtoId::Dns) {
        assert_eq!(pkt.framing(d), 2, "DNS under TCP is always framed");
        assert_eq!(
            dns::parse_records(pkt.framed_body(d)).qd.len(),
            dns::parse_records(&pkt.layer_bytes(d)[2..]).qd.len()
        );
    }
    wiry_fuzz::exercise(&mut pkt);
});
