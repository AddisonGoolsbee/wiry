#![no_main]

use blitzpkt_core::layers::dns;
use libfuzzer_sys::fuzz_target;
use std::time::Instant;

fuzz_target!(|data: &[u8]| {
    let start = Instant::now();
    let r = dns::parse_records(data);
    // Name compression lets the input point anywhere in the message, so the
    // only defence against a decompression bomb is that this returns at all.
    assert!(
        start.elapsed().as_secs() < 2,
        "parse_records took too long on {} bytes",
        data.len()
    );

    // Each record consumes at least one byte, so the header's section counts
    // cannot make the output larger than the input.
    let n = r.qd.len() + r.an.len() + r.ns.len() + r.ar.len();
    assert!(n <= data.len(), "more records than bytes");

    for q in &r.qd {
        assert!(q.qname.len() <= 1024);
    }
    for rr in r.an.iter().chain(&r.ns).chain(&r.ar) {
        assert!(rr.rrname.len() <= 1024);
        let _ = format!("{:?}", rr.rdata);
    }
});
