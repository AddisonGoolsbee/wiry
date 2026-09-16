#![no_main]

use libfuzzer_sys::fuzz_target;
use packetry_core::layers::dns;
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

    // Record count is the wrong quantity: a bomb of 65,535 two-octet pointers
    // stays well under the input size while decoding hundreds of MB of names.
    // Decoded name bytes are what the message has no other bound on.
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
    }
});
