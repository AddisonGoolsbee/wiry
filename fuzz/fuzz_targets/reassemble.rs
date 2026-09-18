#![no_main]

use libfuzzer_sys::fuzz_target;
use wiry_core::frag::{self, Piece};
use wiry_core::packet::Packet;
use wiry_fuzz::all_protos;

// Reassembly buffers what it is handed: an unbounded allocation or a panic on a
// length field is a denial of service on untrusted captures.
fuzz_target!(|data: &[u8]| {
    let Some((sel, body)) = data.split_first() else {
        return;
    };
    let protos = all_protos();
    let link = protos[*sel as usize % protos.len()];

    // One buffer, cut into frames at a marker, so the fuzzer can build a whole
    // fragment set out of flat input.
    let frames: Vec<&[u8]> = body.split(|b| *b == 0xfe).take(64).collect();

    for f in &frames {
        let split = frag::fragment(f, link, (f.len() | 1) % 2048);
        assert!(!split.is_empty(), "fragmenting produced nothing");
        let refs: Vec<&[u8]> = split.iter().map(|x| x.as_slice()).collect();
        for piece in frag::defragment(refs, link) {
            if let Piece::Complete(_, whole) = piece {
                let mut p = Packet::dissect(whole, link);
                wiry_fuzz::check_spans(&p);
                let _ = p.to_bytes();
            }
        }
    }

    let n = frames.len();
    let pieces = frag::defragment(frames, link);
    // Fragments collapse into one datagram, so pieces only ever get fewer.
    assert!(pieces.len() <= n, "reassembly invented pieces");
    for piece in pieces {
        assert!(
            (piece.at() as usize) < n,
            "piece points outside the input"
        );
        if let Piece::Complete(_, whole) = piece {
            assert!(whole.len() <= frag::MAX_DATAGRAM + 128);
            let mut p = Packet::dissect(whole, link);
            wiry_fuzz::exercise(&mut p);
        }
    }
});
