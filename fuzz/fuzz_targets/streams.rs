#![no_main]

use libfuzzer_sys::fuzz_target;
use wiry_core::packet::Packet;
use wiry_core::stream;
use wiry_fuzz::all_protos;

// Stream reassembly buffers what a sender chooses to send, in an order the
// sender chooses, so an unbounded allocation, a panic on a length field or a
// hang on a crafted overlap is a denial of service on untrusted captures.
//
// The write half is exercised too: `reframe` splices reassembled octets back
// into a frame's own headers and rewrites its length fields, and a read-only
// target would leave all of that unfuzzed.
fuzz_target!(|data: &[u8]| {
    let Some((sel, body)) = data.split_first() else {
        return;
    };
    let protos = all_protos();
    let link = protos[*sel as usize % protos.len()];
    let frames: Vec<&[u8]> = body.split(|b| *b == 0xfe).take(128).collect();
    let n = frames.len();
    let input: usize = frames.iter().map(|f| f.len()).sum();

    let streams = stream::reassemble(frames.iter().copied(), link);
    // Nothing stands in for octets that never arrived, so what comes out can
    // never be more than what went in.
    let out: usize = streams
        .iter()
        .flat_map(|s| s.halves.iter())
        .map(|h| h.data.len())
        .sum();
    assert!(out <= input, "reassembly invented octets");

    for s in &streams {
        assert!((s.first as usize) < n, "stream points outside the input");
        let _ = s.key();
        for p in s.packets() {
            assert!((p as usize) < n, "provenance points outside the input");
        }
        for h in &s.halves {
            let mut end = 0u32;
            for seg in &h.segs {
                assert!(seg.at >= end, "provenance is not sorted and disjoint");
                assert!((seg.pkt as usize) < n);
                assert_eq!(h.packet_at(seg.at), Some(seg.pkt));
                end = seg.at + seg.len;
            }
            assert!(end as usize <= h.data.len(), "provenance runs past the data");
            assert!(h.data.len() <= stream::MAX_STREAM);
            for g in &h.gaps {
                assert!(g.at as usize <= h.data.len());
            }
        }
    }

    for m in stream::app_messages(&streams) {
        let h = &streams[m.stream as usize].halves[m.dir as usize];
        let at = m.at as usize;
        let end = at + m.len as usize;
        assert!(end <= h.data.len(), "a message runs past its stream");
        let src = frames[m.pkt as usize];
        let Some(sp) = stream::splice(src, link) else {
            continue;
        };
        let room = stream::room(&sp).max(1);
        for (k, part) in h.data[at..end].chunks(room).enumerate() {
            let Some(f) = stream::reframe(src, link, m.skip + (k * room) as u32, part) else {
                continue;
            };
            assert_eq!(f.len(), sp.payload + part.len());
            assert_eq!(&f[sp.payload..], part);
            let mut p = Packet::dissect(f, link);
            wiry_fuzz::exercise(&mut p);
        }
    }
});
