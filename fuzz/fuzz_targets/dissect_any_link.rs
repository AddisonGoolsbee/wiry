#![no_main]

use libfuzzer_sys::fuzz_target;
use wiry_core::packet::Packet;
use wiry_fuzz::all_protos;

fuzz_target!(|data: &[u8]| {
    let Some((sel, body)) = data.split_first() else {
        return;
    };
    let protos = all_protos();
    let link = protos[*sel as usize % protos.len()];
    let mut pkt = Packet::dissect(body.to_vec(), link);
    wiry_fuzz::exercise(&mut pkt);
});
