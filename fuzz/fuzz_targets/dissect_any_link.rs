#![no_main]

use libfuzzer_sys::fuzz_target;
use wiry_core::packet::Packet;
use wiry_fuzz::ALL_PROTOS;

fuzz_target!(|data: &[u8]| {
    let Some((sel, body)) = data.split_first() else {
        return;
    };
    let link = ALL_PROTOS[*sel as usize % ALL_PROTOS.len()];
    let mut pkt = Packet::dissect(body.to_vec(), link);
    wiry_fuzz::exercise(&mut pkt);
});
