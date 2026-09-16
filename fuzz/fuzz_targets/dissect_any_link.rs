#![no_main]

use blitzpkt_core::packet::Packet;
use blitzpkt_fuzz::ALL_PROTOS;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((sel, body)) = data.split_first() else {
        return;
    };
    let link = ALL_PROTOS[*sel as usize % ALL_PROTOS.len()];
    let mut pkt = Packet::dissect(body.to_vec(), link);
    blitzpkt_fuzz::exercise(&mut pkt);
});
