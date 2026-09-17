#![no_main]

use libfuzzer_sys::fuzz_target;
use wiry_core::packet::Packet;
use wiry_core::proto::ProtoId;

fuzz_target!(|data: &[u8]| {
    let mut pkt = Packet::dissect(data.to_vec(), ProtoId::Ether);
    wiry_fuzz::exercise(&mut pkt);
});
