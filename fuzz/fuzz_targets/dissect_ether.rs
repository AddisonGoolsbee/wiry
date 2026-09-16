#![no_main]

use blitzpkt_core::packet::Packet;
use blitzpkt_core::proto::ProtoId;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut pkt = Packet::dissect(data.to_vec(), ProtoId::Ether);
    blitzpkt_fuzz::exercise(&mut pkt);
});
