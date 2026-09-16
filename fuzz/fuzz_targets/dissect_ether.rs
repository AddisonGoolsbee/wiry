#![no_main]

use libfuzzer_sys::fuzz_target;
use packetry_core::packet::Packet;
use packetry_core::proto::ProtoId;

fuzz_target!(|data: &[u8]| {
    let mut pkt = Packet::dissect(data.to_vec(), ProtoId::Ether);
    packetry_fuzz::exercise(&mut pkt);
});
