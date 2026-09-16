#![no_main]

use packetry_core::packet::Packet;
use packetry_core::proto::ProtoId;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut pkt = Packet::dissect(data.to_vec(), ProtoId::Ether);
    packetry_fuzz::exercise(&mut pkt);
});
