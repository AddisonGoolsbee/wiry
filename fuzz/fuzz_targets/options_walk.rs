#![no_main]

use libfuzzer_sys::fuzz_target;
use wiry_core::layers::{bootp, ipv4, tcp};
use wiry_core::packet::Packet;
use wiry_core::proto::ProtoId;

fuzz_target!(|data: &[u8]| {
    let mut pkt = Packet::build_with(&[(ProtoId::Tcp, Some(data.to_vec()))]);
    wiry_fuzz::exercise(&mut pkt);

    let mut pkt = Packet::build_with(&[(ProtoId::Ipv4, Some(data.to_vec())), (ProtoId::Udp, None)]);
    wiry_fuzz::exercise(&mut pkt);

    // DHCP uses the other length convention and its own walker.
    let mut pkt = Packet::dissect(data.to_vec(), ProtoId::Dhcp);
    wiry_fuzz::exercise(&mut pkt);

    for table in [&tcp::OPTIONS, &ipv4::OPTIONS, &bootp::DHCP_OPTIONS] {
        let items = table.walk(data);
        // Every item consumes an octet, so a non-advancing walk trips this
        // rather than hanging.
        assert!(items.len() <= data.len());
        let _ = table.encode(&items);
    }
});
