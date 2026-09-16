#![no_main]

use libfuzzer_sys::fuzz_target;
use packetry_core::options::{self, Item};
use packetry_core::packet::Packet;
use packetry_core::proto::ProtoId;

fuzz_target!(|data: &[u8]| {
    let mut pkt = Packet::build_with(&[(ProtoId::Tcp, Some(data.to_vec()))]);
    packetry_fuzz::exercise(&mut pkt);

    let mut pkt = Packet::build_with(&[(ProtoId::Ipv4, Some(data.to_vec())), (ProtoId::Udp, None)]);
    packetry_fuzz::exercise(&mut pkt);

    // DHCP uses the other length convention and its own walker.
    let mut pkt = Packet::dissect(data.to_vec(), ProtoId::Dhcp);
    packetry_fuzz::exercise(&mut pkt);

    for single in [&[0u8, 1u8][..], &[][..]] {
        for end in [None, Some(0u8), Some(255u8)] {
            let items = options::walk_tlv(data, single, end, |c, p| {
                Item::uint("o", c as u32, p.iter().map(|b| *b as u64).sum())
            });
            // Every item consumes an octet, so a non-advancing walk trips
            // this rather than hanging.
            assert!(items.len() <= data.len());
        }
    }
});
