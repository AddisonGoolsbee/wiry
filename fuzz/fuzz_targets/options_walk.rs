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

    // RFC 2131 §4.1 overload and RFC 3396 joining only happen with a BOOTP
    // header in front, and only `Packet::options` reaches them.
    let mut framed = vec![0u8; 236];
    framed.extend_from_slice(&bootp::MAGIC_COOKIE);
    framed.extend_from_slice(data);
    let mut pkt = Packet::dissect(framed, ProtoId::Bootp);
    wiry_fuzz::exercise(&mut pkt);

    for table in [
        &tcp::OPTIONS,
        &ipv4::OPTIONS,
        &bootp::DHCP_OPTIONS,
        &bootp::RELAY_OPTIONS,
    ] {
        let items = table.walk(data);
        // Every item consumes an octet, so a non-advancing walk trips this
        // rather than hanging.
        assert!(items.len() <= data.len());
        let _ = table.encode(&items);
        let tlvs = table.walk_raw(data);
        assert_eq!(tlvs.len(), items.len());
        assert!(bootp::decode_joined(table, &tlvs).len() <= items.len());
    }
});
