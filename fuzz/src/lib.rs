//! Shared assertions for the fuzz targets.
//!
//! Every target asserts the same contract: dissection does not panic, it
//! terminates, and no span ever points outside the buffer it came from.

use blitzpkt_core::packet::Packet;
use blitzpkt_core::proto::{desc, ProtoId};
use blitzpkt_core::show;

/// Every protocol the dissector can be entered at.
pub const ALL_PROTOS: [ProtoId; 14] = [
    ProtoId::Raw,
    ProtoId::Padding,
    ProtoId::Ether,
    ProtoId::Dot1Q,
    ProtoId::Arp,
    ProtoId::Ipv4,
    ProtoId::Ipv6,
    ProtoId::Tcp,
    ProtoId::Udp,
    ProtoId::Icmp,
    ProtoId::Icmpv6,
    ProtoId::Dns,
    ProtoId::Bootp,
    ProtoId::Dhcp,
];

/// Spans must stay inside the buffer and must not run backwards.
pub fn check_spans(pkt: &Packet) {
    let n = pkt.len();
    let mut prev = 0u32;
    for s in pkt.layers() {
        assert!(s.off as usize <= n, "span offset past buffer");
        assert!(
            s.off as usize + s.hlen as usize <= n,
            "span header past buffer"
        );
        assert!(s.off >= prev, "spans out of order");
        prev = s.off;
    }
}

/// Read every field of every layer, plus the option region and the serialised
/// bytes. Any out-of-bounds read inside the engine panics, which is the bug.
pub fn exercise(pkt: &mut Packet) {
    check_spans(pkt);
    let n = pkt.layers().len();
    let total = pkt.len();
    for i in 0..n {
        let proto = pkt.layers()[i].proto;
        assert!(pkt.header(i).len() <= total);
        assert!(pkt.payload(i).len() <= total);
        assert!(pkt.layer_bytes(i).len() <= total);
        for f in desc(proto).fields {
            let v = pkt.get_desc(i, f);
            let _ = show::render_value(&v);
            let _ = v.as_uint();
            assert_eq!(pkt.get(i, f.name), Some(v));
        }
        let _ = pkt.options(i);
        assert!(pkt.has_layer(proto));
    }
    let _ = show::summary(pkt);
    let _ = show::show(pkt);
    let _ = pkt.to_bytes();
    check_spans(pkt);
}
