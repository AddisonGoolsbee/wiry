//! Shared assertions: dissection does not panic, it terminates, and no span
//! ever points outside the buffer it came from.

use packetry_core::packet::Packet;
use packetry_core::proto::{self, desc, ProtoId};
use packetry_core::{parse, show};

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

/// Reads every field of every layer, plus the option region and the serialised
/// bytes: an out-of-bounds read inside the engine panics here.
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
    exercise_writes(pkt);
}

/// Values of every shape a write accepts. Strings go through `parse::value_for`
/// exactly as the Python facade sends them.
const WRITE_STRS: [&str; 4] = ["1.2.3.4", "00:11:22:33:44:55", "::1", "SA"];

/// The write half of the engine carries the same never-panic contract as the
/// read half, and only a write pass tests it. Runs on a copy, after the read
/// assertions have seen the input pristine.
pub fn exercise_writes(pkt: &Packet) {
    let mut p = pkt.clone();
    for i in 0..p.layers().len() {
        let proto = p.layers()[i].proto;
        let names: Vec<&'static str> = proto::active_fields(proto, p.header(i))
            .map(|f| f.name)
            .collect();
        for name in names {
            for v in [0u64, 1, u64::MAX] {
                p.set_uint(i, name, v);
            }
            for b in [&[][..], &[0xa5][..], &[0x5a; 24][..]] {
                p.set_bytes(i, name, b);
            }
            for s in WRITE_STRS {
                let Some(f) = proto::active_field_of(proto, p.header(i), name) else {
                    continue;
                };
                match parse::value_for(f, s) {
                    Some(parse::ValueBits::Uint(v)) => p.set_uint(i, name, v),
                    Some(parse::ValueBits::Bytes(b)) => p.set_bytes(i, name, &b),
                    None => false,
                };
            }
        }
        let _ = p.to_bytes();
        check_spans(&p);
    }

    let mut q = pkt.clone();
    if !q.layers().is_empty() {
        q.set_payload(q.layers().len() - 1, b"written payload");
        q.refit_headers();
        let _ = q.to_bytes();
        check_spans(&q);
    }
}
