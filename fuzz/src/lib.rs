//! Shared assertions: dissection does not panic, it terminates, and no span
//! points outside the buffer it came from. wiry-core's
//! `tests/robustness.rs` keeps a deterministic copy of these; the two must
//! stay in step.

use wiry_core::packet::Packet;
use wiry_core::proto::{self, ProtoId};
use wiry_core::{parse, show};

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

/// Reads every field of every layer, the option region and the serialised
/// bytes: an out-of-bounds read inside the engine panics here.
pub fn exercise(pkt: &mut Packet) {
    check_spans(pkt);
    let total = pkt.len();
    for i in 0..pkt.layers().len() {
        assert!(pkt.header(i).len() <= total);
        assert!(pkt.payload(i).len() <= total);
        assert!(pkt.layer_bytes(i).len() <= total);
        for f in pkt.fields(i) {
            let v = pkt.get_desc(i, f);
            let _ = show::render_value(&v);
            let _ = v.as_uint();
            // A lookup by name answers with the field this header carries, so
            // compare only when that resolves back to this one: a false
            // condition, or another field sharing the name under a disjoint
            // condition (ICMP), both give a different answer.
            if pkt
                .active_field(i, f.name)
                .is_some_and(|a| std::ptr::eq(a, f))
            {
                assert_eq!(pkt.get(i, f.name), Some(v));
            }
        }
        let _ = pkt.options(i);
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
    for i in 0..pkt.layers().len() {
        let proto = pkt.layers()[i].proto;
        let names: Vec<&'static str> =
            proto::active_fields(proto, pkt.framing(i) > 0, pkt.header(i))
                .map(|f| f.name)
                .collect();
        for name in names {
            // One copy per field: writing a field can deactivate the
            // conditional fields after it, which would leave them untested.
            let mut p = pkt.clone();
            for v in [0u64, 1, u64::MAX] {
                p.set_uint(i, name, v);
            }
            for b in [&[][..], &[0xa5][..], &[0x5a; 24][..]] {
                p.set_bytes(i, name, b);
            }
            for s in WRITE_STRS {
                let Some(f) = p.active_field(i, name) else {
                    continue;
                };
                match parse::value_for(f, s) {
                    Some(parse::ValueBits::Uint(v)) => p.set_uint(i, name, v),
                    Some(parse::ValueBits::Bytes(b)) => p.set_bytes(i, name, &b),
                    None => false,
                };
            }
            let _ = p.to_bytes();
            check_spans(&p);
        }
    }

    let mut q = pkt.clone();
    if !q.layers().is_empty() {
        q.set_payload(q.layers().len() - 1, b"written payload");
        q.refit_headers();
        let _ = q.to_bytes();
        check_spans(&q);
    }
}
