//! Robustness properties over malformed input.
//!
//! The design promise is that every parser returns what it managed, never
//! panics and never loops forever, because truncated and hostile input is the
//! normal case on snaplen-clipped captures. These are the stable-toolchain
//! equivalent of the `fuzz/` targets: same contract, deterministic inputs, so
//! they run in ordinary `cargo test`. See `fuzz/README.md`.

use blitzpkt_core::layers::dns;
use blitzpkt_core::options::{self, Item};
use blitzpkt_core::packet::Packet;
use blitzpkt_core::proto::{desc, ProtoId};
use blitzpkt_core::{pcap, pcapng, show};
use std::time::{Duration, Instant};

/// Fixed so a failure is reproducible; printed in every assertion message.
const SEED: u64 = 0x2545_F491_4F6C_DD1D;

/// Wall-clock budget for one property loop. Generous enough not to flake on a
/// loaded CI runner, tight enough that an unbounded walk trips it.
const BUDGET: Duration = Duration::from_secs(20);

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next_u64() >> 24) as u8).collect()
    }

    fn bytes_below(&mut self, n: usize) -> Vec<u8> {
        let k = self.below(n);
        self.bytes(k)
    }

    fn byte(&mut self) -> u8 {
        (self.next_u64() >> 24) as u8
    }
}

/// Run `f` on a worker thread and fail if it does not finish in time. A parser
/// that loops forever would otherwise hang the whole run instead of failing.
fn within<F: FnOnce() + Send + 'static>(limit: Duration, what: &'static str, f: F) {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        f();
        let _ = tx.send(());
    });
    match rx.recv_timeout(limit) {
        Ok(()) => {}
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            panic!("{what} did not terminate within {limit:?} (seed {SEED:#x})")
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            panic!("{what} panicked; see the message above (seed {SEED:#x})")
        }
    }
}

const ENTRY_POINTS: [ProtoId; 14] = [
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
fn check_spans(pkt: &Packet, what: &str) {
    let n = pkt.len();
    let mut prev = 0u32;
    for s in pkt.layers() {
        assert!(
            s.off as usize + s.hlen as usize <= n,
            "span {:?} runs past the {n}-byte buffer ({what}, seed {SEED:#x})",
            s
        );
        assert!(s.off >= prev, "spans out of order ({what}, seed {SEED:#x})");
        prev = s.off;
    }
}

/// Read every field of every layer, the option region, and the serialised bytes.
/// Any out-of-bounds read inside the engine panics, which is exactly the bug
/// this is looking for.
fn exercise(pkt: &mut Packet, what: &str) {
    check_spans(pkt, what);
    let total = pkt.len();
    for i in 0..pkt.layers().len() {
        let proto = pkt.layers()[i].proto;
        assert!(pkt.header(i).len() <= total, "{what}, seed {SEED:#x}");
        assert!(pkt.payload(i).len() <= total, "{what}, seed {SEED:#x}");
        assert!(pkt.layer_bytes(i).len() <= total, "{what}, seed {SEED:#x}");
        for f in desc(proto).fields {
            let v = pkt.get_desc(i, f);
            let _ = show::render_value(&v);
            let _ = v.as_uint();
        }
        let _ = pkt.options(i);
    }
    let _ = show::summary(pkt);
    let _ = show::show(pkt);
    let _ = pkt.to_bytes();
    check_spans(pkt, what);
}

// ---- hand-built valid packets, from the RFC layouts, not from any tool ----

fn eth_ip_tcp() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    v.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    v.extend_from_slice(&[0x08, 0x00]);
    v.extend_from_slice(&[0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00]);
    v.extend_from_slice(&[0x40, 0x06, 0x00, 0x00]);
    v.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
    v.extend_from_slice(&[0x1f, 0x90, 0x00, 0x50]);
    v.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0]);
    v.extend_from_slice(&[0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00]);
    v
}

fn eth_ip_tcp_options() -> Vec<u8> {
    let mut v = eth_ip_tcp();
    v[46] = 0x80; // data offset 8: three more 32-bit words of options
    v.splice(
        54..54,
        [
            2, 4, 0x05, 0xb4, 4, 2, 1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0,
        ],
    );
    v
}

fn dns_query() -> Vec<u8> {
    let mut v = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    v.extend_from_slice(&[1, b'a', 3, b'n', b'e', b't', 0]);
    v.extend_from_slice(&[0, 1, 0, 1]);
    v
}

fn eth_ip_udp_dns() -> Vec<u8> {
    let dns = dns_query();
    let mut v = Vec::new();
    v.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    v.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    v.extend_from_slice(&[0x08, 0x00]);
    let total = (20 + 8 + dns.len()) as u16;
    v.extend_from_slice(&[0x45, 0x00]);
    v.extend_from_slice(&total.to_be_bytes());
    v.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00]);
    v.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
    v.extend_from_slice(&[0x14, 0xe9, 0x00, 0x35]);
    v.extend_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
    v.extend_from_slice(&[0x00, 0x00]);
    v.extend_from_slice(&dns);
    v
}

fn eth_arp() -> Vec<u8> {
    let mut v = vec![0xff; 6];
    v.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    v.extend_from_slice(&[0x08, 0x06]);
    v.extend_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    v.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 10, 0, 0, 1]);
    v.extend_from_slice(&[0, 0, 0, 0, 0, 0, 10, 0, 0, 2]);
    v
}

fn eth_ipv6_icmpv6() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    v.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    v.extend_from_slice(&[0x86, 0xdd]);
    v.extend_from_slice(&[0x60, 0, 0, 0, 0, 8, 0x3a, 0x40]);
    v.extend_from_slice(&[0xfe, 0x80]);
    v.extend_from_slice(&[0u8; 13]);
    v.push(1);
    v.extend_from_slice(&[0xfe, 0x80]);
    v.extend_from_slice(&[0u8; 13]);
    v.push(2);
    v.extend_from_slice(&[0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01]);
    v
}

fn eth_dhcp() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&[0xff; 6]);
    v.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    v.extend_from_slice(&[0x08, 0x00]);
    let mut payload = vec![0x01, 0x01, 0x06, 0x00, 0x12, 0x34, 0x56, 0x78];
    payload.extend_from_slice(&[0u8; 228]);
    payload.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    payload.extend_from_slice(&[53, 1, 1, 55, 3, 1, 3, 6, 255]);
    let total = (20 + 8 + payload.len()) as u16;
    v.extend_from_slice(&[0x45, 0x00]);
    v.extend_from_slice(&total.to_be_bytes());
    v.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00]);
    v.extend_from_slice(&[0, 0, 0, 0, 255, 255, 255, 255]);
    v.extend_from_slice(&[0x00, 0x44, 0x00, 0x43]);
    v.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    v.extend_from_slice(&[0x00, 0x00]);
    v.extend_from_slice(&payload);
    v
}

fn valid_frames() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("eth/ip/tcp", eth_ip_tcp()),
        ("eth/ip/tcp+options", eth_ip_tcp_options()),
        ("eth/ip/udp/dns", eth_ip_udp_dns()),
        ("eth/arp", eth_arp()),
        ("eth/ipv6/icmpv6", eth_ipv6_icmpv6()),
        ("eth/ip/udp/dhcp", eth_dhcp()),
    ]
}

// ---- properties ----

#[test]
fn random_bytes_dissect_at_every_entry_point() {
    let mut rng = Rng::new(SEED);
    let start = Instant::now();
    for i in 0..8000 {
        let len = match i % 4 {
            0 => rng.below(8),
            1 => rng.below(64),
            2 => rng.below(600),
            _ => rng.below(1600),
        };
        let data = rng.bytes(len);
        let link = ENTRY_POINTS[rng.below(ENTRY_POINTS.len())];
        let mut pkt = Packet::dissect(data, link);
        exercise(&mut pkt, &format!("random #{i} at {link:?}"));
    }
    assert!(
        start.elapsed() < BUDGET,
        "random dissection did not finish promptly (seed {SEED:#x})"
    );
}

#[test]
fn random_bytes_under_a_valid_prefix() {
    // Pure random bytes rarely reach the deeper parsers, so graft random tails
    // onto real headers.
    let mut rng = Rng::new(SEED ^ 0xa5a5);
    let frames = valid_frames();
    for i in 0..6000 {
        let (name, base) = &frames[rng.below(frames.len())];
        let cut = rng.below(base.len() + 1);
        let mut data = base[..cut].to_vec();
        data.extend(rng.bytes_below(300));
        let mut pkt = Packet::dissect(data, ProtoId::Ether);
        exercise(&mut pkt, &format!("{name} prefix {cut} + random #{i}"));
    }
}

#[test]
fn truncation_at_every_offset() {
    for (name, base) in valid_frames() {
        for cut in 0..=base.len() {
            let mut pkt = Packet::dissect(base[..cut].to_vec(), ProtoId::Ether);
            exercise(&mut pkt, &format!("{name} truncated to {cut}"));
        }
    }
}

#[test]
fn single_bit_flips() {
    for (name, base) in valid_frames() {
        for byte in 0..base.len() {
            for bit in 0..8 {
                let mut data = base.clone();
                data[byte] ^= 1 << bit;
                let mut pkt = Packet::dissect(data, ProtoId::Ether);
                exercise(&mut pkt, &format!("{name} bit {bit} of byte {byte}"));
            }
        }
    }
}

#[test]
fn extreme_length_and_offset_fields() {
    const EXTREMES: [u16; 6] = [0, 1, 0x00ff, 0x0f0f, 0xff00, 0xffff];
    for (name, base) in valid_frames() {
        for pos in 0..base.len() {
            for v in EXTREMES {
                let mut data = base.clone();
                data[pos] = (v >> 8) as u8;
                if pos + 1 < data.len() {
                    data[pos + 1] = (v & 0xff) as u8;
                }
                let mut pkt = Packet::dissect(data, ProtoId::Ether);
                exercise(&mut pkt, &format!("{name} extreme {v:#06x} at {pos}"));
            }
        }
    }
}

#[test]
fn truncated_and_mutated_input_round_trips_to_a_fixed_point() {
    let mut rng = Rng::new(SEED ^ 0x5eed);
    let frames = valid_frames();
    for i in 0..4000 {
        let (name, base) = &frames[rng.below(frames.len())];
        let mut data = base[..rng.below(base.len() + 1)].to_vec();
        for _ in 0..rng.below(6) {
            if data.is_empty() {
                break;
            }
            let at = rng.below(data.len());
            data[at] = rng.byte();
        }
        let link = ENTRY_POINTS[rng.below(ENTRY_POINTS.len())];

        let mut first = Packet::dissect(data, link);
        first.mark_all_dirty();
        let bytes = first.to_bytes().to_vec();

        let mut second = Packet::dissect(bytes.clone(), link);
        second.mark_all_dirty();
        let bytes2 = second.to_bytes().to_vec();

        assert_eq!(
            first.layers(),
            second.layers(),
            "{name} #{i}: layer chain changed after re-serialising (seed {SEED:#x})"
        );
        assert_eq!(
            bytes, bytes2,
            "{name} #{i}: serialisation is not a fixed point (seed {SEED:#x})"
        );
    }
}

#[test]
fn random_input_round_trips_to_a_fixed_point() {
    let mut rng = Rng::new(SEED ^ 0xfeed);
    for i in 0..4000 {
        let data = rng.bytes_below(400);
        let link = ENTRY_POINTS[rng.below(ENTRY_POINTS.len())];
        let mut first = Packet::dissect(data, link);
        first.mark_all_dirty();
        let bytes = first.to_bytes().to_vec();
        let mut second = Packet::dissect(bytes.clone(), link);
        second.mark_all_dirty();
        assert_eq!(
            bytes,
            second.to_bytes(),
            "random #{i} at {link:?}: serialisation is not a fixed point (seed {SEED:#x})"
        );
    }
}

// ---- DNS name compression: the highest-value adversarial surface ----

fn dns_header(qd: u16, an: u16, ns: u16, ar: u16) -> Vec<u8> {
    let mut v = vec![0xab, 0xcd, 0x81, 0x80];
    v.extend_from_slice(&qd.to_be_bytes());
    v.extend_from_slice(&an.to_be_bytes());
    v.extend_from_slice(&ns.to_be_bytes());
    v.extend_from_slice(&ar.to_be_bytes());
    v
}

fn ptr(target: usize) -> [u8; 2] {
    [0xc0 | ((target >> 8) & 0x3f) as u8, (target & 0xff) as u8]
}

#[test]
fn dns_adversarial_compression_pointers_terminate() {
    let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();

    // Self-referential: the pointer at 12 names offset 12.
    let mut m = dns_header(1, 0, 0, 0);
    m.extend_from_slice(&ptr(12));
    m.extend_from_slice(&[0, 1, 0, 1]);
    cases.push(("self-referential", m));

    // Mutually referential: 12 -> 14 -> 12.
    let mut m = dns_header(1, 0, 0, 0);
    m.extend_from_slice(&ptr(14));
    m.extend_from_slice(&ptr(12));
    m.extend_from_slice(&[0, 1, 0, 1]);
    cases.push(("mutually referential", m));

    // Forward pointer into later, unparsed bytes.
    let mut m = dns_header(1, 0, 0, 0);
    m.extend_from_slice(&ptr(40));
    m.extend_from_slice(&[0u8; 40]);
    cases.push(("forward", m));

    // Target past the end of the message.
    let mut m = dns_header(1, 0, 0, 0);
    m.extend_from_slice(&ptr(0x3fff));
    m.extend_from_slice(&[0, 1, 0, 1]);
    cases.push(("out of bounds", m));

    // A long strictly-backwards chain: every pointer is individually legal, so
    // only the jump cap stops the walk.
    let mut m = dns_header(1, 0, 0, 0);
    for i in 0..600 {
        let t = if i == 0 { 12 } else { 12 + (i - 1) * 2 };
        m.extend_from_slice(&ptr(t));
    }
    let last = m.len() - 2;
    m.splice(12..14, ptr(last).iter().copied());
    cases.push(("long backwards chain", m));

    // A chain that alternates a real label with a backwards jump, which is how
    // a decompression bomb is built.
    let mut m = dns_header(1, 0, 0, 0);
    m.extend_from_slice(&[4, b'a', b'a', b'a', b'a']);
    for _ in 0..200 {
        let here = m.len();
        m.extend_from_slice(&[4, b'b', b'b', b'b', b'b']);
        m.extend_from_slice(&ptr(here.saturating_sub(5)));
    }
    cases.push(("label/jump alternation", m));

    // Reserved label types 0b01 and 0b10.
    for (name, top) in [("reserved 0b01", 0x40u8), ("reserved 0b10", 0x80u8)] {
        let mut m = dns_header(1, 0, 0, 0);
        m.extend_from_slice(&[top | 0x0a, 0, 0, 1, 0, 1]);
        cases.push((name, m));
    }

    // Header lies about the section counts.
    let mut m = dns_header(0xffff, 0xffff, 0xffff, 0xffff);
    m.extend_from_slice(&[1, b'a', 0, 0, 1, 0, 1]);
    cases.push(("count lie", m));

    // Maximal counts over a buffer that is all pointers.
    let mut m = dns_header(0xffff, 0xffff, 0xffff, 0xffff);
    for i in 0..2000 {
        m.extend_from_slice(&ptr(12 + (i % 8)));
    }
    cases.push(("pointer field", m));

    // RDLENGTH reaching past the record and into the next one.
    let mut m = dns_header(0, 1, 0, 0);
    m.extend_from_slice(&[1, b'a', 0]);
    m.extend_from_slice(&[0, 6, 0, 1, 0, 0, 0, 0]); // SOA, ttl 0
    m.extend_from_slice(&[0xff, 0xff]); // rdlength 65535
    cases.push(("rdlength overrun", m));

    for (name, msg) in cases {
        within(Duration::from_secs(2), name, move || {
            let r = dns::parse_records(&msg);
            let n = r.qd.len() + r.an.len() + r.ns.len() + r.ar.len();
            assert!(
                n <= msg.len(),
                "{name}: more records ({n}) than message bytes ({})",
                msg.len()
            );
        });
    }
}

#[test]
fn dns_random_and_mutated_messages_terminate() {
    let mut rng = Rng::new(SEED ^ 0xd45);
    let base = eth_ip_udp_dns();
    let dns_off = 42;
    let start = Instant::now();

    for i in 0..6000 {
        let data = match i % 3 {
            // Pure random.
            0 => rng.bytes_below(300),
            // A real message with random mutations, biased towards pointers.
            1 => {
                let mut d = base[dns_off..].to_vec();
                for _ in 0..1 + rng.below(4) {
                    let at = rng.below(d.len());
                    d[at] = if rng.below(2) == 0 {
                        0xc0 | rng.byte() & 0x3f
                    } else {
                        rng.byte()
                    };
                }
                d
            }
            // A valid header over random record bytes.
            _ => {
                let mut d = dns_header(
                    (rng.next_u64() >> 24) as u16,
                    (rng.next_u64() >> 24) as u16,
                    (rng.next_u64() >> 24) as u16,
                    (rng.next_u64() >> 24) as u16,
                );
                d.extend(rng.bytes_below(300));
                d
            }
        };
        let r = dns::parse_records(&data);
        let n = r.qd.len() + r.an.len() + r.ns.len() + r.ar.len();
        assert!(
            n <= data.len(),
            "message #{i}: more records than bytes (seed {SEED:#x})"
        );
        for q in &r.qd {
            assert!(q.qname.len() <= 1024, "qname too long (seed {SEED:#x})");
        }
        for rr in r.an.iter().chain(&r.ns).chain(&r.ar) {
            assert!(rr.rrname.len() <= 1024, "rrname too long (seed {SEED:#x})");
            let _ = format!("{:?}", rr.rdata);
        }
    }

    assert!(
        start.elapsed() < BUDGET,
        "DNS parsing did not finish promptly (seed {SEED:#x})"
    );
}

// ---- option regions ----

#[test]
fn option_regions_never_hang_or_over_read() {
    let mut rng = Rng::new(SEED ^ 0x0071);
    let start = Instant::now();

    let mut fixed: Vec<Vec<u8>> = vec![
        vec![],
        vec![0],
        vec![1],
        vec![2, 0],
        vec![2, 0, 2, 0, 2, 0],
        vec![2, 1],
        vec![2, 255],
        vec![2, 8, 0x05, 0xb4],
        vec![1; 64],
        vec![53, 1, 1, 55, 3, 1, 3, 6, 255],
        vec![0xff; 40],
    ];
    for _ in 0..3000 {
        fixed.push(rng.bytes_below(80));
    }

    for (i, data) in fixed.iter().enumerate() {
        for single in [&[0u8, 1u8][..], &[][..]] {
            for end in [None, Some(0u8), Some(255u8)] {
                let items = options::walk_tlv(data, single, end, |c, p| {
                    Item::uint("o", c as u32, p.iter().map(|b| *b as u64).sum())
                });
                // Every item consumes at least one octet, so a walk that fails
                // to advance shows up here rather than as a hang.
                assert!(
                    items.len() <= data.len(),
                    "walk_tlv emitted more items than octets (#{i}, seed {SEED:#x})"
                );
            }
        }

        let mut pkt = Packet::build_with(&[(ProtoId::Tcp, Some(data.clone()))]);
        exercise(&mut pkt, &format!("tcp options #{i}"));

        let mut pkt =
            Packet::build_with(&[(ProtoId::Ipv4, Some(data.clone())), (ProtoId::Udp, None)]);
        exercise(&mut pkt, &format!("ipv4 options #{i}"));

        let mut pkt = Packet::dissect(data.clone(), ProtoId::Dhcp);
        exercise(&mut pkt, &format!("dhcp options #{i}"));
    }

    assert!(
        start.elapsed() < BUDGET,
        "option walking did not finish promptly (seed {SEED:#x})"
    );
}

// ---- capture file readers ----

fn pcap_file(link: u32, records: &[Vec<u8>]) -> Vec<u8> {
    let mut v = Vec::new();
    pcap::write_header(&mut v, link, 65535);
    for (i, r) in records.iter().enumerate() {
        pcap::write_record(&mut v, i as u32 + 1, 0, r, r.len() as u32);
    }
    v
}

fn pcapng_file(link: u16, records: &[Vec<u8>]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&0x0a0d_0d0au32.to_le_bytes());
    v.extend_from_slice(&28u32.to_le_bytes());
    v.extend_from_slice(&0x1a2b_3c4du32.to_le_bytes());
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&(-1i64).to_le_bytes());
    v.extend_from_slice(&28u32.to_le_bytes());

    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(&20u32.to_le_bytes());
    v.extend_from_slice(&link.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&65535u32.to_le_bytes());
    v.extend_from_slice(&20u32.to_le_bytes());

    for r in records {
        let pad = (4 - r.len() % 4) % 4;
        let total = (32 + r.len() + pad) as u32;
        v.extend_from_slice(&6u32.to_le_bytes());
        v.extend_from_slice(&total.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&(r.len() as u32).to_le_bytes());
        v.extend_from_slice(&(r.len() as u32).to_le_bytes());
        v.extend_from_slice(r);
        v.extend(std::iter::repeat(0u8).take(pad));
        v.extend_from_slice(&total.to_le_bytes());
    }
    v
}

fn read_all_pcap(data: &[u8]) -> usize {
    let Ok(reader) = pcap::Reader::new(data) else {
        return 0;
    };
    let link = pcap::link_to_proto(reader.header.linktype);
    let nanos = reader.header.nanos;
    let mut n = 0;
    for rec in reader {
        n += 1;
        assert!(rec.data.len() <= data.len(), "record over-reads the file");
        assert_eq!(rec.data.len(), rec.caplen as usize);
        let _ = rec.time(nanos);
        let mut pkt = Packet::dissect(rec.data.to_vec(), link);
        exercise(&mut pkt, "pcap record");
    }
    assert!(
        n <= data.len() / 16 + 1,
        "more records than the file can hold"
    );
    n
}

fn read_all_pcapng(data: &[u8]) -> usize {
    let Ok(reader) = pcapng::Reader::new(data) else {
        return 0;
    };
    let link = pcap::link_to_proto(reader.header.linktype);
    let nanos = reader.header.nanos();
    let mut n = 0;
    for rec in reader {
        n += 1;
        assert!(rec.data.len() <= data.len(), "block over-reads the file");
        assert_eq!(rec.data.len(), rec.caplen as usize);
        let _ = rec.time(nanos);
        let mut pkt = Packet::dissect(rec.data.to_vec(), link);
        exercise(&mut pkt, "pcapng record");
    }
    assert!(
        n <= data.len() / 12 + 1,
        "more blocks than the file can hold"
    );
    n
}

#[test]
fn capture_readers_survive_corruption() {
    let frames: Vec<Vec<u8>> = valid_frames().into_iter().map(|(_, v)| v).collect();
    let pcap_ok = pcap_file(1, &frames);
    let png_ok = pcapng_file(1, &frames);

    assert_eq!(read_all_pcap(&pcap_ok), frames.len());
    assert_eq!(read_all_pcapng(&png_ok), frames.len());

    // Truncate at every offset.
    for cut in 0..=pcap_ok.len() {
        read_all_pcap(&pcap_ok[..cut]);
    }
    for cut in 0..=png_ok.len() {
        read_all_pcapng(&png_ok[..cut]);
    }

    // Corrupt single bytes with extreme values, concentrating on the length and
    // offset fields that drive the walk.
    let mut rng = Rng::new(SEED ^ 0xcafe);
    let start = Instant::now();
    for i in 0..6000 {
        let (base, is_png) = if i % 2 == 0 {
            (&pcap_ok, false)
        } else {
            (&png_ok, true)
        };
        let mut data = base.clone();
        for _ in 0..1 + rng.below(4) {
            let at = rng.below(data.len());
            data[at] = match rng.below(4) {
                0 => 0,
                1 => 1,
                2 => 0xff,
                _ => rng.byte(),
            };
        }
        if is_png {
            read_all_pcapng(&data);
        } else {
            read_all_pcap(&data);
        }
    }

    // Pure noise, including buffers that happen to start with a valid magic.
    for _ in 0..2000 {
        let mut data = rng.bytes_below(200);
        read_all_pcap(&data);
        read_all_pcapng(&data);
        if data.len() >= 4 {
            data[..4].copy_from_slice(&pcap::MAGIC_LE_USEC.to_le_bytes());
            read_all_pcap(&data);
            data[..4].copy_from_slice(&0x0a0d_0d0au32.to_le_bytes());
            read_all_pcapng(&data);
        }
    }

    assert!(
        start.elapsed() < BUDGET,
        "capture reading did not finish promptly (seed {SEED:#x})"
    );
}
