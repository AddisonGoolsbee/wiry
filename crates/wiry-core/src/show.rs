use crate::field::{self, FieldValue};
use crate::packet::{LayerSpan, Packet};
use crate::proto::{self, ProtoId};

pub fn render_value(v: &FieldValue) -> String {
    match v {
        FieldValue::Uint(n) => n.to_string(),
        FieldValue::Ipv4(b) => format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]),
        FieldValue::Ipv6(b) => render_ipv6(b),
        FieldValue::Mac(b) => format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        ),
        FieldValue::Flags { bits, names } => render_flags(*bits, names),
        FieldValue::Bytes(b) => format!("{b:?}"),
    }
}

/// Names of more than a letter would run together, so a field carrying any of
/// those separates them with `+`.
fn separator(names: &[&str]) -> &'static str {
    if names.iter().any(|n| n.chars().count() > 1) {
        "+"
    } else {
        ""
    }
}

pub fn render_flags(bits: u64, names: &[&str]) -> String {
    names
        .iter()
        .enumerate()
        // A caller-declared `FlagsField` may name more bits than a `u64` holds;
        // shifting by such an index panics in debug and wraps modulo 64 in
        // release, printing flags that are not set.
        .filter(|(i, n)| !n.is_empty() && *i < 64 && bits & (1u64 << i) != 0)
        .map(|(_, n)| *n)
        .collect::<Vec<_>>()
        .join(separator(names))
}

/// The inverse of `render_flags`. A name counts only where it appears whole:
/// matching by substring also sets every bit whose name is contained in
/// another, so the integer read back would not be the integer on the wire.
///
/// `None` where a token names no flag of this field. Reading a typo as zero
/// builds a packet the caller did not ask for and says nothing about it.
pub fn flags_from(text: &str, names: &[&str]) -> Option<u64> {
    let bit = |tok: &str| {
        if tok.is_empty() {
            // The empty rendering of no flags at all, or a stray separator.
            return Some(0);
        }
        names
            .iter()
            .position(|n| !n.is_empty() && *n == tok)
            // A name past bit 63 names a bit the field cannot hold.
            .filter(|i| *i < 64)
            .map(|i| 1u64 << i)
    };
    let mut v = 0u64;
    if separator(names).is_empty() {
        let mut buf = [0u8; 4];
        for c in text.chars() {
            v |= bit(c.encode_utf8(&mut buf))?;
        }
    } else {
        for tok in text.split('+') {
            v |= bit(tok)?;
        }
    }
    Some(v)
}

/// RFC 5952 form.
pub fn render_ipv6(b: &[u8; 16]) -> String {
    let g: Vec<u16> = (0..8)
        .map(|i| u16::from_be_bytes([b[i * 2], b[i * 2 + 1]]))
        .collect();
    let (mut best_start, mut best_len) = (usize::MAX, 0usize);
    let (mut cur_start, mut cur_len) = (usize::MAX, 0usize);
    for (i, &x) in g.iter().enumerate() {
        if x == 0 {
            if cur_len == 0 {
                cur_start = i;
            }
            cur_len += 1;
            if cur_len > best_len {
                best_start = cur_start;
                best_len = cur_len;
            }
        } else {
            cur_len = 0;
        }
    }
    let hex = |gs: &[u16]| {
        gs.iter()
            .map(|x| format!("{x:x}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    // RFC 5952 §4.2.2: a lone zero group is written out, not elided.
    if best_len < 2 {
        return hex(&g);
    }
    format!(
        "{}::{}",
        hex(&g[..best_start]),
        hex(&g[best_start + best_len..])
    )
}

pub fn summary_of(spans: &[LayerSpan]) -> String {
    spans
        .iter()
        .map(|s| s.proto.name())
        .collect::<Vec<_>>()
        .join(" / ")
}

pub fn summary(pkt: &Packet) -> String {
    summary_of(pkt.layers())
}

fn read(buf: &[u8], spans: &[LayerSpan], id: ProtoId, name: &str) -> Option<FieldValue> {
    let hdr = spans.iter().find(|s| s.proto == id)?.header(buf);
    Some(field::decode(hdr, proto::active_field_of(id, hdr, name)?))
}

fn uint(v: Option<FieldValue>) -> Option<u64> {
    v.and_then(|v| v.as_uint())
}

/// The flow a packet belongs to. The key groups; it does not reassemble.
pub fn session_key(buf: &[u8], spans: &[LayerSpan]) -> String {
    let get = |id, name| read(buf, spans, id, name);
    let has = |id| spans.iter().any(|s| s.proto == id);

    let net = match (get(ProtoId::Ipv4, "src"), get(ProtoId::Ipv4, "dst")) {
        (Some(a), Some(b)) => Some((false, render_value(&a), render_value(&b))),
        _ => match (get(ProtoId::Ipv6, "src"), get(ProtoId::Ipv6, "dst")) {
            (Some(a), Some(b)) => Some((true, render_value(&a), render_value(&b))),
            _ => None,
        },
    };

    if let Some((v6, src, dst)) = net {
        for (id, name) in [(ProtoId::Tcp, "TCP"), (ProtoId::Udp, "UDP")] {
            if has(id) {
                let sp = uint(get(id, "sport")).unwrap_or(0);
                let dp = uint(get(id, "dport")).unwrap_or(0);
                return format!("{name} {src}:{sp} > {dst}:{dp}");
            }
        }
        if v6 {
            let nh = uint(get(ProtoId::Ipv6, "nh")).unwrap_or(0);
            return format!("IPv6 {src} > {dst} nh={nh}");
        }
        if has(ProtoId::Icmp) {
            let t = uint(get(ProtoId::Icmp, "type")).unwrap_or(0);
            let c = uint(get(ProtoId::Icmp, "code")).unwrap_or(0);
            // `id` exists only for the types RFC 792 gives it one.
            return match uint(get(ProtoId::Icmp, "id")) {
                Some(i) => format!("ICMP {src} > {dst} type={t} code={c} id=0x{i:x}"),
                None => format!("ICMP {src} > {dst} type={t} code={c}"),
            };
        }
        let p = uint(get(ProtoId::Ipv4, "proto")).unwrap_or(0);
        return format!("IP {src} > {dst} proto={p}");
    }

    if let (Some(a), Some(b)) = (get(ProtoId::Arp, "psrc"), get(ProtoId::Arp, "pdst")) {
        return format!("ARP {} > {}", render_value(&a), render_value(&b));
    }
    match uint(get(ProtoId::Ether, "type")) {
        Some(t) => format!("Ethernet type={t:04x}"),
        None => "Other".to_string(),
    }
}

pub fn show(pkt: &Packet) -> String {
    let mut out = String::new();
    for (i, s) in pkt.layers().iter().enumerate() {
        let d = crate::proto::desc(s.proto);
        out.push_str(&format!("###[ {} ]###\n", d.name));
        for f in crate::proto::active_fields(s.proto, pkt.header(i)) {
            let v = pkt.get_desc(i, f);
            if let FieldValue::Bytes(ref b) = v {
                if b.is_empty() {
                    continue;
                }
            }
            out.push_str(&format!("  {:<11}= {}\n", f.name, render_value(&v)));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Packet;

    /// IEEE 802.3 clause 3 framing over RFC 791 §3.1 and RFC 9293 §3.1, built
    /// by hand so the offsets are the RFC's and not another library's.
    fn frame(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0x11; 6];
        v.extend_from_slice(&[0x22; 6]);
        v.extend_from_slice(&ethertype.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    fn ipv4(proto: u8, rest: &[u8]) -> Vec<u8> {
        let total = 20 + rest.len();
        let mut v = vec![0x45, 0x00];
        v.extend_from_slice(&(total as u16).to_be_bytes());
        v.extend_from_slice(&[0, 1, 0, 0, 64, proto, 0, 0]);
        v.extend_from_slice(&[10, 0, 0, 1]);
        v.extend_from_slice(&[10, 0, 0, 2]);
        v.extend_from_slice(rest);
        v
    }

    fn key_of(buf: Vec<u8>) -> String {
        let pkt = Packet::dissect(buf, ProtoId::Ether);
        session_key(pkt.raw_bytes(), pkt.layers())
    }

    #[test]
    fn tcp_and_udp_flows_key_on_the_five_tuple() {
        let tcp = [
            0x1f, 0x90, 0x00, 0x50, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0x20, 0x00, 0, 0, 0, 0,
        ];
        assert_eq!(
            key_of(frame(0x0800, &ipv4(6, &tcp))),
            "TCP 10.0.0.1:8080 > 10.0.0.2:80"
        );
        let udp = [0x00, 0x35, 0x14, 0xe9, 0x00, 0x08, 0, 0];
        assert_eq!(
            key_of(frame(0x0800, &ipv4(17, &udp))),
            "UDP 10.0.0.1:53 > 10.0.0.2:5353"
        );
    }

    #[test]
    fn an_echo_carries_its_identifier_and_another_message_does_not() {
        assert_eq!(
            key_of(frame(0x0800, &ipv4(1, &ICMP_ECHO))),
            "ICMP 10.0.0.1 > 10.0.0.2 type=8 code=0 id=0x1234"
        );
        let unreach = [3u8, 1, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            key_of(frame(0x0800, &ipv4(1, &unreach))),
            "ICMP 10.0.0.1 > 10.0.0.2 type=3 code=1"
        );
    }

    /// RFC 792 Echo, identifier 0x1234, sequence 1.
    const ICMP_ECHO: [u8; 12] = [
        0x08, 0x00, 0x48, 0x2d, 0x12, 0x34, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef,
    ];

    #[test]
    fn a_protocol_with_no_ports_keys_on_the_addresses() {
        assert_eq!(
            key_of(frame(0x0800, &ipv4(47, &[0u8; 4]))),
            "IP 10.0.0.1 > 10.0.0.2 proto=47"
        );
    }

    #[test]
    fn arp_and_bare_ethernet_and_neither() {
        // RFC 826 "Packet format": who-has 10.0.0.2, tell 10.0.0.1.
        let arp = [
            0, 1, 8, 0, 6, 4, 0, 1, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 10, 0, 0, 1, 0, 0, 0, 0, 0,
            0, 10, 0, 0, 2,
        ];
        assert_eq!(key_of(frame(0x0806, &arp)), "ARP 10.0.0.1 > 10.0.0.2");
        assert_eq!(key_of(frame(0x9000, &[])), "Ethernet type=9000");
        assert_eq!(
            session_key(&[], &[]),
            "Other",
            "no layers at all is a flow of its own, not a panic"
        );
    }

    #[test]
    fn a_truncated_frame_keys_on_what_it_has() {
        for n in 0..46 {
            let tcp = [0x1f, 0x90, 0x00, 0x50, 0, 0, 0, 1];
            let full = frame(0x0800, &ipv4(6, &tcp));
            let key = key_of(full[..n.min(full.len())].to_vec());
            assert!(!key.is_empty(), "truncated to {n} produced no key");
        }
    }

    #[test]
    fn a_summary_over_spans_matches_the_one_over_a_packet() {
        let pkt = Packet::dissect(frame(0x0800, &ipv4(17, &[0u8; 8])), ProtoId::Ether);
        assert_eq!(summary_of(pkt.layers()), summary(&pkt));
        assert_eq!(summary(&pkt), "Ether / IP / UDP");
    }

    #[test]
    fn ipv6_elides_longest_zero_run() {
        let mut b = [0u8; 16];
        b[0] = 0x20;
        b[1] = 0x01;
        b[15] = 1;
        assert_eq!(render_ipv6(&b), "2001::1");
    }

    #[test]
    fn ipv6_all_zeros_is_double_colon() {
        assert_eq!(render_ipv6(&[0u8; 16]), "::");
    }

    #[test]
    fn ipv6_single_zero_group_not_elided() {
        let mut b = [0u8; 16];
        for i in 0..8 {
            b[i * 2 + 1] = (i + 1) as u8;
        }
        b[3] = 0;
        let s = render_ipv6(&b);
        assert!(!s.contains("::"), "single zero group should not elide: {s}");
    }

    #[test]
    fn flags_render_in_bit_order() {
        let names: &[&str] = &["F", "S", "R", "P", "A"];
        assert_eq!(render_flags(0b1_0010, names), "SA");
    }

    #[test]
    fn multi_letter_flag_names_are_separated() {
        let names: &[&str] = &["MF", "DF", "evil"];
        assert_eq!(render_flags(0b011, names), "MF+DF");
        assert_eq!(render_flags(0b010, names), "DF");
    }

    #[test]
    fn more_names_than_a_u64_has_bits_renders_only_the_bits_that_exist() {
        let owned: Vec<String> = (0..100).map(|i| format!("n{i}")).collect();
        let names: Vec<&str> = owned.iter().map(String::as_str).collect();
        assert_eq!(render_flags(1, &names), "n0");
        assert_eq!(render_flags(u64::MAX, &names).matches('+').count(), 63);
        assert!(!render_flags(u64::MAX, &names).contains("n64"));
    }

    #[test]
    fn a_name_contained_in_another_does_not_set_its_bit() {
        let names: &[&str] = &["a", "ab", "b"];
        assert_eq!(flags_from("a", names), Some(0b001));
        assert_eq!(flags_from("ab", names), Some(0b010));
        assert_eq!(flags_from("b", names), Some(0b100));
        assert_eq!(flags_from("a+b", names), Some(0b101));
    }

    #[test]
    fn every_flag_string_round_trips() {
        for names in [
            &["F", "S", "R", "P", "A"][..],
            &["MF", "DF", "evil"][..],
            &["a", "ab", "b"][..],
            &["", "", "B"][..],
        ] {
            for bits in 0..(1u64 << names.len()) {
                let expect = (0..names.len())
                    .filter(|i| !names[*i].is_empty() && bits & (1 << i) != 0)
                    .fold(0u64, |a, i| a | 1 << i);
                assert_eq!(flags_from(&render_flags(bits, names), names), Some(expect));
            }
        }
    }

    #[test]
    fn an_unknown_flag_name_is_refused_not_read_as_zero() {
        let owned: Vec<String> = (0..100).map(|i| format!("n{i}")).collect();
        let names: Vec<&str> = owned.iter().map(String::as_str).collect();
        assert_eq!(
            flags_from("n64", &names),
            None,
            "named, but past the last bit a u64 has"
        );
        assert_eq!(flags_from("nope", &names), None);
        assert_eq!(flags_from("", &names), Some(0));
        assert_eq!(flags_from("zz", &["F", "S", "A"]), None);
        assert_eq!(flags_from("SAzz", &["F", "S", "A"]), None);
    }
}
