//! Human-readable rendering of field values and packet summaries.

use crate::field::FieldValue;
use crate::packet::Packet;

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

pub fn render_flags(bits: u64, names: &[&str]) -> String {
    let mut s = String::new();
    for (i, n) in names.iter().enumerate() {
        if bits & (1 << i) != 0 {
            s.push_str(n);
        }
    }
    s
}

/// RFC 5952 textual form: lowercase hex, longest run of zero groups elided once.
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
    // A single zero group is written out rather than elided (RFC 5952 §4.2.2).
    if best_len < 2 {
        return g
            .iter()
            .map(|x| format!("{x:x}"))
            .collect::<Vec<_>>()
            .join(":");
    }
    let head: Vec<String> = g[..best_start].iter().map(|x| format!("{x:x}")).collect();
    let tail: Vec<String> = g[best_start + best_len..]
        .iter()
        .map(|x| format!("{x:x}"))
        .collect();
    format!("{}::{}", head.join(":"), tail.join(":"))
}

/// One-line description, in the style of a packet summary.
pub fn summary(pkt: &Packet) -> String {
    pkt.layers()
        .iter()
        .map(|s| s.proto.name().to_string())
        .collect::<Vec<_>>()
        .join(" / ")
}

/// Multi-line field dump.
pub fn show(pkt: &Packet) -> String {
    let mut out = String::new();
    for (i, s) in pkt.layers().iter().enumerate() {
        let d = crate::proto::desc(s.proto);
        out.push_str(&format!("###[ {} ]###\n", d.name));
        for f in d.fields {
            let v = pkt.get_desc(i, f);
            if let FieldValue::Bytes(ref b) = v {
                if b.is_empty() {
                    continue;
                }
            }
            out.push_str(&format!("  {:<10}= {}\n", f.name, render_value(&v)));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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
        b[3] = 0; // group 1 becomes zero, a lone run
        let s = render_ipv6(&b);
        assert!(!s.contains("::"), "single zero group should not elide: {s}");
    }

    #[test]
    fn flags_render_in_bit_order() {
        let names: &[&str] = &["F", "S", "R", "P", "A"];
        // SYN|ACK = bit1 | bit4
        assert_eq!(render_flags(0b1_0010, names), "SA");
    }
}
