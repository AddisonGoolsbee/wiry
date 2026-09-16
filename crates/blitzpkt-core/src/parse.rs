//! Parsing of human-written field values: addresses and flag strings.
//! Kept in the core so it is testable without Python in the loop.

use crate::field::{FieldDesc, FieldKind};

pub fn ipv4(s: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut n = 0;
    for part in s.split('.') {
        if n == 4 || part.is_empty() || part.len() > 3 {
            return None;
        }
        out[n] = part.parse::<u8>().ok()?;
        n += 1;
    }
    if n == 4 {
        Some(out)
    } else {
        None
    }
}

pub fn mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut n = 0;
    for part in s.split([':', '-']) {
        if n == 6 || part.len() != 2 {
            return None;
        }
        out[n] = u8::from_str_radix(part, 16).ok()?;
        n += 1;
    }
    if n == 6 {
        Some(out)
    } else {
        None
    }
}

/// IPv6 textual form including `::` elision and trailing IPv4 form.
pub fn ipv6(s: &str) -> Option<[u8; 16]> {
    if s == "::" {
        return Some([0u8; 16]);
    }
    let (head_s, tail_s) = match s.split_once("::") {
        Some((a, b)) => (a, Some(b)),
        None => (s, None),
    };

    fn groups(part: &str) -> Option<Vec<u16>> {
        if part.is_empty() {
            return Some(Vec::new());
        }
        let mut out = Vec::new();
        let chunks: Vec<&str> = part.split(':').collect();
        for (i, c) in chunks.iter().enumerate() {
            // A trailing dotted-quad stands for the last two groups.
            if i == chunks.len() - 1 && c.contains('.') {
                let v4 = ipv4(c)?;
                out.push(u16::from_be_bytes([v4[0], v4[1]]));
                out.push(u16::from_be_bytes([v4[2], v4[3]]));
                continue;
            }
            if c.is_empty() || c.len() > 4 {
                return None;
            }
            out.push(u16::from_str_radix(c, 16).ok()?);
        }
        Some(out)
    }

    let head = groups(head_s)?;
    let tail = match tail_s {
        Some(t) => groups(t)?,
        None => Vec::new(),
    };

    if tail_s.is_none() {
        if head.len() != 8 {
            return None;
        }
    } else if head.len() + tail.len() > 7 {
        // `::` must stand for at least one zero group.
        return None;
    }

    let mut g = [0u16; 8];
    g[..head.len()].copy_from_slice(&head);
    let start = 8 - tail.len();
    g[start..].copy_from_slice(&tail);

    let mut out = [0u8; 16];
    for (i, v) in g.iter().enumerate() {
        out[i * 2..i * 2 + 2].copy_from_slice(&v.to_be_bytes());
    }
    Some(out)
}

/// Flag letters (e.g. TCP "SA") to their bit value.
pub fn flags(s: &str, names: &[&str]) -> u64 {
    let mut v = 0u64;
    for (i, n) in names.iter().enumerate() {
        if s.contains(n) {
            v |= 1 << i;
        }
    }
    v
}

/// Convert a textual value into the raw bits for a field.
pub fn value_for(f: &FieldDesc, s: &str) -> Option<ValueBits> {
    match f.kind {
        FieldKind::Ipv4Addr => ipv4(s).map(|b| ValueBits::Bytes(b.to_vec())),
        FieldKind::Ipv6Addr => ipv6(s).map(|b| ValueBits::Bytes(b.to_vec())),
        FieldKind::MacAddr => mac(s).map(|b| ValueBits::Bytes(b.to_vec())),
        FieldKind::Flags => Some(ValueBits::Uint(flags(s, f.flags))),
        FieldKind::Uint => s.parse::<u64>().ok().map(ValueBits::Uint),
        FieldKind::Bytes | FieldKind::VarBytes => Some(ValueBits::Bytes(s.as_bytes().to_vec())),
    }
}

pub enum ValueBits {
    Uint(u64),
    Bytes(Vec<u8>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_parses_and_rejects() {
        assert_eq!(ipv4("10.0.0.1"), Some([10, 0, 0, 1]));
        assert_eq!(ipv4("255.255.255.255"), Some([255, 255, 255, 255]));
        assert_eq!(ipv4("10.0.0"), None);
        assert_eq!(ipv4("10.0.0.256"), None);
        assert_eq!(ipv4("10.0.0.1.2"), None);
        assert_eq!(ipv4(""), None);
    }

    #[test]
    fn mac_parses_both_separators() {
        assert_eq!(
            mac("00:11:22:33:44:55"),
            Some([0, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
        assert_eq!(
            mac("00-11-22-33-44-55"),
            Some([0, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
        assert_eq!(mac("00:11:22:33:44"), None);
        assert_eq!(mac("zz:11:22:33:44:55"), None);
    }

    #[test]
    fn ipv6_roundtrips_through_render() {
        use crate::show::render_ipv6;
        for s in ["2001:db8::1", "::", "::1", "fe80::200:5eff:fe00:5213"] {
            let b = ipv6(s).unwrap_or_else(|| panic!("failed to parse {s}"));
            assert_eq!(render_ipv6(&b), s, "roundtrip mismatch for {s}");
        }
    }

    #[test]
    fn ipv6_full_form_and_embedded_v4() {
        assert_eq!(ipv6("0:0:0:0:0:0:0:1"), ipv6("::1"));
        let b = ipv6("::ffff:192.0.2.1").unwrap();
        assert_eq!(&b[12..], &[192, 0, 2, 1]);
    }

    #[test]
    fn ipv6_rejects_malformed() {
        assert_eq!(ipv6("2001:db8"), None);
        assert_eq!(ipv6("gggg::1"), None);
        assert_eq!(ipv6("1:2:3:4:5:6:7:8:9"), None);
    }

    #[test]
    fn flag_letters_map_to_bits() {
        let names: &[&str] = &["F", "S", "R", "P", "A", "U", "E", "C"];
        assert_eq!(flags("S", names), 0b10);
        assert_eq!(flags("SA", names), 0b1_0010);
        assert_eq!(flags("", names), 0);
    }
}
