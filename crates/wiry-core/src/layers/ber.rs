//! The BER reader behind the Rust half of SNMP and LDAP: message framing in
//! the dissection loop, and the typed item lists `columns()` and `filter()`
//! read without Python.
//!
//! Encoding rules from ITU-T X.690 (02/2021) §8: identifier octets §8.1.2,
//! length octets §8.1.3, INTEGER §8.3, OBJECT IDENTIFIER §8.19.
//!
//! `pkt[SNMP]` and every other ASN.1 object tree is `python/wiry/asn1`, whose
//! contract (scapy's) is a Python object per field. This walks one level at a
//! time and never recurses, so nesting costs nothing however deep it goes,
//! and every walk over a constructed value stops at a cap.

use crate::options::ItemValue;

pub const UNIVERSAL: u8 = 0;
pub const APPLICATION: u8 = 1;
pub const CONTEXT: u8 = 2;

pub const BOOLEAN: u32 = 0x01;
pub const INTEGER: u32 = 0x02;
pub const OCTET_STRING: u32 = 0x04;
pub const NULL: u32 = 0x05;
pub const OID: u32 = 0x06;
pub const ENUMERATED: u32 = 0x0a;
pub const SEQUENCE: u32 = 0x10;

/// Elements `children` returns from one constructed value.
pub const MAX_CHILDREN: usize = 256;

/// Subidentifiers `oid` decodes; an OID is a handful of arcs.
pub const MAX_ARCS: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub class: u8,
    pub constructed: bool,
    pub tag: u32,
    pub value: &'a [u8],
    /// Identifier, length and value together.
    pub total: usize,
}

/// `None` for a truncated or indefinite-length encoding, a tag number past
/// 32 bits, or a length past 32 bits: guessing at any of them is worse than
/// stopping, and none fits in a datagram.
pub fn read(data: &[u8]) -> Option<Tlv<'_>> {
    let id = *data.first()?;
    let mut i = 1usize;
    let mut tag = (id & 0x1f) as u32;
    if tag == 0x1f {
        // X.690 §8.1.2.4: base-128, high bit set on all but the last octet.
        tag = 0;
        loop {
            let b = *data.get(i)?;
            i += 1;
            if tag >> 25 != 0 {
                return None;
            }
            tag = (tag << 7) | (b & 0x7f) as u32;
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    let first = *data.get(i)?;
    i += 1;
    let len = if first & 0x80 == 0 {
        first as usize
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let bytes = data.get(i..i + n)?;
        i += n;
        bytes.iter().fold(0usize, |a, b| (a << 8) | *b as usize)
    };
    let value = data.get(i..i.checked_add(len)?)?;
    Some(Tlv {
        class: id >> 6,
        constructed: id & 0x20 != 0,
        tag,
        value,
        total: i + len,
    })
}

/// The elements of one constructed value, up to the first that does not
/// parse and at most `MAX_CHILDREN` of them.
pub fn children(data: &[u8]) -> Vec<Tlv<'_>> {
    children_upto(data, MAX_CHILDREN)
}

/// `children` with the caller's own cap, for a list the caller must report
/// in full.
pub fn children_upto(data: &[u8], cap: usize) -> Vec<Tlv<'_>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < data.len() && out.len() < cap {
        let Some(t) = read(&data[i..]) else { break };
        i += t.total;
        out.push(t);
    }
    out
}

/// X.690 §8.3, unsigned. For fields a protocol defines as non-negative.
pub fn uint(v: &[u8]) -> u64 {
    v.iter().take(8).fold(0u64, |a, b| (a << 8) | *b as u64)
}

/// X.690 §8.3: two's complement, big-endian, as scapy decodes every INTEGER.
/// `None` when it does not fit in 64 bits either signed or unsigned.
pub fn int(v: &[u8]) -> Option<ItemValue> {
    let (&first, _) = v.split_first()?;
    if first & 0x80 == 0 {
        // A positive value may carry one leading zero octet, which is how a
        // Counter64 at 2^64 - 1 arrives in nine.
        let digits = if first == 0 { &v[1..] } else { v };
        if digits.len() > 8 {
            return None;
        }
        return Some(ItemValue::Uint(uint(digits)));
    }
    if v.len() > 8 {
        return None;
    }
    let n = v.iter().fold(-1i64, |a, b| (a << 8) | *b as i64);
    Some(ItemValue::Int(n))
}

/// X.690 §8.19: every subidentifier is base-128 with a continuation bit, and
/// the first packs the leading two arcs as `40 * X + Y`, where only X = 2 may
/// have Y >= 40. Splitting the first by 40 alone, as scapy does, reads 2.999
/// as 26.39.
pub fn oid(v: &[u8]) -> String {
    let mut subs: Vec<u64> = Vec::new();
    let mut acc: u64 = 0;
    for b in v {
        if subs.len() == MAX_ARCS {
            break;
        }
        acc = (acc << 7) | (*b & 0x7f) as u64;
        if *b & 0x80 == 0 {
            subs.push(acc);
            acc = 0;
        }
    }
    let Some((first, rest)) = subs.split_first() else {
        return String::new();
    };
    let (a, b) = if *first < 80 {
        (first / 40, first % 40)
    } else {
        (2, first - 80)
    };
    let mut out = format!("{a}.{b}");
    for s in rest {
        out.push('.');
        out.push_str(&s.to_string());
    }
    out
}

pub fn text(v: &[u8]) -> String {
    String::from_utf8_lossy(v).into_owned()
}

/// A readable form for whichever universal type turned up, for a caller that
/// wants one string per element.
pub fn render(t: &Tlv<'_>) -> String {
    if t.class != UNIVERSAL {
        return match t.value.len() {
            0 => String::new(),
            1..=8 => uint(t.value).to_string(),
            _ => text(t.value),
        };
    }
    match t.tag {
        INTEGER | ENUMERATED => match int(t.value) {
            Some(ItemValue::Int(n)) => n.to_string(),
            Some(ItemValue::Uint(n)) => n.to_string(),
            _ => text(t.value),
        },
        OID => oid(t.value),
        NULL => String::new(),
        _ => text(t.value),
    }
}

/// The value scapy's BER codec decodes an element to, as an item value: an
/// integer for INTEGER, BOOLEAN, ENUMERATED and RFC 2578 §7.1's application
/// counters, a dotted string for an OID or an IpAddress, nothing for NULL,
/// and the octets for anything else.
pub fn value(t: &Tlv<'_>) -> ItemValue {
    match (t.class, t.tag) {
        (UNIVERSAL, BOOLEAN | INTEGER | ENUMERATED) | (APPLICATION, 1 | 2 | 3 | 6) => {
            int(t.value).unwrap_or_else(|| ItemValue::Bytes(t.value.to_vec()))
        }
        (UNIVERSAL, OID) => ItemValue::Text(oid(t.value)),
        (UNIVERSAL, NULL) => ItemValue::Flag,
        (APPLICATION, 0) if t.value.len() == 4 => ItemValue::Text(format!(
            "{}.{}.{}.{}",
            t.value[0], t.value[1], t.value[2], t.value[3]
        )),
        _ => ItemValue::Bytes(t.value.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_form_length_reads_its_value() {
        let t = read(&[0x02, 0x01, 0x00]).unwrap();
        assert_eq!(t.tag, INTEGER);
        assert_eq!(t.value, &[0]);
        assert_eq!(t.total, 3);
    }

    #[test]
    fn a_long_form_length_reads_its_count_octets() {
        let mut v = vec![0x04, 0x81, 0x80];
        v.extend(std::iter::repeat_n(0x41u8, 128));
        let t = read(&v).unwrap();
        assert_eq!(t.value.len(), 128);
        assert_eq!(t.total, 131);
    }

    /// X.690 §8.1.2.4.3: [APPLICATION 201] is 0x5f 0x81 0x49.
    #[test]
    fn a_high_tag_number_reads_base_128() {
        let t = read(&[0x5f, 0x81, 0x49, 0x01, 0xff]).unwrap();
        assert_eq!((t.class, t.tag, t.value), (APPLICATION, 201, &[0xff][..]));
        assert_eq!(t.total, 5);
    }

    #[test]
    fn truncated_indefinite_and_oversized_encodings_are_refused() {
        assert!(read(&[]).is_none());
        assert!(read(&[0x02]).is_none());
        assert!(read(&[0x02, 0x05, 0x00]).is_none());
        assert!(read(&[0x30, 0x80, 0x00, 0x00]).is_none());
        assert!(read(&[0x1f, 0x81]).is_none());
        assert!(read(&[0x1f, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x00]).is_none());
        assert!(read(&[0x04, 0x85, 1, 0, 0, 0, 0]).is_none());
    }

    #[test]
    fn a_sequence_walks_to_its_elements() {
        // SEQUENCE { INTEGER 0, OCTET STRING "ab" }
        let msg = [0x30, 0x07, 0x02, 0x01, 0x00, 0x04, 0x02, b'a', b'b'];
        let seq = read(&msg).unwrap();
        assert!(seq.constructed);
        let kids = children(seq.value);
        assert_eq!(kids.len(), 2);
        assert_eq!(render(&kids[0]), "0");
        assert_eq!(render(&kids[1]), "ab");
    }

    /// X.690 §8.19.5 worked example: 2.999.3 encodes as 88 37 03.
    #[test]
    fn an_oid_unpacks_its_first_two_arcs_and_its_base_128_tail() {
        assert_eq!(oid(&[0x2b, 0x06, 0x01, 0x02, 0x01]), "1.3.6.1.2.1");
        assert_eq!(oid(&[0x88, 0x37, 0x03]), "2.999.3");
        assert_eq!(oid(&[]), "");
    }

    /// X.690 §8.3.3: the minimal two's complement octets of each value.
    #[test]
    fn an_integer_is_twos_complement() {
        assert_eq!(int(&[0x00]), Some(ItemValue::Uint(0)));
        assert_eq!(int(&[0x7f]), Some(ItemValue::Uint(127)));
        assert_eq!(int(&[0x00, 0x80]), Some(ItemValue::Uint(128)));
        assert_eq!(int(&[0x80]), Some(ItemValue::Int(-128)));
        assert_eq!(int(&[0xff, 0x7f]), Some(ItemValue::Int(-129)));
        assert_eq!(int(&[0xff]), Some(ItemValue::Int(-1)));
        let counter64_max = [0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(int(&counter64_max), Some(ItemValue::Uint(u64::MAX)));
        assert_eq!(int(&[0x01; 9]), None);
        assert_eq!(int(&[]), None);
    }

    /// RFC 2578 §7.1.5 IpAddress is [APPLICATION 0] of four octets.
    #[test]
    fn values_take_scapys_types() {
        let ip = read(&[0x40, 0x04, 10, 0, 0, 1]).unwrap();
        assert_eq!(value(&ip), ItemValue::Text("10.0.0.1".into()));
        let ticks = read(&[0x43, 0x02, 0x01, 0x00]).unwrap();
        assert_eq!(value(&ticks), ItemValue::Uint(256));
        let null = read(&[0x05, 0x00]).unwrap();
        assert_eq!(value(&null), ItemValue::Flag);
        let s = read(&[0x04, 0x01, 0x80]).unwrap();
        assert_eq!(value(&s), ItemValue::Bytes(vec![0x80]));
    }

    #[test]
    fn junk_walks_without_panicking() {
        let junk: Vec<u8> = (0..=255u8).cycle().take(2048).collect();
        assert!(children(&junk).len() <= MAX_CHILDREN);
        for i in 0..junk.len() {
            if let Some(t) = read(&junk[i..]) {
                let _ = (value(&t), render(&t));
            }
        }
    }

    /// Nothing here recurses, so nesting costs one `read` however deep it goes.
    /// A recursive walk would overflow the stack on this input.
    #[test]
    fn deep_nesting_costs_one_level() {
        let mut v = vec![0x02, 0x01, 0x01];
        for _ in 0..100_000 {
            let mut outer = vec![0x30, 0x84];
            outer.extend((v.len() as u32).to_be_bytes());
            outer.extend(&v);
            v = outer;
        }
        let t = read(&v).unwrap();
        assert!(t.constructed);
        assert_eq!(children(t.value).len(), 1);
    }

    #[test]
    fn a_sibling_bomb_stays_at_the_cap() {
        let bomb: Vec<u8> = std::iter::repeat_n([0x05u8, 0x00], 65_536)
            .flatten()
            .collect();
        assert_eq!(children(&bomb).len(), MAX_CHILDREN);
    }

    #[test]
    fn an_oid_bomb_stops_at_the_arc_cap() {
        let bomb = vec![0x01u8; 1 << 16];
        assert_eq!(oid(&bomb).split('.').count(), MAX_ARCS + 1);
    }
}
