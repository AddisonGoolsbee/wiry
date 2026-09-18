//! Just enough BER to read the two ASN.1 protocols in scope.
//!
//! Encoding rules from ITU-T X.690 (02/2021) §8: identifier octets §8.1.2,
//! length octets §8.1.3, INTEGER §8.3, OBJECT IDENTIFIER §8.19. SNMP's message
//! shape is RFC 3416 §3 and LDAP's is RFC 4511 §4.1.1.
//!
//! This is a reader, not an ASN.1 compiler. It walks one level at a time and
//! hands back byte ranges; the two layers that use it name the fields their own
//! RFC gives, and anything deeper stays bytes. See DEVIATIONS T2.

pub const UNIVERSAL: u8 = 0;
pub const CONTEXT: u8 = 2;

pub const INTEGER: u32 = 0x02;
pub const OCTET_STRING: u32 = 0x04;
pub const NULL: u32 = 0x05;
pub const OID: u32 = 0x06;
pub const SEQUENCE: u32 = 0x10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub class: u8,
    pub constructed: bool,
    pub tag: u32,
    pub value: &'a [u8],
    /// Identifier, length and value together.
    pub total: usize,
}

/// `None` for a truncated, indefinite-length or high-tag-number encoding: all
/// three are outside what these two protocols use, and guessing is worse than
/// stopping.
pub fn read(data: &[u8]) -> Option<Tlv<'_>> {
    let id = *data.first()?;
    let tag = (id & 0x1f) as u32;
    if tag == 0x1f {
        return None;
    }
    let first = *data.get(1)?;
    let (len, hdr) = if first & 0x80 == 0 {
        (first as usize, 2usize)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let bytes = data.get(2..2 + n)?;
        (
            bytes.iter().fold(0usize, |a, b| (a << 8) | *b as usize),
            2 + n,
        )
    };
    let value = data.get(hdr..hdr.checked_add(len)?)?;
    Some(Tlv {
        class: id >> 6,
        constructed: id & 0x20 != 0,
        tag,
        value,
        total: hdr + len,
    })
}

/// The elements of one constructed value, bounded so a crafted region cannot
/// make the walk unbounded.
pub fn children(data: &[u8]) -> Vec<Tlv<'_>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < data.len() && out.len() < 256 {
        let Some(t) = read(&data[i..]) else { break };
        if t.total == 0 {
            break;
        }
        i += t.total;
        out.push(t);
    }
    out
}

/// X.690 §8.3: two's complement, big-endian. Read unsigned, which is what both
/// protocols' version, error and id fields are.
pub fn uint(v: &[u8]) -> u64 {
    v.iter().take(8).fold(0u64, |a, b| (a << 8) | *b as u64)
}

/// X.690 §8.19: every subidentifier is base-128 with a continuation bit, and
/// the *first* one packs both leading arcs as `arc1 * 40 + arc2`. Splitting the
/// first octet instead is wrong for any second arc above 39, which 2.999 is.
pub fn oid(v: &[u8]) -> String {
    let mut subs: Vec<u64> = Vec::new();
    let mut acc: u64 = 0;
    for b in v.iter().take(256) {
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

/// A readable form for whichever universal type turned up, so a varbind or an
/// LDAP attribute renders without the caller switching on the tag.
pub fn render(t: &Tlv<'_>) -> String {
    if t.class != UNIVERSAL {
        return match t.value.len() {
            0 => String::new(),
            1..=8 => uint(t.value).to_string(),
            _ => text(t.value),
        };
    }
    match t.tag {
        INTEGER => uint(t.value).to_string(),
        OID => oid(t.value),
        NULL => String::new(),
        OCTET_STRING => text(t.value),
        _ => text(t.value),
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

    #[test]
    fn truncated_and_indefinite_encodings_are_refused() {
        assert!(read(&[]).is_none());
        assert!(read(&[0x02]).is_none());
        assert!(read(&[0x02, 0x05, 0x00]).is_none());
        assert!(read(&[0x30, 0x80, 0x00, 0x00]).is_none());
        assert!(read(&[0x1f, 0x81, 0x01, 0x00]).is_none());
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

    #[test]
    fn junk_walks_without_panicking() {
        let junk: Vec<u8> = (0..=255u8).cycle().take(2048).collect();
        assert!(children(&junk).len() <= 256);
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
        assert_eq!(children(&bomb).len(), 256);
    }
}
