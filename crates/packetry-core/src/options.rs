use std::borrow::Cow;

#[derive(Clone, Debug, PartialEq)]
pub enum ItemValue {
    /// Present with no payload (NOP, SAckOK, End of List).
    Flag,
    Uint(u64),
    Pair(u64, u64),
    Bytes(Vec<u8>),
    Ipv4List(Vec<[u8; 4]>),
    Text(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Item {
    /// Conventional name where the code is known, otherwise a numeric label.
    pub name: Cow<'static, str>,
    pub code: u32,
    pub value: ItemValue,
}

impl Item {
    pub fn flag(name: &'static str, code: u32) -> Self {
        Self {
            name: Cow::Borrowed(name),
            code,
            value: ItemValue::Flag,
        }
    }
    pub fn uint(name: &'static str, code: u32, v: u64) -> Self {
        Self {
            name: Cow::Borrowed(name),
            code,
            value: ItemValue::Uint(v),
        }
    }
    pub fn pair(name: &'static str, code: u32, a: u64, b: u64) -> Self {
        Self {
            name: Cow::Borrowed(name),
            code,
            value: ItemValue::Pair(a, b),
        }
    }
    pub fn bytes(name: &'static str, code: u32, b: &[u8]) -> Self {
        Self {
            name: Cow::Borrowed(name),
            code,
            value: ItemValue::Bytes(b.to_vec()),
        }
    }
    pub fn unknown(code: u32, b: &[u8]) -> Self {
        Self {
            name: Cow::Owned(code.to_string()),
            code,
            value: ItemValue::Bytes(b.to_vec()),
        }
    }
}

pub(crate) fn be(b: &[u8]) -> u64 {
    let mut v = 0u64;
    for x in b.iter().take(8) {
        v = (v << 8) | *x as u64;
    }
    v
}

/// TCP/IPv4 length convention: the length octet counts the code and length
/// octets themselves, so the payload is `len - 2` bytes. DHCP (RFC 2132 §2)
/// counts only the option data and so does NOT use this function — using the
/// wrong convention silently mis-decodes every option. `layers/bootp.rs` has
/// its own walker.
///
/// `single_byte` names the codes that occupy one byte with no length octet.
/// Malformed input stops the walk: truncation is normal on a snaplen-clipped
/// capture, not an error.
pub fn walk_tlv<F>(
    data: &[u8],
    single_byte: &[u8],
    end_code: Option<u8>,
    mut decode: F,
) -> Vec<Item>
where
    F: FnMut(u8, &[u8]) -> Item,
{
    let mut out = Vec::new();
    let mut i = 0usize;
    // Bound the walk: a length octet of zero would otherwise spin forever.
    let mut guard = 0;
    while i < data.len() && guard < 512 {
        guard += 1;
        let code = data[i];
        if Some(code) == end_code {
            break;
        }
        if single_byte.contains(&code) {
            out.push(decode(code, &[]));
            i += 1;
            continue;
        }
        if i + 1 >= data.len() {
            break;
        }
        let len = data[i + 1] as usize;
        if len < 2 || i + len > data.len() {
            break;
        }
        out.push(decode(code, &data[i + 2..i + len]));
        i += len;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walks_a_simple_tlv_run() {
        let data = [2u8, 4, 0x05, 0xb4, 1, 3, 3, 7];
        let items = walk_tlv(&data, &[1], Some(0), |c, p| match c {
            1 => Item::flag("NOP", 1),
            _ => Item::uint("opt", c as u32, be(p)),
        });
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].value, ItemValue::Uint(0x05b4));
        assert_eq!(items[1].value, ItemValue::Flag);
        assert_eq!(items[2].value, ItemValue::Uint(7));
    }

    #[test]
    fn stops_at_end_code() {
        let data = [2u8, 4, 0x05, 0xb4, 0, 9, 9, 9];
        let items = walk_tlv(&data, &[1], Some(0), |c, p| {
            Item::uint("o", c as u32, be(p))
        });
        assert_eq!(items.len(), 1);
    }

    #[test]
    fn truncated_option_stops_cleanly() {
        let data = [2u8, 8, 0x05, 0xb4];
        let items = walk_tlv(&data, &[1], Some(0), |c, p| {
            Item::uint("o", c as u32, be(p))
        });
        assert!(items.is_empty());
    }

    #[test]
    fn zero_length_does_not_hang() {
        let data = [2u8, 0, 2, 0, 2, 0];
        let items = walk_tlv(&data, &[], Some(255), |c, p| {
            Item::uint("o", c as u32, be(p))
        });
        assert!(items.is_empty());
    }

    #[test]
    fn be_reads_widths() {
        assert_eq!(be(&[0x01]), 1);
        assert_eq!(be(&[0x05, 0xb4]), 1460);
        assert_eq!(be(&[0, 0, 0, 1]), 1);
        assert_eq!(be(&[]), 0);
    }
}
