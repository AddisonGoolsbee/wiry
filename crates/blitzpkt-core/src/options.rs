//! Structured sub-elements of a header: TCP and IPv4 options, DHCP options.
//!
//! These are the variable-length, type-length-value regions that a flat field
//! table cannot describe. Each protocol that has one supplies a parser; the
//! result is a uniform list so the Python facade can render them the same way.

use std::borrow::Cow;

/// The payload of one option, shaped to match how the option is normally read.
#[derive(Clone, Debug, PartialEq)]
pub enum ItemValue {
    /// Present with no payload (NOP, SAckOK, End of List).
    Flag,
    Uint(u64),
    /// Two values in one option, such as a TCP timestamp.
    Pair(u64, u64),
    Bytes(Vec<u8>),
    /// A list of addresses, as several DHCP options carry.
    Ipv4List(Vec<[u8; 4]>),
    Text(String),
}

/// One parsed option.
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
    /// An option whose code has no conventional name.
    pub fn unknown(code: u32, b: &[u8]) -> Self {
        Self {
            name: Cow::Owned(code.to_string()),
            code,
            value: ItemValue::Bytes(b.to_vec()),
        }
    }
}

/// Read a big-endian unsigned integer of 1, 2, 4 or 8 bytes.
pub(crate) fn be(b: &[u8]) -> u64 {
    let mut v = 0u64;
    for x in b.iter().take(8) {
        v = (v << 8) | *x as u64;
    }
    v
}

/// Walk a type-length-value region.
///
/// IMPORTANT — length conventions differ between protocols, and getting this
/// wrong silently mis-decodes every option. This function implements the
/// TCP/IPv4 convention, where the length octet counts the code and length
/// octets themselves, so the payload is `len - 2` bytes.
///
/// DHCP (RFC 2132 s2) uses the other convention: its length octet counts only
/// the option data, so the total advance is `len + 2`. DHCP therefore does NOT
/// use this function; `layers/bootp.rs` has its own walker. Check which
/// convention your RFC specifies before reaching for this.
///
/// `single_byte` names the codes that occupy one byte with no length octet
/// (TCP/IPv4 End-of-List and NOP, DHCP pad and end). `emit_end` decides whether
/// the terminating code is reported or swallowed.
///
/// Returns the parsed items. Malformed input stops the walk rather than
/// panicking: a truncated option is the normal case on a snaplen-clipped
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
        // Every other option is code, length, then length-2 bytes of payload,
        // where the length octet counts the code and length octets themselves.
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
        // code 2 len 4 payload 0x05b4, then a single-byte NOP (1), then code 3 len 3.
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
        // Claims length 8 but only 4 bytes remain.
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
