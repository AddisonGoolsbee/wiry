//! Neighbor Discovery options, shared by the five RFC 4861 message layers.
//!
//! RFC 4861 §4.6: a one-octet type, a one-octet length **in units of eight
//! octets including the type and length octets**, then the option data. A
//! length octet of zero is invalid and ends the walk. Type values come from the
//! IANA "IPv6 Neighbor Discovery Option Formats" registry; §4.6.1 through
//! §4.6.4 and RFC 8106 §5 name the ones below.

use crate::layers::tlv::{self, TlvFmt};
use crate::options::{Item, ItemValue};

const FMT: TlvFmt = TlvFmt::new(8, 8).covering_header().scaled(8);

fn name(t: u32) -> Option<&'static str> {
    Some(match t {
        1 => "SrcLLAddr",
        2 => "DstLLAddr",
        3 => "Prefix",
        4 => "RedirectedHeader",
        5 => "MTU",
        24 => "RouteInfo",
        25 => "RDNSS",
        31 => "DNSSL",
        _ => return None,
    })
}

/// `at` is where the message body ends and the options begin, which differs per
/// message type (RFC 4861 §4.1 through §4.5).
pub fn options(hdr: &[u8], at: usize) -> Vec<Item> {
    let Some(region) = hdr.get(at..) else {
        return Vec::new();
    };
    tlv::walk(region, &FMT)
        .into_iter()
        .map(|r| match (name(r.tag), r.tag) {
            // §4.6.1: the link-layer address fills the option.
            (Some(n), 1 | 2) => Item::named(n, r.tag, ItemValue::Bytes(r.value.to_vec())),
            // §4.6.4: a 16-bit reserved field then the MTU.
            (Some(n), 5) if r.value.len() == 6 => Item::uint(n, r.tag, tlv::be(&r.value[2..])),
            (Some(n), _) => Item::bytes(n, r.tag, r.value),
            (None, _) => Item::unknown(r.tag, r.value),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4861 §4.6.1 source link-layer address, then §4.6.4 MTU 1500.
    const OPTS: &[u8] = &[
        1, 1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 5, 1, 0, 0, 0, 0, 0x05, 0xdc,
    ];

    #[test]
    fn both_options_decode_from_their_eight_octet_units() {
        let got = options(OPTS, 0);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].name, "SrcLLAddr");
        assert_eq!(
            got[0].value,
            ItemValue::Bytes(vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
        assert_eq!(got[1].name, "MTU");
        assert_eq!(got[1].value, ItemValue::Uint(1500));
    }

    #[test]
    fn an_offset_past_the_end_yields_nothing() {
        assert!(options(OPTS, 99).is_empty());
        assert!(options(&[], 0).is_empty());
    }

    #[test]
    fn truncation_stops_the_walk() {
        for n in 0..OPTS.len() {
            let got = options(&OPTS[..n], 0);
            assert!(got.len() <= 2, "n={n}");
        }
    }
}
