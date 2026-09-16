//! Field model: a protocol header is described by a static table of field
//! descriptors, and values are decoded lazily from the still-borrowed packet
//! bytes. Nothing is materialised until somebody asks for it.

/// How a field's bits are interpreted once extracted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldKind {
    /// Unsigned integer, big-endian, `bit_len` wide (1..=64).
    Uint,
    /// 4-byte IPv4 address, rendered as dotted quad.
    Ipv4Addr,
    /// 16-byte IPv6 address, rendered in RFC 5952 form.
    Ipv6Addr,
    /// 6-byte MAC address, rendered as colon-separated hex.
    MacAddr,
    /// Bitfield rendered as a flag string (e.g. TCP "SA").
    Flags,
    /// Raw bytes of fixed length.
    Bytes,
    /// Raw bytes running to the end of the header (options, padding).
    VarBytes,
}

/// A single named field within a protocol header.
#[derive(Clone, Copy, Debug)]
pub struct FieldDesc {
    pub name: &'static str,
    /// Bit offset from the first byte of this layer's header.
    pub bit_off: u16,
    /// Width in bits. Ignored for `VarBytes`.
    pub bit_len: u16,
    pub kind: FieldKind,
    /// Value used when the field is not supplied during construction.
    pub default: u64,
    /// Flag names, least-significant bit first. Only used by `FieldKind::Flags`.
    pub flags: &'static [&'static str],
    /// True when the engine recomputes this field during serialisation
    /// (checksums, lengths) unless the user pinned it explicitly.
    pub computed: bool,
}

impl FieldDesc {
    pub const fn uint(name: &'static str, bit_off: u16, bit_len: u16, default: u64) -> Self {
        Self { name, bit_off, bit_len, kind: FieldKind::Uint, default, flags: &[], computed: false }
    }
    pub const fn computed_uint(name: &'static str, bit_off: u16, bit_len: u16) -> Self {
        Self { name, bit_off, bit_len, kind: FieldKind::Uint, default: 0, flags: &[], computed: true }
    }
    pub const fn ipv4(name: &'static str, bit_off: u16, default: u64) -> Self {
        Self { name, bit_off, bit_len: 32, kind: FieldKind::Ipv4Addr, default, flags: &[], computed: false }
    }
    pub const fn ipv6(name: &'static str, bit_off: u16) -> Self {
        Self { name, bit_off, bit_len: 128, kind: FieldKind::Ipv6Addr, default: 0, flags: &[], computed: false }
    }
    pub const fn mac(name: &'static str, bit_off: u16) -> Self {
        Self { name, bit_off, bit_len: 48, kind: FieldKind::MacAddr, default: 0, flags: &[], computed: false }
    }
    pub const fn flags(
        name: &'static str, bit_off: u16, bit_len: u16, names: &'static [&'static str],
    ) -> Self {
        Self { name, bit_off, bit_len, kind: FieldKind::Flags, default: 0, flags: names, computed: false }
    }
    pub const fn var_bytes(name: &'static str, bit_off: u16) -> Self {
        Self { name, bit_off, bit_len: 0, kind: FieldKind::VarBytes, default: 0, flags: &[], computed: false }
    }
    pub const fn bytes(name: &'static str, bit_off: u16, bit_len: u16) -> Self {
        Self { name, bit_off, bit_len, kind: FieldKind::Bytes, default: 0, flags: &[], computed: false }
    }
}

/// A decoded field value. Crosses to Python at most once per field actually read.
#[derive(Clone, Debug, PartialEq)]
pub enum FieldValue {
    Uint(u64),
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
    Mac([u8; 6]),
    Flags { bits: u64, names: &'static [&'static str] },
    Bytes(Vec<u8>),
}

impl FieldValue {
    pub fn as_uint(&self) -> Option<u64> {
        match self {
            FieldValue::Uint(v) | FieldValue::Flags { bits: v, .. } => Some(*v),
            FieldValue::Ipv4(b) => Some(u32::from_be_bytes(*b) as u64),
            FieldValue::Mac(b) => {
                let mut v = 0u64;
                for x in b { v = (v << 8) | *x as u64; }
                Some(v)
            }
            _ => None,
        }
    }
}

/// Read `bit_len` bits starting at `bit_off` from `buf`, big-endian.
/// Returns 0 when the read would run past the end of the buffer.
#[inline]
pub fn read_bits(buf: &[u8], bit_off: u16, bit_len: u16) -> u64 {
    debug_assert!(bit_len <= 64);
    let start = bit_off as usize;
    let end = start + bit_len as usize;
    if bit_len == 0 || end > buf.len() * 8 {
        return 0;
    }
    // Fast path: byte-aligned and a whole number of bytes, up to 8 bytes.
    if start % 8 == 0 && bit_len % 8 == 0 && bit_len <= 64 {
        let b0 = start / 8;
        let n = (bit_len / 8) as usize;
        let mut v = 0u64;
        for i in 0..n {
            v = (v << 8) | buf[b0 + i] as u64;
        }
        return v;
    }
    // General path: walk bit by bit. Only used for sub-byte fields.
    let mut v = 0u64;
    for i in start..end {
        let byte = buf[i / 8];
        let bit = (byte >> (7 - (i % 8))) & 1;
        v = (v << 1) | bit as u64;
    }
    v
}

/// Write `bit_len` bits of `val` at `bit_off` into `buf`, big-endian.
#[inline]
pub fn write_bits(buf: &mut [u8], bit_off: u16, bit_len: u16, val: u64) {
    let start = bit_off as usize;
    let end = start + bit_len as usize;
    if bit_len == 0 || end > buf.len() * 8 {
        return;
    }
    if start % 8 == 0 && bit_len % 8 == 0 && bit_len <= 64 {
        let b0 = start / 8;
        let n = (bit_len / 8) as usize;
        for i in 0..n {
            let shift = 8 * (n - 1 - i);
            buf[b0 + i] = ((val >> shift) & 0xff) as u8;
        }
        return;
    }
    for (k, i) in (start..end).enumerate() {
        let bit = ((val >> (bit_len as usize - 1 - k)) & 1) as u8;
        let mask = 1u8 << (7 - (i % 8));
        if bit == 1 {
            buf[i / 8] |= mask;
        } else {
            buf[i / 8] &= !mask;
        }
    }
}

/// Decode one field from a layer's header bytes.
pub fn decode(hdr: &[u8], f: &FieldDesc) -> FieldValue {
    match f.kind {
        FieldKind::Uint => FieldValue::Uint(read_bits(hdr, f.bit_off, f.bit_len)),
        FieldKind::Flags => {
            FieldValue::Flags { bits: read_bits(hdr, f.bit_off, f.bit_len), names: f.flags }
        }
        FieldKind::Ipv4Addr => {
            let b = (f.bit_off / 8) as usize;
            let mut out = [0u8; 4];
            if b + 4 <= hdr.len() { out.copy_from_slice(&hdr[b..b + 4]); }
            FieldValue::Ipv4(out)
        }
        FieldKind::Ipv6Addr => {
            let b = (f.bit_off / 8) as usize;
            let mut out = [0u8; 16];
            if b + 16 <= hdr.len() { out.copy_from_slice(&hdr[b..b + 16]); }
            FieldValue::Ipv6(out)
        }
        FieldKind::MacAddr => {
            let b = (f.bit_off / 8) as usize;
            let mut out = [0u8; 6];
            if b + 6 <= hdr.len() { out.copy_from_slice(&hdr[b..b + 6]); }
            FieldValue::Mac(out)
        }
        FieldKind::Bytes => {
            let b = (f.bit_off / 8) as usize;
            let n = (f.bit_len / 8) as usize;
            FieldValue::Bytes(hdr.get(b..b + n).unwrap_or(&[]).to_vec())
        }
        FieldKind::VarBytes => {
            let b = (f.bit_off / 8) as usize;
            FieldValue::Bytes(hdr.get(b..).unwrap_or(&[]).to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_aligned_reads() {
        let b = [0xde, 0xad, 0xbe, 0xef];
        assert_eq!(read_bits(&b, 0, 8), 0xde);
        assert_eq!(read_bits(&b, 0, 16), 0xdead);
        assert_eq!(read_bits(&b, 0, 32), 0xdeadbeef);
        assert_eq!(read_bits(&b, 16, 16), 0xbeef);
    }

    #[test]
    fn sub_byte_reads() {
        // 0x45 = version 4, ihl 5
        let b = [0x45u8];
        assert_eq!(read_bits(&b, 0, 4), 4);
        assert_eq!(read_bits(&b, 4, 4), 5);
    }

    #[test]
    fn bits_roundtrip() {
        let mut b = [0u8; 4];
        write_bits(&mut b, 0, 4, 4);
        write_bits(&mut b, 4, 4, 5);
        assert_eq!(b[0], 0x45);
        write_bits(&mut b, 8, 16, 0xbeef);
        assert_eq!(read_bits(&b, 8, 16), 0xbeef);
    }

    #[test]
    fn out_of_range_is_zero_not_panic() {
        let b = [0x01u8];
        assert_eq!(read_bits(&b, 0, 32), 0);
        assert_eq!(read_bits(&b, 64, 8), 0);
    }
}
