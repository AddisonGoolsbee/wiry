#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldKind {
    Uint,
    /// Must be a whole number of bytes wide.
    LeUint,
    Ipv4Addr,
    /// Rendered in RFC 5952 form.
    Ipv6Addr,
    MacAddr,
    Flags,
    Bytes,
    /// Runs to the end of the header.
    VarBytes,
}

#[derive(Clone, Copy, Debug)]
pub struct FieldDesc {
    pub name: &'static str,
    pub bit_off: u16,
    /// Ignored for `VarBytes`.
    pub bit_len: u16,
    pub kind: FieldKind,
    pub default: u64,
    /// Least-significant bit first.
    pub flags: &'static [&'static str],
    /// Recomputed during serialisation unless the user pinned it.
    pub computed: bool,
    /// Given the layer's header bytes, so a field can be gated on an earlier
    /// field of the same header, such as ICMP's type.
    pub cond: Option<fn(&[u8]) -> bool>,
    /// For fields wider than the 64 bits `default` holds.
    pub default_bytes: Option<&'static [u8]>,
    /// `VarBytes` only: runs to the end of the whole layer rather than of its
    /// header, so writing it resizes the packet.
    pub to_end: bool,
}

impl FieldDesc {
    pub const fn when(mut self, c: fn(&[u8]) -> bool) -> Self {
        self.cond = Some(c);
        self
    }

    pub const fn with_default(mut self, d: u64) -> Self {
        self.default = d;
        self
    }

    pub const fn defaulting_to(mut self, b: &'static [u8]) -> Self {
        self.default_bytes = Some(b);
        self
    }

    #[inline]
    pub fn is_active(&self, hdr: &[u8]) -> bool {
        match self.cond {
            Some(c) => c(hdr),
            None => true,
        }
    }

    const fn new(
        name: &'static str,
        bit_off: u16,
        bit_len: u16,
        kind: FieldKind,
        default: u64,
    ) -> Self {
        Self {
            name,
            bit_off,
            bit_len,
            kind,
            default,
            flags: &[],
            computed: false,
            cond: None,
            default_bytes: None,
            to_end: false,
        }
    }

    pub const fn uint(name: &'static str, bit_off: u16, bit_len: u16, default: u64) -> Self {
        Self::new(name, bit_off, bit_len, FieldKind::Uint, default)
    }

    pub const fn le_uint(name: &'static str, bit_off: u16, bit_len: u16, default: u64) -> Self {
        Self::new(name, bit_off, bit_len, FieldKind::LeUint, default)
    }

    pub const fn computed_uint(name: &'static str, bit_off: u16, bit_len: u16) -> Self {
        let mut f = Self::new(name, bit_off, bit_len, FieldKind::Uint, 0);
        f.computed = true;
        f
    }

    pub const fn ipv4(name: &'static str, bit_off: u16, default: u64) -> Self {
        Self::new(name, bit_off, 32, FieldKind::Ipv4Addr, default)
    }

    pub const fn ipv6(name: &'static str, bit_off: u16) -> Self {
        Self::new(name, bit_off, 128, FieldKind::Ipv6Addr, 0)
    }

    pub const fn mac(name: &'static str, bit_off: u16) -> Self {
        Self::new(name, bit_off, 48, FieldKind::MacAddr, 0)
    }

    pub const fn flags(
        name: &'static str,
        bit_off: u16,
        bit_len: u16,
        names: &'static [&'static str],
    ) -> Self {
        let mut f = Self::new(name, bit_off, bit_len, FieldKind::Flags, 0);
        f.flags = names;
        f
    }

    pub const fn var_bytes(name: &'static str, bit_off: u16) -> Self {
        Self::new(name, bit_off, 0, FieldKind::VarBytes, 0)
    }

    pub const fn var_bytes_to_end(name: &'static str, bit_off: u16) -> Self {
        let mut f = Self::var_bytes(name, bit_off);
        f.to_end = true;
        f
    }

    pub const fn bytes(name: &'static str, bit_off: u16, bit_len: u16) -> Self {
        Self::new(name, bit_off, bit_len, FieldKind::Bytes, 0)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum FieldValue {
    Uint(u64),
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
    Mac([u8; 6]),
    Flags {
        bits: u64,
        names: &'static [&'static str],
    },
    Bytes(Vec<u8>),
}

impl FieldValue {
    pub fn as_uint(&self) -> Option<u64> {
        match self {
            FieldValue::Uint(v) | FieldValue::Flags { bits: v, .. } => Some(*v),
            FieldValue::Ipv4(b) => Some(u32::from_be_bytes(*b) as u64),
            FieldValue::Mac(b) => {
                let mut v = 0u64;
                for x in b {
                    v = (v << 8) | *x as u64;
                }
                Some(v)
            }
            _ => None,
        }
    }
}

/// Big-endian. Returns 0 when the read would run past the end of `buf`.
#[inline]
pub fn read_bits(buf: &[u8], bit_off: u16, bit_len: u16) -> u64 {
    debug_assert!(bit_len <= 64);
    let start = bit_off as usize;
    let end = start + bit_len as usize;
    if bit_len == 0 || end > buf.len() * 8 {
        return 0;
    }
    if start % 8 == 0 && bit_len % 8 == 0 && bit_len <= 64 {
        let b0 = start / 8;
        let n = (bit_len / 8) as usize;
        let mut v = 0u64;
        for i in 0..n {
            v = (v << 8) | buf[b0 + i] as u64;
        }
        return v;
    }
    let mut v = 0u64;
    for i in start..end {
        let byte = buf[i / 8];
        let bit = (byte >> (7 - (i % 8))) & 1;
        v = (v << 1) | bit as u64;
    }
    v
}

/// Big-endian. A write that would run past the end of `buf` is a no-op.
#[inline]
pub fn write_bits(buf: &mut [u8], bit_off: u16, bit_len: u16, val: u64) {
    let start = bit_off as usize;
    let end = start + bit_len as usize;
    if bit_len == 0 || end > buf.len() * 8 {
        return;
    }
    // An integer fills the low-order 64 bits of a wider field and zeroes the
    // rest, so `IPv6.src = 1` is `::1`.
    if bit_len > 64 {
        for i in start..end - 64 {
            buf[i / 8] &= !(1u8 << (7 - (i % 8)));
        }
        write_bits(buf, (end - 64) as u16, 64, val);
        return;
    }
    if start % 8 == 0 && bit_len % 8 == 0 {
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

fn fixed_bytes<const N: usize>(hdr: &[u8], bit_off: u16) -> [u8; N] {
    let b = (bit_off / 8) as usize;
    let mut out = [0u8; N];
    if let Some(src) = hdr.get(b..b + N) {
        out.copy_from_slice(src);
    }
    out
}

/// Byte-reverses a little-endian field. Its own inverse, so both directions
/// go through here.
#[inline]
pub fn wire_uint(f: &FieldDesc, v: u64) -> u64 {
    if f.kind != FieldKind::LeUint {
        return v;
    }
    let n = ((f.bit_len / 8) as usize).min(8);
    v.to_be_bytes()[8 - n..]
        .iter()
        .rev()
        .fold(0u64, |acc, b| (acc << 8) | *b as u64)
}

pub fn decode(hdr: &[u8], f: &FieldDesc) -> FieldValue {
    match f.kind {
        FieldKind::Uint => FieldValue::Uint(read_bits(hdr, f.bit_off, f.bit_len)),
        FieldKind::LeUint => FieldValue::Uint(wire_uint(f, read_bits(hdr, f.bit_off, f.bit_len))),
        FieldKind::Flags => FieldValue::Flags {
            bits: read_bits(hdr, f.bit_off, f.bit_len),
            names: f.flags,
        },
        FieldKind::Ipv4Addr => FieldValue::Ipv4(fixed_bytes(hdr, f.bit_off)),
        FieldKind::Ipv6Addr => FieldValue::Ipv6(fixed_bytes(hdr, f.bit_off)),
        FieldKind::MacAddr => FieldValue::Mac(fixed_bytes(hdr, f.bit_off)),
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
    fn an_integer_fills_the_low_64_bits_of_a_wider_field() {
        let mut b = [0xffu8; 16];
        write_bits(&mut b, 0, 128, 1);
        assert_eq!(b, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn out_of_range_is_zero_not_panic() {
        let b = [0x01u8];
        assert_eq!(read_bits(&b, 0, 32), 0);
        assert_eq!(read_bits(&b, 64, 8), 0);
    }
}
