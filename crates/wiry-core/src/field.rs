use crate::names::{Host, Names, Table};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldKind {
    Uint,
    /// A whole number of octets, read as one little-endian integer.
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
    pub names: Names,
    /// Octets `[le_at, le_at + le_len)` are one little-endian integer, and
    /// `bit_off` counts from its most significant bit as if it had been written
    /// big-endian in their place. A length below 2 is plain big-endian. An
    /// address or a byte string under one is stored octet-reversed.
    pub le_at: u16,
    pub le_len: u8,
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

    /// At most eight octets, and the field must lie inside them.
    pub const fn little_endian(mut self, at: u16, len: u8) -> Self {
        self.le_at = at;
        self.le_len = len;
        self
    }

    pub const fn defaulting_to(mut self, b: &'static [u8]) -> Self {
        self.default_bytes = Some(b);
        self
    }

    /// Sorted by value.
    pub const fn named(mut self, t: Table) -> Self {
        self.names = Names::Table(t);
        self
    }

    pub const fn host_named(mut self, h: Host) -> Self {
        self.names = Names::Host(h);
        self
    }

    /// The table is picked by the field at `on_off`/`on_len` of the same
    /// header. Both levels sorted by value.
    pub const fn named_by(
        mut self,
        on_off: u16,
        on_len: u16,
        tables: &'static [(u64, Table)],
    ) -> Self {
        self.names = Names::Multi {
            on_off,
            on_len,
            tables,
        };
        self
    }

    /// The enumerated name of `v`, given the header it was read from.
    pub fn name_of(&self, hdr: &[u8], v: u64) -> Option<&'static str> {
        self.names.name(hdr, v)
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
            names: Names::None,
            le_at: 0,
            le_len: 0,
        }
    }

    pub const fn uint(name: &'static str, bit_off: u16, bit_len: u16, default: u64) -> Self {
        Self::new(name, bit_off, bit_len, FieldKind::Uint, default)
    }

    pub const fn le_uint(name: &'static str, bit_off: u16, bit_len: u16, default: u64) -> Self {
        Self::new(name, bit_off, bit_len, FieldKind::LeUint, default)
            .little_endian(bit_off / 8, (bit_len / 8) as u8)
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

/// The octets of a little-endian group, reversed so the group reads as a
/// big-endian integer, and where they start. None for a big-endian field, or
/// for a group the buffer does not hold, which reads as zero and takes no write.
fn le_image(buf: &[u8], f: &FieldDesc) -> Option<([u8; 8], usize, usize)> {
    let n = (f.le_len as usize).min(8);
    let at = f.le_at as usize;
    let src = buf.get(at..at + n)?;
    let mut img = [0u8; 8];
    for (d, s) in img.iter_mut().zip(src.iter().rev()) {
        *d = *s;
    }
    Some((img, at, n))
}

/// Where the field starts inside its group's image.
#[inline]
fn le_off(f: &FieldDesc) -> u16 {
    f.bit_off.wrapping_sub(f.le_at.wrapping_mul(8))
}

#[inline]
fn is_le(f: &FieldDesc) -> bool {
    f.le_len > 1
}

/// An integer or flags field's value, in either byte order.
#[inline]
pub fn read_uint(hdr: &[u8], f: &FieldDesc) -> u64 {
    if !is_le(f) {
        return read_bits(hdr, f.bit_off, f.bit_len);
    }
    match le_image(hdr, f) {
        Some((img, _, n)) => read_bits(&img[..n], le_off(f), f.bit_len),
        None => 0,
    }
}

/// The inverse of `read_uint`. Bits of the field past its width are dropped,
/// as `write_bits` drops them.
#[inline]
pub fn write_uint(buf: &mut [u8], f: &FieldDesc, v: u64) {
    if !is_le(f) {
        return write_bits(buf, f.bit_off, f.bit_len, v);
    }
    if let Some((mut img, at, n)) = le_image(buf, f) {
        write_bits(&mut img[..n], le_off(f), f.bit_len, v);
        for (d, s) in buf[at..at + n].iter_mut().zip(img[..n].iter().rev()) {
            *d = *s;
        }
    }
}

/// `b` as the octets a fixed-width field stores: reversed under a
/// little-endian group, zero-padded to the field's width first so the reversal
/// is of the whole field.
pub fn wire_octets<'a>(f: &FieldDesc, b: &'a [u8]) -> std::borrow::Cow<'a, [u8]> {
    if !is_le(f) || f.kind == FieldKind::VarBytes {
        return std::borrow::Cow::Borrowed(b);
    }
    let mut v = b.to_vec();
    v.resize((f.bit_len / 8) as usize, 0);
    v.reverse();
    std::borrow::Cow::Owned(v)
}

fn fixed_bytes<const N: usize>(hdr: &[u8], f: &FieldDesc) -> [u8; N] {
    let b = (f.bit_off / 8) as usize;
    let mut out = [0u8; N];
    if let Some(src) = hdr.get(b..b + N) {
        out.copy_from_slice(src);
        if is_le(f) {
            out.reverse();
        }
    }
    out
}

/// Whether `v` is representable in this field, so an assignment too wide for it
/// is refused rather than masked by `write_bits`. A field of whole octets is
/// packed by `struct` in the API this follows and rejects an oversized value; a
/// sub-octet field is a bit field there and masks. Both halves are kept.
#[inline]
pub fn fits(f: &FieldDesc, v: u64) -> bool {
    if f.bit_len == 0 || f.bit_len >= 64 || f.bit_off % 8 != 0 || f.bit_len % 8 != 0 {
        return true;
    }
    v >> f.bit_len == 0
}

pub fn decode(hdr: &[u8], f: &FieldDesc) -> FieldValue {
    match f.kind {
        FieldKind::Uint | FieldKind::LeUint => FieldValue::Uint(read_uint(hdr, f)),
        FieldKind::Flags => FieldValue::Flags {
            bits: read_uint(hdr, f),
            names: f.flags,
        },
        FieldKind::Ipv4Addr => FieldValue::Ipv4(fixed_bytes(hdr, f)),
        FieldKind::Ipv6Addr => FieldValue::Ipv6(fixed_bytes(hdr, f)),
        FieldKind::MacAddr => FieldValue::Mac(fixed_bytes(hdr, f)),
        FieldKind::Bytes => {
            let b = (f.bit_off / 8) as usize;
            let n = (f.bit_len / 8) as usize;
            let mut v = hdr.get(b..b + n).unwrap_or(&[]).to_vec();
            if is_le(f) {
                v.reverse();
            }
            FieldValue::Bytes(v)
        }
        FieldKind::VarBytes => {
            let b = (f.bit_off / 8) as usize;
            FieldValue::Bytes(hdr.get(b..).unwrap_or(&[]).to_vec())
        }
    }
}

/// An address left-aligned in sixteen octets, so an IPv4 and an IPv6 flow key
/// are one shape. Anything longer is cut, because nothing addresses wider.
pub fn wide(addr: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let n = addr.len().min(16);
    out[..n].copy_from_slice(&addr[..n]);
    out
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
    fn a_whole_octet_field_rejects_a_value_too_wide_for_it() {
        let ttl = FieldDesc::uint("ttl", 64, 8, 64);
        assert!(fits(&ttl, 255));
        assert!(!fits(&ttl, 256));
        assert!(!fits(&ttl, u64::MAX));

        let sport = FieldDesc::uint("sport", 0, 16, 0);
        assert!(fits(&sport, 65535));
        assert!(!fits(&sport, 70000));

        let le = FieldDesc::le_uint("type", 0, 32, 0);
        assert!(fits(&le, 0xffff_ffff));
        assert!(!fits(&le, 0x1_0000_0000));
    }

    #[test]
    fn a_sub_octet_field_masks_rather_than_rejecting() {
        assert!(fits(&FieldDesc::uint("vlan", 20, 12, 0), 5000));
        assert!(fits(&FieldDesc::flags("flags", 103, 9, &[]), u64::MAX));
        assert!(fits(&FieldDesc::uint("wide", 0, 64, 0), u64::MAX));
        assert!(fits(&FieldDesc::var_bytes("options", 160), u64::MAX));
    }

    /// Bluetooth Core 5.4 Vol 4 Part E §5.4.2: the ACL header's first two
    /// octets are one little-endian word, handle in its low twelve bits.
    fn acl() -> [FieldDesc; 3] {
        [
            FieldDesc::uint("BC", 0, 2, 0).little_endian(0, 2),
            FieldDesc::uint("PB", 2, 2, 0).little_endian(0, 2),
            FieldDesc::uint("handle", 4, 12, 0).little_endian(0, 2),
        ]
    }

    #[test]
    fn a_little_endian_group_reads_from_its_most_significant_bit() {
        let [bc, pb, handle] = acl();
        let b = [0x2a, 0x60];
        assert_eq!(read_uint(&b, &bc), 1);
        assert_eq!(read_uint(&b, &pb), 2);
        assert_eq!(read_uint(&b, &handle), 0x02a);
    }

    #[test]
    fn a_little_endian_write_touches_only_its_own_bits() {
        let [bc, pb, handle] = acl();
        let mut b = [0x2a, 0x60, 0xee];
        write_uint(&mut b, &handle, 0xabc);
        assert_eq!(b, [0xbc, 0x6a, 0xee]);
        write_uint(&mut b, &bc, 0);
        write_uint(&mut b, &pb, 3);
        assert_eq!(b, [0xbc, 0x3a, 0xee]);
        assert_eq!(read_uint(&b, &handle), 0xabc);
    }

    #[test]
    fn a_whole_octet_little_endian_integer_is_byte_reversed() {
        let f = FieldDesc::le_uint("len", 8, 24, 0);
        let mut b = [0u8; 4];
        write_uint(&mut b, &f, 0x0a0b0c);
        assert_eq!(b, [0, 0x0c, 0x0b, 0x0a]);
        assert_eq!(read_uint(&b, &f), 0x0a0b0c);
    }

    #[test]
    fn a_little_endian_address_is_stored_reversed() {
        let f = FieldDesc::mac("bd_addr", 8).little_endian(1, 6);
        let b = [0xff, 6, 5, 4, 3, 2, 1];
        assert_eq!(decode(&b, &f), FieldValue::Mac([1, 2, 3, 4, 5, 6]));
        assert_eq!(
            &wire_octets(&f, &[1, 2, 3, 4, 5, 6])[..],
            &[6, 5, 4, 3, 2, 1]
        );
    }

    #[test]
    fn a_group_the_buffer_does_not_hold_reads_zero_and_takes_no_write() {
        let [_, _, handle] = acl();
        let mut b = [0xffu8];
        assert_eq!(read_uint(&b, &handle), 0);
        write_uint(&mut b, &handle, 1);
        assert_eq!(b, [0xff]);
        let stray = FieldDesc::uint("x", 0, 8, 0).little_endian(u16::MAX, 8);
        assert_eq!(read_uint(&[0u8; 8], &stray), 0);
    }

    #[test]
    fn out_of_range_is_zero_not_panic() {
        let b = [0x01u8];
        assert_eq!(read_bits(&b, 0, 32), 0);
        assert_eq!(read_bits(&b, 64, 8), 0);
    }
}
