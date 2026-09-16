//! Internet checksum (RFC 1071) and the transport pseudo-headers
//! (RFC 9293 §3.1 for TCP, RFC 768 for UDP, RFC 8200 §8.1 for IPv6).

/// One's complement sum of 16-bit big-endian words, folded to 16 bits.
#[inline]
pub fn ones_complement(data: &[u8]) -> u16 {
    !(fold(sum16(data, 0)) as u16)
}

/// Running one's complement sum, so pseudo-headers can be chained.
#[inline]
pub fn sum16(data: &[u8], seed: u32) -> u32 {
    let mut sum = seed;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = *chunks.remainder() {
        sum += (last as u32) << 8;
    }
    fold(sum)
}

#[inline]
pub fn fold(mut sum: u32) -> u32 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum
}

#[inline]
pub fn finish(sum: u32) -> u16 {
    let v = !fold(sum) as u16;
    // RFC 768: a computed UDP checksum of zero is transmitted as all ones.
    v
}

/// IPv4 pseudo-header sum: src, dst, zero, protocol, transport length.
pub fn pseudo_v4(src: &[u8; 4], dst: &[u8; 4], proto: u8, tlen: u16) -> u32 {
    let mut sum = 0u32;
    sum += u16::from_be_bytes([src[0], src[1]]) as u32;
    sum += u16::from_be_bytes([src[2], src[3]]) as u32;
    sum += u16::from_be_bytes([dst[0], dst[1]]) as u32;
    sum += u16::from_be_bytes([dst[2], dst[3]]) as u32;
    sum += proto as u32;
    sum += tlen as u32;
    fold(sum)
}

/// IPv6 pseudo-header sum: src, dst, upper-layer length, next header.
pub fn pseudo_v6(src: &[u8; 16], dst: &[u8; 16], next: u8, tlen: u32) -> u32 {
    let mut sum = 0u32;
    for a in src.chunks_exact(2) {
        sum += u16::from_be_bytes([a[0], a[1]]) as u32;
    }
    for a in dst.chunks_exact(2) {
        sum += u16::from_be_bytes([a[0], a[1]]) as u32;
    }
    sum += tlen >> 16;
    sum += tlen & 0xffff;
    sum += next as u32;
    fold(sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc1071_worked_example() {
        // RFC 1071 section 3 example octets.
        let data = [0x00u8, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(ones_complement(&data), 0x220d);
    }

    #[test]
    fn odd_length_pads_with_zero() {
        // A trailing odd byte is treated as the high byte of a 16-bit word.
        let a = ones_complement(&[0x12, 0x34, 0x56]);
        let b = ones_complement(&[0x12, 0x34, 0x56, 0x00]);
        assert_eq!(a, b);
    }

    #[test]
    fn ipv4_header_checksum_is_self_verifying() {
        // A header whose checksum field is already correct sums to zero.
        let hdr: [u8; 20] = [
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00,
            10, 0, 0, 1, 10, 0, 0, 2,
        ];
        let ck = ones_complement(&hdr);
        let mut fixed = hdr;
        fixed[10] = (ck >> 8) as u8;
        fixed[11] = (ck & 0xff) as u8;
        assert_eq!(ones_complement(&fixed), 0);
    }
}
