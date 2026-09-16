//! Protocol registry. Each layer module exposes a `ProtoDesc`; this module owns
//! the identifier space and the dispatch table used by the dissector.

use crate::field::FieldDesc;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u16)]
pub enum ProtoId {
    Raw = 0,
    Padding = 1,
    Ether = 2,
    Dot1Q = 3,
    Arp = 4,
    Ipv4 = 5,
    Ipv6 = 6,
    Tcp = 7,
    Udp = 8,
    Icmp = 9,
    Icmpv6 = 10,
    Dns = 11,
    Bootp = 12,
    Dhcp = 13,
}

impl ProtoId {
    pub fn name(self) -> &'static str {
        desc(self).name
    }
}

/// What follows this header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Next {
    /// Payload begins immediately after the header and is this protocol.
    Proto(ProtoId),
    /// Remaining bytes are an opaque payload.
    Raw,
    /// Nothing follows; the header consumed the layer entirely.
    End,
}

/// Parses a header's variable-length option region into a uniform item list.
/// Given the full layer header bytes.
pub type OptionParser = fn(&[u8]) -> Vec<crate::options::Item>;

/// Static description of one protocol header.
pub struct ProtoDesc {
    pub id: ProtoId,
    pub name: &'static str,
    pub fields: &'static [FieldDesc],
    /// Smallest valid header. Shorter input dissects as `Raw`.
    pub min_len: usize,
    /// Actual header length in bytes given the header bytes (handles IHL, data offset).
    pub header_len: fn(&[u8]) -> usize,
    /// Which protocol the payload is, given the header bytes.
    pub next: fn(&[u8]) -> Next,
    /// Fixed header length used when constructing from scratch.
    pub build_len: usize,
    /// Parse this header's variable-length option region, when it has one.
    /// Given the full layer header bytes.
    pub parse_options: Option<OptionParser>,
    /// Write this header's own length field (IPv4 ihl, TCP data offset)
    /// after option bytes have been appended. Protocols with a fixed
    /// header leave this None.
    pub set_hlen: Option<fn(&mut [u8], usize)>,
    /// Set this header's demultiplexing field so it points at `next`.
    /// Mirrors the automatic binding that happens when layers are stacked.
    pub bind_next: Option<fn(&mut [u8], ProtoId)>,
}

const fn fixed_len(n: usize) -> fn(&[u8]) -> usize {
    // Rust cannot yet close over `n` in a const fn pointer, so each protocol
    // supplies its own tiny function. Kept here as documentation of intent.
    let _ = n;
    |_| 0
}

/// Look up the descriptor for a protocol.
pub fn desc(id: ProtoId) -> &'static ProtoDesc {
    use crate::layers::*;
    match id {
        ProtoId::Raw => &raw::DESC,
        ProtoId::Padding => &raw::PADDING_DESC,
        ProtoId::Ether => &ether::DESC,
        ProtoId::Dot1Q => &dot1q::DESC,
        ProtoId::Arp => &arp::DESC,
        ProtoId::Ipv4 => &ipv4::DESC,
        ProtoId::Ipv6 => &ipv6::DESC,
        ProtoId::Tcp => &tcp::DESC,
        ProtoId::Udp => &udp::DESC,
        ProtoId::Icmp => &icmp::DESC,
        ProtoId::Icmpv6 => &icmpv6::DESC,
        ProtoId::Dns => &dns::DESC,
        ProtoId::Bootp => &bootp::DESC,
        ProtoId::Dhcp => &bootp::DHCP_DESC,
    }
}

/// Resolve a layer name as written in Python (`"TCP"`) to its identifier.
pub fn by_name(name: &str) -> Option<ProtoId> {
    const ALL: &[ProtoId] = &[
        ProtoId::Raw,
        ProtoId::Padding,
        ProtoId::Ether,
        ProtoId::Dot1Q,
        ProtoId::Arp,
        ProtoId::Ipv4,
        ProtoId::Ipv6,
        ProtoId::Tcp,
        ProtoId::Udp,
        ProtoId::Icmp,
        ProtoId::Icmpv6,
        ProtoId::Dns,
        ProtoId::Bootp,
        ProtoId::Dhcp,
    ];
    ALL.iter().copied().find(|p| desc(*p).name == name)
}

/// Find a field descriptor by name within a protocol.
pub fn field_of(id: ProtoId, name: &str) -> Option<&'static FieldDesc> {
    desc(id).fields.iter().find(|f| f.name == name)
}

#[allow(dead_code, clippy::type_complexity)]
const _UNUSED: fn(usize) -> fn(&[u8]) -> usize = fixed_len;

// ---- Well-known numbers, from IANA registries (not from any GPL source) ----

/// EtherType values. IANA "ETHER TYPES" registry.
pub mod ethertype {
    pub const IPV4: u16 = 0x0800;
    pub const ARP: u16 = 0x0806;
    pub const DOT1Q: u16 = 0x8100;
    pub const IPV6: u16 = 0x86DD;
    /// "Loopback" (Ethernet Configuration Testing Protocol). Carries no payload
    /// of its own, which is why it is the default for a frame with nothing
    /// stacked under it.
    pub const LOOP: u16 = 0x9000;
}

/// IP protocol numbers. IANA "Protocol Numbers" registry.
pub mod ipproto {
    pub const ICMP: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const IPV6_ICMP: u8 = 58;
}

/// Transport ports that imply an application layer.
pub mod ports {
    pub const DNS: u16 = 53;
    pub const BOOTPS: u16 = 67;
    pub const BOOTPC: u16 = 68;
}
