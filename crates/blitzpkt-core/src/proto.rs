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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Next {
    Proto(ProtoId),
    Raw,
    End,
}

pub type OptionParser = fn(&[u8]) -> Vec<crate::options::Item>;

pub struct ProtoDesc {
    pub id: ProtoId,
    pub name: &'static str,
    pub fields: &'static [FieldDesc],
    /// Shorter input dissects as `Raw`.
    pub min_len: usize,
    pub header_len: fn(&[u8]) -> usize,
    pub next: fn(&[u8]) -> Next,
    pub build_len: usize,
    pub parse_options: Option<OptionParser>,
    /// Written after option bytes are appended (IPv4 ihl, TCP data offset).
    pub set_hlen: Option<fn(&mut [u8], usize)>,
    pub bind_next: Option<fn(&mut [u8], ProtoId)>,
    /// Bytes appended when `next` is stacked. BOOTP's magic cookie starts the
    /// option area rather than DHCP itself: RFC 2131 §3.
    pub bind_next_bytes: Option<fn(ProtoId) -> &'static [u8]>,
}

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

/// Ignores conditions, so it sees every field the protocol can ever carry.
pub fn field_of(id: ProtoId, name: &str) -> Option<&'static FieldDesc> {
    desc(id).fields.iter().find(|f| f.name == name)
}

pub fn active_fields(id: ProtoId, hdr: &[u8]) -> impl Iterator<Item = &'static FieldDesc> + '_ {
    desc(id).fields.iter().filter(move |f| f.is_active(hdr))
}

/// Two fields may share a name when their conditions are disjoint, so the
/// header bytes pick between them.
pub fn active_field_of(id: ProtoId, hdr: &[u8], name: &str) -> Option<&'static FieldDesc> {
    active_fields(id, hdr).find(|f| f.name == name)
}

/// Names served by a parser rather than by the flat field table.
pub fn accessor_names(id: ProtoId) -> &'static [&'static str] {
    match id {
        // RFC 1035 §4.1
        ProtoId::Dns => &["qd", "an", "ns", "ar"],
        _ => &[],
    }
}

/// IANA "ETHER TYPES" registry.
pub mod ethertype {
    pub const IPV4: u16 = 0x0800;
    pub const ARP: u16 = 0x0806;
    pub const DOT1Q: u16 = 0x8100;
    pub const IPV6: u16 = 0x86DD;
    /// Loopback (Ethernet Configuration Testing Protocol); carries no payload,
    /// so it is the default for a frame with nothing stacked under it.
    pub const LOOP: u16 = 0x9000;
}

/// IANA "Protocol Numbers" registry.
pub mod ipproto {
    pub const ICMP: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const IPV6_ICMP: u8 = 58;
}

pub mod ports {
    pub const DNS: u16 = 53;
    pub const BOOTPS: u16 = 67;
    pub const BOOTPC: u16 = 68;
}
