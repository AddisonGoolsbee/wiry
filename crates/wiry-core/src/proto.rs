use crate::field::{self, FieldDesc, FieldKind};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct ProtoId(pub u16);

/// Built-in ids are the first `BUILTIN_COUNT` values and never move: the
/// numbering separates the static table from the registry.
#[allow(non_upper_case_globals)]
impl ProtoId {
    pub const Raw: ProtoId = ProtoId(0);
    pub const Padding: ProtoId = ProtoId(1);
    pub const Ether: ProtoId = ProtoId(2);
    pub const Dot1Q: ProtoId = ProtoId(3);
    pub const Arp: ProtoId = ProtoId(4);
    pub const Ipv4: ProtoId = ProtoId(5);
    pub const Ipv6: ProtoId = ProtoId(6);
    pub const Tcp: ProtoId = ProtoId(7);
    pub const Udp: ProtoId = ProtoId(8);
    pub const Icmp: ProtoId = ProtoId(9);
    pub const Icmpv6: ProtoId = ProtoId(10);
    pub const Dns: ProtoId = ProtoId(11);
    pub const Bootp: ProtoId = ProtoId(12);
    pub const Dhcp: ProtoId = ProtoId(13);
    pub const Null: ProtoId = ProtoId(14);
    pub const LinuxSll: ProtoId = ProtoId(15);
    pub const LinuxSll2: ProtoId = ProtoId(16);
    pub const HopByHop: ProtoId = ProtoId(17);
    pub const Routing: ProtoId = ProtoId(18);
    pub const Fragment: ProtoId = ProtoId(19);
    pub const DestOpt: ProtoId = ProtoId(20);
    pub const Gre: ProtoId = ProtoId(21);
    pub const Vxlan: ProtoId = ProtoId(22);
    pub const Geneve: ProtoId = ProtoId(23);
    pub const Mpls: ProtoId = ProtoId(24);
    pub const PppoeDisc: ProtoId = ProtoId(25);
    pub const Pppoe: ProtoId = ProtoId(26);
    pub const Ppp: ProtoId = ProtoId(27);
    pub const GtpU: ProtoId = ProtoId(28);
    pub const ErspanII: ProtoId = ProtoId(29);
    pub const ErspanIII: ProtoId = ProtoId(30);

    pub fn name(self) -> &'static str {
        desc(self).name
    }

    pub fn is_registered(self) -> bool {
        self.0 >= BUILTIN_COUNT
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
    /// The one table this protocol's options are named by, in both directions.
    pub opt_table: Option<&'static crate::options::OptTable>,
    /// Written after option bytes are appended (IPv4 ihl, TCP data offset).
    pub set_hlen: Option<fn(&mut [u8], usize)>,
    pub bind_next: Option<fn(&mut [u8], ProtoId)>,
    /// Bytes appended when `next` is stacked. BOOTP's magic cookie starts the
    /// option area rather than DHCP itself: RFC 2131 §3.
    pub bind_next_bytes: Option<fn(ProtoId) -> &'static [u8]>,
    /// Total bytes this header's own length field claims, itself included.
    /// `None` means the content runs to the end of what encloses it.
    pub content_len: Option<fn(&[u8]) -> usize>,
}

pub const BUILTIN_COUNT: u16 = 31;

const BUILTINS: &[ProtoId] = &[
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
    ProtoId::Null,
    ProtoId::LinuxSll,
    ProtoId::LinuxSll2,
    ProtoId::Raw,
    ProtoId::Padding,
    ProtoId::HopByHop,
    ProtoId::Routing,
    ProtoId::Fragment,
    ProtoId::DestOpt,
    ProtoId::Gre,
    ProtoId::Vxlan,
    ProtoId::Geneve,
    ProtoId::Mpls,
    ProtoId::PppoeDisc,
    ProtoId::Pppoe,
    ProtoId::Ppp,
    ProtoId::GtpU,
    ProtoId::ErspanII,
    ProtoId::ErspanIII,
];

/// Every built-in id, so the fuzz and robustness suites cannot fall behind the
/// layer list by being a second copy of it.
pub fn builtins() -> impl Iterator<Item = ProtoId> {
    (0..BUILTIN_COUNT).map(ProtoId)
}

#[inline]
pub fn desc(id: ProtoId) -> &'static ProtoDesc {
    if id.0 < BUILTIN_COUNT {
        builtin_desc(id)
    } else {
        registered_desc(id)
    }
}

fn builtin_desc(id: ProtoId) -> &'static ProtoDesc {
    use crate::layers::*;
    match id {
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
        ProtoId::Null => &null::DESC,
        ProtoId::LinuxSll => &linux_sll::DESC,
        ProtoId::LinuxSll2 => &linux_sll::DESC_V2,
        ProtoId::HopByHop => &ipv6_ext::HOP_BY_HOP_DESC,
        ProtoId::Routing => &ipv6_ext::ROUTING_DESC,
        ProtoId::Fragment => &ipv6_ext::FRAGMENT_DESC,
        ProtoId::DestOpt => &ipv6_ext::DEST_OPT_DESC,
        ProtoId::Gre => &gre::DESC,
        ProtoId::Vxlan => &vxlan::DESC,
        ProtoId::Geneve => &geneve::DESC,
        ProtoId::Mpls => &mpls::DESC,
        ProtoId::PppoeDisc => &pppoe::DISC_DESC,
        ProtoId::Pppoe => &pppoe::DESC,
        ProtoId::Ppp => &pppoe::PPP_DESC,
        ProtoId::GtpU => &gtp::DESC,
        ProtoId::ErspanII => &erspan::DESC_II,
        ProtoId::ErspanIII => &erspan::DESC_III,
        _ => &raw::DESC,
    }
}

pub fn by_name(name: &str) -> Option<ProtoId> {
    if let Some(p) = BUILTINS.iter().copied().find(|p| desc(*p).name == name) {
        return Some(p);
    }
    // Newest first, so redefining a layer shadows the earlier one.
    registered().rev().find(|d| d.name == name).map(|d| d.id)
}

pub fn known_layers() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = BUILTINS.iter().map(|p| desc(*p).name).collect();
    out.extend(registered().map(|d| d.name));
    out
}

/// Ignores conditions, so it sees every field the protocol can ever carry.
pub fn field_of(id: ProtoId, name: &str) -> Option<&'static FieldDesc> {
    desc(id).fields.iter().find(|f| f.name == name)
}

pub fn active_fields(id: ProtoId, hdr: &[u8]) -> impl Iterator<Item = &'static FieldDesc> + '_ {
    desc(id).fields.iter().filter(move |f| f.is_active(hdr))
}

/// Two fields may share a name when their conditions are disjoint; the header
/// bytes pick between them.
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

/// Registration happens once per Python class definition and is never undone,
/// so the owned data is leaked for the `'static` lifetimes `ProtoDesc` wants.
const MAX_REGISTERED: usize = 1024;

#[allow(clippy::declare_interior_mutable_const)]
const NO_DESC: OnceLock<&'static ProtoDesc> = OnceLock::new();
static REGISTRY: [OnceLock<&'static ProtoDesc>; MAX_REGISTERED] = [NO_DESC; MAX_REGISTERED];
static REGISTERED: AtomicUsize = AtomicUsize::new(0);

fn registered_desc(id: ProtoId) -> &'static ProtoDesc {
    REGISTRY
        .get((id.0 - BUILTIN_COUNT) as usize)
        .and_then(|slot| slot.get())
        .copied()
        .unwrap_or(&crate::layers::raw::DESC)
}

fn registered() -> impl DoubleEndedIterator<Item = &'static ProtoDesc> {
    let n = REGISTERED.load(Ordering::Acquire).min(MAX_REGISTERED);
    REGISTRY[..n].iter().filter_map(|slot| slot.get().copied())
}

/// `dissect_spans` raises this to `min_len`, so a header of one fixed width
/// needs no function of its own.
pub fn fixed_len(_: &[u8]) -> usize {
    0
}

/// A trailing `VarBytes` field runs to the end of the packet.
fn rest_len(hdr: &[u8]) -> usize {
    hdr.len()
}

pub fn raw_next(_: &[u8]) -> Next {
    Next::Raw
}

/// A tunnel whose payload is a whole frame, whatever its own header said.
pub fn frame_next(_: &[u8]) -> Next {
    Next::Proto(ProtoId::Ether)
}

/// `build_len` is the width of the fixed part in bytes.
pub fn register(
    name: String,
    mut fields: Vec<FieldDesc>,
    build_len: usize,
) -> Result<ProtoId, String> {
    if name.is_empty() {
        return Err("layer name must not be empty".into());
    }
    if BUILTINS.iter().any(|p| desc(*p).name == name) {
        return Err(format!(
            "{name} is a built-in layer and cannot be redefined"
        ));
    }
    let slot = REGISTERED.fetch_add(1, Ordering::AcqRel);
    if slot >= MAX_REGISTERED {
        REGISTERED.store(MAX_REGISTERED, Ordering::Release);
        return Err(format!(
            "no room for more than {MAX_REGISTERED} custom layers"
        ));
    }
    let var_tail = fields.last().is_some_and(|f| f.kind == FieldKind::VarBytes);
    if var_tail {
        fields.last_mut().unwrap().to_end = true;
    }
    let d: &'static ProtoDesc = Box::leak(Box::new(ProtoDesc {
        id: ProtoId(BUILTIN_COUNT + slot as u16),
        name: Box::leak(name.into_boxed_str()),
        fields: Box::leak(fields.into_boxed_slice()),
        min_len: build_len,
        header_len: if var_tail { rest_len } else { fixed_len },
        next: raw_next,
        build_len,
        parse_options: None,
        opt_table: None,
        set_hlen: None,
        bind_next: None,
        bind_next_bytes: None,
        content_len: None,
    }));
    let _ = REGISTRY[slot].set(d);
    Ok(d.id)
}

/// When every condition holds in the parent's header, `child` follows it.
struct Bind {
    parent: ProtoId,
    child: ProtoId,
    /// Values are already in wire form.
    conds: &'static [(&'static FieldDesc, u64)],
}

const MAX_BINDS: usize = 1024;

#[allow(clippy::declare_interior_mutable_const)]
const NO_BIND: OnceLock<Bind> = OnceLock::new();
static BINDS: [OnceLock<Bind>; MAX_BINDS] = [NO_BIND; MAX_BINDS];
static BOUND: AtomicUsize = AtomicUsize::new(0);
/// Which protocols appear as a parent, so a layer nobody bound under skips the
/// search. Ids past 64 share a bit: a fruitless search, never a missed binding.
static BOUND_PARENTS: AtomicU64 = AtomicU64::new(0);

#[inline]
fn parent_bit(p: ProtoId) -> u64 {
    1u64 << (p.0 % 64)
}

pub fn bind(
    parent: ProtoId,
    child: ProtoId,
    conds: Vec<(&'static FieldDesc, u64)>,
) -> Result<(), String> {
    let slot = BOUND.fetch_add(1, Ordering::AcqRel);
    if slot >= MAX_BINDS {
        BOUND.store(MAX_BINDS, Ordering::Release);
        return Err(format!("no room for more than {MAX_BINDS} layer bindings"));
    }
    let conds = conds
        .into_iter()
        .map(|(f, v)| (f, field::wire_uint(f, v)))
        .collect::<Vec<_>>();
    let _ = BINDS[slot].set(Bind {
        parent,
        child,
        conds: Box::leak(conds.into_boxed_slice()),
    });
    BOUND_PARENTS.fetch_or(parent_bit(parent), Ordering::Release);
    Ok(())
}

fn binds() -> impl Iterator<Item = &'static Bind> {
    let n = BOUND.load(Ordering::Acquire).min(MAX_BINDS);
    BINDS[..n].iter().filter_map(|slot| slot.get())
}

/// The search is kept out of line, so a layer nothing was bound under pays one
/// relaxed load and a branch.
#[inline]
pub fn bound_next(parent: ProtoId, hdr: &[u8]) -> Option<ProtoId> {
    if BOUND_PARENTS.load(Ordering::Relaxed) & parent_bit(parent) == 0 {
        return None;
    }
    search_binds(parent, hdr)
}

#[inline(never)]
fn search_binds(parent: ProtoId, hdr: &[u8]) -> Option<ProtoId> {
    binds()
        .find(|b| {
            b.parent == parent
                && b.conds
                    .iter()
                    .all(|(f, v)| field::read_bits(hdr, f.bit_off, f.bit_len) == *v)
        })
        .map(|b| b.child)
}

/// The reverse of `bound_next`: writes back the values that make dissection
/// find `child` again.
#[inline]
pub fn apply_bind(hdr: &mut [u8], parent: ProtoId, child: ProtoId) {
    if BOUND_PARENTS.load(Ordering::Relaxed) & parent_bit(parent) == 0 {
        return;
    }
    write_bind(hdr, parent, child);
}

#[inline(never)]
fn write_bind(hdr: &mut [u8], parent: ProtoId, child: ProtoId) {
    if let Some(b) = binds().find(|b| b.parent == parent && b.child == child) {
        for (f, v) in b.conds {
            field::write_bits(hdr, f.bit_off, f.bit_len, *v);
        }
    }
}

/// IANA "ETHER TYPES" registry.
pub mod ethertype {
    pub const IPV4: u16 = 0x0800;
    pub const ARP: u16 = 0x0806;
    pub const DOT1Q: u16 = 0x8100;
    pub const IPV6: u16 = 0x86DD;
    /// Loopback; carries no payload, so it is the default for a frame with
    /// nothing stacked under it.
    pub const LOOP: u16 = 0x9000;
    /// RFC 1701 §3: Transparent Ethernet Bridging, how a tunnel says its
    /// payload is a whole frame rather than a datagram.
    pub const TEB: u16 = 0x6558;
    pub const PPP_LINK: u16 = 0x880B;
    pub const MPLS_UNICAST: u16 = 0x8847;
    pub const MPLS_MULTICAST: u16 = 0x8848;
    pub const PPPOE_DISCOVERY: u16 = 0x8863;
    pub const PPPOE_SESSION: u16 = 0x8864;
    pub const ERSPAN_II: u16 = 0x88BE;
    pub const ERSPAN_III: u16 = 0x22EB;
}

/// IANA "Protocol Numbers" registry.
pub mod ipproto {
    pub const ICMP: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const IPV6_ICMP: u8 = 58;
    /// RFC 8200 §4: the extension headers this build walks.
    pub const HOPOPT: u8 = 0;
    pub const IPV6_ROUTE: u8 = 43;
    pub const IPV6_FRAG: u8 = 44;
    pub const IPV6_OPTS: u8 = 60;
    /// RFC 2003 §3 and RFC 4213 §3: an IP datagram as the payload of another.
    pub const IPV4: u8 = 4;
    pub const IPV6: u8 = 41;
    pub const GRE: u8 = 47;
}

pub mod ports {
    pub const DNS: u16 = 53;
    pub const BOOTPS: u16 = 67;
    pub const BOOTPC: u16 = 68;
    pub const GTP_U: u16 = 2152;
    pub const VXLAN: u16 = 4789;
    pub const GENEVE: u16 = 6081;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uint(name: &'static str, off: u16, len: u16) -> FieldDesc {
        FieldDesc::uint(name, off, len, 0)
    }

    #[test]
    fn builtin_ids_keep_their_numbering() {
        assert_eq!(ProtoId::Raw.0, 0);
        assert_eq!(ProtoId::Tcp.0, 7);
        assert_eq!(ProtoId::ErspanIII.0, BUILTIN_COUNT - 1);
        assert_eq!(desc(ProtoId::Tcp).name, "TCP");
    }

    /// The id list, `BUILTINS` and the dispatch match are three hand-kept
    /// tables: an id missing from any of them fails silently, as `Raw` or as a
    /// layer `by_name` cannot see.
    #[test]
    fn every_builtin_id_is_listed_and_dispatched() {
        for id in builtins() {
            let d = desc(id);
            assert_eq!(d.id, id, "{} dispatches to {}", id.0, d.name);
            assert!(BUILTINS.contains(&id), "{} missing from BUILTINS", d.name);
            assert_eq!(by_name(d.name), Some(id), "{} not found by name", d.name);
        }
        assert_eq!(BUILTINS.len(), BUILTIN_COUNT as usize);
    }

    #[test]
    fn registration_round_trips_through_name_and_desc() {
        let id = register("RegDemo".into(), vec![uint("a", 0, 8), uint("b", 8, 16)], 3).unwrap();
        assert!(id.is_registered());
        assert_eq!(desc(id).name, "RegDemo");
        assert_eq!(desc(id).build_len, 3);
        assert_eq!(desc(id).min_len, 3);
        assert_eq!(by_name("RegDemo"), Some(id));
        assert!(known_layers().contains(&"RegDemo"));
        assert_eq!(field_of(id, "b").unwrap().bit_len, 16);
    }

    #[test]
    fn a_builtin_name_cannot_be_redefined() {
        assert!(register("TCP".into(), vec![], 0).is_err());
        assert!(register(String::new(), vec![], 0).is_err());
    }

    #[test]
    fn an_unknown_id_falls_back_to_raw_rather_than_panicking() {
        assert_eq!(desc(ProtoId(60000)).name, "Raw");
    }

    #[test]
    fn a_trailing_var_field_makes_the_header_run_to_the_end() {
        let id = register(
            "RegVar".into(),
            vec![uint("a", 0, 8), FieldDesc::var_bytes("data", 8)],
            1,
        )
        .unwrap();
        assert_eq!((desc(id).header_len)(&[1, 2, 3, 4]), 4);
        let plain = register("RegPlain".into(), vec![uint("a", 0, 8)], 1).unwrap();
        assert_eq!((desc(plain).header_len)(&[1, 2, 3, 4]), 0);
    }

    #[test]
    fn a_binding_matches_only_when_every_condition_holds() {
        let id = register("RegBound".into(), vec![uint("a", 0, 8)], 1).unwrap();
        let sport = field_of(ProtoId::Udp, "sport").unwrap();
        let dport = field_of(ProtoId::Udp, "dport").unwrap();
        bind(ProtoId::Udp, id, vec![(sport, 1111), (dport, 2222)]).unwrap();

        let mut hdr = [0u8; 8];
        assert_eq!(bound_next(ProtoId::Udp, &hdr), None);
        hdr[0..2].copy_from_slice(&1111u16.to_be_bytes());
        assert_eq!(bound_next(ProtoId::Udp, &hdr), None);
        hdr[2..4].copy_from_slice(&2222u16.to_be_bytes());
        assert_eq!(bound_next(ProtoId::Udp, &hdr), Some(id));
        assert_eq!(bound_next(ProtoId::Tcp, &hdr), None);

        let mut back = [0u8; 8];
        apply_bind(&mut back, ProtoId::Udp, id);
        assert_eq!(&back[..4], &hdr[..4]);
    }
}
