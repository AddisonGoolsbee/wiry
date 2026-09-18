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
    // protogen:ids begin
    pub const Llc: ProtoId = ProtoId(32);
    pub const Snap: ProtoId = ProtoId(33);
    pub const Stp: ProtoId = ProtoId(34);
    pub const Lldp: ProtoId = ProtoId(35);
    pub const Cdp: ProtoId = ProtoId(36);
    pub const RadioTap: ProtoId = ProtoId(37);
    pub const Dot11: ProtoId = ProtoId(38);
    pub const Dot11Beacon: ProtoId = ProtoId(39);
    pub const Dot11ProbeReq: ProtoId = ProtoId(40);
    pub const Dot11ProbeResp: ProtoId = ProtoId(41);
    pub const Dot11Auth: ProtoId = ProtoId(42);
    pub const Dot11AssoReq: ProtoId = ProtoId(43);
    pub const Dot11AssoResp: ProtoId = ProtoId(44);
    pub const Sctp: ProtoId = ProtoId(45);
    pub const Igmp: ProtoId = ProtoId(46);
    pub const Icmpv6NdRs: ProtoId = ProtoId(48);
    pub const Icmpv6NdRa: ProtoId = ProtoId(49);
    pub const Icmpv6NdNs: ProtoId = ProtoId(50);
    pub const Icmpv6NdNa: ProtoId = ProtoId(51);
    pub const Icmpv6NdRedirect: ProtoId = ProtoId(52);
    pub const Icmpv6MlQuery: ProtoId = ProtoId(53);
    pub const Icmpv6MlReport: ProtoId = ProtoId(54);
    pub const Icmpv6MlDone: ProtoId = ProtoId(55);
    pub const Icmpv6MlReport2: ProtoId = ProtoId(56);
    pub const Esp: ProtoId = ProtoId(57);
    pub const Ah: ProtoId = ProtoId(58);
    pub const Ospf: ProtoId = ProtoId(59);
    pub const Rip: ProtoId = ProtoId(60);
    pub const Bgp: ProtoId = ProtoId(61);
    pub const Vrrp: ProtoId = ProtoId(62);
    pub const Hsrp: ProtoId = ProtoId(63);
    pub const Bfd: ProtoId = ProtoId(64);
    pub const Ntp: ProtoId = ProtoId(65);
    pub const Dhcp6: ProtoId = ProtoId(66);
    pub const Snmp: ProtoId = ProtoId(67);
    pub const Tftp: ProtoId = ProtoId(68);
    pub const Syslog: ProtoId = ProtoId(69);
    pub const Nbns: ProtoId = ProtoId(70);
    pub const NbtSession: ProtoId = ProtoId(71);
    pub const Radius: ProtoId = ProtoId(72);
    pub const Rtp: ProtoId = ProtoId(73);
    pub const Rtcp: ProtoId = ProtoId(74);
    pub const NetflowV5: ProtoId = ProtoId(75);
    pub const NetflowV9: ProtoId = ProtoId(76);
    pub const Ipfix: ProtoId = ProtoId(77);
    pub const SFlow: ProtoId = ProtoId(78);
    pub const Quic: ProtoId = ProtoId(79);
    pub const WireGuard: ProtoId = ProtoId(80);
    pub const Tls: ProtoId = ProtoId(81);
    pub const Http: ProtoId = ProtoId(82);
    pub const Ssh: ProtoId = ProtoId(83);
    pub const Mqtt: ProtoId = ProtoId(84);
    pub const Modbus: ProtoId = ProtoId(85);
    pub const Smb2: ProtoId = ProtoId(86);
    pub const Ldap: ProtoId = ProtoId(87);
    pub const Sip: ProtoId = ProtoId(88);
    pub const Ftp: ProtoId = ProtoId(89);
    pub const Smtp: ProtoId = ProtoId(90);
    pub const Imap: ProtoId = ProtoId(91);
    pub const Telnet: ProtoId = ProtoId(92);
    // protogen:ids end

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

/// Shared rather than redefined per module: sixty generated layers want one of
/// these three, and sixty copies of a one-line hook bury the field table that
/// is the only part of a generated file worth reading.
pub fn next_raw(_: &[u8]) -> Next {
    Next::Raw
}

pub fn next_end(_: &[u8]) -> Next {
    Next::End
}

pub fn header_len_rest(hdr: &[u8]) -> usize {
    hdr.len()
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

pub const BUILTIN_COUNT: u16 = 112;

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
    // protogen:builtins begin
    ProtoId::Llc,
    ProtoId::Snap,
    ProtoId::Stp,
    ProtoId::Lldp,
    ProtoId::Cdp,
    ProtoId::RadioTap,
    ProtoId::Dot11,
    ProtoId::Dot11Beacon,
    ProtoId::Dot11ProbeReq,
    ProtoId::Dot11ProbeResp,
    ProtoId::Dot11Auth,
    ProtoId::Dot11AssoReq,
    ProtoId::Dot11AssoResp,
    ProtoId::Sctp,
    ProtoId::Igmp,
    ProtoId::Icmpv6NdRs,
    ProtoId::Icmpv6NdRa,
    ProtoId::Icmpv6NdNs,
    ProtoId::Icmpv6NdNa,
    ProtoId::Icmpv6NdRedirect,
    ProtoId::Icmpv6MlQuery,
    ProtoId::Icmpv6MlReport,
    ProtoId::Icmpv6MlDone,
    ProtoId::Icmpv6MlReport2,
    ProtoId::Esp,
    ProtoId::Ah,
    ProtoId::Ospf,
    ProtoId::Rip,
    ProtoId::Bgp,
    ProtoId::Vrrp,
    ProtoId::Hsrp,
    ProtoId::Bfd,
    ProtoId::Ntp,
    ProtoId::Dhcp6,
    ProtoId::Snmp,
    ProtoId::Tftp,
    ProtoId::Syslog,
    ProtoId::Nbns,
    ProtoId::NbtSession,
    ProtoId::Radius,
    ProtoId::Rtp,
    ProtoId::Rtcp,
    ProtoId::NetflowV5,
    ProtoId::NetflowV9,
    ProtoId::Ipfix,
    ProtoId::SFlow,
    ProtoId::Quic,
    ProtoId::WireGuard,
    ProtoId::Tls,
    ProtoId::Http,
    ProtoId::Ssh,
    ProtoId::Mqtt,
    ProtoId::Modbus,
    ProtoId::Smb2,
    ProtoId::Ldap,
    ProtoId::Sip,
    ProtoId::Ftp,
    ProtoId::Smtp,
    ProtoId::Imap,
    ProtoId::Telnet,
    // protogen:builtins end
];

/// Every built-in id, so the fuzz and robustness suites cannot fall behind the
/// layer list by being a second copy of it.
pub fn builtins() -> impl Iterator<Item = ProtoId> {
    BUILTINS.iter().copied()
}

#[inline]
pub fn desc(id: ProtoId) -> &'static ProtoDesc {
    if id.0 < BUILTIN_COUNT {
        BUILTIN_DESCS[id.0 as usize]
    } else {
        registered_desc(id)
    }
}

/// A match over every registered id is too large for the inliner to take into
/// the dissection walk, which asks for a descriptor once per layer per packet.
/// An id the build does not register reads `Raw`, as the match's `_` arm did.
static BUILTIN_DESCS: [&ProtoDesc; BUILTIN_COUNT as usize] = {
    use crate::layers::*;
    let mut t = [&raw::DESC; BUILTIN_COUNT as usize];
    t[ProtoId::Padding.0 as usize] = &raw::PADDING_DESC;
    t[ProtoId::Ether.0 as usize] = &ether::DESC;
    t[ProtoId::Dot1Q.0 as usize] = &dot1q::DESC;
    t[ProtoId::Arp.0 as usize] = &arp::DESC;
    t[ProtoId::Ipv4.0 as usize] = &ipv4::DESC;
    t[ProtoId::Ipv6.0 as usize] = &ipv6::DESC;
    t[ProtoId::Tcp.0 as usize] = &tcp::DESC;
    t[ProtoId::Udp.0 as usize] = &udp::DESC;
    t[ProtoId::Icmp.0 as usize] = &icmp::DESC;
    t[ProtoId::Icmpv6.0 as usize] = &icmpv6::DESC;
    t[ProtoId::Dns.0 as usize] = &dns::DESC;
    t[ProtoId::Bootp.0 as usize] = &bootp::DESC;
    t[ProtoId::Dhcp.0 as usize] = &bootp::DHCP_DESC;
    t[ProtoId::Null.0 as usize] = &null::DESC;
    t[ProtoId::LinuxSll.0 as usize] = &linux_sll::DESC;
    t[ProtoId::LinuxSll2.0 as usize] = &linux_sll::DESC_V2;
    t[ProtoId::HopByHop.0 as usize] = &ipv6_ext::HOP_BY_HOP_DESC;
    t[ProtoId::Routing.0 as usize] = &ipv6_ext::ROUTING_DESC;
    t[ProtoId::Fragment.0 as usize] = &ipv6_ext::FRAGMENT_DESC;
    t[ProtoId::DestOpt.0 as usize] = &ipv6_ext::DEST_OPT_DESC;
    t[ProtoId::Gre.0 as usize] = &gre::DESC;
    t[ProtoId::Vxlan.0 as usize] = &vxlan::DESC;
    t[ProtoId::Geneve.0 as usize] = &geneve::DESC;
    t[ProtoId::Mpls.0 as usize] = &mpls::DESC;
    t[ProtoId::PppoeDisc.0 as usize] = &pppoe::DISC_DESC;
    t[ProtoId::Pppoe.0 as usize] = &pppoe::DESC;
    t[ProtoId::Ppp.0 as usize] = &pppoe::PPP_DESC;
    t[ProtoId::GtpU.0 as usize] = &gtp::DESC;
    t[ProtoId::ErspanII.0 as usize] = &erspan::DESC_II;
    t[ProtoId::ErspanIII.0 as usize] = &erspan::DESC_III;
    // protogen:desc begin
    t[ProtoId::Llc.0 as usize] = &llc::DESC;
    t[ProtoId::Snap.0 as usize] = &snap::DESC;
    t[ProtoId::Stp.0 as usize] = &stp::DESC;
    t[ProtoId::Lldp.0 as usize] = &lldp::DESC;
    t[ProtoId::Cdp.0 as usize] = &cdp::DESC;
    t[ProtoId::RadioTap.0 as usize] = &radiotap::DESC;
    t[ProtoId::Dot11.0 as usize] = &dot11::DESC;
    t[ProtoId::Dot11Beacon.0 as usize] = &dot11beacon::DESC;
    t[ProtoId::Dot11ProbeReq.0 as usize] = &dot11probereq::DESC;
    t[ProtoId::Dot11ProbeResp.0 as usize] = &dot11proberesp::DESC;
    t[ProtoId::Dot11Auth.0 as usize] = &dot11auth::DESC;
    t[ProtoId::Dot11AssoReq.0 as usize] = &dot11assoreq::DESC;
    t[ProtoId::Dot11AssoResp.0 as usize] = &dot11assoresp::DESC;
    t[ProtoId::Sctp.0 as usize] = &sctp::DESC;
    t[ProtoId::Igmp.0 as usize] = &igmp::DESC;
    t[ProtoId::Icmpv6NdRs.0 as usize] = &icmpv6_rs::DESC;
    t[ProtoId::Icmpv6NdRa.0 as usize] = &icmpv6_ra::DESC;
    t[ProtoId::Icmpv6NdNs.0 as usize] = &icmpv6_ns::DESC;
    t[ProtoId::Icmpv6NdNa.0 as usize] = &icmpv6_na::DESC;
    t[ProtoId::Icmpv6NdRedirect.0 as usize] = &icmpv6_redirect::DESC;
    t[ProtoId::Icmpv6MlQuery.0 as usize] = &mld_query::DESC;
    t[ProtoId::Icmpv6MlReport.0 as usize] = &mld_report::DESC;
    t[ProtoId::Icmpv6MlDone.0 as usize] = &mld_done::DESC;
    t[ProtoId::Icmpv6MlReport2.0 as usize] = &mld_report2::DESC;
    t[ProtoId::Esp.0 as usize] = &esp::DESC;
    t[ProtoId::Ah.0 as usize] = &ah::DESC;
    t[ProtoId::Ospf.0 as usize] = &ospf::DESC;
    t[ProtoId::Rip.0 as usize] = &rip::DESC;
    t[ProtoId::Bgp.0 as usize] = &bgp::DESC;
    t[ProtoId::Vrrp.0 as usize] = &vrrp::DESC;
    t[ProtoId::Hsrp.0 as usize] = &hsrp::DESC;
    t[ProtoId::Bfd.0 as usize] = &bfd::DESC;
    t[ProtoId::Ntp.0 as usize] = &ntp::DESC;
    t[ProtoId::Dhcp6.0 as usize] = &dhcp6::DESC;
    t[ProtoId::Snmp.0 as usize] = &snmp::DESC;
    t[ProtoId::Tftp.0 as usize] = &tftp::DESC;
    t[ProtoId::Syslog.0 as usize] = &syslog::DESC;
    t[ProtoId::Nbns.0 as usize] = &nbns::DESC;
    t[ProtoId::NbtSession.0 as usize] = &nbtsession::DESC;
    t[ProtoId::Radius.0 as usize] = &radius::DESC;
    t[ProtoId::Rtp.0 as usize] = &rtp::DESC;
    t[ProtoId::Rtcp.0 as usize] = &rtcp::DESC;
    t[ProtoId::NetflowV5.0 as usize] = &netflow5::DESC;
    t[ProtoId::NetflowV9.0 as usize] = &netflow9::DESC;
    t[ProtoId::Ipfix.0 as usize] = &ipfix::DESC;
    t[ProtoId::SFlow.0 as usize] = &sflow::DESC;
    t[ProtoId::Quic.0 as usize] = &quic::DESC;
    t[ProtoId::WireGuard.0 as usize] = &wireguard::DESC;
    t[ProtoId::Tls.0 as usize] = &tls::DESC;
    t[ProtoId::Http.0 as usize] = &http::DESC;
    t[ProtoId::Ssh.0 as usize] = &ssh::DESC;
    t[ProtoId::Mqtt.0 as usize] = &mqtt::DESC;
    t[ProtoId::Modbus.0 as usize] = &modbus::DESC;
    t[ProtoId::Smb2.0 as usize] = &smb2::DESC;
    t[ProtoId::Ldap.0 as usize] = &ldap::DESC;
    t[ProtoId::Sip.0 as usize] = &sip::DESC;
    t[ProtoId::Ftp.0 as usize] = &ftp::DESC;
    t[ProtoId::Smtp.0 as usize] = &smtp::DESC;
    t[ProtoId::Imap.0 as usize] = &imap::DESC;
    t[ProtoId::Telnet.0 as usize] = &telnet::DESC;
    // protogen:desc end
    t
};

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

/// Octets of framing a `child` carries when it sits directly under `parent`.
/// RFC 1035 §4.2.2 prefixes a DNS message with its own length over a stream;
/// those two octets belong to neither header alone, so the pair decides. The
/// dissector counts them into the child's header, ahead of every field.
#[inline]
pub fn framing_octets(parent: ProtoId, child: ProtoId) -> usize {
    match (parent, child) {
        (ProtoId::Tcp, ProtoId::Dns) => 2,
        _ => 0,
    }
}

/// Framing moves every field, which a condition cannot express, so it is a
/// second table rather than a second set of conditions.
#[inline]
pub fn fields_of(id: ProtoId, framed: bool) -> &'static [FieldDesc] {
    match (id, framed) {
        (ProtoId::Dns, true) => crate::layers::dns::TCP_FIELDS,
        _ => desc(id).fields,
    }
}

/// Empty for a layer that takes the same layout either way, so the callers below
/// do not walk one table twice.
fn framed_only(id: ProtoId) -> &'static [FieldDesc] {
    let framed = fields_of(id, true);
    if std::ptr::eq(framed, desc(id).fields) {
        &[]
    } else {
        framed
    }
}

/// Ignores conditions and framing, so it sees every field the protocol can ever
/// carry. The descriptor answers questions about the *name* — its kind, width,
/// flags, whether it is computed or conditional. It must not be decoded through:
/// where a layer has two layouts the offsets are only right for one of them, so
/// a read goes via `Packet::active_field`, which knows which layout this packet
/// took.
pub fn field_of(id: ProtoId, name: &str) -> Option<&'static FieldDesc> {
    desc(id)
        .fields
        .iter()
        .chain(framed_only(id))
        .find(|f| f.name == name)
}

pub fn all_field_names(id: ProtoId) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = desc(id).fields.iter().map(|f| f.name).collect();
    for f in framed_only(id) {
        if !out.contains(&f.name) {
            out.push(f.name);
        }
    }
    out
}

pub fn active_fields(
    id: ProtoId,
    framed: bool,
    hdr: &[u8],
) -> impl Iterator<Item = &'static FieldDesc> + '_ {
    fields_of(id, framed)
        .iter()
        .filter(move |f| f.is_active(hdr))
}

/// Two fields may share a name when their conditions are disjoint; the header
/// bytes pick between them.
pub fn active_field_of(
    id: ProtoId,
    framed: bool,
    hdr: &[u8],
    name: &str,
) -> Option<&'static FieldDesc> {
    active_fields(id, framed, hdr).find(|f| f.name == name)
}

/// Names served by a parser rather than by the flat field table.
pub fn accessor_names(id: ProtoId) -> &'static [&'static str] {
    match id {
        // RFC 1035 §4.1
        ProtoId::Dns => &["qd", "an", "ns", "ar"],
        // protogen:accessors begin
        // protogen:accessors end
        _ => &[],
    }
}

/// The field a protocol's `parse_options` answers for. Line-oriented and
/// BER-encoded layers reuse the same parsed-item shape under their own name,
/// so `pkt[HTTP].headers` reads as `pkt[TCP].options` does.
pub fn parsed_field_name(id: ProtoId) -> &'static str {
    match id {
        // protogen:parsed begin
        ProtoId::Lldp => "options",
        ProtoId::Cdp => "msg",
        ProtoId::Snmp => "vars",
        ProtoId::Syslog => "headers",
        ProtoId::Http => "headers",
        ProtoId::Ldap => "vars",
        ProtoId::Sip => "headers",
        ProtoId::Ftp => "lines",
        ProtoId::Smtp => "lines",
        ProtoId::Imap => "lines",
        ProtoId::Telnet => "lines",
        // protogen:parsed end
        _ => "options",
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
    /// RFC 6762 §18.
    pub const MDNS: u16 = 5353;
    /// RFC 4795 §2.
    pub const LLMNR: u16 = 5355;
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
        assert_eq!(desc(ProtoId::Tcp).name, "TCP");
        // The numbering is append-only and may have gaps; what has to hold is
        // that every built-in stays below the count that separates the static
        // table from the registry.
        assert!(BUILTINS.iter().all(|p| p.0 < BUILTIN_COUNT));
        assert!(BUILTINS.iter().all(|p| !p.is_registered()));
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
        assert!(BUILTINS.len() <= BUILTIN_COUNT as usize);
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

    /// Every pair that contributes framing, and every layer that therefore has
    /// a second field table. A layer added without an entry here takes the same
    /// layout under every parent, which is what makes framing invisible to an
    /// author who does not want it — and adding one has to be deliberate.
    const FRAMED: &[(ProtoId, ProtoId)] = &[(ProtoId::Tcp, ProtoId::Dns)];

    #[test]
    fn only_a_declared_pair_carries_framing() {
        for p in (0..BUILTIN_COUNT).map(ProtoId) {
            for c in (0..BUILTIN_COUNT).map(ProtoId) {
                let n = framing_octets(p, c);
                assert_eq!(
                    n > 0,
                    FRAMED.contains(&(p, c)),
                    "{}/{} framing is {n}, which the list does not declare",
                    p.name(),
                    c.name()
                );
            }
        }
        for id in (0..BUILTIN_COUNT).map(ProtoId) {
            let framed = FRAMED.iter().any(|(_, c)| *c == id);
            assert_eq!(
                framed,
                !framed_only(id).is_empty(),
                "{} has a second field table without a pair that reaches it, or the reverse",
                id.name()
            );
        }
    }

    /// A second table shifts the first, so it must still name everything the
    /// first does: a name readable under one parent and missing under another
    /// would be a layout that silently lost a field.
    #[test]
    fn a_framed_table_names_everything_the_plain_one_does() {
        for id in (0..BUILTIN_COUNT).map(ProtoId) {
            let extra = framed_only(id);
            if extra.is_empty() {
                continue;
            }
            for f in desc(id).fields {
                assert!(
                    extra.iter().any(|g| g.name == f.name),
                    "{}.{} is missing from the framed table",
                    id.name(),
                    f.name
                );
            }
        }
    }

    /// A condition is a closure over raw header offsets, and the header a framed
    /// layer is read from starts at the framing, not at the first field. Shifting
    /// the offsets in a second table therefore does not shift its conditions, so
    /// the two cannot be combined until a condition is told where the fields
    /// begin.
    #[test]
    fn no_framed_table_declares_a_conditional_field() {
        for id in (0..BUILTIN_COUNT).map(ProtoId) {
            for f in framed_only(id) {
                assert!(
                    f.cond.is_none(),
                    "{}.{} is conditional in a framed table, where its predicate \
                     would read the framing octets as the first header bytes",
                    id.name(),
                    f.name
                );
            }
        }
    }
}
