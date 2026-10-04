// SPDX-License-Identifier: GPL-2.0-only
//
// Derived from scapy: scapy/packet.py, scapy/fields.py, scapy/layers/*.py
//   scapy 2.7.0
//   Copyright (C) Philippe Biondi and the scapy contributors
//
// Changed by the wiry authors:
//   2026-10-03 — summary(), repr() and show() and each layer's mysummary()
//   transcribed to render from octets and a span table

//! Rendering: how a packet prints. Transcribed from scapy 2.7.0's
//! `Packet.summary`, `Packet.__repr__`, `Packet._show_or_dump` and the
//! `mysummary()` methods of `scapy/layers/*`; see `NOTICE`.
//!
//! It lives in Rust rather than in the facade because `PacketList.summary()`
//! renders a whole capture and must stay one crossing.

use crate::field::{FieldDesc, FieldValue};
use crate::packet::{framing_at, LayerSpan, Packet};
use crate::proto;
use crate::render_tables as tbl;

/// How one field's value prints when it has no enumerated name. `Auto` keeps
/// what the `FieldKind` gives: an address, a flag string, a decimal integer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Repr {
    /// `StrEnumField`: the octets, then their name in parentheses.
    StrEnum(&'static [(&'static [u8], &'static str)]),
    Auto,
    Hex,
    Bytes,
    /// `StrFixedLenField`: trailing NULs are not shown.
    FixedBytes,
    /// `XStrField` and kin: the octets as bare hex digits.
    HexBytes,
    Utc,
    /// `BCDFloatField`: 8.8 fixed point, shown as a float.
    Bcd,
    /// BOOTP's `chaddr`: a MAC address and what pads it to sixteen octets.
    Chaddr,
    /// `IP6ListField`: addresses inside `[ ... ]`; an empty list is omitted
    /// from `repr()` as every empty list is.
    Ip6List,
}

fn lookup(t: &[(u64, &'static str)], v: u64) -> Option<&'static str> {
    t.binary_search_by_key(&v, |e| e.0).ok().map(|i| t[i].1)
}

/// Python's `repr()` of a bytes object, which is what scapy prints for a
/// string field.
pub fn py_bytes(b: &[u8]) -> String {
    let quote = if b.contains(&b'\'') && !b.contains(&b'"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(b.len() + 3);
    out.push('b');
    out.push(quote);
    for &c in b {
        match c {
            b'\\' => out.push_str("\\\\"),
            b'\t' => out.push_str("\\t"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            _ if c == quote as u8 => {
                out.push('\\');
                out.push(quote);
            }
            0x20..=0x7e => out.push(c as char),
            _ => out.push_str(&format!("\\x{c:02x}")),
        }
    }
    out.push(quote);
    out
}

/// A dissected packet as the renderer sees it: the octets plus the span table.
/// Bulk paths dissect to spans without building a `Packet`, so nothing here
/// needs one.
#[derive(Clone, Copy)]
pub struct View<'a> {
    pub buf: &'a [u8],
    pub spans: &'a [LayerSpan],
}

impl<'a> View<'a> {
    pub fn of(pkt: &'a Packet) -> Self {
        View {
            buf: pkt.raw_bytes(),
            spans: pkt.layers(),
        }
    }

    fn header(&self, i: usize) -> &'a [u8] {
        match self.spans.get(i) {
            Some(s) => s.header(self.buf),
            None => &[],
        }
    }

    fn framed(&self, i: usize) -> bool {
        framing_at(self.spans, i) > 0
    }

    fn fields(&self, i: usize) -> &'static [FieldDesc] {
        match self.spans.get(i) {
            Some(s) => proto::fields_of(s.proto, self.framed(i)),
            None => &[],
        }
    }

    fn active(&self, i: usize) -> impl Iterator<Item = &'static FieldDesc> + 'a {
        let hdr = self.header(i);
        self.fields(i).iter().filter(move |f| f.is_active(hdr))
    }

    fn value(&self, i: usize, f: &FieldDesc) -> FieldValue {
        crate::field::decode(self.header(i), f)
    }

    fn name_of(&self, i: usize) -> &'static str {
        self.spans.get(i).map_or("", |s| s.proto.name())
    }

    /// The first layer with this name at or above `from`: scapy resolves
    /// `%Layer.field%` from the layer `sprintf` was called on, outward.
    fn find(&self, from: usize, layer: &str) -> Option<usize> {
        (from..self.spans.len()).find(|i| self.name_of(*i) == layer)
    }

    fn field_named(&self, i: usize, name: &str) -> Option<&'static FieldDesc> {
        self.active(i).find(|f| f.name == name)
    }

    fn uint(&self, i: usize, name: &str) -> Option<u64> {
        let f = self.field_named(i, name)?;
        self.value(i, f).as_uint()
    }

    /// `i2repr`: the value as scapy prints it.
    pub fn field_repr(&self, i: usize, f: &FieldDesc) -> String {
        let layer = self.name_of(i);
        if let Some(s) = self.options_repr(i, layer, f.name) {
            return s;
        }
        let v = self.value(i, f);
        let n = match v {
            FieldValue::Uint(n) => Some(n),
            _ => None,
        };
        if let Some(name) = n.and_then(|n| f.name_of(self.header(i), n)) {
            return name.to_string();
        }
        match (tbl::repr_of(layer, f.name), n, &v) {
            (Repr::Hex, Some(n), _) => format!("0x{n:x}"),
            (Repr::Utc, Some(n), _) => utc(n),
            (Repr::Bcd, Some(n), _) => py_float(n as f64 / 256.0),
            (Repr::FixedBytes, _, FieldValue::Bytes(b)) => {
                let end = b.iter().rposition(|c| *c != 0).map_or(0, |i| i + 1);
                py_bytes(&b[..end])
            }
            (Repr::HexBytes, _, FieldValue::Bytes(b)) => {
                b.iter().map(|c| format!("{c:02x}")).collect()
            }
            (Repr::Chaddr, _, FieldValue::Bytes(b)) => self.chaddr(i, b),
            (Repr::StrEnum(t), _, FieldValue::Bytes(b)) => {
                let end = b.iter().rposition(|c| *c != 0).map_or(0, |i| i + 1);
                let r = &b[..end];
                match t.iter().find(|e| e.0 == &b[..] || e.0 == r) {
                    Some((_, name)) => format!("{} ({name})", py_bytes(r)),
                    None => py_bytes(r),
                }
            }
            (Repr::Ip6List, _, FieldValue::Bytes(b)) => {
                let list: Vec<String> = b
                    .chunks_exact(16)
                    .map(|c| {
                        let mut a = [0u8; 16];
                        a.copy_from_slice(c);
                        crate::show::render_ipv6(&a)
                    })
                    .collect();
                format!("[ {} ]", list.join(", "))
            }
            (_, _, FieldValue::Bytes(b)) => py_bytes(b),
            _ => render_value(&v),
        }
    }

    /// `_BOOTP_chaddr.i2repr`: over Ethernet, the address and then its padding.
    fn chaddr(&self, i: usize, b: &[u8]) -> String {
        if self.uint(i, "htype") != Some(1) || b.len() < 6 {
            let end = b.iter().rposition(|c| *c != 0).map_or(0, |i| i + 1);
            return py_bytes(&b[..end]);
        }
        let mac = b[..6]
            .iter()
            .map(|c| format!("{c:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        if b[6..] == [0u8; 10] {
            format!("{mac} (+ 10 nul pad)")
        } else {
            format!("{mac} (pad: {})", py_bytes(&b[6..]))
        }
    }

    /// The parsed option list, where this field is the one a parser answers.
    fn options_repr(&self, i: usize, layer: &str, field: &str) -> Option<String> {
        let id = self.spans.get(i)?.proto;
        if proto::parsed_field_name(id) != field {
            return None;
        }
        let items = crate::packet::options_at(self.buf, self.spans, i)?;
        Some(if layer == "DHCP" {
            dhcp_options_repr(&items)
        } else {
            let body = items.iter().map(item_repr).collect::<Vec<_>>().join(", ");
            format!("[{body}]")
        })
    }
}

/// scapy keeps a TCP option as a `(name, value)` tuple, so the list prints as
/// Python prints one.
fn item_repr(it: &crate::options::Item) -> String {
    use crate::options::ItemValue;
    let v = match &it.value {
        // scapy's SAckOK carries a zero-length string rather than no value.
        ItemValue::Flag if it.name.as_ref() == "SAckOK" => "b''".to_string(),
        ItemValue::Flag => "None".to_string(),
        other => value_repr(other),
    };
    format!("({}, {})", py_str(&it.name), v)
}

fn value_repr(v: &crate::options::ItemValue) -> String {
    use crate::options::ItemValue;
    match v {
        ItemValue::Flag => "None".to_string(),
        ItemValue::Uint(n) => n.to_string(),
        ItemValue::Pair(a, b) => format!("({a}, {b})"),
        ItemValue::Bytes(b) => py_bytes(b),
        ItemValue::Text(s) => py_str(s),
        ItemValue::Ipv4List(l) => format!(
            "[{}]",
            l.iter()
                .map(|a| py_str(&format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        // A selective-acknowledgement block is one flat tuple in scapy, not a
        // list of pairs.
        ItemValue::Pairs(l) => format!(
            "({})",
            l.iter()
                .flat_map(|(a, b)| [a.to_string(), b.to_string()])
                .collect::<Vec<_>>()
                .join(", ")
        ),
        ItemValue::Items(v) => format!(
            "[{}]",
            v.iter().map(item_repr).collect::<Vec<_>>().join(", ")
        ),
    }
}

/// scapy's `DHCPOptionsField.i2repr`: `name=value`, space separated, and a
/// value-less option as its bare name.
fn dhcp_options_repr(items: &[crate::options::Item]) -> String {
    use crate::options::ItemValue;
    let body = items
        .iter()
        .map(|it| match &it.value {
            ItemValue::Flag => it.name.to_string(),
            ItemValue::Uint(n) if it.name.as_ref() == "message-type" => format!(
                "{}={}",
                it.name,
                lookup(DHCP_TYPES, *n).map_or_else(|| n.to_string(), str::to_string)
            ),
            ItemValue::Uint(n) => format!("{}={n}", it.name),
            // The two options scapy declares as a list of octets.
            ItemValue::Bytes(b)
                if matches!(
                    it.name.as_ref(),
                    "param_req_list" | "forcerenew_nonce_capable"
                ) =>
            {
                format!(
                    "{}=[{}]",
                    it.name,
                    b.iter().map(u8::to_string).collect::<Vec<_>>().join(", ")
                )
            }
            // Every other value scapy keeps is the option's octets.
            ItemValue::Bytes(b) => format!("{}={}", it.name, py_bytes(b)),
            ItemValue::Text(t) => format!("{}={}", it.name, py_bytes(t.as_bytes())),
            ItemValue::Ipv4List(l) => format!(
                "{}={}",
                it.name,
                l.iter()
                    .map(|a| format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            other => format!("{}={}", it.name, value_repr(other)),
        })
        .collect::<Vec<_>>()
        .join(" ");
    format!("[{body}]")
}

/// Python's `repr()` of a float that holds a value of at most 24 significant
/// bits, which is every one a `BCDFloatField` can produce.
fn py_float(x: f64) -> String {
    let s = format!("{x}");
    if s.contains('.') || s.contains('e') || s.contains("inf") || s.contains("NaN") {
        s
    } else {
        s + ".0"
    }
}

/// Python's `repr()` of a str.
pub fn py_str(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ if c == quote => {
                out.push('\\');
                out.push(quote);
            }
            _ => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// scapy's `UTCTimeField`: `%a, %d %b %Y %H:%M:%S %z`, always in UTC here.
fn utc(secs: u64) -> String {
    const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (mut y, mut d) = (1970i64, days);
    loop {
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        let n = if leap { 366 } else { 365 };
        if d < n {
            break;
        }
        d -= n;
        y += 1;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let ml = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut m = 0usize;
    while m < 12 && d >= ml[m] {
        d -= ml[m];
        m += 1;
    }
    format!(
        "{} {:02} {} {} {:02}:{:02}:{:02} +0000",
        DAYS[((days % 7 + 3) % 7) as usize],
        d + 1,
        MONTHS[m.min(11)],
        y,
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
    )
}

pub fn render_value(v: &FieldValue) -> String {
    crate::show::render_value(v)
}

// ---------------------------------------------------------------------------
// summary
// ---------------------------------------------------------------------------

/// One `mysummary()`, as a format string in scapy's own `sprintf` language.
/// `under` restricts the rule to a packet whose enclosing layer is that one,
/// which is how scapy's `isinstance(self.underlayer, IP)` tests read.
pub struct Rule {
    pub under: Option<&'static str>,
    pub when: Option<fn(&View, usize) -> bool>,
    pub fmt: &'static str,
}

const fn rule(fmt: &'static str) -> Rule {
    Rule {
        under: None,
        when: None,
        fmt,
    }
}

const fn under(u: &'static str, fmt: &'static str) -> Rule {
    Rule {
        under: Some(u),
        when: None,
        fmt,
    }
}

const fn when(w: fn(&View, usize) -> bool, fmt: &'static str) -> Rule {
    Rule {
        under: None,
        when: Some(w),
        fmt,
    }
}

fn arp_request(v: &View, i: usize) -> bool {
    v.uint(i, "op") == Some(1)
}

fn arp_reply(v: &View, i: usize) -> bool {
    v.uint(i, "op") == Some(2)
}

/// RFC 7348 §5 reserves the high bit of `flags` for the VNI; scapy's GPE
/// variant reads the G bit as the next one down.
fn vxlan_gpid(v: &View, i: usize) -> bool {
    v.uint(i, "flags").unwrap_or(0) & (1 << 7) != 0
}

const ETHER: &[Rule] = &[rule("%src% > %dst% (%type%)")];
const DOT1Q: &[Rule] = &[
    under(
        "Ether",
        "802.1q %Ether.src% > %Ether.dst% (%Dot1Q.type%) vlan %Dot1Q.vlan%",
    ),
    rule("802.1q (%Dot1Q.type%) vlan %Dot1Q.vlan%"),
];
const ARP: &[Rule] = &[
    when(arp_request, "ARP who has %pdst% says %psrc%"),
    when(arp_reply, "ARP is at %hwsrc% says %psrc%"),
    rule("ARP %op% %psrc% > %pdst%"),
];
const IP: &[Rule] = &[rule("%IP.src% > %IP.dst% %IP.proto%")];
const IPV6: &[Rule] = &[rule("%IPv6.src% > %IPv6.dst% (%i,IPv6.nh%)")];
const TCP: &[Rule] = &[
    under(
        "IP",
        "TCP %IP.src%:%TCP.sport% > %IP.dst%:%TCP.dport% %TCP.flags%",
    ),
    under(
        "IPv6",
        "TCP %IPv6.src%:%TCP.sport% > %IPv6.dst%:%TCP.dport% %TCP.flags%",
    ),
    rule("TCP %TCP.sport% > %TCP.dport% %TCP.flags%"),
];
const UDP: &[Rule] = &[
    under("IP", "UDP %IP.src%:%UDP.sport% > %IP.dst%:%UDP.dport%"),
    under(
        "IPv6",
        "UDP %IPv6.src%:%UDP.sport% > %IPv6.dst%:%UDP.dport%",
    ),
    rule("UDP %UDP.sport% > %UDP.dport%"),
];
const ICMP: &[Rule] = &[
    under("IP", "ICMP %IP.src% > %IP.dst% %ICMP.type% %ICMP.code%"),
    rule("ICMP %ICMP.type% %ICMP.code%"),
];
const IGMP: &[Rule] = &[
    under("IP", "IGMP: %IP.src% > %IP.dst% %IGMP.type% %IGMP.gaddr%"),
    rule("IGMP %IGMP.type% %IGMP.gaddr%"),
];
const VXLAN: &[Rule] = &[
    when(vxlan_gpid, "VXLAN (vni=%VXLAN.vni% gpid=%VXLAN.gpid%)"),
    rule("VXLAN (vni=%VXLAN.vni%)"),
];
const GENEVE: &[Rule] = &[rule(
    "GENEVE (vni=%GENEVE.vni%,optionlen=%GENEVE.optionlen%,proto=%GENEVE.proto%)",
)];
const PPPOED: &[Rule] = &[rule("%code%")];
const BFD: &[Rule] = &[rule(
    "BFD (my_disc=%BFD.my_discriminator%,your_disc=%BFD.your_discriminator%,state=%BFD.sta%)",
)];
const NTP: &[Rule] = &[rule("NTP v%i,NTP.version%, %NTP.mode%")];
const DOT11: &[Rule] = &[rule(
    "802.11 %Dot11.type% %Dot11.subtype% %Dot11.addr2% > %Dot11.addr1%",
)];
const ND_TGT: &[Rule] = &[rule("%name% (tgt: %tgt%)")];
const ND_RA: &[Rule] = &[rule(
    "%name% Lifetime %routerlifetime% Hop Limit %chlim% Preference %prf% \
     Managed %M% Other %O% Home %H%",
)];

/// Transcribed from the `mysummary()` of each layer in scapy 2.7.0.
fn rules(layer: &str) -> &'static [Rule] {
    match layer {
        "Ether" => ETHER,
        "Dot1Q" => DOT1Q,
        "ARP" => ARP,
        "IP" => IP,
        "IPv6" => IPV6,
        "TCP" => TCP,
        "UDP" => UDP,
        "ICMP" => ICMP,
        "IGMP" => IGMP,
        "VXLAN" => VXLAN,
        "GENEVE" => GENEVE,
        "PPPoED" => PPPOED,
        "BFD" => BFD,
        "NTP" => NTP,
        "Dot11" => DOT11,
        "ICMPv6ND_NS" | "ICMPv6ND_NA" => ND_TGT,
        "ICMPv6ND_RA" => ND_RA,
        _ => &[],
    }
}

/// `%[i,][Layer.]field%`, plus `%name%` for the layer's display name, as
/// `sprintf` on layer `i` reads them. An `i` modifier substitutes the raw value
/// rather than its `i2repr`, which is what scapy's `%ir,...%` does.
fn expand(v: &View, i: usize, fmt: &str) -> String {
    let mut out = String::with_capacity(fmt.len() + 24);
    let mut rest = fmt;
    while let Some(a) = rest.find('%') {
        out.push_str(&rest[..a]);
        let after = &rest[a + 1..];
        let Some(b) = after.find('%') else {
            out.push_str(&rest[a..]);
            return out;
        };
        let body = &after[..b];
        rest = &after[b + 1..];
        if body.is_empty() {
            out.push('%');
            continue;
        }
        let (raw, body) = match body.strip_prefix("i,") {
            Some(r) => (true, r),
            None => (false, body),
        };
        if body == "name" {
            out.push_str(tbl::display_name(v.name_of(i)));
            continue;
        }
        let (at, name) = match body.split_once('.') {
            Some((l, f)) => (v.find(i, l), f),
            None => (Some(i), body),
        };
        match at.and_then(|j| v.field_named(j, name).map(|f| (j, f))) {
            Some((j, f)) if raw => out.push_str(
                &v.value(j, f)
                    .as_uint()
                    .map_or_else(|| render_value(&v.value(j, f)), |n| n.to_string()),
            ),
            Some((j, f)) => out.push_str(&v.field_repr(j, f)),
            None => out.push_str("??"),
        }
    }
    out.push_str(rest);
    out
}

/// scapy's per-layer `mysummary()`, empty where the layer has none.
fn mysummary(v: &View, i: usize) -> String {
    let layer = v.name_of(i);
    if let Some(s) = special_summary(v, i, layer) {
        return s;
    }
    let under = i.checked_sub(1).map(|j| v.name_of(j));
    for r in rules(layer) {
        if let Some(u) = r.under {
            if under != Some(u) {
                continue;
            }
        }
        if let Some(w) = r.when {
            if !w(v, i) {
                continue;
            }
        }
        // A rule that names the enclosing layer is that layer's `sprintf`.
        let base = if r.under.is_some() { i - 1 } else { i };
        let mut s = expand(v, base, r.fmt);
        // scapy appends the fragment offset to IP's summary when it is set.
        if layer == "IP" {
            if let Some(frag) = v.uint(i, "frag").filter(|f| *f != 0) {
                s.push_str(&format!(" frag:{frag}"));
            }
        }
        return s;
    }
    String::new()
}

/// The `mysummary()` bodies that are not a format string.
fn special_summary(v: &View, i: usize, layer: &str) -> Option<String> {
    match layer {
        "DNS" => Some(dns_summary(v, i)),
        "DHCP" => Some(dhcp_summary(v, i)),
        _ => None,
    }
}

/// scapy renders a DNS name as the `bytes` it keeps it in, trailing dot and
/// all, so the summary carries a `b'...'`.
fn dns_summary(v: &View, i: usize) -> String {
    use crate::layers::dns;
    let mdns = i
        .checked_sub(1)
        .filter(|j| v.name_of(*j) == "UDP")
        .and_then(|j| v.uint(j, "dport"))
        == Some(5353);
    let body = match v.spans.get(i) {
        Some(s) => {
            let n = framing_at(v.spans, i);
            let a = (s.off as usize + n).min(v.buf.len());
            &v.buf[a..]
        }
        None => &[],
    };
    let recs = dns::parse_records(body);
    let mut name = String::new();
    let kind = if v.uint(i, "qr").unwrap_or(0) != 0 {
        match recs.an.first() {
            Some(rr) => name = format!(" {}", rdata_str(&rr.rdata)),
            None => {
                if let Some(f) = v.field_named(i, "rcode") {
                    if v.value(i, f).as_uint() != Some(0) {
                        name = format!(" {}", v.field_repr(i, f));
                    }
                }
            }
        }
        "Ans"
    } else {
        if let Some(q) = recs.qd.first() {
            name = format!(" {}", py_bytes(q.qname.as_bytes()));
        }
        "Qry"
    };
    format!("{}DNS {}{}", if mdns { "m" } else { "" }, kind, name)
}

fn rdata_str(rd: &crate::layers::dns::RData) -> String {
    use crate::layers::dns::RData;
    match rd {
        RData::A(b) => format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]),
        RData::Aaaa(b) => crate::show::render_ipv6(b),
        RData::Name(n) => py_bytes(n.as_bytes()),
        RData::Other(b) => py_bytes(b),
        other => format!("{other:?}"),
    }
}

/// RFC 2132 §9.6 message types, as scapy's `DHCPTypes` names them.
static DHCP_TYPES: &[(u64, &str)] = &[
    (1, "discover"),
    (2, "offer"),
    (3, "request"),
    (4, "decline"),
    (5, "ack"),
    (6, "nak"),
    (7, "release"),
    (8, "inform"),
    (9, "force_renew"),
    (10, "lease_query"),
    (11, "lease_unassigned"),
    (12, "lease_unknown"),
    (13, "lease_active"),
];

fn dhcp_summary(v: &View, i: usize) -> String {
    use crate::options::ItemValue;
    let Some(items) = crate::packet::options_at(v.buf, v.spans, i) else {
        return String::new();
    };
    for it in &items {
        if it.name.as_ref() != "message-type" {
            continue;
        }
        let ItemValue::Uint(n) = it.value else {
            continue;
        };
        let name = lookup(DHCP_TYPES, n).unwrap_or("");
        let mut c = name.chars();
        let capitalised = match c.next() {
            Some(f) => f.to_uppercase().collect::<String>() + &c.as_str().to_lowercase(),
            None => String::new(),
        };
        return format!("DHCP {capitalised}");
    }
    String::new()
}

/// scapy's `Packet._do_summary`: only the outermost `mysummary()` that returns
/// something is used; every layer under it contributes just its name.
pub fn summary_of(buf: &[u8], spans: &[LayerSpan]) -> String {
    let v = View { buf, spans };
    let shown = visible_layers(&v);
    let mut found = false;
    let mut s = String::new();
    for &i in shown.iter().rev() {
        let mut ret = if found {
            String::new()
        } else {
            mysummary(&v, i)
        };
        if !ret.is_empty() {
            found = true;
        } else {
            // scapy falls back to the class name, which is what wiry calls the
            // layer; `display_name` is the other one, used only by `show()`.
            ret = v.name_of(i).to_string();
        }
        if !s.is_empty() {
            ret.push_str(" / ");
            ret.push_str(&s);
        }
        s = ret;
    }
    s
}

pub fn summary(pkt: &Packet) -> String {
    summary_of(pkt.raw_bytes(), pkt.layers())
}

// ---------------------------------------------------------------------------
// DNS record sections, which scapy shows as nested packets
// ---------------------------------------------------------------------------

/// RFC 1035 §3.2.4, as scapy's `dnsclasses` names them.
static DNS_CLASSES: &[(u64, &str)] = &[(1, "IN"), (2, "CS"), (3, "CH"), (4, "HS"), (255, "ANY")];

struct Sub {
    name: &'static str,
    fields: Vec<(&'static str, String)>,
}

fn class_name(c: u16) -> String {
    let low = (c & 0x7fff) as u64;
    lookup(DNS_CLASSES, low).map_or_else(|| low.to_string(), str::to_string)
}

fn type_name(t: u16) -> String {
    match crate::layers::dns::rtype_name(t) {
        "UNKNOWN" => t.to_string(),
        n => n.to_string(),
    }
}

fn question_sub(q: &crate::layers::dns::Question) -> Sub {
    Sub {
        name: "DNSQR",
        fields: vec![
            ("qname", py_bytes(q.qname.as_bytes())),
            ("qtype", type_name(q.qtype)),
            ("unicastresponse", (q.qclass >> 15).to_string()),
            ("qclass", class_name(q.qclass)),
        ],
    }
}

/// scapy recomputes `rdlen` on build, so a dissected record holds `None` for
/// it: `show()` prints that and `repr()` leaves it out.
fn record_sub(rr: &crate::layers::dns::ResourceRecord) -> Sub {
    Sub {
        name: "DNSRR",
        fields: vec![
            ("rrname", py_bytes(rr.rrname.as_bytes())),
            ("type", type_name(rr.rtype)),
            ("cacheflush", (rr.rclass >> 15).to_string()),
            ("rclass", class_name(rr.rclass)),
            ("ttl", rr.ttl.to_string()),
            ("rdlen", "None".to_string()),
            ("rdata", rdata_str(&rr.rdata)),
        ],
    }
}

/// wiry dissects a DNS message as a twelve-octet header plus the record
/// section as payload; scapy makes the sections fields of the layer, so the
/// renderer folds that payload back in and the `Raw` under it disappears.
fn dns_sections(v: &View, i: usize) -> Option<Vec<(&'static str, Vec<Sub>)>> {
    if v.name_of(i) != "DNS" {
        return None;
    }
    let s = v.spans.get(i)?;
    let n = framing_at(v.spans, i);
    let body = v.buf.get((s.off as usize + n).min(v.buf.len())..)?;
    let recs = crate::layers::dns::parse_records(body);
    let rrs =
        |l: &[crate::layers::dns::ResourceRecord]| l.iter().map(record_sub).collect::<Vec<_>>();
    Some(vec![
        ("qd", recs.qd.iter().map(question_sub).collect()),
        ("an", rrs(&recs.an)),
        ("ns", rrs(&recs.ns)),
        ("ar", rrs(&recs.ar)),
    ])
}

/// True where this layer's payload is already displayed as part of it.
fn folds_payload(v: &View, i: usize) -> bool {
    v.name_of(i) == "DNS" && v.spans.get(i + 1).is_some_and(|s| s.proto.name() == "Raw")
}

fn visible_layers(v: &View) -> Vec<usize> {
    (0..v.spans.len())
        .filter(|i| !i.checked_sub(1).is_some_and(|j| folds_payload(v, j)))
        .collect()
}

// ---------------------------------------------------------------------------
// repr
// ---------------------------------------------------------------------------

/// scapy omits an empty list from `repr()`. Of wiry's fields only the one an
/// option parser answers is a list there; an empty string still prints.
fn empty_list(v: &View, i: usize, f: &FieldDesc) -> bool {
    let Some(s) = v.spans.get(i) else {
        return false;
    };
    let layer = v.name_of(i);
    if tbl::repr_of(layer, f.name) == Repr::Ip6List {
        return matches!(v.value(i, f), FieldValue::Bytes(b) if b.is_empty());
    }
    if proto::parsed_field_name(s.proto) != f.name {
        return false;
    }
    if tbl::scalar(layer, f.name) {
        return false;
    }
    crate::packet::options_at(v.buf, v.spans, i).map_or(true, |items| items.is_empty())
}

/// For a packet still being built, which fields each layer was given. A layer
/// past the end of the list was not built from arguments, so all of it shows.
#[derive(Clone, Copy)]
pub struct Given<'a>(pub &'a [Vec<String>]);

impl Given<'_> {
    fn set(&self, i: usize, name: &str) -> Option<bool> {
        self.0.get(i).map(|l| l.iter().any(|n| n == name))
    }
}

/// Whether a layer being built shows this field: the caller set it or the
/// layer above overloads it.
fn given_or_overloaded(v: &View, given: Option<Given>, i: usize, name: &str) -> bool {
    let Some(g) = given else {
        return true;
    };
    match g.set(i, name) {
        None | Some(true) => true,
        Some(false) => v
            .spans
            .get(i + 1)
            .is_some_and(|n| tbl::overloads(v.name_of(i), n.proto.name()).contains(&name)),
    }
}

fn sub_repr(s: &Sub) -> String {
    let mut out = format!("<{} ", s.name);
    // A dissected record does not hold its `rdlen`; see `record_sub`.
    for (n, v) in s.fields.iter().filter(|(n, _)| *n != "rdlen") {
        out.push_str(&format!(" {n}={v}"));
    }
    out.push_str(" |>");
    out
}

pub fn repr_of(buf: &[u8], spans: &[LayerSpan], given: Option<Given>) -> String {
    let v = View { buf, spans };
    let shown = visible_layers(&v);
    let mut out = String::new();
    for &i in &shown {
        out.push('<');
        out.push_str(v.name_of(i));
        out.push(' ');
        let layer = v.name_of(i);
        for f in v.active(i) {
            if tbl::holds_packets(layer, f.name) {
                continue;
            }
            if !given_or_overloaded(&v, given, i, f.name) || empty_list(&v, i, f) {
                continue;
            }
            out.push(' ');
            out.push_str(f.name);
            out.push('=');
            out.push_str(&v.field_repr(i, f));
        }
        for (name, list) in dns_sections(&v, i).unwrap_or_default() {
            if list.is_empty() {
                continue;
            }
            out.push_str(&format!(
                " {name}=[{}]",
                list.iter().map(sub_repr).collect::<Vec<_>>().join(", ")
            ));
        }
        out.push_str(" |");
    }
    for _ in &shown {
        out.push('>');
    }
    out
}

pub fn repr_packet(pkt: &Packet) -> String {
    repr_of(pkt.raw_bytes(), pkt.layers(), None)
}

// ---------------------------------------------------------------------------
// show
// ---------------------------------------------------------------------------

fn show_field(out: &mut String, lvl: &str, name: &str, text: &str) {
    let pad = " ".repeat(10usize.saturating_sub(name.len()));
    let cont = "\n".to_string() + &" ".repeat(lvl.len() + name.len() + 4);
    out.push_str(&format!(
        "{lvl}  {name}{pad}= {}\n",
        text.replace('\n', &cont)
    ));
}

pub fn show_of(buf: &[u8], spans: &[LayerSpan], given: Option<Given>) -> String {
    let v = View { buf, spans };
    let shown = visible_layers(&v);
    let mut out = String::new();
    for (depth, &i) in shown.iter().enumerate() {
        let lvl = " ".repeat(3 * depth);
        let layer = v.name_of(i);
        out.push_str(&format!("###[ {} ]###\n", tbl::display_name(layer)));
        let section = |out: &mut String, name: &str, list: &[Sub]| {
            let pad = " ".repeat(10usize.saturating_sub(name.len()));
            out.push_str(&format!("{lvl}  \\{name}{pad}\\\n"));
            let label = format!("{lvl}   |");
            for sub in list {
                out.push_str(&format!(
                    "{label}###[ {} ]###\n",
                    tbl::display_name(sub.name)
                ));
                for (n, val) in &sub.fields {
                    show_field(out, &label, n, val);
                }
            }
        };
        for f in v.active(i) {
            if tbl::holds_packets(layer, f.name) {
                section(&mut out, f.name, &[]);
                continue;
            }
            let text = if !given_or_overloaded(&v, given, i, f.name)
                && tbl::unset_is_none(layer, f.name)
            {
                "None".to_string()
            } else {
                v.field_repr(i, f)
            };
            show_field(&mut out, &lvl, f.name, &text);
        }
        for (name, list) in dns_sections(&v, i).unwrap_or_default() {
            section(&mut out, name, &list);
        }
    }
    out
}

pub fn show(pkt: &Packet) -> String {
    show_of(pkt.raw_bytes(), pkt.layers(), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_repr_matches_python() {
        assert_eq!(py_bytes(b""), "b''");
        assert_eq!(py_bytes(b"ab"), "b'ab'");
        assert_eq!(py_bytes(b"\x00\n\\"), "b'\\x00\\n\\\\'");
        assert_eq!(py_bytes(b"it's"), "b\"it's\"");
        assert_eq!(py_bytes(b"it's \"q\""), "b'it\\'s \"q\"'");
    }

    #[test]
    fn utc_renders_the_epoch() {
        assert_eq!(utc(0), "Thu 01 Jan 1970 00:00:00 +0000");
        assert_eq!(utc(1_000_000_000), "Sun 09 Sep 2001 01:46:40 +0000");
    }
}
