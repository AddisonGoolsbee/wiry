// SPDX-License-Identifier: GPL-2.0-only
//
// Derived from scapy: scapy/data.py, scapy/dadict.py, scapy/libs/ethertypes.py, scapy/layers/l2.py
//   scapy 2.7.0
//   Copyright (C) Philippe Biondi and the scapy contributors
//
// Changed by the wiry authors:
//   2026-10-03 — host tables loaded as scapy loads them; the bundled EtherType table transcribed

//! Enumerated field values: the integer-to-name tables behind scapy's
//! `ByteEnumField`, `ShortEnumField`, `BitEnumField`, `MultiEnumField` and
//! their kin. Reading a field yields the integer; the name is for rendering
//! and for accepting `ICMP(type="echo-request")`.

use std::collections::HashMap;
use std::sync::OnceLock;

/// Must be sorted by value: lookups binary-search, so an unsorted table misses.
pub type Table = &'static [(u64, &'static str)];

/// Tables scapy reads from the host at import rather than shipping, so names
/// vary by machine exactly as scapy's do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Host {
    /// `/etc/protocols`; no fallback, so a host without it renders numbers.
    IpProtos,
    /// `/etc/ethertypes`, else the copy scapy bundles.
    EtherTypes,
    /// `/etc/services`, by transport.
    TcpServices,
    UdpServices,
    SctpServices,
}

#[derive(Clone, Copy, Debug)]
pub enum Names {
    None,
    Table(Table),
    Host(Host),
    /// The table is chosen by another field of the same header, at this bit
    /// offset and length: ICMP's code by its type.
    Multi {
        on_off: u16,
        on_len: u16,
        tables: &'static [(u64, Table)],
    },
}

fn find(t: Table, v: u64) -> Option<&'static str> {
    t.binary_search_by_key(&v, |e| e.0).ok().map(|i| t[i].1)
}

/// scapy's `s2i` is the inverse dict built in table order, so where two
/// values share a name the later one wins.
fn rfind(t: Table, s: &str) -> Option<u64> {
    t.iter().rev().find(|e| e.1 == s).map(|e| e.0)
}

impl Names {
    pub fn is_none(&self) -> bool {
        matches!(self, Names::None)
    }

    pub fn name(&self, hdr: &[u8], v: u64) -> Option<&'static str> {
        match *self {
            Names::None => None,
            Names::Table(t) => find(t, v),
            Names::Host(h) => host(h).by_value.get(&v).map(String::as_str),
            Names::Multi {
                on_off,
                on_len,
                tables,
            } => find(sub(tables, selector(hdr, on_off, on_len)?)?, v),
        }
    }

    pub fn value(&self, hdr: &[u8], s: &str) -> Option<u64> {
        match *self {
            Names::None => None,
            Names::Table(t) => rfind(t, s),
            Names::Host(h) => host(h).by_name.get(s).copied(),
            Names::Multi {
                on_off,
                on_len,
                tables,
            } => rfind(sub(tables, selector(hdr, on_off, on_len)?)?, s),
        }
    }

    /// Every (value, name) pair, sorted by value; for a `Multi`, the pairs of
    /// the table this header selects.
    pub fn pairs(&self, hdr: &[u8]) -> Vec<(u64, &'static str)> {
        match *self {
            Names::None => Vec::new(),
            Names::Table(t) => t.to_vec(),
            Names::Host(h) => {
                let mut v: Vec<_> = host(h)
                    .by_value
                    .iter()
                    .map(|(k, s)| (*k, s.as_str()))
                    .collect();
                v.sort_unstable();
                v
            }
            Names::Multi {
                on_off,
                on_len,
                tables,
            } => selector(hdr, on_off, on_len)
                .and_then(|k| sub(tables, k))
                .map(<[_]>::to_vec)
                .unwrap_or_default(),
        }
    }
}

fn selector(hdr: &[u8], on_off: u16, on_len: u16) -> Option<u64> {
    (hdr.len() * 8 >= on_off as usize + on_len as usize)
        .then(|| crate::field::read_bits(hdr, on_off, on_len))
}

fn sub(tables: &'static [(u64, Table)], key: u64) -> Option<Table> {
    tables
        .binary_search_by_key(&key, |e| e.0)
        .ok()
        .map(|i| tables[i].1)
}

struct Loaded {
    by_value: HashMap<u64, String>,
    by_name: HashMap<String, u64>,
}

impl Loaded {
    fn new() -> Self {
        Loaded {
            by_value: HashMap::new(),
            by_name: HashMap::new(),
        }
    }

    fn insert(&mut self, v: u64, name: String) {
        self.by_name.insert(name.clone(), v);
        self.by_value.insert(v, name);
    }
}

/// scapy's `dadict.fixname`: a leading digit gains `n_`, and every other
/// character below U+0100 that is not alphanumeric becomes `_`.
pub fn fixname(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    if s.as_bytes().first().is_some_and(u8::is_ascii_digit) {
        out.push_str("n_");
    }
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || (c as u32) > 0xff {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    out
}

/// `load_protocols`: `name number ...` per line, `#` to end of line ignored.
fn protocols(text: &str, radix: u32, into: &mut Loaded) {
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let mut it = line.split_whitespace();
        let (Some(name), Some(num)) = (it.next(), it.next()) else {
            continue;
        };
        if let Ok(v) = u64::from_str_radix(num, radix) {
            into.insert(v, fixname(name));
        }
    }
}

/// `load_services`: `name port/proto ...`, where the port may be a range.
fn services(text: &str, proto: &str, into: &mut Loaded) {
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let mut it = line.split_whitespace();
        let (Some(name), Some(spec)) = (it.next(), it.next()) else {
            continue;
        };
        let Some((port, p)) = spec.split_once('/') else {
            continue;
        };
        if p != proto {
            continue;
        }
        let name = fixname(name);
        let (lo, hi) = match port.split_once('-') {
            Some((a, b)) => (a.parse::<u64>(), b.parse::<u64>()),
            None => (port.parse::<u64>(), port.parse::<u64>()),
        };
        let (Ok(lo), Ok(hi)) = (lo, hi) else {
            continue;
        };
        // A port is sixteen bits; a wider range in the file names nothing.
        for v in lo..=hi.min(0xffff) {
            into.insert(v, name.clone());
        }
    }
}

fn host(h: Host) -> &'static Loaded {
    static TABLES: [OnceLock<Loaded>; 5] = [
        OnceLock::new(),
        OnceLock::new(),
        OnceLock::new(),
        OnceLock::new(),
        OnceLock::new(),
    ];
    let read = |p: &str| {
        std::fs::read(p)
            .ok()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
    };
    TABLES[h as usize].get_or_init(|| {
        let mut t = Loaded::new();
        match h {
            Host::IpProtos => {
                if let Some(s) = read("/etc/protocols") {
                    protocols(&s, 10, &mut t);
                }
            }
            Host::EtherTypes => {
                match read("/etc/ethertypes") {
                    Some(s) => protocols(&s, 16, &mut t),
                    None => {
                        for (v, n) in BUNDLED_ETHER_TYPES {
                            t.insert(*v, n.to_string());
                        }
                    }
                }
                for (v, n) in ETHER_TYPE_OVERRIDES {
                    t.insert(*v, n.to_string());
                }
            }
            Host::TcpServices | Host::UdpServices | Host::SctpServices => {
                let proto = match h {
                    Host::TcpServices => "tcp",
                    Host::UdpServices => "udp",
                    _ => "sctp",
                };
                if let Some(s) = read("/etc/services") {
                    services(&s, proto, &mut t);
                }
            }
        }
        t
    })
}

/// What `scapy/layers/l2.py` writes over the loaded table before any field
/// copies it. `sixlowpan.py` writes 0xa0ed too, but only after every core
/// field has taken its copy, so it is not here.
static ETHER_TYPE_OVERRIDES: Table = &[
    (0x88a8, "802_1AD"),
    (0x88e5, "802_1AE"),
    (0x88e7, "802_1AH"),
];

/// `scapy/libs/ethertypes.py`, parsed as `load_ethertypes` parses it.
static BUNDLED_ETHER_TYPES: Table = &[
    (4, "n_8023"),
    (512, "PUPAT"),
    (1536, "NS"),
    (1537, "NSAT"),
    (1632, "DLOG1"),
    (1633, "DLOG2"),
    (2048, "IPv4"),
    (2049, "X75"),
    (2050, "NBS"),
    (2051, "ECMA"),
    (2052, "CHAOS"),
    (2053, "X25"),
    (2054, "ARP"),
    (2056, "FRARP"),
    (2989, "VINES"),
    (4096, "TRAIL"),
    (4660, "DCA"),
    (5632, "VALID"),
    (6549, "RCL"),
    (8193, "NHRP"),
    (15364, "NBPCC"),
    (15367, "NBPDG"),
    (16962, "PCS"),
    (19522, "IMLBL"),
    (24577, "MOPDL"),
    (24578, "MOPRC"),
    (24580, "LAT"),
    (24583, "SCA"),
    (24584, "AMBER"),
    (25945, "RAWFR"),
    (28672, "UBDL"),
    (28673, "UBNIU"),
    (28675, "UBNMC"),
    (28677, "UBBST"),
    (28679, "OS9"),
    (28720, "RACAL"),
    (32773, "HP"),
    (32815, "TIGAN"),
    (32840, "DECAM"),
    (32859, "VEXP"),
    (32860, "VPROD"),
    (32861, "ES"),
    (32871, "VEECO"),
    (32873, "ATT"),
    (32890, "MATRA"),
    (32891, "DDE"),
    (32892, "MERIT"),
    (32923, "ATALK"),
    (32966, "PACER"),
    (32981, "SNA"),
    (33010, "RETIX"),
    (33011, "AARP"),
    (33024, "VLAN"),
    (33026, "BOFL"),
    (33072, "HAYES"),
    (33073, "VGLAB"),
    (33079, "IPX"),
    (33087, "MUMPS"),
    (33094, "FLIP"),
    (33097, "NCD"),
    (33098, "ALPHA"),
    (33100, "SNMP"),
    (33149, "XTP"),
    (33150, "SGITW"),
    (33153, "STP"),
    (34525, "IPv6"),
    (34617, "RDP"),
    (34618, "MICP"),
    (34668, "IPAS"),
    (34825, "SLOW"),
    (34827, "PPP"),
    (34887, "MPLS"),
    (34902, "AXIS"),
    (34916, "PPPOE"),
    (34958, "EAPOL"),
    (34978, "AOE"),
    (34984, "QINQ"),
    (35020, "LLDP"),
    (35047, "PBB"),
    (35151, "NSH"),
    (36865, "XNSSM"),
    (36866, "TCPSM"),
    (43690, "DEBNI"),
    (64245, "SONIX"),
    (65280, "VITAL"),
    (65535, "MAX"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixname_matches_scapys() {
        assert_eq!(fixname("http"), "http");
        assert_eq!(fixname("z39.50"), "z39_50");
        assert_eq!(fixname("3com-tsmux"), "n_3com_tsmux");
        assert_eq!(fixname("a\u{e9}"), "a_");
        assert_eq!(fixname("a\u{12c}"), "a\u{12c}");
    }

    #[test]
    fn a_services_range_is_bounded_by_the_port_width() {
        let mut t = Loaded::new();
        services("x 65530-99999999999/tcp\ny 7/udp\n", "tcp", &mut t);
        assert_eq!(t.by_value.len(), 6);
        assert_eq!(t.by_name.get("x"), Some(&65535));
        assert!(!t.by_name.contains_key("y"));
    }

    #[test]
    fn a_multi_table_is_chosen_by_the_other_field() {
        static A: Table = &[(1, "one")];
        static B: Table = &[(1, "uno")];
        static BY: &[(u64, Table)] = &[(3, A), (5, B)];
        let n = Names::Multi {
            on_off: 0,
            on_len: 8,
            tables: BY,
        };
        assert_eq!(n.name(&[3, 1], 1), Some("one"));
        assert_eq!(n.name(&[5, 1], 1), Some("uno"));
        assert_eq!(n.name(&[4, 1], 1), None);
        assert_eq!(n.name(&[], 1), None);
        assert_eq!(n.value(&[5, 0], "uno"), Some(1));
    }

    #[test]
    fn every_built_in_table_is_sorted() {
        let sorted = |t: Table| t.windows(2).all(|w| w[0].0 < w[1].0);
        for p in crate::proto::builtins() {
            for framed in [false, true] {
                for f in crate::proto::fields_of(p, framed) {
                    match f.names {
                        Names::Table(t) => assert!(sorted(t), "{}.{}", p.name(), f.name),
                        Names::Multi { tables, .. } => {
                            assert!(tables.windows(2).all(|w| w[0].0 < w[1].0));
                            for (_, t) in tables {
                                assert!(sorted(t), "{}.{}", p.name(), f.name);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    #[test]
    fn a_shared_name_reads_back_as_the_later_value() {
        let n = Names::Table(&[(1, "x"), (2, "x"), (3, "y")]);
        assert_eq!(n.value(&[], "x"), Some(2));
        assert_eq!(n.name(&[], 1), Some("x"));
        assert_eq!(n.name(&[], 9), None);
    }
}
