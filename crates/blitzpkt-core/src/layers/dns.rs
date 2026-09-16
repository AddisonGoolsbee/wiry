//! DNS. Fixed 12-byte message header from RFC 1035 section 4.1.1:
//!
//! ```text
//!                                 1  1  1  1  1  1
//!   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                      ID                       |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                    QDCOUNT                    |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                    ANCOUNT                    |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                    NSCOUNT                    |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                    ARCOUNT                    |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! ```
//!
//! The question and resource-record sections that follow are variable length and
//! use name compression (RFC 1035 §4.1.4). They stay an opaque `Raw` payload for
//! the byte-level layer model, and are decoded separately by [`parse_records`],
//! which takes the whole message because compression pointers are offsets from the
//! start of the header. See DEVIATIONS.md E8.

use crate::field::FieldDesc;
use crate::proto::{Next, ProtoDesc, ProtoId};

pub static FIELDS: &[FieldDesc] = &[
    FieldDesc::uint("id", 0, 16, 0),
    FieldDesc::uint("qr", 16, 1, 0),
    FieldDesc::uint("opcode", 17, 4, 0),
    FieldDesc::uint("aa", 21, 1, 0),
    FieldDesc::uint("tc", 22, 1, 0),
    FieldDesc::uint("rd", 23, 1, 1),
    FieldDesc::uint("ra", 24, 1, 0),
    FieldDesc::uint("z", 25, 3, 0),
    FieldDesc::uint("rcode", 28, 4, 0),
    FieldDesc::uint("qdcount", 32, 16, 1),
    FieldDesc::uint("ancount", 48, 16, 0),
    FieldDesc::uint("nscount", 64, 16, 0),
    FieldDesc::uint("arcount", 80, 16, 0),
];

fn header_len(_: &[u8]) -> usize {
    12
}

fn next(_: &[u8]) -> Next {
    Next::Raw
}

pub static DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Dns,
    name: "DNS",
    fields: FIELDS,
    min_len: 12,
    header_len,
    next,
    build_len: 12,
    parse_options: None,
    bind_next: None,
};

/// TYPE values from the IANA "Resource Record (RR) TYPEs" registry. The first
/// eight are the ones [`parse_records`] decodes into structured [`RData`].
pub mod rtype {
    pub const A: u16 = 1;
    pub const NS: u16 = 2;
    pub const CNAME: u16 = 5;
    pub const SOA: u16 = 6;
    pub const PTR: u16 = 12;
    pub const MX: u16 = 15;
    pub const TXT: u16 = 16;
    pub const AAAA: u16 = 28;
    pub const SRV: u16 = 33;
    pub const OPT: u16 = 41;
    pub const DS: u16 = 43;
    pub const RRSIG: u16 = 46;
    pub const NSEC: u16 = 47;
    pub const DNSKEY: u16 = 48;
    pub const AXFR: u16 = 252;
    pub const ANY: u16 = 255;
    pub const CAA: u16 = 257;
}

/// Mnemonic for a TYPE (or QTYPE) value; `"UNKNOWN"` for anything unregistered here.
pub fn rtype_name(t: u16) -> &'static str {
    match t {
        rtype::A => "A",
        rtype::NS => "NS",
        rtype::CNAME => "CNAME",
        rtype::SOA => "SOA",
        rtype::PTR => "PTR",
        rtype::MX => "MX",
        rtype::TXT => "TXT",
        rtype::AAAA => "AAAA",
        rtype::SRV => "SRV",
        rtype::OPT => "OPT",
        rtype::DS => "DS",
        rtype::RRSIG => "RRSIG",
        rtype::NSEC => "NSEC",
        rtype::DNSKEY => "DNSKEY",
        rtype::AXFR => "AXFR",
        rtype::ANY => "ANY",
        rtype::CAA => "CAA",
        _ => "UNKNOWN",
    }
}

/// One entry of the question section (RFC 1035 §4.1.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// One entry of the answer/authority/additional sections (RFC 1035 §4.1.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    pub rrname: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: RData,
}

/// Decoded RDATA. Types outside the decoded set, and any RDATA that fails its own
/// consistency checks, land in `Other` with the raw bytes so nothing is lost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A([u8; 4]),
    Aaaa([u8; 16]),
    /// CNAME, NS, PTR: a single <domain-name>.
    Name(String),
    Txt(Vec<String>),
    Mx {
        pref: u16,
        exchange: String,
    },
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Other(Vec<u8>),
}

/// The four record sections of a message, in wire order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Records {
    pub qd: Vec<Question>,
    pub an: Vec<ResourceRecord>,
    pub ns: Vec<ResourceRecord>,
    pub ar: Vec<ResourceRecord>,
}

/// Compression-pointer jumps allowed while decoding one name. Jumps are already
/// required to go strictly backwards, which alone makes loops impossible; this cap
/// is a second, independent bound so a long descending pointer chain cannot make
/// decoding quadratic.
const MAX_JUMPS: usize = 64;

/// RFC 1035 §2.3.4: a domain name is at most 255 octets on the wire. Counting the
/// length octets as we go also bounds the work a compressed name can cause.
const MAX_NAME_OCTETS: usize = 255;

fn be16(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off + 2)?;
    Some(u16::from_be_bytes([s[0], s[1]]))
}

fn be32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// Decode the <domain-name> starting at `pos` in the whole message `msg`.
///
/// Returns the presentation-form name and the offset just past the name *in the
/// original stream* (i.e. past the first pointer, if the name was compressed).
/// `None` means the name is truncated or malformed and the caller should stop
/// parsing the section.
///
/// The root name (a lone zero octet) renders as the empty string, and no name
/// carries a trailing dot: `example.com`, not `example.com.`. Label bytes are
/// rendered with lossy UTF-8 and dots inside a label are not escaped.
fn read_name(msg: &[u8], pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<&[u8]> = Vec::new();
    let mut at = pos;
    let mut end: Option<usize> = None;
    let mut jumps = 0usize;
    let mut octets = 0usize;

    loop {
        let len = *msg.get(at)?;
        match len & 0xc0 {
            // Normal label: a length octet 0..=63 followed by that many bytes.
            0x00 => {
                if len == 0 {
                    end.get_or_insert(at + 1);
                    break;
                }
                let start = at + 1;
                let stop = start + len as usize;
                labels.push(msg.get(start..stop)?);
                octets += len as usize + 1;
                if octets > MAX_NAME_OCTETS {
                    return None;
                }
                at = stop;
            }
            // Compression pointer: 14-bit offset from the start of the message.
            0xc0 => {
                let lo = *msg.get(at + 1)?;
                let target = (((len & 0x3f) as usize) << 8) | lo as usize;
                end.get_or_insert(at + 2);
                jumps += 1;
                // RFC 1035 §4.1.4 pointers refer to a *prior* occurrence, so a
                // target at or after the pointer itself is invalid. Rejecting it
                // makes self-referencing and mutually-referencing pointers
                // terminate instead of looping forever.
                if jumps > MAX_JUMPS || target >= at {
                    return None;
                }
                at = target;
            }
            // 0b01 and 0b10 label types are reserved (RFC 1035 §4.1.4; the 0b01
            // extended-label experiment was deprecated by RFC 6891).
            _ => return None,
        }
    }

    let name = labels
        .iter()
        .map(|l| String::from_utf8_lossy(l))
        .collect::<Vec<_>>()
        .join(".");
    Some((name, end?))
}

/// [`read_name`] for a name that must lie inside an RDATA region ending at `end`.
/// A name's own encoding (pointer included) never extends past its RDATA, so a
/// name that does is a malformed RDLENGTH reaching into the next record.
fn read_name_within(msg: &[u8], pos: usize, end: usize) -> Option<(String, usize)> {
    if pos > end {
        return None;
    }
    let (name, next) = read_name(msg, pos)?;
    if next > end {
        return None;
    }
    Some((name, next))
}

fn read_question(msg: &[u8], pos: usize) -> Option<(Question, usize)> {
    let (qname, pos) = read_name(msg, pos)?;
    let qtype = be16(msg, pos)?;
    let qclass = be16(msg, pos + 2)?;
    Some((
        Question {
            qname,
            qtype,
            qclass,
        },
        pos + 4,
    ))
}

fn read_rr(msg: &[u8], pos: usize) -> Option<(ResourceRecord, usize)> {
    let (rrname, pos) = read_name(msg, pos)?;
    let rtype = be16(msg, pos)?;
    let rclass = be16(msg, pos + 2)?;
    let ttl = be32(msg, pos + 4)?;
    let rdlength = be16(msg, pos + 8)? as usize;
    let rdstart = pos + 10;
    let rdend = rdstart.checked_add(rdlength)?;
    if rdend > msg.len() {
        return None;
    }
    let rdata = decode_rdata(msg, rtype, rdstart, rdend);
    Some((
        ResourceRecord {
            rrname,
            rtype,
            rclass,
            ttl,
            rdata,
        },
        rdend,
    ))
}

fn decode_rdata(msg: &[u8], rtype: u16, start: usize, end: usize) -> RData {
    let raw = &msg[start..end];
    let other = || RData::Other(raw.to_vec());
    match rtype {
        rtype::A => match <[u8; 4]>::try_from(raw) {
            Ok(a) => RData::A(a),
            Err(_) => other(),
        },
        rtype::AAAA => match <[u8; 16]>::try_from(raw) {
            Ok(a) => RData::Aaaa(a),
            Err(_) => other(),
        },
        rtype::NS | rtype::CNAME | rtype::PTR => match read_name_within(msg, start, end) {
            Some((n, _)) => RData::Name(n),
            None => other(),
        },
        rtype::MX => match (be16(msg, start), read_name_within(msg, start + 2, end)) {
            (Some(pref), Some((exchange, _))) => RData::Mx { pref, exchange },
            _ => other(),
        },
        rtype::TXT => decode_txt(raw).map_or_else(other, RData::Txt),
        rtype::SOA => decode_soa(msg, start, end).unwrap_or_else(other),
        _ => other(),
    }
}

/// RDATA of TXT is one or more <character-string>s (RFC 1035 §3.3.14), each a
/// length octet followed by that many bytes. Contents are arbitrary octets, so
/// they are rendered with lossy UTF-8.
fn decode_txt(raw: &[u8]) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < raw.len() {
        let len = raw[i] as usize;
        let start = i + 1;
        let stop = start.checked_add(len)?;
        let s = raw.get(start..stop)?;
        out.push(String::from_utf8_lossy(s).into_owned());
        i = stop;
    }
    Some(out)
}

fn decode_soa(msg: &[u8], start: usize, end: usize) -> Option<RData> {
    let (mname, pos) = read_name_within(msg, start, end)?;
    let (rname, pos) = read_name_within(msg, pos, end)?;
    if pos + 20 > end {
        return None;
    }
    Some(RData::Soa {
        mname,
        rname,
        serial: be32(msg, pos)?,
        refresh: be32(msg, pos + 4)?,
        retry: be32(msg, pos + 8)?,
        expire: be32(msg, pos + 12)?,
        minimum: be32(msg, pos + 16)?,
    })
}

/// Parse the question and resource-record sections of a DNS message.
///
/// `msg` must be the whole message starting at the 12-byte header, because
/// compression pointers are offsets from that origin.
///
/// Truncated or malformed input is normal (snaplen-clipped captures, hostile
/// senders), so parsing stops at the first record that cannot be decoded and
/// whatever was read up to that point is returned rather than an error. The
/// section counts in the header are an upper bound only; records are consumed
/// until the data runs out.
pub fn parse_records(msg: &[u8]) -> Records {
    let mut out = Records::default();
    if msg.len() < 12 {
        return out;
    }
    let counts = [
        be16(msg, 4).unwrap_or(0) as usize,
        be16(msg, 6).unwrap_or(0) as usize,
        be16(msg, 8).unwrap_or(0) as usize,
        be16(msg, 10).unwrap_or(0) as usize,
    ];

    let mut pos = 12usize;
    for _ in 0..counts[0] {
        match read_question(msg, pos) {
            Some((q, next)) => {
                out.qd.push(q);
                pos = next;
            }
            None => return out,
        }
    }

    let mut sections: [Vec<ResourceRecord>; 3] = Default::default();
    'sections: for (i, section) in sections.iter_mut().enumerate() {
        for _ in 0..counts[i + 1] {
            match read_rr(msg, pos) {
                Some((rr, next)) => {
                    section.push(rr);
                    pos = next;
                }
                None => break 'sections,
            }
        }
    }
    let [an, ns, ar] = sections;
    out.an = an;
    out.ns = ns;
    out.ar = ar;
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldValue;
    use crate::packet::Packet;

    /// Standard recursive query for "a.com" A/IN, hand-built from RFC 1035 §4.1.
    /// Flags 0x0100: QR=0, OPCODE=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0.
    fn query() -> Vec<u8> {
        let mut v = vec![
            0xab, 0xcd, // id
            0x01, 0x00, // flags
            0x00, 0x01, // qdcount
            0x00, 0x00, // ancount
            0x00, 0x00, // nscount
            0x00, 0x00, // arcount
        ];
        // Question section: 1 "a" 3 "com" 0, QTYPE=1 (A), QCLASS=1 (IN).
        v.extend_from_slice(b"\x01a\x03com\x00");
        v.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        v
    }

    #[test]
    fn dissects_query_header() {
        let p = Packet::dissect(query(), ProtoId::Dns);
        let d = p.find_layer(ProtoId::Dns).unwrap();
        assert_eq!(p.header(d).len(), 12);
        assert_eq!(p.get(d, "id").unwrap(), FieldValue::Uint(0xabcd));
        assert_eq!(p.get(d, "qr").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(d, "opcode").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(d, "rd").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(d, "qdcount").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(d, "ancount").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(d, "nscount").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(d, "arcount").unwrap(), FieldValue::Uint(0));
    }

    #[test]
    fn record_sections_stay_raw() {
        let p = Packet::dissect(query(), ProtoId::Dns);
        let got: Vec<_> = p.layers().iter().map(|s| s.proto).collect();
        assert_eq!(got, vec![ProtoId::Dns, ProtoId::Raw]);
        let d = p.find_layer(ProtoId::Dns).unwrap();
        assert_eq!(p.payload(d), b"\x01a\x03com\x00\x00\x01\x00\x01");
    }

    #[test]
    fn subbyte_flags_decode_at_rfc_bit_offsets() {
        // Byte 2 = 0x85 = 1 0000 1 0 1 -> QR=1, OPCODE=0, AA=1, TC=0, RD=1
        // Byte 3 = 0x83 = 1 000 0011   -> RA=1, Z=0, RCODE=3 (name error)
        let mut a = vec![0x00, 0x00, 0x85, 0x83];
        a.extend_from_slice(&[0; 8]);
        let p = Packet::dissect(a, ProtoId::Dns);
        assert_eq!(p.get(0, "qr").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(0, "opcode").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(0, "aa").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(0, "tc").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(0, "rd").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(0, "ra").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(0, "z").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(0, "rcode").unwrap(), FieldValue::Uint(3));

        // A second pattern where every field differs, so no two offsets can be
        // swapped and still pass.
        // Byte 2 = 0x13 = 0 0010 0 1 1 -> QR=0, OPCODE=2 (STATUS), AA=0, TC=1, RD=1
        // Byte 3 = 0x5f = 0 101 1111   -> RA=0, Z=5, RCODE=15
        let mut b = vec![0x00, 0x00, 0x13, 0x5f];
        b.extend_from_slice(&[0; 8]);
        let p = Packet::dissect(b, ProtoId::Dns);
        assert_eq!(p.get(0, "qr").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(0, "opcode").unwrap(), FieldValue::Uint(2));
        assert_eq!(p.get(0, "aa").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(0, "tc").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(0, "rd").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(0, "ra").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(0, "z").unwrap(), FieldValue::Uint(5));
        assert_eq!(p.get(0, "rcode").unwrap(), FieldValue::Uint(15));
    }

    #[test]
    fn flag_writes_land_in_the_right_bits() {
        let mut p = Packet::dissect(query(), ProtoId::Dns);
        assert!(p.set_uint(0, "qr", 1));
        assert!(p.set_uint(0, "opcode", 0b0101));
        assert!(p.set_uint(0, "rcode", 0b1001));
        assert!(p.set_uint(0, "ancount", 2));
        // 1 0101 0 0 1 = 0xa9, 0 000 1001 = 0x09
        assert_eq!(&p.raw_bytes()[2..4], &[0xa9, 0x09]);
        assert_eq!(p.get(0, "rd").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(0, "ancount").unwrap(), FieldValue::Uint(2));
    }

    #[test]
    fn roundtrips_unchanged_bytes() {
        let orig = query();
        let p = Packet::dissect(orig.clone(), ProtoId::Dns);
        assert_eq!(p.raw_bytes(), &orig[..]);
        assert_eq!(p.layer_bytes(0), &orig[..]);
    }

    #[test]
    fn short_input_does_not_panic() {
        for n in 0..12usize {
            let p = Packet::dissect(query()[..n].to_vec(), ProtoId::Dns);
            assert!(p.layers().iter().all(|s| s.proto == ProtoId::Raw));
            assert_eq!(p.get(0, "qdcount"), None);
        }
    }

    #[test]
    fn dissects_under_udp_port_53() {
        let mut v = vec![0x30, 0x39, 0x00, 0x35, 0x00, 0x00, 0x00, 0x00];
        v.extend_from_slice(&query());
        let p = Packet::dissect(v, ProtoId::Udp);
        let d = p.find_layer(ProtoId::Dns).expect("dns layer");
        assert_eq!(p.get(d, "id").unwrap(), FieldValue::Uint(0xabcd));
    }

    #[test]
    fn build_defaults_match_a_recursive_query() {
        let p = Packet::build(&[ProtoId::Dns]);
        assert_eq!(p.raw_bytes().len(), 12);
        assert_eq!(p.get(0, "rd").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(0, "qdcount").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(0, "qr").unwrap(), FieldValue::Uint(0));
        assert_eq!(&p.raw_bytes()[0..6], &[0x00, 0x00, 0x01, 0x00, 0x00, 0x01]);
    }

    // ---- record sections (RFC 1035 §4.1.2-4.1.4) --------------------------
    //
    // Every vector below is written out by hand from RFC 1035. The helpers only
    // concatenate literal pieces; nothing is generated from another DNS stack.

    /// Encode a <domain-name> as a sequence of length-prefixed labels + root.
    fn name(labels: &[&str]) -> Vec<u8> {
        let mut v = Vec::new();
        for l in labels {
            v.push(l.len() as u8);
            v.extend_from_slice(l.as_bytes());
        }
        v.push(0);
        v
    }

    fn header(qd: u16, an: u16, ns: u16, ar: u16) -> Vec<u8> {
        let mut v = vec![0x12, 0x34, 0x81, 0x80];
        v.extend_from_slice(&qd.to_be_bytes());
        v.extend_from_slice(&an.to_be_bytes());
        v.extend_from_slice(&ns.to_be_bytes());
        v.extend_from_slice(&ar.to_be_bytes());
        v
    }

    fn question(nm: &[u8], qtype: u16, qclass: u16) -> Vec<u8> {
        let mut v = nm.to_vec();
        v.extend_from_slice(&qtype.to_be_bytes());
        v.extend_from_slice(&qclass.to_be_bytes());
        v
    }

    fn record(nm: &[u8], rtype: u16, rclass: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
        let mut v = nm.to_vec();
        v.extend_from_slice(&rtype.to_be_bytes());
        v.extend_from_slice(&rclass.to_be_bytes());
        v.extend_from_slice(&ttl.to_be_bytes());
        v.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        v.extend_from_slice(rdata);
        v
    }

    #[test]
    fn parses_a_simple_query() {
        // Fully literal: id 0x1234, flags 0x0100 (RD), QDCOUNT=1, rest 0.
        // "example.com" = 7 'example' 3 'com' 0, QTYPE=1 (A), QCLASS=1 (IN).
        let msg: Vec<u8> = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        let r = parse_records(&msg);
        assert_eq!(r.qd.len(), 1);
        assert_eq!(r.qd[0].qname, "example.com");
        assert_eq!(r.qd[0].qtype, rtype::A);
        assert_eq!(r.qd[0].qclass, 1);
        assert!(r.an.is_empty() && r.ns.is_empty() && r.ar.is_empty());
    }

    #[test]
    fn parses_a_response_with_an_a_record() {
        // Answer carries the name in full (no compression); TTL 300 = 0x0000012c,
        // RDLENGTH 4, RDATA 93.184.216.34.
        let msg: Vec<u8> = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // header
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, 0x00, 0x01, // question
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 93, 184, 216, 34,
        ];
        let r = parse_records(&msg);
        assert_eq!(r.qd.len(), 1);
        assert_eq!(r.an.len(), 1);
        let a = &r.an[0];
        assert_eq!(a.rrname, "example.com");
        assert_eq!(a.rtype, rtype::A);
        assert_eq!(a.rclass, 1);
        assert_eq!(a.ttl, 300);
        assert_eq!(a.rdata, RData::A([93, 184, 216, 34]));
    }

    #[test]
    fn answer_name_compressed_to_the_question_decodes_identically() {
        // The question name sits at offset 12, so 0xC00C points at it.
        let mut msg = header(1, 1, 0, 0);
        msg.extend_from_slice(&question(&name(&["example", "com"]), rtype::A, 1));
        msg.extend_from_slice(&record(&[0xc0, 0x0c], rtype::A, 1, 60, &[93, 184, 216, 34]));
        let r = parse_records(&msg);
        assert_eq!(r.qd[0].qname, "example.com");
        assert_eq!(r.an[0].rrname, r.qd[0].qname);
        assert_eq!(r.an[0].ttl, 60);
        assert_eq!(r.an[0].rdata, RData::A([93, 184, 216, 34]));

        // Partial compression: a fresh label followed by a pointer to "example.com".
        let mut msg2 = header(1, 1, 0, 0);
        msg2.extend_from_slice(&question(&name(&["example", "com"]), rtype::A, 1));
        let nm = [0x03, b'w', b'w', b'w', 0xc0, 0x0c];
        msg2.extend_from_slice(&record(&nm, rtype::A, 1, 60, &[1, 2, 3, 4]));
        let r2 = parse_records(&msg2);
        assert_eq!(r2.an[0].rrname, "www.example.com");
    }

    #[test]
    fn pointer_loops_terminate() {
        // The single most important test in this file: a hang here is a DoS.

        // (a) A pointer to itself. Offset 12 holds 0xC00C.
        let mut selfptr = header(1, 0, 0, 0);
        selfptr.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01]);
        assert_eq!(read_name(&selfptr, 12), None);
        assert_eq!(parse_records(&selfptr), Records::default());

        // (b) Two pointers referencing each other: 12 -> 16 and 16 -> 12.
        let mut mutual = header(1, 0, 0, 0);
        mutual.extend_from_slice(&[0xc0, 0x10, 0x00, 0x00, 0xc0, 0x0c, 0x00, 0x00]);
        assert_eq!(read_name(&mutual, 12), None);
        assert_eq!(read_name(&mutual, 16), None);
        assert_eq!(parse_records(&mutual), Records::default());

        // (c) A long strictly-backwards chain: legal jump direction, but deep.
        // Offset 12 holds the real name "a"; pointers at 16, 18, 20, ... each
        // point at the previous one, so reading the top needs N+1 jumps.
        let mut chain = header(0, 0, 0, 0);
        chain.extend_from_slice(&[0x01, b'a', 0x00, 0x00]); // offsets 12..16
        for k in 0..100usize {
            let target = if k == 0 { 12 } else { 16 + 2 * (k - 1) };
            chain.push(0xc0 | (target >> 8) as u8);
            chain.push(target as u8);
        }
        assert_eq!(
            read_name(&chain, 16 + 2 * 9),
            Some(("a".to_string(), 16 + 2 * 9 + 2))
        );
        assert_eq!(read_name(&chain, 16 + 2 * 99), None);
    }

    #[test]
    fn forward_and_out_of_bounds_pointers_are_rejected() {
        // Forward pointer: at offset 12, pointing to 20 (later in the message).
        let mut fwd = header(1, 0, 0, 0);
        fwd.extend_from_slice(&[0xc0, 0x14, 0x00, 0x00, 0x00, 0x00, 0x01, b'a', 0x00, 0x00]);
        assert_eq!(read_name(&fwd, 12), None);

        // Pointer past the end of the message entirely.
        let mut oob = header(1, 0, 0, 0);
        oob.extend_from_slice(&[0xc0, 0xff, 0x00, 0x01, 0x00, 0x01]);
        assert_eq!(read_name(&oob, 12), None);
        assert_eq!(parse_records(&oob), Records::default());

        // A pointer whose second octet is missing.
        let mut half = header(1, 0, 0, 0);
        half.push(0xc0);
        assert_eq!(read_name(&half, 12), None);
        assert_eq!(parse_records(&half), Records::default());

        // Reserved label types 0b01 and 0b10 are not labels and not pointers.
        for top in [0x40u8, 0x80u8] {
            let mut bad = header(1, 0, 0, 0);
            bad.extend_from_slice(&[top | 0x05, 0, 0, 0, 0, 0, 0, 0]);
            assert_eq!(read_name(&bad, 12), None);
        }
    }

    #[test]
    fn decodes_cname_and_aaaa() {
        let mut msg = header(1, 2, 0, 0);
        msg.extend_from_slice(&question(&name(&["www", "example", "com"]), rtype::A, 1));
        msg.extend_from_slice(&record(
            &[0xc0, 0x0c],
            rtype::CNAME,
            1,
            3600,
            &name(&["example", "com"]),
        ));
        // 2001:0db8:0000:0000:0000:0000:0000:0001
        let v6 = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        msg.extend_from_slice(&record(&name(&["example", "com"]), rtype::AAAA, 1, 60, &v6));
        let r = parse_records(&msg);
        assert_eq!(r.an.len(), 2);
        assert_eq!(r.an[0].rrname, "www.example.com");
        assert_eq!(r.an[0].rdata, RData::Name("example.com".to_string()));
        assert_eq!(r.an[0].ttl, 3600);
        assert_eq!(r.an[1].rdata, RData::Aaaa(v6));
    }

    #[test]
    fn decodes_mx_and_txt() {
        let mut mx_rdata = vec![0x00, 0x0a]; // PREFERENCE = 10
        mx_rdata.extend_from_slice(&name(&["mail", "example", "com"]));
        // Two <character-string>s in one TXT RDATA (RFC 1035 §3.3.14).
        let txt_rdata = b"\x05hello\x06world!".to_vec();

        let mut msg = header(1, 2, 0, 0);
        msg.extend_from_slice(&question(&name(&["example", "com"]), rtype::MX, 1));
        msg.extend_from_slice(&record(&[0xc0, 0x0c], rtype::MX, 1, 1800, &mx_rdata));
        msg.extend_from_slice(&record(&[0xc0, 0x0c], rtype::TXT, 1, 1800, &txt_rdata));

        let r = parse_records(&msg);
        assert_eq!(
            r.an[0].rdata,
            RData::Mx {
                pref: 10,
                exchange: "mail.example.com".to_string(),
            }
        );
        assert_eq!(
            r.an[1].rdata,
            RData::Txt(vec!["hello".to_string(), "world!".to_string()])
        );
    }

    #[test]
    fn decodes_soa_with_all_five_timers() {
        let mut rdata = name(&["ns1", "example", "com"]);
        rdata.extend_from_slice(&name(&["hostmaster", "example", "com"]));
        rdata.extend_from_slice(&2024010101u32.to_be_bytes()); // SERIAL
        rdata.extend_from_slice(&7200u32.to_be_bytes()); // REFRESH
        rdata.extend_from_slice(&3600u32.to_be_bytes()); // RETRY
        rdata.extend_from_slice(&1209600u32.to_be_bytes()); // EXPIRE
        rdata.extend_from_slice(&300u32.to_be_bytes()); // MINIMUM

        let mut msg = header(1, 0, 1, 0);
        msg.extend_from_slice(&question(&name(&["example", "com"]), rtype::A, 1));
        msg.extend_from_slice(&record(&[0xc0, 0x0c], rtype::SOA, 1, 900, &rdata));

        let r = parse_records(&msg);
        assert!(r.an.is_empty());
        assert_eq!(r.ns.len(), 1);
        assert_eq!(r.ns[0].rrname, "example.com");
        assert_eq!(
            r.ns[0].rdata,
            RData::Soa {
                mname: "ns1.example.com".to_string(),
                rname: "hostmaster.example.com".to_string(),
                serial: 2024010101,
                refresh: 7200,
                retry: 3600,
                expire: 1209600,
                minimum: 300,
            }
        );
    }

    /// A referral: NS in authority, glue A in additional, plus an unknown type.
    fn referral() -> Vec<u8> {
        let mut msg = header(1, 1, 1, 2);
        msg.extend_from_slice(&question(&name(&["www", "example", "com"]), rtype::A, 1));
        msg.extend_from_slice(&record(
            &[0xc0, 0x0c],
            rtype::PTR,
            1,
            120,
            &name(&["ptr", "example", "com"]),
        ));
        msg.extend_from_slice(&record(
            &name(&["example", "com"]),
            rtype::NS,
            1,
            172800,
            &name(&["ns1", "example", "com"]),
        ));
        msg.extend_from_slice(&record(
            &name(&["ns1", "example", "com"]),
            rtype::A,
            1,
            172800,
            &[192, 0, 2, 1],
        ));
        // TYPE 99 (SPF, obsolete) is not decoded and must survive as Other.
        msg.extend_from_slice(&record(&name(&["example", "com"]), 99, 1, 60, b"\x02hi"));
        msg
    }

    #[test]
    fn fills_all_four_sections() {
        let r = parse_records(&referral());
        assert_eq!(r.qd.len(), 1);
        assert_eq!(r.an.len(), 1);
        assert_eq!(r.ns.len(), 1);
        assert_eq!(r.ar.len(), 2);
        assert_eq!(r.an[0].rdata, RData::Name("ptr.example.com".to_string()));
        assert_eq!(r.ns[0].rdata, RData::Name("ns1.example.com".to_string()));
        assert_eq!(r.ar[0].rdata, RData::A([192, 0, 2, 1]));
        assert_eq!(r.ar[1].rdata, RData::Other(b"\x02hi".to_vec()));
    }

    #[test]
    fn truncation_at_every_cut_point_returns_partial_results() {
        let full = referral();
        let complete = parse_records(&full);
        for n in 0..full.len() {
            let r = parse_records(&full[..n]);
            // Never more than the complete parse, and always a prefix of it.
            assert!(r.qd.len() <= complete.qd.len());
            assert!(r.an.len() <= complete.an.len());
            assert!(r.ns.len() <= complete.ns.len());
            assert!(r.ar.len() <= complete.ar.len());
            assert_eq!(r.qd[..], complete.qd[..r.qd.len()]);
            assert_eq!(r.an[..], complete.an[..r.an.len()]);
            assert_eq!(r.ns[..], complete.ns[..r.ns.len()]);
            assert_eq!(r.ar[..], complete.ar[..r.ar.len()]);
        }
        assert_eq!(complete.ar.len(), 2);
    }

    #[test]
    fn counts_larger_than_the_data_do_not_over_read() {
        // Claims 5 questions and 9 answers, carries exactly one question.
        let mut msg = header(5, 9, 3, 7);
        msg.extend_from_slice(&question(&name(&["example", "com"]), rtype::A, 1));
        let r = parse_records(&msg);
        assert_eq!(r.qd.len(), 1);
        assert!(r.an.is_empty() && r.ns.is_empty() && r.ar.is_empty());

        // Claims one answer but the RDLENGTH runs past the end of the message.
        let mut over = header(0, 1, 0, 0);
        over.extend_from_slice(&name(&["example", "com"]));
        over.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0xff, 0xff, 1, 2, 3, 4]);
        assert_eq!(parse_records(&over), Records::default());
    }

    #[test]
    fn root_name_renders_as_the_empty_string() {
        // A query for the root zone: QNAME is a single zero octet, QTYPE=2 (NS).
        let msg = {
            let mut m = header(1, 0, 0, 0);
            m.extend_from_slice(&[0x00, 0x00, 0x02, 0x00, 0x01]);
            m
        };
        let r = parse_records(&msg);
        assert_eq!(r.qd.len(), 1);
        assert_eq!(r.qd[0].qname, "");
        assert_eq!(r.qd[0].qtype, rtype::NS);
    }

    #[test]
    fn oversized_names_are_rejected() {
        // 4 labels of 63 octets each is 256 wire octets, over the RFC 1035 §2.3.4
        // limit of 255.
        let long = "a".repeat(63);
        let labels = [long.as_str(); 4];
        let mut msg = header(1, 0, 0, 0);
        msg.extend_from_slice(&question(&name(&labels), rtype::A, 1));
        assert_eq!(parse_records(&msg), Records::default());

        // Three of them (192 octets) is still legal.
        let mut ok = header(1, 0, 0, 0);
        ok.extend_from_slice(&question(&name(&labels[..3]), rtype::A, 1));
        assert_eq!(parse_records(&ok).qd.len(), 1);
    }

    #[test]
    fn rtype_names_match_the_iana_registry() {
        assert_eq!(rtype_name(rtype::A), "A");
        assert_eq!(rtype_name(rtype::NS), "NS");
        assert_eq!(rtype_name(rtype::CNAME), "CNAME");
        assert_eq!(rtype_name(rtype::SOA), "SOA");
        assert_eq!(rtype_name(rtype::PTR), "PTR");
        assert_eq!(rtype_name(rtype::MX), "MX");
        assert_eq!(rtype_name(rtype::TXT), "TXT");
        assert_eq!(rtype_name(rtype::AAAA), "AAAA");
        assert_eq!(rtype_name(rtype::OPT), "OPT");
        assert_eq!(rtype_name(rtype::ANY), "ANY");
        assert_eq!(rtype_name(0), "UNKNOWN");
        assert_eq!(rtype_name(0xffff), "UNKNOWN");
        assert_eq!(
            (rtype::A, rtype::NS, rtype::CNAME, rtype::SOA),
            (1, 2, 5, 6)
        );
        assert_eq!(
            (rtype::PTR, rtype::MX, rtype::TXT, rtype::AAAA),
            (12, 15, 16, 28)
        );
    }

    #[test]
    fn malformed_rdata_falls_back_to_other() {
        let mut msg = header(0, 4, 0, 0);
        // A with RDLENGTH 3 instead of 4.
        msg.extend_from_slice(&record(&name(&["a", "com"]), rtype::A, 1, 60, &[1, 2, 3]));
        // TXT whose character-string length runs past the end of its RDATA.
        msg.extend_from_slice(&record(
            &name(&["a", "com"]),
            rtype::TXT,
            1,
            60,
            b"\x09short",
        ));
        // CNAME whose name runs past its own RDLENGTH into the following record.
        // Written out literally because the helper derives RDLENGTH from the data.
        msg.extend_from_slice(&name(&["a", "com"]));
        msg.extend_from_slice(&[0x00, 0x05, 0x00, 0x01, 0, 0, 0, 60, 0x00, 0x02, 0x03, b'w']);
        // SOA with the names present but the timers cut short.
        let mut soa = name(&["ns", "a", "com"]);
        soa.extend_from_slice(&name(&["r", "a", "com"]));
        soa.extend_from_slice(&[0, 0, 0, 1]);
        msg.extend_from_slice(&record(&name(&["a", "com"]), rtype::SOA, 1, 60, &soa));

        let r = parse_records(&msg);
        assert_eq!(r.an.len(), 4);
        assert_eq!(r.an[0].rdata, RData::Other(vec![1, 2, 3]));
        assert_eq!(r.an[1].rdata, RData::Other(b"\x09short".to_vec()));
        assert_eq!(r.an[2].rdata, RData::Other(vec![0x03, b'w']));
        assert!(matches!(r.an[3].rdata, RData::Other(_)));
    }

    #[test]
    fn random_bytes_never_panic() {
        // Cheap deterministic smoke fuzz: an xorshift stream shaped like a DNS
        // message. Only property under test is "returns", for any input.
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..2000 {
            let mut msg = Vec::with_capacity(64);
            for _ in 0..64 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                msg.push(state as u8);
            }
            // Force plausible counts so the record loops are actually entered.
            msg[4] = 0;
            msg[5] = 2;
            msg[6] = 0;
            msg[7] = 2;
            let _ = parse_records(&msg);
            for n in 0..msg.len() {
                let _ = parse_records(&msg[..n]);
            }
        }
    }
}
