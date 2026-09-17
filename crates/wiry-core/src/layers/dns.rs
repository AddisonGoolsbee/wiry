//! RFC 1035 §4.1.1 header; sections stay `Raw` and are decoded by
//! [`parse_records`]. DEVIATIONS.md E8.

use crate::field::FieldDesc;
use crate::proto::{Next, ProtoDesc, ProtoId};

/// RFC 1035 §4.2.2: the length prefix exists only over TCP, which stays `Raw`,
/// so the field is present for the interface but can never apply.
fn over_tcp(_: &[u8]) -> bool {
    false
}

pub static FIELDS: &[FieldDesc] = &[
    FieldDesc::uint("length", 0, 16, 0).when(over_tcp),
    FieldDesc::uint("id", 0, 16, 0),
    FieldDesc::uint("qr", 16, 1, 0),
    FieldDesc::uint("opcode", 17, 4, 0),
    FieldDesc::uint("aa", 21, 1, 0),
    FieldDesc::uint("tc", 22, 1, 0),
    FieldDesc::uint("rd", 23, 1, 1),
    FieldDesc::uint("ra", 24, 1, 0),
    // RFC 1035 Z became AD and CD in RFC 4035.
    FieldDesc::uint("z", 25, 1, 0),
    FieldDesc::uint("ad", 26, 1, 0),
    FieldDesc::uint("cd", 27, 1, 0),
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
    opt_table: None,
    set_hlen: None,
    bind_next: None,
    bind_next_bytes: None,
    content_len: None,
};

/// IANA "Resource Record (RR) TYPEs" registry.
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

/// RFC 1035 §4.1.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// RFC 1035 §4.1.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    pub rrname: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: RData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A([u8; 4]),
    Aaaa([u8; 16]),
    /// CNAME, NS, PTR.
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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Records {
    pub qd: Vec<Question>,
    pub an: Vec<ResourceRecord>,
    pub ns: Vec<ResourceRecord>,
    pub ar: Vec<ResourceRecord>,
}

/// Jumps already go strictly backwards, ruling out loops; this bounds a long
/// descending chain so decoding cannot go quadratic.
const MAX_JUMPS: usize = 64;

/// RFC 1035 §2.3.4; counted as we go, so it also bounds a compressed name.
const MAX_NAME_OCTETS: usize = 255;

/// Per-message decompression budget: a two-octet pointer yields up to 255
/// octets, so without it 2.75 MB of input decodes to hundreds of MB.
pub const MAX_DECODED_NAME_BYTES: usize = 256 * 1024;

/// What one decoded record costs in owned memory, which is what the budget
/// exists to bound.
///
/// Name bytes dominate, but they are not the only cost: TXT splits its RDATA
/// into one owned string per character-string, so RDATA of N zero octets yields
/// N empty strings. The bytes are bounded by RDLENGTH; the per-string overhead
/// is not, and left uncharged it amplified 17 MB of input into 656 MB. Charge
/// each string its header as well as its length.
pub fn decoded_name_bytes(rr: &ResourceRecord) -> usize {
    rr.rrname.len()
        + match &rr.rdata {
            RData::Name(n) => n.len(),
            RData::Mx { exchange, .. } => exchange.len(),
            RData::Soa { mname, rname, .. } => mname.len() + rname.len(),
            RData::Txt(parts) => parts
                .iter()
                .map(|t| t.len() + std::mem::size_of::<String>())
                .sum(),
            _ => 0,
        }
}

fn be16(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off + 2)?;
    Some(u16::from_be_bytes([s[0], s[1]]))
}

fn be32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// Returns the name and the offset just past it *in the original stream*, i.e.
/// past the first pointer when the name was compressed.
fn read_name(msg: &[u8], pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<&[u8]> = Vec::new();
    let mut at = pos;
    let mut end: Option<usize> = None;
    let mut jumps = 0usize;
    let mut octets = 0usize;

    loop {
        let len = *msg.get(at)?;
        match len & 0xc0 {
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
            0xc0 => {
                let lo = *msg.get(at + 1)?;
                let target = (((len & 0x3f) as usize) << 8) | lo as usize;
                end.get_or_insert(at + 2);
                jumps += 1;
                // RFC 1035 §4.1.4 pointers refer to a *prior* occurrence, so
                // rejecting a non-backwards target makes every loop terminate.
                if jumps > MAX_JUMPS || target >= at {
                    return None;
                }
                at = target;
            }
            // RFC 1035 §4.1.4: label types 0b01 and 0b10 are reserved.
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

/// A name reaching past its own RDATA means a malformed RDLENGTH.
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

/// RFC 1035 §3.3.14: one or more length-prefixed <character-string>s.
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

/// `msg` must be the whole message from the 12-byte header, because compression
/// pointers are offsets from that origin. Stops at the first undecodable record
/// or once the budget is spent; section counts are an upper bound only.
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
    let mut budget = MAX_DECODED_NAME_BYTES;
    for _ in 0..counts[0] {
        match read_question(msg, pos) {
            Some((q, next)) => {
                let Some(left) = budget.checked_sub(q.qname.len()) else {
                    return out;
                };
                budget = left;
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
                    let Some(left) = budget.checked_sub(decoded_name_bytes(&rr)) else {
                        break 'sections;
                    };
                    budget = left;
                    section.push(rr);
                    pos = next;
                }
                None => break 'sections,
            }
        }
    }
    [out.an, out.ns, out.ar] = sections;
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldValue;
    use crate::packet::Packet;

    /// RFC 1035 §4.1 recursive query for "a.com" A/IN.
    fn query() -> Vec<u8> {
        let mut v = vec![
            0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
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
        // 0x85 = QR=1, OPCODE=0, AA=1, TC=0, RD=1; 0x83 = RA=1, Z=0, RCODE=3.
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

        // 0x13 = QR=0, OPCODE=2, AA=0, TC=1, RD=1; 0x5f = RA=0, Z=1, AD=0,
        // CD=1, RCODE=15. Every field differs, so no two offsets can swap.
        let mut b = vec![0x00, 0x00, 0x13, 0x5f];
        b.extend_from_slice(&[0; 8]);
        let p = Packet::dissect(b, ProtoId::Dns);
        assert_eq!(p.get(0, "qr").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(0, "opcode").unwrap(), FieldValue::Uint(2));
        assert_eq!(p.get(0, "aa").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(0, "tc").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(0, "rd").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(0, "ra").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(0, "z").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(0, "ad").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(0, "cd").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(0, "rcode").unwrap(), FieldValue::Uint(15));
    }

    #[test]
    fn flag_writes_land_in_the_right_bits() {
        let mut p = Packet::dissect(query(), ProtoId::Dns);
        assert!(p.set_uint(0, "qr", 1));
        assert!(p.set_uint(0, "opcode", 0b0101));
        assert!(p.set_uint(0, "rcode", 0b1001));
        assert!(p.set_uint(0, "ancount", 2));
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
        let msg: Vec<u8> = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01, 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 93, 184, 216, 34,
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

        let mut msg2 = header(1, 1, 0, 0);
        msg2.extend_from_slice(&question(&name(&["example", "com"]), rtype::A, 1));
        let nm = [0x03, b'w', b'w', b'w', 0xc0, 0x0c];
        msg2.extend_from_slice(&record(&nm, rtype::A, 1, 60, &[1, 2, 3, 4]));
        let r2 = parse_records(&msg2);
        assert_eq!(r2.an[0].rrname, "www.example.com");
    }

    #[test]
    fn pointer_loops_terminate() {
        let mut selfptr = header(1, 0, 0, 0);
        selfptr.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01]);
        assert_eq!(read_name(&selfptr, 12), None, "12 -> 12");
        assert_eq!(parse_records(&selfptr), Records::default());

        let mut mutual = header(1, 0, 0, 0);
        mutual.extend_from_slice(&[0xc0, 0x10, 0x00, 0x00, 0xc0, 0x0c, 0x00, 0x00]);
        assert_eq!(read_name(&mutual, 12), None, "12 -> 16");
        assert_eq!(read_name(&mutual, 16), None, "16 -> 12");
        assert_eq!(parse_records(&mutual), Records::default());

        // Strictly backwards and so individually legal: only MAX_JUMPS stops it.
        let mut chain = header(0, 0, 0, 0);
        chain.extend_from_slice(&[0x01, b'a', 0x00, 0x00]);
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
        let mut fwd = header(1, 0, 0, 0);
        fwd.extend_from_slice(&[0xc0, 0x14, 0x00, 0x00, 0x00, 0x00, 0x01, b'a', 0x00, 0x00]);
        assert_eq!(read_name(&fwd, 12), None, "12 -> 20, forwards");

        let mut oob = header(1, 0, 0, 0);
        oob.extend_from_slice(&[0xc0, 0xff, 0x00, 0x01, 0x00, 0x01]);
        assert_eq!(read_name(&oob, 12), None);
        assert_eq!(parse_records(&oob), Records::default());

        let mut half = header(1, 0, 0, 0);
        half.push(0xc0);
        assert_eq!(read_name(&half, 12), None);
        assert_eq!(parse_records(&half), Records::default());

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
        let mut mx_rdata = vec![0x00, 0x0a];
        mx_rdata.extend_from_slice(&name(&["mail", "example", "com"]));
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
        rdata.extend_from_slice(&2024010101u32.to_be_bytes());
        rdata.extend_from_slice(&7200u32.to_be_bytes());
        rdata.extend_from_slice(&3600u32.to_be_bytes());
        rdata.extend_from_slice(&1209600u32.to_be_bytes());
        rdata.extend_from_slice(&300u32.to_be_bytes());

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
        let mut msg = header(5, 9, 3, 7);
        msg.extend_from_slice(&question(&name(&["example", "com"]), rtype::A, 1));
        let r = parse_records(&msg);
        assert_eq!(r.qd.len(), 1);
        assert!(r.an.is_empty() && r.ns.is_empty() && r.ar.is_empty());

        let mut over = header(0, 1, 0, 0);
        over.extend_from_slice(&name(&["example", "com"]));
        over.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0xff, 0xff, 1, 2, 3, 4]);
        assert_eq!(parse_records(&over), Records::default());
    }

    #[test]
    fn root_name_renders_as_the_empty_string() {
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
        // 4 labels of 63 octets is 256 wire octets, over RFC 1035 §2.3.4.
        let long = "a".repeat(63);
        let labels = [long.as_str(); 4];
        let mut msg = header(1, 0, 0, 0);
        msg.extend_from_slice(&question(&name(&labels), rtype::A, 1));
        assert_eq!(parse_records(&msg), Records::default());

        let mut ok = header(1, 0, 0, 0);
        ok.extend_from_slice(&question(&name(&labels[..3]), rtype::A, 1));
        assert_eq!(parse_records(&ok).qd.len(), 1);
    }

    /// Every section full of two-octet pointers to one maximal name: 2.75 MB of
    /// input, 568 MB of output without the budget.
    fn decompression_bomb() -> Vec<u8> {
        let mut msg = header(0xffff, 0xffff, 0xffff, 0xffff);
        // 0xff starts no UTF-8 sequence, so the lossy decode amplifies too.
        let mut long = Vec::new();
        for _ in 0..3 {
            long.push(63u8);
            long.extend(std::iter::repeat(0xffu8).take(63));
        }
        long.push(0);
        msg.extend_from_slice(&question(&long, rtype::A, 1));
        for _ in 1..0xffff {
            msg.extend_from_slice(&question(&[0xc0, 0x0c], rtype::A, 1));
        }
        for _ in 0..3 * 0xffff {
            msg.extend_from_slice(&record(&[0xc0, 0x0c], rtype::A, 1, 0, &[]));
        }
        msg
    }

    #[test]
    fn a_decompression_bomb_spends_a_bounded_budget() {
        let msg = decompression_bomb();
        let r = parse_records(&msg);
        let decoded: usize = r.qd.iter().map(|q| q.qname.len()).sum::<usize>()
            + r.an
                .iter()
                .chain(&r.ns)
                .chain(&r.ar)
                .map(decoded_name_bytes)
                .sum::<usize>();
        assert!(decoded <= MAX_DECODED_NAME_BYTES, "decoded {decoded} bytes");
        assert!(r.qd.len() < 0xffff);
        assert!(decoded > MAX_DECODED_NAME_BYTES / 2);
    }

    /// TXT splits RDATA into one owned string per character-string, so RDATA of
    /// N zero octets used to yield N empty strings free of charge. 17 MB of
    /// input became 656 MB of output.
    #[test]
    fn a_txt_bomb_spends_the_same_bounded_budget() {
        let rdata = vec![0u8; 0xffff];
        let mut msg = vec![0, 1, 0x81, 0x80, 0, 0, 0xff, 0xff, 0, 0, 0, 0];
        for _ in 0..0xffff {
            msg.extend_from_slice(&record(&[0], rtype::TXT, 1, 0, &rdata));
        }
        let r = parse_records(&msg);
        let strings: usize =
            r.an.iter()
                .map(|rr| match &rr.rdata {
                    RData::Txt(parts) => parts.len(),
                    _ => 0,
                })
                .sum();
        let decoded: usize = r.an.iter().map(decoded_name_bytes).sum();
        assert!(decoded <= MAX_DECODED_NAME_BYTES, "decoded {decoded} bytes");
        assert!(
            strings * std::mem::size_of::<String>() <= MAX_DECODED_NAME_BYTES,
            "{strings} strings escaped the budget"
        );
    }

    #[test]
    fn an_ordinary_message_is_nowhere_near_the_budget() {
        let r = parse_records(&referral());
        let decoded: usize = r.qd.iter().map(|q| q.qname.len()).sum::<usize>()
            + r.an
                .iter()
                .chain(&r.ns)
                .chain(&r.ar)
                .map(decoded_name_bytes)
                .sum::<usize>();
        assert!(decoded * 1000 < MAX_DECODED_NAME_BYTES);
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
        msg.extend_from_slice(&record(&name(&["a", "com"]), rtype::A, 1, 60, &[1, 2, 3]));
        msg.extend_from_slice(&record(
            &name(&["a", "com"]),
            rtype::TXT,
            1,
            60,
            b"\x09short",
        ));
        // CNAME running past its own RDLENGTH: literal, because `record`
        // derives RDLENGTH from the data.
        msg.extend_from_slice(&name(&["a", "com"]));
        msg.extend_from_slice(&[0x00, 0x05, 0x00, 0x01, 0, 0, 0, 60, 0x00, 0x02, 0x03, b'w']);
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
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..2000 {
            let mut msg = Vec::with_capacity(64);
            for _ in 0..64 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                msg.push(state as u8);
            }
            // Plausible counts, so the record loops are entered.
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
