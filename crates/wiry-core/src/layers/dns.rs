//! RFC 1035 §4.1.1 header; sections stay `Raw` and are decoded by
//! [`parse_records`]. RDATA layouts: RFC 1035 §3.3, RFC 2782 (SRV),
//! RFC 6891 (OPT), RFC 4034 (DS, RRSIG, NSEC, DNSKEY), RFC 5155 (NSEC3),
//! RFC 8659 (CAA). DEVIATIONS.md E8.

use crate::field::FieldDesc;
use crate::proto::{Next, ProtoDesc, ProtoId};

/// The header is the same twelve octets either way; over a stream RFC 1035
/// §4.2.2 puts a length in front of it. One macro so the two layouts cannot
/// drift apart.
macro_rules! header_fields {
    ($at:expr $(, $pre:expr)?) => {
        &[
            $($pre,)?
            FieldDesc::uint("id", $at, 16, 0),
            FieldDesc::uint("qr", $at + 16, 1, 0),
            FieldDesc::uint("opcode", $at + 17, 4, 0),
            FieldDesc::uint("aa", $at + 21, 1, 0),
            FieldDesc::uint("tc", $at + 22, 1, 0),
            FieldDesc::uint("rd", $at + 23, 1, 1),
            FieldDesc::uint("ra", $at + 24, 1, 0),
            // RFC 1035 Z became AD and CD in RFC 4035.
            FieldDesc::uint("z", $at + 25, 1, 0),
            FieldDesc::uint("ad", $at + 26, 1, 0),
            FieldDesc::uint("cd", $at + 27, 1, 0),
            FieldDesc::uint("rcode", $at + 28, 4, 0),
            FieldDesc::uint("qdcount", $at + 32, 16, 1),
            FieldDesc::uint("ancount", $at + 48, 16, 0),
            FieldDesc::uint("nscount", $at + 64, 16, 0),
            FieldDesc::uint("arcount", $at + 80, 16, 0),
        ]
    };
}

pub static FIELDS: &[FieldDesc] = header_fields!(0);

/// RFC 1035 §4.2.2.
pub static TCP_FIELDS: &[FieldDesc] = header_fields!(16, FieldDesc::computed_uint("length", 0, 16));

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
    pub const NSEC3: u16 = 50;
    pub const NSEC3PARAM: u16 = 51;
    pub const AXFR: u16 = 252;
    pub const ANY: u16 = 255;
    pub const CAA: u16 = 257;
}

/// IANA "DNS EDNS0 Option Codes (OPT)" registry.
pub fn ednsopt_name(code: u16) -> &'static str {
    match code {
        1 => "LLQ",
        2 => "UL",
        3 => "NSID",
        5 => "DAU",
        6 => "DHU",
        7 => "N3U",
        8 => "edns-client-subnet",
        9 => "EDNS-EXPIRE",
        10 => "COOKIE",
        11 => "edns-tcp-keepalive",
        12 => "Padding",
        13 => "CHAIN",
        14 => "edns-key-tag",
        15 => "Extended-DNS-Error",
        _ => "UNKNOWN",
    }
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
        rtype::NSEC3 => "NSEC3",
        rtype::NSEC3PARAM => "NSEC3PARAM",
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

/// RFC 6891 §6.1.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdnsOption {
    pub code: u16,
    pub data: Vec<u8>,
}

/// RFC 6891 §6.1.3: the OPT pseudo-record reuses CLASS and TTL for the fields
/// that would not fit in the twelve-octet header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Edns {
    pub udpsize: u16,
    pub ext_rcode: u8,
    pub version: u8,
    pub dnssec_ok: bool,
    pub z: u16,
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
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Caa {
        flags: u8,
        tag: String,
        value: String,
    },
    Opt(Vec<EdnsOption>),
    Ds {
        keytag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Vec<u8>,
    },
    Rrsig {
        type_covered: u16,
        algorithm: u8,
        labels: u8,
        original_ttl: u32,
        expiration: u32,
        inception: u32,
        keytag: u16,
        signer: String,
        signature: Vec<u8>,
    },
    Nsec {
        next: String,
        types: Vec<u16>,
    },
    Nsec3 {
        hash_alg: u8,
        flags: u8,
        iterations: u16,
        salt: Vec<u8>,
        next_hashed: Vec<u8>,
        types: Vec<u16>,
    },
    Nsec3Param {
        hash_alg: u8,
        flags: u8,
        iterations: u16,
        salt: Vec<u8>,
    },
    Dnskey {
        flags: u16,
        protocol: u8,
        algorithm: u8,
        key: Vec<u8>,
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
/// A signature, a digest or a public key is another unbounded allocation, and a
/// type bit map turns 34 octets into 256 of them, so every owned byte a record
/// type decodes to is charged, not only its names.
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
            RData::Srv { target, .. } => target.len(),
            RData::Caa { tag, value, .. } => tag.len() + value.len(),
            RData::Opt(opts) => opts
                .iter()
                .map(|o| o.data.len() + std::mem::size_of::<EdnsOption>())
                .sum(),
            RData::Ds { digest, .. } => digest.len(),
            RData::Rrsig {
                signer, signature, ..
            } => signer.len() + signature.len(),
            RData::Nsec { next, types } => next.len() + 2 * types.len(),
            RData::Nsec3 {
                salt,
                next_hashed,
                types,
                ..
            } => salt.len() + next_hashed.len() + 2 * types.len(),
            RData::Nsec3Param { salt, .. } => salt.len(),
            RData::Dnskey { key, .. } => key.len(),
            RData::A(_) | RData::Aaaa(_) | RData::Other(_) => 0,
        }
}

impl ResourceRecord {
    /// RFC 6891 §6.1.3.
    pub fn edns(&self) -> Option<Edns> {
        if self.rtype != rtype::OPT {
            return None;
        }
        Some(Edns {
            udpsize: self.rclass,
            ext_rcode: (self.ttl >> 24) as u8,
            version: (self.ttl >> 16) as u8,
            dnssec_ok: self.ttl & 0x8000 != 0,
            z: (self.ttl & 0x7fff) as u16,
        })
    }
}

/// RFC 6891 §6.1.3: the header's four-bit RCODE is the low half of a twelve-bit
/// code whose upper eight bits the OPT record carries.
pub fn extended_rcode(header_rcode: u8, ext: u8) -> u16 {
    ((ext as u16) << 4) | (header_rcode & 0x0f) as u16
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

    Some((render(&labels), end?))
}

/// RFC 1035 §5.1 presentation form: every label is closed by a dot, so the root
/// is "." and a fully qualified name ends in one. A dot or a backslash inside a
/// label is escaped, since RFC 4343 §2.1 allows both and neither separates
/// labels.
fn render(labels: &[&[u8]]) -> String {
    let mut out = String::with_capacity(labels.iter().map(|l| l.len() + 1).sum());
    if labels.is_empty() {
        out.push('.');
        return out;
    }
    for l in labels {
        for c in String::from_utf8_lossy(l).chars() {
            if c == '.' || c == '\\' {
                out.push('\\');
            }
            out.push(c);
        }
        out.push('.');
    }
    out
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
        rtype::SRV => decode_srv(msg, start, end).unwrap_or_else(other),
        rtype::CAA => decode_caa(raw).unwrap_or_else(other),
        rtype::OPT => decode_opt(raw).map_or_else(other, RData::Opt),
        rtype::DS => decode_ds(raw).unwrap_or_else(other),
        rtype::RRSIG => decode_rrsig(msg, start, end).unwrap_or_else(other),
        rtype::NSEC => decode_nsec(msg, start, end).unwrap_or_else(other),
        rtype::NSEC3 => decode_nsec3(raw).unwrap_or_else(other),
        rtype::NSEC3PARAM => decode_nsec3param(raw).unwrap_or_else(other),
        rtype::DNSKEY => decode_dnskey(raw).unwrap_or_else(other),
        _ => other(),
    }
}

/// RFC 2782.
fn decode_srv(msg: &[u8], start: usize, end: usize) -> Option<RData> {
    if start + 6 > end {
        return None;
    }
    let (target, _) = read_name_within(msg, start + 6, end)?;
    Some(RData::Srv {
        priority: be16(msg, start)?,
        weight: be16(msg, start + 2)?,
        port: be16(msg, start + 4)?,
        target,
    })
}

/// RFC 8659 §4.1.
fn decode_caa(raw: &[u8]) -> Option<RData> {
    let flags = *raw.first()?;
    let taglen = *raw.get(1)? as usize;
    let tag = raw.get(2..2 + taglen)?;
    let value = raw.get(2 + taglen..)?;
    Some(RData::Caa {
        flags,
        tag: String::from_utf8_lossy(tag).into_owned(),
        value: String::from_utf8_lossy(value).into_owned(),
    })
}

/// RFC 6891 §6.1.2.
fn decode_opt(raw: &[u8]) -> Option<Vec<EdnsOption>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 4 <= raw.len() {
        let len = be16(raw, i + 2)? as usize;
        let start = i + 4;
        let stop = start.checked_add(len)?;
        out.push(EdnsOption {
            code: be16(raw, i)?,
            data: raw.get(start..stop)?.to_vec(),
        });
        i = stop;
    }
    (i == raw.len()).then_some(out)
}

/// RFC 4034 §5.1.
fn decode_ds(raw: &[u8]) -> Option<RData> {
    Some(RData::Ds {
        keytag: be16(raw, 0)?,
        algorithm: *raw.get(2)?,
        digest_type: *raw.get(3)?,
        digest: raw.get(4..)?.to_vec(),
    })
}

/// RFC 4034 §2.1.
fn decode_dnskey(raw: &[u8]) -> Option<RData> {
    Some(RData::Dnskey {
        flags: be16(raw, 0)?,
        protocol: *raw.get(2)?,
        algorithm: *raw.get(3)?,
        key: raw.get(4..)?.to_vec(),
    })
}

/// RFC 4034 §3.1. The signer's name is never compressed there, but reading it
/// with the general walker costs nothing and stays bounded either way.
fn decode_rrsig(msg: &[u8], start: usize, end: usize) -> Option<RData> {
    if start + 18 > end {
        return None;
    }
    let (signer, pos) = read_name_within(msg, start + 18, end)?;
    Some(RData::Rrsig {
        type_covered: be16(msg, start)?,
        algorithm: *msg.get(start + 2)?,
        labels: *msg.get(start + 3)?,
        original_ttl: be32(msg, start + 4)?,
        expiration: be32(msg, start + 8)?,
        inception: be32(msg, start + 12)?,
        keytag: be16(msg, start + 16)?,
        signer,
        signature: msg.get(pos..end)?.to_vec(),
    })
}

/// RFC 4034 §4.1.
fn decode_nsec(msg: &[u8], start: usize, end: usize) -> Option<RData> {
    let (next, pos) = read_name_within(msg, start, end)?;
    Some(RData::Nsec {
        next,
        types: decode_type_bitmap(msg.get(pos..end)?)?,
    })
}

/// The four fields and the salt RFC 5155 §3.2 and §4.2 share, plus the offset
/// just past them.
fn nsec3_prefix(raw: &[u8]) -> Option<(u8, u8, u16, &[u8], usize)> {
    let saltlen = *raw.get(4)? as usize;
    let salt = raw.get(5..5 + saltlen)?;
    Some((raw[0], raw[1], be16(raw, 2)?, salt, 5 + saltlen))
}

/// RFC 5155 §3.2.
fn decode_nsec3(raw: &[u8]) -> Option<RData> {
    let (hash_alg, flags, iterations, salt, pos) = nsec3_prefix(raw)?;
    let hashlen = *raw.get(pos)? as usize;
    let at = pos + 1;
    let next_hashed = raw.get(at..at + hashlen)?;
    Some(RData::Nsec3 {
        hash_alg,
        flags,
        iterations,
        salt: salt.to_vec(),
        next_hashed: next_hashed.to_vec(),
        types: decode_type_bitmap(raw.get(at + hashlen..)?)?,
    })
}

/// RFC 5155 §4.2.
fn decode_nsec3param(raw: &[u8]) -> Option<RData> {
    let (hash_alg, flags, iterations, salt, pos) = nsec3_prefix(raw)?;
    if pos != raw.len() {
        return None;
    }
    Some(RData::Nsec3Param {
        hash_alg,
        flags,
        iterations,
        salt: salt.to_vec(),
    })
}

/// RFC 4034 §4.1.2: windows of 256 types each, a window number and a bitmap of
/// one to thirty-two octets. Every block advances at least three octets, so the
/// walk is finite on any input.
fn decode_type_bitmap(raw: &[u8]) -> Option<Vec<u16>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 2 <= raw.len() {
        let window = raw[i] as u16;
        let len = raw[i + 1] as usize;
        if len == 0 || len > 32 {
            return None;
        }
        let stop = i + 2 + len;
        let bits = raw.get(i + 2..stop)?;
        for (k, b) in bits.iter().enumerate() {
            for bit in 0..8u16 {
                if b & (0x80 >> bit) != 0 {
                    out.push((window << 8) | (k as u16 * 8 + bit));
                }
            }
        }
        i = stop;
    }
    (i == raw.len()).then_some(out)
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

    /// RFC 9293 §3.1 header with both ports 53, then RFC 1035 §4.2.2 framing.
    fn tcp_dns(msg: &[u8], claimed: u16) -> Vec<u8> {
        let mut v = vec![0x00, 0x35, 0x00, 0x35];
        v.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0]);
        v.extend_from_slice(&[0x50, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00]);
        v.extend_from_slice(&claimed.to_be_bytes());
        v.extend_from_slice(msg);
        v
    }

    #[test]
    fn the_stream_length_prefix_is_a_field_and_the_header_follows_it() {
        let msg = query();
        let p = Packet::dissect(tcp_dns(&msg, msg.len() as u16), ProtoId::Tcp);
        let d = p.find_layer(ProtoId::Dns).expect("dns over tcp");
        assert_eq!(p.header(d).len(), 14);
        assert_eq!(p.framing(d), 2);
        assert_eq!(p.get(d, "length").unwrap(), FieldValue::Uint(23));
        assert_eq!(p.get(d, "id").unwrap(), FieldValue::Uint(0xabcd));
        assert_eq!(p.get(d, "rd").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(d, "qdcount").unwrap(), FieldValue::Uint(1));

        let mut udp = vec![0x30, 0x39, 0x00, 0x35, 0x00, 0x00, 0x00, 0x00];
        udp.extend_from_slice(&msg);
        let u = Packet::dissect(udp, ProtoId::Udp);
        let ud = u.find_layer(ProtoId::Dns).unwrap();
        assert_eq!(u.header(ud).len(), 12);
        assert_eq!(u.get(ud, "length"), None);
        assert_eq!(u.get(ud, "id").unwrap(), FieldValue::Uint(0xabcd));
    }

    #[test]
    fn records_are_read_past_the_stream_prefix() {
        let mut msg = header(1, 1, 0, 0);
        msg.extend_from_slice(&question(&name(&["example", "com"]), rtype::A, 1));
        msg.extend_from_slice(&record(&[0xc0, 0x0c], rtype::A, 1, 60, &[93, 184, 216, 34]));
        let p = Packet::dissect(tcp_dns(&msg, msg.len() as u16), ProtoId::Tcp);
        let d = p.find_layer(ProtoId::Dns).unwrap();
        // Compression counts from the message, not from the prefix: reading
        // from the wrong origin decodes 0xc00c as the two octets before it.
        let r = parse_records(p.framed_body(d));
        assert_eq!(r.qd[0].qname, "example.com.");
        assert_eq!(r.an[0].rrname, "example.com.");
        assert_eq!(r.an[0].rdata, RData::A([93, 184, 216, 34]));
    }

    #[test]
    fn a_stream_message_round_trips_and_its_length_is_recomputed() {
        let msg = query();
        let wire = tcp_dns(&msg, msg.len() as u16);
        let mut p = Packet::dissect(wire.clone(), ProtoId::Tcp);
        assert_eq!(p.to_bytes(), &wire[..]);

        // A prefix over-claiming the segment is corrected once anything is
        // written; one under-claiming it is a second message's framing.
        let mut bad = Packet::dissect(tcp_dns(&msg, 9999), ProtoId::Tcp);
        let d = bad.find_layer(ProtoId::Dns).unwrap();
        assert!(bad.set_uint(d, "id", 1));
        let _ = bad.to_bytes();
        assert_eq!(bad.get(d, "length").unwrap(), FieldValue::Uint(23));

        let mut pinned = Packet::dissect(tcp_dns(&msg, 23), ProtoId::Tcp);
        assert!(pinned.set_uint(d, "length", 4));
        let _ = pinned.to_bytes();
        assert_eq!(pinned.get(d, "length").unwrap(), FieldValue::Uint(4));
    }

    /// A segment holding two messages dissects the first and leaves the rest as
    /// payload, so recomputing the prefix over all of it would relabel the
    /// second message as part of the first.
    #[test]
    fn a_second_message_in_the_segment_keeps_its_own_framing() {
        let msg = query();
        let mut two = msg.clone();
        two.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        two.extend_from_slice(&msg);
        let wire = tcp_dns(&two, msg.len() as u16);

        let mut p = Packet::dissect(wire.clone(), ProtoId::Tcp);
        assert_eq!(p.to_bytes(), &wire[..]);

        // A write anywhere in the packet runs the whole recompute pass.
        let mut p = Packet::dissect(wire.clone(), ProtoId::Tcp);
        let ip = p.find_layer(ProtoId::Tcp).unwrap();
        assert!(p.set_uint(ip, "window", 4096));
        let d = p.find_layer(ProtoId::Dns).unwrap();
        let out = p.to_bytes().to_vec();
        assert_eq!(p.get(d, "length").unwrap(), FieldValue::Uint(23));
        assert_eq!(&out[out.len() - two.len()..], &two[..]);
    }

    #[test]
    fn a_stream_message_builds_with_room_for_its_prefix() {
        let mut p = Packet::build(&[ProtoId::Ipv4, ProtoId::Tcp, ProtoId::Dns]);
        assert_eq!(p.header(2).len(), 14);
        assert_eq!(p.get(1, "dport").unwrap(), FieldValue::Uint(53));
        let bytes = p.to_bytes().to_vec();
        assert_eq!(bytes.len(), 20 + 20 + 14);

        let back = Packet::dissect(bytes, ProtoId::Ipv4);
        let got: Vec<_> = back.layers().iter().map(|s| s.proto).collect();
        assert_eq!(got, vec![ProtoId::Ipv4, ProtoId::Tcp, ProtoId::Dns]);
        assert_eq!(back.get(2, "length").unwrap(), FieldValue::Uint(12));
        assert_eq!(back.get(2, "qdcount").unwrap(), FieldValue::Uint(1));
    }

    #[test]
    fn a_stream_message_too_short_for_the_prefix_stays_raw() {
        let msg = query();
        for n in 0..14usize {
            let p = Packet::dissect(tcp_dns(&msg[..n.min(msg.len())], 0), ProtoId::Tcp);
            let d = p.find_layer(ProtoId::Dns);
            assert_eq!(d.is_some(), n >= 14 - 2, "{n} octets");
        }
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
        assert_eq!(r.qd[0].qname, "example.com.");
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
        assert_eq!(a.rrname, "example.com.");
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
        assert_eq!(r.qd[0].qname, "example.com.");
        assert_eq!(r.an[0].rrname, r.qd[0].qname);
        assert_eq!(r.an[0].ttl, 60);
        assert_eq!(r.an[0].rdata, RData::A([93, 184, 216, 34]));

        let mut msg2 = header(1, 1, 0, 0);
        msg2.extend_from_slice(&question(&name(&["example", "com"]), rtype::A, 1));
        let nm = [0x03, b'w', b'w', b'w', 0xc0, 0x0c];
        msg2.extend_from_slice(&record(&nm, rtype::A, 1, 60, &[1, 2, 3, 4]));
        let r2 = parse_records(&msg2);
        assert_eq!(r2.an[0].rrname, "www.example.com.");
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
            Some(("a.".to_string(), 16 + 2 * 9 + 2))
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
        assert_eq!(r.an[0].rrname, "www.example.com.");
        assert_eq!(r.an[0].rdata, RData::Name("example.com.".to_string()));
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
                exchange: "mail.example.com.".to_string(),
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
        assert_eq!(r.ns[0].rrname, "example.com.");
        assert_eq!(
            r.ns[0].rdata,
            RData::Soa {
                mname: "ns1.example.com.".to_string(),
                rname: "hostmaster.example.com.".to_string(),
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
        assert_eq!(r.an[0].rdata, RData::Name("ptr.example.com.".to_string()));
        assert_eq!(r.ns[0].rdata, RData::Name("ns1.example.com.".to_string()));
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
    fn root_name_renders_as_a_lone_dot() {
        let msg = {
            let mut m = header(1, 0, 0, 0);
            m.extend_from_slice(&[0x00, 0x00, 0x02, 0x00, 0x01]);
            m
        };
        let r = parse_records(&msg);
        assert_eq!(r.qd.len(), 1);
        assert_eq!(r.qd[0].qname, ".");
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
    fn a_dot_inside_a_label_is_escaped_not_read_as_a_separator() {
        // RFC 4343 §2.1: "a.b" is one label, "a" then "b" is two.
        let mut one = header(2, 0, 0, 0);
        one.extend_from_slice(&question(b"\x03a.b\x03com\x00", rtype::A, 1));
        one.extend_from_slice(&question(&name(&["a", "b", "com"]), rtype::A, 1));
        let r = parse_records(&one);
        assert_eq!(r.qd[0].qname, "a\\.b.com.");
        assert_eq!(r.qd[1].qname, "a.b.com.");
        assert_ne!(r.qd[0].qname, r.qd[1].qname);

        let mut back = header(1, 0, 0, 0);
        back.extend_from_slice(&question(b"\x03a\\b\x00", rtype::A, 1));
        assert_eq!(parse_records(&back).qd[0].qname, "a\\\\b.");
    }

    #[test]
    fn decodes_an_opt_pseudo_record() {
        // RFC 6891 §6.1.2: root name, class is the UDP payload size, TTL holds
        // the extended RCODE, version and DO bit.
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&10u16.to_be_bytes());
        rdata.extend_from_slice(&8u16.to_be_bytes());
        rdata.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        rdata.extend_from_slice(&3u16.to_be_bytes());
        rdata.extend_from_slice(&2u16.to_be_bytes());
        rdata.extend_from_slice(b"hi");

        let mut msg = header(0, 0, 0, 1);
        msg.extend_from_slice(&record(&[0x00], rtype::OPT, 4096, 0x0100_8000, &rdata));
        let r = parse_records(&msg);
        let opt = &r.ar[0];
        assert_eq!(opt.rrname, ".");
        assert_eq!(
            opt.rdata,
            RData::Opt(vec![
                EdnsOption {
                    code: 10,
                    data: vec![1, 2, 3, 4, 5, 6, 7, 8],
                },
                EdnsOption {
                    code: 3,
                    data: b"hi".to_vec(),
                },
            ])
        );
        let e = opt.edns().expect("OPT carries EDNS fields");
        assert_eq!(e.udpsize, 4096);
        assert_eq!(e.ext_rcode, 1);
        assert_eq!(e.version, 0);
        assert!(e.dnssec_ok);
        assert_eq!(e.z, 0);
        assert_eq!(extended_rcode(3, e.ext_rcode), 0x13);
        assert_eq!(ednsopt_name(10), "COOKIE");
        assert_eq!(ednsopt_name(0), "UNKNOWN");

        let mut bare = header(0, 0, 0, 1);
        bare.extend_from_slice(&record(&[0x00], rtype::OPT, 1232, 0, &[]));
        assert_eq!(parse_records(&bare).ar[0].rdata, RData::Opt(vec![]));
        assert!(!parse_records(&bare).ar[0].edns().unwrap().dnssec_ok);

        let mut bad = header(0, 0, 0, 1);
        bad.extend_from_slice(&record(&[0x00], rtype::OPT, 512, 0, &[0, 3, 0, 9, 1]));
        assert!(matches!(parse_records(&bad).ar[0].rdata, RData::Other(_)));
        assert!(parse_records(&header(0, 0, 0, 0)).ar.is_empty());
    }

    /// RFC 4034 §4.1.2 type bit maps: window 0, two octets, A and NS set.
    const NSEC_TYPES: &[u8] = &[0x00, 0x02, 0x60, 0x00];

    #[test]
    fn decodes_the_dnssec_record_types() {
        let mut ds = 12345u16.to_be_bytes().to_vec();
        ds.extend_from_slice(&[8, 2]);
        ds.extend_from_slice(&[0xab; 32]);

        let mut key = 257u16.to_be_bytes().to_vec();
        key.extend_from_slice(&[3, 8]);
        key.extend_from_slice(b"public key bytes");

        let mut sig = Vec::new();
        sig.extend_from_slice(&rtype::A.to_be_bytes());
        sig.extend_from_slice(&[8, 2]);
        sig.extend_from_slice(&3600u32.to_be_bytes());
        sig.extend_from_slice(&1700000000u32.to_be_bytes());
        sig.extend_from_slice(&1690000000u32.to_be_bytes());
        sig.extend_from_slice(&12345u16.to_be_bytes());
        sig.extend_from_slice(&name(&["example", "com"]));
        sig.extend_from_slice(b"SIGNATURE");

        let mut nsec = name(&["next", "example", "com"]);
        nsec.extend_from_slice(NSEC_TYPES);

        let mut nsec3 = vec![1, 0];
        nsec3.extend_from_slice(&12u16.to_be_bytes());
        nsec3.push(4);
        nsec3.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        nsec3.push(5);
        nsec3.extend_from_slice(b"HASHD");
        nsec3.extend_from_slice(NSEC_TYPES);

        let mut param = vec![1, 0];
        param.extend_from_slice(&12u16.to_be_bytes());
        param.push(4);
        param.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

        let zone = name(&["example", "com"]);
        let mut msg = header(0, 6, 0, 0);
        msg.extend_from_slice(&record(&zone, rtype::DS, 1, 3600, &ds));
        msg.extend_from_slice(&record(&zone, rtype::DNSKEY, 1, 3600, &key));
        msg.extend_from_slice(&record(&zone, rtype::RRSIG, 1, 3600, &sig));
        msg.extend_from_slice(&record(&zone, rtype::NSEC, 1, 3600, &nsec));
        msg.extend_from_slice(&record(&zone, rtype::NSEC3, 1, 3600, &nsec3));
        msg.extend_from_slice(&record(&zone, rtype::NSEC3PARAM, 1, 3600, &param));

        let r = parse_records(&msg);
        assert_eq!(r.an.len(), 6);
        assert_eq!(
            r.an[0].rdata,
            RData::Ds {
                keytag: 12345,
                algorithm: 8,
                digest_type: 2,
                digest: vec![0xab; 32],
            }
        );
        assert_eq!(
            r.an[1].rdata,
            RData::Dnskey {
                flags: 257,
                protocol: 3,
                algorithm: 8,
                key: b"public key bytes".to_vec(),
            }
        );
        assert_eq!(
            r.an[2].rdata,
            RData::Rrsig {
                type_covered: rtype::A,
                algorithm: 8,
                labels: 2,
                original_ttl: 3600,
                expiration: 1700000000,
                inception: 1690000000,
                keytag: 12345,
                signer: "example.com.".to_string(),
                signature: b"SIGNATURE".to_vec(),
            }
        );
        assert_eq!(
            r.an[3].rdata,
            RData::Nsec {
                next: "next.example.com.".to_string(),
                types: vec![rtype::A, rtype::NS],
            }
        );
        assert_eq!(
            r.an[4].rdata,
            RData::Nsec3 {
                hash_alg: 1,
                flags: 0,
                iterations: 12,
                salt: vec![0xde, 0xad, 0xbe, 0xef],
                next_hashed: b"HASHD".to_vec(),
                types: vec![rtype::A, rtype::NS],
            }
        );
        assert_eq!(
            r.an[5].rdata,
            RData::Nsec3Param {
                hash_alg: 1,
                flags: 0,
                iterations: 12,
                salt: vec![0xde, 0xad, 0xbe, 0xef],
            }
        );
    }

    #[test]
    fn decodes_srv_and_caa() {
        let mut srv = Vec::new();
        srv.extend_from_slice(&10u16.to_be_bytes());
        srv.extend_from_slice(&5u16.to_be_bytes());
        srv.extend_from_slice(&443u16.to_be_bytes());
        srv.extend_from_slice(&name(&["host", "example", "com"]));

        let caa = b"\x00\x05issueca.example.net".to_vec();

        let mut msg = header(0, 2, 0, 0);
        msg.extend_from_slice(&record(&name(&["example", "com"]), rtype::SRV, 1, 60, &srv));
        msg.extend_from_slice(&record(&name(&["example", "com"]), rtype::CAA, 1, 60, &caa));
        let r = parse_records(&msg);
        assert_eq!(
            r.an[0].rdata,
            RData::Srv {
                priority: 10,
                weight: 5,
                port: 443,
                target: "host.example.com.".to_string(),
            }
        );
        assert_eq!(
            r.an[1].rdata,
            RData::Caa {
                flags: 0,
                tag: "issue".to_string(),
                value: "ca.example.net".to_string(),
            }
        );
    }

    #[test]
    fn a_malformed_dnssec_record_keeps_its_raw_rdata() {
        let zone = name(&["example", "com"]);
        let mut msg = header(0, 5, 0, 0);
        // Each one is too short for its own fixed part, or has a bit map block
        // longer than the 32 octets RFC 4034 §4.1.2 allows.
        msg.extend_from_slice(&record(&zone, rtype::DS, 1, 60, &[1, 2, 3]));
        msg.extend_from_slice(&record(&zone, rtype::DNSKEY, 1, 60, &[1, 2]));
        msg.extend_from_slice(&record(&zone, rtype::RRSIG, 1, 60, &[0; 10]));
        msg.extend_from_slice(&record(&zone, rtype::NSEC3, 1, 60, &[1, 0, 0, 12, 9, 1]));
        let mut wide = name(&["x"]);
        wide.extend_from_slice(&[0x00, 0x40]);
        wide.extend_from_slice(&[0xff; 64]);
        msg.extend_from_slice(&record(&zone, rtype::NSEC, 1, 60, &wide));

        let r = parse_records(&msg);
        assert_eq!(r.an.len(), 5);
        for rr in &r.an {
            assert!(
                matches!(rr.rdata, RData::Other(_)),
                "{} decoded {:?}",
                rtype_name(rr.rtype),
                rr.rdata
            );
        }
    }

    #[test]
    fn the_budget_charges_what_the_new_record_types_allocate() {
        let full: Vec<u8> = (0..=255u16)
            .flat_map(|w| [w as u8, 32].into_iter().chain([0xffu8; 32]))
            .collect();
        let mut nsec = name(&["a"]);
        nsec.extend_from_slice(&full);

        // 8,704 octets of bit map decode to 65,536 type numbers: a 15x
        // amplification, so eight records outrun the whole budget.
        let n = 8u16;
        let mut msg = header(0, n, 0, 0);
        for _ in 0..n {
            msg.extend_from_slice(&record(&[0], rtype::NSEC, 1, 0, &nsec));
        }
        let r = parse_records(&msg);
        let decoded: usize = r.an.iter().map(decoded_name_bytes).sum();
        assert!(decoded <= MAX_DECODED_NAME_BYTES, "decoded {decoded} bytes");
        assert!(r.an.len() < n as usize, "the budget stopped nothing");
        assert_eq!(
            r.an[0].rdata,
            RData::Nsec {
                next: "a.".to_string(),
                types: (0..=0xffffu32).map(|t| t as u16).collect(),
            }
        );

        let mut sig = vec![0u8; 18];
        sig.push(0);
        sig.extend_from_slice(&[0x5a; 60000]);
        let mut sigs = header(0, 20, 0, 0);
        for _ in 0..20 {
            sigs.extend_from_slice(&record(&[0], rtype::RRSIG, 1, 0, &sig));
        }
        let r = parse_records(&sigs);
        let decoded: usize = r.an.iter().map(decoded_name_bytes).sum();
        assert!(decoded <= MAX_DECODED_NAME_BYTES, "decoded {decoded} bytes");
        assert!(r.an.len() < 20, "signatures escaped the budget");
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
