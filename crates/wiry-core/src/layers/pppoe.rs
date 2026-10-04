// SPDX-License-Identifier: GPL-2.0-only
//
// Derived from scapy: scapy/layers/ppp.py
//   scapy 2.7.0
//   Copyright (C) Philippe Biondi and the scapy contributors
//
// Changed by the wiry authors:
//   2026-10-03 — PPPoE code and PPP protocol names transcribed into the field table

//! PPPoE from RFC 2516 §4 and PPP framing from RFC 1661 §2. EtherType values
//! 0x8863 (Discovery) and 0x8864 (Session) come from the IANA "ETHER TYPES"
//! registry; PPP protocol numbers from the IANA "PPP DLL PROTOCOL NUMBERS"
//! registry.

use crate::field::FieldDesc;
use crate::names::Table;
use crate::proto::{fixed_len, raw_next, Next, ProtoDesc, ProtoId};

/// scapy 2.7.0 `PPPoED.code`, `PPPoE.code` and `_PPP_PROTOCOLS`.
static DISC_CODES: Table = &[
    (0, "PPP Session Stage"),
    (7, "PPPoE Active Discovery Offer (PADO)"),
    (9, "PPPoE Active Discovery Initiation (PADI)"),
    (10, "PPPoE Active Discovery Session-Grant (PADG)"),
    (11, "PPPoE Active Discovery Session-Credit Response (PADC)"),
    (12, "PPPoE Active Discovery Quality (PADQ)"),
    (25, "PPPoE Active Discovery Request (PADR)"),
    (101, "PPPoE Active Discovery Session-confirmation (PADS)"),
    (167, "PPPoE Active Discovery Terminate (PADT)"),
];

static SESSION_CODES: Table = &[(0, "Session")];

static PPP_PROTOS: Table = &[
    (1, "Padding Protocol"),
    (3, "ROHC small-CID [RFC3095]"),
    (5, "ROHC large-CID [RFC3095]"),
    (33, "Internet Protocol version 4"),
    (35, "OSI Network Layer"),
    (37, "Xerox NS IDP"),
    (39, "DECnet Phase IV"),
    (41, "Appletalk"),
    (43, "Novell IPX"),
    (45, "Van Jacobson Compressed TCP/IP"),
    (47, "Van Jacobson Uncompressed TCP/IP"),
    (49, "Bridging PDU"),
    (51, "Stream Protocol (ST-II)"),
    (53, "Banyan Vines"),
    (55, "reserved (until 1993) [Typo in RFC1172]"),
    (57, "AppleTalk EDDP"),
    (59, "AppleTalk SmartBuffered"),
    (61, "Multi-Link [RFC1717]"),
    (63, "NETBIOS Framing"),
    (65, "Cisco Systems"),
    (67, "Ascom Timeplex"),
    (69, "Fujitsu Link Backup and Load Balancing (LBLB)"),
    (71, "DCA Remote Lan"),
    (73, "Serial Data Transport Protocol (PPP-SDTP)"),
    (75, "SNA over 802.2"),
    (77, "SNA"),
    (79, "IPv6 Header Compression"),
    (81, "KNX Bridging Data [ianp]"),
    (83, "Encryption [Meyer]"),
    (85, "Individual Link Encryption [Meyer]"),
    (87, "Internet Protocol version 6 [Hinden]"),
    (89, "PPP Muxing [RFC3153]"),
    (91, "Vendor-Specific Network Protocol (VSNP) [RFC3772]"),
    (97, "RTP IPHC Full Header [RFC3544]"),
    (99, "RTP IPHC Compressed TCP [RFC3544]"),
    (101, "RTP IPHC Compressed Non TCP [RFC3544]"),
    (103, "RTP IPHC Compressed UDP 8 [RFC3544]"),
    (105, "RTP IPHC Compressed RTP 8 [RFC3544]"),
    (111, "Stampede Bridging"),
    (113, "Reserved [Fox]"),
    (115, "MP+ Protocol [Smith]"),
    (125, "reserved (Control Escape) [RFC1661]"),
    (127, "reserved (compression inefficient [RFC1662]"),
    (129, "Reserved Until 20-Oct-2000 [IANA]"),
    (131, "Reserved Until 20-Oct-2000 [IANA]"),
    (193, "NTCITS IPI [Ungar]"),
    (207, "reserved (PPP NLID)"),
    (251, "single link compression in multilink [RFC1962]"),
    (253, "compressed datagram [RFC1962]"),
    (255, "reserved (compression inefficient)"),
    (513, "802.1d Hello Packets"),
    (515, "IBM Source Routing BPDU"),
    (517, "DEC LANBridge100 Spanning Tree"),
    (519, "Cisco Discovery Protocol [Sastry]"),
    (521, "Netcs Twin Routing [Korfmacher]"),
    (523, "STP - Scheduled Transfer Protocol [Segal]"),
    (525, "EDP - Extreme Discovery Protocol [Grosser]"),
    (529, "Optical Supervisory Channel Protocol (OSCP)[Prasad]"),
    (531, "Optical Supervisory Channel Protocol (OSCP)[Prasad]"),
    (561, "Luxcom"),
    (563, "Sigma Network Systems"),
    (565, "Apple Client Server Protocol [Ridenour]"),
    (641, "MPLS Unicast [RFC3032]  "),
    (643, "MPLS Multicast [RFC3032]"),
    (645, "IEEE p1284.4 standard - data packets [Batchelder]"),
    (647, "ETSI TETRA Network Protocol Type 1 [Nieminen]"),
    (649, "Multichannel Flow Treatment Protocol [McCann]"),
    (8291, "RTP IPHC Compressed TCP No Delta [RFC3544]"),
    (8293, "RTP IPHC Context State [RFC3544]"),
    (8295, "RTP IPHC Compressed UDP 16 [RFC3544]"),
    (8297, "RTP IPHC Compressed RTP 16 [RFC3544]"),
    (16385, "Cray Communications Control Protocol [Stage]"),
    (16387, "CDPD Mobile Network Registration Protocol [Quick]"),
    (16389, "Expand accelerator protocol [Rachmani]"),
    (16391, "ODSICP NCP [Arvind]"),
    (16393, "DOCSIS DLL [Gaedtke]"),
    (16395, "Cetacean Network Detection Protocol [Siller]"),
    (16417, "Stacker LZS [Simpson]"),
    (16419, "RefTek Protocol [Banfill]"),
    (16421, "Fibre Channel [Rajagopal]"),
    (16423, "EMIT Protocols [Eastham]"),
    (16475, "Vendor-Specific Protocol (VSP) [RFC3772]"),
    (32801, "Internet Protocol Control Protocol"),
    (32803, "OSI Network Layer Control Protocol"),
    (32805, "Xerox NS IDP Control Protocol"),
    (32807, "DECnet Phase IV Control Protocol"),
    (32809, "Appletalk Control Protocol"),
    (32811, "Novell IPX Control Protocol"),
    (32813, "reserved"),
    (32815, "reserved"),
    (32817, "Bridging NCP"),
    (32819, "Stream Protocol Control Protocol"),
    (32821, "Banyan Vines Control Protocol"),
    (32823, "reserved (until 1993)"),
    (32825, "reserved"),
    (32827, "reserved"),
    (32829, "Multi-Link Control Protocol"),
    (32831, "NETBIOS Framing Control Protocol"),
    (32833, "Cisco Systems Control Protocol"),
    (32835, "Ascom Timeplex"),
    (32837, "Fujitsu LBLB Control Protocol"),
    (32839, "DCA Remote Lan Network Control Protocol (RLNCP)"),
    (32841, "Serial Data Control Protocol (PPP-SDCP)"),
    (32843, "SNA over 802.2 Control Protocol"),
    (32845, "SNA Control Protocol"),
    (32847, "IP6 Header Compression Control Protocol"),
    (32849, "KNX Bridging Control Protocol [ianp]"),
    (32851, "Encryption Control Protocol [Meyer]"),
    (32853, "Individual Link Encryption Control Protocol [Meyer]"),
    (32855, "IPv6 Control Protovol [Hinden]"),
    (32857, "PPP Muxing Control Protocol [RFC3153]"),
    (
        32859,
        "Vendor-Specific Network Control Protocol (VSNCP) [RFC3772]",
    ),
    (32879, "Stampede Bridging Control Protocol"),
    (32881, "Reserved [Fox]"),
    (32883, "MP+ Control Protocol [Smith]"),
    (32893, "Not Used - reserved [RFC1661]"),
    (32897, "Reserved Until 20-Oct-2000 [IANA]"),
    (32899, "Reserved Until 20-Oct-2000 [IANA]"),
    (32961, "NTCITS IPI Control Protocol [Ungar]"),
    (32975, "Not Used - reserved [RFC1661]"),
    (
        33019,
        "single link compression in multilink control [RFC1962]",
    ),
    (33021, "Compression Control Protocol [RFC1962]"),
    (33023, "Not Used - reserved [RFC1661]"),
    (33287, "Cisco Discovery Protocol Control [Sastry]"),
    (33289, "Netcs Twin Routing [Korfmacher]"),
    (33291, "STP - Control Protocol [Segal]"),
    (
        33293,
        "EDPCP - Extreme Discovery Protocol Ctrl Prtcl [Grosser]",
    ),
    (33333, "Apple Client Server Protocol Control [Ridenour]"),
    (33409, "MPLSCP [RFC3032]"),
    (
        33413,
        "IEEE p1284.4 standard - Protocol Control [Batchelder]",
    ),
    (33415, "ETSI TETRA TNP1 Control Protocol [Nieminen]"),
    (33417, "Multichannel Flow Treatment Protocol [McCann]"),
    (49185, "Link Control Protocol"),
    (49187, "Password Authentication Protocol"),
    (49189, "Link Quality Report"),
    (49191, "Shiva Password Authentication Protocol"),
    (49193, "CallBack Control Protocol (CBCP)"),
    (
        49195,
        "BACP Bandwidth Allocation Control Protocol [RFC2125]",
    ),
    (49197, "BAP [RFC2125]"),
    (
        49243,
        "Vendor-Specific Authentication Protocol (VSAP) [RFC3772]",
    ),
    (49281, "Container Control Protocol [KEN]"),
    (49699, "Challenge Handshake Authentication Protocol"),
    (49701, "RSA Authentication Protocol [Narayana]"),
    (49703, "Extensible Authentication Protocol [RFC2284]"),
    (49705, "Mitsubishi Security Info Exch Ptcl (SIEP) [Seno]"),
    (49775, "Stampede Bridging Authorization Protocol"),
    (49793, "Proprietary Authentication Protocol [KEN]"),
    (49795, "Proprietary Authentication Protocol [Tackabury]"),
    (50305, "Proprietary Node ID Authentication Protocol [KEN]"),
];

/// Discovery and Session share the header; only the names of `code` differ.
macro_rules! header_fields {
    ($codes:expr) => {
        &[
            FieldDesc::uint("version", 0, 4, 1),
            FieldDesc::uint("type", 4, 4, 1),
            FieldDesc::uint("code", 8, 8, 0).named($codes),
            FieldDesc::uint("sessionid", 16, 16, 0),
            FieldDesc::computed_uint("len", 32, 16),
        ]
    };
}

pub static FIELDS: &[FieldDesc] = header_fields!(SESSION_CODES);
pub static DISC_FIELDS: &[FieldDesc] = header_fields!(DISC_CODES);

/// RFC 2516 §4: LENGTH covers the payload alone, so the datagram ends six
/// octets further on than it claims.
fn content_len(hdr: &[u8]) -> usize {
    match hdr.get(4..6) {
        Some(b) => 6 + u16::from_be_bytes([b[0], b[1]]) as usize,
        None => 0,
    }
}

/// RFC 2516 §4: a Session stage packet carries PPP; every other code is a
/// Discovery packet whose payload is a tag list.
fn session_next(hdr: &[u8]) -> Next {
    match hdr.get(1) {
        Some(0) => Next::Proto(ProtoId::Ppp),
        _ => Next::Raw,
    }
}

fn bind_next(hdr: &mut [u8], p: ProtoId) {
    if let (ProtoId::Ppp, Some(b)) = (p, hdr.get_mut(1)) {
        *b = 0;
    }
}

pub static DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Pppoe,
    name: "PPPoE",
    fields: FIELDS,
    min_len: 6,
    header_len: fixed_len,
    next: session_next,
    build_len: 6,
    parse_options: None,
    opt_table: None,
    set_hlen: None,
    bind_next: Some(bind_next),
    bind_next_bytes: None,
    content_len: Some(content_len),
};

pub static DISC_DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::PppoeDisc,
    name: "PPPoED",
    fields: DISC_FIELDS,
    min_len: 6,
    header_len: fixed_len,
    next: raw_next,
    build_len: 6,
    parse_options: None,
    opt_table: None,
    set_hlen: None,
    bind_next: None,
    bind_next_bytes: None,
    content_len: Some(content_len),
};

pub mod pppproto {
    pub const IPV4: u16 = 0x0021;
    pub const IPV6: u16 = 0x0057;
    pub const MPLS_UNICAST: u16 = 0x0281;
    pub const MPLS_MULTICAST: u16 = 0x0283;
}

/// RFC 1661 §2 allows a one-octet Protocol field, but RFC 2516 §4 forbids that
/// compression over PPPoE, which is the only framing this build reaches PPP
/// through, so the field is always two octets here.
pub static PPP_FIELDS: &[FieldDesc] =
    &[FieldDesc::uint("proto", 0, 16, pppproto::IPV4 as u64).named(PPP_PROTOS)];

fn ppp_next(hdr: &[u8]) -> Next {
    if hdr.len() < 2 {
        return Next::Raw;
    }
    match u16::from_be_bytes([hdr[0], hdr[1]]) {
        pppproto::IPV4 => Next::Proto(ProtoId::Ipv4),
        pppproto::IPV6 => Next::Proto(ProtoId::Ipv6),
        pppproto::MPLS_UNICAST | pppproto::MPLS_MULTICAST => Next::Proto(ProtoId::Mpls),
        _ => Next::Raw,
    }
}

fn ppp_bind_next(hdr: &mut [u8], p: ProtoId) {
    let v = match p {
        ProtoId::Ipv4 => pppproto::IPV4,
        ProtoId::Ipv6 => pppproto::IPV6,
        ProtoId::Mpls => pppproto::MPLS_UNICAST,
        _ => return,
    };
    if let Some(dst) = hdr.get_mut(0..2) {
        dst.copy_from_slice(&v.to_be_bytes());
    }
}

pub static PPP_DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Ppp,
    name: "PPP",
    fields: PPP_FIELDS,
    min_len: 2,
    header_len: fixed_len,
    next: ppp_next,
    build_len: 2,
    parse_options: None,
    opt_table: None,
    set_hlen: None,
    bind_next: Some(ppp_bind_next),
    bind_next_bytes: None,
    content_len: None,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldValue;
    use crate::packet::Packet;

    const IP20: &[u8] = &[
        0x45, 0x00, 0x00, 0x14, 0x00, 0x02, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 192, 168, 1, 1,
        192, 168, 1, 2,
    ];

    fn frame(etype: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        v.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        v.extend_from_slice(&etype.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    /// RFC 2516 §4: VER 1, TYPE 1, CODE 0x00 for a session packet.
    fn session(payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0x11, 0x00, 0x00, 0x07];
        v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn a_session_packet_reaches_the_datagram() {
        let mut ppp = vec![0x00, 0x21];
        ppp.extend_from_slice(IP20);
        let p = Packet::dissect(frame(0x8864, &session(&ppp)), ProtoId::Ether);
        assert_eq!(
            p.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![ProtoId::Ether, ProtoId::Pppoe, ProtoId::Ppp, ProtoId::Ipv4]
        );
        assert_eq!(p.get(1, "version").unwrap(), FieldValue::Uint(1));
        assert_eq!(p.get(1, "sessionid").unwrap(), FieldValue::Uint(7));
        assert_eq!(p.get(1, "len").unwrap(), FieldValue::Uint(22));
        assert_eq!(p.get(2, "proto").unwrap(), FieldValue::Uint(0x0021));
        assert_eq!(p.get(3, "src").unwrap(), FieldValue::Ipv4([192, 168, 1, 1]));
    }

    #[test]
    fn a_discovery_packet_keeps_its_tag_list_as_raw() {
        // PADI, code 0x09, one Service-Name tag of zero length.
        let mut disc = vec![0x11, 0x09, 0x00, 0x00, 0x00, 0x04];
        disc.extend_from_slice(&[0x01, 0x01, 0x00, 0x00]);
        let p = Packet::dissect(frame(0x8863, &disc), ProtoId::Ether);
        assert_eq!(
            p.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![ProtoId::Ether, ProtoId::PppoeDisc, ProtoId::Raw]
        );
        assert_eq!(p.get(1, "code").unwrap(), FieldValue::Uint(9));
    }

    #[test]
    fn a_length_shorter_than_the_frame_leaves_a_trailer() {
        let mut ppp = vec![0x00, 0x21];
        ppp.extend_from_slice(IP20);
        let mut payload = session(&ppp);
        payload.extend_from_slice(&[0u8; 8]);
        let p = Packet::dissect(frame(0x8864, &payload), ProtoId::Ether);
        assert_eq!(p.layers().last().unwrap().proto, ProtoId::Padding);
        assert_eq!(p.layers().last().unwrap().hlen, 8);
    }

    #[test]
    fn truncated_input_does_not_panic() {
        let mut ppp = vec![0x00, 0x21];
        ppp.extend_from_slice(IP20);
        let full = frame(0x8864, &session(&ppp));
        for cut in 0..full.len() {
            let mut p = Packet::dissect(full[..cut].to_vec(), ProtoId::Ether);
            assert_eq!(p.to_bytes(), &full[..cut]);
        }
        assert_eq!(ppp_next(&[0x00]), Next::Raw);
        assert_eq!(session_next(&[]), Next::Raw);
        assert_eq!(content_len(&[0x11]), 0);
    }

    #[test]
    fn builds_a_session_that_dissects_back() {
        let mut p = Packet::build(&[
            ProtoId::Ether,
            ProtoId::Pppoe,
            ProtoId::Ppp,
            ProtoId::Ipv4,
            ProtoId::Udp,
        ]);
        assert_eq!(p.get(0, "type").unwrap(), FieldValue::Uint(0x8864));
        assert_eq!(p.get(1, "code").unwrap(), FieldValue::Uint(0));
        assert_eq!(p.get(2, "proto").unwrap(), FieldValue::Uint(0x0021));
        let bytes = p.to_bytes().to_vec();

        let back = Packet::dissect(bytes, ProtoId::Ether);
        assert_eq!(
            back.layers().iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![
                ProtoId::Ether,
                ProtoId::Pppoe,
                ProtoId::Ppp,
                ProtoId::Ipv4,
                ProtoId::Udp
            ]
        );
        // RFC 2516 §4: the PPP header and everything under it.
        assert_eq!(back.get(1, "len").unwrap(), FieldValue::Uint(2 + 20 + 8));
    }
}
