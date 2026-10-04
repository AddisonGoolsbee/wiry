// SPDX-License-Identifier: GPL-2.0-only
//
// Derived from scapy: scapy/layers/pptp.py, scapy/layers/ppp.py,
//   scapy/layers/dot11.py
//   scapy 2.7.0
//   Copyright (C) Philippe Biondi and the scapy contributors
//
// Changed by the wiry authors:
//   2026-10-04 — the dispatch_hooks of PPTP, PPP_LCP and Dot11Encrypted transcribed as matches

//! scapy's `dispatch_hook`: a class that names one of its subclasses from the
//! bytes it is handed, so `PPTP(octets)` is a `PPTPEchoRequest` and so is the
//! layer TCP port 1723 reaches. Dissection asks `resolve` before it dissects
//! any layer, which is how both cases agree. A subclass inherits its base's
//! bindings in scapy, so stacking binds a variant as `base_of` it as well.
//!
//! Hand-written until protogen can declare a variant in the subclass's spec.

use crate::proto::ProtoId;

/// `b` runs from the layer's first octet to the end of what encloses it.
#[inline]
pub fn resolve(p: ProtoId, b: &[u8]) -> ProtoId {
    match p {
        ProtoId::PPTP => pptp(b),
        ProtoId::PPPLCP => ppp_lcp(b),
        ProtoId::Dot11Encrypted => dot11_encrypted(b),
        _ => p,
    }
}

pub fn base_of(p: ProtoId) -> Option<ProtoId> {
    match p {
        ProtoId::PPTPStartControlConnectionRequest
        | ProtoId::PPTPStartControlConnectionReply
        | ProtoId::PPTPStopControlConnectionRequest
        | ProtoId::PPTPStopControlConnectionReply
        | ProtoId::PPTPEchoRequest
        | ProtoId::PPTPEchoReply
        | ProtoId::PPTPOutgoingCallRequest
        | ProtoId::PPTPOutgoingCallReply
        | ProtoId::PPTPIncomingCallRequest
        | ProtoId::PPTPIncomingCallReply
        | ProtoId::PPTPIncomingCallConnected
        | ProtoId::PPTPCallClearRequest
        | ProtoId::PPTPCallDisconnectNotify
        | ProtoId::PPTPWANErrorNotify
        | ProtoId::PPTPSetLinkInfo => Some(ProtoId::PPTP),
        ProtoId::PPPLCPTerminate | ProtoId::PPPLCPEcho | ProtoId::PPPLCPDiscardRequest => {
            Some(ProtoId::PPPLCP)
        }
        ProtoId::Dot11CCMP => Some(ProtoId::Dot11Encrypted),
        _ => None,
    }
}

#[inline(never)]
fn pptp(b: &[u8]) -> ProtoId {
    match b.get(9) {
        Some(1) => ProtoId::PPTPStartControlConnectionRequest,
        Some(2) => ProtoId::PPTPStartControlConnectionReply,
        Some(3) => ProtoId::PPTPStopControlConnectionRequest,
        Some(4) => ProtoId::PPTPStopControlConnectionReply,
        Some(5) => ProtoId::PPTPEchoRequest,
        Some(6) => ProtoId::PPTPEchoReply,
        Some(7) => ProtoId::PPTPOutgoingCallRequest,
        Some(8) => ProtoId::PPTPOutgoingCallReply,
        Some(9) => ProtoId::PPTPIncomingCallRequest,
        Some(10) => ProtoId::PPTPIncomingCallReply,
        Some(11) => ProtoId::PPTPIncomingCallConnected,
        Some(12) => ProtoId::PPTPCallClearRequest,
        Some(13) => ProtoId::PPTPCallDisconnectNotify,
        Some(14) => ProtoId::PPTPWANErrorNotify,
        Some(15) => ProtoId::PPTPSetLinkInfo,
        _ => ProtoId::PPTP,
    }
}

/// Configure, Code-Reject and Protocol-Reject have no layer yet and stay
/// PPP_LCP, as scapy's hook falls back to its own class.
#[inline(never)]
fn ppp_lcp(b: &[u8]) -> ProtoId {
    match b.first() {
        Some(5 | 6) => ProtoId::PPPLCPTerminate,
        Some(9 | 10) => ProtoId::PPPLCPEcho,
        Some(11) => ProtoId::PPPLCPDiscardRequest,
        _ => ProtoId::PPPLCP,
    }
}

/// Wireshark's test, as scapy transcribes it: an extended IV marks TKIP or
/// CCMP, and TKIP's second octet repeats its first with bit 5 set. TKIP and
/// WEP have no layer yet and stay Dot11Encrypted.
#[inline(never)]
fn dot11_encrypted(b: &[u8]) -> ProtoId {
    match b {
        [b0, b1, b2, b3, ..] if b3 & 0x20 != 0 && b.len() >= 8 => {
            if *b1 == (b0 | 0x20) & 0x7f || *b2 != 0 {
                ProtoId::Dot11Encrypted
            } else {
                ProtoId::Dot11CCMP
            }
        }
        [_, _, _, _, ..] => ProtoId::Dot11Encrypted,
        _ => ProtoId::Raw,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Packet;

    const BASES: &[ProtoId] = &[ProtoId::PPTP, ProtoId::PPPLCP, ProtoId::Dot11Encrypted];

    #[test]
    fn every_variant_resolve_names_binds_as_its_base() {
        for &base in BASES {
            for at in 0..16 {
                for v in 0..=255u8 {
                    let mut b = [0u8; 16];
                    b[at] = v;
                    let r = resolve(base, &b);
                    assert!(
                        r == base || r == ProtoId::Raw || base_of(r) == Some(base),
                        "{}",
                        r.name()
                    );
                }
            }
        }
    }

    /// RFC 2637 §2.4: an Echo-Request is control message type 5.
    #[test]
    fn pptp_names_its_message_from_the_control_type() {
        let echo = [
            0x00, 0x10, 0x00, 0x01, 0x1a, 0x2b, 0x3c, 0x4d, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x2a,
        ];
        let p = Packet::dissect(echo.to_vec(), ProtoId::PPTP);
        assert_eq!(p.layers()[0].proto, ProtoId::PPTPEchoRequest);
        let mut unknown = echo;
        unknown[9] = 99;
        let p = Packet::dissect(unknown.to_vec(), ProtoId::PPTP);
        assert_eq!(p.layers()[0].proto, ProtoId::PPTP);
    }

    /// RFC 1661 §5.5: Terminate-Request is LCP code 5, carried as PPP 0xc021.
    #[test]
    fn a_built_variant_binds_as_its_base_and_dissects_back() {
        let p = Packet::build(&[ProtoId::Ppp, ProtoId::PPPLCPTerminate]);
        assert_eq!(&p.buf[..3], &[0xc0, 0x21, 0x05]);
        let back = Packet::dissect(p.buf.clone(), ProtoId::Ppp);
        assert_eq!(back.layers()[1].proto, ProtoId::PPPLCPTerminate);
    }
}
