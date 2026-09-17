use crate::error::CaptureError;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;
use wiry_core::packet::dissect_spans;
use wiry_core::proto::ProtoId;

/// Sends already-built IPv4 datagrams through a raw socket, letting the kernel
/// route and resolve. Parsing the routing table ourselves would need three OS
/// backends and our own ARP, and the kernel's answer is authoritative anyway.
pub fn send_l3(frames: &[Vec<u8>], count: usize, inter: f64) -> Result<usize, CaptureError> {
    if cfg!(windows) {
        return Err(CaptureError::UnsupportedOn(
            "raw IPv4 sending is restricted on Windows; use sendp() at layer 2",
        ));
    }
    let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(255)))
        .map_err(|e| CaptureError::Permission(format!("raw socket: {e}")))?;
    sock.set_header_included_v4(true)
        .map_err(|e| CaptureError::Pcap(format!("IP_HDRINCL: {e}")))?;

    // The whole repetition happens here, so a thousand datagrams cost one
    // crossing of the boundary rather than a thousand.
    let gap = Duration::from_secs_f64(inter.max(0.0));
    let mut sent = 0usize;
    for _ in 0..count {
        for f in frames {
            let spans = dissect_spans(f, ProtoId::Ipv4);
            if spans.first().map(|s| s.proto) != Some(ProtoId::Ipv4) || f.len() < 20 {
                return Err(CaptureError::UnsupportedOn(
                    "send() takes an IPv4 datagram; wrap it in Ether() and use sendp()",
                ));
            }
            let dst = Ipv4Addr::new(f[16], f[17], f[18], f[19]);
            let to = SockAddr::from(SocketAddrV4::new(dst, 0));
            sock.send_to(f, &to)
                .map_err(|e| CaptureError::Pcap(format!("send: {e}")))?;
            sent += 1;
            if !gap.is_zero() {
                std::thread::sleep(gap);
            }
        }
    }
    Ok(sent)
}
