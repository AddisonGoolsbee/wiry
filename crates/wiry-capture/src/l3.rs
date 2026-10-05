use crate::error::CaptureError;
use crate::ipv4_dst;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::SocketAddrV4;
use std::time::Duration;

/// Sends every datagram in `frames`, `count` times over, through one raw
/// socket, pausing `inter` seconds after each; returns how many went out. The
/// kernel routes and resolves, which is authoritative and needs no ARP here.
pub fn send_l3(frames: &[Vec<u8>], count: usize, inter: f64) -> Result<usize, CaptureError> {
    if cfg!(windows) {
        return Err(CaptureError::UnsupportedOn(
            "raw IPv4 sending is restricted on Windows; use sendp() at layer 2",
        ));
    }
    // Validate every datagram first, so a bad one refuses the batch instead of
    // leaving it half sent.
    let dsts = frames
        .iter()
        .map(|f| {
            ipv4_dst(f).ok_or_else(|| {
                CaptureError::BadArgument(
                    "send() takes an IPv4 datagram; wrap it in Ether() and use sendp()".into(),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    // Refused rather than clamped: Duration::MAX would turn the error into a hang.
    let gap = Duration::try_from_secs_f64(inter.max(0.0)).map_err(|_| {
        CaptureError::BadArgument(format!(
            "inter= must be a finite number of seconds, not {inter}"
        ))
    })?;

    let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(255)))
        .map_err(|e| CaptureError::Permission(format!("a raw IPv4 socket: {e}")))?;
    sock.set_header_included_v4(true)
        .map_err(|e| CaptureError::Pcap(format!("IP_HDRINCL: {e}")))?;

    // Repetition happens here so `count` sends cost one FFI crossing.
    let mut sent = 0usize;
    for _ in 0..count {
        for (f, dst) in frames.iter().zip(&dsts) {
            let to = SockAddr::from(SocketAddrV4::new((*dst).into(), 0));
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
