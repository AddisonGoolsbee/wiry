// SPDX-License-Identifier: GPL-2.0-only
//
// Derived from scapy: scapy/interfaces.py (get_working_if)
//   scapy 2.7.0, upstream commit 7d69454
//   Copyright (C) Philippe Biondi and the scapy contributors
//
// Changed by the wiry authors:
//   2026-09-18 — applied scapy's "an interface is usable when it has an
//                address that is not 0.0.0.0" test to libpcap's own device
//                list, since wiry reads no routing table to sort by

use crate::error::CaptureError;
use crate::sink::PacketMeta;
use crate::{Interface, LiveConfig};
use wiry_pcap as raw;

fn map_err(e: raw::Error, ctx: &str) -> CaptureError {
    match e.kind {
        raw::Kind::NotLoaded => CaptureError::LibraryMissing(e.msg),
        raw::Kind::Permission => {
            CaptureError::Permission(format!("{ctx}: {}", e.msg.trim_end_matches('.')))
        }
        raw::Kind::NoSuchDevice => CaptureError::NoSuchDevice(ctx.to_string()),
        raw::Kind::BadFilter => CaptureError::BadFilter(e.msg),
        raw::Kind::Other => CaptureError::Pcap(e.msg),
    }
}

pub struct Handle {
    cap: raw::Handle,
    linktype: u32,
    name: String,
    blocking: bool,
}

impl Handle {
    /// True only where libpcap refused non-blocking mode. A read may then wait
    /// for a frame however long it takes, whatever the read timeout.
    pub fn reads_block(&self) -> bool {
        self.blocking
    }
}

impl Handle {
    /// Copies the next frame into `scratch`; `Ok(None)` when none is ready.
    pub fn next_into(&mut self, scratch: &mut Vec<u8>) -> Result<Option<PacketMeta>, CaptureError> {
        match self.cap.next_into(scratch) {
            Ok(None) => Ok(None),
            Ok(Some(h)) => Ok(Some(PacketMeta {
                ts_sec: h.ts_sec as u32,
                ts_frac: h.ts_usec as u32,
                caplen: h.caplen,
                origlen: h.origlen,
            })),
            Err(e) => Err(map_err(e, "capture")),
        }
    }

    pub fn send(&mut self, data: &[u8]) -> Result<(), CaptureError> {
        self.cap.sendpacket(data).map_err(|e| map_err(e, "send"))
    }

    pub fn linktype(&self) -> u32 {
        self.linktype
    }

    pub fn set_filter(&mut self, expr: &str) -> Result<(), CaptureError> {
        let mask = raw::lookup_net(&self.name);
        let mut prog = self
            .cap
            .compile(expr, mask)
            .map_err(|e| map_err(e, "filter"))?;
        self.cap
            .set_filter(&mut prog)
            .map_err(|e| map_err(e, "filter"))
    }
}

pub struct CompiledFilter {
    prog: raw::Program,
    /// libpcap frees a program independently of its handle; this is held only
    /// so the program can never outlive the handle that compiled it.
    _dead: raw::Handle,
}

impl CompiledFilter {
    pub fn matches(&self, frame: &[u8]) -> bool {
        self.prog.matches(frame)
    }
}

pub fn available() -> bool {
    raw::available()
}

pub fn unavailable_reason() -> Option<CaptureError> {
    raw::unavailable_reason().map(|e| CaptureError::LibraryMissing(e.msg.clone()))
}

pub fn backend_version() -> Option<String> {
    raw::lib_version()
}

pub fn backend_path() -> Option<String> {
    raw::loaded_path().map(str::to_string)
}

pub fn list_interfaces() -> Result<Vec<Interface>, CaptureError> {
    let devs = raw::find_all_devs().map_err(|e| map_err(e, "list"))?;
    Ok(devs
        .into_iter()
        .map(|d| Interface {
            name: d.name,
            description: d.description,
            addresses: d.addresses,
            loopback: d.loopback,
        })
        .collect())
}

/// The interface a capture with no `iface=` uses: the first non-loopback with
/// a routable IPv4 address, else the first non-loopback with any address, else
/// a loopback. This is scapy's `get_working_if` test over libpcap's device
/// list; `pcap_lookupdev` is deprecated and returns an arbitrary device.
pub fn default_interface() -> Result<String, CaptureError> {
    let ifs = list_interfaces()?;
    let routable = |a: &&String| {
        a.parse::<std::net::Ipv4Addr>()
            .is_ok_and(|v4| !v4.is_link_local() && !v4.is_unspecified())
    };
    let pick = ifs
        .iter()
        .find(|i| !i.loopback && i.addresses.iter().any(|a| routable(&a)))
        .or_else(|| ifs.iter().find(|i| !i.loopback && !i.addresses.is_empty()))
        .or_else(|| ifs.iter().find(|i| i.loopback))
        .or_else(|| ifs.first());
    match pick {
        Some(i) => Ok(i.name.clone()),
        None => Err(CaptureError::NoSuchDevice("default".into())),
    }
}

pub fn open_live(cfg: &LiveConfig) -> Result<Handle, CaptureError> {
    let dev = if cfg.iface.is_empty() {
        default_interface()?
    } else {
        cfg.iface.clone()
    };
    let mut cap = raw::Handle::create(&dev).map_err(|e| map_err(e, &dev))?;
    cap.set_snaplen(cfg.snaplen).map_err(|e| map_err(e, &dev))?;
    cap.set_promisc(cfg.promisc).map_err(|e| map_err(e, &dev))?;
    cap.set_timeout(cfg.read_timeout_ms)
        .map_err(|e| map_err(e, &dev))?;
    // A libpcap without immediate mode still captures, only in batches.
    let _ = cap.set_immediate_mode(cfg.immediate);
    cap.activate().map_err(|e| map_err(e, &dev))?;

    // The read timeout does not bound a read: on Linux pcap_next_ex blocks until
    // a frame arrives, so a silent interface would starve every stop condition.
    // The driver waits instead; the timeout remains for a libpcap that refuses
    // non-blocking mode.
    let blocking = cap.set_nonblock(true).is_err();

    let linktype = cap.datalink() as u32;
    let mut h = Handle {
        cap,
        linktype,
        name: dev,
        blocking,
    };
    if let Some(f) = &cfg.filter {
        h.set_filter(f)?;
    }
    Ok(h)
}

/// The DLT libpcap's compiler expects for a file's LINKTYPE. They differ only
/// where a BSD assigned a DLT before the file format reserved a number
/// (`linktype_to_dlt` in libpcap's pcap-common.c).
fn dlt_of(linktype: u32) -> u32 {
    match linktype {
        100 => 11,
        101 if cfg!(target_os = "openbsd") => 14,
        101 => 12,
        102 => 15,
        103 => 16,
        106 => 19,
        other => other,
    }
}

pub fn compile_filter(
    linktype: u32,
    expr: &str,
    snaplen: u32,
) -> Result<CompiledFilter, CaptureError> {
    let mut dead =
        raw::Handle::open_dead(dlt_of(linktype) as i32, snaplen.min(i32::MAX as u32) as i32)
            .map_err(|e| map_err(e, "dead"))?;
    let prog = dead.compile(expr, None).map_err(|e| map_err(e, "filter"))?;
    Ok(CompiledFilter { prog, _dead: dead })
}

pub fn send_l3(frames: &[Vec<u8>], count: usize, inter: f64) -> Result<usize, CaptureError> {
    crate::l3::send_l3(frames, count, inter)
}

#[cfg(test)]
mod tests {
    use super::dlt_of;

    #[test]
    fn a_file_link_type_is_compiled_against_its_dlt() {
        let raw = if cfg!(target_os = "openbsd") { 14 } else { 12 };
        assert_eq!(dlt_of(101), raw);
        assert_eq!(dlt_of(100), 11);
        assert_eq!(dlt_of(1), 1);
        assert_eq!(dlt_of(228), 228);
    }
}
