// SPDX-License-Identifier: GPL-2.0-only
//
// Derived from scapy: scapy/libs/winpcapy.py, scapy/libs/structures.py
//   scapy 2.7.0, upstream commit 7d69454
//   Copyright (C) Massimo Ciani (2009), Gabriel Potter
//
// Changed by the wiry authors:
//   2026-09-18 — translated the ctypes Structures to repr(C) Rust, and made
//                timeval's tv_usec 32-bit on the BSDs, where scapy reads a
//                long over four octets of padding

//! The C declarations, transcribed from `pcap/pcap.h` and `pcap/bpf.h`
//! (libpcap 1.10, BSD-3-Clause) and cross-checked against scapy's ctypes
//! bindings in `scapy/libs/winpcapy.py` and `scapy/libs/structures.py`.
//!
//! Nothing here is called directly. `lib.rs` owns every pointer these produce.

use core::ffi::{c_char, c_int, c_long, c_uint, c_void};

pub const PCAP_ERRBUF_SIZE: usize = 256;

/// `pcap_activate` and friends return these. Negative is failure, positive a
/// warning that still activated the handle (RFC-free: `pcap.h` says so).
pub const PCAP_ERROR_NO_SUCH_DEVICE: c_int = -5;
pub const PCAP_ERROR_PERM_DENIED: c_int = -8;
pub const PCAP_ERROR_IFACE_NOT_UP: c_int = -9;
pub const PCAP_ERROR_PROMISC_PERM_DENIED: c_int = -11;

pub const PCAP_IF_LOOPBACK: c_uint = 0x0000_0001;

/// What `pcap_compile` wants when no netmask is known. Only `ip broadcast`
/// needs one, and it is the one thing a dead handle cannot know.
pub const PCAP_NETMASK_UNKNOWN: c_uint = 0xffff_ffff;

pub type PcapT = c_void;

/// `suseconds_t`. The BSDs and macOS make it a 32-bit int inside a struct that
/// still aligns to 8, so reading it as a `long` would take four bytes of
/// padding libpcap never wrote.
#[cfg(any(
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
pub type Suseconds = c_int;
#[cfg(not(any(
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
pub type Suseconds = c_long;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Timeval {
    pub tv_sec: c_long,
    pub tv_usec: Suseconds,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PcapPkthdr {
    pub ts: Timeval,
    pub caplen: c_uint,
    pub len: c_uint,
}

#[repr(C)]
pub struct BpfInsn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[repr(C)]
pub struct BpfProgram {
    pub bf_len: c_uint,
    pub bf_insns: *mut BpfInsn,
}

#[repr(C)]
pub struct PcapAddr {
    pub next: *mut PcapAddr,
    pub addr: *mut Sockaddr,
    pub netmask: *mut Sockaddr,
    pub broadaddr: *mut Sockaddr,
    pub dstaddr: *mut Sockaddr,
}

#[repr(C)]
pub struct PcapIf {
    pub next: *mut PcapIf,
    pub name: *mut c_char,
    pub description: *mut c_char,
    pub addresses: *mut PcapAddr,
    pub flags: c_uint,
}

/// Opaque on purpose. libpcap allocates each of these at the size of its own
/// family — 16 octets for an `AF_INET`, 28 for an `AF_INET6` — so a Rust struct
/// wide enough for the larger would read past the smaller. Callers read single
/// octets at known offsets instead, and only after the family says how many
/// there are.
pub type Sockaddr = c_void;

pub type PcapCreate = unsafe extern "C" fn(*const c_char, *mut c_char) -> *mut PcapT;
pub type PcapSetInt = unsafe extern "C" fn(*mut PcapT, c_int) -> c_int;
pub type PcapActivate = unsafe extern "C" fn(*mut PcapT) -> c_int;
pub type PcapClose = unsafe extern "C" fn(*mut PcapT);
pub type PcapNextEx =
    unsafe extern "C" fn(*mut PcapT, *mut *mut PcapPkthdr, *mut *const u8) -> c_int;
pub type PcapSendpacket = unsafe extern "C" fn(*mut PcapT, *const u8, c_int) -> c_int;
pub type PcapDatalink = unsafe extern "C" fn(*mut PcapT) -> c_int;
pub type PcapGeterr = unsafe extern "C" fn(*mut PcapT) -> *mut c_char;
pub type PcapStatustostr = unsafe extern "C" fn(c_int) -> *const c_char;
pub type PcapCompile =
    unsafe extern "C" fn(*mut PcapT, *mut BpfProgram, *const c_char, c_int, c_uint) -> c_int;
pub type PcapSetfilter = unsafe extern "C" fn(*mut PcapT, *mut BpfProgram) -> c_int;
pub type PcapSetnonblock = unsafe extern "C" fn(*mut PcapT, c_int, *mut c_char) -> c_int;
pub type PcapFreecode = unsafe extern "C" fn(*mut BpfProgram);
pub type PcapOfflineFilter =
    unsafe extern "C" fn(*const BpfProgram, *const PcapPkthdr, *const u8) -> c_int;
pub type PcapOpenDead = unsafe extern "C" fn(c_int, c_int) -> *mut PcapT;
pub type PcapFindalldevs = unsafe extern "C" fn(*mut *mut PcapIf, *mut c_char) -> c_int;
pub type PcapFreealldevs = unsafe extern "C" fn(*mut PcapIf);
pub type PcapLookupnet =
    unsafe extern "C" fn(*const c_char, *mut c_uint, *mut c_uint, *mut c_char) -> c_int;
pub type PcapLibVersion = unsafe extern "C" fn() -> *const c_char;
