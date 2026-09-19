//! libpcap, loaded at run time.
//!
//! wiry does not link against libpcap. A wheel that did could only be built on
//! a machine with the development headers and could only run on one with the
//! matching shared object, which is why every earlier build kept live capture
//! behind an off-by-default feature. scapy has never had that problem: it
//! `dlopen`s libpcap through ctypes when it is asked to capture and reports a
//! missing library as a missing library. This crate is that, in Rust.
//!
//! **This is the one crate in the workspace that contains `unsafe`.** Every
//! other one is `#![forbid(unsafe_code)]`, and the dissection engine — the part
//! that reads attacker-controlled bytes — is among them. What is unsafe here is
//! the FFI itself: loading a library, calling through a function pointer, and
//! owning the four kinds of pointer libpcap hands back. Nothing in this file
//! parses a packet.
//!
//! Declarations are transcribed from `pcap/pcap.h` (libpcap 1.10,
//! BSD-3-Clause), cross-checked against scapy's ctypes bindings. See `NOTICE`.

#![deny(unsafe_op_in_unsafe_fn)]

mod sys;

use std::ffi::{CStr, CString};
use std::net::Ipv6Addr;
use std::os::raw::{c_char, c_int, c_uint};
use std::sync::{Mutex, OnceLock};

use libloading::Library;
use sys::*;

/// What went wrong, in the shape the caller needs to map it. The message is
/// always libpcap's own where libpcap produced one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// libpcap is not on this machine, or is not loadable.
    NotLoaded,
    Permission,
    NoSuchDevice,
    BadFilter,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub kind: Kind,
    pub msg: String,
}

impl Error {
    fn other(msg: impl Into<String>) -> Self {
        Self {
            kind: Kind::Other,
            msg: msg.into(),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for Error {}

pub struct Device {
    pub name: String,
    pub description: Option<String>,
    pub addresses: Vec<String>,
    pub loopback: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct PktHdr {
    pub ts_sec: i64,
    pub ts_usec: i64,
    pub caplen: u32,
    pub origlen: u32,
}

// ---------------------------------------------------------------- loading ---

struct Api {
    path: String,
    create: PcapCreate,
    set_snaplen: PcapSetInt,
    set_promisc: PcapSetInt,
    set_timeout: PcapSetInt,
    /// libpcap 1.5 and later. An older one still captures; it just batches.
    set_immediate_mode: Option<PcapSetInt>,
    activate: PcapActivate,
    close: PcapClose,
    next_ex: PcapNextEx,
    sendpacket: PcapSendpacket,
    datalink: PcapDatalink,
    geterr: PcapGeterr,
    statustostr: Option<PcapStatustostr>,
    compile: PcapCompile,
    setfilter: PcapSetfilter,
    freecode: PcapFreecode,
    offline_filter: PcapOfflineFilter,
    open_dead: PcapOpenDead,
    findalldevs: PcapFindalldevs,
    freealldevs: PcapFreealldevs,
    lookupnet: PcapLookupnet,
    lib_version: Option<PcapLibVersion>,
    /// Dropping this would `dlclose` libpcap out from under every pointer
    /// above, so it is held for the life of the process and never touched.
    _lib: Library,
}

// SAFETY: every field is either a plain `extern "C" fn` pointer, which is Send
// and Sync, or the `Library` handle, which libloading documents as both.
unsafe impl Send for Api {}
// SAFETY: as above.
unsafe impl Sync for Api {}

/// libpcap before 1.8 kept the filter compiler's lexer in globals, so two
/// threads compiling at once corrupted each other. Distributions still ship
/// those; serialising costs nothing next to the parse.
static COMPILE_LOCK: Mutex<()> = Mutex::new(());

static API: OnceLock<Result<Api, Error>> = OnceLock::new();

fn candidates() -> Vec<String> {
    if let Ok(p) = std::env::var("WIRY_LIBPCAP") {
        if !p.is_empty() {
            return vec![p];
        }
    }
    #[cfg(target_vendor = "apple")]
    {
        vec![
            "/usr/lib/libpcap.A.dylib".into(),
            "libpcap.A.dylib".into(),
            "libpcap.dylib".into(),
        ]
    }
    #[cfg(windows)]
    {
        // Npcap installs beside, not over, an older WinPcap, and its directory
        // is deliberately absent from the default search path. scapy prepends
        // it; so does this.
        let mut out = Vec::new();
        if let Ok(windir) = std::env::var("WINDIR") {
            out.push(format!("{windir}\\System32\\Npcap\\wpcap.dll"));
        }
        out.push("wpcap.dll".into());
        out
    }
    #[cfg(all(unix, not(target_vendor = "apple")))]
    {
        vec![
            "libpcap.so.1".into(),
            "libpcap.so.0.8".into(),
            "libpcap.so".into(),
        ]
    }
}

fn install_hint() -> &'static str {
    if cfg!(windows) {
        "install Npcap from https://npcap.com (tick \"Install Npcap in WinPcap API-compatible Mode\")"
    } else if cfg!(target_vendor = "apple") {
        "libpcap ships with macOS, so this host is unusual; set WIRY_LIBPCAP to its full path"
    } else {
        "install libpcap — Debian/Ubuntu: apt install libpcap0.8; \
         Fedora/RHEL: dnf install libpcap; Alpine: apk add libpcap"
    }
}

/// # Safety
/// `name` must be the NUL-terminated name of a symbol in `lib` whose C type is
/// exactly `T`.
unsafe fn sym<T: Copy>(lib: &Library, name: &[u8]) -> Option<T> {
    // SAFETY: the caller guarantees the type; the pointer is copied out and the
    // library outlives it, being leaked into `API` for the life of the process.
    unsafe { lib.get::<T>(name) }.ok().map(|s| *s)
}

fn required<T: Copy>(lib: &Library, name: &'static [u8], path: &str) -> Result<T, Error> {
    // SAFETY: each call site names a symbol declared in `sys` with the type
    // `pcap.h` gives it.
    unsafe { sym::<T>(lib, name) }.ok_or_else(|| Error {
        kind: Kind::NotLoaded,
        msg: format!(
            "{path} loaded but has no {}; it does not look like libpcap",
            String::from_utf8_lossy(&name[..name.len() - 1])
        ),
    })
}

fn load() -> Result<Api, Error> {
    let tried = candidates();
    let mut lib = None;
    for c in &tried {
        // SAFETY: loading a shared library runs its initialisers, which is the
        // whole point. The candidates are libpcap's own SONAMEs, or a path the
        // operator set deliberately.
        if let Ok(l) = unsafe { Library::new(c) } {
            lib = Some((l, c.clone()));
            break;
        }
    }
    let (lib, path) = lib.ok_or_else(|| Error {
        kind: Kind::NotLoaded,
        msg: format!(
            "libpcap could not be loaded, so live capture is unavailable \
             (tried {}). To fix it, {}. Reading and writing capture files \
             does not need it.",
            tried.join(", "),
            install_hint()
        ),
    })?;

    Ok(Api {
        create: required(&lib, b"pcap_create\0", &path)?,
        set_snaplen: required(&lib, b"pcap_set_snaplen\0", &path)?,
        set_promisc: required(&lib, b"pcap_set_promisc\0", &path)?,
        set_timeout: required(&lib, b"pcap_set_timeout\0", &path)?,
        // SAFETY: `pcap_set_immediate_mode(pcap_t *, int)` where it exists.
        set_immediate_mode: unsafe { sym(&lib, b"pcap_set_immediate_mode\0") },
        activate: required(&lib, b"pcap_activate\0", &path)?,
        close: required(&lib, b"pcap_close\0", &path)?,
        next_ex: required(&lib, b"pcap_next_ex\0", &path)?,
        sendpacket: required(&lib, b"pcap_sendpacket\0", &path)?,
        datalink: required(&lib, b"pcap_datalink\0", &path)?,
        geterr: required(&lib, b"pcap_geterr\0", &path)?,
        // SAFETY: `const char *pcap_statustostr(int)` where it exists.
        statustostr: unsafe { sym(&lib, b"pcap_statustostr\0") },
        compile: required(&lib, b"pcap_compile\0", &path)?,
        setfilter: required(&lib, b"pcap_setfilter\0", &path)?,
        freecode: required(&lib, b"pcap_freecode\0", &path)?,
        offline_filter: required(&lib, b"pcap_offline_filter\0", &path)?,
        open_dead: required(&lib, b"pcap_open_dead\0", &path)?,
        findalldevs: required(&lib, b"pcap_findalldevs\0", &path)?,
        freealldevs: required(&lib, b"pcap_freealldevs\0", &path)?,
        lookupnet: required(&lib, b"pcap_lookupnet\0", &path)?,
        // SAFETY: `const char *pcap_lib_version(void)`.
        lib_version: unsafe { sym(&lib, b"pcap_lib_version\0") },
        path,
        _lib: lib,
    })
}

fn api() -> Result<&'static Api, &'static Error> {
    API.get_or_init(load).as_ref()
}

/// Whether libpcap is loadable on this host. Never raises, and the answer is
/// computed once.
pub fn available() -> bool {
    api().is_ok()
}

/// Why libpcap could not be loaded, and `None` when it could.
pub fn unavailable_reason() -> Option<&'static Error> {
    api().err()
}

/// The file that was loaded, for a diagnostic that has to be believable.
pub fn loaded_path() -> Option<&'static str> {
    api().ok().map(|a| a.path.as_str())
}

/// libpcap's own version banner, e.g. `libpcap version 1.10.4`.
pub fn lib_version() -> Option<String> {
    let a = api().ok()?;
    let f = a.lib_version?;
    // SAFETY: pcap_lib_version returns a pointer to a static string.
    Some(
        unsafe { CStr::from_ptr(f()) }
            .to_string_lossy()
            .into_owned(),
    )
}

// ------------------------------------------------------------------ errors ---

/// # Safety
/// `p` must be NUL-terminated and valid for reads up to the NUL.
unsafe fn text(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: the caller guarantees the pointer.
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

fn classify(msg: &str, code: Option<c_int>) -> Kind {
    // The status code is exact where there is one; the string is the fallback
    // for the calls that return only -1 and a buffer.
    match code {
        Some(PCAP_ERROR_PERM_DENIED) | Some(PCAP_ERROR_PROMISC_PERM_DENIED) => {
            return Kind::Permission
        }
        Some(PCAP_ERROR_NO_SUCH_DEVICE) => return Kind::NoSuchDevice,
        _ => {}
    }
    let l = msg.to_ascii_lowercase();
    if l.contains("permission") || l.contains("not permitted") || l.contains("operation not perm") {
        Kind::Permission
    } else if l.contains("no such device") || l.contains("not exist") {
        Kind::NoSuchDevice
    } else {
        Kind::Other
    }
}

// ----------------------------------------------------------------- handles ---

/// An owned `pcap_t`. Closed on drop.
pub struct Handle {
    raw: *mut PcapT,
    api: &'static Api,
}

// SAFETY: libpcap permits a handle to be used from any one thread at a time,
// which is all `&mut self` on a non-Sync type allows. `AsyncSniffer` moves one
// to a capture thread and never shares it.
unsafe impl Send for Handle {}

impl Handle {
    /// A handle for `device`, created but not yet activated: snaplen, promisc
    /// and the read timeout are only settable before `activate`.
    pub fn create(device: &str) -> Result<Handle, Error> {
        let api = api().map_err(|e| e.clone())?;
        let name = CString::new(device)
            .map_err(|_| Error::other("an interface name cannot contain a NUL"))?;
        let mut err = [0i8 as c_char; PCAP_ERRBUF_SIZE];
        // SAFETY: `name` outlives the call; `err` is PCAP_ERRBUF_SIZE as the
        // contract requires.
        let raw = unsafe { (api.create)(name.as_ptr(), err.as_mut_ptr()) };
        if raw.is_null() {
            // SAFETY: on failure pcap_create fills the buffer with a C string.
            let msg = unsafe { text(err.as_ptr()) };
            return Err(Error {
                kind: classify(&msg, None),
                msg,
            });
        }
        Ok(Handle { raw, api })
    }

    /// A handle that is attached to nothing, for compiling a filter against a
    /// link type without an interface or any privilege at all.
    pub fn open_dead(linktype: i32, snaplen: i32) -> Result<Handle, Error> {
        let api = api().map_err(|e| e.clone())?;
        // SAFETY: no pointers; pcap_open_dead allocates or returns NULL.
        let raw = unsafe { (api.open_dead)(linktype as c_int, snaplen as c_int) };
        if raw.is_null() {
            return Err(Error::other("pcap_open_dead failed to allocate"));
        }
        Ok(Handle { raw, api })
    }

    fn err(&mut self, ctx: &str, code: Option<c_int>) -> Error {
        // SAFETY: pcap_geterr returns the handle's own buffer, valid while the
        // handle is.
        let mut msg = unsafe { text((self.api.geterr)(self.raw)) };
        if msg.is_empty() {
            msg = match (code, self.api.statustostr) {
                // SAFETY: pcap_statustostr returns a pointer to a static string.
                (Some(c), Some(f)) => unsafe { text(f(c)) },
                _ => format!("{ctx} failed"),
            };
        }
        Error {
            kind: classify(&msg, code),
            msg: format!("{ctx}: {msg}"),
        }
    }

    fn set(&mut self, f: PcapSetInt, v: c_int, what: &str) -> Result<(), Error> {
        // SAFETY: a live, unactivated handle and a plain int.
        let rc = unsafe { f(self.raw, v) };
        if rc < 0 {
            Err(self.err(what, Some(rc)))
        } else {
            Ok(())
        }
    }

    pub fn set_snaplen(&mut self, v: u32) -> Result<(), Error> {
        self.set(
            self.api.set_snaplen,
            v.min(c_int::MAX as u32) as c_int,
            "snaplen",
        )
    }

    pub fn set_promisc(&mut self, v: bool) -> Result<(), Error> {
        self.set(self.api.set_promisc, c_int::from(v), "promisc")
    }

    /// libpcap's read timeout, in milliseconds. Never 0: the pcap README warns
    /// that can hang `pcap_next_ex` on macOS, and the timeout is how the driver
    /// gets a turn to check its deadline and its stop flag.
    pub fn set_timeout(&mut self, ms: i32) -> Result<(), Error> {
        self.set(self.api.set_timeout, ms as c_int, "read timeout")
    }

    /// `Ok(false)` where this libpcap predates the call, which is not an error:
    /// capture still works, in whatever batches the kernel chooses.
    pub fn set_immediate_mode(&mut self, v: bool) -> Result<bool, Error> {
        match self.api.set_immediate_mode {
            None => Ok(false),
            Some(f) => self.set(f, c_int::from(v), "immediate mode").map(|()| true),
        }
    }

    pub fn activate(&mut self) -> Result<(), Error> {
        // SAFETY: a live handle from pcap_create, not yet activated.
        let rc = unsafe { (self.api.activate)(self.raw) };
        // Positive is a warning that still activated: promiscuous mode refused
        // on an interface that captures anyway, a link type substituted.
        if rc < 0 {
            let mut e = self.err("open", Some(rc));
            if rc == PCAP_ERROR_IFACE_NOT_UP {
                e.msg = format!("{e} (the interface is down)");
            }
            return Err(e);
        }
        Ok(())
    }

    pub fn datalink(&self) -> i32 {
        // SAFETY: a live handle.
        unsafe { (self.api.datalink)(self.raw) }
    }

    /// The next frame, copied into `out`. `Ok(None)` is the read timeout
    /// expiring, which is the driver's turn to poll, not a failure.
    ///
    /// The copy happens while libpcap's own borrow is live because the next
    /// read reuses that slot.
    pub fn next_into(&mut self, out: &mut Vec<u8>) -> Result<Option<PktHdr>, Error> {
        let mut hdr: *mut PcapPkthdr = std::ptr::null_mut();
        let mut data: *const u8 = std::ptr::null();
        // SAFETY: both out-parameters are live locals; libpcap writes pointers
        // into them that stay valid until the next call on this handle.
        let rc = unsafe { (self.api.next_ex)(self.raw, &mut hdr, &mut data) };
        match rc {
            1 if !hdr.is_null() && !data.is_null() => {
                // SAFETY: rc == 1 means libpcap filled both pointers, and the
                // header it points at is a whole `pcap_pkthdr`.
                let h = unsafe { *hdr };
                // SAFETY: libpcap guarantees `caplen` readable octets at `data`
                // until the next read on this handle, which is after the copy.
                let bytes = unsafe { std::slice::from_raw_parts(data, h.caplen as usize) };
                out.clear();
                out.extend_from_slice(bytes);
                Ok(Some(PktHdr {
                    ts_sec: h.ts.tv_sec as i64,
                    ts_usec: h.ts.tv_usec as i64,
                    caplen: h.caplen as u32,
                    origlen: h.len as u32,
                }))
            }
            // 0 is the read timeout; -2 is end-of-file, which a live handle
            // never reports and a caller treats the same way.
            0 | -2 | 1 => Ok(None),
            _ => Err(self.err("capture", Some(rc))),
        }
    }

    pub fn sendpacket(&mut self, data: &[u8]) -> Result<(), Error> {
        let len = c_int::try_from(data.len())
            .map_err(|_| Error::other("a frame longer than an int cannot be sent"))?;
        // SAFETY: libpcap reads `len` octets from `data` and does not retain it.
        let rc = unsafe { (self.api.sendpacket)(self.raw, data.as_ptr(), len) };
        if rc < 0 {
            Err(self.err("send", Some(rc)))
        } else {
            Ok(())
        }
    }

    pub fn compile(&mut self, expr: &str, netmask: Option<u32>) -> Result<Program, Error> {
        let src = CString::new(expr)
            .map_err(|_| Error::other("a capture filter cannot contain a NUL"))?;
        let mut prog = BpfProgram {
            bf_len: 0,
            bf_insns: std::ptr::null_mut(),
        };
        let rc = {
            let _guard = COMPILE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            // SAFETY: `prog` is an out-parameter libpcap fills on success and
            // leaves alone on failure; `src` outlives the call.
            unsafe {
                (self.api.compile)(
                    self.raw,
                    &mut prog,
                    src.as_ptr(),
                    1,
                    netmask.unwrap_or(PCAP_NETMASK_UNKNOWN) as c_uint,
                )
            }
        };
        if rc < 0 {
            let mut e = self.err("filter", Some(rc));
            e.kind = Kind::BadFilter;
            return Err(e);
        }
        Ok(Program {
            prog,
            api: self.api,
        })
    }

    /// Installs a compiled program on this handle, so the kernel drops what
    /// does not match before it is ever copied to userland.
    pub fn set_filter(&mut self, p: &mut Program) -> Result<(), Error> {
        // SAFETY: a live handle and a program compiled by this same libpcap.
        let rc = unsafe { (self.api.setfilter)(self.raw, &mut p.prog) };
        if rc < 0 {
            let mut e = self.err("filter", Some(rc));
            e.kind = Kind::BadFilter;
            Err(e)
        } else {
            Ok(())
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle is live and this is the only owner.
        unsafe { (self.api.close)(self.raw) }
    }
}

/// A compiled BPF program, freed on drop.
pub struct Program {
    prog: BpfProgram,
    api: &'static Api,
}

// SAFETY: the instruction array is written once by pcap_compile and only read
// afterwards; pcap_offline_filter is a pure interpreter over it.
unsafe impl Send for Program {}
// SAFETY: as above.
unsafe impl Sync for Program {}

impl Program {
    /// Runs the filter over one frame in userland, for the paths that have no
    /// kernel to run it in: an offline capture, or a frame already read.
    pub fn matches(&self, frame: &[u8]) -> bool {
        let n = frame.len().min(c_uint::MAX as usize) as c_uint;
        let hdr = PcapPkthdr {
            ts: Timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            caplen: n,
            len: n,
        };
        // SAFETY: the program is live, the header is a local, and libpcap reads
        // at most `caplen` octets from the frame.
        unsafe { (self.api.offline_filter)(&self.prog, &hdr, frame.as_ptr()) != 0 }
    }

    pub fn len(&self) -> usize {
        self.prog.bf_len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl std::fmt::Debug for Program {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Program({} instructions)", self.len())
    }
}

impl Drop for Program {
    fn drop(&mut self) {
        // SAFETY: pcap_freecode frees the instruction array and zeroes the
        // struct; this is the only owner.
        unsafe { (self.api.freecode)(&mut self.prog) }
    }
}

// -------------------------------------------------------------- interfaces ---

const AF_INET: u16 = 2;
#[cfg(any(
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "dragonfly"
))]
const AF_INET6: u16 = 30;
#[cfg(any(target_os = "openbsd", target_os = "netbsd"))]
const AF_INET6: u16 = 24;
#[cfg(windows)]
const AF_INET6: u16 = 23;
#[cfg(not(any(
    windows,
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_os = "netbsd"
)))]
const AF_INET6: u16 = 10;

/// # Safety
/// `sa` must be null or point at a `struct sockaddr` sized for its own family.
unsafe fn sockaddr_str(sa: *const Sockaddr) -> Option<String> {
    if sa.is_null() {
        return None;
    }
    let p = sa.cast::<u8>();
    // Every sockaddr is at least 16 octets, so the first two are always there.
    // On the BSDs they are a length and a family; everywhere else a 16-bit
    // family. Reading them as octets covers both without a second layout.
    // SAFETY: the caller guarantees a real sockaddr, which is never shorter.
    let head = unsafe { [*p, *p.add(1)] };
    let family = if cfg!(any(
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )) {
        u16::from(head[1])
    } else {
        u16::from_ne_bytes(head)
    };
    // The address sits after the family and the port in both layouts: four
    // octets in for IPv4, eight for IPv6, where the flow label intervenes.
    match family {
        AF_INET => {
            // SAFETY: a sockaddr_in is 16 octets, so 4..8 is inside it.
            let o = unsafe { [*p.add(4), *p.add(5), *p.add(6), *p.add(7)] };
            Some(format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3]))
        }
        AF_INET6 => {
            let mut o = [0u8; 16];
            for (i, b) in o.iter_mut().enumerate() {
                // SAFETY: a sockaddr_in6 is 28 octets, so 8..24 is inside it.
                *b = unsafe { *p.add(8 + i) };
            }
            Some(Ipv6Addr::from(o).to_string())
        }
        _ => None,
    }
}

/// Every interface libpcap will admit to, with its addresses.
///
/// Unprivileged on every platform: this is `getifaddrs`, not a capture.
pub fn find_all_devs() -> Result<Vec<Device>, Error> {
    let api = api().map_err(|e| e.clone())?;
    let mut head: *mut PcapIf = std::ptr::null_mut();
    let mut err = [0i8 as c_char; PCAP_ERRBUF_SIZE];
    // SAFETY: both out-parameters are live locals of the required size.
    let rc = unsafe { (api.findalldevs)(&mut head, err.as_mut_ptr()) };
    if rc < 0 {
        // SAFETY: on failure libpcap fills the buffer with a C string.
        let msg = unsafe { text(err.as_ptr()) };
        return Err(Error {
            kind: classify(&msg, Some(rc)),
            msg,
        });
    }
    let mut out = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: libpcap's list is a chain of live `pcap_if_t` until NULL, and
        // nothing frees it before `pcap_freealldevs` below.
        let d = unsafe { &*cur };
        let mut addresses = Vec::new();
        let mut a = d.addresses;
        while !a.is_null() {
            // SAFETY: as above, for the address chain hanging off this device.
            let ad = unsafe { &*a };
            // SAFETY: libpcap sizes each sockaddr for its own family.
            if let Some(s) = unsafe { sockaddr_str(ad.addr) } {
                addresses.push(s);
            }
            a = ad.next;
        }
        out.push(Device {
            // SAFETY: libpcap always sets `name`; `description` may be NULL,
            // which `text` answers with an empty string.
            name: unsafe { text(d.name) },
            description: match unsafe { text(d.description) } {
                s if s.is_empty() => None,
                s => Some(s),
            },
            addresses,
            loopback: d.flags & PCAP_IF_LOOPBACK != 0,
        });
        cur = d.next;
    }
    // SAFETY: `head` is the list libpcap just allocated and nothing above kept
    // a pointer into it — every string was copied.
    unsafe { (api.freealldevs)(head) };
    Ok(out)
}

/// The netmask of `device`, for the two filter primitives that need one
/// (`ip broadcast`, `ip multicast`). `None` wherever libpcap will not say,
/// which is not an error: the filter compiles either way.
pub fn lookup_net(device: &str) -> Option<u32> {
    let api = api().ok()?;
    let name = CString::new(device).ok()?;
    let (mut net, mut mask) = (0 as c_uint, 0 as c_uint);
    let mut err = [0i8 as c_char; PCAP_ERRBUF_SIZE];
    // SAFETY: `name` outlives the call and all three out-parameters are live
    // locals of the required size.
    let rc = unsafe { (api.lookupnet)(name.as_ptr(), &mut net, &mut mask, err.as_mut_ptr()) };
    (rc == 0).then_some(mask)
}

/// The canonical explanation for a host that cannot capture, for the callers
/// that must raise it without having tried anything yet.
pub fn require() -> Result<(), Error> {
    api().map(|_| ()).map_err(|e| e.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ETHERNET: i32 = 1;

    #[test]
    fn availability_is_a_stable_answer_and_never_panics() {
        let first = available();
        assert_eq!(first, available());
        assert_eq!(first, unavailable_reason().is_none());
        assert_eq!(first, loaded_path().is_some());
    }

    #[test]
    fn an_unloadable_libpcap_explains_itself_rather_than_failing_silently() {
        if let Some(e) = unavailable_reason() {
            assert_eq!(e.kind, Kind::NotLoaded);
            assert!(e.msg.contains("libpcap"), "{}", e.msg);
            assert!(!e.msg.is_empty());
        }
    }

    /// The whole point of the crate: the three things below need no interface,
    /// no root and no /dev/bpf, so they run in ordinary CI on every platform
    /// that has libpcap at all.
    #[test]
    fn a_filter_compiles_and_runs_with_no_device_and_no_privileges() {
        if !available() {
            return;
        }
        let mut dead = Handle::open_dead(ETHERNET, 65535).unwrap();
        let p = dead.compile("tcp port 80", None).unwrap();
        assert!(!p.is_empty(), "a compiled filter with no instructions");

        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&[0x08, 0x00]);
        frame.extend_from_slice(&[0x45, 0, 0, 40, 0, 1, 0, 0, 64, 6, 0, 0]);
        frame.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        frame.extend_from_slice(&[0x1f, 0x90, 0, 80, 0, 0, 0, 1, 0, 0, 0, 0]);
        frame.extend_from_slice(&[0x50, 0x02, 0x20, 0, 0, 0, 0, 0]);
        assert!(p.matches(&frame));
        assert!(!dead.compile("udp", None).unwrap().matches(&frame));
        assert!(!p.matches(&[]), "an empty frame matches nothing");
        assert!(!p.matches(&frame[..8]), "a truncated frame matches nothing");
    }

    #[test]
    fn a_malformed_filter_reports_libpcaps_own_message() {
        if !available() {
            return;
        }
        let mut dead = Handle::open_dead(ETHERNET, 65535).unwrap();
        let e = dead.compile("tcp port", None).unwrap_err();
        assert_eq!(e.kind, Kind::BadFilter);
        assert!(!e.msg.is_empty());
    }

    #[test]
    fn a_filter_holding_a_nul_is_refused_rather_than_truncated() {
        if !available() {
            return;
        }
        let mut dead = Handle::open_dead(ETHERNET, 65535).unwrap();
        assert!(dead.compile("tcp\0 port 80", None).is_err());
        assert!(Handle::create("eth0\0extra").is_err());
    }

    #[test]
    fn listing_interfaces_needs_no_privileges_and_names_a_loopback() {
        if !available() {
            return;
        }
        let devs = find_all_devs().unwrap();
        assert!(!devs.is_empty(), "no interfaces at all");
        assert!(devs.iter().all(|d| !d.name.is_empty()));
        // Every host this can run on has a loopback, and it is the one
        // interface whose flag is not a guess.
        assert!(devs.iter().any(|d| d.loopback), "no loopback interface");
    }

    #[test]
    fn an_address_that_is_read_is_one_that_parses() {
        if !available() {
            return;
        }
        for d in find_all_devs().unwrap() {
            for a in &d.addresses {
                assert!(
                    a.parse::<std::net::IpAddr>().is_ok(),
                    "{}: {a:?} is not an address",
                    d.name
                );
            }
        }
    }

    #[test]
    fn opening_an_interface_that_does_not_exist_says_so() {
        if !available() {
            return;
        }
        let mut h = match Handle::create("wiry-no-such-if0") {
            Ok(h) => h,
            // Some libpcap builds refuse at create rather than at activate.
            Err(e) => {
                assert_ne!(e.kind, Kind::NotLoaded);
                return;
            }
        };
        let e = h.activate().unwrap_err();
        assert!(
            matches!(e.kind, Kind::NoSuchDevice | Kind::Permission | Kind::Other),
            "{e:?}"
        );
    }

    #[test]
    fn the_version_banner_is_libpcaps_own() {
        if !available() {
            return;
        }
        let v = lib_version().expect("pcap_lib_version is in every libpcap since 0.9");
        assert!(
            v.to_ascii_lowercase().contains("pcap"),
            "{v:?} does not look like a libpcap version"
        );
    }

    /// `caplen` and `len` follow the timeval, so a timeval of the wrong width
    /// makes `next_into` read a timestamp as a length. Getting it wrong is
    /// silent, and it is the one part of the layout that differs per platform:
    /// 8 octets where `long` is 32 bits, 16 where it is 64, including on the
    /// BSDs, where a 32-bit `tv_usec` is followed by four of padding.
    #[test]
    fn the_packet_header_has_the_layout_this_platform_uses() {
        use std::mem::{align_of, size_of};
        let word = size_of::<std::os::raw::c_long>();
        assert_eq!(align_of::<Timeval>(), align_of::<std::os::raw::c_long>());
        assert_eq!(size_of::<Timeval>(), word * 2);
        assert_eq!(size_of::<PcapPkthdr>(), word * 2 + 8);
    }
}
