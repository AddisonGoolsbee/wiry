use crate::error::CaptureError;
use crate::sink::PacketMeta;
use crate::{Interface, LiveConfig};
use wiry_pcap as raw;

fn map_err(e: raw::Error, ctx: &str) -> CaptureError {
    match e.kind {
        raw::Kind::NotLoaded => CaptureError::LibraryMissing(e.msg),
        raw::Kind::Permission => CaptureError::Permission(format!("{ctx}: {}", e.msg)),
        raw::Kind::NoSuchDevice => CaptureError::NoSuchDevice(ctx.to_string()),
        raw::Kind::BadFilter => CaptureError::BadFilter(e.msg),
        raw::Kind::Other => CaptureError::Pcap(e.msg),
    }
}

pub struct Handle {
    cap: raw::Handle,
    linktype: u32,
    name: String,
}

impl Handle {
    /// Copies the borrowed ring-buffer bytes into `scratch` while the borrow is
    /// live. libpcap reuses the slot on the next read, so nothing borrowed may
    /// outlive this call.
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
    /// The dead handle the program was compiled on. libpcap frees a program's
    /// instructions independently, but keeping the handle alive costs nothing
    /// and removes the question.
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

/// Why this host cannot capture, for the callers that must say so before
/// trying anything. `None` when it can.
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

/// The interface a capture with no `iface=` should use.
///
/// libpcap's own `pcap_lookupdev` is deprecated, removed from some builds and
/// documented as returning an arbitrary device; scapy stopped trusting it too.
/// This is scapy's `get_working_if` rule instead: the first interface that is
/// not a loopback and carries a routable IPv4 address, then the first with any
/// address at all, and a loopback only when there is nothing else.
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
    // An older libpcap without the call still captures, in whatever batches the
    // kernel chooses, so its absence is not a failure to open.
    let _ = cap.set_immediate_mode(cfg.immediate);
    cap.activate().map_err(|e| map_err(e, &dev))?;

    let linktype = cap.datalink() as u32;
    let mut h = Handle {
        cap,
        linktype,
        name: dev,
    };
    if let Some(f) = &cfg.filter {
        h.set_filter(f)?;
    }
    Ok(h)
}

pub fn compile_filter(
    linktype: u32,
    expr: &str,
    snaplen: u32,
) -> Result<CompiledFilter, CaptureError> {
    let mut dead = raw::Handle::open_dead(linktype as i32, snaplen.min(i32::MAX as u32) as i32)
        .map_err(|e| map_err(e, "dead"))?;
    let prog = dead.compile(expr, None).map_err(|e| map_err(e, "filter"))?;
    Ok(CompiledFilter { prog, _dead: dead })
}

pub fn send_l3(frames: &[Vec<u8>], count: usize, inter: f64) -> Result<usize, CaptureError> {
    crate::l3::send_l3(frames, count, inter)
}
