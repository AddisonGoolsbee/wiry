use crate::error::CaptureError;
use crate::sink::PacketMeta;
use crate::{Interface, LiveConfig};
use pcap::{Active, Capture, Device, Linktype};

fn map_err(e: pcap::Error, ctx: &str) -> CaptureError {
    let msg = e.to_string();
    let lower = msg.to_ascii_lowercase();
    if lower.contains("permission") || lower.contains("not permitted") {
        CaptureError::Permission(ctx.to_string())
    } else if lower.contains("no such device") {
        CaptureError::NoSuchDevice(ctx.to_string())
    } else {
        CaptureError::Pcap(msg)
    }
}

pub struct Handle {
    cap: Capture<Active>,
    linktype: u32,
}

impl Handle {
    /// Copies the borrowed ring-buffer bytes into `scratch` while the borrow is
    /// live. libpcap reuses the slot on the next read, so nothing borrowed may
    /// outlive this call.
    pub fn next_into(&mut self, scratch: &mut Vec<u8>) -> Result<Option<PacketMeta>, CaptureError> {
        match self.cap.next_packet() {
            Ok(p) => {
                scratch.clear();
                scratch.extend_from_slice(p.data);
                Ok(Some(PacketMeta {
                    ts_sec: p.header.ts.tv_sec as u32,
                    ts_frac: p.header.ts.tv_usec as u32,
                    caplen: p.header.caplen,
                    origlen: p.header.len,
                }))
            }
            Err(pcap::Error::TimeoutExpired) => Ok(None),
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
        self.cap
            .filter(expr, true)
            .map_err(|e| CaptureError::BadFilter(e.to_string()))
    }
}

pub struct CompiledFilter(pcap::BpfProgram);

impl CompiledFilter {
    pub fn matches(&self, frame: &[u8]) -> bool {
        self.0.filter(frame)
    }
}

pub fn available() -> bool {
    true
}

pub fn list_interfaces() -> Result<Vec<Interface>, CaptureError> {
    let devs = Device::list().map_err(|e| map_err(e, "list"))?;
    Ok(devs
        .into_iter()
        .map(|d| Interface {
            loopback: d.flags.is_loopback(),
            addresses: d.addresses.iter().map(|a| a.addr.to_string()).collect(),
            description: d.desc,
            name: d.name,
        })
        .collect())
}

pub fn default_interface() -> Result<String, CaptureError> {
    match Device::lookup() {
        Ok(Some(d)) => Ok(d.name),
        Ok(None) => Err(CaptureError::NoSuchDevice("default".into())),
        Err(e) => Err(map_err(e, "lookup")),
    }
}

pub fn open_live(cfg: &LiveConfig) -> Result<Handle, CaptureError> {
    let dev = if cfg.iface.is_empty() {
        default_interface()?
    } else {
        cfg.iface.clone()
    };
    let mut cap = Capture::from_device(dev.as_str())
        .map_err(|e| map_err(e, &dev))?
        .snaplen(cfg.snaplen as i32)
        .promisc(cfg.promisc)
        .timeout(cfg.read_timeout_ms)
        .immediate_mode(cfg.immediate)
        .open()
        .map_err(|e| map_err(e, &dev))?;
    if let Some(f) = &cfg.filter {
        cap.filter(f, true)
            .map_err(|e| CaptureError::BadFilter(e.to_string()))?;
    }
    let linktype = cap.get_datalink().0 as u32;
    Ok(Handle { cap, linktype })
}

pub fn compile_filter(
    linktype: u32,
    expr: &str,
    snaplen: u32,
) -> Result<CompiledFilter, CaptureError> {
    let dead = Capture::dead_with_precision(Linktype(linktype as i32), pcap::Precision::Micro)
        .map_err(|e| map_err(e, "dead"))?;
    let _ = snaplen;
    dead.compile(expr, true)
        .map(CompiledFilter)
        .map_err(|e| CaptureError::BadFilter(e.to_string()))
}

pub fn send_l3(frames: &[Vec<u8>], count: usize, inter: f64) -> Result<usize, CaptureError> {
    crate::l3::send_l3(frames, count, inter)
}
