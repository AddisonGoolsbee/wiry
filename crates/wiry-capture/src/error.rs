use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureError {
    /// Built without the `live` feature.
    Unsupported,
    /// libpcap could not be loaded. Carries the loader's message and this
    /// platform's install instruction.
    LibraryMissing(String),
    /// The operation is impossible on this platform.
    UnsupportedOn(&'static str),
    /// The input cannot be sent. Kept apart from the availability errors so a
    /// malformed packet is never reported as a missing capability.
    BadArgument(String),
    Permission(String),
    NoSuchDevice(String),
    BadFilter(String),
    Pcap(String),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CaptureError::Unsupported => write!(
                f,
                "this build of wiry was compiled with --no-default-features, \
                 which leaves out live capture. A default build has it, and \
                 loads libpcap at run time rather than at build time. Reading \
                 and writing capture files does not need it."
            ),
            CaptureError::LibraryMissing(m) => write!(f, "{m}"),
            CaptureError::UnsupportedOn(why) => write!(f, "{why}"),
            CaptureError::BadArgument(m) => write!(f, "{m}"),
            CaptureError::Permission(d) => write!(
                f,
                "permission denied opening {d}. Live capture needs elevated \
                 privileges: run as root, or on Linux grant the interpreter \
                 CAP_NET_RAW (setcap cap_net_raw,cap_net_admin+eip \"$(readlink \
                 -f $(which python3))\"), or on macOS install ChmodBPF, which \
                 ships with Wireshark, so /dev/bpf* is readable."
            ),
            CaptureError::NoSuchDevice(d) => write!(f, "no such interface: {d}"),
            CaptureError::BadFilter(m) => write!(f, "invalid capture filter: {m}"),
            CaptureError::Pcap(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for CaptureError {}
