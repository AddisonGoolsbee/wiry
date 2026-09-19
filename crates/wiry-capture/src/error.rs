use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureError {
    /// Built without the `live` feature.
    Unsupported,
    /// Built with it, but libpcap is not on this host. Carries libpcap's own
    /// loader message and the install instruction for this platform.
    LibraryMissing(String),
    /// The operation cannot work on this platform at all.
    UnsupportedOn(&'static str),
    /// What the caller handed in is not something this can send. A packet
    /// shape is not an availability problem, so it must not be reported as one.
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
                 CAP_NET_RAW, or on macOS install ChmodBPF so /dev/bpf* is readable."
            ),
            CaptureError::NoSuchDevice(d) => write!(f, "no such interface: {d}"),
            CaptureError::BadFilter(m) => write!(f, "invalid capture filter: {m}"),
            CaptureError::Pcap(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for CaptureError {}
