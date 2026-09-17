use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureError {
    /// Built without the `live` feature.
    Unsupported,
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
                "this build of wiry has no live capture support. Rebuild with \
                 the `live` feature: maturin develop --release --features \
                 pyo3/extension-module,live. Reading and writing capture files \
                 does not need it."
            ),
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
