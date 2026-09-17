//! Live capture and injection. Contains no PyO3 and no notion of a Python
//! callback, so the capture loop is testable without an interpreter.

#![forbid(unsafe_code)]

pub mod error;
pub mod sink;

pub use error::CaptureError;
pub use sink::{CaptureBuf, Flow, PacketMeta, PacketSink};

#[cfg(feature = "live")]
mod l3;
#[cfg(feature = "live")]
mod pcap_backend;
#[cfg(feature = "live")]
use pcap_backend as backend;

#[cfg(not(feature = "live"))]
mod unsupported;
#[cfg(not(feature = "live"))]
use unsupported as backend;

pub use backend::{CompiledFilter, Handle};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    pub description: Option<String>,
    pub addresses: Vec<String>,
    pub loopback: bool,
}

#[derive(Debug, Clone)]
pub struct LiveConfig {
    pub iface: String,
    pub snaplen: u32,
    pub promisc: bool,
    /// libpcap's read timeout. Never 0: the pcap README warns that can hang
    /// next_packet on macOS.
    pub read_timeout_ms: i32,
    pub immediate: bool,
    pub filter: Option<String>,
}

impl Default for LiveConfig {
    fn default() -> Self {
        Self {
            iface: String::new(),
            snaplen: 262_144,
            promisc: true,
            read_timeout_ms: 100,
            immediate: true,
            filter: None,
        }
    }
}

pub fn available() -> bool {
    backend::available()
}

pub fn list_interfaces() -> Result<Vec<Interface>, CaptureError> {
    backend::list_interfaces()
}

pub fn default_interface() -> Result<String, CaptureError> {
    backend::default_interface()
}

pub fn open_live(cfg: &LiveConfig) -> Result<Handle, CaptureError> {
    backend::open_live(cfg)
}

pub fn compile_filter(
    linktype: u32,
    expr: &str,
    snaplen: u32,
) -> Result<CompiledFilter, CaptureError> {
    backend::compile_filter(linktype, expr, snaplen)
}

pub fn send_l3(frames: &[Vec<u8>]) -> Result<usize, CaptureError> {
    backend::send_l3(frames)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_reports_unavailable_and_never_opens() {
        if !available() {
            assert!(matches!(
                open_live(&LiveConfig::default()),
                Err(CaptureError::Unsupported)
            ));
            assert!(list_interfaces().is_err());
        }
    }

    #[test]
    fn the_read_timeout_default_is_never_zero() {
        assert_ne!(LiveConfig::default().read_timeout_ms, 0);
    }
}

#[cfg(all(test, feature = "live"))]
mod live_tests {
    use super::*;

    const ETHERNET: u32 = 1;

    // An Ether/IPv4/TCP frame to port 80, laid out by hand from RFC 791 and
    // RFC 9293 so the filter tests assert against known bytes.
    fn eth_ip_tcp() -> Vec<u8> {
        let mut v = vec![0u8; 12];
        v.extend_from_slice(&[0x08, 0x00]);
        v.extend_from_slice(&[0x45, 0, 0, 40, 0, 1, 0, 0, 64, 6, 0, 0]);
        v.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        v.extend_from_slice(&[0x1f, 0x90, 0, 80, 0, 0, 0, 1, 0, 0, 0, 0]);
        v.extend_from_slice(&[0x50, 0x02, 0x20, 0, 0, 0, 0, 0]);
        v
    }

    #[test]
    fn available_is_true_with_the_feature_on() {
        assert!(available());
    }

    #[test]
    fn a_filter_compiles_without_a_device_or_privileges() {
        assert!(compile_filter(ETHERNET, "tcp port 80", 65535).is_ok());
        assert!(compile_filter(ETHERNET, "arp", 65535).is_ok());
    }

    #[test]
    fn a_bad_filter_reports_libpcaps_own_message() {
        match compile_filter(ETHERNET, "tcp port", 65535) {
            Err(CaptureError::BadFilter(m)) => assert!(!m.is_empty()),
            Err(e) => panic!("expected BadFilter, got {e:?}"),
            Ok(_) => panic!("a malformed filter must not compile"),
        }
    }

    #[test]
    fn a_compiled_filter_matches_the_right_frames() {
        let f = compile_filter(ETHERNET, "tcp port 80", 65535).unwrap();
        assert!(f.matches(&eth_ip_tcp()));
        let udp = compile_filter(ETHERNET, "udp", 65535).unwrap();
        assert!(!udp.matches(&eth_ip_tcp()));
    }

    #[test]
    fn listing_interfaces_does_not_raise() {
        // May legitimately be empty in a container, so assert only that it works.
        let _ = list_interfaces().map(|v| v.len());
    }
}
