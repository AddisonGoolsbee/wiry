//! Live capture and injection. Contains no PyO3 and no notion of a Python
//! callback, so the capture loop is testable without an interpreter.

#![forbid(unsafe_code)]

pub mod error;
pub mod sink;

pub use error::CaptureError;
pub use sink::{CaptureBuf, Flow, PacketMeta, PacketSink, Record};

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

pub fn send_l3(frames: &[Vec<u8>], count: usize, inter: f64) -> Result<usize, CaptureError> {
    backend::send_l3(frames, count, inter)
}

/// The destination of a buffer that really is an IPv4 datagram, and `None` for
/// one that is not.
///
/// The raw socket takes the buffer as given, so this is the only thing between
/// a caller's mistake and a frame on the wire addressed to whatever happened to
/// sit at octets 16..20 — an `Ether()/IP()/TCP()` meant for `sendp`, an IPv6
/// datagram, a line of text. Dissecting is no help: the dissector is *told* the
/// link type rather than asked to detect it, so it reports IPv4 for anything
/// long enough. The three fields RFC 791 §3.1 makes checkable are read here
/// directly: version 4, an internet header length of at least five 32-bit words
/// that the buffer holds, and a total length that neither undercuts the header
/// nor claims more than was handed in.
pub fn ipv4_dst(f: &[u8]) -> Option<[u8; 4]> {
    let first = *f.first()?;
    if first >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(first & 0x0f) * 4;
    if ihl < 20 || f.len() < ihl {
        return None;
    }
    let total = usize::from(u16::from_be_bytes([f[2], f[3]]));
    if total < ihl || total > f.len() {
        return None;
    }
    Some([f[16], f[17], f[18], f[19]])
}

/// The interface's hardware address, for filling an unset `Ether.src` at send
/// time. `pcap::Device` carries none, and sysfs is the answer only on Linux:
/// everywhere else this admits it does not know rather than pulling in another
/// dependency, so `None` is an ordinary outcome that every caller handles.
pub fn interface_mac(name: &str) -> Option<[u8; 6]> {
    if !cfg!(target_os = "linux") || name.is_empty() || name.contains(['/', '\\']) {
        return None;
    }
    let text = std::fs::read_to_string(format!("/sys/class/net/{name}/address")).ok()?;
    let mut parts = text.trim().split(':');
    let mut out = [0u8; 6];
    for b in out.iter_mut() {
        *b = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(out)
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
    fn a_hardware_address_is_never_read_from_outside_the_interface_table() {
        assert_eq!(interface_mac(""), None);
        assert_eq!(interface_mac("../../etc/passwd"), None);
        assert_eq!(interface_mac("wiry-no-such-if0"), None);
    }

    #[test]
    fn the_read_timeout_default_is_never_zero() {
        assert_ne!(LiveConfig::default().read_timeout_ms, 0);
    }

    /// RFC 791 §3.1, no options: 20 octets of header then `rest`.
    fn ip4(src: [u8; 4], dst: [u8; 4], rest: &[u8]) -> Vec<u8> {
        let mut v = vec![0x45, 0x00];
        v.extend_from_slice(&((20 + rest.len()) as u16).to_be_bytes());
        v.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x40, 6, 0x00, 0x00]);
        v.extend_from_slice(&src);
        v.extend_from_slice(&dst);
        v.extend_from_slice(rest);
        v
    }

    #[test]
    fn an_ipv4_datagram_yields_its_destination() {
        let d = ip4([10, 0, 0, 1], [10, 0, 0, 2], &[0u8; 20]);
        assert_eq!(ipv4_dst(&d), Some([10, 0, 0, 2]));
        // Options are ordinary: IHL 6 with 24 octets of header.
        let mut opts = d.clone();
        opts[0] = 0x46;
        opts.splice(20..20, [0x00, 0x00, 0x00, 0x00]);
        let total = (opts.len() as u16).to_be_bytes();
        opts[2] = total[0];
        opts[3] = total[1];
        assert_eq!(ipv4_dst(&opts), Some([10, 0, 0, 2]));
    }

    #[test]
    fn nothing_that_is_not_an_ipv4_datagram_yields_a_destination() {
        let ip = ip4([10, 0, 0, 1], [10, 0, 0, 2], &[0u8; 20]);
        // An Ethernet frame: the single likeliest send()/sendp() mix-up.
        let mut ether = vec![0u8; 12];
        ether.extend_from_slice(&[0x08, 0x00]);
        ether.extend_from_slice(&ip);
        assert_eq!(ipv4_dst(&ether), None);
        // An IPv6 datagram: the version nibble is the whole of the difference.
        let mut six = vec![0x60, 0, 0, 0, 0, 20, 6, 64];
        six.extend_from_slice(&[0u8; 32]);
        assert_eq!(ipv4_dst(&six), None);
        for junk in [
            b"this is not a packet at all!!".to_vec(),
            vec![0u8; 20],
            vec![0xffu8; 40],
            vec![0u8; 19],
            Vec::new(),
        ] {
            assert_eq!(ipv4_dst(&junk), None);
        }
    }

    #[test]
    fn a_header_length_or_total_length_the_buffer_does_not_back_is_refused() {
        let good = ip4([10, 0, 0, 1], [10, 0, 0, 2], &[0u8; 20]);
        // IHL below the five-word minimum, and one past the end of the buffer.
        for ihl in [0x40u8, 0x44, 0x4f] {
            let mut bad = good.clone();
            bad[0] = ihl;
            assert_eq!(ipv4_dst(&bad), None, "ihl nibble {ihl:#x}");
        }
        // A total length claiming more than was handed in.
        let mut long = good.clone();
        long[2] = 0xff;
        assert_eq!(ipv4_dst(&long), None);
        // ...and one that undercuts its own header.
        let mut short = good.clone();
        short[2] = 0;
        short[3] = 10;
        assert_eq!(ipv4_dst(&short), None);
        // Truncated below the header it declares.
        assert_eq!(ipv4_dst(&good[..19]), None);
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
