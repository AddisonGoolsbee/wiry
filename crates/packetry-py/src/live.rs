//! The live drivers: an I/O shim over `SniffState`, which is already proved by
//! the offline driver. Nothing here decides when to keep, count or stop.
//!
//! Two things the offline driver never has to face. A wire read blocks, so the
//! GIL is released across every one of them and the stop conditions are polled
//! between reads rather than per matched packet: `next_into` returning
//! `Ok(None)` on libpcap's read timeout is that poll, not an error. And the
//! link type comes from the handle, since loopback is not Ethernet.

// With the feature off `Handle` is uninhabited, so every driver below is
// unreachable past its `open_live`. Keeping the module compiled anyway is what
// type-checks it in both configurations.
#![cfg_attr(
    not(feature = "live"),
    allow(unreachable_code, unused_variables, unused_mut)
)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use packetry_capture::{open_live, CaptureBuf, Flow, Handle, LiveConfig, PacketMeta};
use packetry_core::pcap;
use packetry_core::proto::ProtoId;
use pyo3::prelude::*;

use crate::capture::to_py_err;
use crate::sniff::SniffState;
use crate::{build_query, PyPktList};

/// How long the loop runs before handing control back to check for a signal.
/// Per slice rather than per packet, so an unbounded `sniff` answers Ctrl-C
/// without paying a GIL hop for every frame.
const SLICE: Duration = Duration::from_millis(250);

/// Where the GIL is. One capture loop then serves both the synchronous driver,
/// which holds it, and the background thread, which does not.
trait GilMode {
    fn blocking<R: Send, F: FnOnce() -> R + Send>(&self, f: F) -> R;
    fn attached<R, F: FnOnce(Python<'_>) -> R>(&self, f: F) -> R;
}

struct Held<'py>(Python<'py>);

impl GilMode for Held<'_> {
    fn blocking<R: Send, F: FnOnce() -> R + Send>(&self, f: F) -> R {
        self.0.allow_threads(f)
    }
    fn attached<R, F: FnOnce(Python<'_>) -> R>(&self, f: F) -> R {
        f(self.0)
    }
}

struct Detached;

impl GilMode for Detached {
    fn blocking<R: Send, F: FnOnce() -> R + Send>(&self, f: F) -> R {
        f()
    }
    fn attached<R, F: FnOnce(Python<'_>) -> R>(&self, f: F) -> R {
        Python::with_gil(f)
    }
}

fn stamp(m: &PacketMeta) -> f64 {
    m.ts_sec as f64 + m.ts_frac as f64 / 1e6
}

pub(crate) fn live_config(
    iface: Option<String>,
    filter: Option<String>,
    promisc: bool,
    snaplen: u32,
) -> LiveConfig {
    LiveConfig {
        iface: iface.unwrap_or_default(),
        snaplen,
        promisc,
        filter,
        ..LiveConfig::default()
    }
}

pub(crate) struct LiveRun {
    handle: Handle,
    st: SniffState,
    out: CaptureBuf,
    link: ProtoId,
    dlt: u32,
    scratch: Vec<u8>,
}

impl LiveRun {
    pub(crate) fn new(handle: Handle, st: SniffState, snaplen: u32) -> Self {
        let dlt = handle.linktype();
        Self {
            link: pcap::link_to_proto(dlt),
            out: CaptureBuf::new(dlt, snaplen),
            dlt,
            handle,
            st,
            scratch: Vec::new(),
        }
    }

    pub(crate) fn finish(self) -> PyPktList {
        let (buf, index, _) = self.out.into_parts();
        PyPktList::from_capture(buf, index, self.dlt, false)
    }

    /// One bounded slice of the capture loop. `Continue` means only that the
    /// slice ran out; `Stop` means the capture is over.
    fn slice<G: GilMode>(
        &mut self,
        gil: &G,
        until: Option<Instant>,
        stop: &AtomicBool,
    ) -> PyResult<Flow> {
        loop {
            if stop.load(Ordering::Relaxed) || self.st.tick() == Flow::Stop {
                return Ok(Flow::Stop);
            }
            if until.is_some_and(|u| Instant::now() >= u) {
                return Ok(Flow::Continue);
            }
            let Self {
                handle, scratch, ..
            } = self;
            let Some(meta) = gil
                .blocking(|| handle.next_into(scratch))
                .map_err(to_py_err)?
            else {
                continue;
            };
            let Self {
                st, scratch, link, ..
            } = self;
            let (store, flow) = if st.needs_python() {
                let t = stamp(&meta);
                gil.attached(|py| st.step_py(py, scratch, *link, t))?
            } else {
                gil.blocking(|| st.step(scratch, *link))
            };
            if store {
                self.out.push(&meta, &self.scratch);
            }
            if flow == Flow::Stop {
                return Ok(Flow::Stop);
            }
        }
    }

    fn run_sync(&mut self, py: Python<'_>, stop: &AtomicBool) -> PyResult<()> {
        loop {
            let until = Some(Instant::now() + SLICE);
            // A Python predicate forces the per-packet path; without one the
            // whole slice runs with the GIL released, as the offline driver does.
            let flow = if self.st.needs_python() {
                self.slice(&Held(py), until, stop)?
            } else {
                py.allow_threads(|| self.slice(&Detached, until, stop))?
            };
            py.check_signals()?;
            if flow == Flow::Stop {
                return Ok(());
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_state(
    py: Python<'_>,
    count: usize,
    store: bool,
    layer: Option<&str>,
    conds: Vec<(String, String, String, PyObject)>,
    timeout: Option<f64>,
    prn: Option<PyObject>,
    lfilter: Option<PyObject>,
    stop_filter: Option<PyObject>,
    wrap: Option<PyObject>,
) -> PyResult<SniffState> {
    let q = build_query(py, layer, conds)?;
    // No userspace BPF: the expression is installed on the handle, so libpcap
    // rejects a frame in the kernel before it is ever copied out.
    Ok(SniffState::new(
        count,
        store,
        timeout,
        None,
        q,
        prn,
        lfilter,
        stop_filter,
        wrap,
    ))
}

/// The synchronous live driver behind `sniff(iface=...)`.
#[allow(clippy::too_many_arguments)]
#[pyfunction]
#[pyo3(signature = (
    iface = None, count = 0, store = true, filter = None, layer = None,
    conds = Vec::new(), timeout = None, promisc = true, snaplen = 262_144,
    prn = None, lfilter = None, stop_filter = None, wrap = None
))]
pub(crate) fn sniff_live(
    py: Python<'_>,
    iface: Option<String>,
    count: usize,
    store: bool,
    filter: Option<String>,
    layer: Option<&str>,
    conds: Vec<(String, String, String, PyObject)>,
    timeout: Option<f64>,
    promisc: bool,
    snaplen: u32,
    prn: Option<PyObject>,
    lfilter: Option<PyObject>,
    stop_filter: Option<PyObject>,
    wrap: Option<PyObject>,
) -> PyResult<PyPktList> {
    let cfg = live_config(iface, filter, promisc, snaplen);
    let st = build_state(
        py,
        count,
        store,
        layer,
        conds,
        timeout,
        prn,
        lfilter,
        stop_filter,
        wrap,
    )?;
    let handle = open_live(&cfg).map_err(to_py_err)?;
    let mut run = LiveRun::new(handle, st, cfg.snaplen);
    let stop = AtomicBool::new(false);
    run.run_sync(py, &stop)?;
    Ok(run.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A zero read timeout can hang `next_packet` on macOS, and it would also
    /// stop the loop ever waking to poll its stop conditions.
    #[test]
    fn the_configured_read_timeout_is_never_zero() {
        let c = live_config(Some("x".into()), Some("tcp".into()), false, 1500);
        assert_ne!(c.read_timeout_ms, 0);
        assert!(c.immediate);
        assert_eq!(c.snaplen, 1500);
    }

    #[test]
    fn an_absent_interface_name_means_libpcaps_own_default() {
        assert!(live_config(None, None, true, 65_535).iface.is_empty());
    }
}
