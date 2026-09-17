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
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use packetry_capture::{open_live, CaptureBuf, Flow, Handle, LiveConfig, PacketMeta, Record};
use packetry_core::pcap;
use packetry_core::proto::ProtoId;
use pyo3::exceptions::PyRuntimeError;
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

    /// The capture as the parts `PyPktList` is built from. Returned rather
    /// than built here, because the background thread holds no GIL.
    fn finish(self) -> (Vec<u8>, Vec<Record>, u32) {
        let (buf, index, _) = self.out.into_parts();
        (buf, index, self.dlt)
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

    /// The background thread's driver. No signal reaches a non-main thread,
    /// so there is nothing to slice the loop for.
    fn run_detached(&mut self, stop: &AtomicBool) -> PyResult<()> {
        self.slice(&Detached, None, stop).map(|_| ())
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
    let (buf, index, dlt) = run.finish();
    Ok(PyPktList::from_capture(buf, index, dlt, false))
}

/// Set once the capture thread has left its loop, so `join` can wait with a
/// timeout without the GIL.
#[derive(Default)]
struct Done {
    over: Mutex<bool>,
    cv: Condvar,
}

impl Done {
    fn signal(&self) {
        *self.over.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.cv.notify_all();
    }

    /// True when the thread has finished; false only when the wait timed out.
    fn wait(&self, timeout: Option<f64>) -> bool {
        let mut g = self.over.lock().unwrap_or_else(|e| e.into_inner());
        match timeout {
            None => {
                while !*g {
                    g = self.cv.wait(g).unwrap_or_else(|e| e.into_inner());
                }
                true
            }
            Some(t) => {
                let deadline = Instant::now() + Duration::from_secs_f64(t.max(0.0));
                while !*g {
                    let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                        break;
                    };
                    g = self
                        .cv
                        .wait_timeout(g, left)
                        .unwrap_or_else(|e| e.into_inner())
                        .0;
                }
                *g
            }
        }
    }
}

type Captured = (Vec<u8>, Vec<Record>, u32);

/// `sniff` on a thread of its own, which owns the handle. Everything Python
/// happens through the state machine, so the thread reacquires the GIL only
/// for a user callback.
#[pyclass(name = "LiveSniffer")]
pub(crate) struct LiveSniffer {
    /// Taken by `start`, so a finished sniffer cannot be restarted onto a
    /// second handle while callers still hold the first one's results.
    pending: Option<(LiveConfig, SniffState)>,
    stop: Arc<AtomicBool>,
    done: Arc<Done>,
    thread: Option<JoinHandle<PyResult<Captured>>>,
    results: Option<Py<PyPktList>>,
}

impl LiveSniffer {
    /// Collects the thread once it has finished. Joining releases the GIL: a
    /// `prn` on that thread is waiting to acquire it.
    fn reap(&mut self, py: Python<'_>) -> PyResult<()> {
        let Some(t) = self.thread.take() else {
            return Ok(());
        };
        match py.allow_threads(|| t.join()) {
            Ok(Ok((buf, index, dlt))) => {
                self.results = Some(Py::new(
                    py,
                    PyPktList::from_capture(buf, index, dlt, false),
                )?);
                Ok(())
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(PyRuntimeError::new_err("the capture thread panicked")),
        }
    }

    fn stored(&self, py: Python<'_>) -> Option<Py<PyPktList>> {
        self.results.as_ref().map(|r| r.clone_ref(py))
    }
}

#[pymethods]
impl LiveSniffer {
    #[allow(clippy::too_many_arguments)]
    #[new]
    #[pyo3(signature = (
        iface = None, count = 0, store = true, filter = None, layer = None,
        conds = Vec::new(), timeout = None, promisc = true, snaplen = 262_144,
        prn = None, lfilter = None, stop_filter = None, wrap = None
    ))]
    fn new(
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
    ) -> PyResult<Self> {
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
        Ok(Self {
            pending: Some((cfg, st)),
            stop: Arc::new(AtomicBool::new(false)),
            done: Arc::new(Done::default()),
            thread: None,
            results: None,
        })
    }

    /// Opens the handle here rather than on the thread, so a caller that gets
    /// back from `start()` knows the capture is already running.
    fn start(&mut self) -> PyResult<()> {
        if self.thread.is_some() {
            return Err(PyRuntimeError::new_err("this sniffer is already running"));
        }
        let Some((cfg, st)) = self.pending.take() else {
            return Err(PyRuntimeError::new_err("a sniffer cannot be restarted"));
        };
        let handle = match open_live(&cfg) {
            Ok(h) => h,
            Err(e) => {
                self.pending = Some((cfg, st));
                return Err(to_py_err(e));
            }
        };
        let mut run = LiveRun::new(handle, st, cfg.snaplen);
        let stop = Arc::clone(&self.stop);
        let done = Arc::clone(&self.done);
        self.thread = Some(std::thread::spawn(move || {
            let outcome = run.run_detached(&stop);
            done.signal();
            outcome.map(|()| run.finish())
        }));
        Ok(())
    }

    fn running(&self) -> bool {
        self.thread.as_ref().is_some_and(|t| !t.is_finished())
    }

    #[pyo3(signature = (timeout = None))]
    fn join(&mut self, py: Python<'_>, timeout: Option<f64>) -> PyResult<Option<Py<PyPktList>>> {
        if self.thread.is_some() {
            let done = Arc::clone(&self.done);
            if py.allow_threads(move || done.wait(timeout)) {
                self.reap(py)?;
            }
        }
        Ok(self.stored(py))
    }

    #[pyo3(signature = (join = true))]
    fn stop(&mut self, py: Python<'_>, join: bool) -> PyResult<Option<Py<PyPktList>>> {
        self.stop.store(true, Ordering::SeqCst);
        if join {
            return self.join(py, None);
        }
        Ok(self.stored(py))
    }

    /// Collects a thread that has already finished, so results appear without
    /// an explicit join.
    fn results(&mut self, py: Python<'_>) -> PyResult<Option<Py<PyPktList>>> {
        if self.thread.as_ref().is_some_and(|t| t.is_finished()) {
            self.reap(py)?;
        }
        Ok(self.stored(py))
    }
}

impl Drop for LiveSniffer {
    /// A capture thread outliving the interpreter would call into a finalised
    /// runtime and segfault, which is exactly the failure this workspace keeps
    /// `panic = "abort"` off to avoid. Joining releases the GIL first, because
    /// the thread may be blocked trying to acquire it for a `prn`.
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            Python::with_gil(|py| {
                py.allow_threads(|| {
                    let _ = t.join();
                })
            });
        }
    }
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
