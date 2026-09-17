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

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use wiry_capture::{open_live, CaptureBuf, Flow, Handle, LiveConfig, PacketMeta, Record};
use wiry_core::answers::{answers, reply_key, ReplyKey};
use wiry_core::packet::dissect_spans;
use wiry_core::pcap;
use wiry_core::proto::ProtoId;

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

    /// The parts `PyPktList` is built from, rather than the list itself: the
    /// background thread holds no GIL.
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

/// Signals on the way out however the thread leaves, so a join never waits on
/// a thread that has already gone.
struct Finally(Arc<Done>);

impl Drop for Finally {
    fn drop(&mut self) {
        self.0.signal();
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
            let _signal = Finally(done);
            run.run_detached(&stop).map(|()| run.finish())
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

/// The repetition lives here, so a `sendp` of a thousand frames crosses the
/// boundary once rather than a thousand times.
fn one_run(h: &mut Handle, frames: &[Vec<u8>], count: usize, gap: Duration) -> PyResult<usize> {
    let mut sent = 0usize;
    for _ in 0..count {
        for f in frames {
            h.send(f).map_err(to_py_err)?;
            sent += 1;
            if !gap.is_zero() {
                std::thread::sleep(gap);
            }
        }
    }
    Ok(sent)
}

/// Layer 2: the frames go out exactly as given, on one interface.
#[pyfunction]
#[pyo3(signature = (frames, iface = None, count = 1, inter = 0.0, repeat = false))]
pub(crate) fn send_frames(
    py: Python<'_>,
    frames: Vec<Vec<u8>>,
    iface: Option<String>,
    count: usize,
    inter: f64,
    repeat: bool,
) -> PyResult<usize> {
    let cfg = live_config(iface, None, false, 65_535);
    let mut h = open_live(&cfg).map_err(to_py_err)?;
    let gap = Duration::from_secs_f64(inter.max(0.0));
    let mut sent = 0usize;
    loop {
        sent += py.allow_threads(|| one_run(&mut h, &frames, count, gap))?;
        if !repeat {
            return Ok(sent);
        }
        // The only way out of an endless loop, as it is in scapy.
        py.check_signals()?;
    }
}

/// Layer 3: the kernel routes and frames each datagram.
#[pyfunction]
#[pyo3(signature = (frames, count = 1, inter = 0.0, repeat = false))]
pub(crate) fn send_datagrams(
    py: Python<'_>,
    frames: Vec<Vec<u8>>,
    count: usize,
    inter: f64,
    repeat: bool,
) -> PyResult<usize> {
    let mut sent = 0usize;
    loop {
        sent += py
            .allow_threads(|| wiry_capture::send_l3(&frames, count, inter))
            .map_err(to_py_err)?;
        if !repeat {
            return Ok(sent);
        }
        py.check_signals()?;
    }
}

/// The state of one `sr` call, so the collect phase can run in bounded slices
/// without unpicking it.
struct Exchange {
    keys: Vec<Option<ReplyKey>>,
    got: Vec<bool>,
    pairs: Vec<(usize, usize)>,
    out: CaptureBuf,
    scratch: Vec<u8>,
    link: ProtoId,
    multi: bool,
}

impl Exchange {
    fn settled(&self) -> bool {
        // With multi= the wait runs to the deadline however many answers land.
        !self.multi && self.got.iter().all(|g| *g)
    }

    fn pending(&self) -> Vec<usize> {
        (0..self.got.len()).filter(|&i| !self.got[i]).collect()
    }

    /// Records every sent packet this frame answers. A frame `answers` does
    /// not recognise is dropped: a wrong match corrupts the caller's results
    /// silently, where a missing one shows up in `unanswered`.
    fn offer(&mut self, meta: &PacketMeta) {
        let spans = dissect_spans(&self.scratch, self.link);
        let mut kept = None;
        for i in 0..self.keys.len() {
            let Some(k) = &self.keys[i] else { continue };
            if !self.multi && self.got[i] {
                continue;
            }
            if !answers(k, &self.scratch, &spans) {
                continue;
            }
            let at = *kept.get_or_insert_with(|| {
                self.out.push(meta, &self.scratch);
                self.out.len() - 1
            });
            self.pairs.push((i, at));
            self.got[i] = true;
            if !self.multi {
                break;
            }
        }
    }

    /// Reads until the exchange is over, the deadline passes, or the slice
    /// runs out. `true` means the phase is finished.
    fn collect(
        &mut self,
        h: &mut Handle,
        deadline: Option<Instant>,
        until: Instant,
    ) -> PyResult<bool> {
        loop {
            if self.settled() || deadline.is_some_and(|d| Instant::now() >= d) {
                return Ok(true);
            }
            if Instant::now() >= until {
                return Ok(false);
            }
            let Some(meta) = h.next_into(&mut self.scratch).map_err(to_py_err)? else {
                continue;
            };
            self.offer(&meta);
        }
    }
}

/// The replies, as (sent index, reply index) pairs into the capture, and the
/// sent indices nothing answered.
type Exchanged = (PyPktList, Vec<(usize, usize)>, Vec<usize>);

/// Send and collect the answers. The receive capture opens before anything is
/// sent, or a reply that comes back at wire speed is already gone.
#[allow(clippy::too_many_arguments)]
#[pyfunction]
#[pyo3(signature = (
    frames, iface = None, l2 = true, filter = None, timeout = None, retry = 0,
    multi = false, inter = 0.0, promisc = true, snaplen = 262_144
))]
pub(crate) fn sr_live(
    py: Python<'_>,
    frames: Vec<Vec<u8>>,
    iface: Option<String>,
    l2: bool,
    filter: Option<String>,
    timeout: Option<f64>,
    retry: usize,
    multi: bool,
    inter: f64,
    promisc: bool,
    snaplen: u32,
) -> PyResult<Exchanged> {
    let cfg = live_config(iface, filter, promisc, snaplen);
    let mut h = open_live(&cfg).map_err(to_py_err)?;
    let dlt = h.linktype();
    let link = pcap::link_to_proto(dlt);
    let sent_link = if l2 { link } else { ProtoId::Ipv4 };
    let gap = Duration::from_secs_f64(inter.max(0.0));

    let mut ex = Exchange {
        keys: frames
            .iter()
            .map(|f| reply_key(f, &dissect_spans(f, sent_link)))
            .collect(),
        got: vec![false; frames.len()],
        pairs: Vec::new(),
        out: CaptureBuf::new(dlt, snaplen),
        scratch: Vec::new(),
        link,
        multi,
    };

    for _ in 0..=retry {
        let pending = ex.pending();
        if pending.is_empty() {
            break;
        }
        let batch: Vec<Vec<u8>> = pending.iter().map(|&i| frames[i].clone()).collect();
        py.allow_threads(|| -> PyResult<()> {
            if l2 {
                one_run(&mut h, &batch, 1, gap)?;
            } else {
                wiry_capture::send_l3(&batch, 1, inter).map_err(to_py_err)?;
            }
            Ok(())
        })?;
        let deadline = timeout.map(|t| Instant::now() + Duration::from_secs_f64(t.max(0.0)));
        loop {
            let until = Instant::now() + SLICE;
            let over = py.allow_threads(|| ex.collect(&mut h, deadline, until))?;
            py.check_signals()?;
            if over {
                break;
            }
        }
    }

    let unanswered = ex.pending();
    let (buf, index, _) = ex.out.into_parts();
    Ok((
        PyPktList::from_capture(buf, index, dlt, false),
        ex.pairs,
        unanswered,
    ))
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

    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];

    /// RFC 791 §3.1, no options.
    fn ip4(id: u16, src: [u8; 4], dst: [u8; 4], rest: &[u8]) -> Vec<u8> {
        let mut v = vec![0x45, 0x00];
        v.extend_from_slice(&((20 + rest.len()) as u16).to_be_bytes());
        v.extend_from_slice(&id.to_be_bytes());
        v.extend_from_slice(&[0x00, 0x00, 0x40, 1, 0x00, 0x00]);
        v.extend_from_slice(&src);
        v.extend_from_slice(&dst);
        v.extend_from_slice(rest);
        v
    }

    /// RFC 792 echo.
    fn echo(ty: u8, id: u16, seq: u16) -> Vec<u8> {
        let mut v = vec![ty, 0, 0, 0];
        v.extend_from_slice(&id.to_be_bytes());
        v.extend_from_slice(&seq.to_be_bytes());
        v
    }

    fn meta(len: usize) -> PacketMeta {
        PacketMeta {
            ts_sec: 1,
            ts_frac: 0,
            caplen: len as u32,
            origlen: len as u32,
        }
    }

    fn exchange(sent: &[Vec<u8>], multi: bool) -> Exchange {
        Exchange {
            keys: sent
                .iter()
                .map(|f| reply_key(f, &dissect_spans(f, ProtoId::Ipv4)))
                .collect(),
            got: vec![false; sent.len()],
            pairs: Vec::new(),
            out: CaptureBuf::new(pcap::linktype::IPV4, 65_535),
            scratch: Vec::new(),
            link: ProtoId::Ipv4,
            multi,
        }
    }

    fn offer(ex: &mut Exchange, frame: Vec<u8>) {
        let m = meta(frame.len());
        ex.scratch = frame;
        ex.offer(&m);
    }

    #[test]
    fn a_reply_is_paired_with_the_probe_it_answers() {
        let req = ip4(7, A, B, &echo(8, 0x1234, 1));
        let mut ex = exchange(&[req], false);
        offer(&mut ex, ip4(9, B, A, &echo(0, 0x9999, 1)));
        assert!(ex.pairs.is_empty(), "a different echo is not an answer");
        assert_eq!(ex.out.len(), 0, "an unmatched frame is not stored");
        offer(&mut ex, ip4(9, B, A, &echo(0, 0x1234, 1)));
        assert_eq!(ex.pairs, vec![(0, 0)]);
        assert!(ex.settled());
        assert!(ex.pending().is_empty());
    }

    #[test]
    fn multi_keeps_collecting_after_the_first_answer() {
        let req = ip4(7, A, B, &echo(8, 0x1234, 1));
        let mut ex = exchange(&[req], true);
        offer(&mut ex, ip4(9, B, A, &echo(0, 0x1234, 1)));
        offer(&mut ex, ip4(10, B, A, &echo(0, 0x1234, 1)));
        assert_eq!(ex.pairs, vec![(0, 0), (0, 1)]);
        assert_eq!(ex.out.len(), 2);
        // The wait runs to the deadline however many answers have landed.
        assert!(!ex.settled());
    }

    #[test]
    fn an_unanswered_probe_is_reported_not_guessed_at() {
        let a = ip4(7, A, B, &echo(8, 0x1111, 1));
        let b = ip4(8, A, B, &echo(8, 0x2222, 1));
        let mut ex = exchange(&[a, b], false);
        offer(&mut ex, ip4(9, B, A, &echo(0, 0x2222, 1)));
        assert_eq!(ex.pairs, vec![(1, 0)]);
        assert_eq!(ex.pending(), vec![0]);
    }

    #[test]
    fn one_frame_answering_two_probes_is_stored_once() {
        let a = ip4(7, A, B, &echo(8, 0x1234, 1));
        let b = ip4(8, A, B, &echo(8, 0x1234, 1));
        let mut ex = exchange(&[a, b], true);
        offer(&mut ex, ip4(9, B, A, &echo(0, 0x1234, 1)));
        assert_eq!(ex.pairs, vec![(0, 0), (1, 0)]);
        assert_eq!(ex.out.len(), 1);
    }
}
