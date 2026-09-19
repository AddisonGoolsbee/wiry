//! The live drivers: an I/O shim over `SniffState`, which is already proved by
//! the offline driver. Nothing here decides when to keep, count or stop.
//!
//! Two things the offline driver never has to face. A wire read can wait, so
//! the GIL is released across every one of them and the stop conditions are
//! polled between reads rather than per matched packet: `next_into` returning
//! `Ok(None)` is that poll, not an error. And the link type comes from the
//! handle, since loopback is not Ethernet.
//!
//! The reads are non-blocking, because libpcap's read timeout is not a bound:
//! on Linux `pcap_next_ex` waits for a frame however the timeout is set, so a
//! capture over a silent interface would never reach its own deadline, its stop
//! flag or the signal check. The waiting is done here instead, where those
//! three things are.

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

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use wiry_capture::{open_live, CaptureBuf, Flow, Handle, LiveConfig, PacketMeta, Record};
use wiry_core::answers::{answers_matching, reply_key, ReplyKey};
use wiry_core::packet::dissect_spans;
use wiry_core::pcap;
use wiry_core::proto::ProtoId;

use crate::capture::to_py_err;
use crate::sniff::{deadline_after, SniffState};
use crate::{build_query, PyPktList};

/// How long the loop runs before handing control back to check for a signal.
/// Per slice rather than per packet, so an unbounded `sniff` answers Ctrl-C
/// without paying a GIL hop for every frame.
const SLICE: Duration = Duration::from_millis(250);

/// The reads are non-blocking, so an idle interface is a loop that has to be
/// slowed down by hand. It doubles from `IDLE_MIN` to `IDLE_MAX` and resets on
/// every frame, which keeps a busy capture spinning and an idle one at a few
/// hundred wakeups a second. `IDLE_MAX` is what the deadline, the stop flag and
/// the signal check are granular to, so it stays far below `SLICE`.
const IDLE_MIN: Duration = Duration::from_micros(50);
const IDLE_MAX: Duration = Duration::from_millis(2);

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

/// The pause between two packets. Unlike a deadline there is no clamp that
/// means anything: `Duration::MAX` between sends is a hang where the panic it
/// replaced was at least visible, so an unrepresentable `inter` is refused.
fn gap_of(inter: f64) -> PyResult<Duration> {
    Duration::try_from_secs_f64(inter.max(0.0)).map_err(|_| {
        PyValueError::new_err(format!(
            "inter= must be a finite number of seconds, not {inter}"
        ))
    })
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
    /// The timeout runs from here, not from wherever the state was built: a
    /// `LiveSniffer` constructed and started seconds apart must still capture
    /// for the whole timeout it was asked for.
    pub(crate) fn new(handle: Handle, mut st: SniffState, snaplen: u32) -> Self {
        let dlt = handle.linktype();
        st.arm();
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
        let mut idle = IDLE_MIN;
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
            let blocking = handle.reads_block();
            let Some(meta) = gil
                .blocking(|| handle.next_into(scratch))
                .map_err(to_py_err)?
            else {
                // Nothing was waiting. A blocking handle already slept in
                // libpcap; a non-blocking one has to be slowed down here, or
                // the loop spins a core while it waits for the deadline it is
                // about to check.
                if !blocking {
                    gil.blocking(|| std::thread::sleep(idle));
                    idle = (idle * 2).min(IDLE_MAX);
                }
                continue;
            };
            idle = IDLE_MIN;
            let Self {
                st, scratch, link, ..
            } = self;
            let (store, flow) = if st.needs_python() {
                let t = stamp(&meta);
                gil.attached(|py| st.step_py(py, scratch, *link, t, meta.origlen))?
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

    fn is_over(&self) -> bool {
        *self.over.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Waits at most `slice`. True when the thread has finished. Bounded on
    /// purpose: the caller has the GIL released and owes Python a signal check.
    fn wait_for(&self, slice: Duration) -> bool {
        let g = self.over.lock().unwrap_or_else(|e| e.into_inner());
        if *g {
            return true;
        }
        *self
            .cv
            .wait_timeout(g, slice)
            .unwrap_or_else(|e| e.into_inner())
            .0
    }

    /// Waits for the thread in slices, checking for a signal between them, so
    /// Ctrl-C reaches a shutdown the way it already reaches the capture loop.
    /// `deadline` of `None` waits however long it takes.
    fn wait_out(&self, py: Python<'_>, deadline: Option<Instant>) -> PyResult<bool> {
        loop {
            let slice = match deadline {
                None => SLICE,
                Some(d) => match d.checked_duration_since(Instant::now()) {
                    None => return Ok(self.is_over()),
                    Some(left) => left.min(SLICE),
                },
            };
            if py.allow_threads(|| self.wait_for(slice)) {
                return Ok(true);
            }
            py.check_signals()?;
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

    /// Whether the caller is the capture thread itself, which is what a `prn`
    /// calling `stop()` on its own sniffer is. Waiting there would park the one
    /// thread that can ever signal the wait.
    fn is_capture_thread(&self) -> bool {
        self.thread
            .as_ref()
            .is_some_and(|t| t.thread().id() == std::thread::current().id())
    }

    fn refuse_self_join(&self) -> PyResult<()> {
        if self.is_capture_thread() {
            // `threading.Thread.join()`'s own words, which is what the offline
            // driver in the same class already raises.
            return Err(PyRuntimeError::new_err("cannot join current thread"));
        }
        Ok(())
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
        // A stop() before the first start() would otherwise end the run on its
        // first read, with an empty PacketList and nothing to explain it.
        self.stop.store(false, Ordering::SeqCst);
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

    /// True when called from the capture thread, i.e. from inside a `prn`.
    /// Exposed so the facade can refuse a self-join in its own words rather
    /// than by catching one.
    fn on_capture_thread(&self) -> bool {
        self.is_capture_thread()
    }

    #[pyo3(signature = (timeout = None))]
    fn join(&mut self, py: Python<'_>, timeout: Option<f64>) -> PyResult<Option<Py<PyPktList>>> {
        self.refuse_self_join()?;
        if self.thread.is_some() {
            // An unrepresentable timeout is no deadline at all, which is what
            // `timeout=None` already means here.
            let deadline = timeout.and_then(deadline_after);
            let done = Arc::clone(&self.done);
            if done.wait_out(py, deadline)? {
                self.reap(py)?;
            }
        }
        Ok(self.stored(py))
    }

    #[pyo3(signature = (join = true))]
    fn stop(&mut self, py: Python<'_>, join: bool) -> PyResult<Option<Py<PyPktList>>> {
        // The flag first, so a refused self-join still stops the capture: that
        // is what `AsyncSniffer.stop()` does on the offline driver.
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
        let Some(t) = self.thread.take() else { return };
        let done = Arc::clone(&self.done);
        Python::with_gil(|py| {
            // Sliced so a signal arriving while a wedged `prn` is waited out still
            // runs its Python handler. The wait itself must never be abandoned: a
            // capture thread outliving the interpreter is the segfault this exists
            // to prevent.
            let mut signal: Option<PyErr> = None;
            while !py.allow_threads(|| done.wait_for(SLICE)) {
                if let Err(e) = py.check_signals() {
                    if signal.is_none() {
                        signal = Some(e);
                    }
                }
            }
            py.allow_threads(|| {
                let _ = t.join();
            });
            // A drop cannot raise, so the interrupt is handed back to whatever
            // runs next — unless something is already on its way out.
            if let Some(e) = signal {
                match PyErr::take(py) {
                    Some(prior) => prior.restore(py),
                    None => e.restore(py),
                }
            }
        });
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
    let gap = gap_of(inter)?;
    let mut h = open_live(&cfg).map_err(to_py_err)?;
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

/// Bounds how much of an unbounded template is ever in memory at once. The
/// send is still one crossing.
const SEND_CHUNK: usize = 256;

/// Walks the product and writes it chunk by chunk. Expansion runs with the GIL
/// released, as the write does, so a send of a huge template never stalls
/// another Python thread for longer than one chunk.
fn stream_template(
    py: Python<'_>,
    template: &crate::template::Template,
    count: usize,
    repeat: bool,
    mut write: impl FnMut(&[Vec<u8>]) -> PyResult<usize>,
) -> PyResult<usize> {
    let total = template.total();
    let mut sent = 0usize;
    loop {
        for _ in 0..count {
            let mut at = 0u128;
            while at < total {
                let chunk = py.allow_threads(|| template.raw_frames(at, SEND_CHUNK))?;
                at += (chunk.len() as u128).max(1);
                sent += write(&chunk)?;
                py.check_signals()?;
            }
        }
        if !repeat {
            return Ok(sent);
        }
        py.check_signals()?;
    }
}

/// `sendp` of a template: the description crosses once and the product is
/// expanded here, so `sendp(Ether()/IP(dst=Net("10.0.0.0/8")))` neither
/// materialises 16 million frames nor crosses the boundary 16 million times.
#[pyfunction]
#[pyo3(signature = (template, iface = None, count = 1, inter = 0.0, repeat = false))]
pub(crate) fn send_template(
    py: Python<'_>,
    template: &crate::template::Template,
    iface: Option<String>,
    count: usize,
    inter: f64,
    repeat: bool,
) -> PyResult<usize> {
    let cfg = live_config(iface, None, false, 65_535);
    let gap = gap_of(inter)?;
    let mut h = open_live(&cfg).map_err(to_py_err)?;
    stream_template(py, template, count, repeat, |chunk| {
        py.allow_threads(|| one_run(&mut h, chunk, 1, gap))
    })
}

/// `send` of a template. The layer-3 path reads every destination before the
/// first octet of a batch goes out, so a template is checked chunk by chunk.
#[pyfunction]
#[pyo3(signature = (template, count = 1, inter = 0.0, repeat = false))]
pub(crate) fn send_template_l3(
    py: Python<'_>,
    template: &crate::template::Template,
    count: usize,
    inter: f64,
    repeat: bool,
) -> PyResult<usize> {
    stream_template(py, template, count, repeat, |chunk| {
        py.allow_threads(|| wiry_capture::send_l3(chunk, 1, inter))
            .map_err(to_py_err)
    })
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
    /// scapy's `conf.checkIPaddr`.
    check_addr: bool,
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
            if !answers_matching(k, &self.scratch, &spans, self.check_addr) {
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
        let mut idle = IDLE_MIN;
        loop {
            if self.settled() || deadline.is_some_and(|d| Instant::now() >= d) {
                return Ok(true);
            }
            if Instant::now() >= until {
                return Ok(false);
            }
            let Some(meta) = h.next_into(&mut self.scratch).map_err(to_py_err)? else {
                if !h.reads_block() {
                    std::thread::sleep(idle);
                    idle = (idle * 2).min(IDLE_MAX);
                }
                continue;
            };
            idle = IDLE_MIN;
            self.offer(&meta);
        }
    }
}

/// The replies, as (sent index, reply index) pairs into the capture, and the
/// sent indices nothing answered.
type Exchanged = (PyPktList, Vec<(usize, usize)>, Vec<usize>);

/// The same pairing with no capture behind it: see [`pair_replies`].
type Paired = (Vec<(usize, usize)>, Vec<usize>);

/// `sr`'s pairing with the wire replaced by a list of frames: the same
/// `Exchange`, the same `answers`, no socket and no privilege.
///
/// This is what makes `traceroute` testable without root. The tool is a TTL
/// sweep plus arithmetic over whatever `sr` paired, so driving the real pairing
/// from canned packets leaves only the socket itself untested offline. Needs no
/// `live` feature: nothing here opens anything.
#[pyfunction]
#[pyo3(signature = (sent, received, link = "IP", multi = false, check_addr = true))]
pub(crate) fn pair_replies(
    sent: Vec<Vec<u8>>,
    received: Vec<Vec<u8>>,
    link: &str,
    multi: bool,
    check_addr: bool,
) -> PyResult<Paired> {
    let link = crate::proto_by_name(link)?;
    let mut ex = Exchange {
        keys: sent
            .iter()
            .map(|f| reply_key(f, &dissect_spans(f, link)))
            .collect(),
        got: vec![false; sent.len()],
        pairs: Vec::new(),
        // Matched frames are stored and then thrown away: only the pairing is
        // asked for, so a discarded buffer's link type changes nothing.
        out: CaptureBuf::new(pcap::linktype::IPV4, 262_144),
        scratch: Vec::new(),
        link,
        multi,
        check_addr,
    };
    let mut pairs: Vec<(usize, usize)> = Vec::new();
    for (at, frame) in received.into_iter().enumerate() {
        let meta = PacketMeta {
            ts_sec: 0,
            ts_frac: 0,
            caplen: frame.len() as u32,
            origlen: frame.len() as u32,
        };
        let before = ex.pairs.len();
        ex.scratch = frame;
        ex.offer(&meta);
        pairs.extend(ex.pairs[before..].iter().map(|&(i, _)| (i, at)));
    }
    Ok((pairs, ex.pending()))
}

/// Send and collect the answers. The receive capture opens before anything is
/// sent, or a reply that comes back at wire speed is already gone.
#[allow(clippy::too_many_arguments)]
#[pyfunction]
#[pyo3(signature = (
    frames, iface = None, l2 = true, filter = None, timeout = None, retry = 0,
    multi = false, inter = 0.0, promisc = true, snaplen = 262_144,
    check_addr = true
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
    check_addr: bool,
) -> PyResult<Exchanged> {
    let cfg = live_config(iface, filter, promisc, snaplen);
    let gap = gap_of(inter)?;
    let mut h = open_live(&cfg).map_err(to_py_err)?;
    let dlt = h.linktype();
    let link = pcap::link_to_proto(dlt);
    let sent_link = if l2 { link } else { ProtoId::Ipv4 };

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
        check_addr,
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
        let deadline = timeout.and_then(deadline_after);
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
            check_addr: true,
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
        assert!(
            !ex.settled(),
            "multi= waits to the deadline however many answers have landed"
        );
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

    /// RFC 792: type, code, checksum, four unused octets, then the datagram
    /// that provoked the error.
    fn time_exceeded(from: [u8; 4], quoted: &[u8]) -> Vec<u8> {
        let mut v = vec![11, 0, 0, 0, 0, 0, 0, 0];
        v.extend_from_slice(quoted);
        ip4(0xffff, from, A, &v)
    }

    /// The invariant `traceroute` rests on. A sweep's probes differ only in
    /// their TTL and IP id, and the TTL is not part of the reply key, so the id
    /// is the whole of what tells one hop's error from another's.
    #[test]
    fn a_ttl_sweep_pairs_every_error_with_the_probe_that_provoked_it() {
        let probes: Vec<Vec<u8>> = (1..=4u16)
            .map(|ttl| ip4(ttl, A, B, &echo(8, 0x1234, 1)))
            .collect();
        let mut ex = exchange(&probes, false);
        for (i, ttl) in [3usize, 0, 2, 1].into_iter().zip([4u16, 1, 3, 2]) {
            let hop = [192, 0, 2, ttl as u8];
            offer(&mut ex, time_exceeded(hop, &probes[i]));
        }
        assert_eq!(ex.pairs, vec![(3, 0), (0, 1), (2, 2), (1, 3)]);
        assert!(ex.settled());
    }

    #[test]
    fn the_address_check_is_what_conf_checkipaddr_turns_off() {
        let req = ip4(7, A, B, &echo(8, 0x1234, 1));
        let from_elsewhere = ip4(9, [10, 0, 0, 9], A, &echo(0, 0x1234, 1));
        let mut strict = exchange(std::slice::from_ref(&req), false);
        offer(&mut strict, from_elsewhere.clone());
        assert!(strict.pairs.is_empty());

        let mut loose = exchange(&[req], false);
        loose.check_addr = false;
        offer(&mut loose, from_elsewhere);
        assert_eq!(loose.pairs, vec![(0, 0)]);
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
