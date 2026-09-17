//! The sniff state machine.
//!
//! One `SniffState` holds every counter, deadline and predicate; a driver feeds
//! it frames. Three drivers exist in the design — offline, live and
//! send-and-receive — and they differ only in where the bytes come from, so all
//! of the control flow is proved by the offline one.
//!
//! Filters are ANDed cheapest first: BPF, then the Rust-side query, then the
//! Python `lfilter`. A frame rejected by BPF costs nothing and one rejected by
//! the query never becomes a Python object.

use std::time::{Duration, Instant};

use packetry_capture::{CompiledFilter, Flow};
use packetry_core::packet::{dissect_spans, Packet as CorePacket};
use packetry_core::proto::ProtoId;
use pyo3::prelude::*;

use crate::{PyPkt, Query};

pub(crate) struct SniffState {
    /// 0 means unbounded, as scapy's `count` does.
    count: usize,
    store: bool,
    deadline: Option<Instant>,
    bpf: Option<CompiledFilter>,
    query: Query,
    prn: Option<PyObject>,
    lfilter: Option<PyObject>,
    stop_filter: Option<PyObject>,
    /// Turns a bare `Pkt` into the facade's `Packet` once per surviving frame,
    /// so the callbacks see what scapy's would.
    wrap: Option<PyObject>,
    kept: usize,
}

impl SniffState {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        count: usize,
        store: bool,
        timeout: Option<f64>,
        bpf: Option<CompiledFilter>,
        query: Query,
        prn: Option<PyObject>,
        lfilter: Option<PyObject>,
        stop_filter: Option<PyObject>,
        wrap: Option<PyObject>,
    ) -> Self {
        Self {
            count,
            store,
            deadline: timeout.map(|t| Instant::now() + Duration::from_secs_f64(t.max(0.0))),
            bpf,
            query,
            prn,
            lfilter,
            stop_filter,
            wrap,
            kept: 0,
        }
    }

    /// True when a Python predicate must run per packet, which forces the
    /// driver onto the slow path that holds the GIL.
    pub(crate) fn needs_python(&self) -> bool {
        self.prn.is_some() || self.lfilter.is_some() || self.stop_filter.is_some()
    }

    fn expired(&self) -> bool {
        self.deadline.is_some_and(|d| Instant::now() >= d)
    }

    /// The deadline, polled between reads. A live driver blocks on the wire, so
    /// the timeout has to be honoured without a packet to hang it on.
    pub(crate) fn tick(&self) -> Flow {
        if self.expired() {
            Flow::Stop
        } else {
            Flow::Continue
        }
    }

    fn passes(&self, data: &[u8], link: ProtoId) -> bool {
        if let Some(f) = &self.bpf {
            if !f.matches(data) {
                return false;
            }
        }
        self.query.is_empty() || self.query.matches(data, &dissect_spans(data, link))
    }

    /// Returns (store this frame, keep sniffing).
    fn accept(&mut self) -> (bool, Flow) {
        self.kept += 1;
        let flow = if self.count > 0 && self.kept >= self.count {
            Flow::Stop
        } else {
            Flow::Continue
        };
        (self.store, flow)
    }

    /// The fast path: no Python predicate, so this runs with the GIL released.
    pub(crate) fn step(&mut self, data: &[u8], link: ProtoId) -> (bool, Flow) {
        if self.expired() {
            return (false, Flow::Stop);
        }
        if !self.passes(data, link) {
            return (false, Flow::Continue);
        }
        self.accept()
    }

    /// The slow path. Reacquiring per packet is inherent to scapy's callback
    /// contract; the object is built once and shared by all three predicates.
    pub(crate) fn step_py(
        &mut self,
        py: Python<'_>,
        data: &[u8],
        link: ProtoId,
        time: f64,
    ) -> PyResult<(bool, Flow)> {
        if self.expired() {
            return Ok((false, Flow::Stop));
        }
        if !self.passes(data, link) {
            return Ok((false, Flow::Continue));
        }
        let raw = Py::new(
            py,
            PyPkt {
                inner: CorePacket::dissect(data.to_vec(), link),
                time,
            },
        )?;
        let pkt: PyObject = match &self.wrap {
            Some(w) => w.call1(py, (raw,))?,
            None => raw.into_any(),
        };
        if let Some(f) = &self.lfilter {
            if !f.call1(py, (pkt.clone_ref(py),))?.is_truthy(py)? {
                return Ok((false, Flow::Continue));
            }
        }
        let (store, mut flow) = self.accept();
        if let Some(f) = &self.prn {
            f.call1(py, (pkt.clone_ref(py),))?;
        }
        if let Some(f) = &self.stop_filter {
            if f.call1(py, (pkt,))?.is_truthy(py)? {
                flow = Flow::Stop;
            }
        }
        Ok((store, flow))
    }
}
