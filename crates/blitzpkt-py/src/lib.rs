//! Python bindings.
//!
//! Boundary rule: cross at file or list granularity, never per field and never
//! per packet in bulk paths. A capture stays in Rust as one buffer plus an index;
//! Python objects are minted only for the packets somebody actually touches.
//! Getting this wrong is the failure mode that has sunk other Rust-core rewrites.

#![forbid(unsafe_code)]
// The #[pymethods]/#[pyfunction] trampolines pyo3 0.22 generates convert PyErr
// to PyErr, which clippy flags as useless_conversion at each function's span.
#![allow(clippy::useless_conversion)]

use blitzpkt_core::field::{self, FieldDesc, FieldValue};
use blitzpkt_core::packet::{dissect_spans, LayerSpan, Packet as CorePacket, Spans};
use blitzpkt_core::pcap;
use blitzpkt_core::proto::{self, ProtoId};
use blitzpkt_core::show;
use pyo3::exceptions::{PyIndexError, PyKeyError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use std::sync::Arc;

fn proto_by_name(name: &str) -> PyResult<ProtoId> {
    proto::by_name(name).ok_or_else(|| PyValueError::new_err(format!("unknown layer {name:?}")))
}

fn value_to_py(py: Python<'_>, v: &FieldValue) -> PyObject {
    match v {
        FieldValue::Uint(n) => n.into_py(py),
        FieldValue::Ipv4(_) | FieldValue::Ipv6(_) | FieldValue::Mac(_) => {
            show::render_value(v).into_py(py)
        }
        // Flags render as their letter string, matching how packet tools show them.
        FieldValue::Flags { .. } => show::render_value(v).into_py(py),
        FieldValue::Bytes(b) => PyBytes::new_bound(py, b).into(),
    }
}

// ---- columnar extraction ---------------------------------------------------
//
// One pass over the capture pulling every requested field, with the predicate
// evaluated here rather than in Python. A Python callback per packet, or one
// pass per field, would put the boundary back in the hot loop.

/// Pseudo-layer carrying per-record metadata that is not in the packet bytes.
const FRAME: &str = "Frame";

#[derive(Clone, Copy)]
enum ColSpec {
    Field(ProtoId, &'static FieldDesc),
    Time,
    Len,
    Num,
}

#[derive(Clone, Copy)]
enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl CmpOp {
    fn parse(s: &str) -> PyResult<Self> {
        Ok(match s {
            "==" | "=" | "eq" => CmpOp::Eq,
            "!=" | "ne" => CmpOp::Ne,
            "<" | "lt" => CmpOp::Lt,
            "<=" | "le" => CmpOp::Le,
            ">" | "gt" => CmpOp::Gt,
            ">=" | "ge" => CmpOp::Ge,
            _ => return Err(PyValueError::new_err(format!("unknown operator {s:?}"))),
        })
    }

    fn test<T: PartialOrd>(self, a: T, b: T) -> bool {
        match self {
            CmpOp::Eq => a == b,
            CmpOp::Ne => a != b,
            CmpOp::Lt => a < b,
            CmpOp::Le => a <= b,
            CmpOp::Gt => a > b,
            CmpOp::Ge => a >= b,
        }
    }
}

enum CondVal {
    Uint(u64),
    Bytes(Vec<u8>),
}

struct Cond {
    proto: ProtoId,
    field: &'static FieldDesc,
    op: CmpOp,
    val: CondVal,
}

/// Rows selected by a query: a layer that must be present, plus field tests.
/// A test against a layer the packet does not have is false, never true.
struct Query {
    layer: Option<ProtoId>,
    conds: Vec<Cond>,
}

impl Query {
    fn is_empty(&self) -> bool {
        self.layer.is_none() && self.conds.is_empty()
    }

    fn matches(&self, buf: &[u8], spans: &[LayerSpan]) -> bool {
        if let Some(l) = self.layer {
            if !spans.iter().any(|s| s.proto == l) {
                return false;
            }
        }
        self.conds.iter().all(|c| {
            let Some(s) = spans.iter().find(|s| s.proto == c.proto) else {
                return false;
            };
            let v = decode_span(buf, s, c.field);
            match &c.val {
                CondVal::Uint(n) => v.as_uint().is_some_and(|x| c.op.test(x, *n)),
                CondVal::Bytes(b) => raw_bytes(&v).is_some_and(|x| c.op.test(x, b.as_slice())),
            }
        })
    }
}

/// Decode one field straight out of the capture buffer, without copying the
/// packet. Clamped exactly as `Packet::get_desc` clamps, so the bulk path and
/// the per-packet path cannot disagree.
#[inline]
fn decode_span(buf: &[u8], s: &LayerSpan, f: &FieldDesc) -> FieldValue {
    let a = s.off as usize;
    let b = (a + s.hlen as usize).min(buf.len());
    field::decode(&buf[a..b], f)
}

fn raw_bytes(v: &FieldValue) -> Option<&[u8]> {
    match v {
        FieldValue::Ipv4(b) => Some(b),
        FieldValue::Ipv6(b) => Some(b),
        FieldValue::Mac(b) => Some(b),
        FieldValue::Bytes(b) => Some(b),
        _ => None,
    }
}

fn resolve_spec(layer: &str, name: &str) -> PyResult<ColSpec> {
    if layer == FRAME {
        return match name {
            "time" => Ok(ColSpec::Time),
            "len" => Ok(ColSpec::Len),
            "num" => Ok(ColSpec::Num),
            _ => Err(PyKeyError::new_err(format!(
                "no field {name:?} on {FRAME}; expected time, len or num"
            ))),
        };
    }
    let id = proto_by_name(layer)?;
    let f = proto::field_of(id, name)
        .ok_or_else(|| PyKeyError::new_err(format!("no field {name:?} on {layer}")))?;
    Ok(ColSpec::Field(id, f))
}

fn build_query(
    py: Python<'_>,
    layer: Option<&str>,
    conds: Vec<(String, String, String, PyObject)>,
) -> PyResult<Query> {
    let layer = match layer {
        Some(l) => Some(proto_by_name(l)?),
        None => None,
    };
    let mut out = Vec::with_capacity(conds.len());
    for (lname, fname, op, val) in conds {
        let proto = proto_by_name(&lname)?;
        let f = proto::field_of(proto, &fname)
            .ok_or_else(|| PyKeyError::new_err(format!("no field {fname:?} on {lname}")))?;
        let v = val.bind(py);
        let cv = if let Ok(n) = v.extract::<u64>() {
            CondVal::Uint(n)
        } else if let Ok(b) = v.extract::<Vec<u8>>() {
            CondVal::Bytes(b)
        } else if let Ok(s) = v.extract::<String>() {
            match blitzpkt_core::parse::value_for(f, &s) {
                Some(blitzpkt_core::parse::ValueBits::Uint(n)) => CondVal::Uint(n),
                Some(blitzpkt_core::parse::ValueBits::Bytes(b)) => CondVal::Bytes(b),
                None => {
                    return Err(PyValueError::new_err(format!(
                        "cannot parse {s:?} for field {fname:?}"
                    )))
                }
            }
        } else {
            return Err(PyValueError::new_err(format!(
                "unsupported comparison value for {lname}.{fname}"
            )));
        };
        out.push(Cond {
            proto,
            field: f,
            op: CmpOp::parse(&op)?,
            val: cv,
        });
    }
    Ok(Query { layer, conds: out })
}

/// One extracted value. `Time` is the only column that is not a field value.
enum Cell {
    Null,
    Val(FieldValue),
    Time(f64),
}

/// A dissected packet.
#[pyclass(name = "Pkt")]
pub struct PyPkt {
    inner: CorePacket,
    #[pyo3(get)]
    time: f64,
}

#[pymethods]
impl PyPkt {
    /// Layer names, outermost first.
    fn layer_names(&self) -> Vec<&'static str> {
        self.inner.layers().iter().map(|s| s.proto.name()).collect()
    }

    fn haslayer(&self, name: &str) -> PyResult<bool> {
        Ok(self.inner.has_layer(proto_by_name(name)?))
    }

    fn layer_index(&self, name: &str) -> PyResult<Option<usize>> {
        Ok(self.inner.find_layer(proto_by_name(name)?))
    }

    /// Read one field. Decodes only that field.
    fn get_field(&self, py: Python<'_>, layer: usize, name: &str) -> PyResult<PyObject> {
        match self.inner.get(layer, name) {
            Some(v) => Ok(value_to_py(py, &v)),
            None => Err(PyKeyError::new_err(format!(
                "no field {name:?} in layer {layer}"
            ))),
        }
    }

    /// Read a field by layer name rather than index.
    fn get_field_by_layer(
        &self,
        py: Python<'_>,
        layer_name: &str,
        field: &str,
    ) -> PyResult<PyObject> {
        let id = proto_by_name(layer_name)?;
        let idx = self
            .inner
            .find_layer(id)
            .ok_or_else(|| PyKeyError::new_err(format!("no {layer_name} layer")))?;
        self.get_field(py, idx, field)
    }

    fn set_field(&mut self, layer: usize, name: &str, val: u64) -> PyResult<()> {
        if !self.inner.set_uint(layer, name, val) {
            return Err(PyKeyError::new_err(format!(
                "no field {name:?} in layer {layer}"
            )));
        }
        Ok(())
    }

    /// Set a field from its textual form (addresses, flag letters).
    fn set_field_str(&mut self, layer: usize, name: &str, val: &str) -> PyResult<()> {
        let span = self
            .inner
            .layers()
            .get(layer)
            .copied()
            .ok_or_else(|| PyIndexError::new_err("layer out of range"))?;
        let f = proto::field_of(span.proto, name)
            .ok_or_else(|| PyKeyError::new_err(format!("no field {name:?} in layer {layer}")))?;
        match blitzpkt_core::parse::value_for(f, val) {
            Some(blitzpkt_core::parse::ValueBits::Uint(v)) => {
                self.inner.set_uint(layer, name, v);
                Ok(())
            }
            Some(blitzpkt_core::parse::ValueBits::Bytes(b)) => {
                self.inner.set_bytes(layer, name, &b);
                Ok(())
            }
            None => Err(PyValueError::new_err(format!(
                "cannot parse {val:?} for field {name:?}"
            ))),
        }
    }

    fn set_field_bytes(&mut self, layer: usize, name: &str, val: &[u8]) -> PyResult<()> {
        if !self.inner.set_bytes(layer, name, val) {
            return Err(PyKeyError::new_err(format!(
                "no field {name:?} in layer {layer}"
            )));
        }
        Ok(())
    }

    fn set_payload(&mut self, layer: usize, data: &[u8]) {
        self.inner.set_payload(layer, data);
    }

    /// Parsed options for a layer, as (name, value) pairs.
    /// None means the protocol has no option region at all, which is different
    /// from an empty list meaning it has one and it is empty.
    fn options(&self, py: Python<'_>, layer: usize) -> Option<Py<PyList>> {
        use blitzpkt_core::options::ItemValue;
        let items = self.inner.options(layer)?;
        let out = PyList::empty_bound(py);
        for it in &items {
            let v: PyObject = match &it.value {
                ItemValue::Flag => py.None(),
                ItemValue::Uint(n) => n.into_py(py),
                ItemValue::Pair(a, b) => (*a, *b).into_py(py),
                ItemValue::Bytes(b) => PyBytes::new_bound(py, b).into(),
                ItemValue::Text(s) => s.into_py(py),
                ItemValue::Ipv4List(l) => l
                    .iter()
                    .map(|a| format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]))
                    .collect::<Vec<_>>()
                    .into_py(py),
            };
            out.append((it.name.as_ref(), v)).ok()?;
        }
        Some(out.unbind())
    }

    /// Parsed DNS question and resource-record sections.
    /// Returns None when the layer is not DNS.
    fn dns_records(&self, py: Python<'_>, layer: usize) -> PyResult<Option<PyObject>> {
        use blitzpkt_core::layers::dns::{self, RData};
        let Some(span) = self.inner.layers().get(layer) else {
            return Ok(None);
        };
        if span.proto != ProtoId::Dns {
            return Ok(None);
        }
        // Compression pointers are offsets from the start of the DNS message,
        // so the parser needs the whole message, not just the header.
        let recs = dns::parse_records(self.inner.layer_bytes(layer));

        let rdata_to_py = |rd: &RData| -> PyObject {
            match rd {
                RData::A(b) => format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]).into_py(py),
                RData::Aaaa(b) => show::render_ipv6(b).into_py(py),
                RData::Name(s) => s.into_py(py),
                RData::Txt(v) => v.clone().into_py(py),
                RData::Mx { pref, exchange } => (*pref, exchange.clone()).into_py(py),
                RData::Soa {
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                } => {
                    let d = PyDict::new_bound(py);
                    let _ = d.set_item("mname", mname);
                    let _ = d.set_item("rname", rname);
                    let _ = d.set_item("serial", serial);
                    let _ = d.set_item("refresh", refresh);
                    let _ = d.set_item("retry", retry);
                    let _ = d.set_item("expire", expire);
                    let _ = d.set_item("minimum", minimum);
                    d.into()
                }
                RData::Other(b) => PyBytes::new_bound(py, b).into(),
            }
        };

        let rrs = |v: &[dns::ResourceRecord]| -> PyResult<Py<PyList>> {
            let out = PyList::empty_bound(py);
            for r in v {
                let d = PyDict::new_bound(py);
                d.set_item("rrname", &r.rrname)?;
                d.set_item("type", dns::rtype_name(r.rtype))?;
                d.set_item("rtype", r.rtype)?;
                d.set_item("rclass", r.rclass)?;
                d.set_item("ttl", r.ttl)?;
                d.set_item("rdata", rdata_to_py(&r.rdata))?;
                out.append(d)?;
            }
            Ok(out.unbind())
        };

        let qd = PyList::empty_bound(py);
        for q in &recs.qd {
            let d = PyDict::new_bound(py);
            d.set_item("qname", &q.qname)?;
            d.set_item("qtype", q.qtype)?;
            d.set_item("type", dns::rtype_name(q.qtype))?;
            d.set_item("qclass", q.qclass)?;
            qd.append(d)?;
        }

        let out = PyDict::new_bound(py);
        out.set_item("qd", qd)?;
        out.set_item("an", rrs(&recs.an)?)?;
        out.set_item("ns", rrs(&recs.ns)?)?;
        out.set_item("ar", rrs(&recs.ar)?)?;
        Ok(Some(out.into()))
    }

    /// Payload bytes beneath a layer.
    fn payload<'py>(&self, py: Python<'py>, layer: usize) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, self.inner.payload(layer))
    }

    /// Serialise, recomputing lengths and checksums.
    // &mut self is required: CorePacket::to_bytes caches computed checksums in place.
    #[allow(clippy::wrong_self_convention)]
    fn to_bytes<'py>(&mut self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, self.inner.to_bytes())
    }

    fn show(&self) -> String {
        show::show(&self.inner)
    }

    /// An independent copy. Used when stacking onto a dissected packet, where
    /// rebuilding from a field spec would lose variable-length header content.
    fn copy(&self) -> PyPkt {
        PyPkt {
            inner: self.inner.clone(),
            time: self.time,
        }
    }

    fn summary(&self) -> String {
        show::summary(&self.inner)
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }

    /// Field names available on a layer, in header order.
    fn field_names(&self, layer: usize) -> PyResult<Vec<&'static str>> {
        let s = self
            .inner
            .layers()
            .get(layer)
            .ok_or_else(|| PyIndexError::new_err("layer out of range"))?;
        Ok(proto::desc(s.proto).fields.iter().map(|f| f.name).collect())
    }
}

/// A capture held entirely in Rust: one buffer plus a record index.
/// Indexing mints a Python object for that packet only.
#[pyclass(name = "PktList")]
pub struct PyPktList {
    buf: Arc<Vec<u8>>,
    /// (offset, caplen, ts_sec, ts_frac) per record.
    index: Vec<(u32, u32, u32, u32)>,
    link: ProtoId,
    nanos: bool,
    /// Positions in the original capture, set when this list is a filtered view.
    nums: Option<Vec<u32>>,
}

impl PyPktList {
    fn num_at(&self, i: usize) -> u32 {
        match &self.nums {
            Some(n) => n[i],
            None => i as u32,
        }
    }

    /// Positions in this list whose packets satisfy the query.
    fn matching(&self, py: Python<'_>, q: &Query) -> Vec<u32> {
        let buf = &self.buf;
        let idx = &self.index;
        let link = self.link;
        py.allow_threads(|| {
            idx.iter()
                .enumerate()
                .filter(|(_, (off, len, _, _))| {
                    let a = *off as usize;
                    let bytes = &buf[a..a + *len as usize];
                    q.matches(bytes, &dissect_spans(bytes, link))
                })
                .map(|(i, _)| i as u32)
                .collect()
        })
    }

    fn dissect_at(&self, i: usize) -> PyPkt {
        let (off, len, sec, frac) = self.index[i];
        let a = off as usize;
        let b = a + len as usize;
        let bytes = self.buf[a..b].to_vec();
        let div = if self.nanos { 1e9 } else { 1e6 };
        PyPkt {
            inner: CorePacket::dissect(bytes, self.link),
            time: sec as f64 + frac as f64 / div,
        }
    }
}

#[pymethods]
impl PyPktList {
    fn __len__(&self) -> usize {
        self.index.len()
    }

    fn __getitem__(&self, i: isize) -> PyResult<PyPkt> {
        let n = self.index.len() as isize;
        let i = if i < 0 { i + n } else { i };
        if i < 0 || i >= n {
            return Err(PyIndexError::new_err("packet index out of range"));
        }
        Ok(self.dissect_at(i as usize))
    }

    /// Count packets containing a layer, without crossing into Python per packet.
    /// This is the shape of API that keeps the speedup: one call, whole capture.
    fn count_layer(&self, py: Python<'_>, name: &str) -> PyResult<usize> {
        let id = proto_by_name(name)?;
        let buf = Arc::clone(&self.buf);
        let idx = self.index.clone();
        let link = self.link;
        // Release the GIL: this is pure Rust work over the whole capture.
        Ok(py.allow_threads(move || {
            idx.iter()
                .filter(|(off, len, _, _)| {
                    let a = *off as usize;
                    let b = a + *len as usize;
                    blitzpkt_core::packet::dissect_spans(&buf[a..b], link)
                        .iter()
                        .any(|s| s.proto == id)
                })
                .count()
        }))
    }

    /// Extract one field across the whole capture in a single crossing.
    /// Packets lacking the layer yield None.
    fn field_column(&self, py: Python<'_>, layer_name: &str, field: &str) -> PyResult<Py<PyList>> {
        let id = proto_by_name(layer_name)?;
        if proto::field_of(id, field).is_none() {
            return Err(PyKeyError::new_err(format!(
                "no field {field:?} on {layer_name}"
            )));
        }
        let buf = Arc::clone(&self.buf);
        let idx = self.index.clone();
        let link = self.link;
        let fname = field.to_string();

        let collected: Vec<Option<FieldValue>> = py.allow_threads(move || {
            idx.iter()
                .map(|(off, len, _, _)| {
                    let a = *off as usize;
                    let b = a + *len as usize;
                    let pkt = CorePacket::dissect(buf[a..b].to_vec(), link);
                    pkt.find_layer(id).and_then(|l| pkt.get(l, &fname))
                })
                .collect()
        });

        let out = PyList::empty_bound(py);
        for v in &collected {
            match v {
                Some(v) => out.append(value_to_py(py, v))?,
                None => out.append(py.None())?,
            }
        }
        Ok(out.unbind())
    }

    /// Extract many fields across the whole capture in ONE pass and ONE crossing.
    ///
    /// Each packet is dissected once and every requested field read from it,
    /// rather than one pass per field. `layer` and `conds` select rows; both are
    /// evaluated in Rust, so filtered extraction never materialises the packets
    /// it rejects. Returns one list per spec, in spec order.
    #[pyo3(signature = (specs, layer = None, conds = Vec::new()))]
    fn columns(
        &self,
        py: Python<'_>,
        specs: Vec<(String, String)>,
        layer: Option<&str>,
        conds: Vec<(String, String, String, PyObject)>,
    ) -> PyResult<Py<PyList>> {
        let resolved: Vec<ColSpec> = specs
            .iter()
            .map(|(l, f)| resolve_spec(l, f))
            .collect::<PyResult<_>>()?;
        let q = build_query(py, layer, conds)?;

        let buf = &self.buf;
        let idx = &self.index;
        let link = self.link;
        let div = if self.nanos { 1e9 } else { 1e6 };
        let nums = self.nums.as_deref();
        let dissect = !q.is_empty() || resolved.iter().any(|s| matches!(s, ColSpec::Field(..)));

        let cols: Vec<Vec<Cell>> = py.allow_threads(|| {
            let mut cols: Vec<Vec<Cell>> = resolved
                .iter()
                .map(|_| Vec::with_capacity(idx.len()))
                .collect();
            for (row, (off, len, sec, frac)) in idx.iter().enumerate() {
                let a = *off as usize;
                let bytes = &buf[a..a + *len as usize];
                let spans = if dissect {
                    dissect_spans(bytes, link)
                } else {
                    Spans::new()
                };
                if !q.matches(bytes, &spans) {
                    continue;
                }
                for (c, spec) in resolved.iter().enumerate() {
                    cols[c].push(match spec {
                        ColSpec::Time => Cell::Time(*sec as f64 + *frac as f64 / div),
                        ColSpec::Len => Cell::Val(FieldValue::Uint(*len as u64)),
                        ColSpec::Num => {
                            Cell::Val(FieldValue::Uint(nums.map_or(row as u64, |n| n[row] as u64)))
                        }
                        ColSpec::Field(id, f) => match spans.iter().find(|s| s.proto == *id) {
                            Some(s) => Cell::Val(decode_span(bytes, s, f)),
                            None => Cell::Null,
                        },
                    });
                }
            }
            cols
        });

        let out = PyList::empty_bound(py);
        for col in &cols {
            let l = PyList::empty_bound(py);
            for cell in col {
                match cell {
                    Cell::Null => l.append(py.None())?,
                    Cell::Val(v) => l.append(value_to_py(py, v))?,
                    Cell::Time(t) => l.append(*t)?,
                }
            }
            out.append(l)?;
        }
        Ok(out.unbind())
    }

    /// Positions in this list whose packets satisfy the query.
    #[pyo3(signature = (layer = None, conds = Vec::new()))]
    fn filter_indices(
        &self,
        py: Python<'_>,
        layer: Option<&str>,
        conds: Vec<(String, String, String, PyObject)>,
    ) -> PyResult<Vec<u32>> {
        let q = build_query(py, layer, conds)?;
        Ok(self.matching(py, &q))
    }

    /// A view over the matching packets. Shares the capture buffer: no copy.
    #[pyo3(signature = (layer = None, conds = Vec::new()))]
    fn filter(
        &self,
        py: Python<'_>,
        layer: Option<&str>,
        conds: Vec<(String, String, String, PyObject)>,
    ) -> PyResult<PyPktList> {
        let q = build_query(py, layer, conds)?;
        let keep = self.matching(py, &q);
        Ok(PyPktList {
            buf: Arc::clone(&self.buf),
            index: keep.iter().map(|&i| self.index[i as usize]).collect(),
            link: self.link,
            nanos: self.nanos,
            nums: Some(keep.iter().map(|&i| self.num_at(i as usize)).collect()),
        })
    }

    /// Positions of these packets in the capture they were filtered from.
    fn nums(&self) -> Vec<u32> {
        (0..self.index.len()).map(|i| self.num_at(i)).collect()
    }

    /// Timestamps for every packet, as floating seconds.
    fn times(&self) -> Vec<f64> {
        let div = if self.nanos { 1e9 } else { 1e6 };
        self.index
            .iter()
            .map(|(_, _, s, f)| *s as f64 + *f as f64 / div)
            .collect()
    }

    /// Raw bytes of one packet without dissecting it.
    fn raw_at<'py>(&self, py: Python<'py>, i: usize) -> PyResult<Bound<'py, PyBytes>> {
        let (off, len, _, _) = *self
            .index
            .get(i)
            .ok_or_else(|| PyIndexError::new_err("packet index out of range"))?;
        let a = off as usize;
        Ok(PyBytes::new_bound(py, &self.buf[a..a + len as usize]))
    }

    #[getter]
    fn linktype(&self) -> &'static str {
        self.link.name()
    }
}

/// Read a pcap file. Records are indexed but not dissected, so this is close to
/// the cost of reading the file.
#[pyfunction]
fn read_pcap(py: Python<'_>, path: &str) -> PyResult<PyPktList> {
    let data = std::fs::read(path)?;
    // Dispatch on the file's own magic so callers do not have to know or care
    // which capture format they were handed.
    let (index, link, nanos) = py
        .allow_threads(|| -> Result<_, String> {
            let base = data.as_ptr() as usize;
            let mut index = Vec::new();
            if blitzpkt_core::pcapng::is_pcapng(&data) {
                let r = blitzpkt_core::pcapng::Reader::new(&data).map_err(|e| e.to_string())?;
                let link = pcap::link_to_proto(r.header.linktype);
                let nanos = r.header.nanos();
                for rec in blitzpkt_core::pcapng::Reader::new(&data).map_err(|e| e.to_string())? {
                    let off = (rec.data.as_ptr() as usize - base) as u32;
                    index.push((off, rec.caplen, rec.ts_sec, rec.ts_frac));
                }
                Ok((index, link, nanos))
            } else {
                let r = pcap::Reader::new(&data).map_err(|e| e.to_string())?;
                let link = pcap::link_to_proto(r.header.linktype);
                let nanos = r.header.nanos;
                for rec in pcap::Reader::new(&data).map_err(|e| e.to_string())? {
                    let off = (rec.data.as_ptr() as usize - base) as u32;
                    index.push((off, rec.caplen, rec.ts_sec, rec.ts_frac));
                }
                Ok((index, link, nanos))
            }
        })
        .map_err(PyValueError::new_err)?;

    Ok(PyPktList {
        buf: Arc::new(data),
        index,
        link,
        nanos,
        nums: None,
    })
}

/// Dissect a single buffer.
#[pyfunction]
#[pyo3(signature = (data, link = "Ether"))]
fn dissect(data: &[u8], link: &str) -> PyResult<PyPkt> {
    Ok(PyPkt {
        inner: CorePacket::dissect(data.to_vec(), proto_by_name(link)?),
        time: 0.0,
    })
}

/// Build a packet from a stack of layer names using default field values.
#[pyfunction]
fn build_stack(names: Vec<String>) -> PyResult<PyPkt> {
    let mut stack = Vec::with_capacity(names.len());
    for n in &names {
        stack.push(proto_by_name(n)?);
    }
    Ok(PyPkt {
        inner: CorePacket::build(&stack),
        time: 0.0,
    })
}

/// Resolve layer names into a build stack, attaching any option bytes.
fn make_stack(
    names: &[String],
    opts: &[(usize, Vec<u8>)],
) -> PyResult<Vec<(ProtoId, Option<Vec<u8>>)>> {
    let mut stack = Vec::with_capacity(names.len());
    for (i, n) in names.iter().enumerate() {
        let o = opts
            .iter()
            .find(|(idx, _)| *idx == i)
            .map(|(_, b)| b.clone());
        stack.push((proto_by_name(n)?, o));
    }
    Ok(stack)
}

fn apply_fields(
    pkt: &mut CorePacket,
    ints: &[(usize, String, u64)],
    strs: &[(usize, String, String)],
    raws: &[(usize, String, Vec<u8>)],
) -> PyResult<()> {
    for (layer, name, v) in ints {
        if !pkt.set_uint(*layer, name, *v) {
            return Err(PyKeyError::new_err(format!(
                "no field {name:?} in layer {layer}"
            )));
        }
    }
    for (layer, name, s) in strs {
        let span = pkt
            .layers()
            .get(*layer)
            .ok_or_else(|| PyIndexError::new_err("layer out of range"))?;
        let f = proto::field_of(span.proto, name)
            .ok_or_else(|| PyKeyError::new_err(format!("no field {name:?} in layer {layer}")))?;
        match blitzpkt_core::parse::value_for(f, s) {
            Some(blitzpkt_core::parse::ValueBits::Uint(v)) => {
                pkt.set_uint(*layer, name, v);
            }
            Some(blitzpkt_core::parse::ValueBits::Bytes(b)) => {
                pkt.set_bytes(*layer, name, &b);
            }
            None => {
                return Err(PyValueError::new_err(format!(
                    "cannot parse {s:?} for field {name:?}"
                )))
            }
        }
    }
    for (layer, name, b) in raws {
        if !pkt.set_bytes(*layer, name, b) {
            return Err(PyKeyError::new_err(format!(
                "no field {name:?} in layer {layer}"
            )));
        }
    }
    Ok(())
}

/// Build and fully serialise a packet in ONE crossing of the boundary.
///
/// This is the fast construction path: the facade accumulates a layer stack and
/// its field assignments in Python, then hands the whole thing over once. Doing
/// it field by field would put an FFI call in the hot loop, which is exactly the
/// mistake that erases the speedup.
#[pyfunction]
#[pyo3(signature = (names, ints, strs, raws, payload = None, opts = Vec::new()))]
fn build_and_serialize<'py>(
    py: Python<'py>,
    names: Vec<String>,
    ints: Vec<(usize, String, u64)>,
    strs: Vec<(usize, String, String)>,
    raws: Vec<(usize, String, Vec<u8>)>,
    payload: Option<Vec<u8>>,
    opts: Vec<(usize, Vec<u8>)>,
) -> PyResult<Bound<'py, PyBytes>> {
    let stack = make_stack(&names, &opts)?;
    let mut pkt = CorePacket::build_with(&stack);
    if let Some(p) = payload {
        let last = stack.len().saturating_sub(1);
        pkt.set_payload(last, &p);
    }
    apply_fields(&mut pkt, &ints, &strs, &raws)?;
    pkt.mark_all_dirty();
    Ok(PyBytes::new_bound(py, pkt.to_bytes()))
}

/// Same as `build_and_serialize` but returns the packet for further inspection.
#[pyfunction]
#[pyo3(signature = (names, ints, strs, raws, payload = None, opts = Vec::new()))]
fn build_packet(
    names: Vec<String>,
    ints: Vec<(usize, String, u64)>,
    strs: Vec<(usize, String, String)>,
    raws: Vec<(usize, String, Vec<u8>)>,
    payload: Option<Vec<u8>>,
    opts: Vec<(usize, Vec<u8>)>,
) -> PyResult<PyPkt> {
    let stack = make_stack(&names, &opts)?;
    let mut pkt = CorePacket::build_with(&stack);
    if let Some(p) = payload {
        let last = stack.len().saturating_sub(1);
        pkt.set_payload(last, &p);
    }
    apply_fields(&mut pkt, &ints, &strs, &raws)?;
    pkt.mark_all_dirty();
    Ok(PyPkt {
        inner: pkt,
        time: 0.0,
    })
}

/// Write packets to a pcap file.
#[pyfunction]
#[pyo3(signature = (path, packets, linktype = 1))]
fn write_pcap(path: &str, packets: Vec<Vec<u8>>, linktype: u32) -> PyResult<()> {
    let mut out = Vec::new();
    pcap::write_header(&mut out, linktype, 65535);
    for p in &packets {
        pcap::write_record(&mut out, 0, 0, p, p.len() as u32);
    }
    std::fs::write(path, out)?;
    Ok(())
}

/// Field names for a layer, in header order.
#[pyfunction]
fn layer_fields(name: &str) -> PyResult<Vec<&'static str>> {
    Ok(proto::desc(proto_by_name(name)?)
        .fields
        .iter()
        .map(|f| f.name)
        .collect())
}

/// Every layer name the engine knows.
#[pyfunction]
fn known_layers() -> Vec<&'static str> {
    const ALL: &[ProtoId] = &[
        ProtoId::Ether,
        ProtoId::Dot1Q,
        ProtoId::Arp,
        ProtoId::Ipv4,
        ProtoId::Ipv6,
        ProtoId::Tcp,
        ProtoId::Udp,
        ProtoId::Icmp,
        ProtoId::Icmpv6,
        ProtoId::Dns,
        ProtoId::Bootp,
        ProtoId::Dhcp,
        ProtoId::Raw,
        ProtoId::Padding,
    ];
    ALL.iter().map(|p| p.name()).collect()
}

#[pymodule]
fn _blitzpkt(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPkt>()?;
    m.add_class::<PyPktList>()?;
    m.add_function(wrap_pyfunction!(read_pcap, m)?)?;
    m.add_function(wrap_pyfunction!(write_pcap, m)?)?;
    m.add_function(wrap_pyfunction!(dissect, m)?)?;
    m.add_function(wrap_pyfunction!(build_stack, m)?)?;
    m.add_function(wrap_pyfunction!(build_packet, m)?)?;
    m.add_function(wrap_pyfunction!(build_and_serialize, m)?)?;
    m.add_function(wrap_pyfunction!(layer_fields, m)?)?;
    m.add_function(wrap_pyfunction!(known_layers, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
