//! Python bindings. The boundary is crossed at file or list granularity, never
//! per field and never per packet on a bulk path.

#![forbid(unsafe_code)]
// pyo3 0.22's generated trampolines convert PyErr to PyErr, which clippy flags
// as useless_conversion at each function's span.
#![allow(clippy::useless_conversion)]

mod capture;
mod live;
mod sniff;
mod writer;
mod template;

use pyo3::exceptions::{PyIndexError, PyKeyError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes, PyDict, PyList, PySequence};
use std::sync::Arc;
use wiry_capture::Flow;
use wiry_core::field::{self, FieldDesc, FieldKind, FieldValue};
use wiry_core::frag;
use wiry_core::options::{Item, OptArg};
use wiry_core::packet::{self, dissect_spans, LayerSpan, Packet as CorePacket, Spans};
use wiry_core::pcap;
use wiry_core::proto::{self, ProtoId};
use wiry_core::show;

pub(crate) fn proto_by_name(name: &str) -> PyResult<ProtoId> {
    proto::by_name(name).ok_or_else(|| PyValueError::new_err(format!("unknown layer {name:?}")))
}

fn value_to_py(py: Python<'_>, v: &FieldValue) -> PyObject {
    match v {
        FieldValue::Uint(n) => n.into_py(py),
        FieldValue::Ipv4(_) | FieldValue::Ipv6(_) | FieldValue::Mac(_) => {
            show::render_value(v).into_py(py)
        }
        FieldValue::Flags { .. } => show::render_value(v).into_py(py),
        FieldValue::Bytes(b) => PyBytes::new_bound(py, b).into(),
    }
}

/// Pseudo-layer carrying per-record metadata that is not in the packet bytes.
const FRAME: &str = "Frame";

#[derive(Clone, Copy)]
enum ColSpec {
    Field(ProtoId, FieldRef),
    Options(ProtoId),
    Time,
    Len,
    Num,
}

/// One field name resolved against both layouts a layer can take. Resolving
/// once, outside the bulk loop, is what keeps a framed layer from being read
/// through the unframed table's offsets — and an unframed one from answering to
/// a name only the framed table declares.
#[derive(Clone, Copy)]
struct FieldRef {
    plain: Option<&'static FieldDesc>,
    framed: Option<&'static FieldDesc>,
}

impl FieldRef {
    fn resolve(id: ProtoId, name: &str) -> Option<Self> {
        let pick = |framed| proto::fields_of(id, framed).iter().find(|f| f.name == name);
        let r = Self {
            plain: pick(false),
            framed: pick(true),
        };
        (r.plain.is_some() || r.framed.is_some()).then_some(r)
    }

    fn any(&self) -> &'static FieldDesc {
        self.plain.or(self.framed).expect("resolve kept one side")
    }

    #[inline]
    fn at(&self, spans: &[LayerSpan], at: usize) -> Option<&'static FieldDesc> {
        if packet::framing_at(spans, at) > 0 {
            self.framed
        } else {
            self.plain
        }
    }
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
    field: FieldRef,
    op: CmpOp,
    val: CondVal,
}

/// A test against a layer the packet does not have is false, never true.
pub(crate) struct Query {
    layer: Option<ProtoId>,
    conds: Vec<Cond>,
}

impl Query {
    pub(crate) fn is_empty(&self) -> bool {
        self.layer.is_none() && self.conds.is_empty()
    }

    pub(crate) fn matches(&self, buf: &[u8], spans: &[LayerSpan]) -> bool {
        if let Some(l) = self.layer {
            if !spans.iter().any(|s| s.proto == l) {
                return false;
            }
        }
        self.conds.iter().all(|c| {
            let Some(at) = spans.iter().position(|s| s.proto == c.proto) else {
                return false;
            };
            let Some(v) = decode_at(buf, spans, at, &c.field) else {
                return false;
            };
            match &c.val {
                CondVal::Uint(n) => v.as_uint().is_some_and(|x| c.op.test(x, *n)),
                CondVal::Bytes(b) => raw_bytes(&v).is_some_and(|x| c.op.test(x, b.as_slice())),
            }
        })
    }
}

/// Clamped exactly as `Packet::get_desc` clamps, so the bulk and per-packet
/// paths cannot disagree.
#[inline]
fn decode_span(buf: &[u8], s: &LayerSpan, f: &FieldDesc) -> Option<FieldValue> {
    let a = (s.off as usize).min(buf.len());
    let b = (a + s.hlen as usize).min(buf.len());
    let hdr = &buf[a..b];
    f.is_active(hdr).then(|| field::decode(hdr, f))
}

#[inline]
fn decode_at(buf: &[u8], spans: &[LayerSpan], at: usize, r: &FieldRef) -> Option<FieldValue> {
    decode_span(buf, spans.get(at)?, r.at(spans, at)?)
}

fn options_to_py(py: Python<'_>, items: &[Item]) -> PyResult<Py<PyList>> {
    use wiry_core::options::ItemValue;
    let out = PyList::empty_bound(py);
    for it in items {
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
            ItemValue::Pairs(l) => PyList::new_bound(py, l).into(),
            ItemValue::Items(v) => options_to_py(py, v)?.into_py(py),
        };
        out.append((it.name.as_ref(), v))?;
    }
    Ok(out.unbind())
}

fn type_names(types: &[u16]) -> Vec<&'static str> {
    types
        .iter()
        .map(|t| wiry_core::layers::dns::rtype_name(*t))
        .collect()
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
    if name == "options" && proto::desc(id).parse_options.is_some() {
        return Ok(ColSpec::Options(id));
    }
    let r = FieldRef::resolve(id, name)
        .ok_or_else(|| PyKeyError::new_err(format!("no field {name:?} on {layer}")))?;
    Ok(ColSpec::Field(id, r))
}

pub(crate) fn build_query(
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
        let r = FieldRef::resolve(proto, &fname)
            .ok_or_else(|| PyKeyError::new_err(format!("no field {fname:?} on {lname}")))?;
        let f = r.any();
        let v = val.bind(py);
        let cv = if let Ok(n) = v.extract::<u64>() {
            CondVal::Uint(n)
        } else if let Ok(b) = v.extract::<Vec<u8>>() {
            CondVal::Bytes(b)
        } else if let Ok(s) = v.extract::<String>() {
            match wiry_core::parse::value_for(f, &s) {
                Some(wiry_core::parse::ValueBits::Uint(n)) => CondVal::Uint(n),
                Some(wiry_core::parse::ValueBits::Bytes(b)) => CondVal::Bytes(b),
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
            field: r,
            op: CmpOp::parse(&op)?,
            val: cv,
        });
    }
    Ok(Query { layer, conds: out })
}

enum Cell {
    Null,
    Val(FieldValue),
    Time(f64),
    Opts(Vec<Item>),
}

impl Cell {
    fn into_py_value(self, py: Python<'_>) -> PyResult<PyObject> {
        Ok(match self {
            Cell::Null => py.None(),
            Cell::Val(v) => value_to_py(py, &v),
            Cell::Time(t) => t.into_py(py),
            Cell::Opts(items) => options_to_py(py, &items)?.into_py(py),
        })
    }
}

#[pyclass(name = "Pkt")]
pub struct PyPkt {
    pub(crate) inner: CorePacket,
    #[pyo3(get)]
    pub(crate) time: f64,
    /// Length on the wire, which exceeds the captured length on a record a
    /// snaplen clipped. Zero where nothing measured it.
    #[pyo3(get)]
    pub(crate) wirelen: u32,
}

#[pymethods]
impl PyPkt {
    /// Outermost first.
    fn layer_names(&self) -> Vec<&'static str> {
        self.inner.layers().iter().map(|s| s.proto.name()).collect()
    }

    fn haslayer(&self, name: &str) -> PyResult<bool> {
        Ok(self.inner.has_layer(proto_by_name(name)?))
    }

    fn layer_index(&self, name: &str) -> PyResult<Option<usize>> {
        Ok(self.inner.find_layer(proto_by_name(name)?))
    }

    fn get_field(&self, py: Python<'_>, layer: usize, name: &str) -> PyResult<PyObject> {
        match self.inner.get(layer, name) {
            Some(v) => Ok(value_to_py(py, &v)),
            None => Err(PyKeyError::new_err(format!(
                "no field {name:?} in layer {layer}"
            ))),
        }
    }

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
        if self.inner.set_uint(layer, name, val) {
            return Ok(());
        }
        // `set_uint` says only yes or no, and a value too wide for the field
        // fails the same way an unknown name does. Tell them apart, or an
        // out-of-range write reports a field that plainly exists as missing.
        if !self.inner.uint_fits(layer, name, val) {
            return Err(PyValueError::new_err(format!(
                "{val} does not fit field {name:?} in layer {layer}"
            )));
        }
        Err(PyKeyError::new_err(format!(
            "no field {name:?} in layer {layer}"
        )))
    }

    fn set_field_str(&mut self, layer: usize, name: &str, val: &str) -> PyResult<()> {
        if layer >= self.inner.layers().len() {
            return Err(PyIndexError::new_err("layer out of range"));
        }
        let f = self
            .inner
            .active_field(layer, name)
            .ok_or_else(|| PyKeyError::new_err(format!("no field {name:?} in layer {layer}")))?;
        match wiry_core::parse::value_for(f, val) {
            Some(wiry_core::parse::ValueBits::Uint(v)) => {
                self.inner.set_uint(layer, name, v);
                Ok(())
            }
            Some(wiry_core::parse::ValueBits::Bytes(b)) => {
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

    fn set_payload(&mut self, layer: usize, data: &[u8]) -> PyResult<()> {
        if !self.inner.set_payload(layer, data) {
            return Err(PyIndexError::new_err("layer out of range"));
        }
        Ok(())
    }

    /// `None` means the protocol has no option region at all, unlike an empty
    /// list, which means it has one and it is empty.
    fn options(&self, py: Python<'_>, layer: usize) -> Option<Py<PyList>> {
        let items = self.inner.options(layer)?;
        options_to_py(py, &items).ok()
    }

    fn dns_records(&self, py: Python<'_>, layer: usize) -> PyResult<Option<PyObject>> {
        use wiry_core::layers::dns::{self, RData};
        let Some(span) = self.inner.layers().get(layer) else {
            return Ok(None);
        };
        if span.proto != ProtoId::Dns {
            return Ok(None);
        }
        let recs = dns::parse_records(self.inner.framed_body(layer));

        let dict = |pairs: &[(&str, PyObject)]| -> PyObject {
            let d = PyDict::new_bound(py);
            for (k, v) in pairs {
                let _ = d.set_item(k, v);
            }
            d.into()
        };

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
                } => dict(&[
                    ("mname", mname.into_py(py)),
                    ("rname", rname.into_py(py)),
                    ("serial", serial.into_py(py)),
                    ("refresh", refresh.into_py(py)),
                    ("retry", retry.into_py(py)),
                    ("expire", expire.into_py(py)),
                    ("minimum", minimum.into_py(py)),
                ]),
                RData::Srv {
                    priority,
                    weight,
                    port,
                    target,
                } => dict(&[
                    ("priority", priority.into_py(py)),
                    ("weight", weight.into_py(py)),
                    ("port", port.into_py(py)),
                    ("target", target.into_py(py)),
                ]),
                RData::Caa { flags, tag, value } => dict(&[
                    ("flags", flags.into_py(py)),
                    ("tag", tag.into_py(py)),
                    ("value", value.into_py(py)),
                ]),
                RData::Opt(opts) => {
                    let out = PyList::empty_bound(py);
                    for o in opts {
                        let _ = out.append(dict(&[
                            ("code", o.code.into_py(py)),
                            ("name", dns::ednsopt_name(o.code).into_py(py)),
                            ("data", PyBytes::new_bound(py, &o.data).into()),
                        ]));
                    }
                    out.into()
                }
                RData::Ds {
                    keytag,
                    algorithm,
                    digest_type,
                    digest,
                } => dict(&[
                    ("keytag", keytag.into_py(py)),
                    ("algorithm", algorithm.into_py(py)),
                    ("digesttype", digest_type.into_py(py)),
                    ("digest", PyBytes::new_bound(py, digest).into()),
                ]),
                RData::Rrsig {
                    type_covered,
                    algorithm,
                    labels,
                    original_ttl,
                    expiration,
                    inception,
                    keytag,
                    signer,
                    signature,
                } => dict(&[
                    ("typecovered", dns::rtype_name(*type_covered).into_py(py)),
                    ("rtypecovered", type_covered.into_py(py)),
                    ("algorithm", algorithm.into_py(py)),
                    ("labels", labels.into_py(py)),
                    ("originalttl", original_ttl.into_py(py)),
                    ("expiration", expiration.into_py(py)),
                    ("inception", inception.into_py(py)),
                    ("keytag", keytag.into_py(py)),
                    ("signersname", signer.into_py(py)),
                    ("signature", PyBytes::new_bound(py, signature).into()),
                ]),
                RData::Nsec { next, types } => dict(&[
                    ("nextname", next.into_py(py)),
                    ("types", type_names(types).into_py(py)),
                    ("rtypes", PyList::new_bound(py, types).into()),
                ]),
                RData::Nsec3 {
                    hash_alg,
                    flags,
                    iterations,
                    salt,
                    next_hashed,
                    types,
                } => dict(&[
                    ("hashalg", hash_alg.into_py(py)),
                    ("flags", flags.into_py(py)),
                    ("iterations", iterations.into_py(py)),
                    ("salt", PyBytes::new_bound(py, salt).into()),
                    (
                        "nexthashedownername",
                        PyBytes::new_bound(py, next_hashed).into(),
                    ),
                    ("types", type_names(types).into_py(py)),
                    ("rtypes", PyList::new_bound(py, types).into()),
                ]),
                RData::Nsec3Param {
                    hash_alg,
                    flags,
                    iterations,
                    salt,
                } => dict(&[
                    ("hashalg", hash_alg.into_py(py)),
                    ("flags", flags.into_py(py)),
                    ("iterations", iterations.into_py(py)),
                    ("salt", PyBytes::new_bound(py, salt).into()),
                ]),
                RData::Dnskey {
                    flags,
                    protocol,
                    algorithm,
                    key,
                } => dict(&[
                    ("flags", flags.into_py(py)),
                    ("protocol", protocol.into_py(py)),
                    ("algorithm", algorithm.into_py(py)),
                    ("publickey", PyBytes::new_bound(py, key).into()),
                ]),
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
                // RFC 6891 §6.1.3: OPT spends CLASS and TTL on other fields.
                if let Some(e) = r.edns() {
                    d.set_item("udpsize", e.udpsize)?;
                    d.set_item("extrcode", e.ext_rcode)?;
                    d.set_item("version", e.version)?;
                    d.set_item("do", e.dnssec_ok)?;
                    d.set_item("z", e.z)?;
                }
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

    fn payload<'py>(&self, py: Python<'py>, layer: usize) -> PyResult<Bound<'py, PyBytes>> {
        if layer >= self.inner.layers().len() {
            return Err(PyIndexError::new_err("layer out of range"));
        }
        Ok(PyBytes::new_bound(py, self.inner.payload(layer)))
    }

    // &mut self: CorePacket::to_bytes caches computed checksums in place.
    #[allow(clippy::wrong_self_convention)]
    fn to_bytes<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        if let Some(e) = self.inner.oversize() {
            return Err(PyValueError::new_err(e));
        }
        Ok(PyBytes::new_bound(py, self.inner.to_bytes()))
    }

    fn show(&self) -> String {
        show::show(&self.inner)
    }

    /// Rebuilding from a field spec would lose variable-length header content.
    fn copy(&self) -> PyPkt {
        PyPkt {
            inner: self.inner.clone(),
            time: self.time,
            wirelen: self.wirelen,
        }
    }

    fn summary(&self) -> String {
        show::summary(&self.inner)
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }

    /// The raw integer behind a field. A flags field renders as a string and an
    /// unnamed bit renders as nothing, so a caller that has to reproduce the
    /// octets reads the number instead.
    fn field_uint(&self, layer: usize, name: &str) -> Option<u64> {
        self.inner.get(layer, name).and_then(|v| v.as_uint())
    }

    /// Bytes the layer stacked under this one contributes to this one's header
    /// (BOOTP's magic cookie, RFC 2131 §3). Construction appends them itself, so
    /// a caller rebuilding from field values must not pass them a second time.
    fn bound_suffix<'py>(&self, py: Python<'py>, layer: usize) -> Bound<'py, PyBytes> {
        let spans = self.inner.layers();
        let extra = match (spans.get(layer), spans.get(layer + 1)) {
            (Some(s), Some(n)) => proto::desc(s.proto)
                .bind_next_bytes
                .map(|f| f(n.proto))
                .unwrap_or(&[]),
            _ => &[],
        };
        PyBytes::new_bound(py, extra)
    }

    /// Octets past the last dissected layer. Dissection stops at a depth bound,
    /// so a chain deeper than that leaves a tail no layer describes and a
    /// caller rebuilding from field values would otherwise drop it.
    fn tail<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        let end = self
            .inner
            .layers()
            .last()
            .map_or(0, |s| (s.off + s.hlen) as usize);
        PyBytes::new_bound(py, self.inner.buf.get(end..).unwrap_or(&[]))
    }

    /// Names `field_names` lists that a parser answers rather than octets
    /// (`DNS.an`), so they have no offset and cannot be read or assigned as
    /// fields. A caller reproducing a header skips exactly these.
    fn accessor_names(&self, layer: usize) -> PyResult<Vec<&'static str>> {
        let proto = self
            .inner
            .layers()
            .get(layer)
            .ok_or_else(|| PyIndexError::new_err("layer out of range"))?
            .proto;
        Ok(proto::accessor_names(proto).to_vec())
    }

    /// A conditional field absent from this particular header is not listed.
    fn field_names(&self, layer: usize) -> PyResult<Vec<&'static str>> {
        let proto = self
            .inner
            .layers()
            .get(layer)
            .ok_or_else(|| PyIndexError::new_err("layer out of range"))?
            .proto;
        let mut out: Vec<&'static str> = self.inner.active_fields(layer).map(|f| f.name).collect();
        out.extend_from_slice(proto::accessor_names(proto));
        Ok(out)
    }
}

/// (offset, caplen, ts_sec, ts_frac, origlen). The offset is a `usize` because
/// `fs::read` has no size limit: as a `u32` it wraps past 4 GiB, and the
/// wrapped slice stays in bounds, so a read returns another packet's bytes.
/// `origlen` is the length on the wire, which a snaplen-clipped record needs
/// to keep or a copy of the file would claim the clipped bytes were all of it.
pub(crate) type Record = (usize, u32, u32, u32, u32);

/// One buffer plus a record index; indexing mints one Python object.
#[pyclass(name = "PktList")]
pub struct PyPktList {
    buf: Arc<Vec<u8>>,
    index: Vec<Record>,
    link: ProtoId,
    /// The file's own DLT. Kept beside `link` because a BPF program is compiled
    /// against the link-layer number, not the dissector it maps to.
    dlt: u32,
    nanos: bool,
    /// Positions in the original capture, set when this list is a filtered view.
    nums: Option<Vec<u32>>,
}

impl PyPktList {
    /// The Rust-side constructor a live driver uses: `CaptureBuf::into_parts`
    /// yields exactly the first three arguments. Not exposed to Python, because
    /// handing an arbitrary buffer and index across the boundary is unchecked.
    pub(crate) fn from_capture(buf: Vec<u8>, index: Vec<Record>, link: u32, nanos: bool) -> Self {
        Self {
            buf: Arc::new(buf),
            index,
            link: pcap::link_to_proto(link),
            dlt: link,
            nanos,
            nums: None,
        }
    }

    /// The capture buffer, its record index, and the unit `ts_frac` is in:
    /// what a writer needs to copy the whole list without minting a packet.
    pub(crate) fn parts(&self) -> (&[u8], &[Record], bool) {
        (&self.buf, &self.index, self.nanos)
    }

    /// A view over the kept positions, sharing the capture buffer.
    fn keeping(&self, keep: &[u32]) -> Self {
        Self {
            buf: Arc::clone(&self.buf),
            index: keep.iter().map(|&i| self.index[i as usize]).collect(),
            link: self.link,
            dlt: self.dlt,
            nanos: self.nanos,
            nums: Some(keep.iter().map(|&i| self.num_at(i as usize)).collect()),
        }
    }

    fn time_at(&self, i: usize) -> f64 {
        let (_, _, sec, frac, _) = self.index[i];
        let div = if self.nanos { 1e9 } else { 1e6 };
        sec as f64 + frac as f64 / div
    }

    fn bytes_at(&self, i: usize) -> &[u8] {
        let (off, len, _, _, _) = self.index[i];
        &self.buf[off..off + len as usize]
    }

    fn num_at(&self, i: usize) -> u32 {
        match &self.nums {
            Some(n) => n[i],
            None => i as u32,
        }
    }

    fn matching(&self, py: Python<'_>, q: &Query) -> Vec<u32> {
        let buf = &self.buf;
        let idx = &self.index;
        let link = self.link;
        py.allow_threads(|| {
            idx.iter()
                .enumerate()
                .filter(|(_, (off, len, _, _, _))| {
                    let a = *off;
                    let bytes = &buf[a..a + *len as usize];
                    q.matches(bytes, &dissect_spans(bytes, link))
                })
                .map(|(i, _)| i as u32)
                .collect()
        })
    }

    fn dissect_at(&self, i: usize) -> PyPkt {
        let (off, len, sec, frac, origlen) = self.index[i];
        let a = off;
        let b = a + len as usize;
        let bytes = self.buf[a..b].to_vec();
        let div = if self.nanos { 1e9 } else { 1e6 };
        PyPkt {
            inner: CorePacket::dissect(bytes, self.link),
            time: sec as f64 + frac as f64 / div,
            wirelen: origlen,
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

    fn count_layer(&self, py: Python<'_>, name: &str) -> PyResult<usize> {
        let id = proto_by_name(name)?;
        let buf = Arc::clone(&self.buf);
        let idx = self.index.clone();
        let link = self.link;
        Ok(py.allow_threads(move || {
            idx.iter()
                .filter(|(off, len, _, _, _)| {
                    let a = *off;
                    let b = a + *len as usize;
                    wiry_core::packet::dissect_spans(&buf[a..b], link)
                        .iter()
                        .any(|s| s.proto == id)
                })
                .count()
        }))
    }

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
        let parses_options = field == "options" && proto::desc(id).parse_options.is_some();

        let collected: Vec<Cell> = py.allow_threads(move || {
            idx.iter()
                .map(|(off, len, _, _, _)| {
                    let a = *off;
                    let b = a + *len as usize;
                    let pkt = CorePacket::dissect(buf[a..b].to_vec(), link);
                    let Some(l) = pkt.find_layer(id) else {
                        return Cell::Null;
                    };
                    match parses_options.then(|| pkt.options(l)).flatten() {
                        Some(items) => Cell::Opts(items),
                        None => pkt.get(l, &fname).map_or(Cell::Null, Cell::Val),
                    }
                })
                .collect()
        });

        let out = PyList::empty_bound(py);
        for v in collected {
            out.append(v.into_py_value(py)?)?;
        }
        Ok(out.unbind())
    }

    /// One pass, one crossing. `layer` and `conds` select rows in Rust, so a
    /// rejected packet is never materialised. One list per spec, in order.
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
        let dissect = !q.is_empty()
            || resolved
                .iter()
                .any(|s| matches!(s, ColSpec::Field(..) | ColSpec::Options(..)));

        let cols: Vec<Vec<Cell>> = py.allow_threads(|| {
            let mut cols: Vec<Vec<Cell>> = resolved
                .iter()
                .map(|_| Vec::with_capacity(idx.len()))
                .collect();
            for (row, (off, len, sec, frac, _)) in idx.iter().enumerate() {
                let a = *off;
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
                        ColSpec::Field(id, r) => match spans.iter().position(|s| s.proto == *id) {
                            Some(at) => {
                                decode_at(bytes, &spans, at, r).map_or(Cell::Null, Cell::Val)
                            }
                            None => Cell::Null,
                        },
                        // The named item list a per-packet `.options` read
                        // returns, not the raw region: `raw_options()` is that.
                        ColSpec::Options(id) => match spans.iter().position(|s| s.proto == *id) {
                            Some(at) => {
                                packet::options_at(bytes, &spans, at).map_or(Cell::Null, Cell::Opts)
                            }
                            None => Cell::Null,
                        },
                    });
                }
            }
            cols
        });

        let out = PyList::empty_bound(py);
        for col in cols {
            let l = PyList::empty_bound(py);
            for cell in col {
                l.append(cell.into_py_value(py)?)?;
            }
            out.append(l)?;
        }
        Ok(out.unbind())
    }

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

    /// Shares the capture buffer: no copy.
    #[pyo3(signature = (layer = None, conds = Vec::new()))]
    fn filter(
        &self,
        py: Python<'_>,
        layer: Option<&str>,
        conds: Vec<(String, String, String, PyObject)>,
    ) -> PyResult<PyPktList> {
        let q = build_query(py, layer, conds)?;
        let keep = self.matching(py, &q);
        Ok(self.keeping(&keep))
    }

    /// The offline sniff driver: the same state machine the live drivers will
    /// feed, over records already indexed from a file. The result shares this
    /// capture's buffer, so it is an ordinary list and costs no copy.
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (
        count = 0, store = true, bpf = None, layer = None, conds = Vec::new(),
        timeout = None, prn = None, lfilter = None, stop_filter = None, wrap = None
    ))]
    fn sniff_offline(
        &self,
        py: Python<'_>,
        count: usize,
        store: bool,
        bpf: Option<&str>,
        layer: Option<&str>,
        conds: Vec<(String, String, String, PyObject)>,
        timeout: Option<f64>,
        prn: Option<PyObject>,
        lfilter: Option<PyObject>,
        stop_filter: Option<PyObject>,
        wrap: Option<PyObject>,
    ) -> PyResult<PyPktList> {
        // Compiles with no device and no privileges, so a BPF filter works on a
        // file exactly as it would on a wire.
        let filter = match bpf {
            Some(e) => Some(
                wiry_capture::compile_filter(self.dlt, e, 262_144).map_err(capture::to_py_err)?,
            ),
            None => None,
        };
        let q = build_query(py, layer, conds)?;
        let mut st = sniff::SniffState::new(
            count,
            store,
            timeout,
            filter,
            q,
            prn,
            lfilter,
            stop_filter,
            wrap,
        );
        let link = self.link;
        let n = self.index.len();
        let mut keep: Vec<u32> = Vec::new();

        if st.needs_python() {
            for i in 0..n {
                let (put, flow) =
                    st.step_py(py, self.bytes_at(i), link, self.time_at(i), self.index[i].4)?;
                if put {
                    keep.push(i as u32);
                }
                if flow == Flow::Stop {
                    break;
                }
            }
        } else {
            py.allow_threads(|| {
                for i in 0..n {
                    let (put, flow) = st.step(self.bytes_at(i), link);
                    if put {
                        keep.push(i as u32);
                    }
                    if flow == Flow::Stop {
                        break;
                    }
                }
            });
        }
        Ok(self.keeping(&keep))
    }

    /// The result is a new capture rather than a view, because a reassembled
    /// datagram is bytes no record in this one holds. Alongside it comes one tag
    /// per packet: 0 carried no fragment, 1 was reassembled, 2 is a fragment
    /// whose datagram never completed.
    fn defragmented(&self, py: Python<'_>) -> (PyPktList, Vec<u8>) {
        let link = self.link;
        let (buf, index, kinds) = py.allow_threads(|| {
            let n = self.index.len();
            let frames: Vec<&[u8]> = (0..n).map(|i| self.bytes_at(i)).collect();
            // Reassembly only ever joins records, so the output is no longer
            // than the input and no reallocation is needed.
            let mut buf: Vec<u8> = Vec::with_capacity(self.buf.len());
            let mut index: Vec<Record> = Vec::with_capacity(n);
            let mut kinds: Vec<u8> = Vec::with_capacity(n);
            for piece in frag::defragment(frames.iter().copied(), link) {
                let (_, _, sec, frac, wirelen) = self.index[piece.at() as usize];
                let (bytes, kind): (&[u8], u8) = match &piece {
                    frag::Piece::Whole(i) => (frames[*i as usize], 0),
                    frag::Piece::Complete(_, f) => (f, 1),
                    frag::Piece::Incomplete(i) => (frames[*i as usize], 2),
                };
                // A reassembled datagram was never one frame on the wire, so the
                // only honest wire length is what it reassembled to. A passed
                // through record keeps the length its own capture recorded.
                let wirelen = match &piece {
                    frag::Piece::Complete(..) => bytes.len() as u32,
                    _ => wirelen.max(bytes.len() as u32),
                };
                index.push((buf.len(), bytes.len() as u32, sec, frac, wirelen));
                buf.extend_from_slice(bytes);
                kinds.push(kind);
            }
            (buf, index, kinds)
        });
        (
            PyPktList::from_capture(buf, index, self.dlt, self.nanos),
            kinds,
        )
    }

    /// Shares the capture buffer: no copy.
    fn select(&self, idx: Vec<u32>) -> PyResult<PyPktList> {
        if idx.iter().any(|i| *i as usize >= self.index.len()) {
            return Err(PyIndexError::new_err("packet index out of range"));
        }
        Ok(self.keeping(&idx))
    }

    /// Shares the capture buffer: no copy.
    fn head(&self, n: usize) -> PyPktList {
        let k = n.min(self.index.len());
        PyPktList {
            buf: Arc::clone(&self.buf),
            index: self.index[..k].to_vec(),
            link: self.link,
            dlt: self.dlt,
            nanos: self.nanos,
            nums: Some((0..k).map(|i| self.num_at(i)).collect()),
        }
    }

    fn nums(&self) -> Vec<u32> {
        (0..self.index.len()).map(|i| self.num_at(i)).collect()
    }

    fn times(&self) -> Vec<f64> {
        let div = if self.nanos { 1e9 } else { 1e6 };
        self.index
            .iter()
            .map(|(_, _, s, f, _)| *s as f64 + *f as f64 / div)
            .collect()
    }

    fn raw_at<'py>(&self, py: Python<'py>, i: usize) -> PyResult<Bound<'py, PyBytes>> {
        let (off, len, _, _, _) = *self
            .index
            .get(i)
            .ok_or_else(|| PyIndexError::new_err("packet index out of range"))?;
        let a = off;
        Ok(PyBytes::new_bound(py, &self.buf[a..a + len as usize]))
    }

    #[getter]
    fn linktype(&self) -> &'static str {
        self.link.name()
    }

    /// The DLT number itself, where `linktype()` gives its name.
    #[getter]
    fn dlt(&self) -> u32 {
        self.dlt
    }

    #[getter]
    fn nanos(&self) -> bool {
        self.nanos
    }
}

/// Records are indexed but not dissected. Dispatches on the file's own magic,
/// so pcap and pcapng are interchangeable.
#[pyfunction]
fn read_pcap(py: Python<'_>, path: &str) -> PyResult<PyPktList> {
    let data = std::fs::read(path)?;
    let (index, dlt, nanos) = py
        .allow_threads(|| -> Result<_, String> {
            let base = data.as_ptr() as usize;
            let mut index = Vec::new();
            if wiry_core::pcapng::is_pcapng(&data) {
                let r = wiry_core::pcapng::Reader::new(&data).map_err(|e| e.to_string())?;
                let dlt = r.header.linktype;
                let nanos = r.header.nanos();
                for rec in wiry_core::pcapng::Reader::new(&data).map_err(|e| e.to_string())? {
                    let off = rec.data.as_ptr() as usize - base;
                    index.push((off, rec.caplen, rec.ts_sec, rec.ts_frac, rec.origlen));
                }
                Ok((index, dlt, nanos))
            } else {
                let r = pcap::Reader::new(&data).map_err(|e| e.to_string())?;
                let dlt = r.header.linktype;
                let nanos = r.header.nanos;
                for rec in pcap::Reader::new(&data).map_err(|e| e.to_string())? {
                    let off = rec.data.as_ptr() as usize - base;
                    index.push((off, rec.caplen, rec.ts_sec, rec.ts_frac, rec.origlen));
                }
                Ok((index, dlt, nanos))
            }
        })
        .map_err(PyValueError::new_err)?;

    Ok(PyPktList {
        buf: Arc::new(data),
        index,
        link: pcap::link_to_proto(dlt),
        dlt,
        nanos,
        nums: None,
    })
}

#[pyfunction]
#[pyo3(signature = (data, link = "Ether"))]
fn dissect(data: &[u8], link: &str) -> PyResult<PyPkt> {
    Ok(PyPkt {
        inner: CorePacket::dissect(data.to_vec(), proto_by_name(link)?),
        time: 0.0,
        wirelen: 0,
    })
}

#[pyfunction]
fn build_stack(names: Vec<String>) -> PyResult<PyPkt> {
    let mut stack = Vec::with_capacity(names.len());
    for n in &names {
        stack.push(proto_by_name(n)?);
    }
    Ok(PyPkt {
        inner: CorePacket::build(&stack),
        time: 0.0,
        wirelen: 0,
    })
}

/// One entry of a layer's option region: a named option for Rust to encode,
/// or, with no name, bytes to append verbatim. The facade normalises the
/// container shape; resolving the name and laying out the payload is this
/// crate's job.
pub(crate) type OptEntry = (usize, Option<String>, OptArgIn);

struct OptArgIn(OptArg);

impl FromPyObject<'_> for OptArgIn {
    fn extract_bound(ob: &Bound<'_, PyAny>) -> PyResult<Self> {
        Ok(OptArgIn(opt_arg(ob)?))
    }
}

fn opt_arg(ob: &Bound<'_, PyAny>) -> PyResult<OptArg> {
    opt_arg_at(ob, 1)
}

/// A Python sequence can hold itself, and a nested one can be arbitrarily
/// deep, so descending it without a bound overflows the stack — a SIGSEGV the
/// interpreter cannot catch, not a Python exception. The bound is the option
/// crate's, since it is what `num_value`, `push_addrs` and `flat_bytes` then
/// recurse over.
fn opt_arg_at(ob: &Bound<'_, PyAny>, depth: usize) -> PyResult<OptArg> {
    if ob.is_none() {
        return Ok(OptArg::Flag);
    }
    if let Ok(b) = ob.downcast::<PyBytes>() {
        return Ok(OptArg::Bytes(b.as_bytes().to_vec()));
    }
    if let Ok(b) = ob.downcast::<PyByteArray>() {
        return Ok(OptArg::Bytes(b.to_vec()));
    }
    if let Ok(s) = ob.extract::<String>() {
        return Ok(OptArg::Text(s));
    }
    if let Ok(n) = ob.extract::<u64>() {
        return Ok(OptArg::Uint(n));
    }
    if let Ok(seq) = ob.downcast::<PySequence>() {
        if depth >= wiry_core::options::MAX_ARG_DEPTH {
            return Err(PyValueError::new_err(format!(
                "option value nests more than {} deep",
                wiry_core::options::MAX_ARG_DEPTH
            )));
        }
        let n = seq.len()?;
        let mut out = Vec::with_capacity(n.min(1024));
        for i in 0..n {
            out.push(opt_arg_at(&seq.get_item(i)?, depth + 1)?);
        }
        return Ok(OptArg::List(out));
    }
    Err(PyTypeError::new_err(format!(
        "cannot encode option value {}",
        ob.repr()?
    )))
}

pub(crate) fn make_stack(
    names: &[String],
    opts: &[OptEntry],
) -> PyResult<Vec<(ProtoId, Option<Vec<u8>>)>> {
    if names.is_empty() {
        return Err(PyValueError::new_err("empty packet"));
    }
    let mut stack = Vec::with_capacity(names.len());
    for (i, n) in names.iter().enumerate() {
        let id = proto_by_name(n)?;
        let region = option_region(id, i, opts)?;
        stack.push((id, (!region.is_empty()).then_some(region)));
    }
    Ok(stack)
}

/// IPv4's `ihl` and TCP's `dataofs` — the two `set_hlen` writers — count 32-bit
/// words in four bits, so the whole header is at most 15 words. A longer option
/// region would be emitted under a header length taken modulo 16, which is a
/// lie of the same kind `compute::oversize` refuses to tell about IPv4 length.
fn option_region_limit(id: ProtoId) -> Option<usize> {
    let d = proto::desc(id);
    d.set_hlen
        .map(|_| (15 * 4usize).saturating_sub(d.build_len))
}

fn option_region(id: ProtoId, layer: usize, opts: &[OptEntry]) -> PyResult<Vec<u8>> {
    let mut out = Vec::new();
    let mut named = Vec::new();
    for (_, name, arg) in opts.iter().filter(|(l, _, _)| *l == layer) {
        let Some(name) = name else {
            match &arg.0 {
                OptArg::Bytes(b) => out.extend_from_slice(b),
                _ => return Err(PyTypeError::new_err("a raw option region must be bytes")),
            }
            continue;
        };
        let desc = proto::desc(id);
        let table = desc.opt_table.ok_or_else(|| {
            PyValueError::new_err(format!(
                "{} does not take an encodable option list",
                desc.name
            ))
        })?;
        named.push(table.item(name, &arg.0).map_err(PyValueError::new_err)?);
    }
    if !named.is_empty() {
        let table = proto::desc(id)
            .opt_table
            .expect("named items imply a table");
        out.extend_from_slice(&table.encode(&named).map_err(PyValueError::new_err)?);
    }
    if let Some(max) = option_region_limit(id) {
        // `build_with` pads the region to a whole word before writing the
        // header length, so the padding counts against the limit too.
        let padded = out.len().div_ceil(4) * 4;
        if padded > max {
            let d = proto::desc(id);
            return Err(PyValueError::new_err(format!(
                "{} options are {} octets; the header length field holds at most {max}",
                d.name,
                out.len()
            )));
        }
    }
    Ok(out)
}

/// Unconditional fields go first: a conditional field's presence is decided by
/// an unconditional one (ICMP's `type`), which can also lengthen the header.
/// Growing it between the passes is what lets `ICMP(type=13, ts_ori=...)`
/// reach octets the fixed template lacks.
pub(crate) fn apply_all_fields(
    pkt: &mut CorePacket,
    ints: &[(usize, String, u64)],
    strs: &[(usize, String, String)],
    raws: &[(usize, String, Vec<u8>)],
) -> PyResult<()> {
    let (plain_ints, cond_ints): (Vec<_>, Vec<_>) = ints
        .iter()
        .cloned()
        .partition(|(l, n, _)| !is_conditional(pkt, *l, n));
    let (plain_strs, cond_strs): (Vec<_>, Vec<_>) = strs
        .iter()
        .cloned()
        .partition(|(l, n, _)| !is_conditional(pkt, *l, n));
    let (plain_raws, cond_raws): (Vec<_>, Vec<_>) = raws
        .iter()
        .cloned()
        .partition(|(l, n, _)| !is_conditional(pkt, *l, n));
    apply_fields(pkt, &plain_ints, &plain_strs, &plain_raws)?;
    pkt.refit_headers();
    apply_fields(pkt, &cond_ints, &cond_strs, &cond_raws)
}

fn is_conditional(pkt: &CorePacket, layer: usize, name: &str) -> bool {
    pkt.layers()
        .get(layer)
        .and_then(|s| proto::field_of(s.proto, name))
        .is_some_and(|f| f.cond.is_some())
}

fn apply_fields(
    pkt: &mut CorePacket,
    ints: &[(usize, String, u64)],
    strs: &[(usize, String, String)],
    raws: &[(usize, String, Vec<u8>)],
) -> PyResult<()> {
    for (layer, name, v) in ints {
        if !pkt.set_uint(*layer, name, *v) {
            if !pkt.uint_fits(*layer, name, *v) {
                return Err(PyValueError::new_err(format!(
                    "{v} does not fit field {name:?} in layer {layer}"
                )));
            }
            return Err(PyKeyError::new_err(format!(
                "no field {name:?} in layer {layer}"
            )));
        }
    }
    for (layer, name, s) in strs {
        if *layer >= pkt.layers().len() {
            return Err(PyIndexError::new_err("layer out of range"));
        }
        let f = pkt
            .active_field(*layer, name)
            .ok_or_else(|| PyKeyError::new_err(format!("no field {name:?} in layer {layer}")))?;
        match wiry_core::parse::value_for(f, s) {
            Some(wiry_core::parse::ValueBits::Uint(v)) => {
                pkt.set_uint(*layer, name, v);
            }
            Some(wiry_core::parse::ValueBits::Bytes(b)) => {
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

/// One crossing: the facade accumulates the stack and its field assignments in
/// Python and hands the whole thing over at once.
#[pyfunction]
#[pyo3(signature = (names, ints, strs, raws, payload = None, opts = Vec::new()))]
fn build_and_serialize<'py>(
    py: Python<'py>,
    names: Vec<String>,
    ints: Vec<(usize, String, u64)>,
    strs: Vec<(usize, String, String)>,
    raws: Vec<(usize, String, Vec<u8>)>,
    payload: Option<Vec<u8>>,
    opts: Vec<OptEntry>,
) -> PyResult<Bound<'py, PyBytes>> {
    let stack = make_stack(&names, &opts)?;
    let mut pkt = CorePacket::build_with(&stack);
    if let Some(p) = payload {
        let last = stack.len().saturating_sub(1);
        pkt.set_payload(last, &p);
    }
    apply_all_fields(&mut pkt, &ints, &strs, &raws)?;
    pkt.mark_all_dirty();
    if let Some(e) = pkt.oversize() {
        return Err(PyValueError::new_err(e));
    }
    Ok(PyBytes::new_bound(py, pkt.to_bytes()))
}

/// `build_and_serialize`, but returning the packet for further inspection.
#[pyfunction]
#[pyo3(signature = (names, ints, strs, raws, payload = None, opts = Vec::new()))]
fn build_packet(
    names: Vec<String>,
    ints: Vec<(usize, String, u64)>,
    strs: Vec<(usize, String, String)>,
    raws: Vec<(usize, String, Vec<u8>)>,
    payload: Option<Vec<u8>>,
    opts: Vec<OptEntry>,
) -> PyResult<PyPkt> {
    let stack = make_stack(&names, &opts)?;
    let mut pkt = CorePacket::build_with(&stack);
    if let Some(p) = payload {
        let last = stack.len().saturating_sub(1);
        pkt.set_payload(last, &p);
    }
    apply_all_fields(&mut pkt, &ints, &strs, &raws)?;
    pkt.mark_all_dirty();
    Ok(PyPkt {
        inner: pkt,
        time: 0.0,
        wirelen: 0,
    })
}

/// One crossing for the whole fragment list.
#[pyfunction]
fn fragment_frame<'py>(
    py: Python<'py>,
    data: &[u8],
    link: &str,
    fragsize: usize,
) -> PyResult<Bound<'py, PyList>> {
    let id = proto_by_name(link)?;
    let out = PyList::empty_bound(py);
    for f in frag::fragment(data, id, fragsize) {
        out.append(PyBytes::new_bound(py, &f))?;
    }
    Ok(out)
}

/// The list-granularity half of reassembly, for packets that are not backed by
/// a capture buffer. Returns the positions that carried no fragment, the
/// datagrams reassembled and where each one began, and the positions of
/// fragments that never completed.
#[pyfunction]
fn defragment_frames<'py>(
    py: Python<'py>,
    frames: Vec<Vec<u8>>,
    link: &str,
) -> PyResult<(Vec<u32>, Bound<'py, PyList>, Vec<u32>)> {
    let id = proto_by_name(link)?;
    let pieces = py.allow_threads(|| {
        let refs: Vec<&[u8]> = frames.iter().map(|f| f.as_slice()).collect();
        frag::defragment(refs, id)
    });
    let (mut whole, mut missing) = (Vec::new(), Vec::new());
    let done = PyList::empty_bound(py);
    for piece in pieces {
        match piece {
            frag::Piece::Whole(i) => whole.push(i),
            frag::Piece::Incomplete(i) => missing.push(i),
            frag::Piece::Complete(i, f) => done.append((i, PyBytes::new_bound(py, &f)))?,
        }
    }
    Ok((whole, done, missing))
}

#[pyfunction]
fn layer_fields(name: &str) -> PyResult<Vec<&'static str>> {
    let id = proto_by_name(name)?;
    let mut out = proto::all_field_names(id);
    out.extend_from_slice(proto::accessor_names(id));
    Ok(out)
}

/// Least significant first. `None` for any other kind, which is what tells the
/// facade not to wrap the value.
#[pyfunction]
fn flag_names(name: &str, field: &str) -> PyResult<Option<Vec<&'static str>>> {
    let id = proto_by_name(name)?;
    Ok(proto::field_of(id, field)
        .filter(|f| f.kind == FieldKind::Flags)
        .map(|f| f.flags.to_vec()))
}

#[pyfunction]
fn known_layers() -> Vec<&'static str> {
    proto::known_layers()
}

fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

/// name, bit width, kind, integer default, wide default, flag names.
type FieldSpec = (String, u16, String, u64, Option<Vec<u8>>, Vec<String>);

pub(crate) fn kind_name(k: FieldKind) -> &'static str {
    match k {
        FieldKind::Uint => "uint",
        FieldKind::LeUint => "le_uint",
        FieldKind::Ipv4Addr => "ipv4",
        FieldKind::Ipv6Addr => "ipv6",
        FieldKind::MacAddr => "mac",
        FieldKind::Flags => "flags",
        FieldKind::Bytes => "bytes",
        FieldKind::VarBytes => "varbytes",
    }
}

fn kind_of(k: &str) -> PyResult<FieldKind> {
    Ok(match k {
        "uint" => FieldKind::Uint,
        "le_uint" => FieldKind::LeUint,
        "ipv4" => FieldKind::Ipv4Addr,
        "ipv6" => FieldKind::Ipv6Addr,
        "mac" => FieldKind::MacAddr,
        "flags" => FieldKind::Flags,
        "bytes" => FieldKind::Bytes,
        "varbytes" => FieldKind::VarBytes,
        _ => return Err(PyValueError::new_err(format!("unknown field kind {k:?}"))),
    })
}

/// The dissector then executes the layer without calling back into Python.
/// Bit offsets follow declaration order.
#[pyfunction]
fn register_layer(name: String, fields: Vec<FieldSpec>) -> PyResult<u16> {
    let mut descs = Vec::with_capacity(fields.len());
    let mut bit_off = 0u16;
    let last = fields.len().saturating_sub(1);
    for (i, (fname, bit_len, kind, default, default_bytes, flag_names)) in
        fields.into_iter().enumerate()
    {
        let kind = kind_of(&kind)?;
        if kind == FieldKind::VarBytes && i != last {
            return Err(PyValueError::new_err(format!(
                "{name}.{fname} has no width of its own, so it must be the last field"
            )));
        }
        let packed = matches!(kind, FieldKind::Uint | FieldKind::LeUint | FieldKind::Flags);
        if packed && bit_len > 64 {
            return Err(PyValueError::new_err(format!(
                "{name}.{fname} is {bit_len} bits; an integer field holds at most 64"
            )));
        }
        if kind == FieldKind::Flags && flag_names.len() > bit_len as usize {
            return Err(PyValueError::new_err(format!(
                "{name}.{fname} is {bit_len} bits but names {} flags",
                flag_names.len()
            )));
        }
        if kind == FieldKind::LeUint && bit_len / 8 * 8 != bit_len {
            return Err(PyValueError::new_err(format!(
                "{name}.{fname} is little-endian and must be a whole number of bytes"
            )));
        }
        descs.push(FieldDesc {
            name: leak(fname),
            bit_off,
            bit_len,
            kind,
            default,
            flags: Box::leak(
                flag_names
                    .into_iter()
                    .map(leak)
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            ),
            computed: false,
            cond: None,
            default_bytes: default_bytes
                .map(|b| &*Box::leak(b.into_boxed_slice()) as &'static [u8]),
            to_end: false,
        });
        bit_off = bit_off.checked_add(bit_len).ok_or_else(|| {
            PyValueError::new_err(format!("{name} has too many bits to describe"))
        })?;
    }
    let build_len = (bit_off / 8) as usize;
    if build_len * 8 != bit_off as usize {
        return Err(PyValueError::new_err(format!(
            "{name} fields total {bit_off} bits, which is not a whole number of bytes"
        )));
    }
    proto::register(name, descs, build_len)
        .map(|id| id.0)
        .map_err(PyValueError::new_err)
}

/// Makes dissection reach `child` from `parent`, and stacking the two write
/// the values back.
#[pyfunction]
fn bind_layer(
    py: Python<'_>,
    parent: &str,
    child: &str,
    conds: Vec<(String, PyObject)>,
) -> PyResult<()> {
    let p = proto_by_name(parent)?;
    let c = proto_by_name(child)?;
    let mut out = Vec::with_capacity(conds.len());
    for (fname, val) in conds {
        let f = proto::field_of(p, &fname)
            .ok_or_else(|| PyKeyError::new_err(format!("no field {fname:?} on {parent}")))?;
        let v = val.bind(py);
        let n = if let Ok(n) = v.extract::<u64>() {
            n
        } else if let Ok(s) = v.extract::<String>() {
            match wiry_core::parse::value_for(f, &s) {
                Some(wiry_core::parse::ValueBits::Uint(n)) => n,
                Some(wiry_core::parse::ValueBits::Bytes(b)) if b.len() <= 8 => {
                    b.iter().fold(0u64, |acc, x| (acc << 8) | *x as u64)
                }
                _ => {
                    return Err(PyValueError::new_err(format!(
                        "cannot bind {parent}.{fname} to {s:?}"
                    )))
                }
            }
        } else {
            return Err(PyValueError::new_err(format!(
                "unsupported bind value for {parent}.{fname}"
            )));
        };
        out.push((f, n));
    }
    proto::bind(p, c, out).map_err(PyValueError::new_err)
}

#[pymodule]
fn _wiry(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPkt>()?;
    m.add_class::<PyPktList>()?;
    m.add_function(wrap_pyfunction!(read_pcap, m)?)?;
    m.add_class::<writer::PyCaptureWriter>()?;
    m.add_function(wrap_pyfunction!(dissect, m)?)?;
    m.add_function(wrap_pyfunction!(fragment_frame, m)?)?;
    m.add_function(wrap_pyfunction!(defragment_frames, m)?)?;
    m.add_function(wrap_pyfunction!(build_stack, m)?)?;
    m.add_function(wrap_pyfunction!(build_packet, m)?)?;
    m.add_function(wrap_pyfunction!(build_and_serialize, m)?)?;
    m.add_function(wrap_pyfunction!(layer_fields, m)?)?;
    m.add_function(wrap_pyfunction!(flag_names, m)?)?;
    m.add_function(wrap_pyfunction!(known_layers, m)?)?;
    m.add_function(wrap_pyfunction!(register_layer, m)?)?;
    m.add_function(wrap_pyfunction!(bind_layer, m)?)?;
    m.add_class::<template::Template>()?;
    m.add_function(wrap_pyfunction!(template::make_template, m)?)?;
    m.add_function(wrap_pyfunction!(template::rand_value, m)?)?;
    m.add_function(wrap_pyfunction!(template::set_rand_seed, m)?)?;
    m.add_function(wrap_pyfunction!(template::field_specs, m)?)?;
    m.add_function(wrap_pyfunction!(template::corrupt, m)?)?;
    m.add_function(wrap_pyfunction!(capture::capture_available, m)?)?;
    m.add_function(wrap_pyfunction!(capture::capture_check, m)?)?;
    m.add_function(wrap_pyfunction!(capture::list_interfaces, m)?)?;
    m.add_function(wrap_pyfunction!(capture::default_interface, m)?)?;
    m.add_function(wrap_pyfunction!(capture::interface_mac, m)?)?;
    m.add_function(wrap_pyfunction!(live::sniff_live, m)?)?;
    m.add_class::<live::LiveSniffer>()?;
    m.add_function(wrap_pyfunction!(live::send_frames, m)?)?;
    m.add_function(wrap_pyfunction!(live::send_template, m)?)?;
    m.add_function(wrap_pyfunction!(live::send_template_l3, m)?)?;
    m.add_function(wrap_pyfunction!(live::send_datagrams, m)?)?;
    m.add_function(wrap_pyfunction!(live::sr_live, m)?)?;
    m.add_function(wrap_pyfunction!(live::pair_replies, m)?)?;
    m.add(
        "CaptureUnavailable",
        m.py().get_type_bound::<capture::CaptureUnavailable>(),
    )?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(layer: &str, opts: &[(Option<&str>, OptArg)]) -> PyResult<Vec<u8>> {
        let id = proto::by_name(layer).expect("known layer");
        let entries: Vec<OptEntry> = opts
            .iter()
            .map(|(n, a)| (0usize, n.map(str::to_string), OptArgIn(a.clone())))
            .collect();
        option_region(id, 0, &entries)
    }

    #[test]
    fn only_the_four_bit_header_lengths_cap_their_option_region() {
        assert_eq!(option_region_limit(ProtoId::Ipv4), Some(40));
        assert_eq!(option_region_limit(ProtoId::Tcp), Some(40));
        assert_eq!(option_region_limit(ProtoId::Udp), None);
        assert_eq!(option_region_limit(ProtoId::Dhcp), None);
    }

    #[test]
    fn a_raw_option_region_the_header_length_cannot_describe_is_refused() {
        for layer in ["IP", "TCP"] {
            let ok = OptArg::Bytes(vec![1u8; 40]);
            assert!(region(layer, &[(None, ok)]).is_ok(), "{layer} 40");
            // 41 octets pad to 44, which is 11 words and wraps the field to 0.
            let over = OptArg::Bytes(vec![1u8; 41]);
            assert!(region(layer, &[(None, over)]).is_err(), "{layer} 41");
        }
    }

    #[test]
    fn a_named_option_list_is_capped_the_same_way() {
        let nops: Vec<_> = (0..44).map(|_| (Some("NOP"), OptArg::Flag)).collect();
        assert!(region("TCP", &nops).is_err());
        assert!(region("TCP", &nops[..40]).is_ok());
    }

    #[test]
    fn a_protocol_without_a_header_length_field_takes_a_long_region() {
        let long = OptArg::Bytes(vec![0u8; 400]);
        assert!(region("DHCP", &[(None, long)]).is_ok());
    }

    #[test]
    fn a_record_offset_past_four_gibibytes_is_not_truncated() {
        let off = u32::MAX as usize + 4096;
        let index: Vec<Record> = vec![(off, 64, 0, 0, 64)];
        let (a, len, _, _, _) = index[0];
        assert_eq!(a, off);
        assert_eq!(a + len as usize, off + 64);
    }
}
