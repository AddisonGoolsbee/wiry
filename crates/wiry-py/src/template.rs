//! Templates: a packet whose generator fields multiply it into many.
//!
//! Python describes each generator as data and hands the whole description over
//! once; the product is walked here. A template of 65,536 packets costs one
//! crossing, and an unbounded one is never materialised at all.

use crate::{apply_all_fields, make_stack, OptEntry, PyPkt};
use pyo3::exceptions::{PyIndexError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes, PySequence};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use wiry_core::generate::{Gen, GenVal, Plan, Rng, Slot};
use wiry_core::packet::Packet as CorePacket;
use wiry_core::proto;

/// A spec can nest — a list of ranges, a choice of sequences — and a Python
/// sequence can hold itself, so descending it without a bound overflows the
/// stack, which is a SIGSEGV rather than an exception.
const MAX_SPEC_DEPTH: usize = 8;

/// Caps what one `frames()` or `packets()` call allocates, however large the
/// request.
const MAX_CHUNK: usize = 1 << 16;

/// One process-wide stream, so a seeded run repeats only when the draws happen
/// in the same order: concurrent draws interleave and are not reproducible.
fn with_rng<T>(f: impl FnOnce(&mut Rng) -> T) -> T {
    static RNG: OnceLock<Mutex<Rng>> = OnceLock::new();
    let cell = RNG.get_or_init(|| {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        Mutex::new(Rng::new(now ^ 0x9E37_79B9_7F4A_7C15))
    });
    let mut g = cell.lock().unwrap_or_else(|e| e.into_inner());
    f(&mut g)
}

/// Seeds the generator every volatile value is drawn from, so a fuzz run can be
/// repeated exactly.
#[pyfunction]
pub(crate) fn set_rand_seed(seed: u64) {
    with_rng(|r| *r = Rng::new(seed));
}

fn gen_val(ob: &Bound<'_, PyAny>) -> PyResult<GenVal> {
    if let Ok(b) = ob.downcast::<PyBytes>() {
        return Ok(GenVal::Bytes(b.as_bytes().to_vec()));
    }
    if let Ok(b) = ob.downcast::<PyByteArray>() {
        return Ok(GenVal::Bytes(b.to_vec()));
    }
    if let Ok(s) = ob.extract::<String>() {
        return Ok(GenVal::Text(s));
    }
    if let Ok(n) = ob.extract::<u64>() {
        return Ok(GenVal::Uint(n));
    }
    Err(PyTypeError::new_err(format!(
        "cannot generate field value {}",
        ob.repr()?
    )))
}

fn each<T>(
    ob: &Bound<'_, PyAny>,
    f: impl Fn(&Bound<'_, PyAny>) -> PyResult<T>,
) -> PyResult<Vec<T>> {
    let seq = ob.downcast::<PySequence>()?;
    let n = seq.len()?;
    let mut out = Vec::with_capacity(n.min(4096));
    for i in 0..n {
        out.push(f(&seq.get_item(i)?)?);
    }
    Ok(out)
}

fn spec_to_gen(ob: &Bound<'_, PyAny>, depth: usize) -> PyResult<Gen> {
    if depth >= MAX_SPEC_DEPTH {
        return Err(PyValueError::new_err(format!(
            "a generator nests more than {MAX_SPEC_DEPTH} deep"
        )));
    }
    let seq = ob.downcast::<PySequence>()?;
    let tag: String = seq.get_item(0)?.extract()?;
    Ok(match tag.as_str() {
        "one" => Gen::One(gen_val(&seq.get_item(1)?)?),
        "range" => Gen::Range {
            lo: seq.get_item(1)?.extract()?,
            hi: seq.get_item(2)?.extract()?,
        },
        "addrs" => Gen::Addrs {
            lo: seq.get_item(1)?.extract()?,
            hi: seq.get_item(2)?.extract()?,
            width: seq.get_item(3)?.extract()?,
        },
        "seq" => Gen::Seq(each(&seq.get_item(1)?, |v| spec_to_gen(v, depth + 1))?),
        "rnum" => Gen::RandNum {
            lo: seq.get_item(1)?.extract()?,
            hi: seq.get_item(2)?.extract()?,
        },
        "raddr" => Gen::RandAddr {
            lo: seq.get_item(1)?.extract()?,
            hi: seq.get_item(2)?.extract()?,
            width: seq.get_item(3)?.extract()?,
        },
        "rbytes" => Gen::RandBytes {
            lo: seq.get_item(1)?.extract()?,
            hi: seq.get_item(2)?.extract()?,
            alphabet: seq.get_item(3)?.extract()?,
        },
        "rpick" => Gen::RandPick(each(&seq.get_item(1)?, gen_val)?),
        other => {
            return Err(PyValueError::new_err(format!(
                "unknown generator kind {other:?}"
            )))
        }
    })
}

fn val_to_py(py: Python<'_>, v: GenVal) -> PyObject {
    match v {
        GenVal::Uint(n) => n.into_py(py),
        GenVal::Bytes(b) => PyBytes::new_bound(py, &b).into(),
        GenVal::Text(s) => s.into_py(py),
    }
}

/// Scalar by nature — `int(RandShort())` — so it is not on any bulk path.
#[pyfunction]
pub(crate) fn rand_value(py: Python<'_>, spec: &Bound<'_, PyAny>) -> PyResult<PyObject> {
    let g = spec_to_gen(spec, 0)?;
    Ok(val_to_py(py, with_rng(|r| g.at(0, r))))
}

#[pyclass(name = "Template")]
pub struct Template {
    stack: Vec<(proto::ProtoId, Option<Vec<u8>>)>,
    ints: Vec<(usize, String, u64)>,
    strs: Vec<(usize, String, String)>,
    raws: Vec<(usize, String, Vec<u8>)>,
    payload: Option<Vec<u8>>,
    plan: Plan,
}

impl Template {
    pub(crate) fn realize(&self, index: u128) -> PyResult<CorePacket> {
        let mut ints = self.ints.clone();
        let mut strs = self.strs.clone();
        let mut raws = self.raws.clone();
        with_rng(|rng| {
            for (layer, name, v) in self.plan.values_at(index, rng) {
                match v {
                    GenVal::Uint(n) => ints.push((layer, name.to_string(), n)),
                    GenVal::Text(s) => strs.push((layer, name.to_string(), s)),
                    GenVal::Bytes(b) => raws.push((layer, name.to_string(), b)),
                }
            }
        });
        let mut pkt = CorePacket::build_with(&self.stack);
        if let Some(p) = &self.payload {
            pkt.set_payload(self.stack.len().saturating_sub(1), p);
        }
        apply_all_fields(&mut pkt, &ints, &strs, &raws)?;
        pkt.mark_all_dirty();
        Ok(pkt)
    }

    fn window(&self, start: u128, limit: usize) -> std::ops::Range<u128> {
        let n = self.plan.count();
        let from = start.min(n);
        let to = from.saturating_add(limit.min(MAX_CHUNK) as u128).min(n);
        from..to
    }

    /// Past the product `values_at` would wrap to the start, so an out-of-range
    /// index has to be refused here rather than silently answered.
    fn checked(&self, index: u128) -> PyResult<u128> {
        if index >= self.plan.count() {
            return Err(PyIndexError::new_err(format!(
                "packet {index} is past the {} this template describes",
                self.plan.count()
            )));
        }
        Ok(index)
    }

    pub(crate) fn frame_at(&self, index: u128) -> PyResult<Vec<u8>> {
        let mut pkt = self.realize(index)?;
        if let Some(e) = pkt.oversize() {
            return Err(PyValueError::new_err(e));
        }
        Ok(pkt.to_bytes().to_vec())
    }

    pub(crate) fn total(&self) -> u128 {
        self.plan.count()
    }

    pub(crate) fn raw_frames(&self, start: u128, limit: usize) -> PyResult<Vec<Vec<u8>>> {
        let w = self.window(start, limit);
        let mut out = Vec::with_capacity((w.end - w.start) as usize);
        for i in w {
            out.push(self.frame_at(i)?);
        }
        Ok(out)
    }
}

#[pymethods]
impl Template {
    /// Saturates rather than wrapping: two /8 address fields really are 2^48
    /// packets, and a span wider than `u128` reports `u128::MAX`.
    #[getter]
    fn count(&self) -> u128 {
        self.plan.count()
    }

    fn frames(&self, py: Python<'_>, start: u128, limit: usize) -> PyResult<Vec<Py<PyBytes>>> {
        let raw = py.allow_threads(|| self.raw_frames(start, limit))?;
        Ok(raw
            .into_iter()
            .map(|f| PyBytes::new_bound(py, &f).into())
            .collect())
    }

    fn packets(&self, py: Python<'_>, start: u128, limit: usize) -> PyResult<Vec<PyPkt>> {
        py.allow_threads(|| {
            let w = self.window(start, limit);
            let mut out = Vec::with_capacity((w.end - w.start) as usize);
            for i in w {
                out.push(PyPkt {
                    inner: self.realize(i)?,
                    time: 0.0,
                });
            }
            Ok(out)
        })
    }

    /// A volatile field is drawn afresh, so two calls need not agree.
    fn packet(&self, index: u128) -> PyResult<PyPkt> {
        Ok(PyPkt {
            inner: self.realize(self.checked(index)?)?,
            time: 0.0,
        })
    }

    fn frame(&self, py: Python<'_>, index: u128) -> PyResult<Py<PyBytes>> {
        let f = self.frame_at(self.checked(index)?)?;
        Ok(PyBytes::new_bound(py, &f).into())
    }
}

/// One generator field, as the facade describes it: layer, field, spec.
type GenEntry = (usize, String, PyObject);

/// Takes `build_packet`'s arguments plus the generator fields, in one crossing.
#[allow(clippy::too_many_arguments)]
#[pyfunction]
#[pyo3(signature = (names, ints, strs, raws, payload = None, opts = Vec::new(), gens = Vec::new()))]
pub(crate) fn make_template(
    py: Python<'_>,
    names: Vec<String>,
    ints: Vec<(usize, String, u64)>,
    strs: Vec<(usize, String, String)>,
    raws: Vec<(usize, String, Vec<u8>)>,
    payload: Option<Vec<u8>>,
    opts: Vec<OptEntry>,
    gens: Vec<GenEntry>,
) -> PyResult<Template> {
    let stack = make_stack(&names, &opts)?;
    let mut slots = Vec::with_capacity(gens.len());
    for (layer, name, spec) in gens {
        let id = stack
            .get(layer)
            .map(|(id, _)| *id)
            .ok_or_else(|| PyValueError::new_err("generator on a layer out of range"))?;
        let rank = proto::desc(id)
            .fields
            .iter()
            .position(|f| f.name == name)
            .unwrap_or(0);
        let gen = spec_to_gen(spec.bind(py), 0)?;
        slots.push((Slot { layer, name, gen }, rank));
    }
    Ok(Template {
        stack,
        ints,
        strs,
        raws,
        payload,
        plan: Plan::new(slots),
    })
}

/// Replaces `n` byte positions, or flips `n` bits, drawing from the same
/// generator every volatile value comes from, so a seeded run repeats.
#[pyfunction]
pub(crate) fn corrupt(py: Python<'_>, data: &[u8], n: usize, bits: bool) -> Py<PyBytes> {
    let mut out = data.to_vec();
    if !out.is_empty() {
        with_rng(|rng| {
            for _ in 0..n {
                let at = rng.in_range(0, out.len() as u64 - 1) as usize;
                if bits {
                    out[at] ^= 1 << rng.in_range(0, 7);
                } else {
                    out[at] = rng.next_u64() as u8;
                }
            }
        });
    }
    PyBytes::new_bound(py, &out).into()
}

/// name, bit width, kind, computed, conditional.
type FieldShape = (&'static str, u16, &'static str, bool, bool);

/// What `fuzz()` needs, in one crossing per layer.
#[pyfunction]
pub(crate) fn field_specs(name: &str) -> PyResult<Vec<FieldShape>> {
    let id = crate::proto_by_name(name)?;
    Ok(proto::desc(id)
        .fields
        .iter()
        .map(|f| {
            (
                f.name,
                f.bit_len,
                crate::kind_name(f.kind),
                f.computed,
                f.cond.is_some(),
            )
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiry_core::proto::ProtoId;

    fn template(stack: &[ProtoId], gens: &[(usize, &str, Gen)]) -> Template {
        let slots = gens
            .iter()
            .map(|(layer, name, gen)| {
                let rank = proto::desc(stack[*layer])
                    .fields
                    .iter()
                    .position(|f| f.name == *name)
                    .unwrap_or(0);
                (
                    Slot {
                        layer: *layer,
                        name: (*name).to_string(),
                        gen: gen.clone(),
                    },
                    rank,
                )
            })
            .collect();
        Template {
            stack: stack.iter().map(|id| (*id, None)).collect(),
            ints: Vec::new(),
            strs: Vec::new(),
            raws: Vec::new(),
            payload: None,
            plan: Plan::new(slots),
        }
    }

    #[test]
    fn the_product_is_walked_in_scapys_order() {
        let t = template(
            &[ProtoId::Ipv4, ProtoId::Tcp],
            &[
                (0, "ttl", Gen::Range { lo: 5, hi: 10 }),
                (1, "dport", Gen::Range { lo: 80, hi: 81 }),
            ],
        );
        assert_eq!(t.total(), 12);
        let frames = t.raw_frames(0, 12).expect("built");
        let got: Vec<(u8, u16)> = frames
            .iter()
            .map(|f| (f[8], u16::from_be_bytes([f[22], f[23]])))
            .collect();
        assert_eq!(got[0], (5, 80));
        assert_eq!(got[1], (5, 81));
        assert_eq!(got[2], (6, 80));
        assert_eq!(got[11], (10, 81));
    }

    #[test]
    fn a_chunk_agrees_with_the_packets_it_covers() {
        let t = template(
            &[ProtoId::Ipv4],
            &[(
                0,
                "dst",
                Gen::Addrs {
                    lo: 0x0a00_0000,
                    hi: 0x0a00_0003,
                    width: 4,
                },
            )],
        );
        let bulk = t.raw_frames(0, 4).expect("built");
        for (i, frame) in bulk.iter().enumerate() {
            assert_eq!(*frame, t.frame_at(i as u128).expect("built"));
        }
        assert_eq!(bulk[2][16..20], [10, 0, 0, 2]);
    }

    #[test]
    fn a_window_never_runs_past_the_product() {
        let t = template(&[ProtoId::Ipv4], &[(0, "ttl", Gen::Range { lo: 1, hi: 3 })]);
        assert_eq!(t.raw_frames(0, 100).expect("built").len(), 3);
        assert!(t.raw_frames(3, 10).expect("built").is_empty());
        assert!(t.raw_frames(u128::MAX, 10).expect("built").is_empty());
    }

    #[test]
    fn a_checksum_is_recomputed_for_every_packet_of_a_template() {
        let t = template(
            &[ProtoId::Ipv4],
            &[(0, "ttl", Gen::Range { lo: 1, hi: 64 })],
        );
        for frame in t.raw_frames(0, 64).expect("built") {
            let sum: u32 = frame[..20]
                .chunks(2)
                .map(|c| u32::from(u16::from_be_bytes([c[0], c[1]])))
                .sum();
            assert_eq!((sum & 0xffff) + (sum >> 16), 0xffff);
        }
    }

    #[test]
    fn a_seed_repeats_a_volatile_template() {
        let t = template(
            &[ProtoId::Ipv4],
            &[(0, "id", Gen::RandNum { lo: 0, hi: 65535 })],
        );
        assert_eq!(t.total(), 1);
        set_rand_seed(99);
        let a: Vec<_> = (0..8).map(|_| t.frame_at(0).expect("built")).collect();
        set_rand_seed(99);
        let b: Vec<_> = (0..8).map(|_| t.frame_at(0).expect("built")).collect();
        assert_eq!(a, b);
        assert!(a.windows(2).any(|w| w[0] != w[1]));
    }

    #[test]
    fn an_unbounded_template_is_counted_but_not_built() {
        let t = template(
            &[ProtoId::Ipv4],
            &[
                (
                    0,
                    "src",
                    Gen::Addrs {
                        lo: 0,
                        hi: u32::MAX as u128,
                        width: 4,
                    },
                ),
                (
                    0,
                    "dst",
                    Gen::Addrs {
                        lo: 0,
                        hi: u32::MAX as u128,
                        width: 4,
                    },
                ),
            ],
        );
        assert_eq!(t.total(), 1u128 << 64);
        assert_eq!(t.raw_frames(0, 4).expect("built").len(), 4);
    }
}
