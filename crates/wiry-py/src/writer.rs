//! Capture-file output. The encoders are wiry-core's; this is the sink, and the
//! single place the two write paths meet, so a whole list and a packet-at-a-time
//! stream cannot disagree about the bytes they produce.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use wiry_core::{pcap, pcapng};

use crate::{PyPktList, Record};

/// Enough for a section header and the interface descriptions that follow it.
const HEAD_PROBE: usize = 64 * 1024;

/// Encoded records go out in chunks rather than one buffer per call, so a bulk
/// write does not hold a second copy of the whole capture.
const CHUNK: usize = 1 << 20;

enum Sink {
    File(BufWriter<File>),
    /// For a gzipped or file-like target: the facade takes the bytes at close.
    Buffer(Vec<u8>),
}

impl Sink {
    fn write_all(&mut self, b: &[u8]) -> std::io::Result<()> {
        match self {
            Sink::File(f) => f.write_all(b),
            Sink::Buffer(v) => {
                v.extend_from_slice(b);
                Ok(())
            }
        }
    }

    fn flush(&mut self, sync: bool) -> std::io::Result<()> {
        if let Sink::File(f) = self {
            f.flush()?;
            if sync {
                f.get_ref().sync_data()?;
            }
        }
        Ok(())
    }
}

#[pyclass(name = "CaptureWriter")]
pub struct PyCaptureWriter {
    sink: Option<Sink>,
    scratch: Vec<u8>,
    pcapng: bool,
    linktype: u32,
    snaplen: u32,
    nanos: bool,
    sync: bool,
}

fn head_of(path: &str) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    File::open(path)?
        .take(HEAD_PROBE as u64)
        .read_to_end(&mut buf)?;
    Ok(buf)
}

/// A pcapng block repeats its total length at both ends, so the last four
/// octets say where the final block began. Both byte orders are tried, since a
/// later section may declare the other and a wrong guess would refuse a sound
/// file; a cut-off file fails under either, needing two words to agree.
fn tail_block_whole(
    len: u64,
    mut word_at: impl FnMut(u64) -> std::io::Result<[u8; 4]>,
) -> std::io::Result<bool> {
    if len < 12 || len & 3 != 0 {
        return Ok(false);
    }
    let last = word_at(len - 4)?;
    for total in [u32::from_le_bytes(last), u32::from_be_bytes(last)] {
        let total = total as u64;
        if total < 12 || total > len || total & 3 != 0 {
            continue;
        }
        let lead = word_at(len - total + 4)?;
        if u32::from_le_bytes(lead) as u64 == total || u32::from_be_bytes(lead) as u64 == total {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The damaged block's length swallows whatever is appended behind it, so both
/// its own records and the new ones vanish from any reader that walks the file.
const CUT_OFF: &str = "the pcapng file ends mid-block, so appending would hide the damage";

/// A frame appended under the wrong link type is unreadable, and silently so.
fn check_appendable(head: &[u8], pcapng: bool, linktype: u32, nanos: bool) -> PyResult<()> {
    if pcapng {
        if !pcapng::is_pcapng(head) {
            return Err(PyValueError::new_err(
                "cannot append pcapng blocks to a file that is not pcapng",
            ));
        }
        let r = pcapng::Reader::new(head).map_err(|e| PyValueError::new_err(e.to_string()))?;
        if r.header.linktype != linktype {
            return Err(PyValueError::new_err(format!(
                "the file describes link type {} and these packets are link type {linktype}",
                r.header.linktype
            )));
        }
        return Ok(());
    }
    if pcapng::is_pcapng(head) {
        return Err(PyValueError::new_err(
            "cannot append pcap records to a pcapng file",
        ));
    }
    let h = pcap::parse_header(head).map_err(|e| PyValueError::new_err(e.to_string()))?;
    if h.linktype != linktype {
        return Err(PyValueError::new_err(format!(
            "the file describes link type {} and these packets are link type {linktype}",
            h.linktype
        )));
    }
    if h.nanos != nanos {
        return Err(PyValueError::new_err(format!(
            "the file timestamps in {}, and this writer in {}",
            if h.nanos {
                "nanoseconds"
            } else {
                "microseconds"
            },
            if nanos { "nanoseconds" } else { "microseconds" },
        )));
    }
    if h.swapped {
        return Err(PyValueError::new_err(
            "cannot append to a big-endian pcap file; wiry writes little-endian records",
        ));
    }
    Ok(())
}

#[pymethods]
impl PyCaptureWriter {
    /// `path` of `None` buffers in memory for the facade to compress or hand to
    /// a file object; `existing` is what such a target already holds.
    #[new]
    #[pyo3(signature = (path, pcapng, linktype, snaplen, nanos, sync, append, existing = None))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        path: Option<String>,
        pcapng: bool,
        linktype: u32,
        snaplen: u32,
        nanos: bool,
        sync: bool,
        append: bool,
        existing: Option<Vec<u8>>,
    ) -> PyResult<Self> {
        if pcapng && linktype > u16::MAX as u32 {
            return Err(PyValueError::new_err(format!(
                "pcapng holds a 16-bit link type, so {linktype} cannot be written"
            )));
        }
        let (mut sink, continuing) = match &path {
            Some(p) => {
                let head = if append {
                    head_of(p).unwrap_or_default()
                } else {
                    Vec::new()
                };
                if head.is_empty() {
                    let f = OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(!append)
                        .open(p)?;
                    (Sink::File(BufWriter::new(f)), false)
                } else {
                    check_appendable(&head, pcapng, linktype, nanos)?;
                    if pcapng {
                        let mut f = File::open(p)?;
                        let len = f.metadata()?.len();
                        let whole = tail_block_whole(len, |off| {
                            f.seek(SeekFrom::Start(off))?;
                            let mut w = [0u8; 4];
                            f.read_exact(&mut w)?;
                            Ok(w)
                        })?;
                        if !whole {
                            return Err(PyValueError::new_err(CUT_OFF));
                        }
                    }
                    let f = OpenOptions::new().append(true).open(p)?;
                    (Sink::File(BufWriter::new(f)), true)
                }
            }
            None => {
                let held = existing.unwrap_or_default();
                let continuing = !held.is_empty();
                if continuing {
                    check_appendable(&held, pcapng, linktype, nanos)?;
                    let whole = pcapng
                        && tail_block_whole(held.len() as u64, |off| {
                            let a = off as usize;
                            Ok(held[a..a + 4].try_into().unwrap())
                        })?;
                    if pcapng && !whole {
                        return Err(PyValueError::new_err(CUT_OFF));
                    }
                }
                (Sink::Buffer(held), continuing)
            }
        };

        let mut head = Vec::new();
        if pcapng {
            // Appending opens a new section rather than reusing an interface
            // described somewhere earlier in the file: its own IDB is the only
            // one these packet blocks can safely name.
            pcapng::write_shb(&mut head);
            pcapng::write_idb(&mut head, linktype, snaplen, nanos);
        } else if !continuing {
            pcap::write_header(&mut head, linktype, snaplen, nanos);
        }
        sink.write_all(&head)?;
        sink.flush(sync)?;

        Ok(Self {
            sink: Some(sink),
            scratch: Vec::new(),
            pcapng,
            linktype,
            snaplen,
            nanos,
            sync,
        })
    }

    /// (bytes, timestamp, wire length). A wire length of 0 means the packet was
    /// not truncated, so its captured length is its length on the wire.
    fn write_records(&mut self, py: Python<'_>, recs: Vec<(Vec<u8>, f64, u32)>) -> PyResult<()> {
        self.ensure_open()?;
        py.allow_threads(|| -> std::io::Result<()> {
            for (data, time, wirelen) in &recs {
                let (sec, frac) = pcap::split_time(*time, self.nanos);
                self.encode(sec, frac, data, *wirelen)?;
            }
            self.finish_batch()
        })?;
        Ok(())
    }

    /// The whole capture in one crossing, straight out of the buffer it was read
    /// into: no Python object is minted for any packet.
    fn write_list(&mut self, py: Python<'_>, list: &Bound<'_, PyPktList>) -> PyResult<()> {
        self.ensure_open()?;
        let list = list.borrow();
        let (buf, index, nanos): (&[u8], &[Record], bool) = list.parts();
        py.allow_threads(|| -> std::io::Result<()> {
            for &(off, len, sec, frac, origlen) in index {
                let data = &buf[off..off + len as usize];
                let frac = pcap::rescale_frac(frac, nanos, self.nanos);
                self.encode(sec, frac, data, origlen)?;
            }
            self.finish_batch()
        })?;
        Ok(())
    }

    fn flush(&mut self, py: Python<'_>) -> PyResult<()> {
        if let Some(sink) = self.sink.as_mut() {
            let sync = self.sync;
            py.allow_threads(|| sink.flush(sync))?;
        }
        Ok(())
    }

    /// Returns the bytes of a buffered target, for the facade to finish writing.
    fn close<'py>(&mut self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyBytes>>> {
        let Some(mut sink) = self.sink.take() else {
            return Ok(None);
        };
        let sync = self.sync;
        py.allow_threads(|| sink.flush(sync))?;
        Ok(match sink {
            Sink::Buffer(v) => Some(PyBytes::new_bound(py, &v)),
            Sink::File(_) => None,
        })
    }

    #[getter]
    fn closed(&self) -> bool {
        self.sink.is_none()
    }

    #[getter]
    fn linktype(&self) -> u32 {
        self.linktype
    }

    #[getter]
    fn snaplen(&self) -> u32 {
        self.snaplen
    }
}

impl PyCaptureWriter {
    fn ensure_open(&self) -> PyResult<()> {
        if self.sink.is_none() {
            return Err(PyValueError::new_err("the capture file is closed"));
        }
        Ok(())
    }

    fn encode(&mut self, sec: u32, frac: u32, data: &[u8], wirelen: u32) -> std::io::Result<()> {
        let origlen = if wirelen == 0 {
            data.len() as u32
        } else {
            wirelen
        };
        if self.pcapng {
            pcapng::write_epb(&mut self.scratch, 0, sec, frac, data, origlen, self.nanos);
        } else {
            pcap::write_record(&mut self.scratch, sec, frac, data, origlen);
        }
        if self.scratch.len() >= CHUNK {
            self.drain()?;
        }
        Ok(())
    }

    fn drain(&mut self) -> std::io::Result<()> {
        if let Some(sink) = self.sink.as_mut() {
            sink.write_all(&self.scratch)?;
        }
        self.scratch.clear();
        Ok(())
    }

    fn finish_batch(&mut self) -> std::io::Result<()> {
        self.drain()?;
        let sync = self.sync;
        match self.sink.as_mut() {
            Some(sink) if sync => sink.flush(sync),
            _ => Ok(()),
        }
    }
}
