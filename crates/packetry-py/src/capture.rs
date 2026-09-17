//! Bindings for the capture crate: availability, interface listing and the
//! error mapping every live entry point shares.

use packetry_capture::{CaptureError, Interface};
use pyo3::exceptions::{PyPermissionError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

// pyo3 0.22's exception boilerplate tests `feature = "gil-refs"`, which is this
// crate's feature set once it declares one of its own.
#[allow(unexpected_cfgs)]
mod exc {
    use pyo3::create_exception;
    use pyo3::exceptions::PyOSError;

    create_exception!(
        _packetry,
        CaptureUnavailable,
        PyOSError,
        "Live capture is not available in this build or on this host."
    );
}

pub(crate) use exc::CaptureUnavailable;

/// A failed library load raises `OSError`, so `except OSError` keeps working;
/// the subclass exists for callers that want to catch only this.
pub(crate) fn to_py_err(e: CaptureError) -> PyErr {
    let msg = e.to_string();
    match e {
        CaptureError::Permission(_) => PyPermissionError::new_err(msg),
        CaptureError::BadFilter(_) => PyValueError::new_err(msg),
        _ => CaptureUnavailable::new_err(msg),
    }
}

#[pyfunction]
pub(crate) fn capture_available() -> bool {
    packetry_capture::available()
}

/// Raises the canonical explanation when this build cannot capture, so every
/// caller reports the same rebuild instruction.
#[pyfunction]
pub(crate) fn capture_check() -> PyResult<()> {
    if packetry_capture::available() {
        Ok(())
    } else {
        Err(to_py_err(CaptureError::Unsupported))
    }
}

fn iface_dict<'py>(py: Python<'py>, i: &Interface) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new_bound(py);
    d.set_item("name", &i.name)?;
    d.set_item("description", i.description.clone())?;
    d.set_item("addresses", i.addresses.clone())?;
    d.set_item("loopback", i.loopback)?;
    Ok(d)
}

#[pyfunction]
pub(crate) fn list_interfaces(py: Python<'_>) -> PyResult<Py<PyList>> {
    let ifs = packetry_capture::list_interfaces().map_err(to_py_err)?;
    let out = PyList::empty_bound(py);
    for i in &ifs {
        out.append(iface_dict(py, i)?)?;
    }
    Ok(out.unbind())
}

#[pyfunction]
pub(crate) fn default_interface() -> PyResult<String> {
    packetry_capture::default_interface().map_err(to_py_err)
}
