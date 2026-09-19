use crate::error::CaptureError;
use crate::sink::PacketMeta;
use crate::{Interface, LiveConfig};

/// Uninhabited: with the `live` feature off a handle can never be constructed,
/// so every method below is unreachable rather than merely unimplemented.
pub enum Handle {}

impl Handle {
    pub fn next_into(
        &mut self,
        _scratch: &mut Vec<u8>,
    ) -> Result<Option<PacketMeta>, CaptureError> {
        match *self {}
    }
    pub fn send(&mut self, _data: &[u8]) -> Result<(), CaptureError> {
        match *self {}
    }
    pub fn linktype(&self) -> u32 {
        match *self {}
    }
    pub fn set_filter(&mut self, _expr: &str) -> Result<(), CaptureError> {
        match *self {}
    }
}

pub enum CompiledFilter {}

impl CompiledFilter {
    pub fn matches(&self, _frame: &[u8]) -> bool {
        match *self {}
    }
}

pub fn available() -> bool {
    false
}

pub fn unavailable_reason() -> Option<CaptureError> {
    Some(CaptureError::Unsupported)
}

pub fn backend_version() -> Option<String> {
    None
}

pub fn backend_path() -> Option<String> {
    None
}

pub fn list_interfaces() -> Result<Vec<Interface>, CaptureError> {
    Err(CaptureError::Unsupported)
}

pub fn default_interface() -> Result<String, CaptureError> {
    Err(CaptureError::Unsupported)
}

pub fn open_live(_cfg: &LiveConfig) -> Result<Handle, CaptureError> {
    Err(CaptureError::Unsupported)
}

pub fn compile_filter(
    _linktype: u32,
    _expr: &str,
    _snaplen: u32,
) -> Result<CompiledFilter, CaptureError> {
    Err(CaptureError::Unsupported)
}

pub fn send_l3(_frames: &[Vec<u8>], _count: usize, _inter: f64) -> Result<usize, CaptureError> {
    Err(CaptureError::Unsupported)
}
