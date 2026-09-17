//! Packet dissection and crafting, with a Rust core.
//!
//! This is the crate to depend on from Rust. It re-exports [`wiry_core`], which
//! holds the engine, and with the `live` feature it also exposes
//! [`wiry_capture`] as [`capture`]. The Python package of the same name is
//! built from `wiry-py` and is not part of this crate.
//!
//! ```
//! use wiry::{Packet, ProtoId};
//!
//! let mut p = Packet::build(&[ProtoId::Ether, ProtoId::Ipv4, ProtoId::Tcp]);
//! p.set_uint(2, "dport", 443);
//! let frame = p.to_bytes().to_vec();
//!
//! let back = Packet::dissect(frame, ProtoId::Ether);
//! assert_eq!(back.layers().len(), 3);
//! ```

#![forbid(unsafe_code)]

pub use wiry_core::*;

#[cfg(feature = "live")]
pub use wiry_capture as capture;
