//! Packet dissection and construction. Protocol layouts cite the RFC or IANA
//! registry that defines them. This crate is GPL-2.0-only and derives from
//! scapy; see NOTICE for attribution and CONTRIBUTING.md for the procedure.

#![forbid(unsafe_code)]

pub mod answers;
pub mod checksum;
pub mod compute;
pub mod field;
pub mod frag;
pub mod generate;
pub mod layers;
pub mod options;
pub mod packet;
pub mod parse;
pub mod pcap;
pub mod pcapng;
pub mod proto;
pub mod repeat;
pub mod show;
pub mod stream;
mod work;

pub use field::{FieldDesc, FieldKind, FieldValue};
pub use packet::{LayerSpan, Packet};
pub use proto::{ProtoDesc, ProtoId};
