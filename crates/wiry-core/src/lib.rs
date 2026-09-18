//! Clean-room packet dissection and construction. Protocol layouts are derived
//! from RFCs and IANA registries; see CONTRIBUTING.md.

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
pub mod show;
pub mod stream;

pub use field::{FieldDesc, FieldKind, FieldValue};
pub use packet::{LayerSpan, Packet};
pub use proto::{ProtoDesc, ProtoId};
