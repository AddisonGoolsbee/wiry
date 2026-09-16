//! blitzpkt-core: a fast, clean-room packet dissection and construction engine.
//!
//! Design in one paragraph: a packet is one contiguous byte buffer plus a small
//! table of `(protocol, offset, header length)` spans. Dissection walks the layer
//! chain touching only the bytes needed to find the next header. Field values are
//! decoded on demand from the still-borrowed bytes, so a caller that reads two
//! fields pays for two fields, not for a whole object graph. Mutation writes in
//! place and marks enclosing layers dirty; serialisation recomputes only the
//! lengths and checksums that actually need it.
//!
//! Protocol layouts are written from RFCs and IANA registries. See CONTRIBUTING.md.

pub mod checksum;
pub mod compute;
pub mod field;
pub mod layers;
pub mod options;
pub mod packet;
pub mod parse;
pub mod pcap;
pub mod pcapng;
pub mod proto;
pub mod show;

pub use field::{FieldDesc, FieldKind, FieldValue};
pub use packet::{LayerSpan, Packet};
pub use proto::{ProtoDesc, ProtoId};
