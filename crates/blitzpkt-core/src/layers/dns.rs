//! STUB: awaiting full implementation. See DEVIATIONS.md.
use crate::field::FieldDesc;
use crate::proto::{Next, ProtoDesc, ProtoId};

pub static FIELDS: &[FieldDesc] = &[FieldDesc::var_bytes("load", 0)];
fn header_len(hdr: &[u8]) -> usize { hdr.len().min(12) }
fn next(_: &[u8]) -> Next { Next::Raw }

pub static DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Dns,
    name: "DNS",
    fields: FIELDS,
    min_len: 12,
    header_len,
    next,
    build_len: 12,
    bind_next: None,
};
