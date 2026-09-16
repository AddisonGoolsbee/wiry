//! STUB: awaiting full implementation. See DEVIATIONS.md.
use crate::field::FieldDesc;
use crate::proto::{Next, ProtoDesc, ProtoId};

pub static FIELDS: &[FieldDesc] = &[FieldDesc::var_bytes("load", 0)];
fn header_len(hdr: &[u8]) -> usize { hdr.len().min(40) }
fn next(_: &[u8]) -> Next { Next::Raw }

pub static DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Ipv6,
    name: "IPv6",
    fields: FIELDS,
    min_len: 40,
    header_len,
    next,
    build_len: 40,
    bind_next: None,
};
