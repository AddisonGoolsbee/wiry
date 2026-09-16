//! STUB: awaiting full implementation. See DEVIATIONS.md.
use crate::field::FieldDesc;
use crate::proto::{Next, ProtoDesc, ProtoId};

pub static FIELDS: &[FieldDesc] = &[FieldDesc::var_bytes("load", 0)];
fn header_len(hdr: &[u8]) -> usize { hdr.len().min(236) }
fn next(_: &[u8]) -> Next { Next::Raw }

pub static DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Bootp, name: "BOOTP", fields: FIELDS,
    min_len: 236, header_len, next, build_len: 236,
    bind_next: None,
};
pub static DHCP_DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Dhcp, name: "DHCP", fields: FIELDS,
    min_len: 4, header_len, next, build_len: 4,
    bind_next: None,
};
