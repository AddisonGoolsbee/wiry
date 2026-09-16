//! Opaque payload. Anything the dissector does not recognise lands here, which
//! is how unimplemented protocols still round-trip byte-for-byte.

use crate::field::FieldDesc;
use crate::proto::{Next, ProtoDesc, ProtoId};

pub static FIELDS: &[FieldDesc] = &[FieldDesc::var_bytes("load", 0)];

fn header_len(hdr: &[u8]) -> usize {
    hdr.len()
}

fn next(_: &[u8]) -> Next {
    Next::End
}

pub static DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Raw,
    name: "Raw",
    fields: FIELDS,
    min_len: 0,
    header_len,
    next,
    build_len: 0,
    parse_options: None,
    set_hlen: None,
    bind_next: None,
    bind_next_bytes: None,
};

pub static PADDING_DESC: ProtoDesc = ProtoDesc {
    id: ProtoId::Padding,
    name: "Padding",
    fields: FIELDS,
    min_len: 0,
    header_len,
    next,
    build_len: 0,
    parse_options: None,
    set_hlen: None,
    bind_next: None,
    bind_next_bytes: None,
};
