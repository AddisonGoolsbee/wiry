// SPDX-License-Identifier: GPL-2.0-only
//
// Derived from scapy: scapy/fields.py
//   scapy 2.7.0
//   Copyright (C) Philippe Biondi and the scapy contributors
//
// Changed by the wiry authors:
//   2026-09-18 — the `count_from` / `length_from` / `max_count` design of
//                PacketListField and FieldListField, and FieldLenField's
//                count_of/length_of back-reference, reworked as a static
//                descriptor walked in Rust rather than a per-element Python
//                object.

//! Repeating groups: "N of these follow".
//!
//! `DEVIATIONS.md` E1 records that the flat `FieldDesc` table cannot express a
//! repeating payload, which for RIP, NetFlow, IGMPv3 and OSPF *is* the
//! protocol. This is the construct that can, in the two shapes that occur:
//! a header field giving an element **count** (RFC 3954 NetFlow v5 `count`,
//! RFC 3376 §4.2 `numgrp`) and a header field giving a **byte extent** the
//! elements fill (RFC 2328 §A.3.1 OSPF `len`). A third, elements running to the
//! end of the datagram, is RFC 2453 §3.6 RIP.
//!
//! An element is itself a flat `FieldDesc` table, so the model gains a
//! dimension rather than a second field model, and the result is the named
//! `Item` list `options.rs` already produces — read identically by the
//! per-packet and the columnar path, and never one Python object per element.
//!
//! **Caps.** Element counts and length fields are attacker-controlled, so every
//! walk is bounded three ways and returns what it managed:
//!
//! - `MAX_ELEMENTS` per group, per nesting level: a `count` of 65,535 over a
//!   two-octet body yields at most this many, whatever the field claims.
//! - `MAX_ITEMS` over a whole walk, nested groups included: bounds the total
//!   work, which `MAX_ELEMENTS` alone does not, since each element carries
//!   fields and may carry a nested group of its own.
//! - `MAX_OWNED_BYTES` over a whole walk: bounds what is *copied out* of the
//!   still-borrowed buffer, which is the axis that turned 2.75 MB of DNS into
//!   568 MB before it had a budget.
//!
//! Nesting is one level, structurally, as `OptDesc::sub` is.

use crate::field::{self, FieldDesc, FieldKind, FieldValue};
use crate::options::{Item, ItemValue, OptArg};
use std::borrow::Cow;

pub const MAX_ELEMENTS: usize = 512;
pub const MAX_ITEMS: usize = 8192;
pub const MAX_OWNED_BYTES: usize = 64 * 1024;
/// The region one `encode` may produce, for the same reason the walk is capped.
pub const MAX_REGION_BYTES: usize = 64 * 1024;

/// Where the elements stop. Bit offsets are into the record that encloses the
/// group — the layer header for a top-level group, the element for a nested
/// one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Extent {
    /// A field holds the number of elements.
    Count { bit_off: u16, bit_len: u16 },
    /// A field holds a byte extent. `covers` is how much of that extent the
    /// enclosing record already spent before the first element, which differs
    /// per protocol exactly as `LenRule` does for a TLV length octet.
    Length {
        bit_off: u16,
        bit_len: u16,
        scale: usize,
        covers: usize,
    },
    /// The elements run to the end of the region.
    Rest,
}

/// One addend of a computed element length: a field of the element, scaled.
#[derive(Clone, Copy, Debug)]
pub struct LenTerm {
    pub bit_off: u16,
    pub bit_len: u16,
    pub scale: usize,
}

#[derive(Clone, Copy, Debug)]
pub enum ElemLen {
    Fixed(usize),
    /// RFC 3376 §4.2.4: a group record is eight octets plus four per source
    /// plus four per auxiliary word, so one length field is not enough.
    Computed {
        base: usize,
        terms: &'static [LenTerm],
    },
}

pub struct GroupDesc {
    /// What one element is called. A group whose element has a single field and
    /// no nested group is a list of that field instead, so this names the
    /// region rather than an element — scapy's FieldListField against its
    /// PacketListField, told apart by the table rather than by a flag.
    pub name: &'static str,
    pub fields: &'static [FieldDesc],
    pub elem: ElemLen,
    pub extent: Extent,
    /// Octets from the start of the enclosing record to the first element.
    pub start: usize,
    /// Elements are padded up to this; 1 means no padding.
    pub align: usize,
    /// One level only, as `OptDesc::sub` is: a walk descends exactly once.
    pub nested: Option<&'static GroupDesc>,
    /// Headers that do not carry this group at all (IGMP is one layer for four
    /// message types).
    pub when: Option<fn(&[u8]) -> bool>,
}

impl GroupDesc {
    pub const fn new(
        name: &'static str,
        fields: &'static [FieldDesc],
        elem: ElemLen,
        extent: Extent,
        start: usize,
    ) -> Self {
        Self {
            name,
            fields,
            elem,
            extent,
            start,
            align: 1,
            nested: None,
            when: None,
        }
    }

    pub const fn aligned(mut self, n: usize) -> Self {
        self.align = n;
        self
    }

    pub const fn nesting(mut self, g: &'static GroupDesc) -> Self {
        self.nested = Some(g);
        self
    }

    pub const fn when(mut self, c: fn(&[u8]) -> bool) -> Self {
        self.when = Some(c);
        self
    }

    pub fn applies(&self, rec: &[u8]) -> bool {
        match self.when {
            Some(c) => c(rec),
            None => true,
        }
    }

    /// True where an element is one field and carries nothing nested, so each
    /// element contributes its own value rather than a wrapper.
    fn is_scalar_list(&self) -> bool {
        self.fields.len() == 1 && self.nested.is_none()
    }

    /// Octets an element occupies before padding, read from its own bytes.
    /// Zero stops the walk: an element of no width cannot make progress.
    fn elem_len(&self, e: &[u8]) -> usize {
        match self.elem {
            ElemLen::Fixed(n) => n,
            ElemLen::Computed { base, terms } => terms.iter().fold(base, |a, t| {
                a.saturating_add(
                    (field::read_bits(e, t.bit_off, t.bit_len) as usize).saturating_mul(t.scale),
                )
            }),
        }
    }

    /// The fixed part an element always has, which is what `encode` lays down
    /// before any nested group or padding.
    fn base_len(&self) -> usize {
        match self.elem {
            ElemLen::Fixed(n) => n,
            ElemLen::Computed { base, .. } => base,
        }
    }

    /// The bytes the elements occupy, already cut to what the extent allows.
    fn region<'a>(&self, rec: &'a [u8]) -> &'a [u8] {
        let r = rec.get(self.start..).unwrap_or(&[]);
        match self.extent {
            Extent::Length {
                bit_off,
                bit_len,
                scale,
                covers,
            } => {
                let claimed = (field::read_bits(rec, bit_off, bit_len) as usize)
                    .saturating_mul(scale)
                    .saturating_sub(covers);
                &r[..claimed.min(r.len())]
            }
            _ => r,
        }
    }

    fn wanted(&self, rec: &[u8]) -> Option<usize> {
        match self.extent {
            Extent::Count { bit_off, bit_len } => {
                Some(field::read_bits(rec, bit_off, bit_len) as usize)
            }
            _ => None,
        }
    }
}

/// What one walk may still spend. The two counters bound different axes:
/// `items` the work, `bytes` the memory a caller ends up holding.
struct Budget {
    items: usize,
    bytes: usize,
}

impl Budget {
    fn new() -> Self {
        Self {
            items: MAX_ITEMS,
            bytes: MAX_OWNED_BYTES,
        }
    }

    fn spend_item(&mut self) -> bool {
        if self.items == 0 {
            return false;
        }
        self.items -= 1;
        true
    }

    fn spend_bytes(&mut self, n: usize) -> usize {
        let take = n.min(self.bytes);
        self.bytes -= take;
        take
    }
}

/// The one walk, so the per-packet and the columnar path cannot answer
/// differently. Truncated and over-claimed input stops the walk rather than
/// erroring: a snaplen-clipped capture ends mid-record routinely.
pub fn walk(rec: &[u8], g: &GroupDesc) -> Vec<Item> {
    walk_in(rec, g, &mut Budget::new())
}

fn walk_in(rec: &[u8], g: &GroupDesc, b: &mut Budget) -> Vec<Item> {
    if !g.applies(rec) {
        return Vec::new();
    }
    let region = g.region(rec);
    let want = g.wanted(rec);
    let mut out: Vec<Item> = Vec::new();
    let mut i = 0usize;
    while i < region.len() && out.len() < MAX_ELEMENTS {
        if want.is_some_and(|w| out.len() >= w) || !b.spend_item() {
            break;
        }
        let total = g.elem_len(&region[i..]);
        if total == 0 || i + total > region.len() {
            break;
        }
        let idx = out.len();
        out.push(element(&region[i..i + total], g, idx, b));
        i += total.div_ceil(g.align.max(1)) * g.align.max(1);
    }
    out
}

fn element(e: &[u8], g: &GroupDesc, idx: usize, b: &mut Budget) -> Item {
    let mut vals: Vec<Item> = Vec::with_capacity(g.fields.len());
    for f in g.fields.iter().filter(|f| f.is_active(e)) {
        if !b.spend_item() {
            break;
        }
        vals.push(Item {
            name: Cow::Borrowed(f.name),
            code: 0,
            value: value_of(e, f, b),
        });
    }
    if let Some(n) = g.nested {
        let inner = walk_in(e, n, b);
        b.spend_item();
        vals.push(Item::named(n.name, 0, ItemValue::Items(inner)));
    }
    if g.is_scalar_list() {
        if let Some(mut one) = vals.pop() {
            one.code = idx as u32;
            return one;
        }
    }
    Item {
        name: Cow::Borrowed(g.name),
        code: idx as u32,
        value: ItemValue::Items(vals),
    }
}

/// Addresses read as text, as they do everywhere else a value leaves the
/// engine; only an opaque field costs owned bytes against the budget.
fn value_of(e: &[u8], f: &FieldDesc, b: &mut Budget) -> ItemValue {
    match field::decode(e, f) {
        FieldValue::Uint(v) => ItemValue::Uint(v),
        FieldValue::Flags { bits, .. } => ItemValue::Uint(bits),
        FieldValue::Ipv4(a) => ItemValue::Text(format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])),
        FieldValue::Ipv6(a) => ItemValue::Text(crate::show::render_ipv6(&a)),
        FieldValue::Mac(a) => ItemValue::Text(
            a.iter()
                .map(|x| format!("{x:02x}"))
                .collect::<Vec<_>>()
                .join(":"),
        ),
        FieldValue::Bytes(v) => {
            let n = b.spend_bytes(v.len());
            ItemValue::Bytes(v[..n].to_vec())
        }
    }
}

/// How many octets after `start` the elements actually occupy, which is what a
/// `header_len` hook needs and what `sync` writes back.
pub fn region_len(rec: &[u8], g: &GroupDesc) -> usize {
    if !g.applies(rec) {
        return 0;
    }
    let region = g.region(rec);
    let want = g.wanted(rec);
    let (mut i, mut n) = (0usize, 0usize);
    while i < region.len() && n < MAX_ELEMENTS {
        if want.is_some_and(|w| n >= w) {
            break;
        }
        let total = g.elem_len(&region[i..]);
        if total == 0 || i + total > region.len() {
            break;
        }
        n += 1;
        i += total.div_ceil(g.align.max(1)) * g.align.max(1);
    }
    i
}

/// Rewrite the field the extent reads, so a region that was appended or
/// replaced describes itself. The walk that counts deliberately ignores the
/// stale value it is about to overwrite.
pub fn sync(rec: &mut [u8], g: &GroupDesc) {
    if !g.applies(rec) {
        return;
    }
    let free = GroupDesc {
        extent: Extent::Rest,
        ..copy_of(g)
    };
    let used = region_len(rec, &free);
    match g.extent {
        Extent::Count { bit_off, bit_len } => {
            let mut n = 0usize;
            let mut i = 0usize;
            let region = free.region(rec);
            while i < region.len() && n < MAX_ELEMENTS {
                let total = free.elem_len(&region[i..]);
                if total == 0 || i + total > region.len() {
                    break;
                }
                n += 1;
                i += total.div_ceil(free.align.max(1)) * free.align.max(1);
            }
            field::write_bits(rec, bit_off, bit_len, n as u64);
        }
        Extent::Length {
            bit_off,
            bit_len,
            scale,
            covers,
        } => {
            let v = (used + covers) / scale.max(1);
            field::write_bits(rec, bit_off, bit_len, v as u64);
        }
        Extent::Rest => {}
    }
}

/// `GroupDesc` is not `Copy` only because it is large; every field is.
fn copy_of(g: &GroupDesc) -> GroupDesc {
    GroupDesc {
        name: g.name,
        fields: g.fields,
        elem: g.elem,
        extent: g.extent,
        start: g.start,
        align: g.align,
        nested: g.nested,
        when: g.when,
    }
}

// ---------------------------------------------------------------- write path

/// Resolve a named element the way a caller types it — `("RIPEntry", [("addr",
/// "10.0.0.0"), ("metric", 1)])` — into the same `Item` a walk produces, so the
/// two directions meet on one shape.
pub fn item(g: &GroupDesc, name: &str, arg: &OptArg) -> Result<Item, String> {
    if arg.nests_deeper_than(crate::options::MAX_ARG_DEPTH) {
        return Err(format!(
            "{} element value nests more than {} deep",
            g.name,
            crate::options::MAX_ARG_DEPTH
        ));
    }
    if name != g.name && !g.is_scalar_list() {
        return Err(format!("unknown {} element {name:?}", g.name));
    }
    if g.is_scalar_list() {
        let f = &g.fields[0];
        return Ok(Item {
            name: Cow::Borrowed(f.name),
            code: 0,
            value: field_value(f, arg)?,
        });
    }
    let mut vals = Vec::new();
    let OptArg::List(entries) = arg else {
        return Err(format!("a {} element takes a list of fields", g.name));
    };
    for e in entries {
        let OptArg::List(pair) = e else {
            return Err(format!("a {} field takes a name and a value", g.name));
        };
        let (fname, v) = match pair.as_slice() {
            [OptArg::Text(n), v] => (n.as_str(), v.clone()),
            [OptArg::Text(n), rest @ ..] => (n.as_str(), OptArg::List(rest.to_vec())),
            _ => return Err(format!("a {} field takes a name and a value", g.name)),
        };
        if let Some(n) = g.nested.filter(|n| n.name == fname) {
            let OptArg::List(es) = &v else {
                return Err(format!("{} takes a list", n.name));
            };
            let inner = es
                .iter()
                .map(|x| item(n, n.name, x))
                .collect::<Result<Vec<_>, _>>()?;
            vals.push(Item::named(n.name, 0, ItemValue::Items(inner)));
            continue;
        }
        let f = g
            .fields
            .iter()
            .find(|f| f.name == fname)
            .ok_or_else(|| format!("{} has no field {fname:?}", g.name))?;
        vals.push(Item {
            name: Cow::Borrowed(f.name),
            code: 0,
            value: field_value(f, &v)?,
        });
    }
    Ok(Item {
        name: Cow::Borrowed(g.name),
        code: 0,
        value: ItemValue::Items(vals),
    })
}

fn field_value(f: &FieldDesc, arg: &OptArg) -> Result<ItemValue, String> {
    match arg {
        OptArg::Flag => Ok(ItemValue::Uint(f.default)),
        OptArg::Uint(n) => Ok(ItemValue::Uint(*n)),
        OptArg::Bytes(b) => Ok(ItemValue::Bytes(b.clone())),
        OptArg::Text(s) => Ok(ItemValue::Text(s.clone())),
        OptArg::List(v) => match v.as_slice() {
            [one] => field_value(f, one),
            _ => Err(format!("cannot encode a list into {:?}", f.name)),
        },
    }
}

/// The inverse of `walk`: the region bytes for a list of elements, each padded
/// out to the length its own fields claim so the result re-walks to itself.
pub fn encode(g: &GroupDesc, items: &[Item]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for it in items {
        if out.len() >= MAX_REGION_BYTES {
            return Err(format!(
                "{} region is longer than {MAX_REGION_BYTES} octets",
                g.name
            ));
        }
        out.extend_from_slice(&encode_one(g, it)?);
    }
    Ok(out)
}

fn encode_one(g: &GroupDesc, it: &Item) -> Result<Vec<u8>, String> {
    let mut e = vec![0u8; g.base_len()];
    for f in g.fields {
        if f.default != 0 {
            field::write_bits(&mut e, f.bit_off, f.bit_len, field::wire_uint(f, f.default));
        }
        if let Some(d) = f.default_bytes {
            put_bytes(&mut e, f, d);
        }
    }
    let vals: &[Item] = match (&it.value, g.is_scalar_list()) {
        (ItemValue::Items(v), false) => v,
        (_, true) => std::slice::from_ref(it),
        _ => return Err(format!("a {} element takes a list of fields", g.name)),
    };
    let mut tail = Vec::new();
    for v in vals {
        if let Some(n) = g.nested.filter(|n| n.name == v.name) {
            let ItemValue::Items(inner) = &v.value else {
                return Err(format!("{} takes a list", n.name));
            };
            tail = encode(n, inner)?;
            continue;
        }
        let f = g
            .fields
            .iter()
            .find(|f| f.name == v.name)
            .ok_or_else(|| format!("{} has no field {:?}", g.name, v.name))?;
        write_value(&mut e, f, &v.value)?;
    }
    if let Some(n) = g.nested {
        e.extend_from_slice(&tail);
        sync(&mut e, n);
    }
    // A term the caller did not back with bytes (auxiliary data) still has to
    // be paid for, or the element would not re-walk to its own length.
    let want = g.elem_len(&e);
    if want > e.len() {
        if want > MAX_REGION_BYTES {
            return Err(format!("{} element claims {want} octets", g.name));
        }
        e.resize(want, 0);
    }
    let pad = e.len().div_ceil(g.align.max(1)) * g.align.max(1);
    e.resize(pad, 0);
    Ok(e)
}

fn write_value(e: &mut [u8], f: &FieldDesc, v: &ItemValue) -> Result<(), String> {
    match v {
        ItemValue::Uint(n) => {
            field::write_bits(e, f.bit_off, f.bit_len, field::wire_uint(f, *n));
            Ok(())
        }
        ItemValue::Bytes(b) => {
            put_bytes(e, f, b);
            Ok(())
        }
        ItemValue::Text(s) => match f.kind {
            FieldKind::Ipv4Addr => {
                let a = crate::parse::ipv4(s).ok_or_else(|| format!("{s:?} is not IPv4"))?;
                put_bytes(e, f, &a);
                Ok(())
            }
            FieldKind::Ipv6Addr => {
                let a = crate::parse::ipv6(s).ok_or_else(|| format!("{s:?} is not IPv6"))?;
                put_bytes(e, f, &a);
                Ok(())
            }
            FieldKind::MacAddr => {
                let a = crate::parse::mac(s).ok_or_else(|| format!("{s:?} is not a MAC"))?;
                put_bytes(e, f, &a);
                Ok(())
            }
            FieldKind::Flags => {
                let bits = crate::parse::flags(s, f.flags)
                    .ok_or_else(|| format!("cannot encode {s:?} into {:?}", f.name))?;
                field::write_bits(e, f.bit_off, f.bit_len, bits);
                Ok(())
            }
            _ => {
                let n = s
                    .parse::<u64>()
                    .map_err(|_| format!("cannot encode {s:?} into {:?}", f.name))?;
                field::write_bits(e, f.bit_off, f.bit_len, field::wire_uint(f, n));
                Ok(())
            }
        },
        _ => Err(format!("cannot encode {:?}", f.name)),
    }
}

fn put_bytes(e: &mut [u8], f: &FieldDesc, b: &[u8]) {
    let a = (f.bit_off / 8) as usize;
    let want = if f.kind == FieldKind::VarBytes {
        b.len()
    } else {
        (f.bit_len / 8) as usize
    };
    let n = b.len().min(want).min(e.len().saturating_sub(a));
    e[a..a + n].copy_from_slice(&b[..n]);
}

#[cfg(test)]
mod tests {
    use super::*;

    static PAIR: &[FieldDesc] = &[
        FieldDesc::uint("a", 0, 16, 0),
        FieldDesc::uint("b", 16, 16, 0),
    ];

    static COUNTED: GroupDesc = GroupDesc::new(
        "P",
        PAIR,
        ElemLen::Fixed(4),
        Extent::Count {
            bit_off: 0,
            bit_len: 16,
        },
        2,
    );

    static RESTED: GroupDesc = GroupDesc::new("P", PAIR, ElemLen::Fixed(4), Extent::Rest, 0);

    static LENGTHED: GroupDesc = GroupDesc::new(
        "P",
        PAIR,
        ElemLen::Fixed(4),
        Extent::Length {
            bit_off: 0,
            bit_len: 16,
            scale: 1,
            covers: 2,
        },
        2,
    );

    static ADDR: &[FieldDesc] = &[FieldDesc::ipv4("sa", 0, 0)];

    static VAR_FIELDS: &[FieldDesc] = &[
        FieldDesc::uint("rtype", 0, 8, 0),
        FieldDesc::uint("n", 8, 8, 0),
    ];

    static SOURCES: GroupDesc = GroupDesc::new(
        "srcs",
        ADDR,
        ElemLen::Fixed(4),
        Extent::Count {
            bit_off: 8,
            bit_len: 8,
        },
        2,
    );

    static VAR: GroupDesc = GroupDesc::new(
        "R",
        VAR_FIELDS,
        ElemLen::Computed {
            base: 2,
            terms: &[LenTerm {
                bit_off: 8,
                bit_len: 8,
                scale: 4,
            }],
        },
        Extent::Rest,
        0,
    )
    .nesting(&SOURCES);

    fn names(items: &[Item]) -> Vec<&str> {
        items.iter().map(|i| i.name.as_ref()).collect()
    }

    fn uints(it: &Item) -> Vec<u64> {
        let ItemValue::Items(v) = &it.value else {
            panic!("not a record")
        };
        v.iter()
            .filter_map(|i| match i.value {
                ItemValue::Uint(n) => Some(n),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_count_field_stops_the_walk() {
        let data = [0u8, 2, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6];
        let got = walk(&data, &COUNTED);
        assert_eq!(got.len(), 2);
        assert_eq!(uints(&got[0]), vec![1, 2]);
        assert_eq!(uints(&got[1]), vec![3, 4]);
    }

    #[test]
    fn a_count_larger_than_the_region_yields_what_fits() {
        let data = [0xffu8, 0xff, 0, 1, 0, 2];
        assert_eq!(walk(&data, &COUNTED).len(), 1);
    }

    #[test]
    fn a_length_field_stops_the_walk_before_trailing_padding() {
        // Claims six octets, of which two are the count field itself, so one
        // element; the four zero octets after it are frame padding.
        let data = [0u8, 6, 0, 1, 0, 2, 0, 0, 0, 0];
        let got = walk(&data, &LENGTHED);
        assert_eq!(got.len(), 1);
        assert_eq!(uints(&got[0]), vec![1, 2]);
    }

    #[test]
    fn a_length_field_past_the_buffer_is_clamped() {
        let data = [0xffu8, 0xff, 0, 1, 0, 2];
        assert_eq!(walk(&data, &LENGTHED).len(), 1);
    }

    #[test]
    fn elements_fill_the_region_when_nothing_bounds_them() {
        let data = [0u8, 1, 0, 2, 0, 3, 0, 4];
        assert_eq!(walk(&data, &RESTED).len(), 2);
    }

    #[test]
    fn a_partial_trailing_element_is_dropped() {
        let data = [0u8, 1, 0, 2, 0, 3];
        assert_eq!(walk(&data, &RESTED).len(), 1);
    }

    #[test]
    fn truncation_at_every_length_returns_rather_than_panicking() {
        let full = [0u8, 3, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6];
        for n in 0..full.len() {
            for g in [&COUNTED, &RESTED, &LENGTHED] {
                let _ = walk(&full[..n], g);
            }
        }
    }

    #[test]
    fn a_computed_length_carries_a_nested_scalar_list() {
        let data = [
            1u8, 2, 10, 0, 0, 1, 10, 0, 0, 2, // one record, two sources
            2, 0, // a second record with none
        ];
        let got = walk(&data, &VAR);
        assert_eq!(got.len(), 2);
        let ItemValue::Items(first) = &got[0].value else {
            panic!()
        };
        assert_eq!(names(first), vec!["rtype", "n", "srcs"]);
        let ItemValue::Items(srcs) = &first[2].value else {
            panic!()
        };
        // One field per element and nothing nested, so each source is its own
        // value rather than a one-field record.
        assert_eq!(names(srcs), vec!["sa", "sa"]);
        assert_eq!(srcs[0].value, ItemValue::Text("10.0.0.1".into()));
        assert_eq!(srcs[1].value, ItemValue::Text("10.0.0.2".into()));
    }

    #[test]
    fn a_zero_width_element_stops_rather_than_spinning() {
        static ZERO: GroupDesc = GroupDesc::new(
            "Z",
            VAR_FIELDS,
            ElemLen::Computed {
                base: 0,
                terms: &[],
            },
            Extent::Rest,
            0,
        );
        assert!(walk(&[0u8; 64], &ZERO).is_empty());
    }

    /// The shape the caps exist for: a claimed count far past anything the
    /// bytes can back must not allocate for the claim.
    #[test]
    fn the_element_cap_bounds_a_huge_region() {
        let data = vec![0u8; MAX_ELEMENTS * 8];
        assert_eq!(walk(&data, &RESTED).len(), MAX_ELEMENTS);
    }

    /// The element cap alone does not bound the work, because a nested group
    /// multiplies it: 512 records of 20 sources each is past the item budget.
    #[test]
    fn the_item_cap_bounds_the_total_work_across_nesting() {
        let mut data = Vec::new();
        for _ in 0..MAX_ELEMENTS {
            data.extend_from_slice(&[1u8, 20]);
            data.extend(std::iter::repeat(0u8).take(80));
        }
        let items = count(&walk(&data, &VAR));
        assert!(items <= MAX_ITEMS, "{items} items");
        assert!(items > MAX_ITEMS / 2, "the budget was never approached");
    }

    fn count(items: &[Item]) -> usize {
        items
            .iter()
            .map(|i| match &i.value {
                ItemValue::Items(v) => 1 + count(v),
                _ => 1,
            })
            .sum()
    }

    #[test]
    fn the_byte_cap_bounds_what_is_copied_out() {
        static BLOB: &[FieldDesc] = &[FieldDesc::bytes("blob", 0, 8 * 512)];
        static BLOBS: GroupDesc = GroupDesc::new("B", BLOB, ElemLen::Fixed(512), Extent::Rest, 0);
        let data = vec![0xaau8; 512 * 400];
        let got = walk(&data, &BLOBS);
        let held: usize = got
            .iter()
            .map(|i| match &i.value {
                ItemValue::Bytes(b) => b.len(),
                _ => 0,
            })
            .sum();
        assert!(held <= MAX_OWNED_BYTES, "held {held}");
    }

    #[test]
    fn a_group_its_header_does_not_carry_reads_empty() {
        static NEVER: GroupDesc = GroupDesc::new("P", PAIR, ElemLen::Fixed(4), Extent::Rest, 0)
            .when(|h| h.first() == Some(&9));
        assert!(walk(&[0u8, 1, 0, 2], &NEVER).is_empty());
        assert!(!walk(&[9u8, 1, 0, 2], &NEVER).is_empty());
    }

    #[test]
    fn padding_rounds_each_element_up() {
        static PADDED: GroupDesc =
            GroupDesc::new("P", PAIR, ElemLen::Fixed(3), Extent::Rest, 0).aligned(4);
        let data = [0u8, 1, 9, 0, 0, 2, 9, 0];
        let got = walk(&data, &PADDED);
        assert_eq!(got.len(), 2);
        assert_eq!(uints(&got[1])[0], 2);
    }

    #[test]
    fn what_a_walk_produced_encodes_back_to_the_same_bytes() {
        let data = [0u8, 2, 0, 1, 0, 2, 0, 3, 0, 4];
        let items = walk(&data, &COUNTED);
        assert_eq!(encode(&COUNTED, &items).unwrap(), &data[2..]);
    }

    #[test]
    fn a_nested_group_round_trips_and_its_count_is_rewritten() {
        let data = [1u8, 2, 10, 0, 0, 1, 10, 0, 0, 2, 2, 0];
        let items = walk(&data, &VAR);
        let back = encode(&VAR, &items).unwrap();
        assert_eq!(back, &data[..]);
        assert_eq!(walk(&back, &VAR), items);
    }

    #[test]
    fn a_named_element_encodes_from_the_shape_a_caller_types() {
        let arg = OptArg::List(vec![
            OptArg::List(vec![OptArg::Text("a".into()), OptArg::Uint(7)]),
            OptArg::List(vec![OptArg::Text("b".into()), OptArg::Uint(9)]),
        ]);
        let it = item(&COUNTED, "P", &arg).unwrap();
        assert_eq!(encode(&COUNTED, &[it]).unwrap(), vec![0, 7, 0, 9]);
    }

    #[test]
    fn an_unknown_element_or_field_is_refused() {
        let arg = OptArg::List(vec![OptArg::List(vec![
            OptArg::Text("nope".into()),
            OptArg::Uint(1),
        ])]);
        assert!(item(&COUNTED, "P", &arg).is_err());
        assert!(item(&COUNTED, "Q", &OptArg::List(vec![])).is_err());
    }

    #[test]
    fn a_scalar_list_takes_its_value_directly() {
        let it = item(&SOURCES, "srcs", &OptArg::Text("10.0.0.9".into())).unwrap();
        assert_eq!(encode(&SOURCES, &[it]).unwrap(), vec![10, 0, 0, 9]);
    }

    #[test]
    fn sync_writes_the_count_a_region_actually_holds() {
        let mut data = [0u8, 0, 0, 1, 0, 2, 0, 3, 0, 4];
        sync(&mut data, &COUNTED);
        assert_eq!(u16::from_be_bytes([data[0], data[1]]), 2);
    }

    #[test]
    fn sync_writes_the_extent_a_region_actually_fills() {
        let mut data = [0u8, 0, 0, 1, 0, 2, 0, 3, 0, 4];
        sync(&mut data, &LENGTHED);
        assert_eq!(u16::from_be_bytes([data[0], data[1]]), 10);
    }

    #[test]
    fn region_len_reports_what_the_walk_consumed() {
        let data = [0u8, 2, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6];
        assert_eq!(region_len(&data, &COUNTED), 8);
    }
}
