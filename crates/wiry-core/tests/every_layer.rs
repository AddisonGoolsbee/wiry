//! Properties every layer must hold, asserted over all of them at once. Sixty
//! of them come from one emission template, so a mistake in that template is a
//! mistake sixty times and a per-module test would find it sixty times too late.

use wiry_core::field::{self, FieldKind, FieldValue};
use wiry_core::packet::Packet;
use wiry_core::proto::{self, desc, ProtoId};

fn layers() -> Vec<ProtoId> {
    let v: Vec<ProtoId> = proto::known_layers()
        .into_iter()
        .filter_map(proto::by_name)
        .collect();
    assert!(v.len() >= 75, "expected every built-in, got {}", v.len());
    v
}

fn max_for(bits: u16) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

/// A default construction must survive a dissect with the same bytes, or the
/// build path and the read path disagree about the layout.
#[test]
fn a_default_build_dissects_to_itself() {
    for id in layers() {
        let mut built = Packet::build(&[id]);
        let bytes = built.to_bytes().to_vec();
        assert_eq!(
            bytes.len(),
            desc(id).build_len,
            "{}: build emitted {} bytes for a build_len of {}",
            desc(id).name,
            bytes.len(),
            desc(id).build_len
        );

        let mut p = Packet::dissect(bytes.clone(), id);
        assert_eq!(
            p.raw_bytes(),
            &bytes[..],
            "{}: dissect changed the buffer",
            desc(id).name
        );
        assert_eq!(
            p.to_bytes(),
            &bytes[..],
            "{}: an untouched packet did not round-trip",
            desc(id).name
        );
    }
}

/// Every declared default must be readable back at the offset the same table
/// says it lives at. A bit offset that is wrong in the emission template is
/// wrong in both directions and cancels out, so this only catches a default
/// that does not fit or a width the writer and reader disagree on — which is
/// exactly what a mis-assembled big-endian store looks like.
#[test]
fn declared_defaults_read_back() {
    for id in layers() {
        let mut built = Packet::build(&[id]);
        let bytes = built.to_bytes().to_vec();
        let p = Packet::dissect(bytes, id);
        let Some(l) = p.find_layer(id) else { continue };
        let hdr = p.header(l).to_vec();
        for f in desc(id).fields {
            if !f.is_active(&hdr) || f.default == 0 || f.default_bytes.is_some() {
                continue;
            }
            if !matches!(f.kind, FieldKind::Uint | FieldKind::LeUint) {
                continue;
            }
            if (f.bit_off as usize + f.bit_len as usize) > hdr.len() * 8 {
                continue;
            }
            assert!(
                field::fits(f, f.default),
                "{}.{}: default {} does not fit {} bits",
                desc(id).name,
                f.name,
                f.default,
                f.bit_len
            );
            assert_eq!(
                p.get(l, f.name),
                Some(FieldValue::Uint(f.default)),
                "{}.{}: default did not read back",
                desc(id).name,
                f.name
            );
        }
    }
}

/// 0 and the field's maximum are accepted and read back exactly; one past the
/// maximum is refused and leaves the buffer alone. A field that silently wraps
/// emits a packet the caller did not ask for.
#[test]
fn boundary_writes_round_trip_and_overflow_is_refused() {
    for id in layers() {
        let name = desc(id).name;
        let mut built = Packet::build(&[id]);
        let base = built.to_bytes().to_vec();

        let probe = Packet::dissect(base.clone(), id);
        let Some(l) = probe.find_layer(id) else {
            continue;
        };
        let hlen = probe.header(l).len();
        let fields: Vec<_> = desc(id)
            .fields
            .iter()
            .filter(|f| matches!(f.kind, FieldKind::Uint | FieldKind::LeUint))
            .filter(|f| f.is_active(probe.header(l)))
            .filter(|f| (f.bit_off as usize + f.bit_len as usize) <= hlen * 8)
            .collect();
        drop(probe);

        for f in fields {
            for want in [0u64, max_for(f.bit_len)] {
                let mut p = Packet::dissect(base.clone(), id);
                let l = p.find_layer(id).unwrap();
                assert!(
                    p.set_uint(l, f.name, want),
                    "{name}.{}: refused {want}, which fits {} bits",
                    f.name,
                    f.bit_len
                );
                let n = p.raw_bytes().len();
                assert_eq!(
                    p.get(l, f.name),
                    Some(FieldValue::Uint(want)),
                    "{name}.{}: {want} did not read back",
                    f.name
                );
                assert_eq!(
                    p.to_bytes().len(),
                    n,
                    "{name}.{}: writing {want} resized the packet",
                    f.name
                );
                let l = p.find_layer(id).unwrap();
                assert_eq!(
                    p.get(l, f.name),
                    Some(FieldValue::Uint(want)),
                    "{name}.{}: {want} did not survive serialisation",
                    f.name
                );
            }

            if f.bit_len >= 64 {
                continue;
            }
            let over = max_for(f.bit_len) + 1;
            let mut p = Packet::dissect(base.clone(), id);
            let l = p.find_layer(id).unwrap();
            let before = p.raw_bytes().to_vec();
            let whole_octets = f.bit_off % 8 == 0 && f.bit_len % 8 == 0;
            if whole_octets {
                assert!(
                    !p.set_uint(l, f.name, over),
                    "{name}.{}: accepted {over}, which needs more than {} bits",
                    f.name,
                    f.bit_len
                );
                assert_eq!(
                    p.raw_bytes(),
                    &before[..],
                    "{name}.{}: a refused write still touched the buffer",
                    f.name
                );
                continue;
            }
            // `field::fits` deliberately lets a sub-octet field mask, matching
            // what a bit field does in the API this follows. What must still
            // hold is that the masked write stays inside its own bits.
            let others: Vec<(&'static str, Option<FieldValue>)> = desc(id)
                .fields
                .iter()
                .filter(|g| g.name != f.name)
                .map(|g| (g.name, p.get(l, g.name)))
                .collect();
            assert!(
                p.set_uint(l, f.name, over),
                "{name}.{}: a sub-octet field refused {over} where it masks",
                f.name
            );
            assert_eq!(
                p.get(l, f.name),
                Some(FieldValue::Uint(over & max_for(f.bit_len))),
                "{name}.{}: masking {over} did not keep the low {} bits",
                f.name,
                f.bit_len
            );
            for (gname, was) in others {
                assert_eq!(
                    p.get(l, gname),
                    was,
                    "{name}.{}: writing {over} changed the neighbouring {gname}",
                    f.name
                );
            }
            assert_eq!(
                p.raw_bytes().len(),
                before.len(),
                "{name}.{}: a masked write resized the packet",
                f.name
            );
        }
    }
}

/// No generated layer recomputes a length or a checksum, so a dissect followed
/// by a serialise must be the identity on every byte — including after the
/// whole stack has been marked dirty, which is what forces the write path to
/// run at all.
#[test]
fn a_dirty_rebuild_is_the_identity() {
    for id in layers() {
        let mut built = Packet::build(&[id]);
        let bytes = built.to_bytes().to_vec();
        let mut p = Packet::dissect(bytes.clone(), id);
        p.mark_all_dirty();
        assert_eq!(
            p.to_bytes(),
            &bytes[..],
            "{}: a dirty rebuild changed the bytes",
            desc(id).name
        );
    }
}

/// Stacking writes the parent's selector, and dissection reads it back. If a
/// generated `bind_next` and the generated `next` disagree — different offset,
/// different width, a value written but not matched — the chain the user built
/// is not the chain that comes back.
#[test]
fn stacking_a_child_produces_a_chain_that_dissects_to_itself() {
    let all = layers();
    let mut checked = 0usize;
    for parent in all.iter().copied() {
        for child in all.iter().copied() {
            if child == parent || child == ProtoId::Raw || child == ProtoId::Padding {
                continue;
            }
            let mut probe = Packet::build(&[parent]);
            let head = probe.to_bytes().to_vec();
            let mut p = Packet::build(&[parent, child]);
            let bytes = p.to_bytes().to_vec();
            // Only a pair the parent actually binds says anything: for the rest
            // the child is indistinguishable from payload and dissecting back
            // to `Raw` is correct.
            let probe2 = Packet::dissect(bytes.clone(), parent);
            if !probe2.has_layer(child) {
                continue;
            }
            // A computed length is the other thing a stacked child changes in
            // the parent header, and it is not a selector.
            assert!(
                bytes.starts_with(&head[..head.len().min(bytes.len())])
                    || desc(parent).bind_next.is_some()
                    || desc(parent).bind_next_bytes.is_some()
                    || desc(parent).fields.iter().any(|f| f.computed),
                "{}/{}:  stacking rewrote the parent header with no binder",
                desc(parent).name,
                desc(child).name
            );
            let mut back = Packet::dissect(bytes.clone(), parent);
            assert_eq!(
                back.to_bytes(),
                &bytes[..],
                "{}/{}: the built chain did not round-trip",
                desc(parent).name,
                desc(child).name
            );
            checked += 1;
        }
    }
    assert!(checked > 40, "only {checked} bound pairs found");
}

/// A header shorter than the layout declares is routine on a snaplen-clipped
/// capture. Every prefix of a default build must read, write and serialise
/// without panicking and without inventing bytes.
#[test]
fn every_prefix_of_every_layer_survives_a_read_write_rebuild() {
    for id in layers() {
        let mut built = Packet::build(&[id]);
        let bytes = built.to_bytes().to_vec();
        for n in 0..=bytes.len() {
            let clipped = bytes[..n].to_vec();
            let mut p = Packet::dissect(clipped.clone(), id);
            if let Some(l) = p.find_layer(id) {
                let names: Vec<&'static str> = desc(id).fields.iter().map(|f| f.name).collect();
                for nm in &names {
                    let _ = p.get(l, nm);
                }
                for nm in &names {
                    p.set_uint(l, nm, 1);
                }
            }
            p.mark_all_dirty();
            let out = p.to_bytes().to_vec();
            assert_eq!(
                out.len(),
                clipped.len(),
                "{} clipped to {n}: rebuild changed the length",
                desc(id).name
            );
        }
    }
}
