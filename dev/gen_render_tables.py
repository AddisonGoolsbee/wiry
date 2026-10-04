"""Writes crates/wiry-core/src/render_tables.rs from scapy's own field classes:
how each field of each layer wiry shares with scapy prints, which fields hold
nested packets, and each layer's display name. Enumerated names are not here;
they belong to the field table (`FieldDesc::names`).

wiry is GPL-2.0-only and derives from scapy; `NOTICE` records the provenance.
A dev tool, not shipped and not imported at runtime.

Run: python dev/gen_render_tables.py [--check]
"""

import sys
from pathlib import Path

import scapy.all as S  # noqa: F401  (registers every layer)
from scapy.config import conf
from scapy.packet import Packet

import wiry._wiry as _b

conf.verb = 0

OUT = Path(__file__).resolve().parent.parent / "crates/wiry-core/src/render_tables.rs"

# scapy field class -> how its i2repr renders a value. "auto" keeps whatever the
# wiry FieldKind already produces (addresses, flags, plain integers).
KIND = {
    "ByteField": "auto",
    "ShortField": "auto",
    "IntField": "auto",
    "LongField": "auto",
    "BitField": "auto",
    "SignedIntField": "auto",
    "LEShortField": "auto",
    "LEIntField": "auto",
    "LELongField": "auto",
    "ThreeBytesField": "auto",
    "FieldLenField": "auto",
    "BitFieldLenField": "auto",
    "LEFieldLenField": "auto",
    "IPField": "auto",
    "SourceIPField": "auto",
    "DestIPField": "auto",
    "IP6Field": "auto",
    "SourceIP6Field": "auto",
    "DestIP6Field": "auto",
    "MACField": "auto",
    "SourceMACField": "auto",
    "DestMACField": "auto",
    "FlagsField": "auto",
    "_PhantomAutoPadField": "auto",
    "XByteField": "hex",
    "XShortField": "hex",
    "XIntField": "hex",
    "XLongField": "hex",
    "XBitField": "hex",
    "X3BytesField": "hex",
    "XLEIntField": "hex",
    "XLEShortField": "hex",
    "StrField": "bytes",
    "StrLenField": "bytes",
    "StrFixedLenField": "fixed_bytes",
    "XStrField": "hex_bytes",
    "XStrLenField": "hex_bytes",
    "XStrFixedLenField": "hex_bytes",
    "StrNullField": "bytes",
    "_BOOTP_chaddr": "chaddr",
    "BCDFloatField": "bcd",
    "IP6ListField": "ip6_list",
    "OUIField": "hex",
    "UTCTimeField": "utc",
}

# An enumerated field prints its name where it has one; what it prints for a
# value without one is all that is recorded here.
ENUMISH = (
    "ByteEnumField", "ShortEnumField", "IntEnumField", "LongEnumField",
    "BitEnumField", "LEShortEnumField", "LEIntEnumField", "StrEnumField",
    "LoIntEnumField", "_PPPProtoField", "MultiEnumField", "BitMultiEnumField",
)
XENUMISH = ("XShortEnumField", "XByteEnumField", "XIntEnumField")


def classes():
    out = {}

    def walk(cls):
        for sub in cls.__subclasses__():
            out.setdefault(sub.__name__, sub)
            walk(sub)

    walk(Packet)
    return out


def rs_str(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def unwrap(f):
    while hasattr(f, "fld"):
        f = f.fld
    return f


def unset_prints_none(cls, f):
    """Whether scapy shows this field of a layer built with no arguments as
    `None`: a default left for the build to compute, which no `i2h` fills."""
    if f.default is not None:
        return False
    try:
        return f.i2repr(cls(), None) == "None"
    except Exception:
        return False


def main():
    byname = classes()
    entries = {}  # layer -> [(field, rust Repr expression)]
    holds = []  # (layer, field) scapy shows as a nested packet list
    unset_none = []  # (layer, field) an unbuilt layer shows as None
    display = {}

    unknown = set()
    # scapy's DNS record classes are not wiry layers: their sections are parsed
    # out of the DNS payload, but `show()` still prints them under their names.
    for extra in ("DNSQR", "DNSRR"):
        cls = byname.get(extra)
        if cls is not None:
            display[extra] = str(getattr(cls, "_name", None) or extra)
    for layer in _b.known_layers():
        cls = byname.get(layer)
        if cls is None:
            continue
        display[layer] = str(getattr(cls, "_name", None) or layer)
        wiry_fields = {f[0] for f in _b.field_specs(layer)}
        wiry_fields.update(_b.layer_fields(layer))
        rows = []
        for f in cls.fields_desc:
            if f.name not in wiry_fields:
                continue
            if unset_prints_none(cls, f):
                unset_none.append((layer, f.name))
            if getattr(f, "islist", False) and getattr(f, "holds_packets", False):
                holds.append((layer, f.name))
                continue
            name = type(unwrap(f)).__name__
            if name in XENUMISH:
                rows.append((f.name, "Repr::Hex"))
                continue
            if name in ENUMISH:
                continue
            kind = KIND.get(name)
            if kind is None:
                unknown.add(name)
                continue
            if kind != "auto":
                rows.append((f.name, "Repr::%s" % kind.title().replace("_", "")))
        if rows:
            entries[layer] = rows

    overloads = {}  # (parent, child) -> [field]
    known = [l for l in _b.known_layers() if l in byname]
    for child in known:
        for parent_cls, fields in byname[child]._overload_fields.items():
            parent = parent_cls.__name__
            if parent in known and fields:
                overloads[(parent, child)] = sorted(fields)

    if unknown:
        print("unmapped scapy field classes (rendered as-is):",
              ", ".join(sorted(unknown)), file=sys.stderr)

    def pairs(fn, doc, items):
        out.append(doc)
        out.append("pub fn %s(layer: &str, field: &str) -> bool {" % fn)
        out.append("    matches!(")
        out.append("        (layer, field),")
        out.append("        " + "\n            | ".join(
            "(%s, %s)" % (rs_str(a), rs_str(b)) for a, b in sorted(set(items))))
        out.append("    )")
        out.append("}")
        out.append("")

    out = []
    out.append("// SPDX-License-Identifier: GPL-2.0-only")
    out.append("//")
    out.append("// Derived from scapy: scapy/fields.py, scapy/layers/*.py")
    out.append("//   scapy 2.7.0")
    out.append("//   Copyright (C) Philippe Biondi and the scapy contributors")
    out.append("//")
    out.append("// Changed by the wiry authors:")
    out.append("//   2026-10-03 — each field's rendering class, nested-packet fields,")
    out.append("//   unset-is-None fields, overloaded fields and display names, read")
    out.append("//   off scapy's classes for the layers wiry shares")
    out.append("")
    out.append("//! How scapy prints each field. Generated by `dev/gen_render_tables.py`;")
    out.append("//! regenerate rather than edit.")
    out.append("")
    out.append("use crate::render::Repr;")
    out.append("")
    out.append("pub fn repr_of(layer: &str, field: &str) -> Repr {")
    out.append("    match layer {")
    for layer, rows in sorted(entries.items()):
        out.append("        %s => match field {" % rs_str(layer))
        for fname, expr in rows:
            out.append("            %s => %s," % (rs_str(fname), expr))
        out.append("            _ => Repr::Auto,")
        out.append("        },")
    out.append("        _ => Repr::Auto,")
    out.append("    }")
    out.append("}")
    out.append("")
    pairs("holds_packets",
          "/// Fields scapy shows as a nested list of packets rather than as a\n"
          "/// value, which `show()` marks with a backslash line.", holds)
    pairs("unset_is_none",
          "/// Fields a layer still being built shows as `None`: their value is\n"
          "/// computed when it is built.", unset_none)
    out.append("/// scapy's `overload_fields`: what stacking `child` on `parent` sets in")
    out.append("/// `parent`, which a layer being built shows as though it were given.")
    out.append("pub fn overloads(parent: &str, child: &str) -> &'static [&'static str] {")
    out.append("    match (parent, child) {")
    for (a, b), fields in sorted(overloads.items()):
        out.append("        (%s, %s) => &[%s]," % (
            rs_str(a), rs_str(b), ", ".join(rs_str(f) for f in fields)))
    out.append("        _ => &[],")
    out.append("    }")
    out.append("}")
    out.append("")
    out.append("/// scapy's `Packet.name`, which is what `show()` prints and is")
    out.append("/// not always the class name `summary()` prints.")
    out.append("pub fn display_name(layer: &str) -> &str {")
    out.append("    match layer {")
    for layer, name in sorted(display.items()):
        if name != layer:
            out.append("        %s => %s," % (rs_str(layer), rs_str(name)))
    out.append("        other => other,")
    out.append("    }")
    out.append("}")
    out.append("")

    text = "\n".join(out)
    if "--check" in sys.argv:
        if OUT.read_text() != text:
            sys.exit("render_tables.rs is stale; run dev/gen_render_tables.py")
        print("render_tables.rs up to date")
        return
    OUT.write_text(text)
    print("wrote", OUT, "-", len(entries), "layers")


if __name__ == "__main__":
    main()
