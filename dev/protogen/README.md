# protogen — protocol layers from declarative specs

A dev tool. It is not shipped, not imported at runtime, and not a dependency of
the wheel. It reads one TOML file per protocol from `specs/` and writes the Rust.

```sh
python dev/protogen/protogen.py            # write the tree
python dev/protogen/protogen.py --check    # exit 1 if anything would change
```

## Why this exists

Adding a flat protocol to wiry was, until now, six edits in five files: a new
`layers/<name>.rs` with a `FieldDesc` table, a `header_len`, a `next`, a
`bind_next` and a `DESC`; then a `ProtoId` constant, a `BUILTINS` entry, a
`builtin_desc` arm and a `BUILTIN_COUNT` bump in `proto.rs`; then a line in
`layers/mod.rs`. Five of those six are mechanical. Doing them fifty times by
hand is fifty chances to mistype a bit offset in a file nobody reads twice.

**This does not automate the part that matters.** The field layout is still
hand-authored from the RFC, one field at a time, in the spec. What is automated
is the boilerplate around it.

### It strengthens the citation rule rather than weakening it

`CONTRIBUTING.md` requires every layer to cite the RFC or IANA registry its
layout came from. That was a convention enforced by review. Here `citation` is a
**required key**: a spec without one does not generate, it raises. The citation
is copied into the module's doc comment, so it stays next to the table it
justifies.

The same file used to forbid reading scapy's layer sources. It no longer does —
wiry is GPL-2.0-only and derives from scapy — and the citation is now an accuracy
control rather than a licensing one. A spec whose table also came from scapy
records that in the generated module's provenance block; `NOTICE` has the format.

### It makes CLAUDE.md §8 concretely true

§8 says protocol layers are uniform and independent so separate agents can build
them in parallel, and that shared files are the orchestrator's. Before this, a
contributor adding a layer had to edit `proto.rs` — a shared file — which
serialises everyone. Now a contributor writes **one new file** and touches
nothing anyone else is touching. The shared-file edits are marked regions that
the generator rewrites from the full spec set.

## The spec format

```toml
name = "BFD"              # the layer name as Python sees it
id = "Bfd"                # the ProtoId constant
num = 64                  # its numeric value; append-only, gaps are fine
module = "bfd"            # optional; defaults to the file stem
citation = """            # REQUIRED. Becomes the module doc comment.
RFC 5880 §4.1: a three-bit version, a five-bit diagnostic code, ...
"""
min_len = 24              # shorter input dissects as Raw
header_len = 24           # an integer, or "rest", or "hand"
build_len = 24            # bytes a default construction emits
next = "raw"              # "raw" | "end" | "hand" | a [next] table
content_len = "hand"      # optional; "hand"
parse_options = "hand"    # optional; "hand"
parsed_field = "headers"  # optional; the field a parsed item list answers under

[[fields]]
name = "detect_mult"
off = 16                  # bit offset
len = 8                   # bit length
kind = "uint"             # uint le_uint computed ipv4 ipv6 mac flags bytes
                          # var_bytes var_bytes_to_end
default = 3
when = "is_v2"            # optional: a hand-written fn(&[u8]) -> bool
flags = ["M", "D"]        # required when kind = "flags"; least significant first
default_bytes = [255, 255]
overlaps = true           # only where two fields deliberately share octets

[next]                    # generates `next` and `bind_next` from one table
off = 0
len = 8
fallback = "raw"
[[next.arms]]
value = 0xaa
proto = "Snap"

[group]                   # a repeating payload: "N of these follow"
name = "RIPEntry"         # what one record is called
start = 4                 # octets from the header start to the first record
extent = "rest"           # "count" | "length" | "rest"
count_off = 16            # bits; the field holding the record count
count_len = 16
len_off = 16              # bits; the field holding a byte extent, for "length"
len_len = 16
len_scale = 1             # optional; units the extent counts, default 1
len_covers = 24           # optional; octets of the extent spent before the
                          # first record, default 0
elem_len = 20             # a fixed record width in octets, or:
elem_base = 8             # a base width plus one term per length field
align = 4                 # optional; records padded up to this, default 1
when = "is_v3_report"     # optional fn(&[u8]) -> bool over the header

[[group.terms]]           # base plus the sum of (field x scale), per record
off = 16
len = 16
scale = 4

[[group.fields]]          # the record's own flat field table
name = "addr"
off = 32
kind = "ipv4"

[group.nested]            # one level only; the same keys, minus `nested`
name = "srcaddrs"
start = 8
extent = "count"
count_off = 16
count_len = 16
elem_len = 4
[[group.nested.fields]]
name = "sa"
off = 0
kind = "ipv4"

[provenance]              # GPL-2.0 §2(a) block, where a table came from scapy
source = "scapy/layers/rip.py"
version = "scapy 2.7.0"
changed = ["2026-09-18 — what was taken and what changed"]

[[parents]]               # how dissection reaches this layer
from = "udp_port"         # ethertype ipproto udp_port tcp_port llc_sap icmpv6_type
values = [3784, 3785, 4784]
bind = 3784               # the value stacking writes back; defaults to values[0]
guard = "crate::layers::bfd::looks_like"   # optional fn(&[u8]) -> bool over the payload

[vector]                  # seeds the test module, once
source = "RFC 5880 §4.1 control packet: ..."
bytes = [0x20, 0xc0, 0x03, 0x18]
[vector.fields]
version = 1
```

`[[parents]]` entries across all specs are collected into
`crates/wiry-core/src/layers/dispatch.rs`, one static `match` per selector, plus
the reverse `*_of` functions that stacking uses. Two protocols may claim the same
selector value — NetFlow v5, NetFlow v9 and IPFIX all arrive on UDP 2055 — and
their guards decide in turn.

## Refusals, not guesses

A generator that quietly emits a wrong layout is worse than no generator. These
raise:

- no `citation`, `name`, `id` or `num`
- a duplicate `num` or a duplicate layer name
- a field with no bit length, or a `flags` field naming more flags than its width
  has bits
- a variable-length field that is not last
- two fields sharing octets without a `when` condition or an explicit
  `overlaps = true`
- a field that ends past a **fixed** `header_len` — the flat model cannot place
  it, and the error says to use a hand-written hook instead
- a `[group]` under a fixed `header_len`: the walk is handed the header, so
  records outside it would be invisible. `"rest"` or `"hand"` is required
- a `[group]` whose spec does not also name `parsed_field` and end the field
  table with a `var_bytes` of that name at the group's `start`, so the region is
  in the field table and `raw_options()` still reaches it
- a group with both, or neither, of `elem_len` and `elem_base`; a record field
  that ends past a fixed `elem_len`; a group nested inside a nested one
- a `[provenance]` table missing `source`, `version` or `changed`

## The escape hatch

`DEVIATIONS.md` E1 (type-dependent structure), E2 (option regions) and computed
lengths and checksums are outside the flat `FieldDesc` model. A repeating payload
is not: `[group]` declares one and the generator emits both the `GroupDesc` and
its registration. Where a protocol needs one, the spec says `"hand"` for that
hook and the code goes in the region the generated file marks:

```rust
// protogen:hand begin
fn header_len(hdr: &[u8]) -> usize { ... }
// protogen:hand end
```

The generator reads that region back out of the existing file and splices it into
the new output, so regeneration never destroys it. A region whose markers are
damaged — one of the pair missing, or duplicated — is **refused**, because the
region is the only copy of the code inside it and the spec cannot rebuild it.

The test module has its own `// protogen:tests` region, seeded once from
`[vector]` and hand-owned after that. An **empty** region counts as nothing
written yet and takes the seed again: a cleared `protogen:tests` region comes
back from `[vector]`, while a cleared `protogen:hand` region stays empty,
because a hand-written hook has no seed. Clearing one therefore does not restore
it; it breaks the build at the hook the spec still names, which is the direction
that cannot be missed.

## Idempotence

Re-running on an unchanged spec set produces a byte-identical tree, which is what
lets CI run `--check`. `tests/test_protogen.py` asserts it. The generated Rust is
piped through `rustfmt` before it is compared or written, because CI also runs
`cargo fmt --check` and the two would otherwise contradict each other.
