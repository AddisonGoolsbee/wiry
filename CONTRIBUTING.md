# Contributing to wiry

## Provenance policy (read this before writing any protocol layer)

wiry is a **clean-room** implementation. It is API-compatible with Scapy and
shares no code with it.

Scapy is licensed **GPL-2.0-only**. Reimplementing its *API* is settled fair use
(*Google LLC v. Oracle America, Inc.*, 594 U.S. ___ (2021)): names, signatures, and
calling conventions are interface, not expression. Copying its *implementation* is
not, and would relicense this entire project as GPLv2.

Therefore, when adding or modifying a protocol layer:

**Do**
- Derive field layouts, widths, and offsets from the RFC or IANA registry. Cite the
  RFC and section in a comment at the top of the layer module.
- Match Scapy's public field *names* (`sport`, `dport`, `chksum`, `ttl`, ...) and
  default values. Names are interface.
- Build test vectors from RFC examples, Wireshark/tshark output, or public pcaps.

**Do not**
- Open `scapy/layers/*.py` or `scapy/fields.py` while writing the equivalent layer.
- Transcribe, translate, or paraphrase Scapy's `fields_desc` tables, enum
  dictionaries, or `guess_payload_class` logic.
- Generate golden test vectors by running Scapy. A corpus mechanically derived from
  GPL code is a grey area we do not need to enter; Wireshark is BSD-licensed and is
  a better oracle anyway.

If you are unsure whether something is interface or expression, ask in the issue
before writing code.

## Adding a protocol layer

Do not hand-write the Rust. A flat protocol is one TOML file in
`dev/protogen/specs/`, and the generator writes the layer module, the `ProtoId`,
the registration and the dispatch:

```sh
$EDITOR dev/protogen/specs/myproto.toml
python dev/protogen/protogen.py
```

That is the whole workflow, and it touches **no shared file**, so two people
adding layers at the same time do not conflict.

It also makes the policy above a build error rather than a review comment:
`citation` is a **required key**, and a spec without one does not generate. What
the generator does *not* do is read the RFC for you — the field table is still
written out by hand, one offset and width at a time, from the specification you
cite. `dev/protogen/README.md` has the spec format, the full list of things the
generator refuses to guess at, and the marked hand-written region that carries
the protocols the flat field model cannot express on its own.

## License

Contributions are licensed under MIT, matching the project.
