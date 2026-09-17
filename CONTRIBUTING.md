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

## License

Contributions are licensed under MIT, matching the project.
