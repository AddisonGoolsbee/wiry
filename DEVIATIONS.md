# Deviations, cut corners, and known gaps

Running log of every simplification made against full Scapy parity. Nothing here is
hidden from users: the README links this file, and the launch benchmark will state
the supported surface explicitly.

Status key: **OPEN** = still a gap · **CLOSED** = resolved, kept for history.

---

## Scope decisions (deliberate, made 2026-09-15)

| # | Decision | Rationale | Status |
|---|---|---|---|
| S1 | Protocol scope limited to Ether, ARP, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, DNS, DHCP/BOOTP, VLAN(802.1Q), Raw, Padding | Scapy registers 1,746 layers on import and 4,160 `Packet` subclasses with contrib. Full parity is multi-person-year. This set covers the overwhelming majority of real scripts. | OPEN |
| S2 | No live capture or injection in v1 (`sniff`, `send`, `sendp`, `sr`, `sr1`, `srp`) | Requires raw sockets, root, and per-OS backends; untestable in CI. Parse/build is where the measured 1000x lives. API shape is reserved so capture is additive, not breaking. | OPEN |
| S3 | Standalone, clean-room, no Scapy import at runtime | Scapy is GPL-2.0-only. Importing it would relicense this project and forfeit both commercial adopters and the Rust crates.io audience. | CLOSED |
| S4 | Unimplemented protocols dissect to `Raw`, exactly as Scapy does for layers it lacks | Preserves correct round-trip bytes for everything, at any depth. | CLOSED |
| S5 | Name `blitzpkt` is provisional and not yet registered on PyPI/crates.io/GitHub | Deliberately not squatting until the project is real. | OPEN |

## Provenance policy (licensing-critical)

See `CONTRIBUTING.md`. Summary: protocol field layouts are written from RFCs and IANA
registries, never transcribed from `scapy/layers/*.py`. Reimplementing an API is
settled fair use (*Google v. Oracle*, 2021); copying field-table source is not.
Golden test vectors come from Wireshark/tshark and hand-built RFC vectors, not from
running Scapy, because a machine-generated corpus derived from GPL code is a grey area.

## Engineering shortcuts

| # | Shortcut | Consequence | Status |
|---|---|---|---|
| E1 | Field model is a static table per protocol; no arbitrary computed fields yet | Scapy's `ConditionalField` / `MultipleTypeField` semantics are only partially expressible | OPEN |
| E2 | IPv4/TCP options are read and written: `pkt[TCP].options` returns a named list, and `TCP(options=[('MSS', 1460)])` encodes one. Raw bytes accepted too, and `raw_options()` returns them | Remaining: SACK blocks are not split into edge pairs, and DHCP options are read-only (no encoder yet) | PARTIAL |
| E3 | No `fields_desc` user-extensibility from Python yet | This is the feature that makes people choose Scapy over dpkt. Must land before any launch. Tracked as the top priority after core parity. | OPEN |
| E4 | `show()` output formatting matched by eye, not byte-for-byte against Scapy | Cosmetic divergence possible in edge cases | OPEN |
| E5 | pcapng **reading** implemented (`pcapng.rs`: SHB, IDB with `if_tsresol`, EPB, SPB, both endiannesses, unknown blocks skipped, trailing-length validated); **writing** not implemented | Modern captures read fine and yield the same `pcap::Record` as classic pcap, so callers need not care which format they got. Still missing: writing pcapng; per-interface link types when one file mixes them (`FileHeader.linktype` reports the first IDB's, though each interface's own `if_tsresol` is honoured per packet); multi-section files with differing link types (endianness and the interface table do reset at a new SHB, the reported link type does not); Name Resolution Blocks; Decryption Secrets Blocks; per-packet options. Resolutions other than 10^-6 and 10^-9 truncate to microseconds, since `Record.ts_frac` has no finer unit | OPEN |
| E6 | No IPv6 extension-header chain walking beyond the common set | Exotic chains fall back to `Raw` | OPEN |
| E7 | DHCP options (RFC 2132) are parsed into a named item list via `Packet::options`; the raw `options` field still exposes the untouched bytes | Per-option lookup works for the common codes (message type, lease time, requested address, masks, routers, name servers, client id, parameter request list). Still missing: option 82 sub-options stay opaque bytes, long-option concatenation across repeated codes (RFC 3396) is not implemented, and options past the first End are discarded rather than read from `sname`/`file` overload (RFC 2131 §4.1, option 52) | OPEN |
| E8 | DNS record sections are now parsed: `dns::parse_records` returns `qd`/`an`/`ns`/`ar` over the whole message, including name compression (RFC 1035 §4.1.4) with bounded pointer following, and decodes RDATA for A, NS, CNAME, SOA, PTR, MX, TXT and AAAA | Remaining: the DNS-over-TCP two-octet length prefix is not stripped, so TCP-carried messages must be de-framed by the caller; EDNS0/OPT pseudo-records (RFC 6891) get no special treatment (no extended rcode, UDP payload size, or option list) and DNSSEC types (DS/RRSIG/NSEC/DNSKEY) fall back to raw RDATA bytes, as does every other unlisted type; names render without a trailing dot and without escaping dots inside a label; the sections are a standalone function, not yet layer fields, so `pkt[DNS].qd` is not exposed from Python, and the layer's payload still dissects as `Raw` so bytes round-trip unchanged | OPEN |
| E9 | Source MAC defaults (`Ether.src`, `ARP.hwsrc`) stay zero instead of being filled from the host interface | Scapy queries the live interface; this build is offline-only (see S2), so constructed frames are deterministic rather than host-dependent. Byte output differs from Scapy for these two fields unless set explicitly | OPEN |

## Correctness debt

| # | Item | Status |
|---|---|---|
| C1 | Checksum recomputation implemented for IPv4/TCP/UDP/ICMP/ICMPv6 only | OPEN |
| C2 | No fuzzing of the dissector against malformed input yet (`cargo-fuzz` planned) | OPEN |
| C3 | Endianness assumed little-endian host; big-endian hosts untested | OPEN |
