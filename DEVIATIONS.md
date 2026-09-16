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
| E2 | `options` parsing for IPv4/TCP initially returns raw bytes rather than a parsed option list | Round-trips correctly, but `pkt[TCP].options` will not yet be a list of tuples | OPEN |
| E3 | No `fields_desc` user-extensibility from Python yet | This is the feature that makes people choose Scapy over dpkt. Must land before any launch. Tracked as the top priority after core parity. | OPEN |
| E4 | `show()` output formatting matched by eye, not byte-for-byte against Scapy | Cosmetic divergence possible in edge cases | OPEN |
| E5 | pcapng read/write not implemented in v1 (pcap only) | pcapng is common in modern captures; needed before launch | OPEN |
| E6 | No IPv6 extension-header chain walking beyond the common set | Exotic chains fall back to `Raw` | OPEN |

## Correctness debt

| # | Item | Status |
|---|---|---|
| C1 | Checksum recomputation implemented for IPv4/TCP/UDP/ICMP only | OPEN |
| C2 | No fuzzing of the dissector against malformed input yet (`cargo-fuzz` planned) | OPEN |
| C3 | Endianness assumed little-endian host; big-endian hosts untested | OPEN |
