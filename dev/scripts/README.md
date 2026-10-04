# dev/scripts

Idiomatic scapy programs, written from the public API in the shapes people
actually use: read a capture and summarise it, filter and count, craft and
display a packet, follow a stream, scan a subnet, trace a route, build a query,
pull hosts out of HTTP.

`dev/script_parity.py` runs each one under `scapy.all` and under `wiry`, a
statement at a time, and diffs printed output, every name bound, and any
exception. So a script here:

- takes its names from the ambient namespace and imports nothing from scapy;
- reads `PCAP` (a capture scapy writes before either run), `WORKDIR`, and
  `REAL_PCAP` (the first 200 packets of `--pcap`; a script naming it is
  skipped without one), all injected by the harness;
- touches no network and no clock, so that a difference between the two runs
  means a difference between the two libraries.
