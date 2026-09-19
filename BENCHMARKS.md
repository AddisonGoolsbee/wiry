# Benchmarks and verification

Moved out of README.md to keep it short. This is the evidence behind the
headline numbers, including how they were measured and what is not verified.

## Numbers

`bigFlows.pcap` from the tcpreplay project: 368,083,648 bytes, 791,615 packets,
SHA-256 `2b630291cc848c79949e12a54edebe07d20f644747db28899ac4d568c42dc141`,
fetched from `https://s3.amazonaws.com/tcpreplay-pcap-files/bigFlows.pcap`. That
URL is mutable and has already served a different capture under the same name,
so the hash is what makes "the same corpus" checkable.

Apple M1 Pro, macOS 26.6, CPython 3.13.5, scapy 2.7.0, dpkt 1.9.8, measured
2026-09-18 on a **release build**: a debug one reads about a third as fast, and
`dev/bench.py` refuses to run on one rather than publish that. Each row is the
best of nine: three invocations of the script, each taking the best of three.

```sh
pip install .                  # maturin builds release; maturin develop does not
python dev/bench.py <pcap>
```

| Read `IP.src` and `TCP.dport` from every packet | rate | |
|---|---|---|
| scapy `PcapReader` loop | 11,315 pkt/s | |
| dpkt `Reader` loop | 183,305 pkt/s | |
| wiry per-packet loop | 305,113 pkt/s | **1.7x dpkt** |
| wiry `columns()` | 2,667,208 pkt/s | **14.6x dpkt** |

| Other workloads | scapy | wiry | |
|---|---|---|---|
| Dissect + re-serialise | 11,127 pkt/s | 688,520 pkt/s | **61.9x** |
| Build + serialise Ether/IP/TCP | 4,570 pkt/s | 94,860 pkt/s | **20.8x** |

Memory, each in its own process (`python dev/bench_memory.py <pcap>`):

| | packets held | peak RSS | per packet |
|---|---|---|---|
| scapy | 200,000 | 1,317 MB | 6.59 KB |
| wiry | 791,615 | 487 MB | **0.62 KB** |

Read the per-packet row honestly: **against dpkt it is 1.7x, not an order of
magnitude.** Every per-packet API pays for one Python object per packet and that
cost sets the ceiling. dpkt sits near it and so do we. Across the three
invocations that ratio moved between 1.6x and 1.7x, which is the measurement's
own spread and worth more than a third significant figure. `columns()` amortises
the object cost instead, returning one list per field for the whole capture, and
that is where the 14.6x comes from — 14.5x to 15.1x across the same three.

An earlier version of the last row published 22.3x. It was `field_column()`,
which reads one field, sitting under a header that says two and ratioed against
three rows that read two. The row now does the same work as the rows above it,
and the number is smaller.

The same effect caps the bulk API. Four separate `field_column()` calls dissect
the capture four times, yet cost 1.6x one fused `columns()` pass rather than 4x
(687 ms against 423 ms, `python dev/bench_columnar.py <pcap>`). Fusing the
passes removes three quarters of the dissection and well under half the runtime,
so most of what is left is building the Python lists. That is the floor, and no
amount of Rust moves it.

The machine was not idle: load average sat near 5 throughout, against the idle
machine this project's own rules ask for. The check that it did not distort the
comparison is that scapy and dpkt both reproduced their previously published
rates to within 3%, and load hurts them more than it hurts us, not less.

An earlier version of this table read higher per packet on a different corpus
and a smaller protocol set. Bounds checks, Ethernet-trailer handling and sixty-nine
more layers in the dispatch tables all cost something, and a table measured on a
different capture cannot price them.


## How we know it is right

Over the first 20,000 packets of the corpus above, compared with scapy 2.7.0:
all 20,000 layer chains agree, all 210,910 field comparisons are equal, and
every packet re-serialises byte-identically.

scapy's own regression suite runs against wiry. Over its whole `test/`
directory: **64 pass, 610 skip, 6 fail**; over `regression.uts` alone, 50 pass,
292 skip, 3 fail; over `test/scapy/automaton.uts`, 7 pass, 8 skip, 0 fail. Read
the skip column honestly: it is 90% of the suite, and that ratio is the coverage
statement, not the pass count. A skip is a scope boundary — most often a layer
we do not implement, a scapy internal we have no equivalent for, a call we
refuse by design, or a test whose `~` marker asks for a Linux host, root or
tshark. A refusal counts as a skip rather than a failure, which is a choice the
harness makes and `dev/scapy_suite.py` shows. Of the 6 failures, 1 needs
Windows, 2 assert by patching a scapy internal we do not have, 1 is a generator
difference [DEVIATIONS.md](DEVIATIONS.md) E21 states outright, and 1 is the
source MAC wiry deliberately does not fill from the live interface (E9). The
sixth is a real wrong answer and not a scope boundary:
`get_if_hwaddr(conf.loopback_name)` raises on macOS, where scapy answers
`00:00:00:00:00:00` for a loopback that has no hardware address. Every other gap
is enumerated in DEVIATIONS.

790 Rust and 1,410 Python tests pass; 784 and 1,383 with
`--no-default-features`, which drops live capture.

The live paths were run against a real wire for the first time on
2026-09-18, on a Linux veth pair as root: `dev/live/netns_check.py` passes in
full — a frame sent with `sendp` arrives byte-identical, `sr1`, `srp1`,
`arping`, `getmacbyip`, `srloop` and `traceroute` all match real replies. It
found two defects that no offline test could reach, and
[DEVIATIONS.md](DEVIATIONS.md) S2 names them, what is still unverified (macOS
`/dev/bpf`, all of Windows) and what a burst costs.

Four of the five crates set `#![forbid(unsafe_code)]`, the dissector — the part
that reads attacker-controlled bytes — among them. The fifth is `wiry-pcap`,
which is nothing but the FFI: it `dlopen`s libpcap, calls through function
pointers and owns what libpcap hands back. It parses no packets. That
constrains this code and says nothing about dependencies: PyO3 contains
hundreds of unsafe blocks and is compiled in. The dissector carries ten fuzz
targets plus seeded property tests that run on stable.

The core and every branch merged for this release were reviewed adversarially
for wrong answers, hostile-input failures and races. Each defect a review found
is named in the commit that fixed it and has a regression test, so the list is
in `git log` rather than in a total here: an earlier draft of this paragraph
published a count, and it could not be recounted from the history.
The worst of them: a fragment reassembler that went quadratic on crafted input,
which is remote-controllable; a TCP reassembler whose sequence reference drifted
from the frontier it was named for until a direction went permanently deaf, with
no gap recorded and no flag raised; a session splice that could hand back about
twelve times the capture it was given, that silently dropped the octets a packet
carried alongside a framed message, and whose frames kept a TCP checksum that
reads as valid over bytes it never covered; an append path that truncated the
user's existing capture before writing its replacement; unbounded gzip
decompression, where a
200 KB file expanded to most of a gigabyte of resident memory; a `sprintf`
format parser that was exponential in unclosed blocks, so a 72-character format
never finished; a `columns()` read that answered a DNS transaction id where a
length was asked for; and a code generator that silently deleted hand-written
code inside a damaged marker region. All are fixed, with a regression test each.

