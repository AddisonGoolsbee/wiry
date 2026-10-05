# Benchmarks and verification

The evidence behind the README's numbers: how they were measured, and what is not
verified.

## Numbers

`bigFlows.pcap` from the tcpreplay project: 368,083,648 bytes, 791,615 packets,
SHA-256 `2b630291cc848c79949e12a54edebe07d20f644747db28899ac4d568c42dc141`,
fetched from `https://s3.amazonaws.com/tcpreplay-pcap-files/bigFlows.pcap`. That
URL has served a different capture under the same name, so the hash, not the
URL, identifies the corpus.

Apple M1 Pro, macOS 26.6, CPython 3.13.5, scapy 2.7.0, dpkt 1.9.8, measured
2026-09-18 on a **release build**. A debug build reads about a third as fast, and
`dev/bench.py` refuses to run on one. Each row is the best of nine: three
invocations of the script, each taking the best of three.

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

**Against dpkt the per-packet loop is 1.7x, not an order of magnitude.** Every
per-packet API pays for one Python object per packet, and that cost sets the
ceiling; dpkt sits near it and so does wiry. Across the three invocations the
ratio ranged from 1.6x to 1.7x. `columns()` amortises the object cost by
returning one list per field for the whole capture, which is where 14.6x comes
from (14.5x to 15.1x across the same three).

The same cost caps the bulk API. Four separate `field_column()` calls dissect the
capture four times yet cost only 1.6x one fused `columns()` pass (687 ms against
423 ms, `python dev/bench_columnar.py <pcap>`). Fusing removes three quarters of
the dissection and well under half the runtime, so most of what remains is
building the Python lists. No amount of Rust moves that floor.

The machine was not idle: load average sat near 5 throughout. Load slows scapy
and dpkt more than wiry, which would flatter wiry's ratios, but both reproduced
their previously published rates to within 3%.

Corrections: the `columns()` row once read 22.3x, measured with
`field_column()`, which reads one field where the other rows read two. Earlier
per-packet figures were higher because they were measured on a different corpus
with a smaller protocol set; bounds checks, Ethernet-trailer handling and
sixty-nine more layers in the dispatch tables each cost something.

## How we know it is right

Over the first 20,000 packets of the corpus above, compared with scapy 2.7.0:
all 20,000 layer chains agree, all 210,910 field comparisons are equal, and
every packet re-serialises byte-identically.

scapy's own regression suite runs against wiry. Over its whole `test/`
directory: **64 pass, 610 skip, 6 fail**; over `regression.uts` alone, 50 pass,
292 skip, 3 fail; over `test/scapy/automaton.uts`, 7 pass, 8 skip, 0 fail. The
skip column, 90% of the suite, is the coverage statement, not the pass count. A
skip is a scope boundary: most often a layer wiry does not implement, a scapy
internal with no equivalent, a call refused by design, or a test whose `~`
marker asks for a Linux host, root or tshark. The harness counts a refusal as a
skip rather than a failure, as `dev/scapy_suite.py` shows. Of the 6 failures, 1
needs Windows, 2 assert by patching a scapy internal wiry lacks, 1 is a
generator difference [DEVIATIONS.md](DEVIATIONS.md) E21 states, and 1 is the
source MAC wiry deliberately does not fill from the live interface (E9). The
sixth is a real wrong answer: `get_if_hwaddr(conf.loopback_name)` raises on
macOS, where scapy answers `00:00:00:00:00:00` for a loopback with no hardware
address. Every other gap is enumerated in DEVIATIONS.

790 Rust and 1,410 Python tests pass; 784 and 1,383 with
`--no-default-features`, which drops live capture.

The live paths were run against a real wire on 2026-09-18, on a Linux veth pair
as root: `dev/live/netns_check.py` passes in full. A frame sent with `sendp`
arrives byte-identical, and `sr1`, `srp1`, `arping`, `getmacbyip`, `srloop` and
`traceroute` all match real replies. The run found two defects no offline test
could reach; [DEVIATIONS.md](DEVIATIONS.md) S2 names them, what is still
unverified (macOS `/dev/bpf`, all of Windows) and what a burst costs.

Four of the five crates set `#![forbid(unsafe_code)]`, including the dissector,
which reads attacker-controlled bytes. The fifth, `wiry-pcap`, is only the FFI:
it `dlopen`s libpcap, calls through function pointers and owns what libpcap
returns. It parses no packets. This constrains wiry's own code and says nothing
about dependencies: PyO3 contains hundreds of unsafe blocks and is compiled in.
The dissector has ten fuzz targets plus seeded property tests that run on stable.

The core and every branch merged for this release were reviewed adversarially
for wrong answers, hostile-input failures and races. Each defect found is named
in the commit that fixed it and has a regression test, so the list lives in
`git log` rather than as a total here that nobody could recount. The worst: a
fragment reassembler that went quadratic on crafted, remotely supplied input; a
TCP reassembler whose sequence reference drifted from its frontier until a
direction went permanently deaf, with no gap recorded and no flag raised; a
session splice that could return about twelve times the capture it was given,
dropped the octets a packet carried beside a framed message, and kept a TCP
checksum that read as valid over bytes it never covered; an append path that
truncated the user's existing capture before writing its replacement; unbounded
gzip decompression, where a 200 KB file expanded to most of a gigabyte of
resident memory; a `sprintf` format parser exponential in unclosed blocks, so a
72-character format never finished; a `columns()` read that returned a DNS
transaction id where a length was asked for; and a code generator that silently
deleted hand-written code inside a damaged marker region.
