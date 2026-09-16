# blitzpkt

Fast packet dissection and crafting for Python. Rust core, familiar API.

```python
from blitzpkt import *

pkt = Ether()/IP(dst="10.0.0.1")/TCP(dport=443, flags="S")
pkt.show()

cap = rdpcap("capture.pcap")
print(cap.count_layer(TCP), "TCP packets")
print(cap.field_column(IP, "src")[:5])
```

**Status: early. Working and measured, but not yet at feature parity.** Read
[DEVIATIONS.md](DEVIATIONS.md) before depending on it; it lists every gap.

## Why

Packet dissection in Python is slow for a structural reason: every field of every
layer becomes a Python object, whether or not you read it. Reading two fields out
of a capture costs you the whole object graph.

blitzpkt keeps a packet as one byte buffer plus a small table of
`(protocol, offset, header length)` spans. Dissection walks the layer chain
touching only the bytes needed to find each next header. Field values decode on
demand. A capture stays in Rust; Python objects appear only for packets you
actually index.

## Numbers

Measured against scapy 2.7.0 on `bigFlows.pcap`, a public 256 MB capture of
549,726 real packets from the tcpreplay project. Apple M1 Pro, 8 cores,
macOS 26.6, CPython 3.13.5. Reproduce with `python dev/bench.py <pcap>`. Figures vary a few percent
between runs; these are from the lower of two.

| Workload | scapy | blitzpkt | |
|---|---|---|---|
| Read + 2 fields per packet | 11,141 pkt/s | 222,126 pkt/s | **19.9x** |
| Same, bulk column API | 11,141 pkt/s | 4,362,903 pkt/s | **391.6x** |
| Dissect + re-serialise | 10,655 pkt/s | 625,220 pkt/s | **58.7x** |
| Build + serialise Ether/IP/TCP | 4,571 pkt/s | 142,744 pkt/s | **31.2x** |

Memory, each measured in its own process (`python dev/bench_memory.py <pcap>`):

| | packets held | peak RSS | per packet |
|---|---|---|---|
| scapy | 200,000 | 1,334 MB | 6.67 KB |
| blitzpkt | 549,726 | 339 MB | **0.62 KB** |

blitzpkt read the entire 549,726-packet file and extracted a field from every
packet in 0.24 s. scapy took 18.82 s to do the same for 200,000 of them.

Two honest caveats about these numbers:

- **The 391.6x is a different API, not the same one made faster.** It is
  `field_column`, which does whole-capture work in one crossing of the Rust
  boundary. The like-for-like per-packet loop number is 19.9x. Both are reported
  above and both are in the benchmark script.
- **blitzpkt currently implements fewer protocols than scapy.** Speed and
  coverage are not the same axis. The benchmark only touches Ethernet, IPv4, TCP
  and UDP, which both libraries fully implement, so the comparison is on shared
  ground. See the supported surface below.

## What works

Ethernet, 802.1Q VLAN, ARP, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, DNS, BOOTP and
DHCP. Anything else dissects to `Raw`, exactly as scapy does for protocols it
lacks, so bytes always round-trip unchanged.

Beyond the fixed headers:

- **TCP, IPv4 and DHCP options** parse into a named list: `pkt[TCP].options`
  gives `[('MSS', 1460), ('SAckOK', None), ('WScale', 7)]`.
- **DNS question and record sections**, including name compression, via
  `pkt[DNS].qd` and `pkt[DNS].an`.
- **ICMP's type-dependent fields**: a redirect has `gw`, a timestamp has
  `ts_ori`/`ts_rx`/`ts_tx`, an unreachable has `nexthopmtu`, and asking a message
  for a field its type does not define is an error rather than a wrong answer.
- **pcap and pcapng** both read, dispatched on the file's own magic.

Verified against scapy 2.7.0 on a real 14,261-packet capture: 3,000 of 3,000
layer chains agree, 32,982 of 32,982 field comparisons are equal, and 3,000 of
3,000 packets round-trip byte-identical, and every field name scapy defines for
these layers exists here. 150 Rust and 380 Python tests pass.

Offline only for now. There is no `sniff()` or `send()` yet; see
[DEVIATIONS.md](DEVIATIONS.md) S2 for why and what the plan is.

## Install

```sh
pip install blitzpkt        # not yet published
```

From source:

```sh
git clone https://github.com/blitzpkt/blitzpkt && cd blitzpkt
pip install maturin && maturin develop --release
```

## API

The surface intentionally mirrors what people already type.

```python
from blitzpkt import *

# construct
p = Ether(dst="00:11:22:33:44:55")/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(dport=80)
raw(p)                      # bytes, with checksums and lengths filled in
p.summary()                 # 'Ether / IP / TCP'
p.show()                    # every field

# dissect
q = Ether(some_bytes)
q[IP].ttl                   # 64
q[TCP].flags                # 'S'
TCP in q                    # True
q.haslayer(UDP)             # False

# mutate and re-serialise; checksums recompute
q[TCP].dport = 443
raw(q)

# captures
cap = rdpcap("in.pcap")
len(cap)
cap[0].summary()
for pkt in PcapReader("in.pcap"):
    ...
wrpcap("out.pcap", [p])
```

### Bulk API

The per-packet loop is already much faster, but a Python-level loop still pays a
boundary crossing per packet. When you want one thing across a whole capture,
ask for it in one call:

```python
cap.count_layer(TCP)            # int
cap.field_column(IP, "src")     # one entry per packet, None where absent
cap.times()                     # timestamps
```

These are the APIs that give the 391.6x figure. They agree exactly with the
equivalent Python loop, and the test suite asserts that invariant.

## Relationship to scapy

blitzpkt is an independent, clean-room implementation. It shares no code with
scapy.

scapy is licensed GPL-2.0. Reimplementing an API is settled fair use
(*Google LLC v. Oracle America*, 2021): names, signatures and calling conventions
are interface, not expression. Copying an implementation is a different thing,
and this project does not. Every protocol layout here is written from its RFC or
IANA registry, cited in a comment at the top of each layer module, and
contributors are asked not to read scapy's source while writing the equivalent
layer. See [CONTRIBUTING.md](CONTRIBUTING.md).

That is why blitzpkt can be MIT OR Apache-2.0, which means it can go into
products that GPL would exclude, and the Rust core is usable from Rust.

scapy is a far more capable tool and will remain so. If you need its protocol
breadth, its interactive shell, or live capture, use scapy. Use blitzpkt when
you are moving a lot of packets offline and the dissection cost is what hurts.

## License

MIT OR Apache-2.0, at your option.
