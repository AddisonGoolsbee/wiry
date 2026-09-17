# packetry

Fast packet dissection and crafting for Python. Rust core, familiar API.

```python
from packetry import *

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

packetry keeps a packet as one byte buffer plus a small table of
`(protocol, offset, header length)` spans. Dissection walks the layer chain
touching only the bytes needed to find each next header. Field values decode on
demand. A capture stays in Rust; Python objects appear only for packets you
actually index.

## Numbers

Measured against scapy 2.7.0 on `bigFlows.pcap`, a public 256 MB capture of
549,726 real packets from the tcpreplay project. Apple M1 Pro, 8 cores,
macOS 26.6, CPython 3.13.5. Reproduce with `python dev/bench.py <pcap>`. Figures vary a few percent
between runs; these are from the lower of two.

| Workload | scapy | packetry | |
|---|---|---|---|
| Read + 2 fields per packet | 11,490 pkt/s | 196,892 pkt/s | **17.1x** |
| Same, bulk column API | 11,490 pkt/s | 4,071,061 pkt/s | **354.3x** |
| Dissect + re-serialise | 11,347 pkt/s | 626,076 pkt/s | **55.2x** |
| Build + serialise Ether/IP/TCP | 4,641 pkt/s | 120,557 pkt/s | **26.0x** |

Memory, each measured in its own process (`python dev/bench_memory.py <pcap>`):

| | packets held | peak RSS | per packet |
|---|---|---|---|
| scapy | 200,000 | 1,318 MB | 6.59 KB |
| packetry | 549,726 | 347 MB | **0.63 KB** |

packetry read the entire 549,726-packet file and extracted a field from every
packet in 0.21 s. scapy took 18.23 s to do the same for 200,000 of them.

Three honest caveats about these numbers:

- **The 354.3x is a different API, not the same one made faster.** It is
  `field_column`, which does whole-capture work in one crossing of the Rust
  boundary. The like-for-like per-packet loop number is 17.1x. Both are reported
  above and both are in the benchmark script.
- **These figures fell as correctness work landed.** An earlier build read at
  19.9x and built at 31.2x. Bounds checks, Ethernet-trailer handling and a rich
  flag type cost roughly 10% on the per-packet paths. That trade was worth it:
  the same work fixed length and checksum corruption on 1,568 of 14,261 real
  packets.
- **packetry currently implements fewer protocols than scapy.** Speed and
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
- **Layers you define yourself**, declared in Python and executed in Rust; see
  below.

Verified against scapy 2.7.0 over an entire real capture: all 14,261 layer
chains agree, all 155,501 field comparisons are equal, and all 14,261 packets
round-trip byte-identical. 38 of 38 construction cases are byte-identical too,
and field names match scapy exactly across all eleven layers.

Scapy's own regression suite runs against packetry: 37 pass, 14 fail, 629 skip.
Every skip is a scope boundary such as live capture or a layer we do not
implement; every remaining failure is a feature we do not claim, and each is
listed in [DEVIATIONS.md](DEVIATIONS.md).

228 Rust and 568 Python tests pass. All three crates forbid unsafe code, and
the dissector is covered by seven fuzz targets plus seeded property tests that
run on stable.

`sniff(offline=...)` is complete and needs no privileges, no network and no
optional feature: the whole state machine — `count`, `store`, `prn`, `lfilter`,
`stop_filter`, `timeout`, BPF `filter=` and the `where=` extension — is driven
from a capture file and tested that way. Capturing from an interface, and
`send`/`sr`, need the `live` feature and are still being wired; without it they
raise `CaptureUnavailable` naming the rebuild command. See
[DEVIATIONS.md](DEVIATIONS.md) S2 and E15.

## Install

```sh
pip install packetry        # not yet published
```

From source:

```sh
git clone https://github.com/packetry/packetry && cd packetry
pip install maturin && maturin develop --release
```

## API

The surface intentionally mirrors what people already type.

```python
from packetry import *

# construct
p = Ether(dst="00:11:22:33:44:55")/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(dport=80)
raw(p)                      # bytes, with checksums and lengths filled in
p.summary()                 # 'Ether / IP / TCP'
p.show()                    # every field

# dissect
q = Ether(some_bytes)
q[IP].ttl                   # 64
q[TCP].flags                # <Flag 2 (S)>: equals 2 and 'S', and q[TCP].flags.S
q[0].name                   # 'Ether'; q.getlayer(IP, ttl=64) filters on fields
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

## Your own protocol layers

A layer you declare is data, not code. Python hands the description to Rust once,
at class-definition time, and the same dissector that runs the built-in layers
runs yours — nothing crosses back into Python per packet or per field.

```python
from packetry import Packet, bind_layers, IP, UDP
from packetry.fields import ByteField, BitField, ShortField, IntField, IPField

class MyProto(Packet):
    name = "MyProto"
    fields_desc = [
        ByteField("version", 1),
        BitField("flags", 0, 4),
        BitField("reserved", 0, 4),
        ShortField("length", 0),
        IntField("magic", 0xDEADBEEF),
        IPField("peer", "0.0.0.0"),
    ]

bind_layers(UDP, MyProto, dport=9999)

pkt = IP()/UDP()/MyProto(version=2, peer="10.0.0.1")   # dport set by the binding
back = IP(bytes(pkt))
back[MyProto].peer          # '10.0.0.1'
MyProto in back             # True
```

From there it is an ordinary layer: `/` stacking, `pkt[MyProto]`, `in`, field
get and set, `show()`, `summary()`, `bytes()`, dissection out of a capture, and
the columnar API (`cap.columns([("MyProto", "version")])`).

`packetry.fields` has `ByteField`, `ShortField`, `IntField`, `LongField`, their
`X` and `LE` variants, `BitField`, `FlagsField`, `IPField`, `IP6Field`,
`MACField`, `StrFixedLenField` and `StrField`. Bit offsets come from summing
widths in declaration order, so bit fields may straddle octets as long as the
layer totals a whole number of bytes. See [DEVIATIONS.md](DEVIATIONS.md) E3 for
what a declared layer cannot yet express.

## Captures as columns

This is the part scapy has no equivalent for. A capture already lives in Rust as
one buffer; pulling a few fields out of all of it should not mean building a
Python object per packet.

```python
cap = rdpcap("capture.pcap")

cap.columns([("IP", "src"), ("IP", "dst"), ("TCP", "dport")])
cap.columns([("TCP", "dport")], layer="TCP")
cap.columns(conds=[("TCP", "dport", "==", 443)])
cap.to_dict()
```

One call, one pass, one crossing: each packet is dissected once and every
requested field read from that dissection. Filters are data rather than
callbacks, so selection stays in Rust.

Dataframes, each library imported lazily so none of them is a dependency:

```python
from packetry.columnar import to_polars, to_arrow, to_pandas

df = to_polars(cap)
```

Install with `pip install 'packetry[polars]'`, or `[arrow]`, or `[pandas]`.

Four columns over the same 549,726-packet capture:

| Approach | Rate | |
|---|---|---|
| `columns()`, one pass | 1,946,683 pkt/s | |
| four separate `field_column()` calls | 1,345,818 pkt/s | 1.4x slower |
| Python loop over packets | 179,148 pkt/s | 10.9x slower |
| scapy loop over packets | 10,609 pkt/s | **183x slower** |

Filtering to TCP first reaches 8,779,263 pkt/s, against a 758x slower scapy
equivalent. The honest caveat: the win over four `field_column()` calls is only
1.4x, because once the work is in Rust it is building the Python results that
dominates, not the dissection.

## Relationship to scapy

packetry is an independent, clean-room implementation. It shares no code with
scapy.

scapy is licensed GPL-2.0. Reimplementing an API is settled fair use
(*Google LLC v. Oracle America*, 2021): names, signatures and calling conventions
are interface, not expression. Copying an implementation is a different thing,
and this project does not. Every protocol layout here is written from its RFC or
IANA registry, cited in a comment at the top of each layer module, and
contributors are asked not to read scapy's source while writing the equivalent
layer. See [CONTRIBUTING.md](CONTRIBUTING.md).

That is why packetry can be MIT OR Apache-2.0, which means it can go into
products that GPL would exclude, and the Rust core is usable from Rust.

scapy is a far more capable tool and will remain so. If you need its protocol
breadth, its interactive shell, or live capture, use scapy. Use packetry when
you are moving a lot of packets offline and the dissection cost is what hurts.

## License

MIT OR Apache-2.0, at your option.
