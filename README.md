# wiry

Packet dissection and crafting for Python, with scapy's API and a Rust core.
MIT licensed.

```python
from wiry import rdpcap

cap = rdpcap("capture.pcap")
cap.columns([("IP", "src"), ("IP", "dst"), ("TCP", "dport")])
```

Those two lines read a 256 MB capture off disk and pull three fields out of all
549,726 packets in 295 ms, without building a Python object for a single one of
them.

**wiry implements 29 protocols. scapy registers 1,746.** If yours is not
Ethernet, 802.1Q, ARP, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, DNS, BOOTP/DHCP,
Loopback or Linux cooked capture, it dissects to `Raw` and round-trips unchanged,
and you get bytes rather than fields.

The rest are encapsulations, because losing one of those loses every layer under
it rather than one leaf: the four IPv6 extension headers (hop-by-hop, routing,
fragment, destination options), GRE, VXLAN, Geneve, IP-in-IP and 6in4, MPLS,
PPPoE with PPP, GTP-U and ERSPAN. A tunnelled packet dissects through to its
inner transport, tunnels nest, and `columns()` reaches inside them.
`DEVIATIONS.md` E6 states exactly where each of those stops.

The method surface is narrower too. `show2`, `sprintf`, `fragment`, `json` and
`command` are absent. Most of what else scapy's `Packet` carries is its own
internal machinery, `do_build`, `post_dissect`, `self_build` and the rest, which
exists because scapy assembles an object graph per packet. wiry does not, so it
has no equivalent and needs none.

That is the trade. Everything below assumes you already know it.

## Numbers

`bigFlows.pcap`, a public 256 MB capture of 549,726 real packets from the
tcpreplay project. Apple M1 Pro, macOS 26.6, CPython 3.13.5, scapy 2.7.0,
dpkt 1.9.8. Best of three. Reproduce with `python dev/bench.py <pcap>`.

| Read 2 fields from every packet | rate | |
|---|---|---|
| scapy `PcapReader` loop | 9,942 pkt/s | |
| dpkt `Reader` loop | 169,009 pkt/s | |
| wiry per-packet loop | 335,549 pkt/s | **2.0x dpkt** |
| wiry `columns()` | 4,026,073 pkt/s | **23.8x dpkt** |

| Other workloads | scapy | wiry | |
|---|---|---|---|
| Dissect + re-serialise | 9,446 pkt/s | 808,850 pkt/s | **85.6x** |
| Build + serialise Ether/IP/TCP | 3,939 pkt/s | 102,924 pkt/s | **26.1x** |

Memory, each in its own process (`python dev/bench_memory.py <pcap>`):

| | packets held | peak RSS | per packet |
|---|---|---|---|
| scapy | 200,000 | 1,317 MB | 6.59 KB |
| wiry | 549,726 | 344 MB | **0.63 KB** |

Read the per-packet row honestly: **against dpkt it is 2.0x, not an
order of magnitude.** Every per-packet API pays for one Python object per packet
and that cost sets the ceiling. dpkt sits near it and so do we. `columns()`
amortises the cost instead, returning one list per field for the whole capture,
and that is where the 23.8x comes from.

The same effect caps the bulk API. Four separate `field_column()` calls dissect
the capture four times, yet cost 1.7x one fused `columns()` pass rather than 4x.
Fusing the passes removes three quarters of the dissection and well under half
the runtime, so most of what is left is building the Python lists. That is the
floor, and no amount of Rust moves it.

These figures fell about 10% as correctness work landed. Bounds checks and
Ethernet-trailer handling cost that much, and the same work fixed length and
checksum corruption on 1,568 of 14,261 real packets.

## Crafting

dpkt cannot build a packet from field defaults. wiry can, 26.1x faster than
scapy, and 38 of 38 enumerated construction cases come out byte-identical to
scapy's bytes. Source MACs are pinned on both sides for that comparison, because
scapy fills them from the live interface at build time and wiry deliberately does
not, so that `bytes(Ether())` does not depend on the host.

```python
from wiry import *

p = Ether(dst="00:11:22:33:44:55")/IP(dst="10.0.0.2")/TCP(dport=80, flags="S")
raw(p)                      # checksums and lengths filled in
p[TCP].dport = 443          # mutate; checksums recompute
p.command()                 # the expression that rebuilds it, byte for byte
```

`fragment(pkt, 1480)` splits a datagram per RFC 791 §3.2 and `defragment(cap)`
puts one back together, over a whole capture in a single crossing. Reassembly
buffers attacker-controlled bytes, so its bounds and its overlap rule are
stated in [DEVIATIONS.md](DEVIATIONS.md) E18 rather than left to be discovered.

Capture and injection work too: `sniff`, `send`, `sendp`, `sr`, `sr1`, `srp`,
`srp1` and `AsyncSniffer`, with scapy's arguments and semantics — and the tools
built on them: `traceroute`, `arping`, `srloop`, `srploop`, `getmacbyip` and
`get_if_hwaddr`. Two limits, both real.
They need the `live` cargo feature, which is **off in the first release**,
so a plain `pip install` raises `CaptureUnavailable` naming the rebuild command.
And they are Linux and macOS only.

Windows gets everything else. Dissection, crafting, capture files and `columns()`
are pure Rust with no libpcap, so they build and pass the same test suite there.
What Windows does not get is the wire: live capture needs Npcap, and raw sends
have been restricted by the OS since XP SP2. Those entry points exist and raise
`CaptureUnavailable` rather than being missing.

`sniff(offline=...)` needs none of that. It runs the whole state machine from a
capture file with no privileges and no feature flag: `count`, `store`, `prn`,
`lfilter`, `stop_filter`, `timeout` and the `where=` extension.

## Capture files

pcap and pcapng, read and written, plus gzip on both sides — picked by magic
bytes on the way in and by file name on the way out.

```python
from wiry import rdpcap, wrpcap, PcapWriter, Ether, IP, TCP

wrpcap("out.pcapng", rdpcap("capture.pcap"))   # whole capture, one crossing

with PcapWriter("stream.pcap.gz", append=True) as w:
    w.write(Ether()/IP()/TCP(dport=80))
```

Writing a whole `PacketList` copies it inside Rust with the GIL released and
builds no Python object per packet; `PcapWriter.write()` is the per-packet
streaming path, and both encode through the same code, so the files agree byte
for byte. Appending reads the existing file's header first and refuses a link
type it would misdescribe, or a pcapng that ends mid-block; a refused append
leaves the file exactly as it found it. What pcapng we do not write is listed in
[DEVIATIONS.md](DEVIATIONS.md) E5.

## Captures as columns

The part scapy has no equivalent for. A capture already lives in Rust as one
buffer; pulling a few fields out of all of it should not mean building a Python
object per packet.

```python
from wiry import rdpcap, IP, TCP

cap = rdpcap("capture.pcap")

cap.columns([("IP", "src"), ("TCP", "dport")])
cap.columns([("IP", "src")], where=[("TCP", "dport", "==", 443)])
cap.count_layer(TCP)
cap.field_column(IP, "src")
cap.to_dict()
```

One call, one pass, one crossing. Filters are data rather than callbacks, so
selection stays in Rust. Dataframes export lazily to polars, arrow and pandas:
`pip install 'wiry[polars]'`.

## Your own layers

A layer you declare is data, not code. Python hands the description to Rust once,
at class-definition time, and the same dissector that runs the built-in layers
runs yours. Nothing crosses back into Python per packet or per field, so a
declared layer reads at built-in speed.

```python
from wiry import Packet, bind_layers, UDP, IP
from wiry.fields import ByteField, ShortField, IPField

class MyProto(Packet):
    name = "MyProto"
    fields_desc = [
        ByteField("version", 1),
        ShortField("length", 0),
        IPField("peer", "0.0.0.0"),
    ]

bind_layers(UDP, MyProto, dport=9999)

pkt = IP()/UDP()/MyProto(version=2, peer="10.0.0.1")
IP(bytes(pkt))[MyProto].peer        # '10.0.0.1'
```

From there it is an ordinary layer: stacking, indexing, `in`, get and set,
`show()`, dissection out of a capture, and `columns()`. See
[DEVIATIONS.md](DEVIATIONS.md) E3 for what a declared layer cannot express.

## How we know it is right

Against a real 14,261-packet capture, compared with scapy 2.7.0: all 14,261
layer chains agree, all 155,501 field comparisons are equal, and every packet
re-serialises byte-identically.

scapy's own regression suite runs against wiry: **40 pass, 636 skip, 4 fail.**
A skip is a scope boundary, most often a layer we do not implement or a test
whose `~` marker asks for a Linux host, root or tshark. Of the 4 failures, 2 are
scapy's `Net` address generators, 1 needs Windows, and 1 asserts by patching a
scapy internal we do not have. Every gap is enumerated in
[DEVIATIONS.md](DEVIATIONS.md).

328 Rust and 654 Python tests pass, 333 Rust with live capture built in. All
three crates set `#![forbid(unsafe_code)]`, which constrains this code and says
nothing about dependencies: PyO3 contains hundreds of unsafe blocks and is
compiled in. The dissector carries eight fuzz targets plus seeded property tests
that run on stable.

Four adversarial reviews went looking for wrong answers, hostile-input
failures and races in the capture surface. They found twenty bugs, including a
field write that could corrupt the layer beside it, a reply matcher that paired
answers with the wrong probe, an option value that could crash the interpreter,
and four length fields that wrapped rather than refusing a region too wide to
describe. All are fixed, with a regression test each.

## When not to use wiry

- **You need a protocol outside the twenty-nine.** scapy has 1,746 and an interactive
  shell. It is a more capable tool and will stay one.
- **You have a few thousand packets.** scapy takes a second. Nothing here matters.
- **You only want a fast parser and dpkt's API suits you.** dpkt is 2.0x
  behind per packet, BSD-licensed, and fine. Its last release was 2022.

Use wiry when you are moving a lot of packets offline, when you want scapy's API
without GPL-2.0, or when `columns()` is the shape of your problem.

## Install

```sh
pip install wiry
```

PyPI currently holds a 0.0.0 placeholder. Until the first real release, build
from source.

From source, with live capture:

```sh
git clone https://github.com/AddisonGoolsbee/wiry && cd wiry
MATURIN_PEP517_ARGS="--features pyo3/extension-module,live" pip install .
```

Confirm it took with `python -c "import wiry; print(wiry.capture_available())"`.
Building this way needs libpcap, which macOS already ships and which Debian and
Ubuntu call `libpcap-dev`.

The Rust crate is separate and needs none of that:

```sh
cargo add wiry
```

## Relationship to scapy

wiry is an independent clean-room implementation and shares no code with scapy.

scapy is GPL-2.0. Reimplementing an API is settled fair use (*Google LLC v.
Oracle America*, 2021): names, signatures and calling conventions are interface,
not expression. Copying an implementation is a different thing, and this project
does not. Every protocol layout here is written from its RFC or IANA registry,
cited at the top of each layer module, and contributors are asked not to read
scapy's source while writing the equivalent layer. See
[CONTRIBUTING.md](CONTRIBUTING.md).

That is what makes the permissive licence defensible, and it is why the Rust
core is usable from Rust.

## Status

Early. Working, measured, and short of parity. Read
[DEVIATIONS.md](DEVIATIONS.md) before depending on it.

## License

MIT.
