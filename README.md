# wiry

Packet dissection and crafting for Python, with scapy's API and a Rust core.
MIT licensed.

```python
from wiry import rdpcap

cap = rdpcap("capture.pcap")
cap.columns([("IP", "src"), ("IP", "dst"), ("TCP", "dport")])
```

Those two lines read a 368 MB capture off disk and pull three fields out of all
791,615 packets in 407 ms, without building a Python object for a single one of
them.

**wiry implements 91 layers. scapy registers 1,746.** Anything outside them
dissects to `Raw` and round-trips unchanged, and you get bytes rather than
fields.

Seventeen of them are the core, and those are complete: options parsed in both
directions, lengths and checksums recomputed on write. Ethernet, 802.1Q, ARP,
IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, DNS, BOOTP, DHCP, Loopback, Linux cooked
capture in both versions, `Raw` and `Padding`.

Fourteen are encapsulations, because losing one of those loses every layer under
it rather than one leaf: the four IPv6 extension headers, GRE, VXLAN, Geneve,
MPLS, PPPoE and PPP, GTP-U and the two ERSPAN types. IP-in-IP and 6in4 need no
layer of their own. A tunnelled packet dissects through to its inner transport,
tunnels nest, and `columns()` reaches inside them.

The remaining sixty are shallower, and that is the part to read before counting
on them: 802.2 LLC and SNAP, STP, LLDP, CDP, radiotap and 802.11 with its six
management bodies, SCTP, IGMP, the Neighbor Discovery and MLD messages, ESP, AH,
OSPF, RIP, BGP, VRRP, HSRP, BFD, NTP, DHCPv6, SNMP, TFTP, syslog, NBNS, NBT,
RADIUS, RTP, RTCP, NetFlow v5 and v9, IPFIX, sFlow, QUIC, WireGuard, TLS, HTTP,
SSH, MQTT, Modbus/TCP, SMB2, LDAP, SIP, FTP, SMTP, IMAP and Telnet. A layer that
dissects its header and leaves its body as `Raw` is listed in
[DEVIATIONS.md](DEVIATIONS.md) as exactly that: repeating record arrays stay in
the payload, none of the sixty recomputes a length or a checksum, encrypted
bodies stay encrypted, and port dispatch is a heuristic with a guard over the
payload. `DEVIATIONS.md` E6 and the P rows state where each one stops.

The method surface is narrower too. TCP stream reassembly is absent: `sessions()`
groups packets into flows but never reorders or rebuilds a stream. Most of what
else scapy's `Packet` carries is its own internal machinery, `do_build`,
`post_dissect`, `self_build` and the rest, which exists because scapy assembles
an object graph per packet. wiry does not, so it has no equivalent and needs
none.

That is the trade. Everything below assumes you already know it.

## Numbers

`bigFlows.pcap` from the tcpreplay project: 368,083,648 bytes, 791,615 packets,
SHA-256 `2b630291cc848c79949e12a54edebe07d20f644747db28899ac4d568c42dc141`,
fetched from `https://s3.amazonaws.com/tcpreplay-pcap-files/bigFlows.pcap`. That
URL is mutable and has already served a different capture under the same name —
an earlier version of this table was measured on a 256 MB, 549,726-packet
revision of it — so the hash is what makes "the same corpus" checkable. Apple M1 Pro, macOS 26.6,
CPython 3.13.5, scapy 2.7.0, dpkt 1.9.8, measured 2026-09-18. Each row is the
best of nine timed runs: three invocations of `dev/bench.py`, each taking the
best of three. Reproduce with `python dev/bench.py <pcap>`.

| Read 2 fields from every packet | rate | |
|---|---|---|
| scapy `PcapReader` loop | 11,183 pkt/s | |
| dpkt `Reader` loop | 178,944 pkt/s | |
| wiry per-packet loop | 301,473 pkt/s | **1.7x dpkt** |
| wiry `field_column()` | 3,992,337 pkt/s | **22.3x dpkt** |

| Other workloads | scapy | wiry | |
|---|---|---|---|
| Dissect + re-serialise | 11,116 pkt/s | 680,985 pkt/s | **61.3x** |
| Build + serialise Ether/IP/TCP | 4,577 pkt/s | 96,384 pkt/s | **21.1x** |

Memory, each in its own process (`python dev/bench_memory.py <pcap>`):

| | packets held | peak RSS | per packet |
|---|---|---|---|
| scapy | 200,000 | 1,317 MB | 6.59 KB |
| wiry | 791,615 | 492 MB | **0.62 KB** |

Read the per-packet row honestly: **against dpkt it is 1.7x, not an order of
magnitude.** Every per-packet API pays for one Python object per packet and that
cost sets the ceiling. dpkt sits near it and so do we. Across the three
invocations that ratio moved between 1.6x and 1.8x, which is the measurement's
own spread and worth more than a third significant figure. `columns()` amortises
the object cost instead, returning one list per field for the whole capture, and
that is where the 22.3x comes from.

The same effect caps the bulk API. Four separate `field_column()` calls dissect
the capture four times, yet cost 1.7x one fused `columns()` pass rather than 4x
(793 ms against 472 ms, `python dev/bench_columnar.py <pcap>`). Fusing the
passes removes three quarters of the dissection and well under half the runtime,
so most of what is left is building the Python lists. That is the floor, and no
amount of Rust moves it.

An earlier version of this table read higher per packet. It is not comparable:
both the corpus and the protocol set changed underneath it. Bounds checks,
Ethernet-trailer handling and sixty more layers in the dispatch tables all cost
something, and a table measured on a different capture cannot price them.

## Crafting

dpkt cannot build a packet from field defaults. wiry can, 21.1x faster than
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

One declaration can also stand for many packets. A field may hold a list, an
inclusive range, a `Net`/`Net6` or a `Rand*` value, and the packet carrying one
is a template that expands in scapy's order. The description crosses into Rust
once and the product is walked there, so `sendp(Ether()/IP(dst=Net("10.0.0.0/8")))`
is one crossing rather than sixteen million, and iteration is lazy in chunks.
`fuzz()`, `corrupt_bytes` and `corrupt_bits` are there too, over a seedable
generator that makes a whole run repeat — which scapy cannot do.
[DEVIATIONS.md](DEVIATIONS.md) E21 states what a template refuses and where the
seed's guarantee stops.

`fragment(pkt, 1480)` splits a datagram per RFC 791 §3.2 and `defragment(cap)`
puts one back together, over a whole capture in a single crossing;
`fragment6`/`defragment6` do RFC 8200 §4.5. Reassembly buffers
attacker-controlled bytes, so its bounds and its overlap rule are stated in
[DEVIATIONS.md](DEVIATIONS.md) E19 rather than left to be discovered.

Capture and injection work too: `sniff`, `send`, `sendp`, `sr`, `sr1`, `srp`,
`srp1` and `AsyncSniffer`, with scapy's arguments and semantics — and the tools
built on them: `traceroute`, `arping`, `srloop`, `srploop`, `getmacbyip` and
`get_if_hwaddr`. Two limits, both real.
They need the `live` cargo feature, which is **off in the first release**,
so a plain `pip install` raises `CaptureUnavailable` naming the rebuild command.
And they are Linux and macOS only.

Windows gets everything else. Dissection, crafting, capture files and `columns()`
are pure Rust with no libpcap, so they build and pass the same test suite there
in CI. What Windows does not get is the wire: live capture needs Npcap, and raw
sends have been restricted by the OS since XP SP2. Those entry points exist and
raise `CaptureUnavailable` rather than being missing.

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
for byte. `pkt.wirelen` carries a snaplen-clipped record's original wire length
through the round trip rather than collapsing it to the bytes that were kept.
Appending reads the existing file's header first and refuses a link type it would
misdescribe, or a pcapng that ends mid-block; a refused append leaves the file
exactly as it found it. What pcapng we do not write is listed in
[DEVIATIONS.md](DEVIATIONS.md) E5, and what the writer costs is in E20.

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

## Reporting

The familiar reporting surface, on the same machinery.

```python
from wiry import rdpcap, Ether, IP, TCP

pkt = Ether() / IP(dst="10.0.0.2") / TCP(dport=80, flags="S")
pkt.sprintf("%IP.src% > %IP.dst% {TCP:%TCP.flags%}")
pkt.show2()                 # as it will be sent: lengths and checksums computed

cap = rdpcap("capture.pcap")
cap.sprintf("%IP.src% > %IP.dst%")   # the whole capture, one pass
cap.summary()
cap.sessions()                       # flows, keyed by address tuple
```

`sprintf` over a `PacketList` resolves the fields the format names as columns, so
it dissects once and builds no packet. `sessions()` computes the flow keys in
Rust and leaves the membership there: a flow's packets become a `PacketList` only
when you ask for that flow. Give either one a callback — `prn`, or a
`session_extractor` — and the per-packet crossing is back, because that is what
the callback asked for.

Flows, not streams. wiry does not reassemble TCP.

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

A layer meant to ship in the engine itself is written a second way: one TOML
spec in `dev/protogen/`, from which the layer module, its id, its registration
and its dispatch entry are generated. The citation is a required key, so a spec
without its RFC does not build, and the generator refuses rather than guesses
where the flat field model cannot place a field. See
[dev/protogen/README.md](dev/protogen/README.md).

## How we know it is right

Over the first 20,000 packets of the corpus above, compared with scapy 2.7.0:
all 20,000 layer chains agree, all 210,910 field comparisons are equal, and
every packet re-serialises byte-identically.

scapy's own regression suite runs against wiry. Over its whole `test/`
directory: **55 pass, 621 skip, 4 fail**; over `regression.uts` alone, 44 pass,
298 skip, 3 fail. A skip is a scope boundary, most often a layer we do not
implement, a scapy internal we have no equivalent for, or a test whose `~`
marker asks for a Linux host, root or tshark. Of the 4 failures, 1 needs
Windows, 1 asserts by patching a scapy internal we do not have, and 2 are
generator differences [DEVIATIONS.md](DEVIATIONS.md) E21 states outright. Every
gap is enumerated there.

632 Rust and 1,158 Python tests pass, 638 Rust with live capture built in. All
three crates set `#![forbid(unsafe_code)]`, which constrains this code and says
nothing about dependencies: PyO3 contains hundreds of unsafe blocks and is
compiled in. The dissector carries nine fuzz targets plus seeded property tests
that run on stable.

Twelve adversarial reviews have gone looking for wrong answers, hostile-input
failures and races. Four over the core found twenty bugs. Eight more, one over
each branch merged for this release, found twenty-two — counted one per defect
that a review found in code already written and that now has a regression test.
The worst of them: a fragment reassembler that went quadratic on crafted input,
which is remote-controllable; an append path that truncated the user's existing
capture before writing its replacement; unbounded gzip decompression, where a
200 KB file expanded to most of a gigabyte of resident memory; a `sprintf`
format parser that was exponential in unclosed blocks, so a 72-character format
never finished; a `columns()` read that answered a DNS transaction id where a
length was asked for; and a code generator that silently deleted hand-written
code inside a damaged marker region. All are fixed, with a regression test each.

## When not to use wiry

- **You need a protocol outside the ninety-one, or deeper inside one of the
  sixty than its header.** scapy has 1,746 layers and an interactive shell. It is
  a more capable tool and will stay one.
- **You have a few thousand packets.** scapy takes a second. Nothing here matters.
- **You only want a fast parser and dpkt's API suits you.** dpkt is 1.7x
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
