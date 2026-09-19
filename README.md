# wiry

Packet dissection and crafting for Python, with scapy's API and a Rust core.
Derived from scapy, and GPL-2.0-only for that reason.

```python
from wiry import rdpcap

cap = rdpcap("capture.pcap")
cap.columns([("IP", "src"), ("IP", "dst"), ("TCP", "dport")])
```

Those two lines read a 368 MB capture off disk and pull three fields out of all
791,615 packets in 391 ms, without building a Python object for a single one of
them.

**wiry implements 100 layers. scapy registers 1,746.** Anything outside them
dissects to `Raw` and round-trips unchanged, and you get bytes rather than
fields. Seventeen of the hundred are complete; the rest stop somewhere, and
[DEVIATIONS.md](DEVIATIONS.md)'s P and T rows say where, one row at a time.

Seventeen of them are the core, and those are complete: options parsed in both
directions, lengths and checksums recomputed on write. Ethernet, 802.1Q, ARP,
IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, DNS, BOOTP, DHCP, Loopback, Linux cooked
capture in both versions, `Raw` and `Padding`.

Fourteen are encapsulations, because losing one of those loses every layer under
it rather than one leaf: the four IPv6 extension headers, GRE, VXLAN, Geneve,
MPLS, PPPoE and PPP, GTP-U and the two ERSPAN types. IP-in-IP and 6in4 need no
layer of their own. A tunnelled packet dissects through to its inner transport,
tunnels nest, and `columns()` reaches inside them.
[DEVIATIONS.md](DEVIATIONS.md) E6 states where each of those stops.

The remaining sixty-nine dissect their header and, where the body is a
repeating record array, that too: RIP entries, NetFlow v5 records, IGMPv3 group
records, all five OSPF bodies, BGP OPEN parameters and UPDATE path attributes,
MLDv2 address records, sFlow samples, VRRP addresses, RTP contributing sources,
SCTP chunk parameters, and NetFlow v9 and IPFIX sets. What stays `Raw` is a
record body whose layout varies by a type field, a payload that needs state from
an earlier datagram, and anything encrypted. None of them recomputes a length or
a checksum, and port dispatch is a heuristic with a guard over the payload. That
is the part to read before counting on them, and `DEVIATIONS.md`'s P and T rows
say where each one stops: 802.2 LLC and SNAP,
STP, LLDP, CDP, radiotap and 802.11 with its six management bodies, SCTP, IGMP,
the Neighbor Discovery and MLD messages, ESP, AH, OSPF and its five bodies, RIP,
BGP and its four, VRRP, HSRP,
BFD, NTP, DHCPv6, SNMP, TFTP, syslog, NBNS, NBT, RADIUS, RTP, RTCP, NetFlow v5
and v9, IPFIX, sFlow, QUIC, WireGuard, TLS, HTTP, SSH, MQTT, Modbus/TCP, SMB2,
LDAP, SIP, FTP, SMTP, IMAP and Telnet.

The method surface is narrower too. Most of what
scapy's `Packet` carries is its own internal machinery, `do_build`,
`post_dissect`, `self_build` and the rest, which exists because scapy assembles
an object graph per packet. wiry does not, so it has no equivalent and needs
none.

That is the trade. Everything below assumes you already know it.

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

## Crafting

dpkt builds from field defaults too, but you assign each payload and its
protocol number by hand: there is no `/`, and nothing prints the expression
back. wiry's 38 of 38 enumerated construction cases come out byte-identical to
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
`get_if_hwaddr`. They need the `live` cargo feature, which a default build does
not set, so a plain `pip install` raises `CaptureUnavailable` naming the rebuild
command. And they are Linux and macOS only.

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

The part scapy has no equivalent for.

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
cap.streams()                        # what the flows said, in sequence order
```

`sprintf` over a `PacketList` resolves the fields the format names as columns, so
it dissects once and builds no packet. `sessions()` computes the flow keys in
Rust and leaves the membership there: a flow's packets become a `PacketList` only
when you ask for that flow. Give either one a callback — `prn`, or a
`session_extractor` — and the per-packet crossing is back, because that is what
the callback asked for.

`sessions()` says which packets belong to a flow; `streams()` says what the flow
said. It reassembles every TCP stream in one crossing — octets in sequence order,
retransmissions dropped, out-of-order arrival put back, holes named rather than
filled in — and hands back each direction with the provenance to map a stream
offset to the packet it came from. `sniff(offline=..., session=TCPSession)` takes
the scapy-shaped route to the same engine.

That is what makes the application layers reach past one segment. On
`bigFlows.pcap`, 37% of the complete HTTP messages and 29% of the complete TLS
records span more than one segment, and no single-packet dissector can see any of
them. The bounds it works inside, and the rule it resolves overlapping octets by,
are stated in `crates/wiry-core/src/stream.rs` and in DEVIATIONS E25.

## Your own layers

A layer you declare is data, not code. Python hands the description to Rust once,
at class-definition time, and the same dissector that runs the built-in layers
runs yours: no Python runs during dissection, and nothing crosses back per
packet or per field. We have not timed a declared layer against a built-in one,
so that is the mechanism and not a measured claim.

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
298 skip, 3 fail. Read the skip column honestly: it is 91% of the suite, and
that ratio is the coverage statement, not the pass count. A skip is a scope
boundary — most often a layer we do not implement, a scapy internal we have no
equivalent for, a call we refuse by design, or a test whose `~` marker asks for
a Linux host, root or tshark. A refusal counts as a skip rather than a failure,
which is a choice the harness makes and `dev/scapy_suite.py` shows. Of the 4
failures, 1 needs Windows, 1 asserts by patching a scapy internal we do not
have, and 2 are
generator differences [DEVIATIONS.md](DEVIATIONS.md) E21 states outright. Every
gap is enumerated there.

670 Rust and 1,196 Python tests pass, 676 Rust with live capture built in. All
four crates set `#![forbid(unsafe_code)]`, which constrains this code and says
nothing about dependencies: PyO3 contains hundreds of unsafe blocks and is
compiled in. The dissector carries ten fuzz targets plus seeded property tests
that run on stable.

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

## When not to use wiry

- **You need a protocol outside the 100, or deeper inside one of the
  sixty-nine than `DEVIATIONS.md` says it goes.** scapy has 1,746 layers and an interactive shell. It is
  a more capable tool and will stay one.
- **Your work is live, on a default install.** `sniff`, `send` and the `sr`
  family need a non-default build, on Linux or macOS. Offline needs nothing.
- **You have a few thousand packets.** scapy takes a second. Nothing here matters.
- **You only want a fast parser and dpkt's API suits you.** dpkt is BSD-licensed
  and fine, and the per-packet margin over it is small. Its last release was 2022.

- **You need a permissive licence.** wiry is GPL-2.0-only and cannot be relicensed
  — see [Relationship to scapy](#relationship-to-scapy). If you are shipping a
  proprietary product, or writing a Rust crate you want the rest of crates.io to
  be able to depend on, wiry is the wrong dependency and dpkt or a
  purpose-written parser is the right one.

Use wiry when you are moving a lot of packets offline, when GPL-2.0 is a licence
you can live with, or when `columns()` is the shape of your problem.

## Install

PyPI currently holds a 0.0.0 placeholder, so `pip install wiry` does not yet get
you the library. Until the first real release, build from source:

```sh
git clone https://github.com/AddisonGoolsbee/wiry && cd wiry
pip install .
```

With live capture, from the same checkout:

```sh
MATURIN_PEP517_ARGS="--features pyo3/extension-module,live" pip install .
```

Confirm it took with `python -c "import wiry; print(wiry.capture_available())"`.
Building this way needs libpcap, which macOS already ships and which Debian and
Ubuntu call `libpcap-dev`.

The Rust crate is separate and needs none of that:

```sh
cargo add wiry
```

It is a GPL-2.0-only crate, which is unusual on crates.io and is a real
constraint rather than a formality: linking it into a crate of your own makes
that crate's distribution subject to GPL-2.0. Check that before you add it.

## Relationship to scapy

**wiry is a derivative work of scapy, and is licensed GPL-2.0-only because scapy
is.** It is not a clean-room implementation, and earlier versions of this file
said it was.

scapy — https://github.com/secdev/scapy, copyright Philippe Biondi and the scapy
contributors — is licensed GPL-2.0-only. wiry copies from it: field tables,
defaults, enumerations, dispatch logic, translated into Rust or into this
project's spec format. GPL-2.0 permits exactly that, on three conditions, and
wiry meets them: the derivative stays GPL-2.0-only, scapy's copyright notices
are preserved, and files carrying scapy-derived material state that they were
changed and when. [NOTICE](NOTICE) records the attribution and the ledger;
[CONTRIBUTING.md](CONTRIBUTING.md) is the procedure.

The *Google LLC v. Oracle America* fair-use argument — that names, signatures
and calling conventions are interface rather than expression — is no longer
what the licence rests on, and it is not cited here as if it were. It would
still cover the API surface, but the licence question is settled by GPL-2.0
compliance instead, which is a stronger footing and a narrower grant.

Protocol layouts are still written against the RFC or IANA registry that defines
them, and every layer still cites one. That is now an accuracy habit — an RFC is
a better source of truth than any implementation — not a licensing control.

Nothing here is endorsed by or affiliated with the scapy project. Report bugs in
wiry to wiry.

### The MIT period

wiry was published under MIT from its first public commit through `f756662`
inclusive, and those commits are on GitHub. Relicensing is not retroactive:
anyone who took wiry at `f756662` or earlier holds that copy under MIT
permanently. From the relicence commit forward the project is GPL-2.0-only, and
no scapy-derived material existed in the tree before that commit — the relicence
deliberately landed first, so the provenance of every line is readable from the
history.

## Status

Early. Working, measured, and short of parity. Read
[DEVIATIONS.md](DEVIATIONS.md) before depending on it.

## License

GPL-2.0-only. Not "or later" — scapy is GPL-2.0-only, and a derivative cannot
widen the terms it inherited. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
