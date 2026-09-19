# wiry

scapy's interface, with a Rust engine underneath. Same API, same output,
20–236x faster.

```python
from wiry import *
```

Anything written for scapy should run unchanged. Where it does not,
[DEVIATIONS.md](DEVIATIONS.md) says so.

## Examples

Craft a packet and look at it:

```python
from wiry import *

p = Ether()/IP(dst="10.0.0.2")/TCP(dport=443, flags="S")
p.show()
raw(p)                      # checksums and lengths filled in
```

Read a capture:

```python
from wiry import *

cap = rdpcap("capture.pcap")
cap.summary()
cap[0][IP].src
[p for p in cap if TCP in p and p[TCP].dport == 80]
```

Sniff — needs root, see Platforms:

```python
# needs root
from wiry import *

sniff(iface="en0", count=10, prn=lambda p: p.summary())
sniff(filter="tcp port 443", timeout=30)
```

Send and get a reply:

```python
# needs root
from wiry import *

sr1(IP(dst="8.8.8.8")/ICMP(), timeout=2)
traceroute("example.com")
arping("192.168.1.0/24")
```

Follow TCP:

```python
from wiry import *

cap = rdpcap("capture.pcap")
cap.sessions()              # grouped into flows
cap.streams()               # reassembled, both directions
```

An interactive shell, like scapy's:

```sh
wiry
```

## Speed

`bigFlows.pcap`, 791,615 packets. Apple M1 Pro, CPython 3.13, scapy 2.7.0,
release build. Method, corpus hash and the rest of the table are in
[BENCHMARKS.md](BENCHMARKS.md); reproduce with `python dev/bench.py <pcap>`.

| | scapy | wiry | |
|---|---|---|---|
| Read two fields per packet | 11,315 pkt/s | 305,113 pkt/s | 27x |
| Dissect + re-serialise | 11,127 pkt/s | 688,520 pkt/s | 62x |
| Build Ether/IP/TCP | 4,570 pkt/s | 94,860 pkt/s | 21x |
| Read two fields, in bulk | 11,315 pkt/s | 2,667,208 pkt/s | 236x |

## Install

```sh
pip install wiry
```

libpcap is not needed to build — it is loaded at run time if it is there.

## Platforms

macOS and Linux are what this is built and tested on.

**Windows gets wheels but no wire.** Dissection, crafting and capture files are
pure Rust and should work; live capture needs Npcap, and raw sends have been
restricted by the OS since XP SP2. None of it has been run on Windows, so treat
it as untested rather than supported.

Live capture needs root, exactly as scapy does:

```sh
sudo python your_script.py
```

On macOS you can install ChmodBPF once instead — it ships with Wireshark — and
then neither scapy nor wiry needs sudo.

## What is missing

100 protocol layers; scapy has 1,746. Anything else dissects to `Raw` and
round-trips unchanged. Every known gap is written down in
[DEVIATIONS.md](DEVIATIONS.md).

## Licence

GPL-2.0-only, the same as scapy, because wiry derives from it. [NOTICE](NOTICE)
records what came from where.
