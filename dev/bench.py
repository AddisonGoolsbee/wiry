"""Head-to-head benchmark against scapy and dpkt on a real capture.

Reports two modes deliberately:
  lazy  - read a couple of fields per packet, the common scripting pattern
  eager - dissect and re-serialise every packet, the worst case
Reporting only the lazy number invites the fair accusation of cherry-picking.

Run: python dev/bench.py <pcap> [limit]

`limit` truncates scapy's and dpkt's streaming loops but not wiry's rdpcap,
which always parses the whole file, so a limit below the packet count charges
wiry for work it does not report. Default is the whole capture.
"""

import gc
import os
import resource
import sys
import time

import wiry as B

try:
    import scapy.all as S
    from scapy.config import conf as sconf

    sconf.verb = 0
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False

try:
    import dpkt

    HAVE_DPKT = True
except ImportError:
    HAVE_DPKT = False

REPS = 3


def rss_mb():
    r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return r / (1024 * 1024) if sys.platform == "darwin" else r / 1024


def best(fn):
    out = None
    dt = float("inf")
    for _ in range(REPS):
        gc.collect()
        t0 = time.perf_counter()
        out = fn()
        dt = min(dt, time.perf_counter() - t0)
    return dt, out


def row(label, dt, n, extra=""):
    rate = n / dt if dt > 0 else 0
    print(f"  {label:<44} {dt * 1000:9.1f} ms  {rate:>12,.0f} pkt/s  {extra}")
    return rate


def bench_read(path, limit):
    print(f"\n=== READ + FIELD ACCESS ({limit:,} packets) ===")
    results = {}

    def wiry_lazy():
        pl = B.rdpcap(path)
        n = min(limit, len(pl))
        tcp = 0
        for i in range(n):
            p = pl[i]
            if "TCP" in p.layers():
                _ = p["IP"].src
                _ = p["TCP"].dport
                tcp += 1
        return n, tcp

    dt, (n, tcp) = best(wiry_lazy)
    results["wiry"] = row("wiry      per-packet loop", dt, n, f"({tcp} tcp)")

    def wiry_bulk():
        pl = B.rdpcap(path)
        col = pl.field_column("TCP", "dport")
        tcp = sum(1 for x in col if x is not None)
        return len(col), tcp

    dt, (n2, c) = best(wiry_bulk)
    results["wiry_bulk"] = row(
        f"wiry      bulk column API ({n2:,} pkts)", dt, n2, f"({c} tcp)"
    )

    if HAVE_DPKT:
        def dpkt_lazy():
            cnt = 0
            tcp = 0
            with open(path, "rb") as f:
                for _ts, buf in dpkt.pcap.Reader(f):
                    cnt += 1
                    eth = dpkt.ethernet.Ethernet(buf)
                    ip = eth.data
                    if isinstance(ip, dpkt.ip.IP):
                        t = ip.data
                        if isinstance(t, dpkt.tcp.TCP):
                            _ = ip.src
                            _ = t.dport
                            tcp += 1
                    if cnt >= limit:
                        break
            return cnt, tcp

        dt, (n4, tcp4) = best(dpkt_lazy)
        results["dpkt"] = row("dpkt      Reader loop", dt, n4, f"({tcp4} tcp)")

    if HAVE_SCAPY:
        def scapy_lazy():
            cnt = 0
            tcp = 0
            with S.PcapReader(path) as pr:
                for p in pr:
                    cnt += 1
                    if S.TCP in p:
                        _ = p[S.IP].src
                        _ = p[S.TCP].dport
                        tcp += 1
                    if cnt >= limit:
                        break
            return cnt, tcp

        dt, (n3, tcp3) = best(scapy_lazy)
        results["scapy"] = row("scapy     PcapReader loop", dt, n3, f"({tcp3} tcp)")

    return results


def bench_roundtrip(path, limit):
    print(f"\n=== DISSECT + RE-SERIALISE ({limit:,} packets) ===")
    results = {}

    def wiry_rt():
        pl = B.rdpcap(path)
        n = min(limit, len(pl))
        total = 0
        for i in range(n):
            total += len(bytes(pl[i]))
        return n, total

    dt, (n, _) = best(wiry_rt)
    results["wiry"] = row("wiry", dt, n)

    if HAVE_SCAPY:
        def scapy_rt():
            cnt = 0
            total = 0
            with S.PcapReader(path) as pr:
                for p in pr:
                    total += len(S.raw(p))
                    cnt += 1
                    if cnt >= limit:
                        break
            return cnt, total

        dt, (n2, _) = best(scapy_rt)
        results["scapy"] = row("scapy", dt, n2)

    return results


def bench_build(n=20000):
    print(f"\n=== BUILD + SERIALISE ({n:,} packets) ===")
    results = {}

    def wiry_b():
        for _ in range(n):
            bytes(
                B.Ether(dst="00:11:22:33:44:55")
                / B.IP(dst="10.0.0.1")
                / B.TCP(dport=80)
            )
        return n

    dt, _ = best(wiry_b)
    results["wiry"] = row("wiry      Ether/IP/TCP", dt, n)

    if HAVE_SCAPY:
        def scapy_b():
            for _ in range(n):
                S.raw(
                    S.Ether(dst="00:11:22:33:44:55")
                    / S.IP(dst="10.0.0.1")
                    / S.TCP(dport=80)
                )
            return n

        dt, _ = best(scapy_b)
        results["scapy"] = row("scapy     Ether/IP/TCP", dt, n)

    print("  dpkt      cannot build a packet from field defaults")
    return results


def bench_memory(path):
    print("\n=== MEMORY: load a whole capture ===")
    size = os.path.getsize(path) / 1e6
    base = rss_mb()
    pl = B.rdpcap(path)
    n = len(pl)
    after = rss_mb()
    print(f"  file {size:,.0f} MB, {n:,} packets")
    print(f"  wiry rdpcap peak RSS delta: {after - base:,.0f} MB")
    return n


def summarise(name, r):
    for baseline in ("scapy", "dpkt"):
        if r.get(baseline, 0) > 0:
            for k in r:
                if k not in ("scapy", "dpkt"):
                    print(f"  -> {name}: {k} is {r[k] / r[baseline]:,.1f}x {baseline}")


if __name__ == "__main__":
    pcap = sys.argv[1]
    total = len(B.rdpcap(pcap))
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else total
    print(f"file: {pcap}  ({os.path.getsize(pcap) / 1e6:,.1f} MB, {total:,} packets)")
    print(f"best of {REPS} runs")
    if not HAVE_SCAPY:
        print("scapy not installed")
    if not HAVE_DPKT:
        print("dpkt not installed")
    if limit < total:
        print(f"WARNING: limit {limit:,} < {total:,}; wiry is charged for the "
              f"whole file but credited with {limit:,} packets")

    r1 = bench_read(pcap, limit)
    summarise("read+fields", r1)
    r2 = bench_roundtrip(pcap, limit)
    summarise("roundtrip", r2)
    r3 = bench_build()
    summarise("build", r3)
    bench_memory(pcap)
