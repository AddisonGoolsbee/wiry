"""Head-to-head benchmark against Scapy on real captures.

Reports two modes deliberately:
  lazy  - read a couple of fields per packet, the common scripting pattern
  eager - dissect and re-serialise every packet, the worst case
Reporting only the lazy number invites the fair accusation of cherry-picking.

Run: python dev/bench.py <pcap> [limit]
"""

import gc
import os
import resource
import sys
import time

import packetry as B

try:
    import scapy.all as S
    from scapy.config import conf as sconf

    sconf.verb = 0
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False


def rss_mb():
    r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return r / (1024 * 1024) if sys.platform == "darwin" else r / 1024


def timed(fn):
    gc.collect()
    t0 = time.perf_counter()
    out = fn()
    return time.perf_counter() - t0, out


def row(label, dt, n, extra=""):
    rate = n / dt if dt > 0 else 0
    print(f"  {label:<44} {dt * 1000:9.1f} ms  {rate:>12,.0f} pkt/s  {extra}")
    return rate


def bench_read(path, limit):
    print(f"\n=== READ + FIELD ACCESS ({limit:,} packets) ===")
    results = {}

    def blitz_lazy():
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

    dt, (n, tcp) = timed(blitz_lazy)
    results["packetry"] = row("packetry  per-packet loop", dt, n, f"({tcp} tcp)")

    # Bulk mode works over the whole capture, so the rate is per packet.
    def blitz_bulk():
        pl = B.rdpcap(path)
        col = pl.field_column("TCP", "dport")
        tcp = sum(1 for x in col if x is not None)
        return len(col), tcp

    dt, (n2, c) = timed(blitz_bulk)
    results["packetry_bulk"] = row(
        f"packetry  bulk column API ({n2:,} pkts)", dt, n2, f"({c} tcp)"
    )

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

        dt, (n3, tcp3) = timed(scapy_lazy)
        results["scapy"] = row("scapy     PcapReader loop", dt, n3, f"({tcp3} tcp)")

    return results


def bench_roundtrip(path, limit):
    print(f"\n=== DISSECT + RE-SERIALISE ({limit:,} packets) ===")
    results = {}

    def blitz():
        pl = B.rdpcap(path)
        n = min(limit, len(pl))
        total = 0
        for i in range(n):
            total += len(bytes(pl[i]))
        return n, total

    dt, (n, _) = timed(blitz)
    results["packetry"] = row("packetry", dt, n)

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

        dt, (n2, _) = timed(scapy_rt)
        results["scapy"] = row("scapy", dt, n2)

    return results


def bench_build(n=20000):
    print(f"\n=== BUILD + SERIALISE ({n:,} packets) ===")
    results = {}

    def blitz():
        for _ in range(n):
            bytes(
                B.Ether(dst="00:11:22:33:44:55")
                / B.IP(dst="10.0.0.1")
                / B.TCP(dport=80)
            )
        return n

    dt, _ = timed(blitz)
    results["packetry"] = row("packetry  Ether/IP/TCP", dt, n)

    if HAVE_SCAPY:
        def scapy_b():
            for _ in range(n):
                S.raw(
                    S.Ether(dst="00:11:22:33:44:55")
                    / S.IP(dst="10.0.0.1")
                    / S.TCP(dport=80)
                )
            return n

        dt, _ = timed(scapy_b)
        results["scapy"] = row("scapy     Ether/IP/TCP", dt, n)

    return results


def bench_memory(path):
    print("\n=== MEMORY: load a whole capture ===")
    size = os.path.getsize(path) / 1e6
    base = rss_mb()
    pl = B.rdpcap(path)
    n = len(pl)
    after = rss_mb()
    print(f"  file {size:,.0f} MB, {n:,} packets")
    print(f"  packetry rdpcap peak RSS delta: {after - base:,.0f} MB")
    print("  (scapy rdpcap on a capture this size is measured separately;")
    print("   it materialises one Python object graph per packet)")
    return n


def summarise(name, r):
    if "scapy" in r and r.get("scapy", 0) > 0:
        for k in r:
            if k != "scapy":
                print(f"  -> {name}: {k} is {r[k] / r['scapy']:,.1f}x scapy")


if __name__ == "__main__":
    pcap = sys.argv[1]
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 20000
    print(f"file: {pcap}  ({os.path.getsize(pcap) / 1e6:,.1f} MB)")
    if not HAVE_SCAPY:
        print("scapy not installed; showing packetry numbers only")

    r1 = bench_read(pcap, limit)
    summarise("read+fields", r1)
    r2 = bench_roundtrip(pcap, limit)
    summarise("roundtrip", r2)
    r3 = bench_build()
    summarise("build", r3)
    bench_memory(pcap)
