"""Benchmark the columnar API: four fields out of one real capture.

Four ways of getting the same four columns, on the same packets:
  columns()        one pass, one crossing, every field from one dissection
  field_column()   four calls, so four passes over the capture
  python loop      the obvious way, one crossing per packet per field
  scapy            the incumbent, same fields, same file

Scapy is imported here and never in tests/: it is a development oracle, not a
dependency. Run: python dev/bench_columnar.py <pcap> [limit]
"""

import gc
import os
import sys
import time

import blitzpkt as B

try:
    import scapy.all as S
    from scapy.config import conf as sconf

    sconf.verb = 0
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False

SPECS = [("IP", "src"), ("IP", "dst"), ("TCP", "sport"), ("TCP", "dport")]


def timed(fn):
    gc.collect()
    t0 = time.perf_counter()
    out = fn()
    return time.perf_counter() - t0, out


def row(label, dt, n, extra=""):
    rate = n / dt if dt > 0 else 0
    print(f"  {label:<40} {dt * 1000:9.1f} ms  {rate:>12,.0f} pkt/s  {extra}")
    return rate


def checksum(cols):
    """Something cheap that proves every column was really materialised."""
    return tuple(sum(1 for v in c if v is not None) for c in cols)


def bench(path, limit):
    pl = B.rdpcap(path)
    n = min(limit, len(pl))
    print(f"\n=== FOUR COLUMNS FROM {n:,} PACKETS ===")
    results = {}

    # Both sides must cover identical packet sets: a bulk call over the whole
    # capture against a loop over a prefix gives a flattering, wrong ratio.
    cap = pl.head(n)

    def bulk():
        cols = cap.columns(SPECS)
        return checksum(cols.values())

    dt, want = timed(bulk)
    results["columns"] = row("blitzpkt  columns()  one pass", dt, n, str(want))

    def four_calls():
        cols = [cap.field_column(layer, field) for layer, field in SPECS]
        return checksum(cols)

    dt, got = timed(four_calls)
    assert got == want, (got, want)
    results["field_column"] = row("blitzpkt  field_column() x4", dt, n)

    def py_loop():
        cols = [[] for _ in SPECS]
        for pkt in cap:
            for c, (layer, field) in zip(cols, SPECS):
                c.append(getattr(pkt[layer], field) if pkt.haslayer(layer) else None)
        return checksum(cols)

    dt, got = timed(py_loop)
    assert got == want, (got, want)
    results["loop"] = row("blitzpkt  per-packet Python loop", dt, n)

    if HAVE_SCAPY:
        def scapy_loop():
            cols = [[] for _ in SPECS]
            cnt = 0
            with S.PcapReader(path) as pr:
                for pkt in pr:
                    for c, (layer, field) in zip(cols, SPECS):
                        lay = getattr(S, "IP" if layer == "IP" else layer)
                        c.append(getattr(pkt[lay], field) if lay in pkt else None)
                    cnt += 1
                    if cnt >= n:
                        break
            return checksum(cols)

        dt, got = timed(scapy_loop)
        results["scapy"] = row("scapy     per-packet loop", dt, n, str(got))

    return results


def bench_filtered(path, limit):
    """Filtered extraction: only TCP ports, rejected packets never materialised."""
    pl = B.rdpcap(path)
    n = min(limit, len(pl))
    cap = pl.head(n)
    print(f"\n=== TCP PORTS ONLY, FROM {n:,} PACKETS ===")

    def bulk():
        cols = cap.columns([("TCP", "sport"), ("TCP", "dport")], layer="TCP")
        return len(cols["TCP.dport"])

    dt, hits = timed(bulk)
    row("blitzpkt  columns(layer='TCP')", dt, n, f"({hits:,} tcp rows)")

    def py_loop():
        out = []
        for pkt in cap:
            if pkt.haslayer("TCP"):
                out.append((pkt["TCP"].sport, pkt["TCP"].dport))
        return len(out)

    dt, got = timed(py_loop)
    assert got == hits
    row("blitzpkt  per-packet Python loop", dt, n)

    if HAVE_SCAPY:
        def scapy_loop():
            out = []
            cnt = 0
            with S.PcapReader(path) as pr:
                for pkt in pr:
                    if S.TCP in pkt:
                        out.append((pkt[S.TCP].sport, pkt[S.TCP].dport))
                    cnt += 1
                    if cnt >= n:
                        break
            return len(out)

        dt, got = timed(scapy_loop)
        row("scapy     per-packet loop", dt, n, f"({got:,} tcp rows)")


def summarise(r):
    base = r.get("columns")
    if not base:
        return
    print()
    for k in ("field_column", "loop", "scapy"):
        if r.get(k):
            print(f"  -> columns() is {base / r[k]:,.1f}x {k}")
    print("  (one pass saves three dissections, not the Python objects: four")
    print("   columns cost four columns' worth of objects either way)")


if __name__ == "__main__":
    pcap = sys.argv[1]
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 10**9
    print(f"file: {pcap}  ({os.path.getsize(pcap) / 1e6:,.1f} MB)")
    if not HAVE_SCAPY:
        print("scapy not installed; showing blitzpkt numbers only")
    summarise(bench(pcap, limit))
    bench_filtered(pcap, limit)
