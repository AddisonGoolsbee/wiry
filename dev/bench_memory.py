"""Peak-memory comparison, each library in its own process.

Measuring both in one process is meaningless: ru_maxrss is a high-water mark,
so whichever runs second reports whatever the first one peaked at.

Run: python dev/bench_memory.py <pcap> [limit]
"""

import os
import subprocess
import sys

CHILD = r"""
import resource, sys, time
which, path, limit = sys.argv[1], sys.argv[2], int(sys.argv[3])

def rss_mb():
    r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return r / (1024*1024) if sys.platform == "darwin" else r / 1024

t0 = time.perf_counter()
if which == "packetry":
    import packetry as B
    pl = B.rdpcap(path)
    n = len(pl)
    # Touch a field on every packet so the comparison is like for like.
    col = pl.field_column("IP", "src")
    touched = sum(1 for x in col if x is not None)
else:
    from scapy.config import conf
    conf.verb = 0
    import scapy.all as S
    pkts = []
    with S.PcapReader(path) as pr:
        for i, p in enumerate(pr):
            if i >= limit: break
            pkts.append(p)
    n = len(pkts)
    touched = 0
    for p in pkts:
        if S.IP in p:
            _ = p[S.IP].src
            touched += 1
dt = time.perf_counter() - t0
print(f"{which}\t{n}\t{touched}\t{dt:.3f}\t{rss_mb():.1f}")
"""


def run(which, path, limit):
    r = subprocess.run(
        [sys.executable, "-c", CHILD, which, path, str(limit)],
        capture_output=True,
        text=True,
        timeout=1800,
    )
    line = [x for x in r.stdout.strip().splitlines() if x.startswith(which)]
    if not line:
        return None, r.stderr.strip()[-400:]
    which, n, touched, dt, rss = line[0].split("\t")
    return (int(n), int(touched), float(dt), float(rss)), None


if __name__ == "__main__":
    path = sys.argv[1]
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 200000
    size = os.path.getsize(path) / 1e6
    print(f"file: {path} ({size:,.1f} MB), limit {limit:,} packets\n")
    print(f"  {'library':<10} {'packets':>10} {'IP pkts':>10} {'time':>9} {'peak RSS':>11}")

    rows = {}
    for which in ("packetry", "scapy"):
        out, err = run(which, path, limit)
        if out is None:
            print(f"  {which:<10} FAILED: {err}")
            continue
        n, touched, dt, rss = out
        rows[which] = (n, dt, rss)
        print(f"  {which:<10} {n:>10,} {touched:>10,} {dt:>8.2f}s {rss:>10,.0f} MB")

    if "packetry" in rows and "scapy" in rows:
        bn, bt, br = rows["packetry"]
        sn, st, sr = rows["scapy"]
        print()
        print(f"  packetry processed {bn / sn:,.1f}x the packets")
        print(f"  memory per packet: packetry {br * 1e3 / bn:,.2f} KB "
              f"vs scapy {sr * 1e3 / sn:,.2f} KB "
              f"({(sr / sn) / (br / bn):,.0f}x less)")
