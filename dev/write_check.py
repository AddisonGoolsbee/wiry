"""Check that the files we write are the files other tools read.

Dev-only oracle. Never shipped, never used to generate fixtures.

Every combination of format, timestamp resolution and compression goes out
through `wrpcap`, then back in through our own reader, scapy, dpkt and tshark.
A round-trip against our own reader alone proves only that we are consistent
with ourselves, which is exactly what a shared misunderstanding of the format
would look like.

Run: python dev/write_check.py
"""

import os
import shutil
import subprocess
import sys
import tempfile

import wiry as W

try:
    import scapy.all as S
    from scapy.config import conf

    conf.verb = 0
except ImportError:
    S = None

try:
    import dpkt
except ImportError:
    dpkt = None

TSHARK = shutil.which("tshark")


def packets():
    pkts = [
        W.Ether() / W.IP(dst="10.0.0.1") / W.TCP(dport=80),
        W.Ether() / W.IP(dst="10.0.0.2") / W.UDP(sport=53, dport=53) / W.Raw(load=b"q"),
        W.Ether() / W.IPv6(src="2001:db8::1") / W.UDP(sport=7, dport=7),
        W.Ether() / W.IP() / W.ICMP(),
        # An odd length, to land the pcapng padding on every residue.
        W.Ether() / W.IP() / W.UDP() / W.Raw(load=b"\xa5" * 3),
    ]
    for i, pkt in enumerate(pkts):
        pkt.time = 1_632_568_366.384_185 + i
    return pkts


def expected(pkts, nano):
    return [(bytes(p), p.time) for p in pkts], 1e-9 if nano else 1e-6


def check(label, got, want, tick, fails):
    ok = len(got) == len(want) and all(
        g[0] == w[0] and abs(g[1] - w[1]) <= tick for g, w in zip(got, want)
    )
    print(f"    {label:10} {'OK' if ok else 'MISMATCH'}  ({len(got)} packets)")
    if not ok:
        fails.append(label)
        for i, (g, w) in enumerate(zip(got, want)):
            if g != w:
                print(f"      #{i} ours={w[0].hex()[:40]} t={w[1]}")
                print(f"          got={g[0].hex()[:40]} t={g[1]}")
                break


def read_wiry(path):
    got = W.rdpcap(path)
    return list(zip([bytes(p) for p in got], got.times()))


def read_scapy(path):
    return [(bytes(p), float(p.time)) for p in S.rdpcap(path)]


def read_dpkt(path, pcapng, gz):
    import gzip

    opener = gzip.open if gz else open
    with opener(path, "rb") as fh:
        reader = dpkt.pcapng.Reader(fh) if pcapng else dpkt.pcap.Reader(fh)
        return [(bytes(buf), float(ts)) for ts, buf in reader]


def read_tshark(path):
    out = subprocess.run(
        [TSHARK, "-r", path, "-T", "fields", "-e", "frame.number"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if out.returncode != 0:
        return None, out.stderr.strip().splitlines()[:1]
    return len([line for line in out.stdout.splitlines() if line.strip()]), []


def main():
    pkts = packets()
    fails = []
    tmp = tempfile.mkdtemp(prefix="wiry-write-")

    for pcapng in (False, True):
        for nano in (False, True):
            for gz in (False, True):
                name = "c%s%s%s" % (
                    ".pcapng" if pcapng else ".pcap",
                    ".nano" if nano else "",
                    ".gz" if gz else "",
                )
                path = os.path.join(tmp, name + (".gz" if gz else ""))
                W.wrpcap(path, pkts, nano=nano, pcapng=pcapng, gz=gz)
                want, tick = expected(pkts, nano)
                print(f"  {name:20} {os.path.getsize(path):6} bytes")

                check("wiry", read_wiry(path), want, tick, fails)
                if S is not None:
                    check("scapy", read_scapy(path), want, tick, fails)
                if dpkt is not None:
                    check("dpkt", read_dpkt(path, pcapng, gz), want, tick, fails)
                if TSHARK is not None and not gz:
                    n, err = read_tshark(path)
                    ok = n == len(want)
                    print(f"    {'tshark':10} {'OK' if ok else 'MISMATCH'}  ({n} packets)")
                    if not ok:
                        fails.append("tshark " + name)
                        for line in err:
                            print(f"      {line}")

    if TSHARK is None:
        print("\n  tshark not on PATH; that half of the check did not run")
    if S is None:
        print("  scapy not installed; that half of the check did not run")
    if dpkt is None:
        print("  dpkt not installed; that half of the check did not run")

    print(f"\n=== SUMMARY ===\n  {len(fails)} mismatches")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
