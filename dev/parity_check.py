"""Differential check against Scapy, used as a development oracle.

This script is NOT part of the shipped test suite and its output is never
committed as fixtures. Scapy is GPL-2.0; comparing observable behaviour is fine,
but a vendored corpus mechanically derived from it is a licensing grey area we
stay out of. The shipped tests use hand-built RFC vectors instead.

Run: python dev/parity_check.py <pcap> [limit]
"""

import sys

import wiry as B

try:
    import scapy.all as S
    from scapy.config import conf as sconf

    sconf.verb = 0
except ImportError:
    sys.exit("scapy not installed; this is a dev-only oracle")


def hx(b):
    return b.hex()


def check_build():
    """Identical construction should produce identical bytes."""
    cases = [
        (
            B.Ether(dst="00:11:22:33:44:55", src="66:77:88:99:aa:bb")
            / B.IP(src="10.0.0.1", dst="10.0.0.2")
            / B.TCP(sport=1234, dport=80, flags="S", seq=42),
            S.Ether(dst="00:11:22:33:44:55", src="66:77:88:99:aa:bb")
            / S.IP(src="10.0.0.1", dst="10.0.0.2")
            / S.TCP(sport=1234, dport=80, flags="S", seq=42),
            "Ether/IP/TCP SYN",
        ),
        (
            B.IP(src="192.168.1.1", dst="8.8.8.8", ttl=32)
            / B.UDP(sport=5353, dport=53),
            S.IP(src="192.168.1.1", dst="8.8.8.8", ttl=32)
            / S.UDP(sport=5353, dport=53),
            "IP/UDP",
        ),
        (
            B.IP(src="1.2.3.4", dst="5.6.7.8") / B.ICMP(),
            S.IP(src="1.2.3.4", dst="5.6.7.8") / S.ICMP(),
            "IP/ICMP echo",
        ),
        (
            B.Ether() / B.ARP(psrc="10.0.0.1", pdst="10.0.0.2"),
            S.Ether() / S.ARP(psrc="10.0.0.1", pdst="10.0.0.2"),
            "Ether/ARP",
        ),
        (
            B.IPv6(src="2001:db8::1", dst="2001:db8::2") / B.TCP(dport=443),
            S.IPv6(src="2001:db8::1", dst="2001:db8::2") / S.TCP(dport=443),
            "IPv6/TCP",
        ),
    ]
    ok = fail = 0
    print("=== BUILD PARITY ===")
    for mine, theirs, label in cases:
        a, b = bytes(mine), bytes(theirs)
        if a == b:
            ok += 1
            print(f"  MATCH  {label}  ({len(a)} bytes)")
        else:
            fail += 1
            print(f"  DIFFER {label}")
            print(f"     wiry: {hx(a)}")
            print(f"     scapy   : {hx(b)}")
            for i, (x, y) in enumerate(zip(a, b)):
                if x != y:
                    print(f"     first difference at byte {i}: {x:#04x} vs {y:#04x}")
                    break
            if len(a) != len(b):
                print(f"     length {len(a)} vs {len(b)}")
    return ok, fail


def check_dissect(path, limit):
    """Dissecting the same capture should agree on layers and key fields."""
    print(f"\n=== DISSECT PARITY on {path} (first {limit}) ===")
    pl = B.rdpcap(path)
    n = min(limit, len(pl))

    agree_layers = 0
    disagree_layers = 0
    field_checks = 0
    field_bad = 0
    examples = []

    with S.PcapReader(path) as pr:
        for i in range(n):
            try:
                sp = next(pr)
            except StopIteration:
                break
            bp = pl[i]

            mine = [x for x in bp.layers() if x not in ("Raw", "Padding")]
            theirs = []
            cur = sp
            while cur is not None and cur.__class__.__name__ not in ("NoPayload",):
                nm = cur.__class__.__name__
                if nm not in ("Raw", "Padding"):
                    theirs.append(nm)
                cur = cur.payload if cur.payload else None

            # Compare only the prefix wiry claims to implement.
            known = set(B.known_layers())
            theirs_known = [t for t in theirs if t in known]
            common = min(len(mine), len(theirs_known))
            if mine[:common] == theirs_known[:common] and common > 0:
                agree_layers += 1
            else:
                disagree_layers += 1
                if len(examples) < 5:
                    examples.append((i, mine, theirs))

            for lname, fields in (
                ("IP", ["src", "dst", "ttl", "proto", "len", "id"]),
                ("TCP", ["sport", "dport", "seq", "ack", "window"]),
                ("UDP", ["sport", "dport", "len"]),
            ):
                if lname in mine and lname in theirs:
                    scls = {"IP": S.IP, "TCP": S.TCP, "UDP": S.UDP}[lname]
                    for f in fields:
                        try:
                            mv = getattr(bp[lname], f)
                            tv = getattr(sp[scls], f)
                        except Exception:
                            continue
                        field_checks += 1
                        if str(mv) != str(tv):
                            field_bad += 1
                            if len(examples) < 8:
                                examples.append(
                                    (i, f"{lname}.{f}", f"{mv!r} vs {tv!r}")
                                )

    print(f"  layer chains agreeing : {agree_layers}/{agree_layers + disagree_layers}")
    print(f"  field comparisons     : {field_checks - field_bad}/{field_checks} equal")
    if examples:
        print("  first divergences:")
        for e in examples[:8]:
            print(f"    packet {e[0]}: {e[1]}  {e[2] if len(e) > 2 else ''}")
    return agree_layers, disagree_layers, field_checks, field_bad


def check_roundtrip(path, limit):
    """Dissect then re-serialise must return the original bytes exactly."""
    print(f"\n=== ROUND-TRIP (dissect -> bytes) on first {limit} ===")
    pl = B.rdpcap(path)
    n = min(limit, len(pl))
    same = 0
    diff = 0
    for i in range(n):
        orig = pl.raw_at(i)
        got = bytes(pl[i])
        if orig == got:
            same += 1
        else:
            diff += 1
            if diff <= 3:
                print(f"  packet {i}: {len(orig)} vs {len(got)} bytes")
    print(f"  byte-identical: {same}/{same + diff}")
    return same, diff


if __name__ == "__main__":
    pcap = sys.argv[1] if len(sys.argv) > 1 else None
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 2000
    bok, bfail = check_build()
    if pcap:
        check_dissect(pcap, limit)
        check_roundtrip(pcap, limit)
    print(f"\nbuild parity: {bok} match, {bfail} differ")
