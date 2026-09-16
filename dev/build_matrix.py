"""Construction parity against scapy, enumerated rather than hand-picked.

The dissection harness in parity_check.py compares thousands of real packets,
which is why read-path bugs get caught. The write path had no equivalent, which
is how a payload could be dropped with a green suite. This enumerates the build
path: every layer alone, in realistic stacks, with defaults and with explicit
fields, and diffs the bytes against scapy.

Dev-only oracle. Never shipped, never used to generate fixtures.
Run: python dev/build_matrix.py [-v]
"""

import sys

import packetry as B

try:
    import scapy.all as S
    from scapy.config import conf

    conf.verb = 0
except ImportError:
    sys.exit("scapy not installed; this is a dev-only oracle")

VERBOSE = "-v" in sys.argv

# scapy fills these from the live interface, so both sides must be pinned or
# every comparison is a spurious mismatch (DEVIATIONS.md E9).
MAC = "00:11:22:33:44:55"
MAC2 = "66:77:88:99:aa:bb"


def cases():
    """(label, packetry packet, scapy packet) triples."""
    out = []

    def add(label, a, b):
        out.append((label, a, b))

    add("Ether", B.Ether(src=MAC2, dst=MAC), S.Ether(src=MAC2, dst=MAC))
    add("IP", B.IP(src="10.0.0.1", dst="10.0.0.2"), S.IP(src="10.0.0.1", dst="10.0.0.2"))
    add("IPv6", B.IPv6(src="2001:db8::1", dst="2001:db8::2"),
        S.IPv6(src="2001:db8::1", dst="2001:db8::2"))
    add("TCP", B.TCP(), S.TCP())
    add("UDP", B.UDP(), S.UDP())
    add("ICMP", B.ICMP(), S.ICMP())
    add("ARP", B.ARP(hwsrc=MAC2, psrc="10.0.0.1", hwdst=MAC, pdst="10.0.0.2"),
        S.ARP(hwsrc=MAC2, psrc="10.0.0.1", hwdst=MAC, pdst="10.0.0.2"))
    add("Dot1Q", B.Dot1Q(vlan=100), S.Dot1Q(vlan=100))

    add("IP fields", B.IP(src="1.2.3.4", dst="5.6.7.8", ttl=33, tos=8, id=7),
        S.IP(src="1.2.3.4", dst="5.6.7.8", ttl=33, tos=8, id=7))
    add("TCP fields", B.TCP(sport=1234, dport=80, seq=42, ack=7, window=1024),
        S.TCP(sport=1234, dport=80, seq=42, ack=7, window=1024))
    add("TCP flags letters", B.TCP(flags="SA"), S.TCP(flags="SA"))
    add("TCP flags int", B.TCP(flags=0x12), S.TCP(flags=0x12))
    add("UDP ports", B.UDP(sport=5353, dport=53), S.UDP(sport=5353, dport=53))
    add("ICMP fields", B.ICMP(type=8, code=0, id=99, seq=5),
        S.ICMP(type=8, code=0, id=99, seq=5))

    eth = dict(src=MAC2, dst=MAC)
    ip = dict(src="10.0.0.1", dst="10.0.0.2")
    add("Ether/IP/TCP", B.Ether(**eth) / B.IP(**ip) / B.TCP(dport=80),
        S.Ether(**eth) / S.IP(**ip) / S.TCP(dport=80))
    add("Ether/IP/UDP", B.Ether(**eth) / B.IP(**ip) / B.UDP(dport=53),
        S.Ether(**eth) / S.IP(**ip) / S.UDP(dport=53))
    add("Ether/IP/ICMP", B.Ether(**eth) / B.IP(**ip) / B.ICMP(),
        S.Ether(**eth) / S.IP(**ip) / S.ICMP())
    add("Ether/ARP",
        B.Ether(**eth) / B.ARP(hwsrc=MAC2, psrc="10.0.0.1", hwdst=MAC, pdst="10.0.0.2"),
        S.Ether(**eth) / S.ARP(hwsrc=MAC2, psrc="10.0.0.1", hwdst=MAC, pdst="10.0.0.2"))
    add("Ether/Dot1Q/IP/TCP",
        B.Ether(**eth) / B.Dot1Q(vlan=100) / B.IP(**ip) / B.TCP(),
        S.Ether(**eth) / S.Dot1Q(vlan=100) / S.IP(**ip) / S.TCP())
    v6 = dict(src="2001:db8::1", dst="2001:db8::2")
    add("Ether/IPv6/TCP", B.Ether(**eth) / B.IPv6(**v6) / B.TCP(dport=443),
        S.Ether(**eth) / S.IPv6(**v6) / S.TCP(dport=443))
    add("Ether/IPv6/UDP", B.Ether(**eth) / B.IPv6(**v6) / B.UDP(),
        S.Ether(**eth) / S.IPv6(**v6) / S.UDP())
    add("IP/UDP", B.IP(**ip) / B.UDP(), S.IP(**ip) / S.UDP())

    for load in (b"", b"a", b"hello world", bytes(range(256)), b"\x00" * 64):
        tag = f"{len(load)}B"
        add(f"Ether/IP/TCP/Raw({tag})",
            B.Ether(**eth) / B.IP(**ip) / B.TCP() / B.Raw(load=load),
            S.Ether(**eth) / S.IP(**ip) / S.TCP() / S.Raw(load=load))
        add(f"Ether/IP/UDP/Raw({tag})",
            B.Ether(**eth) / B.IP(**ip) / B.UDP() / B.Raw(load=load),
            S.Ether(**eth) / S.IP(**ip) / S.UDP() / S.Raw(load=load))
    add("positional bytes",
        B.Ether(**eth) / B.IP(**ip) / B.TCP() / b"hi",
        S.Ether(**eth) / S.IP(**ip) / S.TCP() / b"hi")
    add("ICMP with payload",
        B.IP(**ip) / B.ICMP() / B.Raw(load=b"ping"),
        S.IP(**ip) / S.ICMP() / S.Raw(load=b"ping"))

    add("TCP MSS",
        B.IP(**ip) / B.TCP(options=[("MSS", 1460)]),
        S.IP(**ip) / S.TCP(options=[("MSS", 1460)]))
    add("TCP SYN option block",
        B.IP(**ip) / B.TCP(options=[("MSS", 1460), ("SAckOK", None), ("NOP", None),
                                    ("WScale", 7)]),
        S.IP(**ip) / S.TCP(options=[("MSS", 1460), ("SAckOK", ""), ("NOP", None),
                                    ("WScale", 7)]))
    add("TCP Timestamp",
        B.IP(**ip) / B.TCP(options=[("Timestamp", (111, 222))]),
        S.IP(**ip) / S.TCP(options=[("Timestamp", (111, 222))]))
    add("TCP options + payload",
        B.IP(**ip) / B.TCP(options=[("MSS", 536)]) / B.Raw(load=b"x" * 10),
        S.IP(**ip) / S.TCP(options=[("MSS", 536)]) / S.Raw(load=b"x" * 10))

    return out


def check_bytes():
    print("=== BUILD BYTE PARITY ===")
    ok = bad = err = 0
    failures = []
    for label, mine, theirs in cases():
        try:
            a = bytes(mine)
        except Exception as exc:
            err += 1
            print(f"  ERROR  {label}: packetry raised {type(exc).__name__}: {exc}")
            continue
        try:
            b = bytes(theirs)
        except Exception as exc:
            print(f"  SKIP   {label}: scapy raised {type(exc).__name__}")
            continue
        if a == b:
            ok += 1
            if VERBOSE:
                print(f"  MATCH  {label} ({len(a)}B)")
        else:
            bad += 1
            failures.append(label)
            print(f"  DIFFER {label}  ours={len(a)}B scapy={len(b)}B")
            first = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), None)
            if first is not None:
                print(f"         first difference at byte {first}: "
                      f"{a[first]:#04x} vs {b[first]:#04x}")
            print(f"         ours : {a.hex()}")
            print(f"         scapy: {b.hex()}")
    print(f"\n  {ok} match, {bad} differ, {err} errored")
    return ok, bad, err, failures


def check_roundtrip():
    """Bytes we produce must dissect back to the values we set."""
    print("\n=== BUILD ROUND-TRIP (build -> dissect -> compare) ===")
    checks = [
        ("IP", dict(src="1.2.3.4", dst="5.6.7.8", ttl=33),
         lambda: B.Ether(src=MAC2, dst=MAC) / B.IP(src="1.2.3.4", dst="5.6.7.8", ttl=33)
         / B.TCP()),
        ("TCP", dict(sport=1234, dport=80, window=1024),
         lambda: B.Ether() / B.IP() / B.TCP(sport=1234, dport=80, window=1024)),
        ("UDP", dict(sport=5353, dport=53),
         lambda: B.Ether() / B.IP() / B.UDP(sport=5353, dport=53)),
        ("ICMP", dict(type=8, id=99, seq=5),
         lambda: B.Ether() / B.IP() / B.ICMP(type=8, id=99, seq=5)),
        ("ARP", dict(psrc="10.0.0.1", pdst="10.0.0.2"),
         lambda: B.Ether() / B.ARP(psrc="10.0.0.1", pdst="10.0.0.2")),
        ("Dot1Q", dict(vlan=100),
         lambda: B.Ether() / B.Dot1Q(vlan=100) / B.IP() / B.TCP()),
        ("IPv6", dict(src="2001:db8::1", dst="2001:db8::2", hlim=5),
         lambda: B.Ether() / B.IPv6(src="2001:db8::1", dst="2001:db8::2", hlim=5)
         / B.TCP()),
    ]
    ok = bad = 0
    for layer, expected, make in checks:
        pkt = make()
        back = B.Ether(bytes(pkt))
        for field, want in expected.items():
            got = getattr(back[layer], field)
            if str(got) == str(want):
                ok += 1
            else:
                bad += 1
                print(f"  {layer}.{field}: built {want!r} but read back {got!r}")
    pkt = B.Ether() / B.IP() / B.UDP() / B.Raw(load=b"hello")
    raw = bytes(pkt)
    back = B.Ether(raw)
    for label, cond in [
        ("payload survives", raw.endswith(b"hello")),
        ("udp len", back[B.UDP].len == 8 + 5),
        ("ip len", back[B.IP].len == len(raw) - 14),
    ]:
        if cond:
            ok += 1
        else:
            bad += 1
            print(f"  payload: {label} FAILED")
    print(f"\n  {ok} round-trip checks passed, {bad} failed")
    return ok, bad


if __name__ == "__main__":
    o, b, e, failures = check_bytes()
    ro, rb = check_roundtrip()
    print("\n=== SUMMARY ===")
    print(f"  byte parity : {o} match, {b} differ, {e} errored")
    print(f"  round-trip  : {ro} passed, {rb} failed")
    if failures:
        print("  differing cases: " + ", ".join(failures))
    sys.exit(1 if (b or e or rb) else 0)
