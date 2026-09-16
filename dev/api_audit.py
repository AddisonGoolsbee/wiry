"""Audit our API surface against scapy's, layer by layer.

Dev-only oracle. Never shipped, never used to generate fixtures.
Run: python dev/api_audit.py
"""

import sys

import blitzpkt as B

try:
    import scapy.all as S
    from scapy.config import conf

    conf.verb = 0
except ImportError:
    sys.exit("scapy not installed; this is a dev-only audit")

# Our layer name -> scapy class. Names match where both implement the protocol.
PAIRS = [
    ("Ether", S.Ether),
    ("Dot1Q", S.Dot1Q),
    ("ARP", S.ARP),
    ("IP", S.IP),
    ("IPv6", S.IPv6),
    ("TCP", S.TCP),
    ("UDP", S.UDP),
    ("ICMP", S.ICMP),
    ("DNS", S.DNS),
    ("BOOTP", S.BOOTP),
    ("DHCP", S.DHCP),
]


def scapy_fields(cls):
    return [f.name for f in cls.fields_desc]


def audit_fields():
    print("=== FIELD NAME PARITY ===")
    total_missing = total_extra = 0
    for name, cls in PAIRS:
        try:
            ours = B._b.layer_fields(name)
        except Exception as exc:
            print(f"  {name:8} ERROR {exc}")
            continue
        theirs = scapy_fields(cls)
        missing = [f for f in theirs if f not in ours]
        extra = [f for f in ours if f not in theirs]
        total_missing += len(missing)
        total_extra += len(extra)
        status = "OK" if not missing and not extra else ""
        print(f"  {name:8} ours={len(ours):3} scapy={len(theirs):3}  {status}")
        if missing:
            print(f"           MISSING: {', '.join(missing)}")
        if extra:
            print(f"           EXTRA  : {', '.join(extra)}")
    print(f"\n  total missing fields: {total_missing}, extra: {total_extra}")
    return total_missing


def audit_defaults():
    """Compare the bytes a bare layer produces."""
    print("\n=== DEFAULT-CONSTRUCTION PARITY (bare layer) ===")
    diff = 0
    for name, cls in PAIRS:
        layer = getattr(B, name, None)
        if layer is None:
            continue
        try:
            a = bytes(layer())
        except Exception as exc:
            print(f"  {name:8} ours raised {type(exc).__name__}: {exc}")
            diff += 1
            continue
        try:
            b = bytes(cls())
        except Exception:
            print(f"  {name:8} scapy raised; skipped")
            continue
        if a == b:
            print(f"  {name:8} MATCH ({len(a)} bytes)")
        else:
            diff += 1
            print(f"  {name:8} DIFFER ours={len(a)}B scapy={len(b)}B")
            print(f"           ours : {a.hex()}")
            print(f"           scapy: {b.hex()}")
    print(f"\n  layers differing on defaults: {diff}")
    return diff


def audit_methods():
    print("\n=== PACKET METHOD SURFACE ===")
    ours = {m for m in dir(B.Packet) if not m.startswith("_")}
    theirs = {m for m in dir(S.Packet) if not m.startswith("_")}
    # Methods that are meaningless without live capture, deliberately out of scope.
    live = {
        "answers", "hashret", "send", "sendp", "sr", "sr1", "srp", "srp1",
        "sniff", "route", "src", "dst", "psdump", "pdfdump", "canvas_dump",
        "fuzz", "command", "decode_payload_as", "voidpayload",
    }
    missing = sorted(theirs - ours - live)
    print(f"  ours: {len(ours)}  scapy: {len(theirs)}")
    print(f"  missing (excluding live-capture and rendering): {len(missing)}")
    for m in missing:
        print(f"    {m}")
    return len(missing)


if __name__ == "__main__":
    mf = audit_fields()
    md = audit_defaults()
    mm = audit_methods()
    print("\n=== SUMMARY ===")
    print(f"  missing fields   : {mf}")
    print(f"  default mismatches: {md}")
    print(f"  missing methods  : {mm}")
