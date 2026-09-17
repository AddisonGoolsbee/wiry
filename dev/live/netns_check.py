"""Privileged round-trip checks on an isolated veth pair. Linux, root.

Driven by dev/live/netns.sh, which creates the pair. Not part of the shipped
suite: it needs root and a real interface.
"""

import sys
import time

import wiry as P
from wiry import ARP, Ether, ICMP, IP, Raw, UDP

FAILED = []


def check(name, cond, detail=""):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}  {detail}")
    if not cond:
        FAILED.append(name)


def main(veth):
    if not P.capture_available():
        sys.exit("built without the live feature; see dev/live/README.md")

    print(f"=== {veth} ===")
    check("interface is listed", veth in P.get_if_list())

    frame = bytes(
        Ether(dst="02:00:00:00:00:02", src="02:00:00:00:00:01")
        / IP(src="10.99.0.1", dst="10.99.0.2")
        / UDP(sport=4444, dport=4445)
        / Raw(load=b"wiry-netns-probe")
    )

    # Capture must be open before sending, or a fast frame is missed.
    s = P.AsyncSniffer(iface=veth, filter="udp port 4445", count=1, timeout=5)
    s.start()
    time.sleep(0.3)
    P.sendp(Ether(frame), iface=veth)
    s.join()
    got = s.results

    check("captured exactly one frame", len(got) == 1, f"got {len(got)}")
    if len(got) == 1:
        check("bytes are identical", bytes(got[0]) == frame)
        check("dissects to the sent stack", got[0].layers()[:4]
              == ["Ether", "IP", "UDP", "Raw"], str(got[0].layers()))
        check("payload survived", got[0][Raw].load == b"wiry-netns-probe")

    # A filter that cannot match must return nothing rather than hang.
    t0 = time.monotonic()
    none = P.sniff(iface=veth, filter="tcp port 9", timeout=2)
    check("non-matching filter terminates on timeout",
          len(none) == 0 and time.monotonic() - t0 < 5,
          f"{time.monotonic() - t0:.1f}s")

    # sr1 against the peer, which the kernel answers from the namespace.
    ans = P.sr1(IP(dst="10.99.0.2") / ICMP(), timeout=3, iface=veth)
    check("sr1 got an ICMP echo reply",
          ans is not None and ICMP in ans and ans[ICMP].type == 0,
          "no answer" if ans is None else str(ans.layers()))

    # srp for ARP, which does not need layer-3 routing.
    arp = P.srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="10.99.0.2"),
                 timeout=3, iface=veth)
    check("srp1 got an ARP reply",
          arp is not None and ARP in arp and arp[ARP].op == 2,
          "no answer" if arp is None else str(arp.layers()))

    # Stopping a sniffer that will never see traffic must return promptly.
    s2 = P.AsyncSniffer(iface=veth, filter="tcp port 9")
    s2.start()
    time.sleep(0.2)
    t0 = time.monotonic()
    s2.stop()
    check("stop() returns promptly", time.monotonic() - t0 < 2,
          f"{time.monotonic() - t0:.2f}s")

    print()
    if FAILED:
        sys.exit(f"{len(FAILED)} failed: {', '.join(FAILED)}")
    print("all checks passed")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "pkt0")
