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

    # arping over the pair's own /24, where exactly one address answers. This
    # is where E9's send-time fill earns its keep: a request carrying hwsrc
    # 00:00:00:00:00:00 and psrc 0.0.0.0 gets no reply from anyone.
    found, _ = P.arping("10.99.0.0/24", timeout=3, iface=veth, verbose=0)
    addrs = {r[ARP].psrc for _, r in found}
    check("arping found the peer and nobody else", addrs == {"10.99.0.2"},
          str(sorted(addrs)))

    mac = P.getmacbyip("10.99.0.2", iface=veth, timeout=3)
    check("getmacbyip agrees with the sweep",
          mac is not None and mac in {r[ARP].hwsrc for _, r in found},
          str(mac))
    check("a multicast group needs no request at all",
          P.getmacbyip("224.0.0.1") == "01:00:5e:00:00:01")

    loop_ans, loop_unans = P.srloop(IP(dst="10.99.0.2") / ICMP(), count=3,
                                    inter=0.1, timeout=3, iface=veth,
                                    verbose=0)
    check("srloop collected three rounds",
          len(loop_ans) == 3 and not loop_unans,
          f"{len(loop_ans)} answered, {len(loop_unans)} silent")

    # The peer is one hop away, so it answers the first probe itself and the
    # rest of the sweep goes unanswered.
    trace, trace_unans = P.traceroute("10.99.0.2", maxttl=3, dport=9,
                                      iface=veth, timeout=2, verbose=0)
    hops = trace.get_trace().get("10.99.0.2", {})
    check("traceroute reached the peer",
          any(final for _, final in hops.values()), str(hops))
    check("the sweep is fully accounted for",
          len(trace) + len(trace_unans) == 3,
          f"{len(trace)} + {len(trace_unans)}")

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
