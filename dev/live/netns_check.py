"""Privileged round-trip checks on an isolated veth pair. Linux, root.

Driven by dev/live/netns.sh, which creates the pair. Not part of the shipped
suite: it needs root and a real interface.
"""

import os
import signal
import sys
import threading
import time

import wiry as P
from wiry import ARP, Ether, ICMP, IP, Raw, UDP

FAILED = []


def check(name, cond, detail=""):
    # Flushed, because the next line may be the one that hangs and an
    # unflushed buffer would lose every result before it.
    print(f"  {'PASS' if cond else 'FAIL'}  {name}  {detail}", flush=True)
    if not cond:
        FAILED.append(name)


def timed(seconds, fn, *args, **kw):
    """Runs fn on a worker with a deadline. A capture that never returns is
    the failure this harness exists to catch, and a wall-clock assertion made
    after the call cannot catch it."""
    out, err = [], []

    def go():
        try:
            out.append(fn(*args, **kw))
        except BaseException as e:
            err.append(e)

    t = threading.Thread(target=go, daemon=True)
    t0 = time.monotonic()
    t.start()
    t.join(seconds)
    if t.is_alive():
        return None, seconds, TimeoutError(f"still running after {seconds}s")
    return (out[0] if out else None), time.monotonic() - t0, (err[0] if err else None)


def main(veth):
    if not P.capture_available():
        sys.exit(P.capture_backend()["reason"])
    print(f"=== {veth} :: {P.capture_backend()['version']} ===", flush=True)
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

    # A filter that cannot match must return nothing rather than hang. This is
    # the check that caught libpcap's read timeout not being a bound on Linux:
    # pcap_next_ex waits for a frame there however the timeout is set, so the
    # deadline was only ever honoured on an interface that had traffic.
    none, took, err = timed(15, P.sniff, iface=veth, filter="tcp port 9",
                            timeout=2)
    check("a silent interface still honours the deadline",
          err is None and none is not None and len(none) == 0 and took < 5,
          f"{took:.1f}s, asked for 2" + (f", {err!r}" if err else ""))

    # The same, with a count it will never reach.
    _, took, err = timed(15, P.sniff, iface=veth, filter="tcp port 9",
                         count=5, timeout=2)
    check("an unreachable count still honours the deadline",
          err is None and took < 5, f"{took:.1f}s" + (f", {err!r}" if err else ""))

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
    _, took, err = timed(15, s2.stop)
    check("stop() returns promptly on a silent interface",
          err is None and took < 2, f"{took:.2f}s" + (f", {err!r}" if err else ""))

    # An unbounded sniff must answer Ctrl-C. It can only do that between reads,
    # so a read that never returns is a capture that cannot be interrupted.
    threading.Thread(
        target=lambda: (time.sleep(1.0), os.kill(os.getpid(), signal.SIGINT)),
        daemon=True,
    ).start()
    t0 = time.monotonic()
    try:
        P.sniff(iface=veth, filter="tcp port 9")
        check("an unbounded sniff answers Ctrl-C", False, "returned by itself")
    except KeyboardInterrupt:
        check("an unbounded sniff answers Ctrl-C",
              time.monotonic() - t0 < 5, f"{time.monotonic() - t0:.2f}s")

    print()
    if FAILED:
        sys.exit(f"{len(FAILED)} failed: {', '.join(FAILED)}")
    print("all checks passed")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "pkt0")
