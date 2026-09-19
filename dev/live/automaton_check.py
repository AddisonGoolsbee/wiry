"""Privileged check for the sockets a state machine listens on. Needs root.

Everything about an `Automaton` that is logic — states, transitions, timers,
actions, io events, what it replies with — is in `tests/test_automaton.py`,
driven from canned packets through `OfflineSocket` with no privileges at all.
What is left, and what is here, is whether the live sockets really carry frames
to and from a wire, and whether their threads stop when told.

    sudo .venv/bin/python dev/live/automaton_check.py [iface]

`iface` defaults to a loopback interface, which is enough for every check here:
a frame sent on loopback comes back.
"""

import sys
import threading
import time

import wiry as P
from wiry import ATMT, ICMP, IP, Automaton, Ether, L2ListenSocket, L2Socket

FAILED = []


def check(name, cond, detail=""):
    print(f"  {'ok  ' if cond else 'FAIL'}  {name}{' — ' + detail if detail else ''}")
    if not cond:
        FAILED.append(name)


def loopback():
    for info in P.interfaces():
        if info["loopback"]:
            return info["name"]
    return P.conf.iface


def probe(seq):
    return Ether() / IP(src="127.0.0.1", dst="127.0.0.1") / ICMP(seq=seq)


def check_listen_socket(iface):
    """A frame put on the wire reaches a listening socket's descriptor."""
    sock = L2ListenSocket(iface=iface, filter="icmp")
    try:
        time.sleep(0.3)  # libpcap needs a moment before the handle is live
        L2Socket(iface=iface).send(probe(0x4242))
        deadline = time.time() + 3
        seen = False
        while time.time() < deadline and not seen:
            if P.select_objects([sock], 0.2):
                pkt = sock.recv()
                seen = "ICMP" in pkt.layers() and pkt["ICMP"].seq == 0x4242
        check("a listening socket receives what a sending one sent", seen)
    finally:
        sock.close()
    check("closing a listening socket stops its capture", sock.closed)


def check_automaton_over_the_wire(iface):
    """The whole machine, with the wire in front of it instead of a capture."""

    class Waiter(Automaton):
        @ATMT.state(initial=1)
        def BEGIN(self):
            self.send(probe(0x1234))
            raise self.WAIT()

        @ATMT.state()
        def WAIT(self):
            pass

        def master_filter(self, pkt):
            return "ICMP" in pkt.layers() and pkt["ICMP"].seq == 0x1234

        @ATMT.receive_condition(WAIT)
        def got(self, pkt):
            raise self.END(pkt)

        @ATMT.timeout(WAIT, 5)
        def gave_up(self):
            raise self.END(None)

        @ATMT.state(final=1)
        def END(self, pkt):
            return pkt

    before = threading.active_count()
    m = Waiter(ll=lambda **k: L2Socket(iface=iface, **k),
               recvsock=lambda **k: L2ListenSocket(iface=iface,
                                                   filter="icmp", **k))
    got = m.run()
    check("a machine sends on the wire and its receive condition fires",
          got is not None, "timed out" if got is None else got.summary())
    m.destroy()
    for _ in range(50):
        if threading.active_count() <= before:
            break
        time.sleep(0.1)
    check("a finished machine leaves no thread behind",
          threading.active_count() <= before,
          f"{threading.active_count()} vs {before}")


def check_route_matches_the_kernel():
    """What `conf.route` answers, against what the host would really do."""
    import subprocess

    for dst in ("127.0.0.1", "8.8.8.8"):
        iface, src, gw = P.conf.route.route(dst)
        out = subprocess.run(["route", "-n", "get", dst] if sys.platform != "linux"
                             else ["ip", "route", "get", dst],
                             capture_output=True, text=True, check=False).stdout
        check(f"route({dst}) names the interface the kernel does",
              iface in out, f"wiry says {iface}; kernel said {out.strip()[:90]!r}")


def main(argv):
    iface = argv[1] if len(argv) > 1 else loopback()
    if not P.capture_available():
        sys.exit("built without the live feature")
    print(f"interface: {iface}")
    check_listen_socket(iface)
    check_automaton_over_the_wire(iface)
    check_route_matches_the_kernel()
    print(f"\n{len(FAILED)} failed" if FAILED else "\nall checks passed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
