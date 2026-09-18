"""Privileged round-trip checks for the active tools. Needs root and a network.

The arithmetic these tools are made of — the TTL sweep, the trace grouping, the
presentation, the CIDR expansion, the multicast mapping — is all in
`tests/test_tools.py`, driven from canned packets with no privileges at all.
What is left, and what is here, is whether real routers and real hosts answer
the probes that logic builds.

    sudo .venv/bin/python dev/live/tools_check.py [target] [--net 10.0.0.0/24]

`target` defaults to 1.1.1.1, and the sweep to the /24 around the outgoing
interface's own address.
"""

import ipaddress
import sys
import time

import wiry as P
from wiry import ARP, ICMP, IP

FAILED = []


def check(name, cond, detail=""):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}  {detail}")
    if not cond:
        FAILED.append(name)


def local_net(iface):
    """The /24 around the interface's own address, which is the range a sweep
    on an ordinary LAN is asking about."""
    addr = P.get_if_addr(iface)
    if addr == "0.0.0.0":
        return None
    return str(ipaddress.ip_network(f"{addr}/24", strict=False))


def check_hwaddr(iface):
    print(f"=== hardware address of {iface} ===")
    try:
        mac = P.get_if_hwaddr(iface)
    except ValueError as exc:
        check("interface reports a hardware address", False, str(exc))
        return
    octets = mac.split(":")
    check("six octets", len(octets) == 6, mac)
    check("not all zero", any(int(o, 16) for o in octets), mac)


def check_arping(net, iface):
    print(f"=== arping {net} ===")
    if net is None:
        check("interface has an address to sweep from", False)
        return None
    t0 = time.monotonic()
    answered, unanswered = P.arping(net, timeout=3, iface=iface, verbose=0)
    print(f"  {len(answered)} answered, {len(unanswered)} silent, "
          f"{time.monotonic() - t0:.1f}s")
    check("something answered", len(answered) > 0,
          "an empty LAN, or hwsrc/psrc are not being filled (E9)")
    inside = ipaddress.ip_network(net)
    for _, reply in answered:
        who, mac = reply[ARP].psrc, reply[ARP].hwsrc
        check(f"{who} is inside the swept range",
              ipaddress.ip_address(who) in inside)
        check(f"{who} gave a real hardware address",
              any(int(o, 16) for o in mac.split(":")), mac)
    return answered[0][1][ARP].psrc if answered else None


def check_getmacbyip(addr, iface):
    print("=== getmacbyip ===")
    # RFC 1112 §6.4, computed rather than asked about: no privilege involved,
    # and it must agree with the unprivileged unit test.
    check("a multicast group maps without touching the wire",
          P.getmacbyip("224.0.0.1") == "01:00:5e:00:00:01")
    if addr is None:
        return
    first = P.getmacbyip(addr, iface=iface, timeout=3)
    check(f"{addr} answered", first is not None, str(first))
    # No cache: the second call asks again and must get the same answer.
    second = P.getmacbyip(addr, iface=iface, timeout=3)
    check("a second lookup agrees with the first", first == second,
          f"{first} then {second}")


def check_traceroute(target, iface, maxttl):
    print(f"=== traceroute {target} ===")
    result, unanswered = P.traceroute(target, maxttl=maxttl, iface=iface,
                                     timeout=3, verbose=0)
    result.show()
    trace = result.get_trace()
    check("the target has a trace", target in trace, str(list(trace)))
    hops = trace.get(target, {})
    check("more than one hop answered", len(hops) > 1, f"{len(hops)} hops")
    # The invariant the whole sweep rests on: `answers.rs` pairs an error with
    # the probe whose IP id its quote carries, so one TTL cannot collect two
    # hops and two TTLs cannot collect one reply by accident.
    check("each answered TTL got its own hop",
          len(hops) == len({ttl for ttl in hops}), str(sorted(hops)))
    check("every TTL is inside the sweep",
          all(1 <= ttl <= maxttl for ttl in hops), str(sorted(hops)))
    check("answered plus unanswered is the whole sweep",
          len(result) + len(unanswered) == maxttl,
          f"{len(result)} + {len(unanswered)} != {maxttl}")
    final = [ttl for ttl, (_, is_final) in hops.items() if is_final]
    print(f"  reached the target at TTL {min(final)}" if final
          else "  the target itself never answered")


def check_srloop(target, iface):
    print(f"=== srloop {target} ===")
    answered, unanswered = P.srloop(IP(dst=target) / ICMP(), count=3, inter=0.2,
                                   timeout=3, iface=iface, verbose=0)
    check("three rounds were collected", len(answered) + len(unanswered) == 3,
          f"{len(answered)} answered, {len(unanswered)} silent")
    check("the echo replies came back", len(answered) > 0)
    for _, reply in answered:
        check("reply is an echo reply",
              ICMP in reply and reply[ICMP].type == 0, str(reply.layers()))


def check_loose_matching(target, iface):
    print("=== conf.checkIPaddr ===")
    saved = P.conf.checkIPaddr
    try:
        P.conf.checkIPaddr = False
        answer = P.sr1(IP(dst=target) / ICMP(), timeout=3, iface=iface,
                       verbose=0)
        check("a reply still matches with the address check off",
              answer is not None)
    finally:
        P.conf.checkIPaddr = saved


def main(argv):
    if not P.capture_available():
        sys.exit("built without the live feature; see dev/live/README.md")

    target = "1.1.1.1"
    net = None
    rest = list(argv)
    if "--net" in rest:
        i = rest.index("--net")
        net = rest[i + 1]
        del rest[i:i + 2]
    if rest:
        target = rest[0]

    iface = P.conf.iface
    print(f"interface {iface}, route to {target}: "
          f"{P.conf.route.route(target)}\n")

    check_hwaddr(iface)
    answered_addr = check_arping(net or local_net(iface), iface)
    check_getmacbyip(answered_addr, iface)
    check_traceroute(target, iface, 8)
    check_srloop(target, iface)
    check_loose_matching(target, iface)

    print()
    if FAILED:
        sys.exit(f"{len(FAILED)} failed: {', '.join(FAILED)}")
    print("all checks passed")


if __name__ == "__main__":
    main(sys.argv[1:])
