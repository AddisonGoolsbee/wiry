"""The active tools: traceroute, arping, the sr loops, and address lookup.

Every one of these is `sr`/`srp` plus arithmetic. The arithmetic is kept here,
in plain functions over plain data — which probes to build, which reply belongs
to which hop, what to print — so it is exercised from a canned list of packets
with no interface, no privileges and no root. Only the exchange itself needs
the ``live`` feature, and it raises ``CaptureUnavailable`` without it.

Nothing here runs on a thread. A Rust capture thread calling into Python after
finalisation segfaults, so the loops below are ordinary synchronous loops:
`sr` already answers Ctrl-C from inside a round, and these answer it between
rounds by returning what they have collected so far.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from typing import Any, Callable, Iterable, Optional

from . import ARP, ICMP, IP, TCP, Ether
from .capture import conf, sr, srp, srp1

__all__ = [
    "traceroute", "TracerouteResult", "arping", "srloop", "srploop",
    "getmacbyip",
]

# RFC 792 and RFC 1812 §4.3.2.3: the messages that quote the datagram which
# provoked them, which is the same set `answers.rs` matches on.
_ICMP_ERRORS = {
    3: "dest-unreach",
    4: "source-quench",
    5: "redirect",
    11: "time-exceeded",
    12: "param-problem",
}

#: The widest range `arping` will sweep, in addresses.
MAX_SWEEP = 65536


def _verbose(verbose: Optional[int]) -> int:
    return conf.verb if verbose is None else verbose


def _nap(seconds: float) -> None:
    """Sleep in the 250 ms slices the capture loop uses, so a pause between
    rounds is no less interruptible than a round is."""
    end = time.monotonic() + max(0.0, float(seconds))
    while True:
        left = end - time.monotonic()
        if left <= 0:
            return
        time.sleep(min(left, 0.25))


def _resolve(target: Any) -> str:
    """A hostname as an address. Addresses pass through untouched, so nothing
    here reaches the resolver unless a name was actually given.

    Resolution belongs to the tool, not to the field: `IP(dst="example.com")`
    is still refused (DEVIATIONS E13), because that would put DNS in the build
    path of every packet.
    """
    text = str(target)
    try:
        ipaddress.ip_address(text)
        return text
    except ValueError:
        return socket.gethostbyname(text)


def _targets(target: Any) -> list:
    if isinstance(target, (str, bytes)):
        return [_resolve(target)]
    return [_resolve(t) for t in target]


def _trace_filter(proto: str) -> str:
    """The BPF a trace wants: an error from a router, or the target answering.

    Narrow on purpose. The Rust-side matcher decides what actually answers
    what; this only keeps the interface's other traffic out of the capture.
    """
    errors = " or ".join(f"icmp[0] = {t}" for t in _ICMP_ERRORS)
    return f"(icmp and ({errors})) or {proto}"


def _probes(targets: list, minttl: int, maxttl: int, dport: int,
            sport: Optional[int], l4: Any) -> list:
    """One probe per target per TTL.

    ``IP.id`` carries the TTL. wiry has no field generators (E13), so without
    it every probe of a sweep would be byte-identical but for the TTL — and the
    TTL is not part of a reply key, while the quoted IP id is. Every hop's
    time-exceeded would then pair with the first probe and the trace would be
    one row long.
    """
    if not 1 <= minttl <= maxttl <= 255:
        raise ValueError(
            f"a TTL sweep runs from 1 to 255, not {minttl} to {maxttl}"
        )
    out = []
    for dst in targets:
        for ttl in range(minttl, maxttl + 1):
            if l4 is None:
                upper = TCP(dport=dport, flags="S")
                if sport is not None:
                    upper.sport = sport
            else:
                upper = l4.copy()
            out.append(IP(dst=dst, ttl=ttl, id=ttl) / upper)
    return out


def _hop(snd: Any, rcv: Any) -> tuple:
    """One row of a trace: ``(target, ttl, address, final, what)``."""
    target = snd[IP].dst
    who = rcv[IP].src if IP in rcv else "?"
    final = who == target
    if ICMP in rcv:
        kind = rcv[ICMP].type
        what = f"ICMP {_ICMP_ERRORS.get(kind, f'type {kind}')}"
    elif TCP in rcv:
        what = f"TCP {rcv[TCP].flags}"
    else:
        what = rcv.summary()
    return target, snd[IP].ttl, who, final, what


class TracerouteResult:
    """A finished trace, grouped by target.

    Presentation only: it is built from ``(sent, received)`` pairs and reads
    nothing but those packets, so a trace can be assembled and shown from a
    canned list with no network anywhere near it.
    """

    __slots__ = ("res",)

    def __init__(self, res: Iterable = ()):
        self.res = list(res)

    def __len__(self) -> int:
        return len(self.res)

    def __iter__(self):
        return iter(self.res)

    def __getitem__(self, i: Any) -> Any:
        return self.res[i]

    def get_trace(self) -> dict:
        """``{target: {ttl: (address, is_final)}}``, as scapy's returns."""
        out: dict = {}
        for snd, rcv in self.res:
            target, ttl, who, final, _ = _hop(snd, rcv)
            out.setdefault(target, {})[ttl] = (who, final)
        return out

    def _rows(self) -> dict:
        out: dict = {}
        for snd, rcv in self.res:
            target, ttl, who, final, what = _hop(snd, rcv)
            out.setdefault(target, {})[ttl] = (who, final, what)
        return out

    def show_str(self) -> str:
        """The trace as text, one block per target.

        A TTL between two answered hops that nobody answered is a ``*`` row, so
        a gap in the middle of a path is visible rather than implied by a jump
        in the numbering. Nothing past the last answer is shown: the probes
        beyond it are in ``unanswered``, where they can be counted.
        """
        blocks = []
        for target, hops in self._rows().items():
            lines = [f"traceroute to {target}"]
            for ttl in range(min(hops), max(hops) + 1):
                row = hops.get(ttl)
                if row is None:
                    lines.append(f"{ttl:>3}  *")
                    continue
                who, final, what = row
                mark = "  <- target" if final else ""
                lines.append(f"{ttl:>3}  {who:<16} {what}{mark}")
            blocks.append("\n".join(lines))
        return "\n\n".join(blocks) + ("\n" if blocks else "")

    def show(self) -> None:
        print(self.show_str(), end="")

    def summary(self) -> str:
        return "\n".join(f"{s.summary()} ==> {r.summary()}" for s, r in self.res)

    def nsummary(self) -> None:
        for i, (s, r) in enumerate(self.res):
            print(f"{i:04d} {s.summary()} ==> {r.summary()}")

    def __repr__(self) -> str:
        return f"<TracerouteResult: {len(self.res)} hops>"


def traceroute(target: Any, dport: int = 80, minttl: int = 1, maxttl: int = 30,
               sport: Optional[int] = None, l4: Any = None,
               filter: Optional[str] = None, timeout: float = 2,
               iface: Any = None, verbose: Optional[int] = None,
               **kwargs: Any) -> tuple:
    """Trace the path to one or more targets.

    One `sr` over the whole TTL sweep, not one exchange per hop: every probe
    goes out before any reply is waited for, so a thirty-hop trace costs one
    timeout rather than thirty. ``(TracerouteResult, unanswered)`` comes back.

    The default probe is a TCP SYN to ``dport``; ``l4=`` replaces it with any
    layer, and each copy is stacked under its own ``IP``.
    """
    targets = _targets(target)
    probes = _probes(targets, minttl, maxttl, dport, sport, l4)
    proto = (l4.layers()[0] if l4 is not None else "TCP").lower()
    answered, unanswered = sr(
        probes, filter=_trace_filter(proto) if filter is None else filter,
        timeout=timeout, iface=iface, verbose=0, **kwargs,
    )
    result = TracerouteResult(answered)
    if _verbose(verbose):
        result.show()
    return result, unanswered


def _hosts(net: Any) -> list:
    """The addresses an ARP sweep should ask about.

    A CIDR is expanded here, with the standard library, rather than by the
    address generators E13 rules out: the expansion is this function's own and
    never reaches a field, so `IP(dst="10.0.0.0/24")` is still one packet.
    """
    def refuse(n: int) -> None:
        if n > MAX_SWEEP:
            raise ValueError(
                f"{n} addresses is more than arping will sweep "
                f"({MAX_SWEEP}); ask about a smaller range"
            )

    if not isinstance(net, (str, bytes)):
        hosts = [str(h) for h in net]
        refuse(len(hosts))
        return hosts
    if "/" not in str(net):
        return [str(net)]
    network = ipaddress.ip_network(str(net), strict=False)
    if network.version != 4:
        raise ValueError("ARP asks about IPv4 addresses only")
    # Counted before it is walked: a /8 is sixteen million addresses, and
    # listing them to find out how many there are is the hang this prevents.
    refuse(network.num_addresses - (2 if network.prefixlen < 31 else 0))
    return [str(h) for h in network.hosts()]


def arping(net: Any, timeout: float = 2, iface: Any = None,
           verbose: Optional[int] = None, cache: int = 0,
           **kwargs: Any) -> tuple:
    """Ask who has each address in ``net``, and collect the replies.

    ``net`` is an address, a CIDR block, or any iterable of addresses. The
    request's own ``hwsrc`` and ``psrc`` are filled from the outgoing interface
    at send time (E9), so the sweep asks on its own behalf rather than on
    0.0.0.0's — which is the whole difference between getting answers and not.
    """
    probes = [
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=h) for h in _hosts(net)
    ]
    answered, unanswered = srp(
        probes, filter="arp and arp[6:2] = 2", timeout=timeout, iface=iface,
        verbose=0, **kwargs,
    )
    if _verbose(verbose):
        print(arping_str(answered), end="")
    return answered, unanswered


def arping_str(answered: Iterable) -> str:
    """Who answered, one per line."""
    rows = [f"  {r[ARP].hwsrc}  {r[ARP].psrc}" for _, r in answered]
    return "\n".join(rows) + ("\n" if rows else "")


def _round_str(answered: list, unanswered: list, prn: Optional[Callable],
               prnfail: Optional[Callable]) -> str:
    """One round's report. ``prn`` sees ``(sent, received)`` and ``prnfail``
    the sent packet alone, as scapy's do; either returning ``None`` prints
    nothing for that packet."""
    lines = []
    for snd, rcv in answered:
        text = rcv.summary() if prn is None else prn(snd, rcv)
        if text is not None:
            lines.append(f"RECV {text}")
    for snd in unanswered:
        text = f"fail {snd.summary()}" if prnfail is None else prnfail(snd)
        if text is not None:
            lines.append(str(text))
    return "\n".join(lines) + ("\n" if lines else "")


def _loop(exchange: Callable, count: Optional[int], inter: float,
          prn: Optional[Callable], prnfail: Optional[Callable],
          verbose: int, store: bool) -> tuple:
    """Repeat one exchange, reporting each round.

    ``exchange`` is the whole of the I/O, which is what lets the loop be driven
    from a stand-in. ``count=None`` runs until interrupted, and an interrupt
    returns what has been collected rather than losing it.
    """
    answered: list = []
    unanswered: list = []
    n = 0
    try:
        while count is None or n < count:
            n += 1
            got, lost = exchange()
            if store:
                answered += list(got)
                unanswered += list(lost)
            if verbose:
                print(_round_str(list(got), list(lost), prn, prnfail), end="")
            if count is None or n < count:
                _nap(inter)
    except KeyboardInterrupt:
        pass
    return answered, unanswered


def _srloop(fn: Callable, pkts: Any, prn: Optional[Callable],
            prnfail: Optional[Callable], inter: float, timeout: Optional[float],
            count: Optional[int], verbose: Optional[int], store: bool,
            kwargs: dict) -> tuple:
    def exchange():
        return fn(pkts, timeout=timeout, verbose=0, **kwargs)

    return _loop(exchange, count, inter, prn, prnfail, _verbose(verbose), store)


def srloop(pkts: Any, prn: Optional[Callable] = None,
           prnfail: Optional[Callable] = None, inter: float = 1,
           timeout: Optional[float] = None, count: Optional[int] = None,
           verbose: Optional[int] = None, store: bool = True,
           **kwargs: Any) -> tuple:
    """Send and receive at layer 3, over and over, reporting each round.

    ``count=None`` loops until Ctrl-C, which returns the rounds already
    collected. The accumulated ``(answered, unanswered)`` come back either way.
    """
    return _srloop(sr, pkts, prn, prnfail, inter, timeout, count, verbose,
                   store, kwargs)


def srploop(pkts: Any, prn: Optional[Callable] = None,
            prnfail: Optional[Callable] = None, inter: float = 1,
            timeout: Optional[float] = None, count: Optional[int] = None,
            verbose: Optional[int] = None, store: bool = True,
            **kwargs: Any) -> tuple:
    """`srloop` at layer 2."""
    return _srloop(srp, pkts, prn, prnfail, inter, timeout, count, verbose,
                   store, kwargs)


def _mapped_mac(ip: str) -> Optional[str]:
    """The hardware address an IPv4 address maps to without asking anyone.

    RFC 919 §7 for the broadcast address, and RFC 1112 §6.4 for multicast: the
    low 23 bits of the group go into ``01:00:5e``, which is why 224.0.0.1 and
    225.128.0.1 share a MAC. ``None`` for an ordinary address, which has to be
    asked about.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version != 4:
        return None
    octets = addr.packed
    if addr.is_multicast:
        return "01:00:5e:%02x:%02x:%02x" % (
            octets[1] & 0x7F, octets[2], octets[3]
        )
    if int(addr) == 0xFFFFFFFF:
        return "ff:ff:ff:ff:ff:ff"
    return None


def getmacbyip(ip: Any, chainCC: int = 0, iface: Any = None,
               timeout: float = 2, verbose: Optional[int] = None) -> Optional[str]:
    """The hardware address for an IPv4 address, or ``None``.

    Broadcast and multicast are computed rather than asked about; anything else
    is one ARP request. There is no cache: a stale entry answering for a host
    that has since moved is a worse failure than a second request.
    """
    mapped = _mapped_mac(str(ip))
    if mapped is not None:
        return mapped
    reply = srp1(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(ip)),
        filter="arp and arp[6:2] = 2", timeout=timeout, iface=iface, verbose=0,
    )
    return None if reply is None else reply[ARP].hwsrc
