# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from scapy: scapy/route.py, scapy/route6.py, scapy/arch/unix.py
#   (read_routes, read_routes6), scapy/arch/linux/rtnetlink.py (the route
#   tuple shapes) and scapy/utils6.py (source address selection)
#   scapy 2.7.0, upstream commit 7d69454
#   Copyright (C) Philippe Biondi <phil@secdev.org>
#   Copyright (C) the scapy contributors
#
# Changed by the wiry authors:
#   2026-09-18 — the kernel tables are read from /proc on Linux and netstat on
#                BSD/macOS rather than netlink, interface addresses come from
#                ioctl so routing works in a build without the live feature,
#                and RFC 3484 source selection is reduced to scope plus longest
#                common prefix.

"""The routing table, read from the OS.

``conf.route.route(dst)`` answers ``(iface, source address, gateway)``: which
interface a packet for ``dst`` leaves by, what source address it will carry and
which router it goes to. That is what lets ``send()`` name an interface, and
what ``traceroute`` and ``sr`` want to know before they send anything.

The table is the kernel's, parsed at first use and cached. ``add`` and
``delete`` change wiry's copy and never the kernel's — a packet library decides
where to send its own packets, it does not reconfigure the host. ``resync()``
throws the copy away and reads the OS again.

Reading it needs no privileges and no libpcap: ``/proc/net/route`` and
``/proc/net/ipv6_route`` on Linux, ``netstat -rn`` on BSD and macOS, and
``SIOCGIFADDR`` for the interface addresses those tables leave out.
"""

from __future__ import annotations

import os
import socket
import struct
import subprocess
import sys
from typing import Any, Dict, Iterable, List, Optional, Tuple

__all__ = [
    "Route", "Route6", "read_routes", "read_routes6", "in6_getifaddr",
    "atol", "ltoa", "itom", "loopback_name",
]

_LINUX = sys.platform.startswith("linux")
_DARWIN = sys.platform == "darwin"
_BSD = sys.platform.startswith(("freebsd", "openbsd", "netbsd", "darwin"))

#: An IPv4 route: (network, netmask, gateway, iface, source address, metric),
#: network and netmask as integers, in scapy's order.
IPv4Route = Tuple[int, int, str, str, str, int]
#: An IPv6 route: (prefix, prefix length, next hop, iface, source candidates,
#: metric).
IPv6Route = Tuple[str, int, str, str, List[str], int]


def atol(x: str) -> int:
    """A dotted quad as an integer."""
    try:
        return struct.unpack("!I", socket.inet_aton(x))[0]
    except OSError as exc:
        raise ValueError(f"not an IPv4 address: {x!r}") from exc


def ltoa(x: int) -> str:
    """An integer as a dotted quad."""
    return socket.inet_ntoa(struct.pack("!I", x & 0xFFFFFFFF))


def itom(x: int) -> int:
    """A prefix length as a netmask."""
    return (0xFFFFFFFF << (32 - x)) & 0xFFFFFFFF if x else 0


def platform_loopback() -> str:
    """What this host calls its loopback interface."""
    return "lo" if _LINUX else "lo0"


def loopback_name() -> str:
    """The loopback interface a route falls back to, which `conf` may override."""
    from .capture import conf

    return conf.loopback_name


# ---------------------------------------------------------------- interfaces

#: SIOCGIFADDR. The number is the ioctl encoding, which differs by kernel.
_SIOCGIFADDR = 0x8915 if _LINUX else 0xC0206921


def _if_addr(name: str) -> str:
    """An interface's first IPv4 address, or ``0.0.0.0``.

    Through ioctl rather than libpcap, so a build without the ``live`` feature
    still routes. A name the host does not know, a down interface and an
    interface with no address all answer the same way, which is what every
    caller here does with them anyway.
    """
    try:
        import fcntl
    except ImportError:  # not a Unix
        return _if_addr_pcap(name)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            req = struct.pack("16s16x", name.encode("utf-8")[:15])
            res = fcntl.ioctl(s.fileno(), _SIOCGIFADDR, req)
        return socket.inet_ntoa(res[20:24])
    except (OSError, ValueError):
        return "0.0.0.0"


def _if_addr_pcap(name: str) -> str:
    from .capture import get_if_addr

    try:
        return get_if_addr(name)
    except Exception:
        return "0.0.0.0"


def _if_names() -> List[str]:
    try:
        return [n for _, n in socket.if_nameindex()]
    except (OSError, AttributeError):
        return []


def _run(cmd: List[str]) -> str:
    """A system tool's stdout, or empty where it is not there. A routing table
    that cannot be read is an empty one, never an exception out of import."""
    try:
        out = subprocess.run(cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout.decode("utf-8", "replace")


# ------------------------------------------------------------------ IPv4 read

def _proc_addr(hexfield: str) -> int:
    return struct.unpack("!I", struct.pack("=I", int(hexfield, 16)))[0]


def _read_routes_proc() -> List[IPv4Route]:
    """Linux: ``/proc/net/route``, whose addresses are host-order hex."""
    routes: List[IPv4Route] = []
    try:
        with open("/proc/net/route") as fd:
            lines = fd.readlines()[1:]
    except OSError:
        return routes
    for line in lines:
        f = line.split()
        if len(f) < 8:
            continue
        try:
            iface = f[0]
            # The hex is the in_addr as the host stores it, so it is read back
            # through native byte order rather than assumed little-endian.
            dst = _proc_addr(f[1])
            gw = _proc_addr(f[2])
            flags = int(f[3], 16)
            metric = int(f[6])
            mask = _proc_addr(f[7])
        except (ValueError, struct.error):
            continue
        if not flags & 0x1:  # RTF_UP
            continue
        routes.append((dst, mask, ltoa(gw), iface, _if_addr(iface), metric))
    return routes


def _netstat_columns(header: str) -> Dict[str, bool]:
    low = header.lower()
    return {
        "mtu": "mtu" in low,
        "prio": "prio" in low,
        "refs": "ref" in low,
        "use": "use" in low or "nhop" in low,
    }


def _read_routes_netstat() -> List[IPv4Route]:
    """BSD and macOS: ``netstat -rn -f inet``.

    The column count varies by kernel, so the header is read for which optional
    columns are present rather than the positions being assumed.
    """
    routes: List[IPv4Route] = []
    text = _run(["netstat", "-rn", "-f", "inet"])
    cols: Optional[Dict[str, bool]] = None
    for raw in text.splitlines():
        line = raw.strip().lower()
        if not line or "----" in line:
            continue
        if cols is None:
            if line.startswith("destination"):
                cols = _netstat_columns(line)
            continue
        rt = line.split()
        if len(rt) < 4:
            continue
        dest_, gw, flg = rt[:3]
        offset = cols["mtu"] + cols["prio"] + cols["refs"] + cols["use"]
        if 3 + offset >= len(rt):
            continue
        netif = rt[3 + offset]
        if "lc" in flg:
            continue
        if dest_ == "default":
            dest, netmask = 0, 0
        else:
            if "/" in dest_:
                dest_, plen = dest_.split("/")
                netmask = itom(int(plen))
            else:
                netmask = itom((dest_.count(".") + 1) * 8)
            dest_ += ".0" * (3 - dest_.count("."))
            try:
                dest = atol(dest_)
            except ValueError:
                continue
        if "g" not in flg:
            gw = "0.0.0.0"
        try:
            atol(gw)
        except ValueError:  # the Gateway column can hold a link-layer address
            gw = "0.0.0.0"
        routes.append((dest, netmask, gw, netif, _if_addr(netif), 1))
    return routes


def _read_routes_ifaces() -> List[IPv4Route]:
    """The last resort: one host route per interface address.

    No gateway and no netmask worth the name, but it still says which interface
    owns which address, which is the part a caller on an unknown platform can
    use.
    """
    routes: List[IPv4Route] = []
    for name in _if_names():
        addr = _if_addr(name)
        if addr != "0.0.0.0":
            routes.append((atol(addr), 0xFFFFFFFF, "0.0.0.0", name, addr, 1))
    return routes


def read_routes() -> List[IPv4Route]:
    """The host's IPv4 routing table, in scapy's six-tuple shape."""
    if _LINUX:
        routes = _read_routes_proc()
    elif _BSD:
        routes = _read_routes_netstat()
    else:
        routes = []
    return routes or _read_routes_ifaces()


# ------------------------------------------------------------------ IPv6 read

IPV6_ADDR_GLOBAL = 0x01
IPV6_ADDR_SITELOCAL = 0x02
IPV6_ADDR_LINKLOCAL = 0x04
IPV6_ADDR_LOOPBACK = 0x08
IPV6_ADDR_MULTICAST = 0x10


def _in6_bytes(addr: str) -> bytes:
    return socket.inet_pton(socket.AF_INET6, addr)


def _in6_valid(addr: str) -> bool:
    try:
        _in6_bytes(addr)
    except (OSError, ValueError):
        return False
    return True


def in6_getscope(addr: str) -> int:
    """Which scope an IPv6 address belongs to."""
    try:
        b = _in6_bytes(addr)
    except (OSError, ValueError):
        return -1
    if b == b"\x00" * 15 + b"\x01":
        return IPV6_ADDR_LOOPBACK
    if b[0] == 0xFF:
        return IPV6_ADDR_MULTICAST
    if b[0] == 0xFE and b[1] & 0xC0 == 0x80:
        return IPV6_ADDR_LINKLOCAL
    if b[0] == 0xFE and b[1] & 0xC0 == 0xC0:
        return IPV6_ADDR_SITELOCAL
    return IPV6_ADDR_GLOBAL


def _in6_included(dst: str, prefix: str, plen: int) -> bool:
    try:
        d, p = _in6_bytes(dst), _in6_bytes(prefix)
    except (OSError, ValueError):
        return False
    whole, rest = divmod(plen, 8)
    if d[:whole] != p[:whole]:
        return False
    if rest:
        mask = (0xFF << (8 - rest)) & 0xFF
        return d[whole] & mask == p[whole] & mask
    return True


def _common_prefix_bits(a: str, b: str) -> int:
    try:
        x, y = _in6_bytes(a), _in6_bytes(b)
    except (OSError, ValueError):
        return 0
    n = 0
    for p, q in zip(x, y):
        if p == q:
            n += 8
            continue
        diff = p ^ q
        while not diff & 0x80:
            n += 1
            diff <<= 1
        break
    return n


def construct_source_candidate_set(addr: str, plen: int,
                                   laddr: Iterable[Tuple[str, int, str]]
                                   ) -> List[str]:
    """The interface addresses that share a scope with ``addr/plen``.

    A global destination is not reachable from a link-local source, so a route
    whose interface has no address of the right scope is no route at all.
    """
    scope = in6_getscope(addr)
    if scope == IPV6_ADDR_MULTICAST:
        # A multicast group is joined from whatever the interface has; a global
        # address is the better source where there is one.
        cset = [x for x in laddr]
    elif scope in (IPV6_ADDR_LOOPBACK, -1):
        cset = [x for x in laddr]
    else:
        cset = [x for x in laddr if x[1] == scope]
    out = [x[0] for x in cset]
    out.sort(key=lambda a: in6_getscope(a) != IPV6_ADDR_GLOBAL)
    return out


def get_source_addr_from_candidate_set(dst: str,
                                       candidate_set: List[str]
                                       ) -> Optional[str]:
    """RFC 3484 §5, reduced: prefer a matching scope, then the longest common
    prefix. The rules this leaves out are named in DEVIATIONS E16."""
    if not candidate_set:
        return None
    want = in6_getscope(dst)
    scored = sorted(
        candidate_set,
        key=lambda a: (in6_getscope(a) != want, -_common_prefix_bits(a, dst)),
    )
    return scored[0]


def _in6_getifaddr_proc() -> List[Tuple[str, int, str]]:
    """Linux: ``/proc/net/if_inet6``, one address per line as 32 hex digits."""
    out: List[Tuple[str, int, str]] = []
    try:
        with open("/proc/net/if_inet6") as fd:
            lines = fd.readlines()
    except OSError:
        return out
    for line in lines:
        f = line.split()
        if len(f) < 6:
            continue
        try:
            addr = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(f[0]))
        except (ValueError, OSError):
            continue
        out.append((addr, in6_getscope(addr), f[5]))
    return out


def _in6_getifaddr_ifconfig() -> List[Tuple[str, int, str]]:
    """BSD and macOS: ``ifconfig``, whose inet6 lines carry a zone id."""
    out: List[Tuple[str, int, str]] = []
    text = _run(["ifconfig", "-a"])
    iface = ""
    for raw in text.splitlines():
        if raw and not raw[0].isspace():
            iface = raw.split(":", 1)[0]
            continue
        parts = raw.split()
        if len(parts) >= 2 and parts[0] == "inet6":
            addr = parts[1].split("%", 1)[0]
            dev = iface
            if "%" in parts[1]:
                dev = parts[1].split("%", 1)[1]
            if _in6_valid(addr):
                out.append((addr, in6_getscope(addr), dev))
    return out


def in6_getifaddr() -> List[Tuple[str, int, str]]:
    """Every IPv6 address on the host, as ``(address, scope, interface)``."""
    if _LINUX:
        return _in6_getifaddr_proc()
    return _in6_getifaddr_ifconfig()


def _read_routes6_proc() -> List[IPv6Route]:
    routes: List[IPv6Route] = []
    lifaddr = in6_getifaddr()
    try:
        with open("/proc/net/ipv6_route") as fd:
            lines = fd.readlines()
    except OSError:
        return routes
    for line in lines:
        f = line.split()
        if len(f) < 10:
            continue
        try:
            prefix = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(f[0]))
            plen = int(f[1], 16)
            nh = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(f[4]))
            metric = int(f[5], 16)
            flags = int(f[8], 16)
        except (ValueError, OSError):
            continue
        dev = f[9]
        if not flags & 0x1:  # RTF_UP
            continue
        if in6_getscope(prefix) == IPV6_ADDR_MULTICAST:
            continue  # multicast routing is decided in Route6.route()
        devaddrs = [x for x in lifaddr if x[2] == dev]
        cset = construct_source_candidate_set(prefix, plen, devaddrs)
        if cset:
            routes.append((prefix, plen, nh, dev, cset, metric))
    return routes


def _read_routes6_netstat() -> List[IPv6Route]:
    routes: List[IPv6Route] = []
    lifaddr = in6_getifaddr()
    if not lifaddr:
        return routes
    text = _run(["netstat", "-rn", "-f", "inet6"])
    started = False
    for raw in text.splitlines():
        if not started:
            if raw.lower().startswith("destination"):
                started = True
            continue
        parts = raw.split()
        if len(parts) < 4:
            continue
        destination, next_hop, flags, dev = parts[:4]
        if "U" not in flags or "R" in flags or "m" in flags:
            continue
        if "link" in next_hop:
            next_hop = "::"
        plen: Any = 128
        if "%" in destination:
            destination, dev = destination.split("%", 1)
            if "/" in dev:
                dev, plen = dev.split("/", 1)
        if "%" in next_hop:
            next_hop, dev = next_hop.split("%", 1)
        if not _in6_valid(next_hop):
            next_hop = "::"
        if destination == "default":
            destination, plen = "::", 0
        elif "/" in destination:
            destination, plen = destination.split("/", 1)
        if "/" in dev:
            dev, plen = dev.split("/", 1)
        if not _in6_valid(destination):
            continue
        try:
            plen = int(plen)
        except (TypeError, ValueError):
            continue
        if in6_getscope(destination) == IPV6_ADDR_MULTICAST:
            continue
        if dev == loopback_name():
            cset = ["::1"]
            next_hop = "::"
        else:
            devaddrs = [x for x in lifaddr if x[2] == dev]
            cset = construct_source_candidate_set(destination, plen, devaddrs)
        if cset:
            routes.append((destination, plen, next_hop, dev, cset, 1))
    return routes


def read_routes6() -> List[IPv6Route]:
    """The host's IPv6 routing table, in scapy's six-tuple shape."""
    if _LINUX:
        return _read_routes6_proc()
    if _BSD:
        return _read_routes6_netstat()
    return []


# ---------------------------------------------------------------- the tables

def _pretty(rows: List[Tuple[str, ...]], header: Tuple[str, ...]) -> str:
    widths = [len(h) for h in header]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    out = ["  ".join(h.ljust(w) for h, w in zip(header, widths)).rstrip()]
    for row in rows:
        out.append("  ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip())
    return "\n".join(out)


class Route:
    """wiry's IPv4 routing table: the kernel's, read once and then owned here.

    ``route(dst)`` answers ``(iface, source address, gateway)`` by longest
    prefix, with the metric as the tie-break — the decision the kernel would
    make, made where a packet library can see it.
    """

    def __init__(self, autoload: bool = True):
        self.routes: List[IPv4Route] = []
        self.invalidate_cache()
        self._loaded = False
        if autoload:
            self.resync()

    def invalidate_cache(self) -> None:
        self.cache: Dict[Tuple[str, Optional[str]], Tuple[str, str, str]] = {}

    def resync(self) -> None:
        """Read the OS table again, dropping anything added here."""
        self.invalidate_cache()
        self.routes = read_routes()
        self._loaded = True

    def make_route(self, host: Optional[str] = None, net: Optional[str] = None,
                   gw: Optional[str] = None, dev: Optional[str] = None,
                   metric: int = 1) -> IPv4Route:
        if host is not None:
            thenet, msk = host, 32
        elif net is not None:
            thenet, msk_b = net.split("/")
            msk = int(msk_b)
        else:
            raise ValueError(
                "make_route: give a host= or a net=, not neither")
        if gw is None:
            gw = "0.0.0.0"
        if dev is None:
            dev, ifaddr, _ = self.route(gw if gw else thenet)
        else:
            ifaddr = "0.0.0.0"  # a 'via' route, with no source of its own
        return (atol(thenet), itom(msk), gw, dev, ifaddr, metric)

    def add(self, *args: Any, **kargs: Any) -> None:
        """Add a route to wiry's table. The kernel's is not touched.

        ``add(net="192.168.1.0/24", gw="192.168.0.254")`` or
        ``add(host="10.0.0.1", dev="eth0")``.
        """
        self.invalidate_cache()
        self.routes.append(self.make_route(*args, **kargs))

    def delt(self, *args: Any, **kargs: Any) -> None:
        """Remove a route from wiry's table. Same arguments as ``add``."""
        self.invalidate_cache()
        route = self.make_route(*args, **kargs)
        try:
            self.routes.remove(route)
        except ValueError:
            raise ValueError("No matching route found!") from None

    #: scapy spells the removal `delt`; the obvious spelling works too.
    delete = delt

    def ifchange(self, iff: str, addr: str) -> None:
        """Tell the table an interface's address changed."""
        self.invalidate_cache()
        the_addr, the_msk_b = (addr.split("/") + ["32"])[:2]
        the_msk = itom(int(the_msk_b))
        the_net = atol(the_addr) & the_msk
        for i, (net, msk, gw, iface, _, metric) in enumerate(self.routes):
            if iff != iface:
                continue
            if gw == "0.0.0.0":
                self.routes[i] = (the_net, the_msk, gw, iface, the_addr, metric)
            else:
                self.routes[i] = (net, msk, gw, iface, the_addr, metric)

    def ifdel(self, iff: str) -> None:
        self.invalidate_cache()
        self.routes = [rt for rt in self.routes if rt[3] != iff]

    def ifadd(self, iff: str, addr: str) -> None:
        self.invalidate_cache()
        the_addr, the_msk_b = (addr.split("/") + ["32"])[:2]
        the_msk = itom(int(the_msk_b))
        self.routes.append(
            (atol(the_addr) & the_msk, the_msk, "0.0.0.0", iff, the_addr, 1))

    def route(self, dst: Any = None, dev: Optional[str] = None,
              verbose: Any = None, _internal: bool = False) -> Tuple[str, str, str]:
        """``(iface, source address, gateway)`` for a destination.

        A destination that is one of our own addresses routes over loopback, as
        the kernel does. A destination nothing matches answers the loopback
        interface and ``0.0.0.0``, which is a visible non-answer rather than a
        plausible wrong one.
        """
        dst = dst or "0.0.0.0"
        if isinstance(dst, bytes):
            dst = dst.decode("utf-8", "strict")
        dst = str(dst)
        if (dst, dev) in self.cache:
            return self.cache[(dst, dev)]
        # "192.168.*.1-5" names a set; route the first address of it.
        _dst = dst.split("/")[0].replace("*", "0")
        while True:
            idx = _dst.find("-")
            if idx < 0:
                break
            m = (_dst[idx:] + ".").find(".")
            _dst = _dst[:idx] + _dst[idx + m:]

        atol_dst = atol(_dst)
        paths = []
        for d, m, gw, i, a, me in self.routes:
            if not a:  # an interface that is not currently connected
                continue
            if dev is not None and i != dev:
                continue
            aa = atol(a)
            if aa == atol_dst and aa != 0:
                paths.append((0xFFFFFFFF, 1, (loopback_name(), a, "0.0.0.0")))
            if (atol_dst & m) == (d & m):
                paths.append((m, me, (i, a, gw)))

        if not paths:
            return (dev or loopback_name(), "0.0.0.0", "0.0.0.0")
        paths.sort(key=lambda x: (-x[0], x[1]))
        ret = paths[0][2]
        if ret[1] == "0.0.0.0" and not _internal:
            # A 'via' route with no source of its own: take the gateway's.
            ret = (ret[0], self.route(ret[2], _internal=True)[1], ret[2])
        self.cache[(dst, dev)] = ret
        return ret

    def get_if_bcast(self, iff: str) -> List[str]:
        """Every broadcast address of an interface."""
        out = []
        for net, msk, _, iface, _, _ in self.routes:
            if net == 0 or msk == 0xFFFFFFFF or iff != iface:
                continue
            out.append(ltoa(net | (~msk & 0xFFFFFFFF)))
        return out

    def __repr__(self) -> str:
        rows = [(ltoa(net), ltoa(msk), gw, iface, addr, str(metric))
                for net, msk, gw, iface, addr, metric in self.routes]
        return _pretty(rows, ("Network", "Netmask", "Gateway", "Iface",
                              "Output IP", "Metric"))


class Route6:
    """wiry's IPv6 routing table. See `Route`; the differences are IPv6's.

    A route carries a *set* of candidate source addresses rather than one,
    because an interface usually has several and which one is right depends on
    the destination's scope.
    """

    def __init__(self, autoload: bool = True):
        self.routes: List[IPv6Route] = []
        self.ipv6_ifaces: set = set()
        self.invalidate_cache()
        if autoload:
            self.resync()

    def invalidate_cache(self) -> None:
        self.cache: Dict[str, Tuple[str, str, str]] = {}

    def flush(self) -> None:
        self.invalidate_cache()
        self.routes.clear()
        self.ipv6_ifaces.clear()

    def resync(self) -> None:
        self.invalidate_cache()
        self.routes = read_routes6()
        self.ipv6_ifaces = {r[3] for r in self.routes}

    def make_route(self, dst: str, gw: Optional[str] = None,
                   dev: Optional[str] = None) -> IPv6Route:
        prefix, plen_b = (dst.split("/") + ["128"])[:2]
        plen = int(plen_b)
        if gw is None:
            gw = "::"
        if dev is None:
            dev, ifaddr_uniq, _ = self.route(gw)
            ifaddr = [ifaddr_uniq]
        else:
            devaddrs = [x for x in in6_getifaddr() if x[2] == dev]
            ifaddr = construct_source_candidate_set(prefix, plen, devaddrs)
        self.ipv6_ifaces.add(dev)
        return (prefix, plen, gw, dev, ifaddr, 1)

    def add(self, *args: Any, **kargs: Any) -> None:
        """``add(dst="2001:db8::/32", gw="2001:db8::1")``."""
        self.invalidate_cache()
        self.routes.append(self.make_route(*args, **kargs))

    def delt(self, dst: str, gw: Optional[str] = None) -> None:
        prefix, plen_b = (dst.split("/") + ["128"])[:2]
        plen = int(plen_b)
        want = _in6_bytes(prefix)
        to_del = [x for x in self.routes
                  if _in6_bytes(x[0]) == want and x[1] == plen]
        if gw:
            gwb = _in6_bytes(gw)
            to_del = [x for x in to_del if _in6_bytes(x[2]) == gwb]
        if len(to_del) != 1:
            raise ValueError(
                "No matching route found!" if not to_del
                else "More than one route matches; give a gw= to pick one")
        self.invalidate_cache()
        self.routes.remove(to_del[0])
        self.ipv6_ifaces = {r[3] for r in self.routes}

    delete = delt

    def ifdel(self, iff: str) -> None:
        self.invalidate_cache()
        self.routes = [rt for rt in self.routes if rt[3] != iff]
        self.ipv6_ifaces = {r[3] for r in self.routes}

    def ifadd(self, iff: str, addr: str) -> None:
        addr, plen_b = (addr.split("/") + ["128"])[:2]
        plen = int(plen_b)
        raw = _in6_bytes(addr)
        whole, rest = divmod(plen, 8)
        masked = bytearray(16)
        masked[:whole] = raw[:whole]
        if rest:
            masked[whole] = raw[whole] & ((0xFF << (8 - rest)) & 0xFF)
        prefix = socket.inet_ntop(socket.AF_INET6, bytes(masked))
        self.invalidate_cache()
        self.routes.append((prefix, plen, "::", iff, [addr], 1))
        self.ipv6_ifaces.add(iff)

    def route(self, dst: str = "", dev: Optional[str] = None,
              verbose: Any = None) -> Tuple[str, str, str]:
        """``(iface, source address, next hop)`` for an IPv6 destination."""
        dst = dst or "::/0"
        dst = str(dst).split("/")[0].replace("*", "0")
        idx = dst.find("-")
        while idx >= 0:
            m = (dst[idx:] + ":").find(":")
            dst = dst[:idx] + dst[idx + m:]
            idx = dst.find("-")
        if not _in6_valid(dst):
            raise ValueError(f"not an IPv6 address: {dst!r}")

        k = dst if dev is None else dst + "%%" + dev
        if k in self.cache:
            return self.cache[k]

        paths = []
        for p, plen, gw, iface, cset, me in self.routes:
            if dev is not None and iface != dev:
                continue
            if _in6_included(dst, p, plen):
                paths.append((plen, me, (iface, cset, gw)))
            elif (in6_getscope(dst) == IPV6_ADDR_MULTICAST and
                    in6_getscope(p) == IPV6_ADDR_LINKLOCAL and cset and
                    in6_getscope(cset[0]) == IPV6_ADDR_LINKLOCAL):
                paths.append((plen, me, (iface, cset, gw)))

        if not paths:
            if dst == "::1":
                return (loopback_name(), "::1", "::")
            return (dev or loopback_name(), "::", "::")

        paths.sort(key=lambda x: (-x[0], x[1]))
        best = (paths[0][0], paths[0][1])
        paths = [x for x in paths if (x[0], x[1]) == best]

        res = []
        for plen, me, (iface, cset, gw) in paths:
            src = get_source_addr_from_candidate_set(dst, cset)
            if src is not None:
                res.append((iface, src, gw))
        if not res:
            return (loopback_name(), "::", "::")
        self.cache[k] = res[0]
        return res[0]

    def __repr__(self) -> str:
        rows = [("%s/%i" % (net, msk), gw, iface, ",".join(cset), str(metric))
                for net, msk, gw, iface, cset, metric in self.routes]
        return _pretty(rows, ("Destination", "Next Hop", "Iface",
                              "Src candidates", "Metric"))
