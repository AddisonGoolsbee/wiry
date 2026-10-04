# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from scapy: scapy/layers/l2.py (ARP_am), scapy/layers/inet.py
#   (ICMPEcho_am), scapy/layers/dhcp.py (BOOTP_am, DHCP_am),
#   scapy/layers/dns.py (DNS_am, mDNS_am), scapy/layers/llmnr.py (LLMNR_am)
#   and scapy/layers/netbios.py (NBNS_am)
#   scapy 2.7.0, upstream commit 7d69454; BOOTP_am's exhausted-pool check and
#   DNS_am's LLMNR scoping from scapy master e2e35c0
#   Copyright (C) Philippe Biondi and the scapy contributors
#
# Changed by the wiry authors:
#   2026-10-03 — ported onto wiry's layers. Replies are built as layer stacks,
#                so an unset source address is filled from the interface at
#                send time (E9). DNS records and NetBIOS names are encoded
#                here per RFC 1035 and RFC 1002, since the layers read them
#                but do not write them (E8). mDNS's negative NSEC lists the
#                types the name holds (RFC 6762 §6.1); DHCP_am answers nothing,
#                rather than raising, once its pool is exhausted.

"""scapy's ready-made answering machines, over wiry's layers.

Each is an `AnsweringMachine`: ``farpd(...)`` and friends sniff and answer,
and ``ARP_am(...).replies_to(packets)`` computes the answers to a capture
without sending anything.
"""

from __future__ import annotations

import ipaddress
import struct
from typing import Any, Dict, List, Optional, Tuple

from . import (
    ARP, BOOTP, DHCP, DNS, ICMP, IP, NBNS, UDP, Ether, IPv6, Net, Net6, Raw,
)
from . import ansmachine as _am
from .ansmachine import AnsweringMachine, ReferenceAM

__all__ = [
    "ARP_am", "ICMPEcho_am", "BOOTP_am", "DHCP_am", "DNS_am", "mDNS_am",
    "LLMNR_am", "NBNS_am", "ReferenceAM",
    "farpd", "icmpechod", "bootpd", "dhcpd", "dnsd", "mdnsd", "llmnrd",
    "nbnsd",
]

_BROADCAST = "ff:ff:ff:ff:ff:ff"
_ZERO_MAC = "00:00:00:00:00:00"


def _conf() -> Any:
    from .capture import conf
    return conf


def _hwaddr(iface: Any) -> str:
    try:
        from .capture import get_if_hwaddr
        return get_if_hwaddr(iface)
    except Exception:
        return _ZERO_MAC


def _iface(am: AnsweringMachine) -> str:
    return str(am.optsniff.get("iface") or _conf().iface)


def _if_addr(iface: str, six: bool) -> Optional[str]:
    """The interface's first address of one family, scope suffix dropped."""
    from .capture import interfaces

    for i in interfaces():
        if i["name"] == iface:
            for a in i["addresses"]:
                if (":" in a) == six:
                    return a.split("%")[0]
    return None


def _after(pkt: Any, layer: str) -> bytes:
    """The octets following the first `layer`'s header."""
    return pkt._materialize().payload(pkt.layers().index(layer))


def _link_reply(req: Any) -> Any:
    """An Ether header back to the sender; a request that arrived broadcast
    leaves the source unset, for the interface to fill (E9)."""
    e = req[Ether]
    kw = {"dst": e.src}
    if e.dst != _BROADCAST:
        kw["src"] = e.dst
    return Ether(**kw)




class ARP_am(AnsweringMachine):
    """Fake ARP relay daemon: answer who-has requests with ``ARP_addr``.

    ``farpd(IP_addr="192.168.1.100", ARP_addr="00:01:02:03:04:05")`` answers
    for one address; omit ``IP_addr`` to answer for every one, and ``ARP_addr``
    to answer with the interface's own MAC.
    """

    function_name = "farpd"
    filter = "arp"
    send_function = staticmethod(_am.sendp)

    def parse_options(self, IP_addr: Any = None, ARP_addr: Optional[str] = None,
                      from_ip: Any = None) -> None:
        self.IP_addr = Net(IP_addr) if isinstance(IP_addr, str) else IP_addr
        self.from_ip = Net(from_ip) if isinstance(from_ip, str) else from_ip
        self.ARP_addr = ARP_addr

    def is_request(self, req: Any) -> bool:
        if ARP not in req:
            return False
        arp = req[ARP]
        return (
            arp.op == 1
            and (self.IP_addr is None or arp.pdst in self.IP_addr)
            and (self.from_ip is None or arp.psrc in self.from_ip)
        )

    def make_reply(self, req: Any) -> Any:
        arp = req[ARP]
        iff = self.optsend["iface"] if "iface" in self.optsend \
            else _conf().route.route(arp.psrc)[0]
        self.iff = iff
        mac = self.ARP_addr if self.ARP_addr is not None else _hwaddr(iff)
        dst = req[Ether].src if Ether in req else arp.hwsrc
        return Ether(dst=dst, src=mac) / ARP(
            op=2, hwsrc=mac, psrc=arp.pdst, hwdst=arp.hwsrc, pdst=arp.psrc,
        )

    def send_reply(self, reply: Any, send_function: Any = None) -> None:
        if send_function:
            send_function(reply)
            return
        opts = dict(self.optsend)
        opts.setdefault("iface", self.iff)
        self.send_function(reply, **opts)

    def print_reply(self, req: Any, reply: Any) -> None:
        print("%s ==> %s on %s" % (req.summary(), reply.summary(), self.iff))




class ICMPEcho_am(AnsweringMachine):
    """Answer ICMP echo requests (RFC 792), echoing id, seq and data."""

    function_name = "icmpechod"

    def is_request(self, req: Any) -> bool:
        return ICMP in req and req[ICMP].type == 8

    def print_reply(self, req: Any, reply: Any) -> None:
        print("Replying %s to %s" % (reply[IP].dst, req[IP].dst))

    def make_reply(self, req: Any) -> Any:
        ip, icmp = req[IP], req[ICMP]
        kw = dict(src=ip.dst, dst=ip.src, tos=ip.tos, id=ip.id,
                  flags=int(ip.flags), frag=ip.frag, ttl=ip.ttl)
        opts = ip.raw_options()
        if opts:
            kw["options"] = opts
        reply = IP(**kw) / ICMP(type=0, code=icmp.code, id=icmp.id, seq=icmp.seq)
        data = _after(req, "ICMP")
        if data:
            reply = reply / Raw(load=data)
        return _link_reply(req) / reply if Ether in req else reply




class BOOTP_am(AnsweringMachine):
    """Hand out addresses from ``pool`` (RFC 951), one per client MAC."""

    function_name = "bootpd"
    filter = "udp and port 68 and port 67"

    def parse_options(self, pool: Any = "192.168.1.128/25",
                      network: str = "192.168.1.0/24",
                      gw: Optional[str] = "192.168.1.1",
                      nameserver: Any = None, domain: Optional[str] = None,
                      renewal_time: int = 60, lease_time: int = 1800,
                      **kwargs: Any) -> None:
        """Other DHCP options pass as keywords by option name:
        ``dhcpd(pool=Net("10.0.10.0/24"), router="10.0.10.1")``."""
        self.domain = domain
        net = ipaddress.ip_network(network, strict=False)
        self.netmask = str(net.netmask)
        self.network = str(net.network_address)
        self.broadcast = str(net.broadcast_address)
        self.gw = gw
        if nameserver is None:
            self.nameserver: Tuple = (gw,)
        elif isinstance(nameserver, str):
            self.nameserver = (nameserver,)
        else:
            self.nameserver = tuple(nameserver)
        if isinstance(pool, str):
            pool = Net(pool)
        if not isinstance(pool, (str, bytes)) and hasattr(pool, "__iter__"):
            pool = [k for k in pool
                    if k not in (gw, self.network, self.broadcast)]
            pool.reverse()
        if isinstance(pool, list) and len(pool) == 1:
            pool, = pool
        self.pool = pool
        self.lease_time = lease_time
        self.renewal_time = renewal_time
        self.leases: Dict[str, str] = {}
        self.kwargs = kwargs

    def is_request(self, req: Any) -> bool:
        return BOOTP in req and req[BOOTP].op == 1

    def print_reply(self, _: Any, reply: Any) -> None:
        print("Reply %s to %s" % (reply[IP].dst, reply[Ether].dst))

    def make_reply(self, req: Any) -> Any:
        mac = req[Ether].src
        if isinstance(self.pool, list):
            if mac not in self.leases:
                if not self.pool:
                    return None
                self.leases[mac] = self.pool.pop()
            ip = self.leases[mac]
        else:
            ip = self.pool
        b = req[BOOTP]
        # The BOOTP options field (the RFC 1497 magic cookie) is left to the
        # build path: setting it here and stacking DHCP drops the DHCP options.
        fields = {f: getattr(b, f) for f in (
            "htype", "hlen", "hops", "xid", "secs", "chaddr", "sname", "file",
        )}
        fields["flags"] = int(b.flags)
        if self.gw is not None:
            fields.update(siaddr=self.gw, ciaddr=self.gw, giaddr=self.gw)
        udp = req[UDP]
        return (Ether(dst=mac) / IP(dst=ip)
                / UDP(sport=udp.dport, dport=udp.sport)
                / BOOTP(op=2, yiaddr=ip, **fields))


_MSGTYPE_REPLY = {1: 2, 3: 5}


class DHCP_am(BOOTP_am):
    """`BOOTP_am` answering DHCP (RFC 2131): a discover gets an offer and a
    request an ack, carrying the options RFC 2132 names."""

    function_name = "dhcpd"

    def make_reply(self, req: Any) -> Any:
        resp = BOOTP_am.make_reply(self, req)
        if resp is None or DHCP not in req:
            return resp
        opts: List[Any] = [
            (op[0], _MSGTYPE_REPLY.get(op[1], op[1]))
            for op in req[DHCP].options
            if isinstance(op, tuple) and op[0] == "message-type"
        ]
        opts += [
            x for x in [
                ("server_id", self.gw),
                ("domain", self.domain),
                ("router", self.gw),
                ("name_server", *self.nameserver),
                ("broadcast_address", self.broadcast),
                ("subnet_mask", self.netmask),
                ("renewal_time", self.renewal_time),
                ("lease_time", self.lease_time),
            ]
            if x[1] is not None
        ]
        opts += list(self.kwargs.items())
        opts.append("end")
        return resp / DHCP(options=opts)




def _labels(name: Any) -> List[bytes]:
    """A name in RFC 1035 §5.1 presentation form, with `\\.` and `\\DDD`
    escapes (RFC 4343 §2.1), as its labels."""
    if isinstance(name, (bytes, bytearray)):
        name = bytes(name).decode("latin-1")
    out: List[bytes] = []
    cur = bytearray()
    i = 0
    while i < len(name):
        c = name[i]
        if c == "\\" and i + 1 < len(name):
            tail = name[i + 1:i + 4]
            if len(tail) == 3 and tail.isdigit():
                cur.append(int(tail) & 0xFF)
                i += 4
                continue
            cur += name[i + 1].encode("latin-1", "replace")
            i += 2
            continue
        if c == ".":
            if cur:
                out.append(bytes(cur))
            cur = bytearray()
        else:
            cur += c.encode("latin-1", "replace")
        i += 1
    if cur:
        out.append(bytes(cur))
    return [lab[:63] for lab in out]


def _norm(name: Any) -> str:
    if isinstance(name, (bytes, bytearray)):
        name = bytes(name).decode("latin-1")
    name = name.lower()
    return name if name.endswith(".") else name + "."


def _type_bitmap(types: Any) -> bytes:
    """RFC 4034 §4.1.2's windowed type bit map."""
    windows: Dict[int, bytearray] = {}
    for t in sorted(set(int(x) for x in types)):
        w, b = divmod(t, 256)
        windows.setdefault(w, bytearray(32))[b // 8] |= 0x80 >> (b % 8)
    out = bytearray()
    for w, bm in sorted(windows.items()):
        n = max(i for i, v in enumerate(bm) if v) + 1
        out += bytes([w, n]) + bm[:n]
    return bytes(out)


class _Message:
    """The sections of a DNS message after its twelve-octet header.

    Names compress against every name already written (RFC 1035 §4.1.4),
    except inside SRV and NSEC RDATA, which RFC 2782 and RFC 4034 §4.1.1 say
    must stay uncompressed.
    """

    def __init__(self, compress: bool):
        self.buf = bytearray()
        self.seen: Optional[Dict[bytes, int]] = {} if compress else None

    def name(self, name: Any, compress: bool = True) -> None:
        labels = _labels(name)
        for i in range(len(labels)):
            key = b".".join(labels[i:]).lower()
            if compress and self.seen is not None and key in self.seen:
                self.buf += struct.pack("!H", 0xC000 | self.seen[key])
                return
            at = len(self.buf) + 12
            if self.seen is not None and at < 0x4000:
                self.seen.setdefault(key, at)
            self.buf += bytes([len(labels[i])]) + labels[i]
        self.buf.append(0)

    def question(self, q: Dict[str, Any]) -> None:
        self.name(q["qname"])
        self.buf += struct.pack("!HH", q["qtype"], q.get("qclass", 1))

    def record(self, rr: Tuple) -> None:
        rrname, rtype, rclass, ttl, rdata = rr
        self.name(rrname)
        self.buf += struct.pack("!HHI", rtype, rclass, ttl)
        at = len(self.buf)
        self.buf += b"\x00\x00"
        if rtype == 1:
            self.buf += ipaddress.IPv4Address(rdata).packed
        elif rtype == 28:
            self.buf += ipaddress.IPv6Address(rdata).packed
        elif rtype == 12:
            self.name(rdata)
        elif rtype == 33:
            priority, weight, port, target = rdata
            self.buf += struct.pack("!HHH", priority, weight, port)
            self.name(target, compress=False)
        elif rtype == 47:
            nextname, types = rdata
            self.name(nextname, compress=False)
            self.buf += _type_bitmap(types)
        else:
            self.buf += bytes(rdata)
        struct.pack_into("!H", self.buf, at, len(self.buf) - at - 2)


class DNS_am(AnsweringMachine):
    """A DNS server answering A, AAAA, SRV and in-addr.arpa PTR queries.

    ``joker`` is the IPv4 address for any name not in ``match`` (None mirrors
    the interface's, False answers nothing); ``joker6`` is the same for AAAA,
    off by default. ``match`` maps a name to an address or to an
    ``(IPv4, IPv6)`` pair, or is a list of names answered with the jokers.
    ``srvmatch`` maps a name to ``(port, target)``; ``jokerarpa`` is the name
    every in-addr.arpa PTR query gets. ``send_error`` answers an unknown name
    with NXDOMAIN rather than silence.
    """

    function_name = "dnsd"
    filter = "udp port 53"
    mDNS = False
    llmnr = False
    dport = 53

    def parse_options(self, joker: Any = None, match: Any = None,
                      srvmatch: Any = None, joker6: Any = False,
                      send_error: bool = False, relay: bool = False,
                      from_ip: Any = True, from_ip6: Any = False,
                      src_ip: Optional[str] = None,
                      src_ip6: Optional[str] = None, ttl: int = 10,
                      jokerarpa: Any = False) -> None:
        if relay:
            raise NotImplementedError(
                "DNS_am(relay=True) needs a resolver; wiry has no "
                "conf.nameservers or dns_resolve to relay through"
            )
        if not isinstance(joker, (str, bool)) and joker is not None:
            raise ValueError("Bad 'joker': should be an IPv4 (str) or False !")
        if not isinstance(joker6, (str, bool)) and joker6 is not None:
            raise ValueError("Bad 'joker6': should be an IPv6 (str) or False !")
        if not isinstance(jokerarpa, (str, bool)):
            raise ValueError("Bad 'jokerarpa': should be a hostname or False !")
        if not isinstance(from_ip, (str, Net, bool)):
            raise ValueError("Bad 'from_ip': should be an IPv4 (str), Net or False !")
        if not isinstance(from_ip6, (str, Net6, bool)):
            raise ValueError("Bad 'from_ip6': should be an IPv6 (str), Net or False !")
        if self.mDNS and (src_ip or src_ip6):
            raise ValueError("Cannot use 'src_ip' in mDNS !")
        if joker is None and match is not None:
            joker = False
        self.joker = joker
        self.joker6 = joker6
        self.jokerarpa = jokerarpa

        def normv(v: Any) -> Tuple:
            if isinstance(v, (tuple, list)) and len(v) == 2:
                return tuple(v)
            if isinstance(v, str):
                return (v, joker6)
            raise ValueError("Bad match value: '%s'" % repr(v))

        self.match: Dict[str, Tuple] = {}
        if match:
            if isinstance(match, (list, set)):
                self.match.update({_norm(k): (None, None) for k in match})
            else:
                self.match.update({_norm(k): normv(v) for k, v in match.items()})
        self.srvmatch = {_norm(k): tuple(v) for k, v in (srvmatch or {}).items()}
        self.send_error = send_error
        self.relay = relay
        self.from_ip = Net(from_ip) if isinstance(from_ip, str) else from_ip
        self.from_ip6 = Net6(from_ip6) if isinstance(from_ip6, str) else from_ip6
        self.src_ip = src_ip
        self.src_ip6 = src_ip6
        self.ttl = ttl

    def is_request(self, req: Any) -> bool:
        if DNS not in req or UDP not in req or req[DNS].qr != 0:
            return False
        if self.llmnr:
            if req[UDP].dport != 5355:
                return False
            if IPv6 in req:
                if req[IPv6].dst != "ff02::1:3" or req[IPv6].hlim != 1:
                    return False
            elif IP in req:
                if req[IP].dst != "224.0.0.252" or req[IP].ttl != 1:
                    return False
            else:
                return False
        if IPv6 in req:
            return self.from_ip6 is True or bool(
                self.from_ip6 and req[IPv6].src in self.from_ip6)
        if IP in req:
            return self.from_ip is True or bool(
                self.from_ip and req[IP].src in self.from_ip)
        return False

    def _network(self, req: Any) -> Tuple[Any, Dict[str, Any]]:
        if IPv6 in req:
            ip6 = req[IPv6]
            if self.mDNS:
                kw = dict(dst="ff02::fb", fl=ip6.fl, hlim=255)
            elif self.llmnr:
                kw = dict(dst=ip6.src, src=self.src_ip6, fl=ip6.fl, hlim=ip6.hlim)
            else:
                kw = dict(dst=ip6.src, src=self.src_ip6 or ip6.dst, fl=ip6.fl,
                          hlim=ip6.hlim)
            return IPv6, {k: v for k, v in kw.items() if v is not None}
        ip = req[IP]
        if self.mDNS:
            kw = dict(dst="224.0.0.251", id=ip.id, ttl=255)
        elif self.llmnr:
            kw = dict(dst=ip.src, src=self.src_ip, id=ip.id, ttl=ip.ttl)
        else:
            kw = dict(dst=ip.src, src=self.src_ip or ip.dst, id=ip.id, ttl=ip.ttl)
        return IP, {k: v for k, v in kw.items() if v is not None}

    def _src_addr(self, rdata: Any, six: bool) -> Optional[str]:
        if rdata is not None:
            return rdata
        if self.relay:
            return None
        return _if_addr(_iface(self), six)

    def _answer(self, rq: Dict[str, Any], resp_src: Dict[str, Any]) -> List[Tuple]:
        qname = rq["qname"]
        key = _norm(qname)
        qtype = rq["qtype"]
        if qtype in (1, 28):
            six = qtype == 28
            rdata = self.match.get(key, (self.joker, self.joker6))[1 if six else 0]
            rdata = self._src_addr(rdata, six)
            if self.mDNS and rdata:
                resp_src["src"] = rdata
            if not rdata:
                return []
            addrs = rdata if isinstance(rdata, list) else [rdata]
            return [(qname, qtype, 1, self.ttl, a) for a in addrs]
        if qtype == 33 and key in self.srvmatch:
            port, target = self.srvmatch[key]
            return [(qname, 33, 1, self.ttl, (0, 100, port, target))]
        if qtype == 12 and _norm(qname).endswith(".in-addr.arpa.") \
                and self.jokerarpa:
            return [(qname, 12, 1, self.ttl, self.jokerarpa + ".")]
        return []

    def make_reply(self, req: Any) -> Any:
        if DNS not in req or UDP not in req \
                or (IP not in req and IPv6 not in req):
            return None
        l3cls, l3kw = self._network(req)
        link = None
        if Ether in req:
            e = req[Ether]
            if self.mDNS:
                link = Ether()
            elif self.llmnr:
                link = Ether(dst=e.src)
            else:
                link = _link_reply(req)
        udp = req[UDP]
        queries = list(req[DNS].qd or [])
        ans: List[Tuple] = []
        for rq in queries:
            if rq.get("qtype") == 255:
                queries += [{"qname": rq["qname"], "qtype": t,
                             "qclass": rq.get("qclass", 1)} for t in (1, 28)]
        for rq in queries:
            if rq.get("qtype") == 255:
                continue
            got = self._answer(rq, l3kw)
            if got:
                ans += got
            elif self.mDNS:
                # RFC 6762 §6.1: assert nonexistence of the missing type.
                ans.append((rq["qname"], 47, 1, self.ttl,
                            (rq["qname"], [rq["qtype"]])))
        if self.mDNS and ans and all(rr[1] == 47 for rr in ans):
            return None
        resp = l3cls(**l3kw) / UDP(sport=udp.dport, dport=udp.sport)
        if not ans:
            if self.send_error:
                dns = self._dns_bytes(req[DNS].id, queries, [], rcode=3)
                return (link / resp / dns) if link else (resp / dns)
            return None
        dns = self._dns_bytes(req[DNS].id, [] if self.mDNS else queries, ans)
        return (link / resp / dns) if link else (resp / dns)

    def _dns_bytes(self, ident: int, queries: List[Dict[str, Any]],
                   answers: List[Tuple], rcode: int = 0) -> Any:
        msg = _Message(compress=not self.llmnr)
        for q in queries:
            msg.question(q)
        for rr in answers:
            msg.record(rr)
        header = dict(id=ident, qr=1, qdcount=len(queries), ancount=len(answers),
                      rcode=rcode)
        if self.mDNS:
            header.update(aa=1, rd=0)
        return DNS(**header) / Raw(load=bytes(msg.buf))


class mDNS_am(DNS_am):
    """`DNS_am` for multicast DNS (RFC 6762) on UDP 5353."""

    function_name = "mdnsd"
    filter = "udp port 5353"
    mDNS = True
    dport = 5353


class LLMNR_am(DNS_am):
    """`DNS_am` for LLMNR (RFC 4795) on UDP 5355."""

    function_name = "llmnrd"
    filter = "udp port 5355"
    llmnr = True
    dport = 5355




def _nb_encode(name: bytes) -> bytes:
    """RFC 1001 §4.1: a 16-octet NetBIOS name, each nibble a letter from A."""
    padded = name[:15].ljust(15) + b"\x00"
    body = bytes(0x41 + (b >> 4) for b in padded) \
        + bytes(0x41 + (b & 0xF) for b in padded)
    body = bytes(x for pair in zip(body[:16], body[16:]) for x in pair)
    return bytes([32]) + body + b"\x00"


class NBNS_am(AnsweringMachine):
    """Answer NetBIOS name queries (RFC 1002) with ``ip``."""

    function_name = "nbnsd"
    filter = "udp port 137"

    def parse_options(self, server_name: Any = None, from_ip: Any = None,
                      ip: Optional[str] = None) -> None:
        self.ServerName = _to_bytes(server_name or b"")
        self.ip = ip
        self.from_ip = Net(from_ip) if isinstance(from_ip, str) else from_ip

    def is_request(self, req: Any) -> bool:
        if self.from_ip and IP in req and req[IP].src not in self.from_ip:
            return False
        if NBNS not in req or req[NBNS].QDCOUNT < 1:
            return False
        return not self.ServerName or self._question(req)[0] == self.ServerName

    def _question(self, req: Any) -> Tuple[bytes, int]:
        """The decoded question name and its 16-bit suffix."""
        body = _after(req, "NBNS")
        length = body[0]
        encoded = body[1:1 + length]
        raw = bytes(
            ((encoded[2 * i] - 0x41) << 4) | (encoded[2 * i + 1] - 0x41)
            for i in range(len(encoded) // 2)
        )
        name = raw[:15].rstrip(b" ").rstrip(b"\x00")
        suffix = raw[15] if len(raw) > 15 else 0
        return name, suffix

    def make_reply(self, req: Any) -> Any:
        name, suffix = self._question(req)
        rr_name = self.ServerName or name
        addr = self.ip or _if_addr(_iface(self), six=False) or "0.0.0.0"
        header = req[NBNS]
        udp = req[UDP]
        # RFC 1002 §4.2.13: a positive name query response carries one
        # resource record: the RR_NAME, type NB, TTL, and a 6-octet address
        # entry (NB_FLAGS plus the IPv4 address).
        rr = (
            _nb_encode(rr_name)
            + struct.pack("!HHIH", 0x20, 1, 0x493E0, 6)
            + struct.pack("!H", 0)
            + ipaddress.IPv4Address(addr).packed
        )
        return (
            _link_reply(req) / IP(dst=req[IP].src)
            / UDP(sport=udp.dport, dport=udp.sport)
            / NBNS(NAME_TRN_ID=header.NAME_TRN_ID, FLAGS=0x8500, ANCOUNT=1)
            / Raw(load=rr)
        )


def _to_bytes(x: Any) -> bytes:
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    return str(x).encode("latin-1")
