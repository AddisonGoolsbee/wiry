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
#                send time (E9). NetBIOS names are encoded here per RFC 1002,
#                since NBNS reads them but does not write them. DHCP_am answers
#                nothing, rather than raising, once its pool is exhausted.
#   2026-10-04 — the DNS machines build replies from wiry.layers.dns's
#                records and compress them as scapy does; relay=True asks
#                conf.nameservers. mDNS's negative NSEC lists the types the
#                name holds (RFC 6762 §6.1), not the type asked for.

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




def _normk(k: Any) -> bytes:
    from ._pyfields import bytes_encode

    k = bytes_encode(k).lower()
    return k if k.endswith(b".") else k + b"."


class DNS_am(AnsweringMachine):
    """A DNS server answering A, AAAA, SRV and in-addr.arpa PTR queries.

    ``joker`` is the IPv4 address for any name not in ``match`` (None mirrors
    the interface's, False answers nothing); ``joker6`` is the same for AAAA,
    off by default. ``match`` maps a name to an address or to an
    ``(IPv4, IPv6)`` pair, or is a list of names answered with the jokers.
    ``srvmatch`` maps a name to ``(port, target)``; ``jokerarpa`` is the name
    every in-addr.arpa PTR query gets. ``relay`` asks ``conf.nameservers``
    for anything else; ``send_error`` answers what is left with NXDOMAIN
    rather than silence.
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
        if self.mDNS and src_ip:
            raise ValueError("Cannot use 'src_ip' in mDNS !")
        if self.mDNS and src_ip6:
            raise ValueError("Cannot use 'src_ip6' in mDNS !")
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

        self.match: Dict[bytes, Tuple] = {}
        if match:
            if isinstance(match, (list, set)):
                self.match.update({_normk(k): (None, None) for k in match})
            else:
                self.match.update({_normk(k): normv(v) for k, v in match.items()})
        self.srvmatch = {_normk(k): normv(v) for k, v in (srvmatch or {}).items()}
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
            # RFC 4795 §2.1: a query arrives at the link-scope group with a
            # hop limit of 1, and nothing else is answered.
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
                # RFC 6762 §11: every response goes out with a hop limit of 255.
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

    def _address(self, rqname: bytes, qtype: int) -> Any:
        """What an A (1) or AAAA (28) query for `rqname` is answered with,
        or a false value for nothing."""
        six = qtype == 28
        entry = self.match.get(rqname)
        rdata = (self.joker6 if six else self.joker) if entry is None \
            else entry[1 if six else 0]
        if rdata is None and not self.relay:
            rdata = _if_addr(_iface(self), six)
        return rdata

    def make_reply(self, req: Any) -> Any:
        from .layers.dns import (
            DNSQR, DNSRR, DNSRRNSEC, DNSRROPT, DNSRRSRV, EDNS0OWN,
            RRlist2bitmap, dns_compress, dns_resolve,
        )

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
        dnsreq = req[DNS]
        queries = list(dnsreq.qd)
        # An ALL query is answered as an A query and an AAAA query.
        allquery = next(
            (x for x in queries if getattr(x, "qtype", None) == 255), None)
        if allquery is not None:
            queries.remove(allquery)
            queries.extend(
                DNSQR(qtype=x, qname=allquery.qname,
                      unicastresponse=allquery.unicastresponse,
                      qclass=allquery.qclass)
                for x in (1, 28)
            )
        ans: List[Any] = []
        ars: List[Any] = []
        for rq in queries:
            if not isinstance(rq, DNSQR):
                continue
            rqname = rq.qname.lower()
            if rq.qtype in (1, 28):
                rdata = self._address(rqname, rq.qtype)
                if self.mDNS and rdata:
                    l3kw["src"] = rdata
                if rdata:
                    ans.extend(
                        DNSRR(rrname=rq.qname, ttl=self.ttl, rdata=x,
                              type=rq.qtype, cacheflush=self.mDNS)
                        for x in (rdata if isinstance(rdata, list) else [rdata])
                    )
                    continue
            elif rq.qtype == 33 and rqname in self.srvmatch:
                port, target = self.srvmatch[rqname]
                ans.append(DNSRRSRV(rrname=rq.qname, port=port, target=target,
                                    weight=100, ttl=self.ttl))
                continue
            elif rq.qtype == 12:
                if rq.qname[-14:] == b".in-addr.arpa." and self.jokerarpa:
                    ans.append(DNSRR(rrname=rq.qname, type=rq.qtype,
                                     ttl=self.ttl, rdata=self.jokerarpa))
                    continue
            if self.relay:
                try:
                    rslv = dns_resolve(rq.qname, qtype=rq.qtype, raw=True)
                except TimeoutError:
                    rslv = None
                if rslv:
                    ans.extend(rslv.an)
                    ars.extend(rslv.ar)
                    continue
            if self.mDNS:
                # RFC 6762 §6.1: the negative answer's bit map lists the types
                # the name does have. scapy lists the type asked for, which
                # asserts the very record being denied.
                held = [t for t in (1, 28) if self._address(rqname, t)]
                ans.append(DNSRRNSEC(
                    ttl=self.ttl, rrname=rq.qname, nextname=rq.qname,
                    typebitmaps=RRlist2bitmap(held) if held else b"",
                ))
        if self.mDNS and all(x.type == 47 for x in ans):
            return None
        resp = l3cls(**l3kw) / UDP(sport=udp.dport, dport=udp.sport)
        if not ans:
            if self.send_error:
                dns = DNS(id=dnsreq.id, qr=1, qd=dnsreq.qd, rcode=3)
                return (link / resp / dns) if link else (resp / dns)
            return None
        if self.mDNS:
            # A Windows extension scapy sends: the responder's own MAC.
            ars.append(DNSRROPT(z=0x1194, rdata=[EDNS0OWN(
                primary_mac=None)]))
            dns = DNS(id=dnsreq.id, aa=1, rd=0, qr=1, qd=[], ar=ars, an=ans)
        else:
            dns = DNS(id=dnsreq.id, qr=1, qd=dnsreq.qd, ar=ars, an=ans)
        if not self.llmnr:
            dns = dns_compress(dns)
        return (link / resp / dns) if link else (resp / dns)


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
