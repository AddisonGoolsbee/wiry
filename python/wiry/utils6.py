# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from scapy: scapy/utils6.py
#   scapy 2.7.0
#   Copyright (C) Philippe Biondi <phil@secdev.org>
#   Copyright (C) 2005 Guillaume Valadon <guedou@hongo.wide.ad.jp>
#                      Arnaud Ebalard <arnaud.ebalard@eads.net>
#
# Changed by the wiry authors:
#   2026-10-03 — ported onto the standard library; corrected six places where
#                scapy departs from the RFC it cites: source selection rules 1
#                and 2 (RFC 6724 §5), the randomized interface identifier's
#                U/L bit (RFC 4941 §3.2.1), the ULA global ID's bits and clock
#                (RFC 4193 §3.2.2), subnet anycast detection (RFC 2526 §2),
#                multicast scopes in in6_getAddrType (RFC 4291 §2.7) and
#                RFC 1924's fixed twenty digits.

"""IPv6 address arithmetic. Addresses are printable strings unless a function
says it takes or returns the 16-octet network form."""

from __future__ import annotations

import os
import socket
import struct
import time
from functools import cmp_to_key
from typing import Iterable, List, Optional, Tuple, Union

from .error import Scapy_Exception, log_runtime
from .data import (
    IPV6_ADDR_6TO4, IPV6_ADDR_GLOBAL, IPV6_ADDR_LINKLOCAL, IPV6_ADDR_LOOPBACK,
    IPV6_ADDR_MULTICAST, IPV6_ADDR_SITELOCAL, IPV6_ADDR_UNICAST,
    IPV6_ADDR_UNSPECIFIED,
)

__all__ = [
    "IPV6_ADDR_6TO4", "IPV6_ADDR_GLOBAL", "IPV6_ADDR_LINKLOCAL",
    "IPV6_ADDR_LOOPBACK", "IPV6_ADDR_MULTICAST", "IPV6_ADDR_SITELOCAL",
    "IPV6_ADDR_UNICAST", "IPV6_ADDR_UNSPECIFIED",
    "construct_source_candidate_set", "get_source_addr_from_candidate_set",
    "in6_getAddrType", "in6_mactoifaceid", "in6_ifaceidtomac",
    "in6_addrtomac", "in6_addrtovendor", "in6_getLinkScopedMcastAddr",
    "in6_get6to4Prefix", "in6_6to4ExtractAddr", "in6_getLocalUniquePrefix",
    "in6_getRandomizedIfaceId", "in6_ctop", "in6_ptoc", "in6_isaddr6to4",
    "in6_isaddrTeredo", "teredoAddrExtractInfo", "in6_iseui64",
    "in6_isanycast", "in6_or", "in6_and", "in6_xor", "in6_cidr2mask",
    "in6_mask2cidr", "in6_getnsma", "in6_getnsmac", "in6_getha", "in6_ptop",
    "in6_isincluded", "in6_isllsnmaddr", "in6_isdocaddr", "in6_islladdr",
    "in6_issladdr", "in6_isuladdr", "in6_isgladdr", "in6_ismaddr",
    "in6_ismnladdr", "in6_ismgladdr", "in6_ismlladdr", "in6_ismsladdr",
    "in6_isaddrllallnodes", "in6_isaddrllallservers", "in6_getscope",
    "in6_get_common_plen", "in6_isvalid", "teredoPrefix", "teredoServerPort",
]


# RFC 4380 §2.6.
teredoPrefix = "2001::"
teredoServerPort = 3544


def _pton(addr: str) -> bytes:
    return socket.inet_pton(socket.AF_INET6, addr)


def _ntop(addr: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET6, addr)


def construct_source_candidate_set(
        addr: str, plen: int,
        laddr: Iterable[Tuple[str, int, str]]) -> List[str]:
    """The addresses in ``laddr`` (as ``(addr, scope, iface)``) whose scope
    matches ``addr/plen``, global ones first and native before 6to4."""
    def cset_sort(x: str, y: str) -> int:
        x_global = 1 if in6_isgladdr(x) else 0
        y_global = 1 if in6_isgladdr(y) else 0
        res = y_global - x_global
        if res != 0 or y_global != 1:
            return res
        if not in6_isaddr6to4(x):
            return -1
        return -res

    laddr = list(laddr)
    cset: List[Tuple[str, int, str]] = []
    if in6_isgladdr(addr) or in6_isuladdr(addr):
        cset = [x for x in laddr if x[1] == IPV6_ADDR_GLOBAL]
    elif in6_islladdr(addr):
        cset = [x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL]
    elif in6_issladdr(addr):
        cset = [x for x in laddr if x[1] == IPV6_ADDR_SITELOCAL]
    elif in6_ismaddr(addr):
        if in6_ismnladdr(addr):
            from .capture import conf
            cset = [("::1", 16, conf.loopback_name)]
        elif in6_ismgladdr(addr):
            cset = [x for x in laddr if x[1] == IPV6_ADDR_GLOBAL]
        elif in6_ismlladdr(addr):
            cset = [x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL]
        elif in6_ismsladdr(addr):
            cset = [x for x in laddr if x[1] == IPV6_ADDR_SITELOCAL]
    elif addr == "::" and plen == 0:
        cset = [x for x in laddr if x[1] == IPV6_ADDR_GLOBAL]
    elif addr == "::1":
        cset = [x for x in laddr if x[1] == IPV6_ADDR_LOOPBACK]
    addrs = [x[0] for x in cset]
    addrs.sort(key=cmp_to_key(cset_sort))
    return addrs


_SCOPE_RANK = {IPV6_ADDR_GLOBAL: 4, IPV6_ADDR_SITELOCAL: 3,
               IPV6_ADDR_LINKLOCAL: 2, IPV6_ADDR_LOOPBACK: 1}


def _scope_rank(addr: str) -> int:
    scope = in6_getscope(addr)
    return _SCOPE_RANK[IPV6_ADDR_LOOPBACK if scope == -1 else scope]


def get_source_addr_from_candidate_set(dst: str, candidate_set: List[str]) -> str:
    """The best source for ``dst`` by RFC 6724 §5 rules 1, 2 and 8; the other
    rules need policy and state a candidate list does not carry."""
    def better(a: str, b: str) -> int:
        """Positive when ``a`` is the better source."""
        if a == dst:
            return 1
        if b == dst:
            return -1
        sa, sb, sd = _scope_rank(a), _scope_rank(b), _scope_rank(dst)
        if sa < sb:
            return -1 if sa < sd else 1
        if sb < sa:
            return 1 if sb < sd else -1
        pa, pb = in6_get_common_plen(a, dst), in6_get_common_plen(b, dst)
        return (pa > pb) - (pa < pb)

    if not candidate_set:
        return ""
    candidate_set.sort(key=cmp_to_key(better), reverse=True)
    return candidate_set[0]


def in6_getAddrType(addr: str) -> int:
    """The address's cast and scope bits, in Linux's ``ipv6_addr_type`` terms.

    Deprecated site-local unicast (RFC 3879) and ULAs are global unicast, as
    RFC 4291 §2.5.7 tells new implementations to treat them.
    """
    naddr = _pton(addr)
    if naddr[0] & 0xE0 == 0x20:
        kind = IPV6_ADDR_UNICAST | IPV6_ADDR_GLOBAL
        if naddr[:2] == b"\x20\x02":
            kind |= IPV6_ADDR_6TO4
        return kind
    if naddr[0] == 0xFF:
        scope = naddr[1] & 0x0F
        return IPV6_ADDR_MULTICAST | {
            0x1: IPV6_ADDR_LOOPBACK,
            0x2: IPV6_ADDR_LINKLOCAL,
            0x5: IPV6_ADDR_SITELOCAL,
        }.get(scope, IPV6_ADDR_GLOBAL)
    if naddr[0] == 0xFE and naddr[1] & 0xC0 == 0x80:
        return IPV6_ADDR_UNICAST | IPV6_ADDR_LINKLOCAL
    if naddr == b"\x00" * 15 + b"\x01":
        return IPV6_ADDR_LOOPBACK
    if naddr == b"\x00" * 16:
        return IPV6_ADDR_UNSPECIFIED
    return IPV6_ADDR_GLOBAL | IPV6_ADDR_UNICAST


def in6_mactoifaceid(mac: str, ulbit: Optional[int] = None) -> str:
    """The modified EUI-64 interface identifier for a MAC (RFC 4291 App. A).
    The U/L bit is inverted unless ``ulbit`` forces it to 0 or 1."""
    if len(mac) != 17:
        raise ValueError("Invalid MAC")
    m = "".join(mac.split(":"))
    if len(m) != 12:
        raise ValueError("Invalid MAC")
    first = int(m[0:2], 16)
    if ulbit is None or ulbit not in (0, 1):
        ulbit = 0 if first & 0x02 else 1
    first_b = "%.02x" % ((first & 0xFD) | (ulbit * 2))
    eui64 = first_b + m[2:4] + ":" + m[4:6] + "FF:FE" + m[6:8] + ":" + m[8:12]
    return eui64.upper()


def in6_ifaceidtomac(ifaceid_s: str) -> Optional[str]:
    """The MAC a modified EUI-64 interface identifier was built from, or None
    where it was not built from one."""
    try:
        ifaceid = _pton("::" + ifaceid_s)[8:16]
    except (OSError, ValueError):
        return None
    if ifaceid[3:5] != b"\xff\xfe":
        return None
    first = ifaceid[0] ^ 0x02
    return ":".join("%.02x" % b for b in bytes([first]) + ifaceid[1:3] + ifaceid[5:])


def in6_addrtomac(addr: str) -> Optional[str]:
    """The MAC behind an address's EUI-64 interface identifier, or None."""
    x = in6_and(_pton("::ffff:ffff:ffff:ffff"), _pton(addr))
    return in6_ifaceidtomac(_ntop(x)[2:])


def in6_addrtovendor(addr: str) -> Optional[str]:
    """The vendor of the MAC behind an EUI-64 address: None where there is
    no such MAC, "UNKNOWN" where the OUI is not in the database."""
    mac = in6_addrtomac(addr)
    if mac is None:
        return None
    from .data import MANUFDB
    if not MANUFDB:
        return None
    res = MANUFDB._get_manuf(mac)
    if len(res) == 17 and res.count(":") != 5:
        res = "UNKNOWN"
    return res


def in6_getLinkScopedMcastAddr(addr: str,
                               grpid: Optional[Union[bytes, str, int]] = None,
                               scope: int = 2) -> Optional[str]:
    """RFC 4489's link-scoped multicast address for a link-local ``addr``.

    ``grpid`` fills the last 32 bits: four octets, eight hex digits, or an
    int. RFC 4489 allows only scopes up to 2. None on any invalid input.
    """
    if scope not in (0, 1, 2):
        return None
    try:
        if not in6_islladdr(addr):
            return None
        baddr = _pton(addr)
    except (OSError, ValueError):
        log_runtime.warning("in6_getLinkScopedMcastPrefix(): Invalid address provided")
        return None
    if grpid is None:
        b_grpid = b"\x00\x00\x00\x00"
    elif isinstance(grpid, str) and len(grpid) == 8:
        try:
            b_grpid = struct.pack("!I", int(grpid, 16) & 0xFFFFFFFF)
        except ValueError:
            log_runtime.warning("in6_getLinkScopedMcastPrefix(): Invalid group id provided")
            return None
    elif isinstance(grpid, bytes) and len(grpid) == 4:
        b_grpid = grpid
    elif isinstance(grpid, int) and not isinstance(grpid, bool):
        b_grpid = struct.pack("!I", grpid & 0xFFFFFFFF)
    else:
        log_runtime.warning("in6_getLinkScopedMcastPrefix(): Invalid group id provided")
        return None
    flgscope = bytes([(0x3 << 4) | scope])
    return _ntop(b"\xff" + flgscope + b"\x00\xff" + baddr[8:] + b_grpid)


def in6_get6to4Prefix(addr: str) -> Optional[str]:
    """The 6to4 /48 for an IPv4 address (RFC 3056 §2), or None."""
    try:
        return _ntop(b"\x20\x02" + socket.inet_pton(socket.AF_INET, addr) + b"\x00" * 10)
    except (OSError, ValueError):
        return None


def in6_6to4ExtractAddr(addr: str) -> Optional[str]:
    """The IPv4 address inside a 6to4 address, or None."""
    try:
        baddr = _pton(addr)
    except (OSError, ValueError):
        return None
    if baddr[:2] != b"\x20\x02":
        return None
    return socket.inet_ntop(socket.AF_INET, baddr[2:6])


# Seconds from the NTP era (1900) to the Unix epoch.
_NTP_OFFSET = 2208988800


def in6_getLocalUniquePrefix() -> str:
    """A random ULA /48 by RFC 4193 §3.2.2: the low 40 bits of SHA-1 over an
    NTP timestamp and an EUI-64. The EUI-64 comes from a random MAC, since
    the point is a prefix unlikely to collide, not one tied to this host."""
    import hashlib
    tod = time.time() + _NTP_OFFSET
    seconds = int(tod)
    btod = struct.pack("!II", seconds & 0xFFFFFFFF, int((tod - seconds) * 2**32))
    mac = ":".join("%02x" % b for b in os.urandom(6))
    eui64 = _pton("::" + in6_mactoifaceid(mac))[8:]
    globalid = hashlib.sha1(btod + eui64).digest()[-5:]
    return _ntop(b"\xfd" + globalid + b"\x00" * 10)


def in6_getRandomizedIfaceId(ifaceid: str,
                             previous: Optional[str] = None) -> Tuple[str, str]:
    """A temporary interface identifier by RFC 4941 §3.2.1 and the history
    value to pass back in next time, both in printable form."""
    import hashlib
    if previous is None:
        b_previous = os.urandom(8)
    else:
        b_previous = _pton("::" + previous)[8:]
    s = hashlib.md5(_pton("::" + ifaceid)[8:] + b_previous).digest()
    s1, s2 = bytes([s[0] & ~0x02 & 0xFF]) + s[1:8], s[8:]
    return _ntop(b"\xff" * 8 + s1)[20:], _ntop(b"\xff" * 8 + s2)[20:]


_rfc1924map = (
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "!#$%&()*+-;<=>?@^_`{|}~"
)


def in6_ctop(addr: str) -> Optional[str]:
    """An RFC 1924 compact address in printable form, or None."""
    if len(addr) != 20 or not all(c in _rfc1924map for c in addr):
        return None
    i = 0
    for c in addr:
        i = 85 * i + _rfc1924map.index(c)
    if i >= 1 << 128:
        return None
    return _ntop(i.to_bytes(16, "big"))


def in6_ptoc(addr: str) -> Optional[str]:
    """A printable address in RFC 1924's compact form: always twenty digits,
    leading zeros kept, so ``in6_ctop`` reads it back."""
    try:
        rem = int.from_bytes(_pton(addr), "big")
    except (OSError, ValueError):
        return None
    res = []
    for _ in range(20):
        rem, digit = divmod(rem, 85)
        res.append(_rfc1924map[digit])
    return "".join(reversed(res))


def in6_isaddr6to4(x: str) -> bool:
    """Whether ``x`` is in 2002::/16."""
    return _pton(x)[:2] == b"\x20\x02"


def in6_isaddrTeredo(x: str) -> bool:
    """Whether ``x`` is under the Teredo /32."""
    return _pton(x)[0:4] == _pton(teredoPrefix)[0:4]


def teredoAddrExtractInfo(x: str) -> Tuple[str, int, str, int]:
    """(server, flags, client address, client port) from a Teredo address,
    with the client's obfuscation undone (RFC 4380 §4)."""
    addr = _pton(x)
    server = socket.inet_ntop(socket.AF_INET, addr[4:8])
    flag = struct.unpack("!H", addr[8:10])[0]
    mappedport = struct.unpack("!H", in6_xor(addr[10:12], b"\xff" * 2))[0]
    mappedaddr = socket.inet_ntop(socket.AF_INET, in6_xor(addr[12:16], b"\xff" * 4))
    return server, flag, mappedaddr, mappedport


def in6_iseui64(x: str) -> bool:
    """Whether the interface identifier carries the ``ff:fe`` an EUI-64
    built from a MAC does."""
    eui64 = _pton("::ff:fe00:0")
    return in6_and(_pton(x), eui64) == eui64


def in6_isanycast(x: str) -> bool:
    """Whether ``x`` is a reserved subnet anycast address (RFC 2526 §2).

    Where RFC 4291 requires 64-bit interface identifiers, which is every
    prefix outside ::/3, the identifier is ``fdff:ffff:ffff:ff80`` with a
    7-bit anycast ID; the U/L bit has to be 0. Under ::/3 it is all ones bar
    the anycast ID, read here over the low 64 bits.
    """
    b = _pton(x)
    iid = int.from_bytes(b[8:], "big") & ~0x7F
    if b[0] & 0xE0 == 0:
        return iid == 0xFFFFFFFFFFFFFF80
    return iid == 0xFDFFFFFFFFFFFF80


def in6_or(a1: bytes, a2: bytes) -> bytes:
    """Bitwise OR of two network-form addresses."""
    return bytes(x | y for x, y in zip(a1, a2))


def in6_and(a1: bytes, a2: bytes) -> bytes:
    """Bitwise AND of two network-form addresses."""
    return bytes(x & y for x, y in zip(a1, a2))


def in6_xor(a1: bytes, a2: bytes) -> bytes:
    """Bitwise XOR of two network-form addresses."""
    return bytes(x ^ y for x, y in zip(a1, a2))


def in6_cidr2mask(m: int) -> bytes:
    """The 16-octet mask of a prefix length."""
    if m > 128 or m < 0:
        raise Scapy_Exception(
            "value provided to in6_cidr2mask outside [0, 128] domain (%d)" % m)
    return (((1 << m) - 1) << (128 - m)).to_bytes(16, "big")


def in6_mask2cidr(m: bytes) -> int:
    """The prefix length of a 16-octet mask: its leading one bits."""
    if len(m) != 16:
        raise Scapy_Exception("value must be 16 octets long")
    v = int.from_bytes(m, "big")
    for i in range(128):
        if not v & (1 << (127 - i)):
            return i
    return 128


def in6_getnsma(a: bytes) -> bytes:
    """The solicited-node multicast address of a network-form address
    (RFC 4291 §2.7.1): ff02::1:ff plus its low 24 bits."""
    return in6_or(_pton("ff02::1:ff00:0"), in6_and(a, _pton("::ff:ffff")))


def in6_getnsmac(a: bytes) -> str:
    """The Ethernet multicast MAC of a network-form IPv6 address: 33:33 and
    its low 32 bits (RFC 2464 §7)."""
    return "33:33:" + ":".join("%.2x" % x for x in a[-4:])


def in6_getha(prefix: str) -> str:
    """The Mobile IPv6 home agents anycast address on a /64 (RFC 2526 §3)."""
    r = in6_and(_pton(prefix), in6_cidr2mask(64))
    return _ntop(in6_or(r, _pton("::fdff:ffff:ffff:fffe")))


def in6_ptop(str: str) -> str:
    """``str`` in canonical printable form."""
    return _ntop(_pton(str))


def in6_isincluded(addr: str, prefix: str, plen: int) -> bool:
    """Whether ``addr`` is in ``prefix/plen``."""
    return _pton(prefix) == in6_and(_pton(addr), in6_cidr2mask(plen))


def in6_isllsnmaddr(str: str) -> bool:
    """Whether ``str`` is in ff02::1:ff00:0/104."""
    return in6_isincluded(str, "ff02::1:ff00:0", 104)


def in6_isdocaddr(str: str) -> bool:
    """Whether ``str`` is in 2001:db8::/32 (RFC 3849)."""
    return in6_isincluded(str, "2001:db8::", 32)


def in6_islladdr(str: str) -> bool:
    """Whether ``str`` is link-local unicast, fe80::/10."""
    return in6_isincluded(str, "fe80::", 10)


def in6_issladdr(str: str) -> bool:
    """Whether ``str`` is deprecated site-local unicast, fec0::/10."""
    return in6_isincluded(str, "fec0::", 10)


def in6_isuladdr(str: str) -> bool:
    """Whether ``str`` is a unique local address, fc00::/7 (RFC 4193)."""
    return in6_isincluded(str, "fc00::", 7)


def in6_isgladdr(str: str) -> bool:
    """Whether ``str`` is global unicast, 2000::/3. ULAs are not."""
    return in6_isincluded(str, "2000::", 3)


def in6_ismaddr(str: str) -> bool:
    """Whether ``str`` is multicast, ff00::/8."""
    return in6_isincluded(str, "ff00::", 8)


def in6_ismnladdr(str: str) -> bool:
    """Whether ``str`` is interface-local multicast, ff01::/16."""
    return in6_isincluded(str, "ff01::", 16)


def in6_ismgladdr(str: str) -> bool:
    """Whether ``str`` is global multicast, ff0e::/16."""
    return in6_isincluded(str, "ff0e::", 16)


def in6_ismlladdr(str: str) -> bool:
    """Whether ``str`` is link-local multicast, ff02::/16."""
    return in6_isincluded(str, "ff02::", 16)


def in6_ismsladdr(str: str) -> bool:
    """Whether ``str`` is site-local multicast, ff05::/16."""
    return in6_isincluded(str, "ff05::", 16)


def in6_isaddrllallnodes(str: str) -> bool:
    """Whether ``str`` is ff02::1."""
    return _pton(str) == _pton("ff02::1")


def in6_isaddrllallservers(str: str) -> bool:
    """Whether ``str`` is ff02::2."""
    return _pton(str) == _pton("ff02::2")


def in6_getscope(addr: str) -> int:
    """The address's scope as an ``IPV6_ADDR_*`` value, or -1. ULAs count as
    global, interface-local multicast as loopback."""
    if in6_isgladdr(addr) or in6_isuladdr(addr):
        return IPV6_ADDR_GLOBAL
    if in6_islladdr(addr):
        return IPV6_ADDR_LINKLOCAL
    if in6_issladdr(addr):
        return IPV6_ADDR_SITELOCAL
    if in6_ismaddr(addr):
        if in6_ismgladdr(addr):
            return IPV6_ADDR_GLOBAL
        if in6_ismlladdr(addr):
            return IPV6_ADDR_LINKLOCAL
        if in6_ismsladdr(addr):
            return IPV6_ADDR_SITELOCAL
        if in6_ismnladdr(addr):
            return IPV6_ADDR_LOOPBACK
        return -1
    if addr == "::1":
        return IPV6_ADDR_LOOPBACK
    return -1


def in6_get_common_plen(a: str, b: str) -> int:
    """How many leading bits ``a`` and ``b`` share."""
    diff = int.from_bytes(_pton(a), "big") ^ int.from_bytes(_pton(b), "big")
    return 128 - diff.bit_length()


def in6_isvalid(address: str) -> bool:
    """Whether ``address`` parses as an IPv6 address."""
    try:
        _pton(address)
        return True
    except (OSError, ValueError, TypeError):
        return False
