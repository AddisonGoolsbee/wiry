"""IPv6 address helpers, checked against the examples and rules of the RFCs
they implement."""

import socket

import pytest

from wiry import utils6 as U
from wiry.data import (
    IPV6_ADDR_6TO4, IPV6_ADDR_GLOBAL, IPV6_ADDR_LINKLOCAL, IPV6_ADDR_LOOPBACK,
    IPV6_ADDR_MULTICAST, IPV6_ADDR_SITELOCAL, IPV6_ADDR_UNICAST,
    IPV6_ADDR_UNSPECIFIED,
)


def pton(a):
    return socket.inet_pton(socket.AF_INET6, a)


def ntop(b):
    return socket.inet_ntop(socket.AF_INET6, b)


def test_solicited_node_multicast_rfc4291():
    # RFC 4291 §2.7.1's own example.
    nsma = U.in6_getnsma(pton("4037::01:800:200E:8C6C"))
    assert ntop(nsma) == "ff02::1:ff0e:8c6c"
    assert U.in6_isllsnmaddr(ntop(nsma))
    assert not U.in6_isllsnmaddr("ff02::1:fe0e:8c6c")
    # RFC 2464 §7: 33:33 and the low 32 bits.
    assert U.in6_getnsmac(nsma) == "33:33:ff:0e:8c:6c"


def test_eui64_rfc2464():
    # RFC 2464 §4: 34-56-78-9A-BC-DE gives 3656:78FF:FE9A:BCDE.
    assert U.in6_mactoifaceid("34:56:78:9a:bc:de") == "3656:78FF:FE9A:BCDE"
    assert U.in6_mactoifaceid("34:56:78:9a:bc:de", ulbit=0) == "3456:78FF:FE9A:BCDE"
    assert U.in6_ifaceidtomac("3656:78ff:fe9a:bcde") == "34:56:78:9a:bc:de"
    assert U.in6_addrtomac("fe80::3656:78ff:fe9a:bcde") == "34:56:78:9a:bc:de"
    assert U.in6_ifaceidtomac("3656:78ff:fd9a:bcde") is None
    assert U.in6_iseui64("fe80::3656:78ff:fe9a:bcde")
    assert not U.in6_iseui64("fe80::1")
    with pytest.raises(ValueError):
        U.in6_mactoifaceid("34:56:78")


def test_6to4_rfc3056():
    assert U.in6_get6to4Prefix("192.0.2.4") == "2002:c000:204::"
    assert U.in6_6to4ExtractAddr("2002:c000:204::1") == "192.0.2.4"
    assert U.in6_6to4ExtractAddr("2001:db8::1") is None
    assert U.in6_get6to4Prefix("not an address") is None
    assert U.in6_isaddr6to4("2002:c000:204::1")
    assert not U.in6_isaddr6to4("2001:db8::1")


def test_teredo_rfc4380():
    # Server 65.54.227.120, cone flag set, client 192.0.2.45:40000 obfuscated.
    addr = "2001:0:4136:e378:8000:63bf:3fff:fdd2"
    assert U.in6_isaddrTeredo(addr)
    assert not U.in6_isaddrTeredo("2001:db8::1")
    assert U.teredoAddrExtractInfo(addr) == ("65.54.227.120", 0x8000, "192.0.2.45", 40000)


def test_documentation_prefix_rfc3849():
    assert U.in6_isdocaddr("2001:db8:ffff::1")
    assert not U.in6_isdocaddr("2001:db9::1")


def test_ula_rfc4193():
    p = U.in6_getLocalUniquePrefix()
    b = pton(p)
    assert b[0] == 0xFD
    assert b[6:] == b"\x00" * 10
    assert U.in6_isuladdr(p)
    assert U.in6_getscope(p) == IPV6_ADDR_GLOBAL
    assert not U.in6_isgladdr(p)


def test_randomized_iface_id_rfc4941():
    iid, history = U.in6_getRandomizedIfaceId("3656:78ff:fe9a:bcde", previous="1:2:3:4")
    again = U.in6_getRandomizedIfaceId("3656:78ff:fe9a:bcde", previous="1:2:3:4")
    assert (iid, history) == again
    # §3.2.1: the U/L bit, 0x02 of the first octet, is cleared.
    assert pton("::" + iid)[8] & 0x02 == 0
    for _ in range(20):
        fresh, _ = U.in6_getRandomizedIfaceId("3656:78ff:fe9a:bcde")
        assert pton("::" + fresh)[8] & 0x02 == 0


def test_rfc1924_compact_form():
    # RFC 1924 §5's example, both ways.
    assert U.in6_ptoc("1080:0:0:0:8:800:200C:417A") == "4)+k&C#VzJ4br>0wv%Yp"
    assert U.in6_ctop("4)+k&C#VzJ4br>0wv%Yp") == "1080::8:800:200c:417a"
    assert U.in6_ptoc("::") == "0" * 20
    assert U.in6_ctop(U.in6_ptoc("::1")) == "::1"
    assert U.in6_ctop("short") is None
    assert U.in6_ctop("~" * 20) is None


def test_subnet_anycast_rfc2526():
    assert U.in6_isanycast("2001:db8::fdff:ffff:ffff:ff80")
    assert U.in6_isanycast("2001:db8::fdff:ffff:ffff:fffe")
    # A 64-bit identifier has to have the U/L bit clear.
    assert not U.in6_isanycast("2001:db8::ffff:ffff:ffff:ff80")
    assert not U.in6_isanycast("2001:db8::1")
    # Under ::/3 the identifier is all ones bar the anycast ID.
    assert U.in6_isanycast("0:0:0:1:ffff:ffff:ffff:ff81")
    assert U.in6_getha("2001:db8:1:2::") == "2001:db8:1:2:fdff:ffff:ffff:fffe"


def test_link_scoped_multicast_rfc4489():
    assert U.in6_getLinkScopedMcastAddr("fe80::1:2:3:4") == "ff32:ff:1:2:3:4::"
    want = "ff32:ff:1:2:3:4:1234:5678"
    assert U.in6_getLinkScopedMcastAddr("fe80::1:2:3:4", grpid=0x12345678) == want
    assert U.in6_getLinkScopedMcastAddr("fe80::1:2:3:4", grpid="12345678") == want
    assert U.in6_getLinkScopedMcastAddr("fe80::1:2:3:4", grpid=b"\x12\x34\x56\x78") == want
    assert U.in6_getLinkScopedMcastAddr("fe80::1:2:3:4", scope=1).startswith("ff31:")
    assert U.in6_getLinkScopedMcastAddr("fe80::1:2:3:4", scope=5) is None
    assert U.in6_getLinkScopedMcastAddr("2001:db8::1") is None
    assert U.in6_getLinkScopedMcastAddr("fe80::1", grpid=1.5) is None


def test_scopes_rfc4291():
    assert U.in6_getscope("2001:db8::1") == IPV6_ADDR_GLOBAL
    assert U.in6_getscope("fd00::1") == IPV6_ADDR_GLOBAL
    assert U.in6_getscope("fe80::1") == IPV6_ADDR_LINKLOCAL
    assert U.in6_getscope("fec0::1") == IPV6_ADDR_SITELOCAL
    assert U.in6_getscope("ff02::1") == IPV6_ADDR_LINKLOCAL
    assert U.in6_getscope("ff05::1") == IPV6_ADDR_SITELOCAL
    assert U.in6_getscope("ff0e::1") == IPV6_ADDR_GLOBAL
    assert U.in6_getscope("ff01::1") == IPV6_ADDR_LOOPBACK
    assert U.in6_getscope("ff08::1") == -1
    assert U.in6_getscope("::1") == IPV6_ADDR_LOOPBACK
    assert U.in6_isaddrllallnodes("ff02:0::1")
    assert U.in6_isaddrllallservers("ff02::2")
    assert U.in6_ismnladdr("ff01::1") and U.in6_ismsladdr("ff05::1")


def test_address_type():
    assert U.in6_getAddrType("2002::1") == IPV6_ADDR_UNICAST | IPV6_ADDR_GLOBAL | IPV6_ADDR_6TO4
    assert U.in6_getAddrType("2001:db8::1") == IPV6_ADDR_UNICAST | IPV6_ADDR_GLOBAL
    assert U.in6_getAddrType("FF0E::1") == IPV6_ADDR_GLOBAL | IPV6_ADDR_MULTICAST
    assert U.in6_getAddrType("FF02::1") == IPV6_ADDR_LINKLOCAL | IPV6_ADDR_MULTICAST
    # RFC 4291 §2.7's scope field, which scapy reads as global for both.
    assert U.in6_getAddrType("ff05::1") == IPV6_ADDR_SITELOCAL | IPV6_ADDR_MULTICAST
    assert U.in6_getAddrType("ff01::1") == IPV6_ADDR_LOOPBACK | IPV6_ADDR_MULTICAST
    assert U.in6_getAddrType("fe80::1") == IPV6_ADDR_UNICAST | IPV6_ADDR_LINKLOCAL
    assert U.in6_getAddrType("::1") == IPV6_ADDR_LOOPBACK
    assert U.in6_getAddrType("::") == IPV6_ADDR_UNSPECIFIED
    # RFC 4291 §2.5.7: deprecated site-local is global unicast now.
    assert U.in6_getAddrType("fec0::1") == IPV6_ADDR_UNICAST | IPV6_ADDR_GLOBAL


def test_masks_and_bitwise():
    assert U.in6_cidr2mask(0) == b"\x00" * 16
    assert U.in6_cidr2mask(48) == b"\xff" * 6 + b"\x00" * 10
    assert U.in6_cidr2mask(128) == b"\xff" * 16
    assert all(U.in6_mask2cidr(U.in6_cidr2mask(n)) == n for n in range(129))
    with pytest.raises(Exception):
        U.in6_cidr2mask(129)
    with pytest.raises(Exception):
        U.in6_mask2cidr(b"\xff")
    a = pton("2001:db8::2807")
    assert U.in6_xor(a, a) == b"\x00" * 16
    assert U.in6_and(a, b"\x00" * 16) == b"\x00" * 16
    assert U.in6_or(a, b"\x00" * 16) == a
    assert U.in6_get_common_plen("2001:db8::", "2001:db9::") == 31
    assert U.in6_get_common_plen("::1", "::1") == 128
    assert U.in6_isincluded("2001:db8:1::5", "2001:db8::", 32)
    assert not U.in6_isincluded("2001:db9::5", "2001:db8::", 32)
    assert U.in6_ptop("2001:0db8:0:0::1") == "2001:db8::1"
    assert U.in6_isvalid("::1") and not U.in6_isvalid("1.2.3.4")


def test_source_candidate_set():
    dev = [("fe80::1", IPV6_ADDR_LINKLOCAL, "eth0"),
           ("2002:c000:204::1", IPV6_ADDR_GLOBAL, "eth0"),
           ("2001:db8::1", IPV6_ADDR_GLOBAL, "eth0"),
           ("fec0::1", IPV6_ADDR_SITELOCAL, "eth0")]
    # Global first, and a native address ahead of a 6to4 one.
    assert U.construct_source_candidate_set("2001:db8::99", 64, dev) == [
        "2001:db8::1", "2002:c000:204::1"]
    assert U.construct_source_candidate_set("fe80::99", 64, dev) == ["fe80::1"]
    assert U.construct_source_candidate_set("ff02::1", 0, dev) == ["fe80::1"]
    assert U.construct_source_candidate_set("ff05::1", 0, dev) == ["fec0::1"]
    assert U.construct_source_candidate_set("::", 0, dev)[0] == "2001:db8::1"
    assert U.construct_source_candidate_set("ff01::1", 0, dev) == ["::1"]


def test_source_selection_rfc6724():
    # Rule 1: the destination itself, wherever it sits in the list.
    assert U.get_source_addr_from_candidate_set(
        "2001:db8::1", ["2001:db8::2", "2001:db8::1"]) == "2001:db8::1"
    assert U.get_source_addr_from_candidate_set(
        "2001:db8::1", ["2001:db8::1", "2001:db8::2"]) == "2001:db8::1"
    # Rule 2: a link-local source never reaches a global destination.
    for order in (["fe80::1", "2001:db8::2"], ["2001:db8::2", "fe80::1"]):
        assert U.get_source_addr_from_candidate_set("2001:db8::1", list(order)) == "2001:db8::2"
    # ... and a link-local destination prefers the smallest sufficient scope.
    for order in (["fe80::1", "2001:db8::2"], ["2001:db8::2", "fe80::1"]):
        assert U.get_source_addr_from_candidate_set("fe80::9", list(order)) == "fe80::1"
    # Rule 8: longest matching prefix.
    for order in (["2001:db8:1::1", "2001:db8:ffff::1"], ["2001:db8:ffff::1", "2001:db8:1::1"]):
        assert U.get_source_addr_from_candidate_set("2001:db8:1::9", list(order)) == "2001:db8:1::1"
    assert U.get_source_addr_from_candidate_set("2001:db8::1", []) == ""


def test_vendor_from_eui64_address():
    # 00-00-0C is Cisco's oldest IEEE assignment.
    assert "Cisco" in U.in6_addrtovendor("fe80::200:cff:fe00:1")
    assert U.in6_addrtovendor("fe80::1") is None
