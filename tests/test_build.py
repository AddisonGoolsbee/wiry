"""Construction, layering, and the fields the engine computes at serialisation."""

import struct

import pytest

import wiry
from wiry import (
    ARP, DHCP, DNS, BOOTP, Dot1Q, Ether, ICMP, ICMPv6, IP, IPv6, Packet,
    Padding, Raw, TCP, UDP,
)
from helpers import checksum, pseudo_v4, pseudo_v6


def test_slash_builds_the_expected_layer_list():
    pkt = Ether() / IP() / TCP()
    assert pkt.layers() == ["Ether", "IP", "TCP"]


def test_slash_groups_the_same_either_way():
    left = (Ether() / IP()) / TCP()
    right = Ether() / (IP() / TCP())
    assert left.layers() == right.layers()
    assert bytes(left) == bytes(right)


@pytest.mark.parametrize(
    "name,size",
    [
        ("Ether", 14), ("Dot1Q", 4), ("ARP", 28), ("IP", 20), ("IPv6", 40),
        ("TCP", 20), ("UDP", 8), ("ICMP", 8), ("ICMPv6", 4), ("DNS", 12),
        ("BOOTP", 236), ("DHCP", 0), ("Raw", 0), ("Padding", 0),
    ],
)
def test_single_layer_serialises_to_its_header_size(name, size):
    assert len(bytes(getattr(wiry, name)())) == size


@pytest.mark.parametrize(
    "build,size",
    [
        (lambda: Ether(), 14),
        (lambda: Ether() / IP(), 34),
        (lambda: Ether() / IP() / TCP(), 54),
        (lambda: Ether() / IP() / UDP(), 42),
        (lambda: Ether() / IP() / ICMP(), 42),
        (lambda: Ether() / IPv6() / TCP(), 74),
        (lambda: Ether() / IPv6() / ICMPv6(), 58),
        (lambda: Ether() / ARP(), 42),
        (lambda: Ether() / Dot1Q() / IP() / UDP(), 46),
        (lambda: Ether() / IP() / UDP() / DNS(), 54),
    ],
)
def test_stack_length_is_the_sum_of_its_headers(build, size):
    pkt = build()
    assert len(bytes(pkt)) == size
    assert len(pkt) == size


@pytest.mark.parametrize(
    "layer,ethertype",
    [(IP, 0x0800), (IPv6, 0x86DD), (ARP, 0x0806), (Dot1Q, 0x8100)],
)
def test_stacking_sets_the_ethertype(layer, ethertype):
    pkt = Ether() / layer()
    assert pkt[Ether].type == ethertype
    assert struct.unpack("!H", bytes(pkt)[12:14])[0] == ethertype


@pytest.mark.parametrize("layer,proto", [(TCP, 6), (UDP, 17), (ICMP, 1)])
def test_stacking_sets_the_ipv4_protocol(layer, proto):
    pkt = Ether() / IP() / layer()
    assert pkt[IP].proto == proto
    assert bytes(pkt)[23] == proto


@pytest.mark.parametrize("layer,nh", [(TCP, 6), (UDP, 17), (ICMPv6, 58)])
def test_stacking_sets_the_ipv6_next_header(layer, nh):
    pkt = Ether() / IPv6() / layer()
    assert pkt[IPv6].nh == nh
    assert bytes(pkt)[20] == nh


@pytest.mark.parametrize(
    "layer,ethertype", [(IP, 0x0800), (IPv6, 0x86DD), (ARP, 0x0806), (Dot1Q, 0x8100)]
)
def test_stacking_sets_the_vlan_inner_ethertype(layer, ethertype):
    pkt = Ether() / Dot1Q() / layer()
    assert pkt[Dot1Q].type == ethertype
    assert struct.unpack("!H", bytes(pkt)[16:18])[0] == ethertype


def test_raw_payload_is_appended_verbatim():
    pkt = Ether() / IP() / TCP() / Raw(load=b"hello")
    data = bytes(pkt)
    assert len(data) == 59
    assert data.endswith(b"hello")


def test_padding_carries_its_load():
    assert bytes(Padding(load=b"\x00\x00\x07")) == b"\x00\x00\x07"


def test_bare_bytes_on_the_right_become_a_raw_layer():
    with_bytes = Ether() / IP() / UDP(sport=9, dport=9) / b"abc"
    with_raw = Ether() / IP() / UDP(sport=9, dport=9) / Raw(load=b"abc")
    assert with_bytes.layers() == with_raw.layers() == ["Ether", "IP", "UDP", "Raw"]
    assert bytes(with_bytes) == bytes(with_raw)


def test_bare_bytes_on_the_left_become_a_raw_layer():
    pkt = b"\xde\xad" / IP()
    assert pkt.layers() == ["Raw", "IP"]


def test_dividing_by_a_non_packet_is_a_type_error():
    with pytest.raises(TypeError):
        Ether() / 5


def test_serialising_an_empty_packet_is_an_error():
    with pytest.raises(ValueError):
        bytes(Packet())


def test_ipv4_header_checksum_verifies():
    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP()
    header = bytes(pkt)[14:34]
    # RFC 1071: summing a correct header including its checksum field gives zero.
    assert checksum(header) == 0


@pytest.mark.parametrize("payload", [b"", b"a", b"hello world", bytes(500)])
def test_ipv4_total_length_equals_the_bytes_after_the_ether_header(payload):
    pkt = Ether() / IP() / UDP(sport=9, dport=9) / Raw(load=payload)
    data = bytes(pkt)
    assert struct.unpack("!H", data[16:18])[0] == len(data) - 14


@pytest.mark.parametrize("payload", [b"", b"a", b"hello world", bytes(500)])
def test_udp_length_equals_header_plus_data(payload):
    pkt = Ether() / IP() / UDP(sport=9, dport=9) / Raw(load=payload)
    data = bytes(pkt)
    assert struct.unpack("!H", data[38:40])[0] == 8 + len(payload)


def test_ipv6_payload_length_excludes_the_fixed_header():
    pkt = Ether() / IPv6() / UDP(sport=9, dport=9) / Raw(load=b"1234567")
    data = bytes(pkt)
    assert struct.unpack("!H", data[18:20])[0] == len(data) - 14 - 40


@pytest.mark.parametrize("payload", [b"", b"odd", b"even"])
def test_udp_checksum_verifies_over_the_ipv4_pseudo_header(payload):
    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1, dport=2)
    pkt = pkt / Raw(load=payload)
    data = bytes(pkt)
    udp = data[34:]
    ph = pseudo_v4(data[26:30], data[30:34], 17, len(udp))
    assert checksum(ph + udp) == 0


@pytest.mark.parametrize("payload", [b"", b"odd", b"even"])
def test_tcp_checksum_verifies_over_the_ipv4_pseudo_header(payload):
    pkt = Ether() / IP(src="192.0.2.1", dst="198.51.100.7") / TCP(sport=1, dport=2)
    pkt = pkt / Raw(load=payload)
    data = bytes(pkt)
    tcp = data[34:]
    ph = pseudo_v4(data[26:30], data[30:34], 6, len(tcp))
    assert checksum(ph + tcp) == 0


def test_icmp_checksum_verifies_with_no_pseudo_header():
    pkt = Ether() / IP() / ICMP() / Raw(load=b"abcdefgh")
    # RFC 792: the ICMP checksum covers the message alone.
    assert checksum(bytes(pkt)[34:]) == 0


def test_icmpv6_checksum_verifies_over_the_ipv6_pseudo_header():
    pkt = Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / ICMPv6()
    data = bytes(pkt)
    body = data[54:]
    ph = pseudo_v6(data[22:38], data[38:54], 58, len(body))
    assert checksum(ph + body) == 0


def test_tcp_checksum_verifies_over_the_ipv6_pseudo_header():
    pkt = Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP() / Raw(load=b"zz")
    data = bytes(pkt)
    tcp = data[54:]
    ph = pseudo_v6(data[22:38], data[38:54], 6, len(tcp))
    assert checksum(ph + tcp) == 0


def test_changing_a_field_changes_the_checksum_on_reserialisation():
    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP()
    before = bytes(pkt)
    pkt[IP].ttl = 7
    after = bytes(pkt)
    assert before != after
    assert before[24:26] != after[24:26]
    assert checksum(after[14:34]) == 0


def test_changing_an_address_changes_the_transport_checksum():
    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1, dport=2)
    before = bytes(pkt)
    pkt[IP].dst = "10.0.0.3"
    after = bytes(pkt)
    assert before[40:42] != after[40:42]
    data = after
    ph = pseudo_v4(data[26:30], data[30:34], 17, len(data) - 34)
    assert checksum(ph + data[34:]) == 0


def test_computed_fields_are_filled_in_by_serialisation():
    pkt = Ether() / IP() / UDP(sport=9, dport=9) / Raw(load=b"abcde")
    assert pkt[IP].len == 0 and pkt[UDP].len == 0
    total = len(bytes(pkt))
    assert pkt[IP].len == total - 14
    assert pkt[UDP].len == 13


def test_bootp_stack_reaches_dhcp():
    pkt = Ether() / IP() / UDP(sport=68, dport=67) / BOOTP() / DHCP()
    # RFC 2131 puts the magic cookie at the end of the BOOTP header, not in DHCP.
    assert len(bytes(pkt)) == 14 + 20 + 8 + 236 + 4
    assert pkt[BOOTP].options == bytes([99, 130, 83, 99])


def test_explicit_field_values_survive_serialisation():
    pkt = Ether(dst="00:11:22:33:44:55") / IP(ttl=33, id=9) / TCP(sport=1234)
    data = bytes(pkt)
    assert data[:6] == b"\x00\x11\x22\x33\x44\x55"
    assert data[22] == 33
    assert struct.unpack("!H", data[18:20])[0] == 9
    assert struct.unpack("!H", data[34:36])[0] == 1234


@pytest.mark.parametrize(
    "kwargs,exc",
    [
        ({"src": "not-an-ip"}, ValueError),
        ({"src": "10.0.0.256"}, ValueError),
        ({"nosuch": 1}, KeyError),
        ({"ttl": 3.5}, TypeError),
    ],
)
def test_bad_construction_values_are_reported(kwargs, exc):
    with pytest.raises(exc):
        bytes(Ether() / IP(**kwargs))


def test_a_maximal_datagram_still_serialises():
    # RFC 791 §3.1: 65,535 is exactly what the total length field holds.
    pkt = Ether() / IP() / Raw(load=b"\x00" * 65515)
    assert Ether(bytes(pkt))[IP].len == 65535


@pytest.mark.parametrize(
    "pkt,field",
    [
        (Ether() / IP() / Raw(load=b"\x00" * 65516), "IP.len"),
        (Ether() / IPv6() / Raw(load=b"\x00" * 65536), "IPv6.plen"),
        (UDP() / Raw(load=b"\x00" * 70000), "UDP.len"),
        (TCP() / Raw(load=b"\x00" * 70000), "TCP pseudo-header"),
    ],
)
def test_a_length_field_too_narrow_is_an_error_not_a_wrapped_value(pkt, field):
    with pytest.raises(ValueError, match=field.replace(".", r"\.")):
        bytes(pkt)


def test_growing_a_payload_past_the_length_field_is_an_error():
    pkt = Ether(bytes(Ether() / IP() / UDP() / Raw(load=b"1234")))
    pkt[Raw].load = b"\x00" * 70000
    with pytest.raises(ValueError, match="IP.len"):
        bytes(pkt)
