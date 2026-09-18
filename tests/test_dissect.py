"""Dissection of hand-built vectors, round-tripping, and malformed input."""

import struct

import pytest

from wiry import (
    ARP, DNS, Dot1Q, Ether, ICMP, IP, IPv6, Raw, TCP, UDP,
)
from helpers import (
    ARP_WHO_HAS, DNS_HEADER, ETHER_IP_TCP, GARBAGE, ICMP_ECHO, VLAN_IP, checksum,
)


def test_helper_checksum_agrees_with_the_hand_built_icmp_vector():
    # RFC 792 vector; a correct RFC 1071 sum over the whole message is zero.
    assert checksum(ICMP_ECHO) == 0


def test_dissects_the_expected_chain():
    assert Ether(ETHER_IP_TCP).layers() == ["Ether", "IP", "TCP"]


@pytest.mark.parametrize(
    "layer,field,expected",
    [
        (Ether, "dst", "00:11:22:33:44:55"),
        (Ether, "src", "66:77:88:99:aa:bb"),
        (Ether, "type", 0x0800),
        (IP, "version", 4),
        (IP, "ihl", 5),
        (IP, "len", 40),
        (IP, "id", 1),
        (IP, "ttl", 64),
        (IP, "proto", 6),
        (IP, "src", "10.0.0.1"),
        (IP, "dst", "10.0.0.2"),
        (TCP, "sport", 8080),
        (TCP, "dport", 80),
        (TCP, "seq", 1),
        (TCP, "dataofs", 5),
        (TCP, "flags", "S"),
        (TCP, "window", 8192),
    ],
)
def test_fields_of_the_hand_built_frame(layer, field, expected):
    assert getattr(Ether(ETHER_IP_TCP)[layer], field) == expected


def test_dissects_a_vlan_tagged_frame():
    pkt = Ether(VLAN_IP)
    assert pkt.layers() == ["Ether", "Dot1Q", "IP"]
    assert pkt[Ether].type == 0x8100
    assert (pkt[Dot1Q].prio, pkt[Dot1Q].dei, pkt[Dot1Q].vlan) == (3, 0, 100)
    assert pkt[Dot1Q].type == 0x0800
    assert pkt[IP].src == "10.0.0.1"


def test_dissects_an_icmp_echo_request():
    pkt = ICMP(ICMP_ECHO)
    assert pkt.layers() == ["ICMP", "Raw"]
    assert pkt[ICMP].type == 8
    assert pkt[ICMP].code == 0
    assert pkt[ICMP].chksum == 0x482D
    assert pkt[ICMP].id == 0x1234
    assert pkt[ICMP].seq == 1
    assert pkt[Raw].load == b"\xde\xad\xbe\xef"


def test_dissects_an_arp_request():
    pkt = ARP(ARP_WHO_HAS)
    assert pkt.layers() == ["ARP"]
    assert (pkt[ARP].hwtype, pkt[ARP].ptype) == (1, 0x0800)
    assert (pkt[ARP].hwlen, pkt[ARP].plen) == (6, 4)
    assert pkt[ARP].op == 1
    assert pkt[ARP].hwsrc == "00:11:22:33:44:55"
    assert pkt[ARP].psrc == "10.0.0.1"
    assert pkt[ARP].hwdst == "00:00:00:00:00:00"
    assert pkt[ARP].pdst == "10.0.0.2"


def test_dissects_a_dns_header_only():
    pkt = DNS(DNS_HEADER)
    assert pkt.layers() == ["DNS"]
    assert pkt[DNS].id == 0x1234
    assert (pkt[DNS].qr, pkt[DNS].opcode, pkt[DNS].rd) == (0, 0, 1)
    assert (pkt[DNS].qdcount, pkt[DNS].ancount) == (1, 0)


def test_udp_port_53_reaches_the_dns_layer():
    pkt = Ether() / IP() / UDP(sport=40000, dport=53) / Raw(load=DNS_HEADER)
    assert Ether(bytes(pkt)).layers() == ["Ether", "IP", "UDP", "DNS"]


def test_every_field_survives_a_build_serialise_dissect_cycle():
    built = (
        Ether(dst="00:11:22:33:44:55", src="66:77:88:99:aa:bb")
        / IP(src="192.0.2.1", dst="198.51.100.9", ttl=17, tos=8, id=513)
        / TCP(sport=4321, dport=8443, seq=99, ack=5, flags="PA", window=4096)
        / Raw(load=b"payload")
    )
    built[IP].version  # materialise, so bytes() settles computed fields
    data = bytes(built)
    back = Ether(data)
    assert back.layers() == ["Ether", "IP", "TCP", "Raw"]
    for layer in (Ether, IP, TCP):
        for name in back[layer].fields():
            assert getattr(back[layer], name) == getattr(built[layer], name), name
    assert back[Raw].load == b"payload"
    assert bytes(back) == data


@pytest.mark.parametrize(
    "data",
    [ETHER_IP_TCP, VLAN_IP, GARBAGE, b"", b"\x00", b"\xff" * 13, b"\x08\x00" * 40],
)
def test_dissect_then_serialise_returns_the_same_bytes(data):
    assert bytes(Ether(data)) == data


@pytest.mark.parametrize("n", list(range(0, 60)))
def test_every_truncation_dissects_without_raising(n):
    chunk = ETHER_IP_TCP[:n]
    pkt = Ether(chunk)
    assert bytes(pkt) == chunk
    names = pkt.layers()
    if n == 0:
        assert names == []
    else:
        assert names[0] == ("Ether" if n >= 14 else "Raw")
        assert set(names) <= {"Ether", "IP", "TCP", "Raw"}


def test_empty_input_has_no_layers():
    pkt = Ether(b"")
    assert pkt.layers() == []
    assert bytes(pkt) == b""
    assert pkt.summary() == ""
    assert not pkt.haslayer(Ether)


@pytest.mark.parametrize(
    "n,expected",
    [
        (13, ["Raw"]),
        (14, ["Ether"]),
        (20, ["Ether", "Raw"]),
        (33, ["Ether", "Raw"]),
        (34, ["Ether", "IP"]),
        (40, ["Ether", "IP", "Raw"]),
    ],
)
def test_short_input_falls_back_to_raw_at_the_right_depth(n, expected):
    assert Ether(ETHER_IP_TCP[:n]).layers() == expected


def test_header_longer_than_the_buffer_claims_is_not_over_read():
    # IHL says 15 words but only 20 bytes of IPv4 are present.
    data = bytearray(ETHER_IP_TCP)
    data[14] = 0x4F
    pkt = Ether(bytes(data))
    assert pkt.layers() == ["Ether", "IP"]
    assert bytes(pkt) == bytes(data)


@pytest.mark.parametrize(
    "ethertype", [0x9100, 0xFFFF],
)
def test_unimplemented_ethertypes_dissect_to_raw(ethertype):
    data = bytearray(ETHER_IP_TCP)
    data[12:14] = struct.pack("!H", ethertype)
    assert Ether(bytes(data)).layers() == ["Ether", "Raw"]


@pytest.mark.parametrize("proto", [103, 121, 254])
def test_unimplemented_ip_protocols_dissect_to_raw(proto):
    data = bytearray(ETHER_IP_TCP)
    data[23] = proto
    assert Ether(bytes(data)).layers() == ["Ether", "IP", "Raw"]


@pytest.mark.parametrize(
    "nh,layer",
    [
        (0, "IPv6ExtHdrHopByHop"),
        (43, "IPv6ExtHdrRouting"),
        (44, "IPv6ExtHdrFragment"),
        (60, "IPv6ExtHdrDestOpt"),
    ],
)
def test_ipv6_extension_headers_are_walked(nh, layer):
    pkt = Ether() / IPv6() / TCP()
    data = bytearray(bytes(pkt))
    data[20] = nh
    # What follows the extension header is TCP's bytes read as one, so only the
    # shape of the chain down to it is under test here.
    assert Ether(bytes(data)).layers()[:3] == ["Ether", "IPv6", layer]


def test_non_initial_fragment_has_no_transport_layer():
    data = bytearray(ETHER_IP_TCP)
    data[20:22] = struct.pack("!H", 100)
    assert Ether(bytes(data)).layers() == ["Ether", "IP", "Raw"]


@pytest.mark.parametrize("depth", [1, 2, 3, 5, 10])
def test_nested_vlan_tags_all_dissect(depth):
    pkt = Ether()
    for i in range(depth):
        pkt = pkt / Dot1Q(vlan=i + 1)
    pkt = pkt / IP() / UDP(sport=9, dport=9)
    data = bytes(pkt)
    back = Ether(data)
    assert back.layers() == ["Ether"] + ["Dot1Q"] * depth + ["IP", "UDP"]
    assert bytes(back) == data


def test_absurd_vlan_nesting_is_bounded_and_still_round_trips():
    pkt = Ether()
    for i in range(60):
        pkt = pkt / Dot1Q(vlan=1)
    data = bytes(pkt)
    back = Ether(data)
    assert len(back.layers()) <= 32
    assert bytes(back) == data


def test_dissection_can_start_at_a_non_ethernet_link():
    inner = bytes(IP(src="10.1.1.1") / UDP(sport=1, dport=2))
    pkt = IP(inner)
    assert pkt.layers() == ["IP", "UDP"]
    assert pkt[IP].src == "10.1.1.1"
    assert bytes(pkt) == inner


def test_raw_layer_from_bytes_keeps_the_whole_buffer():
    pkt = Raw(GARBAGE)
    assert pkt.layers() == ["Raw"]
    assert pkt[Raw].load == GARBAGE


def test_a_clipped_capture_keeps_the_lengths_the_wire_gave():
    # A clipped record holds fewer bytes than its length fields describe;
    # recomputing from what was captured would destroy them.
    full = bytes(Ether() / IP() / UDP() / Raw(load=b"x" * 60))
    clipped = Ether(full[:60])
    assert clipped[IP].len == 88
    clipped[IP].ttl = 33
    out = bytes(clipped)
    back = Ether(out)
    assert back[IP].ttl == 33
    assert back[IP].len == 88
    assert back[UDP].len == 68
    assert checksum(out[14:34]) == 0


def test_stacking_onto_a_dissected_packet_keeps_its_fields():
    # Stacking copies the real packet and appends to its bytes: variable-length
    # content cannot survive the build path.
    dissected = Ether(ETHER_IP_TCP)
    combined = dissected / Raw(load=b"zz")
    assert combined[IP].src == "10.0.0.1"
    assert combined[TCP].dport == 80
    out = bytes(combined)
    assert out.endswith(b"zz")
    assert len(out) == len(ETHER_IP_TCP) + 2
    # Only the IPv4 total length and the two checksums may change.
    assert combined[IP].len == len(ETHER_IP_TCP) - 14 + 2
    assert out[:16] == ETHER_IP_TCP[:16]
