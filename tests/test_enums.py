"""Enumerated fields: the integer is the value, the name is how it prints and
an equally good way to assign it."""

import pytest

from wiry import ICMP, IP, TCP, UDP, Ether, Packet, rdpcap, wrpcap
from wiry.fields import BitEnumField, ByteEnumField, ShortField


def test_a_name_assigns_the_value_and_reading_gives_the_integer():
    p = IP() / ICMP(type="echo-reply")
    assert p[ICMP].type == 0
    assert bytes(p)[20] == 0


def test_a_name_decides_the_layout_before_the_fields_it_gates_are_set():
    # nexthopmtu exists only for destination-unreachable, so the type has to
    # be in place before it is written.
    p = IP() / ICMP(type="dest-unreach", code="port-unreachable", nexthopmtu=1500)
    raw = bytes(p)
    assert raw[20:22] == b"\x03\x03"
    assert raw[26:28] == b"\x05\xdc"


def test_a_name_assigns_through_a_built_packet():
    p = Ether(bytes(Ether() / IP() / ICMP()))
    p[ICMP].type = "echo-reply"
    assert p[ICMP].type == 0
    with pytest.raises(ValueError):
        p[ICMP].type = "no-such-type"


def test_rendering_uses_the_name_and_an_unknown_value_its_number():
    p = IP() / ICMP(type=8)
    assert p.sprintf("%ICMP.type% %r,ICMP.type%") == "echo-request 8"
    assert "type       = echo-request" in p.show_str()
    assert (IP() / ICMP(type=200)).sprintf("%ICMP.type%") == "200"


def test_the_code_names_follow_the_type():
    assert (IP() / ICMP(type=3, code=3)).sprintf("%ICMP.code%") == "port-unreachable"
    assert (IP() / ICMP(type=11, code=0)).sprintf("%ICMP.code%") == "ttl-zero-during-transit"
    assert (IP() / ICMP(type=8, code=3)).sprintf("%ICMP.code%") == "3"


def test_the_declaration_carries_the_table():
    assert ICMP.type.i2s[8] == "echo-request"
    assert ICMP.type.s2i["echo-reply"] == 0
    assert Ether.type.i2s[0x0800] == "IPv4"


def test_a_filter_takes_a_name(tmp_path):
    path = str(tmp_path / "x.pcap")
    wrpcap(path, [Ether() / IP() / UDP(), Ether() / IP() / TCP(), Ether() / IP() / ICMP()])
    cap = rdpcap(path)
    assert len(cap.filter([("IP", "proto", "==", "udp")])) == 1
    assert cap.sprintf("%IP.proto%") == ["udp", "tcp", "icmp"]


class Coloured(Packet):
    fields_desc = [
        ByteEnumField("colour", "green", {1: "red", 2: "green"}),
        BitEnumField("size", 0, 4, ["small", "large"]),
        BitEnumField("pad", 0, 4, {}),
        ShortField("n", 0),
    ]


def test_a_declared_layer_carries_its_names():
    assert Coloured().colour == 2
    p = Coloured(colour="red", size="large")
    assert (p.colour, p.size) == (1, 1)
    assert Coloured(bytes(p)).sprintf("%Coloured.colour% %Coloured.size%") == "red large"
