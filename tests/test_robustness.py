"""Hostile input: no entry point may panic or allocate without a bound."""

import struct

import pytest

import packetry
from packetry import DNS, IP, TCP, UDP

_b = packetry._packetry


def pkt():
    return IP() / TCP() / b"payload"


@pytest.mark.parametrize("layer", [3, 99, 2**32])
def test_payload_past_the_stack_raises(layer):
    p = pkt()._materialize()
    with pytest.raises(IndexError):
        p.payload(layer)


@pytest.mark.parametrize("layer", [3, 99, 2**32])
def test_set_payload_past_the_stack_raises(layer):
    p = pkt()._materialize()
    with pytest.raises(IndexError):
        p.set_payload(layer, b"x")


def test_payload_within_the_stack_still_works():
    p = pkt()._materialize()
    assert p.payload(0) == bytes(TCP() / b"payload")


@pytest.mark.parametrize("fn", [_b.build_packet, _b.build_and_serialize])
def test_building_with_no_layers_raises(fn):
    with pytest.raises(ValueError):
        fn([], [], [], [], b"x", [])


@pytest.mark.parametrize(
    "load", [2**31, 0, 5, True, [1, 2, 3], range(5), 1.5]
)
@pytest.mark.parametrize("layer", [packetry.Raw, packetry.Padding])
def test_a_non_bytes_load_is_refused_not_allocated(layer, load):
    with pytest.raises(TypeError):
        bytes(IP() / layer(load=load))


@pytest.mark.parametrize("load", [b"ab", bytearray(b"ab"), memoryview(b"ab"), "ab"])
def test_a_bytes_like_load_still_builds(load):
    assert bytes(packetry.Raw(load=load)) == b"ab"


@pytest.mark.parametrize("length", [2**34, 2**16, 8192, -1, True, "4", 4.0])
def test_an_undeclarable_field_width_is_refused_before_it_allocates(length):
    with pytest.raises(ValueError):
        packetry.fields.StrFixedLenField("x", b"", length=length)


def test_the_widest_declarable_field_still_works():
    f = packetry.fields.StrFixedLenField(
        "x", b"ab", length=packetry.fields.MAX_FIELD_OCTETS
    )
    assert len(f.spec()[4]) == packetry.fields.MAX_FIELD_OCTETS


def dns_bomb() -> bytes:
    """2.75 MB claiming 65,535 records in every section, each a two-octet
    pointer to one maximal name of octets that decode three bytes wide."""
    n = 0xFFFF
    msg = struct.pack(">HHHHHH", 0x1234, 0x8180, n, n, n, n)
    msg += (bytes([63]) + b"\xff" * 63) * 3 + b"\x00" + struct.pack(">HH", 1, 1)
    msg += (b"\xc0\x0c" + struct.pack(">HH", 1, 1)) * (n - 1)
    msg += (b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 0, 0)) * (3 * n)
    return msg


def test_a_dns_decompression_bomb_decodes_a_bounded_amount():
    msg = dns_bomb()
    dns = (UDP(sport=53, dport=53) / DNS(msg))["DNS"]
    sections = [getattr(dns, s) for s in ("qd", "an", "ns", "ar")]
    decoded = sum(
        len(r.get("qname", r.get("rrname", ""))) for s in sections for r in s
    )
    # The engine budgets decoded bytes; a replacement character is one Python
    # character per three, so this is under the 256 KB cap.
    assert decoded <= 256 * 1024
    assert sum(len(s) for s in sections) < 0xFFFF
