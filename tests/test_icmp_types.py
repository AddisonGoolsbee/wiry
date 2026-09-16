"""ICMP's type-dependent fields, through the Python API.

The four octets after the checksum mean different things per message type, so
which fields a header has is decided by its type. Vectors are laid out from the
RFC 792 message diagrams, RFC 950 §2 (address mask), RFC 1191 §4 (next-hop MTU)
and RFC 4884 §4 (the extension length octet).
"""

import struct

import pytest
from helpers import checksum

from packetry import ICMP, IP, Ether, Raw


def icmp(type_: int, code: int, rest: bytes, payload: bytes = b"") -> ICMP:
    """Dissect a hand-laid-out ICMP message."""
    return ICMP(struct.pack("!BBH", type_, code, 0) + rest + payload)


ECHO = icmp(8, 0, struct.pack("!HH", 0x1234, 1), b"abcd")
REDIRECT = icmp(5, 1, bytes([10, 0, 0, 1]))
UNREACH = icmp(3, 4, struct.pack("!BBH", 0, 5, 1500))
TIME_EXCEEDED = icmp(11, 0, struct.pack("!BBH", 0, 2, 0))
PARAM_PROBLEM = icmp(12, 0, struct.pack("!BBH", 20, 0, 0))
TIMESTAMP = icmp(13, 0, struct.pack("!HH", 7, 9) + struct.pack("!III", 0x1000, 0x2000, 0x3000))
ADDR_MASK = icmp(17, 0, struct.pack("!HH", 1, 2) + bytes([255, 255, 255, 0]))


@pytest.mark.parametrize(
    "pkt,present",
    [
        (ECHO, ["type", "code", "chksum", "id", "seq"]),
        (REDIRECT, ["type", "code", "chksum", "gw"]),
        (UNREACH, ["type", "code", "chksum", "reserved", "length", "nexthopmtu"]),
        (TIME_EXCEEDED, ["type", "code", "chksum", "reserved", "length"]),
        (PARAM_PROBLEM, ["type", "code", "chksum", "ptr", "length"]),
        (
            TIMESTAMP,
            ["type", "code", "chksum", "id", "seq", "ts_ori", "ts_rx", "ts_tx"],
        ),
        (ADDR_MASK, ["type", "code", "chksum", "id", "seq", "addr_mask"]),
    ],
)
def test_each_message_type_lists_exactly_its_own_fields(pkt, present):
    assert pkt[ICMP].fields() == present


@pytest.mark.parametrize(
    "pkt,absent",
    [
        (ECHO, ["gw", "ptr", "reserved", "length", "ts_ori", "addr_mask", "unused"]),
        (REDIRECT, ["id", "seq", "ptr", "length", "nexthopmtu"]),
        (UNREACH, ["id", "seq", "gw", "ptr", "unused"]),
        (TIME_EXCEEDED, ["nexthopmtu", "id", "gw"]),
        (PARAM_PROBLEM, ["reserved", "nexthopmtu", "id", "gw"]),
        (TIMESTAMP, ["gw", "ptr", "addr_mask", "length"]),
        (ADDR_MASK, ["gw", "ts_ori", "nexthopmtu"]),
    ],
)
def test_reading_a_field_this_type_lacks_raises(pkt, absent):
    for field in absent:
        with pytest.raises(AttributeError):
            getattr(pkt[ICMP], field)


def test_echo_request_values():
    assert ECHO[ICMP].type == 8
    assert ECHO[ICMP].id == 0x1234
    assert ECHO[ICMP].seq == 1
    assert bytes(ECHO).endswith(b"abcd")


def test_redirect_gateway_is_an_address():
    assert REDIRECT[ICMP].gw == "10.0.0.1"
    assert REDIRECT[ICMP].code == 1


def test_destination_unreachable_carries_the_next_hop_mtu():
    assert UNREACH[ICMP].nexthopmtu == 1500
    assert UNREACH[ICMP].length == 5
    assert UNREACH[ICMP].reserved == 0


def test_parameter_problem_carries_a_pointer():
    assert PARAM_PROBLEM[ICMP].ptr == 20


def test_timestamp_carries_three_timestamps_and_a_longer_header():
    assert TIMESTAMP[ICMP].id == 7
    assert TIMESTAMP[ICMP].seq == 9
    assert TIMESTAMP[ICMP].ts_ori == 0x1000
    assert TIMESTAMP[ICMP].ts_rx == 0x2000
    assert TIMESTAMP[ICMP].ts_tx == 0x3000
    assert len(bytes(TIMESTAMP)) == 20


def test_address_mask_reply_carries_a_mask():
    assert ADDR_MASK[ICMP].addr_mask == "255.255.255.0"


def test_router_advertisement_names_its_four_octets_unused():
    # Type 9 has no structured layout here.
    pkt = icmp(9, 0, bytes([1, 2, 3, 4]))
    assert pkt[ICMP].fields() == ["type", "code", "chksum", "unused"]
    assert pkt[ICMP].unused == 0x01020304


def test_extension_fields_are_never_present():
    # RFC 4884 puts them after the quoted datagram, in the payload.
    for pkt in (UNREACH, TIME_EXCEEDED, PARAM_PROBLEM):
        for field in ("ext", "extpad"):
            with pytest.raises(AttributeError):
                getattr(pkt[ICMP], field)


def test_writing_a_field_this_type_lacks_raises():
    pkt = Ether() / IP() / ICMP(type=8)
    pkt[ICMP].type  # materialise, so the write reaches the engine immediately
    with pytest.raises(KeyError):
        pkt[ICMP].gw = "10.0.0.1"


def test_constructing_with_a_field_this_type_lacks_raises():
    with pytest.raises(KeyError):
        bytes(ICMP(type=8, gw="10.0.0.1"))
    with pytest.raises(KeyError):
        bytes(ICMP(type=5, seq=1))


def test_changing_type_changes_which_fields_exist():
    pkt = ICMP(bytes(ECHO))
    pkt[ICMP].type = 5
    assert pkt[ICMP].fields() == ["type", "code", "chksum", "gw"]
    assert pkt[ICMP].gw == "18.52.0.1"
    with pytest.raises(AttributeError):
        pkt[ICMP].id


def test_constructing_each_variant_sets_the_right_octets():
    echo = bytes(ICMP(type=8, id=99, seq=5))
    assert echo == struct.pack("!BBHHH", 8, 0, checksum(echo[:2] + bytes(2) + echo[4:]), 99, 5)
    assert bytes(ICMP(type=5, gw="10.0.0.1"))[4:8] == bytes([10, 0, 0, 1])
    assert bytes(ICMP(type=3, code=4, nexthopmtu=1500))[6:8] == struct.pack("!H", 1500)
    assert bytes(ICMP(type=12, ptr=20))[4] == 20


def test_constructing_a_timestamp_grows_the_header():
    pkt = ICMP(type=13, id=7, seq=9, ts_ori=0x1000, ts_rx=0x2000, ts_tx=0x3000)
    data = bytes(pkt)
    assert len(data) == 20
    assert struct.unpack("!III", data[8:20]) == (0x1000, 0x2000, 0x3000)
    back = ICMP(data)
    assert back[ICMP].ts_tx == 0x3000
    assert back[ICMP].id == 7


def test_constructing_an_address_mask_grows_the_header():
    pkt = ICMP(type=17, addr_mask="255.255.0.0")
    data = bytes(pkt)
    assert len(data) == 12
    assert data[8:12] == bytes([255, 255, 0, 0])


def test_a_grown_header_still_carries_its_payload():
    pkt = IP() / ICMP(type=13, ts_tx=0x3000) / Raw(load=b"pad")
    data = bytes(pkt)
    assert data.endswith(b"pad")
    assert struct.unpack("!I", data[20 + 16 : 20 + 20])[0] == 0x3000


def test_dissecting_under_ip_keeps_the_conditional_fields():
    inner = bytes(ICMP(type=13, id=7, ts_rx=0x2000))
    pkt = Ether(bytes(Ether() / IP() / ICMP(type=13, id=7, ts_rx=0x2000)))
    assert bytes(pkt)[34:] == inner
    assert pkt[ICMP].ts_rx == 0x2000
    assert pkt[ICMP].id == 7
