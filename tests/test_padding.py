"""Padding: bytes on the wire that no enclosing length or checksum counts.

RFC 791 §3.1 defines IPv4 total length as the header plus its own data, and
RFC 768 defines the UDP length the same way. Trailing pad octets belong to the
frame, not to the datagram, so they fall outside both.
"""

from packetry import IP, UDP, Ether, Padding, Raw, TCP, raw


def test_padding_alone_is_just_its_bytes():
    assert raw(Padding("abc")) == b"abc"
    assert raw(Padding(b"abc")) == b"abc"
    assert raw(Padding("abc") / Padding("def")) == b"abcdef"


def test_padding_is_assembled_after_every_payload():
    assert raw(Raw("ABC") / Padding("abc") / Padding("def")) == b"ABCabcdef"
    assert raw(Raw("ABC") / Padding("abc") / Raw("DEF")) == b"ABCDEFabc"
    assert (
        raw(Raw("ABC") / Padding("abc") / Raw("DEF") / Padding("def"))
        == b"ABCDEFabcdef"
    )


def test_padding_is_outside_the_ip_total_length():
    frame = raw(IP() / Padding("abc"))
    assert len(frame) == 23
    assert IP(frame).len == 20


def test_padding_is_outside_the_ip_length_but_payload_is_not():
    frame = raw(IP() / Raw("ABC") / Padding("abc"))
    assert len(frame) == 26
    assert IP(frame).len == 23

    frame = raw(IP() / Raw("ABC") / Padding("abc") / Padding("def"))
    assert len(frame) == 29
    assert IP(frame).len == 23


def test_padding_is_outside_the_udp_length():
    frame = raw(IP() / UDP() / Padding("abcd"))
    pkt = IP(frame)
    assert len(frame) == 32
    assert pkt.len == 28
    assert pkt[UDP].len == 8


def test_padding_is_outside_the_transport_checksums():
    padded = IP() / UDP() / Raw("hello") / Padding("\0\0\0\0")
    bare = IP() / UDP() / Raw("hello")
    assert IP(raw(padded))[UDP].chksum == IP(raw(bare))[UDP].chksum

    padded = IP() / TCP() / Raw("hello") / Padding("\0\0\0\0")
    bare = IP() / TCP() / Raw("hello")
    assert IP(raw(padded))[TCP].chksum == IP(raw(bare))[TCP].chksum


def test_padding_still_reaches_the_wire_under_a_frame():
    frame = raw(Ether() / IP() / UDP() / Padding(b"\0\0\0\0\0\0"))
    assert len(frame) == 14 + 20 + 8 + 6
    assert Ether(frame)[IP].len == 28


def test_a_padding_layer_keeps_its_place_in_the_stack():
    pkt = IP() / Padding("abc")
    assert pkt.layers() == ["IP", "Padding"]
    assert pkt[Padding].load == b"abc"
