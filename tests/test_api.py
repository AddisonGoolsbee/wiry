"""Field access, layer lookup, and the display helpers."""

import io
import contextlib

import pytest

import wiry
from wiry import (
    ARP, Dot1Q, Ether, ICMP, IP, IPv6, Padding, Raw, TCP, UDP, hexdump_str,
    known_layers, ls, raw,
)
from helpers import ETHER_IP_TCP, checksum


@pytest.fixture
def pkt():
    return (
        Ether(dst="00:11:22:33:44:55", src="66:77:88:99:aa:bb")
        / IP(src="10.0.0.1", dst="10.0.0.2", ttl=33)
        / TCP(sport=1234, dport=80, flags="SA")
    )


@pytest.mark.parametrize(
    "layer,field,expected",
    [
        (Ether, "dst", "00:11:22:33:44:55"),
        (Ether, "src", "66:77:88:99:aa:bb"),
        (Ether, "type", 0x0800),
        (IP, "src", "10.0.0.1"),
        (IP, "dst", "10.0.0.2"),
        (IP, "ttl", 33),
        (IP, "version", 4),
        (IP, "ihl", 5),
        (TCP, "sport", 1234),
        (TCP, "dport", 80),
        (TCP, "flags", "SA"),
        (TCP, "window", 8192),
    ],
)
def test_field_reads_through_layer_lookup(pkt, layer, field, expected):
    assert getattr(pkt[layer], field) == expected


def test_fields_are_also_reachable_from_the_packet(pkt):
    assert pkt.ttl == 33
    assert pkt.dport == 80
    assert pkt.type == 0x0800


def test_unknown_field_read_raises_attribute_error(pkt):
    with pytest.raises(AttributeError, match="nosuch"):
        pkt[IP].nosuch
    with pytest.raises(AttributeError, match="nosuch"):
        pkt.nosuch


def test_unknown_field_write_raises(pkt):
    pkt[IP].ttl  # materialise, so the write reaches the engine immediately
    with pytest.raises(KeyError):
        pkt[IP].nosuch = 1
    with pytest.raises(AttributeError):
        pkt.nosuch = 1


def test_layer_lists_its_field_names(pkt):
    assert pkt[TCP].fields()[:4] == ["sport", "dport", "seq", "ack"]
    assert pkt[TCP].name == "TCP"


@pytest.mark.parametrize(
    "layer,field,value",
    [
        (IP, "ttl", 1),
        (IP, "tos", 0x10),
        (IP, "id", 4242),
        (TCP, "dport", 443),
        (TCP, "seq", 0xDEADBEEF),
        (TCP, "window", 1),
        (Ether, "type", 0x86DD),
    ],
)
def test_set_then_read_back(pkt, layer, field, value):
    setattr(pkt[layer], field, value)
    assert getattr(pkt[layer], field) == value
    assert getattr(Ether(bytes(pkt))[layer], field) == value


def test_set_through_the_packet_attribute(pkt):
    pkt.ttl = 99
    assert Ether(bytes(pkt))[IP].ttl == 99


@pytest.mark.parametrize("dotted", ["0.0.0.0", "10.0.0.1", "192.168.255.1", "255.255.255.255"])
def test_ipv4_dotted_quad_strings(pkt, dotted):
    pkt[IP].dst = dotted
    assert Ether(bytes(pkt))[IP].dst == dotted


@pytest.mark.parametrize("mac", ["00:11:22:33:44:55", "aa-bb-cc-dd-ee-ff", "ff:ff:ff:ff:ff:ff"])
def test_mac_strings_accept_both_separators(pkt, mac):
    pkt[Ether].dst = mac
    assert Ether(bytes(pkt))[Ether].dst == mac.replace("-", ":").lower()


def test_an_oversized_byte_value_is_truncated_to_its_field(pkt):
    pkt[IP].src = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    assert pkt[IP].src == "1.2.3.4"
    assert pkt[IP].dst == "10.0.0.2"

    pkt[Ether].src = b"\xaa" * 12
    assert pkt[Ether].src == "aa:aa:aa:aa:aa:aa"
    assert pkt[Ether].dst == "00:11:22:33:44:55"
    assert pkt[Ether].type == 0x0800


@pytest.mark.parametrize("load", [b"ABCDEFGHIJKLMNOP", b"XY", b""])
def test_writing_a_trailing_variable_length_field_resizes_the_frame(load):
    orig = bytes(Ether() / IP() / UDP(sport=4444, dport=4444) / Raw(load=b"12345678"))
    pkt = Ether(orig)
    pkt[Raw].load = load

    out = Ether(bytes(pkt))
    if load:
        assert out[Raw].load == load
    else:
        assert Raw not in out
    assert len(bytes(out)) == len(orig) - 8 + len(load)
    assert out[IP].len == 28 + len(load)
    assert out[UDP].len == 8 + len(load)
    assert checksum(bytes(out)[14:34]) == 0


def test_a_resized_payload_leaves_no_stale_octets():
    orig = bytes(Ether() / IP() / UDP(sport=4444, dport=4444) / Raw(load=b"12345678"))
    pkt = Ether(orig)
    pkt[Raw].load = b"XY"
    assert Ether(bytes(pkt))[Raw].load == b"XY"


def test_a_trailing_pad_survives_a_payload_being_rewritten():
    built = Ether() / IP() / UDP(sport=4444, dport=4444) / Raw(load=b"1234")
    pkt = Ether(bytes(built / Padding(load=b"\x00" * 6)))
    pkt[Raw].load = b"abcdefghij"

    out = Ether(bytes(pkt))
    assert out[Raw].load == b"abcdefghij"
    assert out[Padding].load == b"\x00" * 6
    # RFC 791 §3.1: the pad is not part of the datagram.
    assert out[IP].len == 38


def test_an_option_region_bounded_by_its_header_does_not_resize():
    # TCP options end where the data offset says.
    pkt = Ether(ETHER_IP_TCP)
    pkt[TCP].options = b"\x02\x04\x05\xb4"
    assert len(bytes(pkt)) == len(ETHER_IP_TCP)


@pytest.mark.parametrize(
    "written,read_back",
    [
        ("::", "::"),
        ("::1", "::1"),
        ("2001:db8::1", "2001:db8::1"),
        ("fe80::200:5eff:fe00:5213", "fe80::200:5eff:fe00:5213"),
        # RFC 5952: full form and elided form denote the same address.
        ("0:0:0:0:0:0:0:1", "::1"),
        ("::ffff:192.0.2.1", "::ffff:c000:201"),
    ],
)
def test_ipv6_strings_including_elision(written, read_back):
    pkt = Ether() / IPv6(src=written) / TCP()
    assert Ether(bytes(pkt))[IPv6].src == read_back


@pytest.mark.parametrize(
    "letters,bits",
    [("", 0), ("S", 0x02), ("SA", 0x12), ("FA", 0x11), ("PA", 0x18), ("R", 0x04)],
)
def test_tcp_flag_letters_map_to_the_control_bits(letters, bits):
    pkt = Ether() / IP() / TCP(flags=letters)
    data = bytes(pkt)
    assert data[47] == bits
    assert Ether(data)[TCP].flags == letters


@pytest.mark.parametrize("bits,letters", [(0x02, "S"), (0x12, "SA"), (0x10, "A")])
def test_tcp_flags_accept_a_raw_integer(bits, letters):
    pkt = Ether() / IP() / TCP(flags=bits)
    assert Ether(bytes(pkt))[TCP].flags == letters


def test_ipv4_flags_render_as_names():
    pkt = Ether() / IP(flags="DF") / TCP()
    assert Ether(bytes(pkt))[IP].flags == "DF"
    assert bytes(pkt)[20] & 0x40


@pytest.mark.parametrize("layer", [Ether, IP, TCP])
def test_present_layers_are_found(pkt, layer):
    assert layer in pkt
    assert pkt.haslayer(layer)
    assert pkt.getlayer(layer) is not None


@pytest.mark.parametrize("layer", [UDP, ICMP, ARP, Dot1Q, IPv6])
def test_absent_layers_are_reported_missing(pkt, layer):
    assert layer not in pkt
    assert not pkt.haslayer(layer)
    assert pkt.getlayer(layer) is None
    with pytest.raises(IndexError):
        pkt[layer]


@pytest.mark.parametrize("spec", [TCP, TCP(), "TCP"])
def test_lookup_accepts_class_instance_or_name(pkt, spec):
    assert pkt.haslayer(spec)
    assert pkt.getlayer(spec).name == "TCP"


def test_lookup_rejects_something_that_is_not_a_layer(pkt):
    with pytest.raises(TypeError):
        pkt.haslayer(42)


def test_getlayer_returns_the_outermost_match():
    pkt = Ether() / Dot1Q(vlan=10) / Dot1Q(vlan=20) / IP()
    assert Ether(bytes(pkt)).getlayer(Dot1Q).vlan == 10


def test_summary_joins_the_layer_names(pkt):
    assert pkt.summary() == "Ether / IP / TCP"
    assert Ether(bytes(pkt)).summary() == "Ether / IP / TCP"
    assert repr(pkt) == "<Ether / IP / TCP>"


def test_show_str_lists_every_header_and_field(pkt):
    text = pkt.show_str()
    for header in ("###[ Ether ]###", "###[ IP ]###", "###[ TCP ]###"):
        assert header in text
    for field in ("dst", "src", "ttl", "proto", "chksum", "sport", "dport", "window"):
        assert field in text
    assert "10.0.0.2" in text
    assert text.endswith("\n")


def test_show_prints_what_show_str_returns(pkt):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        pkt.show()
    assert out.getvalue() == pkt.show_str()


def test_hexdump_str_formats_offset_hex_and_text():
    lines = hexdump_str(Ether() / IP()).splitlines()
    assert len(lines) == 3
    assert lines[0].startswith("0000  ff ff ff ff ff ff")
    assert lines[1].startswith("0010  ")
    assert lines[0].endswith("..............E.")
    assert all(len(line) == len(lines[0]) for line in lines[:2])


def test_hexdump_str_accepts_raw_bytes_and_a_width():
    text = hexdump_str(b"ABCDEFGH", width=4)
    assert text == "0000  41 42 43 44  ABCD\n0004  45 46 47 48  EFGH\n"


def test_hexdump_prints(capsys):
    wiry.hexdump(b"AB")
    assert capsys.readouterr().out == hexdump_str(b"AB")


def test_layer_view_repr(pkt):
    assert repr(pkt[IP]) == "<IP layer 1>"


def test_known_layers_matches_the_exported_classes():
    names = known_layers()
    assert names[0] == "Ether"
    assert {"IP", "IPv6", "TCP", "UDP", "ICMP", "ARP", "Raw"} <= set(names)
    for name in wiry._LAYERS:
        assert name in names
        assert getattr(wiry, name)._name == name


def test_ls_lists_layers_and_fields():
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        ls()
    assert out.getvalue().split() == known_layers()

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        ls(TCP)
    assert out.getvalue().split()[:3] == ["sport", "dport", "seq"]


def test_ls_of_a_packet_lists_each_layer(pkt):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        ls(pkt)
    printed = out.getvalue()
    assert "###[ Ether ]###" in printed and "###[ TCP ]###" in printed
    assert "  sport" in printed


def test_ls_verbose_keeps_the_fields_a_header_does_not_carry():
    built = ICMP(bytes(ICMP(type=0)))
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        ls(built)
    terse = out.getvalue()
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        ls(built, verbose=True)
    assert len(out.getvalue()) > len(terse)


def test_layers_are_reachable_by_position(pkt):
    assert pkt[0].name == "Ether"
    assert pkt[1].name == "IP"
    assert pkt[-1].name == "TCP"
    assert pkt[1].ttl == pkt[IP].ttl
    with pytest.raises(IndexError):
        pkt[9]


def test_getlayer_takes_field_filters():
    stack = IP() / IP(ttl=3) / IP(ttl=9)
    assert stack.getlayer(IP, ttl=3).ttl == 3
    assert stack[IP::{"ttl": 9}].ttl == 9
    assert stack.getlayer(IP, ttl=42) is None
    assert stack.getlayer(IP, 2).ttl == 3
    assert stack[IP:3].ttl == 9


def test_iterating_a_packet_yields_an_independent_copy(pkt):
    got = list(pkt)
    assert len(got) == 1
    got[0].ttl = 7
    assert pkt[IP].ttl == 33


def test_a_str_payload_is_latin_1_bytes():
    assert bytes(wiry.Raw("sca") / "py") == b"scapy"
    assert bytes("sca" / wiry.Raw("py")) == b"scapy"
    assert bytes(wiry.Raw("\xff")) == b"\xff"
    joined = wiry.Raw("sca")
    joined.add_payload("py")
    assert bytes(joined) == b"scapy"


def test_public_names_are_exported():
    for name in ("Packet", "PacketList", "rdpcap", "wrpcap", "PcapReader", "raw",
                 "hexdump", "hexdump_str", "ls", "known_layers"):
        assert name in wiry.__all__
        assert hasattr(wiry, name)
    assert set(wiry._LAYERS) <= set(wiry.__all__)


def test_raw_helper_is_the_same_as_bytes(pkt):
    assert raw(pkt) == bytes(pkt)


def test_equality_and_hashing_follow_the_bytes(pkt):
    twin = Ether(bytes(pkt))
    assert pkt == twin
    assert pkt == bytes(pkt)
    assert hash(pkt) == hash(twin)
    assert pkt != Ether() / IP() / TCP()


def test_dissected_packet_exposes_its_time():
    assert Ether(ETHER_IP_TCP).time == 0.0


@pytest.mark.parametrize(
    "layer,field,expected",
    [
        (IPv6, "src", "::1"),
        (IPv6, "dst", "::1"),
    ],
)
def test_an_integer_fills_the_low_order_bits_of_a_field_wider_than_64(layer, field, expected):
    pkt = layer()
    setattr(pkt[layer], field, 1)
    assert getattr(pkt[layer], field) == expected
