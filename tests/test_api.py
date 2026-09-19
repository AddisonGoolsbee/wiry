"""Field access, layer lookup, and the display helpers."""

import io
import contextlib

import pytest

import wiry
from wiry import (
    ARP, Dot1Q, Ether, ICMP, IP, IPv6, Padding, Raw, TCP, UDP, hexdump_str,
    known_layers, ls, lsc, explore, raw,
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


def test_writing_options_grows_the_header_instead_of_the_next_layer():
    """The option region used to be written over whatever followed it: the
    frame kept its length, the data offset never moved, and the bytes landed on
    the payload or the next layer."""
    pkt = Ether(ETHER_IP_TCP)
    assert pkt[TCP].dataofs == 5
    pkt[TCP].options = b"\x02\x04\x05\xb4"

    out = Ether(bytes(pkt))
    assert len(bytes(pkt)) == len(ETHER_IP_TCP) + 4
    assert out[TCP].dataofs == 6
    assert out[TCP].options == [("MSS", 1460)]
    assert out[IP].len == 44


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
    # Two sets, and they stopped being the same set once a user could declare
    # a layer: `_LAYERS` is every layer class wiry knows, and `__all__` is the
    # ones it ships. A declared layer is in the first and not the second.
    for name, cls in wiry._LAYERS.items():
        assert name in names
        assert cls._name == name
    for name in set(wiry.__all__) & set(names):
        assert getattr(wiry, name)._name == name


def _printed(fn, *a, **kw):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        fn(*a, **kw)
    return out.getvalue()


def test_ls_lists_every_layer_with_its_shape():
    lines = [ln for ln in _printed(ls).splitlines() if " : " in ln]
    assert [ln.split()[0] for ln in lines] == sorted(known_layers())
    assert "fields" in lines[0] and "octets" in lines[0]


def test_ls_of_a_class_names_each_field_its_type_and_its_default():
    printed = _printed(ls, TCP)
    assert [ln.split()[0] for ln in printed.splitlines()][:3] == [
        "sport", "dport", "seq"
    ]
    # A computed field has no default: it has whatever the octets make it.
    assert "chksum" in printed and "computed" in printed
    assert "(None)" in printed
    assert "uint (2 bytes)" in printed and "flags (9 bits)" in printed


def test_ls_searches_by_name_closest_match_first():
    printed = _printed(ls, "tcp")
    names = [ln.split()[0] for ln in printed.splitlines() if " : " in ln]
    assert names[0] == "TCP"
    assert "RTCP" in names
    assert "UDP" not in names


def test_ls_of_a_packet_lists_each_layer_with_values_and_defaults(pkt):
    printed = _printed(ls, pkt)
    assert "###[ Ether ]###" in printed and "###[ TCP ]###" in printed
    # value first, then the default it was compared against
    assert "= 80" in printed and "(80)" in printed
    assert "'00:11:22:33:44:55'" in printed


def test_ls_verbose_names_the_bits_of_a_flags_field():
    assert "F, S, R" not in _printed(ls, TCP)
    assert "F, S, R, P, A, U, E, C, N" in _printed(ls, TCP, verbose=True)


def test_ls_of_something_that_is_not_a_layer_says_so():
    assert "Not a packet class" in _printed(ls, object())


def test_lsc_lists_commands_with_their_first_doc_line():
    printed = _printed(lsc)
    assert "rdpcap" in printed and "sniff" in printed
    # Layers and value classes are not commands.
    assert "\nIP " not in printed and "RandIP " not in printed
    assert "wrpcap" in _printed(lsc, "pcap")
    assert "sniff" not in _printed(lsc, "pcap")


def test_explore_shows_one_layer_in_full():
    printed = _printed(explore, "TCP")
    assert "###[ TCP ]###" in printed
    assert "dataofs" in printed
    assert "options" in printed


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
    assert set(wiry.__all__) & set(known_layers()) <= set(wiry._LAYERS)


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


# --- the surface a script reaches for ------------------------------------

def test_a_packet_walks_its_own_layers(pkt):
    assert [v.name for v in pkt.iterpayloads()] == ["Ether", "IP", "TCP"]
    assert pkt.firstlayer().name == "Ether"
    assert pkt.lastlayer().name == "TCP"
    assert pkt.name == "Ether"


def test_field_values_are_reachable_by_name(pkt):
    assert pkt.getfieldval("ttl") == 33
    pkt.setfieldval("ttl", 5)
    assert pkt.ttl == 5
    info, value = pkt.getfield_and_val("dport")
    assert info.name == "dport" and value == 80
    assert pkt.get_field("ttl").kind == "uint"
    with pytest.raises(KeyError):
        pkt.get_field("nosuch")


def test_unsetting_a_field_puts_its_default_back():
    p = IP(ttl=9, id=4)
    p.delfieldval("ttl")
    with pytest.raises(AttributeError):
        p.delfieldval("ttl")
    assert p.ttl == 64 and p.id == 4


@pytest.mark.parametrize("call", [
    lambda p: p.delfieldval("ttl"),
    lambda p: p.hide_defaults(),
    lambda p: p.clone_with(ttl=1),
    lambda p: p.remove_payload(),
])
def test_editing_the_spec_needs_a_packet_that_is_still_a_spec(call):
    # Reading a field builds the packet, and from then on the octets are the
    # truth; the stack that made them is not, so these four refuse rather than
    # quietly editing something nobody will serialise. This is fuzz()'s rule.
    p = IP(ttl=9) / TCP()
    p.ttl
    with pytest.raises(NotImplementedError):
        call(p)


def test_hiding_defaults_leaves_only_what_was_chosen():
    p = IP(ttl=64, id=4, dst="10.0.0.1")
    p.hide_defaults()
    assert p.fields == {"id": 4, "dst": "10.0.0.1"}
    assert p.ttl == 64


def test_clone_with_replaces_the_bottom_layers_fields():
    p = IP(ttl=9) / TCP(dport=80)
    clone = p.clone_with(ttl=3)
    assert p.clone_with(ttl=3, dst="10.0.0.9") / Raw(b"x") == bytes(
        IP(ttl=3, dst="10.0.0.9") / TCP(dport=80) / Raw(b"x")
    )
    assert clone.ttl == 3 and clone.dport == 80
    assert p.ttl == 9


def test_removing_the_payload_leaves_the_bottom_layer():
    p = IP(ttl=9) / TCP(dport=80)
    p.remove_payload()
    assert p.layers() == ["IP"]
    assert bytes(p) == bytes(IP(ttl=9))


def test_a_packet_reports_what_its_bottom_layer_declares(pkt):
    assert [f.name for f in pkt.fields_desc][:2] == ["dst", "src"]
    assert pkt.default_fields["dst"] == "ff:ff:ff:ff:ff:ff"
    assert pkt[IP].default_fields["ttl"] == 64
    assert pkt[IP].get_field("ttl").bits == 8


def test_a_dissected_packet_reports_the_values_its_header_holds():
    p = IP(bytes(IP(ttl=9)))
    assert p.fields["ttl"] == 9
    assert p.fields["version"] == 4


def test_from_hexcap_reads_a_pasted_dump():
    data = bytes(Ether() / IP(ttl=9) / TCP(dport=80))
    dump = "\n".join(
        "%04x  %s  %s" % (
            off,
            " ".join(f"{b:02x}" for b in data[off:off + 16]),
            "".join(chr(b) if 32 <= b < 127 else "." for b in data[off:off + 16]),
        )
        for off in range(0, len(data), 16)
    )
    back = Ether.from_hexcap(dump)
    assert bytes(back) == data
    assert back.layers() == ["Ether", "IP", "TCP"]
    with pytest.raises(TypeError, match="call from_hexcap"):
        wiry.Packet.from_hexcap("00")


def test_from_hexcap_takes_a_bare_hex_run_too():
    from wiry.describe import from_hexcap

    assert from_hexcap("00 11 22\n33 44") == b"\x00\x11\x223\x44"
    # An offset column needs a colon or two spaces after it to be one.
    assert from_hexcap("0000:  0011 2233") == b"\x00\x11\x223"
    assert from_hexcap("0010  00 11") == b"\x00\x11"


def test_display_is_show(pkt):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        pkt.display()
    assert out.getvalue() == pkt.show_str()
