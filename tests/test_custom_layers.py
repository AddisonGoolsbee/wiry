"""User-defined layers: declared in Python, executed in Rust.

Every layout here is invented for the test, so nothing is derived from another
packet library.
"""

import pytest

from wiry import IP, UDP, Ether, Packet, TCP, bind_layers, known_layers, rdpcap, wrpcap
from wiry.fields import (
    BitField, ByteField, FlagsField, IP6Field, IPField, IntField, LEShortField,
    LongField, MACField, ShortField, StrField, StrFixedLenField, XByteField,
    XIntField, XShortField,
)


class MyProto(Packet):
    name = "MyProto"
    fields_desc = [
        ByteField("version", 1),
        BitField("flags", 0, 4),
        BitField("reserved", 0, 4),
        ShortField("length", 0),
        IntField("magic", 0xDEADBEEF),
        IPField("peer", "0.0.0.0"),
    ]


bind_layers(UDP, MyProto, dport=9999)


class Every(Packet):
    name = "Every"
    fields_desc = [
        ByteField("b", 0x11),
        XByteField("xb", 0x22),
        ShortField("s", 0x3344),
        XShortField("xs", 0x5566),
        LEShortField("les", 0x0102),
        IntField("i", 0x778899AA),
        XIntField("xi", 0xBBCCDDEE),
        LongField("l", 0x0102030405060708),
        IPField("ip", "10.0.0.1"),
        IP6Field("ip6", "2001:db8::1"),
        MACField("mac", "00:11:22:33:44:55"),
        StrFixedLenField("tag", b"abc", 4),
        FlagsField("fl", 0, 8, ["A", "B", "C", "D"]),
    ]


class Bits(Packet):
    name = "Bits"
    fields_desc = [
        BitField("a", 0, 3),
        BitField("b", 0, 7),
        BitField("c", 0, 6),
        ByteField("tail", 0),
    ]


class Other(Packet):
    name = "Other"
    fields_desc = [ShortField("token", 0xBEEF)]


bind_layers(TCP, Other, dport=7777)


class Trailer(Packet):
    name = "Trailer"
    fields_desc = [ByteField("kind", 7), StrField("data", b"")]


bind_layers(UDP, Trailer, dport=8888)


def test_a_declared_layer_joins_the_known_layers():
    assert "MyProto" in known_layers()
    assert "Every" in known_layers()


def test_the_documented_example_round_trips():
    pkt = IP() / UDP(dport=9999) / MyProto(version=2, peer="10.0.0.1")
    back = IP(bytes(pkt))
    assert back[MyProto].version == 2
    assert back[MyProto].peer == "10.0.0.1"
    assert back[MyProto].magic == 0xDEADBEEF
    assert MyProto in back
    assert back.layers() == ["IP", "UDP", "MyProto"]


def test_stacking_sets_the_parent_field_automatically():
    pkt = IP() / UDP() / MyProto()
    assert pkt[UDP].dport == 9999
    other = IP() / UDP(dport=1234) / MyProto()
    assert other[UDP].dport == 1234


def test_the_header_is_exactly_as_wide_as_its_fields():
    assert len(bytes(MyProto())) == 1 + 1 + 2 + 4 + 4
    assert bytes(MyProto()) == b"\x01\x00\x00\x00\xde\xad\xbe\xef\x00\x00\x00\x00"


def test_every_field_class_round_trips_its_value():
    pkt = Every()
    back = Every(bytes(pkt))
    assert back.b == 0x11
    assert back.xb == 0x22
    assert back.s == 0x3344
    assert back.xs == 0x5566
    assert back.les == 0x0102
    assert back.i == 0x778899AA
    assert back.xi == 0xBBCCDDEE
    assert back.l == 0x0102030405060708
    assert back.ip == "10.0.0.1"
    assert back.ip6 == "2001:db8::1"
    assert back.mac == "00:11:22:33:44:55"
    assert back.tag == b"abc\x00"
    assert back.fl == ""


def test_little_endian_fields_are_byte_reversed_on_the_wire():
    raw = bytes(Every())
    assert raw[6:8] == b"\x02\x01"
    changed = Every(les=0x00FF)
    assert bytes(changed)[6:8] == b"\xff\x00"
    assert Every(bytes(changed)).les == 0x00FF


def test_values_can_be_set_and_read_back():
    pkt = Every(b=9, s=0x1234, ip="192.0.2.7", mac="aa:bb:cc:dd:ee:ff", tag=b"zz")
    back = Every(bytes(pkt))
    assert back.b == 9
    assert back.s == 0x1234
    assert back.ip == "192.0.2.7"
    assert back.mac == "aa:bb:cc:dd:ee:ff"
    assert back.tag == b"zz\x00\x00"


def test_flags_render_by_name():
    assert Every(fl=0b0101).fl == "AC"
    assert Every(bytes(Every(fl=0b1010))).fl == "BD"


def test_bit_fields_pack_across_byte_boundaries():
    # 3 + 7 + 6 bits fills two octets exactly.
    pkt = Bits(a=0b101, b=0b1111111, c=0b000000, tail=0xFF)
    assert bytes(pkt) == b"\xbf\xc0\xff"
    back = Bits(bytes(pkt))
    assert (back.a, back.b, back.c, back.tail) == (0b101, 0b1111111, 0, 0xFF)
    assert len(bytes(Bits())) == 3


def test_fields_that_do_not_fill_whole_bytes_are_rejected():
    with pytest.raises(ValueError) as exc:

        class Ragged(Packet):
            name = "Ragged"
            fields_desc = [BitField("a", 0, 3), BitField("b", 0, 2)]

    assert "whole number of bytes" in str(exc.value)
    assert "Ragged" not in known_layers()


def test_a_variable_length_field_that_is_not_last_is_rejected():
    with pytest.raises(ValueError) as exc:

        class TwoVar(Packet):
            name = "TwoVar"
            fields_desc = [
                StrField("a", b"xx"), ByteField("n", 1), StrField("b", b"yy"),
            ]

    assert "must be the last field" in str(exc.value)
    assert "TwoVar" not in known_layers()


def test_a_builtin_name_cannot_be_taken_over():
    with pytest.raises(ValueError):

        class Clash(Packet):
            name = "TCP"
            fields_desc = [ByteField("x", 0)]


def test_binding_reaches_the_layer_through_a_whole_stack():
    pkt = Ether() / IP() / UDP(dport=9999) / MyProto(version=5)
    back = Ether(bytes(pkt))
    assert back.layers() == ["Ether", "IP", "UDP", "MyProto"]
    assert back[MyProto].version == 5


def test_an_unbound_value_does_not_reach_the_layer():
    pkt = Ether() / IP() / UDP(sport=1, dport=1234) / MyProto()
    back = Ether(bytes(pkt))
    assert "MyProto" not in back.layers()
    assert back.layers()[-1] == "Raw"


def test_two_custom_layers_coexist():
    a = IP() / UDP(dport=9999) / MyProto(version=3)
    b = IP() / TCP(dport=7777) / Other(token=0x1234)
    assert IP(bytes(a))[MyProto].version == 3
    assert IP(bytes(b))[Other].token == 0x1234
    assert Other not in IP(bytes(a))
    assert MyProto not in IP(bytes(b))


def test_a_trailing_string_field_takes_the_rest_of_the_packet():
    pkt = IP() / UDP(dport=8888) / Trailer(kind=9, data=b"hello world")
    back = IP(bytes(pkt))
    assert back[Trailer].kind == 9
    assert back[Trailer].data == b"hello world"


@pytest.mark.parametrize("data", [b"much longer than before", b"hi"])
def test_rewriting_a_trailing_string_field_resizes_the_packet(data):
    pkt = IP(bytes(IP() / UDP(dport=8888) / Trailer(kind=9, data=b"hello world")))
    pkt[Trailer].data = data

    back = IP(bytes(pkt))
    assert back[Trailer].data == data
    assert back[Trailer].kind == 9
    assert back[UDP].len == 8 + 1 + len(data)


def test_show_and_summary_name_the_layer_and_its_fields():
    pkt = IP() / UDP(dport=9999) / MyProto(version=4)
    text = pkt.show_str()
    assert "###[ MyProto ]###" in text
    assert "version    = 4" in text
    assert "peer       = 0.0.0.0" in text
    assert pkt.summary().endswith("MyProto")
    assert IP(bytes(pkt)).summary() == "IP / UDP / MyProto"


def test_field_names_are_listed_in_declaration_order():
    pkt = IP(bytes(IP() / UDP(dport=9999) / MyProto()))
    assert pkt[MyProto].fields() == [
        "version", "flags", "reserved", "length", "magic", "peer",
    ]


def test_a_layer_is_reachable_from_a_capture_and_the_columnar_api(tmp_path):
    pkts = [
        Ether() / IP(dst="10.0.0.%d" % i) / UDP(dport=9999) / MyProto(version=i)
        for i in range(4)
    ]
    pkts.append(Ether() / IP(dst="10.9.9.9") / UDP(sport=1, dport=4) / b"nope")
    path = str(tmp_path / "custom.pcap")
    wrpcap(path, pkts)
    cap = rdpcap(path)

    assert cap.count_layer(MyProto) == 4
    cols = cap.columns([("IP", "dst"), ("MyProto", "version"), ("MyProto", "peer")])
    assert cols["MyProto.version"] == [0, 1, 2, 3, None]
    assert cols["MyProto.peer"][0] == "0.0.0.0"
    assert cols["IP.dst"][4] == "10.9.9.9"

    loop = [p[MyProto].version if MyProto in p else None for p in cap]
    assert loop == cols["MyProto.version"]

    only = cap.filter(layer=MyProto, where=[("MyProto", "version", ">=", 2)])
    assert len(only) == 2
    assert cap.filter_indices(layer=MyProto, where=[("MyProto", "version", ">=", 2)]) == [2, 3]


def test_a_layer_without_fields_desc_still_behaves_as_before():
    class Plain(Packet):
        pass

    assert "Plain" not in known_layers()
    assert Plain()._stack == []


def test_a_declared_layer_is_discoverable_like_a_built_in():
    import io
    import contextlib

    from wiry import explore, ls

    class Declared(Packet):
        name = "Declared"
        fields_desc = [ByteField("kind", 7), ShortField("size", 300)]

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        ls(Declared)
        explore("Declared")
    printed = out.getvalue()
    # Its defaults come from the layer it declared, not from the empty table a
    # layer missing from the registry would give.
    assert "(7)" in printed and "(300)" in printed
    assert "3 octets" in printed
    assert "kind" in dir(Declared)
    assert Declared.kind.bits == 8


def test_redeclaring_a_name_describes_the_layer_that_won():
    import io
    import contextlib

    from wiry import ls

    class First(Packet):
        name = "Twice"
        fields_desc = [ByteField("a", 1)]

    ls(First)

    class Second(Packet):
        name = "Twice"
        fields_desc = [ByteField("b", 2)]

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        ls(Second)
    assert "b" in out.getvalue() and "\na " not in out.getvalue()
