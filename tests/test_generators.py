"""Generators: one declaration that multiplies into many packets.

Read and write are covered separately: reading a generator field back, and the
bytes every expansion actually produces.
"""

import itertools
import struct
import sys
import time

import pytest

import wiry
from wiry import (
    Ether, ICMP, IP, IPv6, Net, Net6, RandBin, RandByte, RandChoice,
    RandEnumKeys, RandInt, RandIP, RandIP6, RandMAC, RandNum, RandShort,
    RandString, TCP, UDP, VolatileValue, corrupt_bits, corrupt_bytes, fuzz,
    set_rand_seed,
)
from helpers import checksum


def test_a_range_expands_inclusively():
    assert [p.ttl for p in IP(ttl=(5, 10))] == [5, 6, 7, 8, 9, 10]


def test_a_list_expands_to_its_values():
    assert [p[TCP].dport for p in TCP(dport=[80, 443])] == [80, 443]


def test_a_list_may_hold_ranges():
    assert [p.ttl for p in IP(ttl=[1, 2, (5, 9)])] == [1, 2, 5, 6, 7, 8, 9]


def test_the_product_follows_scapys_order():
    pkt = Ether() / IP(ttl=(5, 10)) / TCP(dport=[80, 443])
    got = [(p[IP].ttl, p[TCP].dport) for p in pkt]
    assert len(got) == 12
    assert got[:4] == [(5, 80), (5, 443), (6, 80), (6, 443)]
    assert got[-1] == (10, 443)


def test_the_last_field_of_a_layer_varies_slowest():
    # `src` is declared after `tos`, so it is the outer loop.
    pkt = IP(tos=[1, 2], src=["1.1.1.1", "2.2.2.2"])
    assert [(p.tos, p.src) for p in pkt] == [
        (1, "1.1.1.1"), (2, "1.1.1.1"), (1, "2.2.2.2"), (2, "2.2.2.2"),
    ]


def test_an_address_tuple_is_a_range_of_addresses():
    assert len(list(IP(dst=("192.168.0.100", "192.168.0.199")))) == 100
    assert len(list(IPv6(dst=("fe80::1", "fe80::1f")))) == 31


def test_a_cidr_string_in_an_address_field_is_a_net():
    assert [p.dst for p in IP(dst="10.0.0.0/30")] == [
        "10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3",
    ]
    assert IP(dst="10.0.0.0/30").dst == Net("10.0.0.0/30")


def test_a_slash_outside_an_address_field_is_just_a_character():
    assert bytes(wiry.Raw(load="a/b")) == b"a/b"


def test_a_generator_field_reads_back_as_the_generator():
    assert IP(ttl=(5, 10)).ttl == (5, 10)
    assert IP(dst=["1.1.1.1", "2.2.2.2"]).dst == ["1.1.1.1", "2.2.2.2"]
    assert IP(dst=["1.1.1.1", "2.2.2.2"]).dst[0] == "1.1.1.1"


def test_a_generator_assigned_after_construction_still_expands():
    pkt = IP() / TCP()
    pkt[TCP].dport = [1, 2]
    assert [p[TCP].dport for p in pkt] == [1, 2]


def test_an_ordinary_packet_still_iterates_once():
    pkt = IP()
    assert len(list(pkt)) == 1
    assert list(pkt)[0] is not pkt


def test_iteration_yields_independent_copies():
    pkt = Ether() / IP() / ICMP()
    for one in pkt:
        one.sent_time = 1
    assert pkt.sent_time is None


def test_every_expanded_packet_gets_its_own_computed_fields():
    for p in IP(ttl=(1, 8)) / UDP():
        raw = bytes(p)
        assert checksum(raw[:20]) == 0
        assert struct.unpack("!H", raw[2:4])[0] == len(raw)


def test_expanding_a_product_runs_no_python():
    # The whole point of the feature: a naive binding would hand Python one
    # object per packet, and the Rust would buy nothing.
    tmpl = (Ether() / IP(dst=Net("10.0.0.0/22"))).template()
    seen = [0]

    def count(frame, event, arg):
        if event in ("call", "c_call"):
            seen[0] += 1

    sys.setprofile(count)
    try:
        frames = tmpl.frames(0, 1024)
    finally:
        sys.setprofile(None)
    assert len(frames) == 1024
    assert seen[0] <= 2


def test_the_bulk_path_agrees_with_the_per_packet_path():
    pkt = Ether() / IP(dst=Net("10.0.0.0/29")) / TCP(dport=[80, 443])
    tmpl = pkt.template()
    assert [bytes(p) for p in pkt] == list(tmpl.frames(0, tmpl.count))


def _routes(tmp_path):
    """Every way a template can be realised, as lists of octets."""
    def whole_chunk(p):
        t = p.template()
        return list(t.frames(0, int(t.count)))

    def one_index_at_a_time(p):
        t = p.template()
        return [bytes(t.frame(i)) for i in range(int(t.count))]

    def unaligned_chunks(p):
        t, out, at = p.template(), [], 0
        while at < t.count:
            chunk = list(t.frames(at, 7))
            if not chunk:
                break
            out += chunk
            at += len(chunk)
        return out

    def through_a_file(p):
        path = str(tmp_path / "routes.pcap")
        wiry.wrpcap(path, p)
        return [bytes(q) for q in wiry.rdpcap(path)]

    return {
        "iter": lambda p: [bytes(q) for q in p],
        "expand": lambda p: [bytes(q) for q in wiry.expand(p)],
        "frames": lambda p: list(wiry._expand_frames(p)),
        "whole_chunk": whole_chunk,
        "one_at_a_time": one_index_at_a_time,
        "unaligned": unaligned_chunks,
        "wrpcap": through_a_file,
    }


@pytest.mark.parametrize(
    "build",
    [lambda: IP(ttl=[1, 2, (5, 9)]),
     lambda: Ether() / IP(dst=Net("10.0.0.0/23")),
     lambda: Ether() / IP(ttl=(1, 3)) / TCP(dport=[80, 443], options=[("MSS", 1460)]),
     lambda: Ether() / IPv6(dst=Net6("2001:db8::/124")),
     lambda: Ether() / IP(ttl=(1, 4)) / UDP() / wiry.Raw(load=b"Z" * 1400),
     lambda: Ether() / IP(ttl=(1, 3)) / wiry.Padding(b"pad"),
     lambda: Ether() / wiry.ARP(pdst=Net("10.0.0.0/29"))],
)
def test_every_route_through_a_template_produces_the_same_octets(build, tmp_path):
    # CLAUDE.md: if the bulk path and the per-packet path disagree, the bulk
    # path is wrong. One case crosses the 256-packet chunk boundary.
    got = {name: route(build()) for name, route in _routes(tmp_path).items()}
    for name, frames in got.items():
        assert frames == got["iter"], f"route {name!r} disagrees"


def test_a_template_serialises_as_its_first_packet():
    pkt = IP(ttl=(5, 10))
    assert bytes(pkt) == bytes(next(iter(pkt)))


def test_an_empty_generator_is_refused():
    with pytest.raises(ValueError, match="no packets"):
        bytes(IP(ttl=[]))


def test_a_template_stacks_like_any_other_packet():
    pkt = Ether() / IP(ttl=(1, 2)) / TCP()
    assert pkt.layers() == ["Ether", "IP", "TCP"]
    assert len(list(pkt)) == 2


def test_a_huge_product_is_counted_but_never_built():
    pkt = IP(src=Net("10.0.0.0/8"), dst=Net("10.0.0.0/8"))
    assert pkt.template().count == 2 ** 48
    first = list(itertools.islice(iter(pkt), 3))
    assert [p.dst for p in first] == ["10.0.0.0"] * 3
    assert [p.src for p in first] == ["10.0.0.0", "10.0.0.1", "10.0.0.2"]


def test_an_index_past_the_product_is_refused():
    # The walk is modular, so an unchecked index silently returns packet 0.
    tmpl = IP(ttl=(1, 3)).template()
    assert bytes(tmpl.frame(2))[8] == 3
    for past in (3, 4, 2 ** 128 - 1):
        with pytest.raises(IndexError, match="past the 3"):
            tmpl.frame(past)
        with pytest.raises(IndexError, match="past the 3"):
            tmpl.packet(past)


def test_a_template_may_be_iterated_more_than_once():
    pkt = IP(dst=Net("10.0.0.0/30"))
    assert [p.dst for p in pkt] == [p.dst for p in pkt]
    assert len(list(pkt)) == 4


def test_the_widest_address_space_saturates_its_count():
    # u128 cannot hold 2**128, so the template reports one packet fewer than
    # Net6 itself counts. Anything wider saturates outright.
    assert Net6("::/0").__iterlen__() == 2 ** 128
    assert IPv6(dst=Net6("::/0")).template().count == 2 ** 128 - 1
    assert IPv6(src=Net6("::/0"), dst=Net6("::/0")).template().count == 2 ** 128 - 1


def test_a_saturated_count_still_refuses_a_helper(tmp_path):
    with pytest.raises(ValueError, match="iterate it instead"):
        wiry.wrpcap(str(tmp_path / "x.pcap"), IPv6(dst=Net6("::/0")))


def test_a_helper_that_must_materialise_refuses_a_huge_product(tmp_path):
    pkt = IP(src=Net("10.0.0.0/8"), dst=Net("10.0.0.0/8"))
    with pytest.raises(ValueError, match="iterate it instead"):
        wiry.wrpcap(str(tmp_path / "x.pcap"), pkt)


def test_wrpcap_expands_a_template(tmp_path):
    path = str(tmp_path / "gen.pcap")
    wiry.wrpcap(path, Ether() / IP(dst=Net("10.0.0.0/30")))
    got = wiry.rdpcap(path)
    assert [p[IP].dst for p in got] == [
        "10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3",
    ]


def test_wrpcap_mixes_templates_and_plain_packets(tmp_path):
    path = str(tmp_path / "mix.pcap")
    wiry.wrpcap(path, [Ether() / IP(ttl=(1, 3)), Ether() / IP(ttl=9)])
    assert [p[IP].ttl for p in wiry.rdpcap(path)] == [1, 2, 3, 9]


# --- Net ------------------------------------------------------------------

def test_net_iterates_its_addresses():
    assert list(Net("192.168.0.0/31")) == ["192.168.0.0", "192.168.0.1"]


def test_net_takes_a_first_and_last_address():
    assert Net("1.2.3.0/24") == Net("1.2.3.0", "1.2.3.255")
    assert hash(Net("1.2.3.0/24")) == hash(Net("1.2.3.0", "1.2.3.255"))


def test_net_contains_addresses_and_subnets():
    assert "1.2.3.4" in Net("0.0.0.0/0")
    assert "192.168.0.0/25" in Net("192.168.0.0/24")
    assert "192.168.0.0/23" not in Net("192.168.0.0/24")
    assert "0.0.0.0/1" in Net("0.0.0.0/0")
    assert "0.0.0.0/0" not in Net("0.0.0.0/1")


def test_net_masks_off_the_host_bits():
    assert list(Net("192.168.0.3/30"))[0] == "192.168.0.0"


def test_a_bare_address_is_a_single_address_net():
    assert list(Net("1.2.3.4")) == ["1.2.3.4"]
    assert repr(Net("1.2.3.4")) == 'Net("1.2.3.4/32")'


def test_net6_matches_net_but_not_across_families():
    assert len(list(Net6("2001:db8::/127"))) == 2
    assert len(Net6("fec0::/110")) == 262144
    assert "ffff::ffff" in Net6("::/0")
    assert "::/1" in Net6("::/0")
    assert "::/0" not in Net6("::/1")
    assert Net6("::/120") == Net6("::", "::ff")
    assert Net6("::1.2.3.0/120") != Net("1.2.3.0/24")
    assert hash(Net6("::1.2.3.0/120")) != hash(Net("1.2.3.0/24"))


def test_a_net_too_wide_for_len_still_reports_its_count():
    assert Net6("::/0").__iterlen__() == 2 ** 128
    with pytest.raises(OverflowError):
        len(Net6("::/0"))


def test_a_bad_prefix_is_refused():
    for bad in ["1.2.3.4/33", "1.2.3.4/x", "1.2.3.4.5/8", "not-an-address"]:
        with pytest.raises(ValueError):
            Net(bad)


def test_a_hostname_is_not_resolved():
    with pytest.raises(ValueError):
        Net("example.com")


# --- volatile values ------------------------------------------------------

@pytest.mark.parametrize(
    "make,lo,hi",
    [(RandByte, 0, 0xFF), (RandShort, 0, 0xFFFF), (RandInt, 0, 0xFFFFFFFF)],
)
def test_a_random_integer_stays_in_its_width(make, lo, hi):
    for _ in range(200):
        assert lo <= int(make()) <= hi


def test_randnum_stays_inside_its_range():
    for _ in range(200):
        assert 7 <= int(RandNum(7, 9)) <= 9


def test_a_random_address_renders_as_an_address():
    assert str(RandIP("10.1.2.0/24")).startswith("10.1.2.")
    assert str(RandIP6("2001:db8::/120")).startswith("2001:db8::")
    assert str(RandMAC("00:11:22")).startswith("00:11:22:")
    assert len(bytes(RandIP())) == 4
    assert len(bytes(RandIP6())) == 16
    assert len(bytes(RandMAC())) == 6


def test_a_random_string_keeps_to_its_alphabet():
    for _ in range(50):
        assert bytes(RandString(8)).isalnum()
        assert len(bytes(RandString(8))) == 8
    assert len(bytes(RandBin(5))) == 5


def test_a_choice_only_ever_yields_one_of_its_values():
    seen = {int(RandChoice(3, 5, 9)) for _ in range(200)}
    assert seen and seen <= {3, 5, 9}
    keys = {str(RandEnumKeys({"a": 1, "b": 2})) for _ in range(100)}
    assert keys <= {"a", "b"}


def test_a_volatile_value_is_drawn_afresh_each_time():
    r = RandInt()
    assert len({int(r) for _ in range(50)}) > 1


def test_a_volatile_field_does_not_multiply_the_packet():
    pkt = IP(id=RandShort())
    assert len(list(pkt)) == 1
    assert len({bytes(pkt) for _ in range(20)}) > 1


def test_a_volatile_field_still_lands_in_the_right_octets():
    for _ in range(20):
        raw = bytes(IP(src=RandIP("10.9.0.0/16")))
        assert raw[12] == 10 and raw[13] == 9


def test_a_seed_repeats_a_run():
    set_rand_seed(4242)
    first = [bytes(fuzz(IP() / TCP())) for _ in range(5)]
    set_rand_seed(4242)
    assert [bytes(fuzz(IP() / TCP())) for _ in range(5)] == first


# --- fuzz -----------------------------------------------------------------

def test_fuzz_leaves_the_fields_the_caller_pinned():
    pkt = fuzz(IP(tos=2) / ICMP())
    assert pkt.tos == 2
    assert all(bytes(pkt)[1] == 2 for _ in range(20))


def test_fuzz_randomises_the_rest():
    pkt = fuzz(IP() / TCP())
    assert isinstance(pkt.ttl, VolatileValue)
    assert len({bytes(pkt) for _ in range(20)}) > 1


def test_fuzz_leaves_computed_fields_to_be_computed():
    for _ in range(50):
        raw = bytes(fuzz(IP()))
        assert checksum(raw[:20]) == 0
        assert struct.unpack("!H", raw[2:4])[0] == len(raw)


def test_a_fuzzed_flags_field_is_volatile():
    assert isinstance(fuzz(TCP()).flags, VolatileValue)


def test_fuzz_yields_one_packet_per_iteration():
    assert len(list(fuzz(IP() / TCP()))) == 1


@pytest.mark.parametrize(
    "build",
    [lambda: IP(), lambda: IPv6(), lambda: Ether() / IP() / UDP(),
     lambda: wiry.ARP(pdst="127.0.0.1"), lambda: IP() / ICMP(),
     lambda: Ether() / wiry.Dot1Q() / IP() / TCP(),
     lambda: wiry.BOOTP(), lambda: IP() / UDP() / wiry.DNS()],
)
def test_fuzz_builds_every_in_scope_layer(build):
    for _ in range(10):
        assert isinstance(bytes(fuzz(build())), bytes)


def test_fuzz_refuses_a_dissected_packet():
    pkt = IP(bytes(IP() / TCP()))
    with pytest.raises(NotImplementedError, match="dissected"):
        fuzz(pkt)


def test_fuzz_takes_a_packet():
    with pytest.raises(TypeError):
        fuzz(b"not a packet")


# --- corruption -----------------------------------------------------------

def test_corrupt_bytes_changes_only_whole_octets():
    data = b"A" * 40
    got = corrupt_bytes(data, n=4)
    assert len(got) == len(data)
    assert 0 < sum(a != b for a, b in zip(data, got)) <= 4


def test_corrupt_bits_flips_single_bits():
    data = b"\x00" * 40
    got = corrupt_bits(data, n=3)
    assert len(got) == len(data)
    assert 0 < sum(bin(b).count("1") for b in got) <= 3


def test_corruption_takes_text_as_latin_1():
    assert len(corrupt_bytes("ABCDE", n=1)) == 5


def test_corruption_of_nothing_is_nothing():
    assert corrupt_bytes(b"") == b""
    assert corrupt_bits(b"") == b""


def test_a_corruption_fraction_cannot_run_away():
    # p is a fraction; unclamped, p=1e9 spun in Rust for 88 s with the GIL held.
    started = time.perf_counter()
    assert len(corrupt_bytes(b"A" * 64, p=1e9)) == 64
    assert len(corrupt_bits(b"A" * 64, p=float("inf"))) == 64
    assert corrupt_bytes(b"A" * 64, p=-1) == b"A" * 64
    assert time.perf_counter() - started < 5


def test_a_seed_repeats_a_corruption():
    set_rand_seed(11)
    first = corrupt_bytes(b"A" * 32, n=6)
    set_rand_seed(11)
    assert corrupt_bytes(b"A" * 32, n=6) == first
