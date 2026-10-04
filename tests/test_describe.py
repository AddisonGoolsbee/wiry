"""`command()`, `json()` and `hexdiff()`."""

import json

import pytest

import wiry
from helpers import ARP_WHO_HAS, DNS_HEADER, ETHER_IP_TCP, ICMP_ECHO, VLAN_IP
from wiry import (
    ARP,
    DHCP,
    DNS,
    ICMP,
    IP,
    UDP,
    BOOTP,
    Dot1Q,
    Ether,
    Raw,
    TCP,
    hexdiff_str,
)

BUILT = [
    Ether() / IP() / TCP(),
    Ether() / IP(dst="10.0.0.2", ttl=3) / UDP(dport=53) / Raw(load=b"payload"),
    Ether() / IP(options=b"\x94\x04\x00\x00") / TCP(flags="SA", options=[("MSS", 1460)]),
    Ether() / ARP(pdst="10.0.0.2"),
    Ether() / Dot1Q(vlan=100) / IP() / ICMP(),
    IP() / ICMP(type=13),
    Ether() / IP() / UDP() / DNS(),
    Ether() / IP() / UDP(sport=68, dport=67) / BOOTP() / DHCP(options=[("message-type", 3), "end"]),
    Ether() / IP() / TCP() / Raw(load=b"") / wiry.Padding(load=b"\x00\x00"),
]

DISSECTED = [
    Ether(ETHER_IP_TCP),
    Ether(VLAN_IP),
    ICMP(ICMP_ECHO),
    ARP(ARP_WHO_HAS),
    DNS(DNS_HEADER),
]


@pytest.mark.parametrize("p", BUILT, ids=lambda p: p.summary())
def test_eval_of_command_rebuilds_a_built_packet(p):
    assert bytes(eval(p.command(), vars(wiry))) == bytes(p)


@pytest.mark.parametrize("p", DISSECTED, ids=lambda p: p.summary())
def test_eval_of_command_rebuilds_a_dissected_packet(p):
    assert bytes(eval(p.command(), vars(wiry))) == bytes(p)


def test_command_names_every_layer_in_order():
    cmd = (Ether() / IP() / TCP()).command()
    assert [c.split("(")[0] for c in cmd.split("/")] == ["Ether", "IP", "TCP"]


def test_command_of_a_packet_under_construction_names_only_what_was_assigned():
    p = IP(dst="127.0.0.1", src="127.0.0.1") / UDP(dport=12345, sport=654)
    assert p.command() == (
        "IP(src='127.0.0.1', dst='127.0.0.1')/UDP(sport=654, dport=12345)"
    )


def test_command_of_a_dissected_packet_names_the_computed_values():
    p = Ether(bytes(Ether() / IP() / UDP() / Raw(load=b"1234")))
    assert "len=32" in p.command()
    assert "len=12" in p.command()


def test_json_is_valid_and_keyed_by_layer():
    p = Ether() / IP(ttl=5) / TCP(dport=80)
    got = json.loads(p.json())
    assert list(got) == ["Ether", "IP", "TCP"]
    assert got["IP"]["ttl"] == 5
    assert got["TCP"]["dport"] == 80


def test_json_renders_bytes_as_hex():
    got = json.loads((Ether() / IP() / Raw(load=b"\x00\xff")).json())
    assert got["Raw"]["load"] == "00ff"


def test_json_keeps_a_repeated_layer_name():
    got = json.loads((Ether() / IP() / IP()).json())
    assert sum(k.startswith("IP") for k in got) == 2


def test_hexdiff_prints_one_row_for_a_row_both_sides_share():
    row = hexdiff_str(b"ab", b"ab")
    assert row == "0000 0000   61 62" + " " * 46 + "ab\n"


def test_hexdiff_prints_each_side_of_a_row_that_differs():
    # scapy's own expectation, test/regression.uts "Test hexdiff function".
    assert hexdiff_str("abcde", "abCde") == (
        "0000        61 62 63 64 65                                     abcde\n"
        "     0000   61 62 43 64 65                                     abCde\n"
    )


def test_hexdiff_shows_an_insertion_as_a_gap_with_a_negative_offset():
    assert hexdiff_str("add_common_", "_common_removed") == (
        "0000        61 64 64 5F 63 6F 6D 6D  6F 6E 5F                  add_common_     \n"
        "     -003            5F 63 6F 6D 6D  6F 6E 5F 72 65 6D 6F 76      _common_remov\n"
        "     000d   65 64                                              ed\n"
    )


def test_hexdiff_of_packets_compares_their_octets():
    a = IP(dst="127.0.0.1", src="127.0.0.1")
    b = IP(dst="127.0.0.2", src="127.0.0.1")
    lines = hexdiff_str(a, b).splitlines()
    assert [line[:9] for line in lines] == ["0000     ", "     0000", "0010     ", "     0010"]


def test_hexdiff_of_empty_input_is_empty():
    assert hexdiff_str(b"", b"") == ""


def test_hexdiff_of_large_input_switches_to_difflib_and_stays_quick():
    import time

    a = bytes(range(256)) * 16
    b = a[:100] + b"XY" + a[100:]
    start = time.monotonic()
    out = hexdiff_str(a, b)
    assert time.monotonic() - start < 5
    assert "58 59" in out


def test_hexdiff_refuses_an_unknown_algorithm():
    with pytest.raises(ValueError, match="Unknown algorithm"):
        hexdiff_str(b"a", b"b", algo="levenshtein")


def test_command_keeps_bytes_past_the_dissection_depth_bound():
    # Dissection stops at a bounded number of layers; whatever it did not name
    # still has to come back, or the expression rebuilds a shorter packet.
    p = Ether()
    for i in range(60):
        p = p / Dot1Q(vlan=i + 1)
    p = p / IP() / TCP()
    deep = Ether(bytes(p))
    assert len(deep.layers()) == 32
    assert bytes(eval(deep.command(), vars(wiry))) == bytes(deep)
    assert "Raw" in json.loads(deep.json())


def test_hexdiff_of_a_padded_pair_does_not_go_quadratic():
    # Zero padding is a run of one byte, which is the worst case for sequence
    # alignment; a deadline on a worker thread is what catches a hang, since an
    # assertion after the call cannot.
    import threading

    a = bytes(1 << 16)
    b = bytes((1 << 16) - 1) + b"\x01"
    done = threading.Thread(target=hexdiff_str, args=(a, b), daemon=True)
    done.start()
    done.join(10.0)
    assert not done.is_alive()
