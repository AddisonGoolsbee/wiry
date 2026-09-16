"""Flag fields as a value that is an integer, a set of bits and a string.

Bit positions come from RFC 9293 §3.1 with RFC 3540's NS bit, RFC 791 §3.1
and RFC 2131 figure 2.
"""

import pytest

from packetry import BOOTP, IP, TCP, FlagValue

# RFC 9293 §3.1, least significant bit first.
TCP_BITS = {"F": 1, "S": 2, "R": 4, "P": 8, "A": 16, "U": 32, "E": 64, "C": 128}


@pytest.mark.parametrize("letter,bit", TCP_BITS.items())
def test_each_control_bit_has_its_rfc_value(letter, bit):
    assert TCP(flags=letter).flags == bit


def test_a_flag_value_is_its_integer_and_its_string():
    flags = TCP(flags="SA").flags
    assert flags == 18
    assert flags == "SA"
    assert flags == "AS"
    assert int(flags) == 18
    assert str(flags) == "SA"
    assert repr(flags) == "<Flag 18 (SA)>"
    assert hash(flags) == hash(18)
    assert bool(flags)
    assert not TCP(flags=0).flags


def test_named_bits_read_as_booleans():
    flags = TCP(flags="SA").flags
    assert flags.S and flags.A
    assert not any(getattr(flags, f) for f in "FRPUECN")


def test_concatenated_names_are_the_and_of_their_bits():
    flags = TCP(flags="SA").flags
    assert flags.SA
    assert not flags.SAU
    assert not TCP(flags="S").flags.SA


def test_a_name_that_is_not_a_flag_raises():
    with pytest.raises(AttributeError):
        TCP(flags="S").flags.Z


def test_assigning_a_bit_writes_through_to_the_packet():
    pkt = TCP(flags="SA")
    pkt.flags.U = True
    pkt.flags.S = False
    assert pkt.flags == 48
    assert bytes(pkt)[13] == 48


def test_operators_take_an_int_a_string_or_another_flag_value():
    flags = TCP(flags="SA").flags
    assert flags & "S" == 2
    assert flags | "P" == 26
    assert flags ^ flags == 0
    assert flags & 16 == "A"
    assert TCP(flags="SU").flags & TCP(flags="AU").flags == "U"
    assert TCP(flags="SU").flags | TCP(flags="AU").flags == "SAU"


def test_in_place_operators_update_the_packet():
    pkt = TCP(flags="AU")
    pkt.flags &= "SFA"
    pkt.flags |= "P"
    assert pkt.flags == "PA"
    assert bytes(pkt)[13] == 24


def test_iterating_yields_the_names_of_the_set_bits():
    assert list(TCP(flags="SA").flags) == ["S", "A"]
    assert list(TCP(flags=0).flags) == []


def test_the_ninth_control_bit_is_carried():
    # RFC 3540 puts NS in the low bit of the reserved field.
    pkt = TCP(flags="N")
    assert pkt.flags == 256
    assert bytes(pkt)[12] & 0x01
    assert TCP(bytes(pkt)).flags.N


def test_a_reassigned_field_still_reads_back_as_flags():
    pkt = TCP()
    pkt.flags = 50
    assert pkt.flags.SAU
    pkt.flags = "FA"
    assert pkt.flags == 17
    pkt.flags = TCP(flags="S").flags
    assert pkt.flags == "S"


def test_multi_letter_flag_names_match_whole():
    # RFC 791 §3.1 names the bits MF and DF, so a single letter is not a flag.
    pkt = IP(flags="DF")
    assert pkt.flags == 2
    assert pkt.flags.DF and not pkt.flags.MF
    with pytest.raises(AttributeError):
        pkt.flags.D


def test_an_unassigned_bit_has_no_name_and_stays_clear():
    # RFC 2131 assigns only the top bit of the BOOTP flags field.
    pkt = BOOTP(flags="B")
    assert bytes(pkt)[10:12] == b"\x80\x00"
    assert pkt.flags.B
    assert list(pkt.flags) == ["B"]


def test_a_detached_value_does_not_write_back():
    pkt = TCP(flags="S")
    derived = pkt.flags | "A"
    derived.U = True
    assert derived == "SAU"
    assert pkt.flags == "S"


def test_comparing_with_an_unrelated_type_is_false_not_an_error():
    assert TCP(flags="S").flags != object()
    assert FlagValue(2, ("F", "S")) == 2
