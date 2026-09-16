"""Option regions: reading, writing, and the round trip between them.

Vectors are hand-built from RFC 791 (IPv4 options), RFC 9293 (TCP options),
RFC 2018 (SACK), RFC 7323 (window scale, timestamps) and RFC 2132 (DHCP).
"""

import struct

import pytest

from packetry import DHCP, IP, TCP, UDP, BOOTP, Ether, Raw


def _tcp_with(opts: bytes) -> bytes:
    """An Ether/IPv4/TCP frame whose TCP header carries `opts`."""
    assert len(opts) % 4 == 0, "TCP options must fill whole 32-bit words"
    tcp = bytearray(20 + len(opts))
    tcp[0:2] = struct.pack("!H", 1234)
    tcp[2:4] = struct.pack("!H", 80)
    tcp[12] = ((20 + len(opts)) // 4) << 4
    tcp[13] = 0x02
    tcp[20:] = opts
    ip = bytearray(20)
    ip[0] = 0x45
    ip[9] = 6
    ip[2:4] = struct.pack("!H", 20 + len(tcp))
    ip[12:16] = bytes([10, 0, 0, 1])
    ip[16:20] = bytes([10, 0, 0, 2])
    return bytes(12) + b"\x08\x00" + bytes(ip) + bytes(tcp)


def test_reads_a_realistic_syn_option_block():
    # MSS 1460, SACK permitted, NOP, window scale 7, then EOL padding.
    opts = bytes([2, 4, 0x05, 0xB4, 4, 2, 1, 3, 3, 7, 0, 0])
    pkt = Ether(_tcp_with(opts))
    assert pkt[TCP].options == [
        ("MSS", 1460),
        ("SAckOK", None),
        ("NOP", None),
        ("WScale", 7),
    ]


def test_timestamp_option_decodes_as_a_pair():
    opts = bytes([8, 10]) + struct.pack("!II", 111, 222) + bytes([0, 0])
    pkt = Ether(_tcp_with(opts))
    assert ("Timestamp", (111, 222)) in pkt[TCP].options


def test_unknown_option_keeps_its_code_and_does_not_abort_the_walk():
    opts = bytes([99, 4, 0xAA, 0xBB, 2, 4, 0x05, 0xB4])
    pkt = Ether(_tcp_with(opts))
    names = [n for n, _ in pkt[TCP].options]
    assert "99" in names and "MSS" in names


def test_header_without_options_reads_as_an_empty_list():
    pkt = Ether(_tcp_with(b""))
    assert pkt[TCP].options == []


def test_raw_option_bytes_remain_available():
    opts = bytes([2, 4, 0x05, 0xB4])
    pkt = Ether(_tcp_with(opts))
    assert pkt[TCP].raw_options() == opts


def test_a_layer_without_an_option_region_reports_none_shaped_result():
    # UDP has no option region, so the attribute falls through to the fields.
    pkt = Ether(_tcp_with(b""))
    with pytest.raises(AttributeError):
        _ = pkt[Ether].options


@pytest.mark.parametrize(
    "opts",
    [
        [("MSS", 1460)],
        [("MSS", 1460), ("SAckOK", None)],
        [("MSS", 1460), ("SAckOK", None), ("NOP", None), ("WScale", 7)],
        [("Timestamp", (111, 222))],
        [("WScale", 7)],
    ],
)
def test_written_options_read_back_identically(opts):
    pkt = Ether() / IP(dst="10.0.0.1") / TCP(dport=443, options=opts)
    back = Ether(bytes(pkt))
    assert back[TCP].options == opts


def test_writing_options_updates_the_data_offset():
    # 10 bytes of options padded to 12: 3 extra 32-bit words.
    pkt = Ether() / IP() / TCP(
        options=[("MSS", 1460), ("SAckOK", None), ("NOP", None), ("WScale", 7)]
    )
    back = Ether(bytes(pkt))
    assert back[TCP].dataofs == 8


def test_writing_ipv4_options_updates_ihl():
    pkt = IP(dst="10.0.0.1", options=[("RA", 0)]) / UDP()
    back = IP(bytes(pkt))
    assert back[IP].ihl == 6
    assert back[IP].options == [("RA", 0)]


def test_options_do_not_disturb_neighbouring_fields():
    pkt = Ether() / IP(dst="10.0.0.9", ttl=33) / TCP(
        dport=8080, options=[("MSS", 536)]
    )
    back = Ether(bytes(pkt))
    assert back[IP].dst == "10.0.0.9"
    assert back[IP].ttl == 33
    assert back[TCP].dport == 8080


def test_option_bytes_may_be_supplied_raw():
    pkt = Ether() / IP() / TCP(options=bytes([2, 4, 0x05, 0xB4]))
    back = Ether(bytes(pkt))
    assert back[TCP].options == [("MSS", 1460)]


def test_ipv4_total_length_accounts_for_tcp_options():
    pkt = Ether() / IP() / TCP(options=[("MSS", 1460), ("SAckOK", None)])
    raw = bytes(pkt)
    back = Ether(raw)
    assert back[IP].len == len(raw) - 14


def test_unknown_option_name_is_rejected():
    with pytest.raises(ValueError):
        bytes(IP() / TCP(options=[("NoSuchOption", 1)]))


def test_options_survive_a_payload_being_added():
    pkt = Ether() / IP() / TCP(options=[("MSS", 1460)]) / Raw(load=b"hello")
    back = Ether(bytes(pkt))
    assert back[TCP].options == [("MSS", 1460)]
    assert bytes(back).endswith(b"hello")


def _dhcp_frame(opt_bytes: bytes) -> bytes:
    bootp = bytearray(236)
    bootp[0] = 1  # BOOTREQUEST
    bootp[1] = 1  # htype Ethernet
    bootp[2] = 6
    udp = bytearray(8)
    udp[0:2] = struct.pack("!H", 68)
    udp[2:4] = struct.pack("!H", 67)
    body = bytes(bootp) + bytes([99, 130, 83, 99]) + opt_bytes
    udp[4:6] = struct.pack("!H", 8 + len(body))
    return bytes(udp) + body


def test_dhcp_options_decode_by_name():
    pkt = UDP(_dhcp_frame(bytes([53, 1, 1, 255])))
    assert ("message-type", 1) in pkt[DHCP].options


def test_dhcp_address_option_decodes():
    opts = bytes([54, 4, 10, 0, 0, 1, 255])
    pkt = UDP(_dhcp_frame(opts))
    names = dict(pkt[DHCP].options)
    assert names["server_id"] == ["10.0.0.1"]


def test_bootp_option_field_is_the_magic_cookie():
    # RFC 2131 §3: the cookie ends the BOOTP header, so it is what BOOTP's own
    # option field holds.
    pkt = UDP(_dhcp_frame(bytes([255])))
    assert BOOTP in pkt
    assert pkt[BOOTP].options == bytes([99, 130, 83, 99])
    assert pkt[DHCP].raw_options() == bytes([255])


# RFC 2132 §9.13: option 60 is unnamed here, so it is labelled with its code.
DHCP_WITH_VENDOR_CLASS = bytes(
    [53, 1, 3, 60, 8]
) + b"MSFT 5.0" + bytes([55, 3, 1, 3, 6, 255])


def test_a_parsed_option_list_encodes_back_to_the_same_bytes():
    pkt = UDP(_dhcp_frame(DHCP_WITH_VENDOR_CLASS))
    assert ("60", b"MSFT 5.0") in pkt[DHCP].options
    assert bytes(DHCP(options=pkt[DHCP].options)) == DHCP_WITH_VENDOR_CLASS


def test_an_unnamed_tcp_option_round_trips():
    parsed = IP(bytes(IP() / TCP(options=b"\x1f\x04\xaa\xbb")))[TCP].options
    assert parsed == [("31", b"\xaa\xbb")]
    assert b"\x1f\x04\xaa\xbb" in bytes(IP() / TCP(options=parsed))


def test_an_unnamed_ipv4_option_round_trips():
    parsed = IP(bytes(IP(options=b"\x52\x04\xaa\xbb") / TCP()))[IP].options
    assert parsed == [("82", b"\xaa\xbb")]
    assert b"\x52\x04\xaa\xbb" in bytes(IP(options=parsed) / TCP())
