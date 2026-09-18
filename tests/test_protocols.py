"""The fifty protocols added by dev/protogen, from the Python side.

Every frame here is hand-built from the RFC cited in the corresponding
`dev/protogen/specs/*.toml`, never captured and never produced by running scapy.
"""

import wiry as B
from wiry import IP, IPv6, TCP, UDP, Ether, Raw


NEW_LAYERS = [
    "LLC", "SNAP", "STP", "LLDPDU", "CDP", "RadioTap",
    "Dot11", "Dot11Beacon", "Dot11ProbeReq", "Dot11ProbeResp", "Dot11Auth",
    "Dot11AssoReq", "Dot11AssoResp",
    "SCTP", "IGMP",
    "ICMPv6ND_RS", "ICMPv6ND_RA", "ICMPv6ND_NS", "ICMPv6ND_NA",
    "ICMPv6ND_Redirect",
    "ICMPv6MLQuery", "ICMPv6MLReport", "ICMPv6MLDone", "ICMPv6MLReport2",
    "ESP", "AH", "OSPF_Hdr", "RIP", "BGPHeader", "VRRP", "HSRP", "BFD",
    "NTP", "DHCP6", "SNMP", "TFTP", "Syslog", "NBNS", "NBTSession", "Radius",
    "RTP", "RTCP", "NetflowHeaderV5", "NetflowHeaderV9", "IPFIX", "SFlow",
    "QUIC", "WireGuard",
    "TLS", "HTTP", "SSH", "MQTT", "ModbusADU", "SMB2_Header", "LDAP",
    "SIP", "FTP", "SMTP", "IMAP", "Telnet",
]


def udp_frame(payload, sport=1234, dport=1234):
    return bytes(Ether() / IP() / UDP(sport=sport, dport=dport) / Raw(payload))


def tcp_frame(payload, sport=1234, dport=80):
    return bytes(Ether() / IP() / TCP(sport=sport, dport=dport) / Raw(payload))


def chain(data):
    return Ether(data).layers()


# ---------------------------------------------------------------- inventory


def test_every_new_layer_is_known_and_exported():
    known = set(B.known_layers())
    for name in NEW_LAYERS:
        assert name in known, name
        assert hasattr(B, name), name


def test_every_new_layer_constructs_and_serialises():
    for name in NEW_LAYERS:
        pkt = getattr(B, name)()
        raw = bytes(pkt)
        assert isinstance(raw, bytes)
        # A default construction has to be re-readable as itself.
        assert getattr(B, name)(raw) is not None


def test_every_new_layer_dissects_its_own_default_bytes():
    for name in NEW_LAYERS:
        raw = bytes(getattr(B, name)())
        if not raw:
            continue
        pkt = getattr(B, name)(raw)
        assert bytes(pkt) == raw, name


# ------------------------------------------------------------- L2 / L3


def test_an_802_3_length_field_reaches_llc_and_stp():
    """IEEE 802.3 clause 3.2.6: at or below 1500 the field is a length."""
    bpdu = bytes([0x42, 0x42, 0x03]) + bytes(
        [0x00, 0x00, 0x00, 0x00, 0x00]
        + [0x80, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
        + [0x00, 0x00, 0x00, 0x00]
        + [0x80, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
        + [0x80, 0x01, 0x00, 0x00, 0x14, 0x00, 0x02, 0x00, 0x0F, 0x00]
    )
    frame = bytes([0x01, 0x80, 0xC2, 0, 0, 0] + [0, 0x11, 0x22, 0x33, 0x44, 0x55]) \
        + len(bpdu).to_bytes(2, "big") + bpdu
    pkt = Ether(frame)
    assert pkt.layers()[:3] == ["Ether", "LLC", "STP"]
    assert pkt["LLC"].dsap == 0x42
    assert pkt["STP"].rootmac == "00:11:22:33:44:55"
    assert pkt["STP"].hellotime == 0x0200
    assert bytes(pkt) == frame


def test_snap_with_a_zero_oui_carries_an_ethertype():
    """RFC 1042."""
    inner = bytes([0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x06]) + bytes(28)
    frame = bytes(12) + len(inner).to_bytes(2, "big") + inner
    pkt = Ether(frame)
    assert pkt.layers()[:4] == ["Ether", "LLC", "SNAP", "ARP"]
    assert pkt["SNAP"].code == 0x0806


def test_lldp_tlvs_decode_by_name():
    """IEEE 802.1AB §8.5."""
    pdu = bytes(
        [0x02, 0x07, 0x04, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
        + [0x04, 0x07, 0x03, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
        + [0x06, 0x02, 0x00, 0x78]
        + [0x0A, 0x02, ord("r"), ord("1")]
        + [0x00, 0x00]
    )
    frame = bytes(12) + b"\x88\xcc" + pdu
    pkt = Ether(frame)
    assert pkt.layers()[:2] == ["Ether", "LLDPDU"]
    opts = dict(pkt["LLDPDU"].options)
    assert opts["TTL"] == 120
    assert opts["SystemName"] == "r1"
    assert bytes(pkt) == frame


def test_sctp_chunks_decode_and_the_common_header_reads():
    """RFC 9260 §3.1, §3.2."""
    sctp = bytes(
        [0x04, 0xD2, 0x16, 0x2E, 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0]
        + [0x04, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 0x04]
    )
    data = bytearray(bytes(Ether() / IP() / Raw(sctp)))
    data[23] = 132
    pkt = Ether(bytes(data))
    assert pkt.layers()[:3] == ["Ether", "IP", "SCTP"]
    assert pkt["SCTP"].sport == 1234
    assert pkt["SCTP"].dport == 5678
    assert pkt["SCTP"].tag == 0x11223344
    assert [n for n, _ in pkt["SCTP"].options] == ["HEARTBEAT"]
    assert bytes(pkt) == bytes(data)


def test_igmp_v2_and_v3_share_one_layer_with_conditional_fields():
    """RFC 2236 §2 and RFC 3376 §4.1: the same prefix, different tails."""
    v2 = bytes([0x16, 0x00, 0x09, 0x04, 0xE0, 0x00, 0x00, 0xFB])
    data = bytearray(bytes(Ether() / IP() / Raw(v2)))
    data[23] = 2
    pkt = Ether(bytes(data))
    assert pkt.layers()[:3] == ["Ether", "IP", "IGMP"]
    assert pkt["IGMP"].type == 0x16
    assert pkt["IGMP"].gaddr == "224.0.0.251"
    assert "numgrp" not in pkt["IGMP"].fields()

    v3 = bytes([0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01])
    data = bytearray(bytes(Ether() / IP() / Raw(v3)))
    data[23] = 2
    pkt = Ether(bytes(data))
    assert pkt["IGMP"].numgrp == 1
    assert "gaddr" not in pkt["IGMP"].fields()


def test_ospf_esp_ah_and_vrrp_are_reached_by_ip_protocol_number():
    cases = {
        50: ("ESP", bytes([0x11, 0x22, 0x33, 0x44, 0, 0, 0, 1]) + bytes(8)),
        51: ("AH", bytes([6, 4, 0, 0, 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 1]) + bytes(12)),
        89: ("OSPF_Hdr", bytes([2, 1, 0, 24]) + bytes(20)),
        112: ("VRRP", bytes([0x21, 0x01, 0x64, 0x01, 0x00, 0x01, 0xBA, 0x52])),
    }
    for proto, (name, body) in cases.items():
        data = bytearray(bytes(Ether() / IP() / Raw(body)))
        data[23] = proto
        pkt = Ether(bytes(data))
        assert pkt.layers()[:3] == ["Ether", "IP", name], (proto, pkt.layers())
        assert bytes(pkt) == bytes(data)


def test_ah_dissects_the_protocol_it_protects():
    """RFC 4302 §2.2: the Next Header field names what follows the ICV."""
    ah = bytes([6, 4, 0, 0, 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 1]) + bytes(12)
    inner = bytes(TCP(sport=1, dport=2))
    data = bytearray(bytes(Ether() / IP() / Raw(ah + inner)))
    data[23] = 51
    pkt = Ether(bytes(data))
    assert pkt.layers()[:4] == ["Ether", "IP", "AH", "TCP"]
    assert pkt["AH"].nh == 6
    assert pkt["TCP"].dport == 2


# ------------------------------------------------------------- ICMPv6 / NDP


def test_neighbour_solicitation_is_one_layer_with_its_options():
    """RFC 4861 §4.3 and §4.6.1."""
    ns = bytes(
        [0x87, 0x00, 0x00, 0x00, 0, 0, 0, 0]
        + [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02]
        + [0x01, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
    )
    pkt = Ether() / IPv6() / Raw(ns)
    data = bytearray(bytes(pkt))
    data[20] = 58
    got = Ether(bytes(data))
    assert got.layers()[:3] == ["Ether", "IPv6", "ICMPv6ND_NS"]
    assert got["ICMPv6ND_NS"].tgt == "2001:db8::2"
    assert dict(got["ICMPv6ND_NS"].options)["SrcLLAddr"] == bytes(
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
    )
    assert bytes(got) == bytes(data)


def test_router_advertisement_flags_and_mtu_option():
    """RFC 4861 §4.2, §4.6.4."""
    ra = bytes(
        [0x86, 0x00, 0x00, 0x00, 0x40, 0x80, 0x07, 0x08]
        + [0, 0, 0, 0, 0, 0, 0, 0]
        + [0x05, 0x01, 0, 0, 0, 0, 0x05, 0xDC]
    )
    data = bytearray(bytes(Ether() / IPv6() / Raw(ra)))
    data[20] = 58
    got = Ether(bytes(data))
    assert got["ICMPv6ND_RA"].chlim == 64
    assert got["ICMPv6ND_RA"].M == 1
    assert got["ICMPv6ND_RA"].O == 0
    assert got["ICMPv6ND_RA"].routerlifetime == 1800
    assert dict(got["ICMPv6ND_RA"].options)["MTU"] == 1500


def test_mld_query_v1_and_v2_are_told_apart_by_length():
    """RFC 2710 §3 is 24 octets; RFC 3810 §5.1 is at least 28."""
    v1 = bytes([0x82, 0, 0, 0, 0x27, 0x10, 0, 0]) + bytes(16)
    data = bytearray(bytes(Ether() / IPv6() / Raw(v1)))
    data[20] = 58
    got = Ether(bytes(data))
    assert got.layers()[:3] == ["Ether", "IPv6", "ICMPv6MLQuery"]
    assert got["ICMPv6MLQuery"].mrd == 10000
    assert "qqic" not in got["ICMPv6MLQuery"].fields()

    v2 = v1 + bytes([0x02, 0x7D, 0x00, 0x00])
    data = bytearray(bytes(Ether() / IPv6() / Raw(v2)))
    data[20] = 58
    got = Ether(bytes(data))
    assert got["ICMPv6MLQuery"].qqic == 0x7D
    assert got["ICMPv6MLQuery"].numsrc == 0


def test_a_plain_icmpv6_echo_still_reaches_the_generic_layer():
    echo = bytes([0x80, 0x00, 0x12, 0x13, 0x12, 0x34, 0x00, 0x01])
    data = bytearray(bytes(Ether() / IPv6() / Raw(echo)))
    data[20] = 58
    assert Ether(bytes(data)).layers()[:3] == ["Ether", "IPv6", "ICMPv6"]


# ------------------------------------------------------------- UDP services


def test_ntp_reads_its_rfc_5905_header():
    ntp = bytes([0x23, 0x00, 0x06, 0xEC]) + bytes(44)
    frame = udp_frame(ntp, dport=123)
    pkt = Ether(frame)
    assert pkt.layers()[:4] == ["Ether", "IP", "UDP", "NTP"]
    assert pkt["NTP"].version == 4
    assert pkt["NTP"].mode == 3
    assert pkt["NTP"].poll == 6
    assert bytes(pkt) == frame


def test_dhcpv6_options_decode_from_their_16_bit_codes():
    """RFC 8415 §21.1."""
    msg = bytes([0x01, 0x0A, 0x0B, 0x0C, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00])
    pkt = Ether(udp_frame(msg, sport=546, dport=547))
    assert pkt.layers()[:4] == ["Ether", "IP", "UDP", "DHCP6"]
    assert pkt["DHCP6"].msgtype == 1
    assert pkt["DHCP6"].trid == 0x0A0B0C
    assert [n for n, _ in pkt["DHCP6"].options] == ["elapsedtime"]


def test_snmp_decodes_its_ber_message_into_named_items():
    """RFC 1157 §4.1 over ITU-T X.690 §8."""
    msg = bytes([
        0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70,
        0x75, 0x62, 0x6C, 0x69, 0x63, 0xA0, 0x19, 0x02,
        0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
        0x30, 0x0E, 0x30, 0x0C, 0x06, 0x08, 0x2B, 0x06,
        0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
    ])
    frame = udp_frame(msg, dport=161)
    pkt = Ether(frame)
    assert pkt.layers()[:4] == ["Ether", "IP", "UDP", "SNMP"]
    got = dict(pkt["SNMP"].vars)
    assert got["version"] == 0
    assert got["community"] == "public"
    assert got["PDU"] == "get_request"
    assert got["request_id"] == 1
    assert got["1.3.6.1.2.1.1.1.0"] == ""
    assert bytes(pkt) == frame


def test_tftp_read_request_decodes_its_nul_terminated_strings():
    """RFC 1350 §5."""
    rrq = b"\x00\x01" + b"a\x00octet\x00"
    pkt = Ether(udp_frame(rrq, dport=69))
    assert pkt.layers()[:4] == ["Ether", "IP", "UDP", "TFTP"]
    assert pkt["TFTP"].op == 1
    assert dict(pkt["TFTP"].options) == {"filename": "a", "mode": "octet"}


def test_syslog_splits_its_priority_into_facility_and_severity():
    """RFC 5424 §6.2.1 and §6.5 Example 1."""
    msg = b"<34>1 2003-10-11T22:14:15.003Z host su - ID47 - msg"
    pkt = Ether(udp_frame(msg, dport=514))
    assert pkt.layers()[:4] == ["Ether", "IP", "UDP", "Syslog"]
    got = dict(pkt["Syslog"].headers)
    assert got["pri"] == 34
    assert got["facility"] == 4
    assert got["severity"] == 2
    assert got["hostname"] == "host"
    assert got["app-name"] == "su"
    assert got["msg"] == "msg"


def test_a_bsd_syslog_line_still_yields_its_message():
    """RFC 3164 §4.1 has no version digit and no structured header."""
    pkt = Ether(udp_frame(b"<13>Oct 11 22:14:15 host su: it broke", dport=514))
    got = dict(pkt["Syslog"].headers)
    assert got["severity"] == 5
    assert got["msg"].startswith("Oct 11")


def test_radius_attributes_decode_by_name():
    """RFC 2865 §3, §5."""
    pkt_bytes = bytes([0x01, 0x00, 0x00, 0x1A]) + bytes(16) + bytes(
        [0x01, 0x05, ord("b"), ord("o"), ord("b"), 0x00]
    )
    pkt = Ether(udp_frame(pkt_bytes, dport=1812))
    assert pkt.layers()[:4] == ["Ether", "IP", "UDP", "Radius"]
    assert pkt["Radius"].code == 1
    assert [n for n, _ in pkt["Radius"].options] == ["User-Name"]


def test_the_three_flow_export_formats_share_a_port_and_a_version_guard():
    """NetFlow v5, RFC 3954 v9 and RFC 7011 IPFIX all arrive on UDP 2055."""
    cases = [
        ("NetflowHeaderV5", bytes([0, 5, 0, 1]) + bytes(20)),
        ("NetflowHeaderV9", bytes([0, 9, 0, 1]) + bytes(16)),
        ("IPFIX", bytes([0, 10, 0, 16]) + bytes(12)),
    ]
    for name, body in cases:
        pkt = Ether(udp_frame(body, dport=2055))
        assert pkt.layers()[:4] == ["Ether", "IP", "UDP", name], pkt.layers()
    # Version 42 is none of them.
    pkt = Ether(udp_frame(bytes([0, 42, 0, 1]) + bytes(20), dport=2055))
    assert pkt.layers()[3] == "Raw"


def test_sflow_and_bfd_and_hsrp_are_reached_by_port():
    cases = [
        ("SFlow", 6343, bytes([0, 0, 0, 5, 0, 0, 0, 1]) + bytes(20)),
        ("BFD", 3784, bytes([0x20, 0xC0, 0x03, 0x18]) + bytes(20)),
        ("HSRP", 1985, bytes([0, 0, 0x10, 0x03, 0x0A, 0x78, 0, 0])
         + b"cisco\x00\x00\x00" + bytes([10, 0, 0, 1])),
        ("RIP", 520, bytes([1, 2, 0, 0]) + bytes(20)),
        ("NBNS", 137, bytes([0x12, 0x34, 0x01, 0x10]) + bytes(8)),
    ]
    for name, port, body in cases:
        pkt = Ether(udp_frame(body, dport=port))
        assert pkt.layers()[:4] == ["Ether", "IP", "UDP", name], pkt.layers()


def test_a_claimed_port_is_found_on_either_side_of_the_flow():
    """Both ports are offered, so a reply dissects like the request it answers."""
    ntp = bytes([0x23, 0x00, 0x06, 0xEC]) + bytes(44)
    for sport, dport in [(1234, 123), (123, 1234)]:
        pkt = Ether(udp_frame(ntp, sport=sport, dport=dport))
        assert pkt.layers()[:4] == ["Ether", "IP", "UDP", "NTP"], (sport, dport)


def test_a_claimed_port_whose_guard_refuses_falls_to_raw():
    """The port admits the match; the guard still decides, in either direction."""
    body = b"not a BGP message, and not 19 octets of header either"
    for sport, dport in [(1234, 179), (179, 1234)]:
        pkt = Ether(tcp_frame(body, sport=sport, dport=dport))
        assert pkt.layers()[:4] == ["Ether", "IP", "TCP", "Raw"], (sport, dport)
    flow = bytes([0, 42, 0, 1]) + bytes(20)
    for sport, dport in [(1234, 2055), (2055, 1234)]:
        pkt = Ether(udp_frame(flow, sport=sport, dport=dport))
        assert pkt.layers()[:4] == ["Ether", "IP", "UDP", "Raw"], (sport, dport)


def test_quic_needs_its_fixed_bit_and_reads_its_connection_ids():
    """RFC 9000 §17.2."""
    long_hdr = bytes([0xC0, 0, 0, 0, 1, 0x04, 0x11, 0x22, 0x33, 0x44, 0x00]) + bytes(8)
    pkt = Ether(udp_frame(long_hdr, dport=443))
    assert pkt.layers()[:4] == ["Ether", "IP", "UDP", "QUIC"]
    got = dict(pkt["QUIC"].options)
    assert got["version"] == 1
    assert got["dcid"] == bytes([0x11, 0x22, 0x33, 0x44])
    # The fixed bit clear is not a QUIC v1 packet.
    pkt = Ether(udp_frame(bytes([0x00]) + bytes(20), dport=443))
    assert pkt.layers()[3] == "Raw"


def test_wireguard_transport_data_reads_its_counter():
    """WireGuard whitepaper §5.4.6."""
    msg = bytes([4, 0, 0, 0, 1, 0, 0, 0]) + bytes(8) + b"\xaa\xbb"
    pkt = Ether(udp_frame(msg, dport=51820))
    assert pkt.layers()[:4] == ["Ether", "IP", "UDP", "WireGuard"]
    assert pkt["WireGuard"].message_type == 4
    assert pkt["WireGuard"].receiver_index == 1
    assert pkt["WireGuard"].counter == 0


def test_mdns_and_llmnr_dissect_as_dns():
    """RFC 6762 §18 and RFC 4795 §2: the RFC 1035 message on another port."""
    dns = bytes([0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0])
    for port in (5353, 5355):
        pkt = Ether(udp_frame(dns, dport=port))
        assert pkt.layers()[:4] == ["Ether", "IP", "UDP", "DNS"], port


# ------------------------------------------------------------- TCP services


HTTP_REQ = (
    b"GET /a HTTP/1.1\r\n"
    b"Host: a.example\r\n"
    b"content-type: text/plain\r\n"
    b"\r\n"
    b"body"
)


def test_http_decodes_its_start_line_and_field_lines():
    """RFC 9112 §2.1, §3; RFC 9110 §5."""
    frame = tcp_frame(HTTP_REQ)
    pkt = Ether(frame)
    assert pkt.layers()[:5] == ["Ether", "IP", "TCP", "HTTP", "Raw"]
    got = dict(pkt["HTTP"].headers)
    assert got["Method"] == "GET"
    assert got["Path"] == "/a"
    assert got["Http-Version"] == "HTTP/1.1"
    assert got["Host"] == "a.example"
    # RFC 9110 §5.1: field names are case-insensitive, so one spelling is kept.
    assert got["Content-Type"] == "text/plain"
    assert pkt["Raw"].load == b"body"
    assert bytes(pkt) == frame


def test_an_http_response_reads_its_status_line():
    resp = b"HTTP/1.1 404 Not Found\r\nServer: x\r\n\r\n"
    got = dict(Ether(tcp_frame(resp, sport=80, dport=1234))["HTTP"].headers)
    assert got["Status-Code"] == "404"
    assert got["Reason-Phrase"] == "Not Found"


def test_a_mid_stream_segment_on_port_80_is_not_http():
    """The guard is what keeps a continuation segment out of the layer."""
    pkt = Ether(tcp_frame(b"\x00\x01\x02\x03 not a request line\r\n"))
    assert pkt.layers()[:4] == ["Ether", "IP", "TCP", "Raw"]


CLIENT_HELLO = bytes(
    [0x16, 0x03, 0x01, 0x00, 0x40]
    + [0x01, 0x00, 0x00, 0x3C, 0x03, 0x03]
    + [0x00] * 32
    + [0x00]
    + [0x00, 0x02, 0x13, 0x01]
    + [0x01, 0x00]
    + [0x00, 0x11]
    + [0x00, 0x00, 0x00, 0x0D, 0x00, 0x0B, 0x00, 0x00, 0x08]
    + list(b"a.io.com")
)


def test_tls_reaches_the_server_name_in_a_client_hello():
    """RFC 8446 §5.1, §4.1.2 and RFC 6066 §3 — the field people want."""
    frame = tcp_frame(CLIENT_HELLO, dport=443)
    pkt = Ether(frame)
    assert pkt.layers()[:4] == ["Ether", "IP", "TCP", "TLS"]
    assert pkt["TLS"].type == 22
    assert pkt["TLS"].version == 0x0301
    got = dict(pkt["TLS"].options)
    assert got["handshake_type"] == 1
    assert got["server_name"] == "a.io.com"
    assert bytes(pkt) == frame


def test_application_data_records_decode_without_a_handshake():
    rec = bytes([0x17, 0x03, 0x03, 0x00, 0x04, 1, 2, 3, 4])
    pkt = Ether(tcp_frame(rec, sport=443, dport=1234))
    assert pkt["TLS"].type == 23
    assert dict(pkt["TLS"].options) == {"content_type": 23}


def test_a_non_record_payload_on_port_443_is_not_tls():
    pkt = Ether(tcp_frame(b"hello there this is not a record", dport=443))
    assert pkt.layers()[:4] == ["Ether", "IP", "TCP", "Raw"]


def test_ssh_reads_both_its_banner_and_its_binary_packet():
    """RFC 4253 §4.2 and §6."""
    pkt = Ether(tcp_frame(b"SSH-2.0-wiry\r\n", dport=22))
    assert pkt.layers()[:4] == ["Ether", "IP", "TCP", "SSH"]
    assert dict(pkt["SSH"].options)["Version"] == "SSH-2.0-wiry"

    binary = bytes([0, 0, 0, 0x0C, 0x0A]) + bytes(11)
    pkt = Ether(tcp_frame(binary, sport=22, dport=1234))
    got = dict(pkt["SSH"].options)
    assert got["packet_length"] == 12
    assert got["padding_length"] == 10


def test_mqtt_reads_its_variable_length_remaining_length():
    """OASIS MQTT 3.1.1 §2.2.3."""
    pkt = Ether(tcp_frame(bytes([0xC0, 0x00]), dport=1883))
    assert pkt.layers()[:4] == ["Ether", "IP", "TCP", "MQTT"]
    assert pkt["MQTT"].type == 12
    assert [n for n, _ in pkt["MQTT"].options] == ["PINGREQ", "remaining_length"]

    # 193 needs two length octets: 0xC1 0x01.
    pkt = Ether(tcp_frame(bytes([0x30, 0xC1, 0x01]) + bytes(193), dport=1883))
    assert dict(pkt["MQTT"].options)["remaining_length"] == 193


def test_modbus_and_smb2_and_ldap_reach_their_layers():
    cases = [
        ("ModbusADU", 502, bytes([0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 1])),
        ("SMB2_Header", 445, bytes([0xFE, 0x53, 0x4D, 0x42, 0x40, 0, 0, 0]) + bytes(56)),
        ("LDAP", 389, bytes([0x30, 0x0C, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02,
                             0x01, 0x03, 0x04, 0x00, 0x80, 0x00])),
        ("BGPHeader", 179, bytes([0xFF] * 16) + bytes([0x00, 0x13, 0x04])),
    ]
    for name, port, body in cases:
        frame = tcp_frame(body, dport=port)
        pkt = Ether(frame)
        assert pkt.layers()[:4] == ["Ether", "IP", "TCP", name], pkt.layers()
        assert bytes(pkt) == frame


def test_smb2_reads_its_little_endian_fields():
    """[MS-SMB2] §2.2.1.2."""
    body = bytes([0xFE, 0x53, 0x4D, 0x42, 0x40, 0, 0, 0]) + bytes(56)
    pkt = Ether(tcp_frame(body, dport=445))
    assert pkt["SMB2_Header"].ProtocolId == 0xFE534D42
    assert pkt["SMB2_Header"].StructureSize == 64


def test_ldap_names_its_protocol_operation():
    """RFC 4511 §4.2."""
    body = bytes([0x30, 0x0C, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02,
                  0x01, 0x03, 0x04, 0x00, 0x80, 0x00])
    got = dict(Ether(tcp_frame(body, dport=389))["LDAP"].vars)
    assert got["messageID"] == 1
    assert got["protocolOp"] == "bindRequest"


def test_nbt_session_service_carries_smb2():
    """RFC 1002 §4.3.1."""
    smb = bytes([0xFE, 0x53, 0x4D, 0x42, 0x40, 0, 0, 0]) + bytes(56)
    body = bytes([0x00, 0x00]) + len(smb).to_bytes(2, "big") + smb
    pkt = Ether(tcp_frame(body, dport=139))
    assert pkt.layers()[:5] == ["Ether", "IP", "TCP", "NBTSession", "SMB2_Header"]
    assert pkt["NBTSession"].LENGTH == len(smb)


# ------------------------------------------------------------- text protocols


def test_ftp_and_smtp_split_replies_from_commands():
    """RFC 959 §4.2 and RFC 5321 §4.2."""
    pkt = Ether(tcp_frame(b"220 ready\r\n", sport=21, dport=1234))
    assert pkt.layers()[:4] == ["Ether", "IP", "TCP", "FTP"]
    assert pkt["FTP"].lines == [("code", 220), ("text", "ready")]

    pkt = Ether(tcp_frame(b"USER bob\r\n", dport=21))
    assert pkt["FTP"].lines == [("command", "USER"), ("arg", "bob")]

    pkt = Ether(tcp_frame(b"220 a.io ESMTP\r\n", sport=25, dport=1234))
    assert pkt["SMTP"].lines == [("code", 220), ("text", "a.io ESMTP")]


def test_imap_reads_tagged_and_untagged_lines():
    """RFC 3501 §2.2."""
    pkt = Ether(tcp_frame(b"* OK IMAP4rev1\r\n", sport=143, dport=1234))
    assert pkt.layers()[:4] == ["Ether", "IP", "TCP", "IMAP"]
    assert pkt["IMAP"].lines[:2] == [("tag", "*"), ("command", "OK")]

    pkt = Ether(tcp_frame(b"A001 LOGIN bob pw\r\n", dport=143))
    assert dict(pkt["IMAP"].lines)["tag"] == "A001"


def test_telnet_separates_its_iac_commands_from_its_text():
    """RFC 854, RFC 857, RFC 858."""
    body = bytes([0xFF, 0xFD, 0x03, 0xFF, 0xFB, 0x01]) + b"hi"
    pkt = Ether(tcp_frame(body, dport=23))
    assert pkt.layers()[:4] == ["Ether", "IP", "TCP", "Telnet"]
    assert pkt["Telnet"].lines == [
        ("DO", "SuppressGoAhead"),
        ("WILL", "Echo"),
        ("data", "hi"),
    ]


def test_sip_reads_its_request_line_and_headers():
    """RFC 3261 §7.1, §7.3."""
    msg = b"OPTIONS sip:a@b SIP/2.0\r\nCSeq: 1 OPTIONS\r\nVia: x\r\n\r\n"
    pkt = Ether(udp_frame(msg, dport=5060))
    assert pkt.layers()[:4] == ["Ether", "IP", "UDP", "SIP"]
    got = dict(pkt["SIP"].headers)
    assert got["Method"] == "OPTIONS"
    assert got["Uri"] == "sip:a@b"
    assert got["Sip-Version"] == "SIP/2.0"
    assert got["Cseq"] == "1 OPTIONS"


def test_a_sip_response_reads_its_status_line():
    msg = b"SIP/2.0 200 OK\r\nCSeq: 1 OPTIONS\r\n\r\n"
    got = dict(Ether(udp_frame(msg, sport=5060))["SIP"].headers)
    assert got["Status-Code"] == "200"
    assert got["Reason-Phrase"] == "OK"


# ------------------------------------------------------------- write paths


def test_writing_a_field_on_a_dissected_new_layer_keeps_the_frame_size():
    frame = udp_frame(bytes([0x23, 0x00, 0x06, 0xEC]) + bytes(44), dport=123)
    pkt = Ether(frame)
    pkt["NTP"].stratum = 3
    pkt["NTP"].mode = 4
    out = bytes(pkt)
    assert len(out) == len(frame)
    again = Ether(out)
    assert again["NTP"].stratum == 3
    assert again["NTP"].mode == 4


def test_writing_every_uint_field_of_every_new_layer_never_resizes():
    """The write half of the engine carries the same contract as the read half."""
    for name in NEW_LAYERS:
        raw = bytes(getattr(B, name)())
        if not raw:
            continue
        pkt = getattr(B, name)(raw)
        layer = pkt[name]
        for field in layer.fields():
            try:
                before = getattr(layer, field)
            except AttributeError:
                continue
            if not isinstance(before, int):
                continue
            setattr(layer, field, 1)
        assert len(bytes(pkt)) == len(raw), name


def test_stacking_a_new_layer_writes_the_parent_selector_back():
    assert Ether(bytes(Ether() / IP() / UDP() / B.NTP())).layers()[:4] == [
        "Ether", "IP", "UDP", "NTP",
    ]
    assert Ether(bytes(Ether() / IP() / B.SCTP())).layers()[:3] == [
        "Ether", "IP", "SCTP",
    ]
    assert Ether(bytes(Ether() / B.LLDPDU())).layers()[:2] == ["Ether", "LLDPDU"]
    assert Ether(bytes(Ether() / IPv6() / B.ICMPv6ND_NS())).layers()[:3] == [
        "Ether", "IPv6", "ICMPv6ND_NS",
    ]


def test_a_new_layer_survives_a_pcap_round_trip(tmp_path):
    frames = [
        udp_frame(bytes([0x23, 0x00, 0x06, 0xEC]) + bytes(44), dport=123),
        tcp_frame(HTTP_REQ),
        tcp_frame(CLIENT_HELLO, dport=443),
    ]
    path = tmp_path / "new.pcap"
    B.wrpcap(str(path), [Ether(f) for f in frames])
    back = B.rdpcap(str(path))
    assert [bytes(p) for p in back] == frames
    assert back[0].layers()[3] == "NTP"
    assert back[1].layers()[3] == "HTTP"
    assert back[2].layers()[3] == "TLS"


# ------------------------------------------------------- the FFI boundary


def test_the_bulk_column_agrees_with_the_per_packet_read(tmp_path):
    """CLAUDE.md: the bulk path must never disagree with the per-packet path."""
    frames = [
        udp_frame(bytes([0x23, 0x00, 0x06, 0xEC]) + bytes(44), dport=123),
        tcp_frame(CLIENT_HELLO, dport=443),
        tcp_frame(HTTP_REQ),
        bytes(Ether() / IP() / TCP()),
    ]
    path = tmp_path / "mixed.pcap"
    B.wrpcap(str(path), [Ether(f) for f in frames])
    pl = B.rdpcap(str(path))

    for layer, field in (("NTP", "stratum"), ("TLS", "type"), ("TLS", "options")):
        bulk = pl.field_column(layer, field)
        one = []
        for i in range(len(pl)):
            p = pl[i]
            one.append(getattr(p[layer], field) if layer in p.layers() else None)
        assert bulk == one, (layer, field)


def test_a_condition_list_filter_selects_on_a_new_layer():
    frames = [
        udp_frame(bytes([0x23, 0x00, 0x06, 0xEC]) + bytes(44), dport=123),
        bytes(Ether() / IP() / TCP()),
    ]
    got = [Ether(f) for f in frames]
    assert [p for p in got if "NTP" in p.layers()][0].layers()[3] == "NTP"
