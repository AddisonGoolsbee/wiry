"""The parts of DNS, DHCP and TCP options that had holes in them.

Vectors are hand-built from RFC 1035 (§4.1 records, §4.2.2 stream framing,
§5.1 presentation form), RFC 2782 (SRV), RFC 6891 (EDNS0), RFC 4034 and
RFC 5155 (DNSSEC), RFC 8659 (CAA), RFC 2018 (SACK), RFC 2131 §4.1 and
RFC 3046 and RFC 3396 (DHCP).
"""

import struct

from wiry import DHCP, DNS, IP, TCP, UDP, BOOTP, Ether, Raw


def name(*labels: str) -> bytes:
    return b"".join(bytes([len(l)]) + l.encode() for l in labels) + b"\x00"


def header(qd: int, an: int, ns: int, ar: int) -> bytes:
    return b"\x12\x34\x81\x80" + struct.pack("!HHHH", qd, an, ns, ar)


def question(nm: bytes, qtype: int, qclass: int = 1) -> bytes:
    return nm + struct.pack("!HH", qtype, qclass)


def record(nm: bytes, rtype: int, rclass: int, ttl: int, rdata: bytes) -> bytes:
    return nm + struct.pack("!HHIH", rtype, rclass, ttl, len(rdata)) + rdata


def over_tcp(msg: bytes, claimed: int | None = None) -> bytes:
    """An Ether/IP/TCP frame carrying `msg` with its RFC 1035 §4.2.2 prefix."""
    prefix = struct.pack("!H", len(msg) if claimed is None else claimed)
    return bytes(
        Ether() / IP() / TCP(sport=40000, dport=53) / Raw(load=prefix + msg)
    )


def over_udp(msg: bytes) -> bytes:
    return bytes(Ether() / IP() / UDP(sport=40000, dport=53) / Raw(load=msg))


QUERY = header(1, 0, 0, 0) + question(name("example", "com"), 1)


# --- RFC 1035 §4.2.2, DNS over TCP -----------------------------------------


def test_tcp_port_53_reaches_dns_and_strips_the_length_prefix():
    pkt = Ether(over_tcp(QUERY))
    assert pkt.layers()[:4] == ["Ether", "IP", "TCP", "DNS"]
    assert pkt[DNS].length == len(QUERY)
    assert pkt[DNS].id == 0x1234
    assert pkt[DNS].qdcount == 1
    assert pkt[DNS].qd == [
        {"qname": "example.com.", "qtype": 1, "type": "A", "qclass": 1}
    ]


def test_the_length_prefix_exists_only_over_tcp():
    assert "length" in Ether(over_tcp(QUERY))[DNS].fields()
    udp = Ether(over_udp(QUERY))
    assert "length" not in udp[DNS].fields()
    assert udp[DNS].id == 0x1234
    assert udp[DNS].qd == Ether(over_tcp(QUERY))[DNS].qd


def test_a_stream_message_round_trips_and_recomputes_its_length():
    raw = over_tcp(QUERY)
    assert bytes(Ether(raw)) == raw

    stale = Ether(over_tcp(QUERY, claimed=9999))
    stale[DNS].id = 7
    assert bytes(stale)[-len(QUERY) - 2 : -len(QUERY)] == struct.pack(
        "!H", len(QUERY)
    )
    assert Ether(bytes(stale))[DNS].length == len(QUERY)


def test_a_built_dns_over_tcp_dissects_back():
    pkt = IP() / TCP() / DNS()
    back = IP(bytes(pkt))
    assert back.layers() == ["IP", "TCP", "DNS"]
    assert back[TCP].dport == 53
    assert back[DNS].length == 12


# --- RFC 6891 EDNS0 ---------------------------------------------------------


def opt_record(udpsize: int, ttl: int, rdata: bytes) -> bytes:
    return record(b"\x00", 41, udpsize, ttl, rdata)


def test_an_opt_pseudo_record_exposes_its_edns_fields():
    cookie = struct.pack("!HH", 10, 8) + bytes(range(8))
    msg = header(1, 0, 0, 1) + question(name("example", "com"), 1)
    msg += opt_record(4096, 0x01008000, cookie)
    ar = Ether(over_udp(msg))[DNS].ar
    assert len(ar) == 1
    assert ar[0]["rrname"] == "."
    assert ar[0]["type"] == "OPT"
    assert ar[0]["udpsize"] == 4096
    assert ar[0]["extrcode"] == 1
    assert ar[0]["version"] == 0
    assert ar[0]["do"] is True
    assert ar[0]["rdata"] == [
        {"code": 10, "name": "COOKIE", "data": bytes(range(8))}
    ]


def test_an_opt_record_with_no_options_is_an_empty_list():
    msg = header(0, 0, 0, 1) + opt_record(1232, 0, b"")
    ar = Ether(over_udp(msg))[DNS].ar
    assert ar[0]["rdata"] == []
    assert ar[0]["do"] is False
    assert ar[0]["udpsize"] == 1232


# --- RFC 4034 / RFC 5155 DNSSEC --------------------------------------------


def test_dnssec_rdata_is_decoded_rather_than_left_raw():
    zone = name("example", "com")
    ds = struct.pack("!HBB", 12345, 8, 2) + b"\xab" * 32
    key = struct.pack("!HBB", 257, 3, 8) + b"public key"
    sig = (
        struct.pack("!HBBIIIH", 1, 8, 2, 3600, 1700000000, 1690000000, 12345)
        + zone
        + b"SIGNATURE"
    )
    # RFC 4034 §4.1.2 window 0, two octets, bits for A (1) and NS (2).
    bitmap = b"\x00\x02\x60\x00"
    nsec = name("next", "example", "com") + bitmap

    msg = header(0, 4, 0, 0)
    msg += record(zone, 43, 1, 3600, ds)
    msg += record(zone, 48, 1, 3600, key)
    msg += record(zone, 46, 1, 3600, sig)
    msg += record(zone, 47, 1, 3600, nsec)
    an = Ether(over_udp(msg))[DNS].an

    assert [r["type"] for r in an] == ["DS", "DNSKEY", "RRSIG", "NSEC"]
    assert an[0]["rdata"] == {
        "keytag": 12345,
        "algorithm": 8,
        "digesttype": 2,
        "digest": b"\xab" * 32,
    }
    assert an[1]["rdata"]["flags"] == 257
    assert an[1]["rdata"]["publickey"] == b"public key"
    assert an[2]["rdata"]["typecovered"] == "A"
    assert an[2]["rdata"]["signersname"] == "example.com."
    assert an[2]["rdata"]["signature"] == b"SIGNATURE"
    assert an[3]["rdata"]["nextname"] == "next.example.com."
    assert an[3]["rdata"]["types"] == ["A", "NS"]


def test_srv_rdata_is_decoded():
    rdata = struct.pack("!HHH", 10, 5, 443) + name("host", "example", "com")
    msg = header(0, 1, 0, 0) + record(name("example", "com"), 33, 1, 60, rdata)
    an = Ether(over_udp(msg))[DNS].an
    assert an[0]["rdata"] == {
        "priority": 10,
        "weight": 5,
        "port": 443,
        "target": "host.example.com.",
    }


def test_an_unknown_type_still_falls_back_to_raw_bytes():
    msg = header(0, 1, 0, 0) + record(name("a", "com"), 999, 1, 60, b"\xde\xad")
    an = Ether(over_udp(msg))[DNS].an
    assert an[0]["type"] == "UNKNOWN"
    assert an[0]["rdata"] == b"\xde\xad"


# --- RFC 1035 §5.1 presentation form ---------------------------------------


def test_names_end_in_the_root_dot_and_escape_a_dot_inside_a_label():
    msg = header(3, 0, 0, 0)
    msg += question(name("example", "com"), 1)
    msg += question(b"\x03a.b\x03com\x00", 1)
    msg += question(b"\x00", 2)
    qd = Ether(over_udp(msg))[DNS].qd
    assert qd[0]["qname"] == "example.com."
    assert qd[1]["qname"] == "a\\.b.com."
    assert qd[2]["qname"] == "."


# --- RFC 2018 SACK ----------------------------------------------------------


def test_sack_blocks_read_as_edge_pairs_and_encode_back():
    pkt = IP() / TCP(
        options=[("SAckOK", None), ("SAck", [(1000, 2000), (3000, 4000)])]
    )
    raw = bytes(pkt)
    back = IP(raw)
    assert back[TCP].options == [
        ("SAckOK", None),
        ("SAck", [(1000, 2000), (3000, 4000)]),
    ]
    again = IP() / TCP(options=back[TCP].options)
    assert bytes(again)[20:] == raw[20:]
    assert back[TCP].raw_options()[2:] == struct.pack(
        "!BBIIII", 5, 18, 1000, 2000, 3000, 4000
    )


def test_a_sack_length_that_is_not_whole_blocks_keeps_its_octets():
    tcp = bytearray(28)
    tcp[0:2] = struct.pack("!H", 1234)
    tcp[2:4] = struct.pack("!H", 80)
    tcp[12] = 7 << 4
    tcp[20:28] = bytes([5, 6, 0, 0, 0, 1, 1, 1])
    pkt = IP(bytes(IP(proto=6) / Raw(load=bytes(tcp))))
    assert pkt[TCP].options[0] == ("SAck", b"\x00\x00\x00\x01")


# --- DHCP: RFC 3046, RFC 3396, RFC 2131 §4.1 --------------------------------


def dhcp_frame(bootp_hdr: bytes, opts: bytes):
    payload = bootp_hdr + b"\x63\x82\x53\x63" + opts
    return Ether() / IP() / UDP(sport=67, dport=68) / Raw(load=payload)


def bare_bootp() -> bytearray:
    h = bytearray(236)
    h[0:3] = bytes([2, 1, 6])
    return h


def test_relay_agent_sub_options_are_named():
    opts = bytes([53, 1, 5]) + bytes(
        [82, 10, 1, 4, ord("e"), ord("t"), ord("h"), ord("0"), 2, 2, 0xAB, 0xCD]
    ) + bytes([255])
    pkt = Ether(bytes(dhcp_frame(bytes(bare_bootp()), opts)))
    got = dict(pkt[DHCP].options)
    assert got["relay_agent_information"] == [
        ("agent_circuit_id", b"eth0"),
        ("agent_remote_id", b"\xab\xcd"),
    ]


def test_a_relay_agent_option_encodes_from_the_list_it_parses_to():
    pkt = IP() / UDP() / BOOTP() / DHCP(
        options=[
            ("message-type", "ack"),
            (
                "relay_agent_information",
                [("agent_circuit_id", b"eth0"), ("agent_remote_id", b"\xab\xcd")],
            ),
            ("end", None),
        ]
    )
    back = IP(bytes(pkt))
    assert dict(back[DHCP].options)["relay_agent_information"] == [
        ("agent_circuit_id", b"eth0"),
        ("agent_remote_id", b"\xab\xcd"),
    ]


def test_a_long_value_split_over_repeated_codes_is_joined():
    # RFC 3396 §5: option 60 appears twice and is one value.
    opts = bytes([53, 1, 5])
    opts += bytes([60, 3]) + b"abc" + bytes([60, 2]) + b"de"
    opts += bytes([255])
    pkt = Ether(bytes(dhcp_frame(bytes(bare_bootp()), opts)))
    names = [n for n, _ in pkt[DHCP].options]
    assert names == ["message-type", "60", "end"]
    assert dict(pkt[DHCP].options)["60"] == b"abcde"


def test_options_in_sname_and_file_are_read_when_option_52_says_so():
    h = bare_bootp()
    h[44:50] = bytes([12, 3, ord("p"), ord("c"), ord("1"), 255])
    h[108:115] = bytes([54, 4, 192, 168, 1, 1, 255])
    opts = bytes([53, 1, 5, 52, 1, 3, 255])
    pkt = Ether(bytes(dhcp_frame(bytes(h), opts)))
    got = pkt[DHCP].options
    # RFC 3396 §4 order: the options field, then file, then sname.
    assert [n for n, _ in got] == [
        "message-type",
        "overload",
        "end",
        "server_id",
        "end",
        "hostname",
        "end",
    ]
    assert dict(got)["server_id"] == ["192.168.1.1"]
    assert dict(got)["hostname"] == "pc1"


def test_without_option_52_those_fields_are_not_read_as_options():
    h = bare_bootp()
    h[108:116] = b"boot.img"
    pkt = Ether(bytes(dhcp_frame(bytes(h), bytes([53, 1, 5, 255]))))
    assert [n for n, _ in pkt[DHCP].options] == ["message-type", "end"]
    assert pkt[BOOTP].file.rstrip(b"\x00") == b"boot.img"


def test_a_bulk_read_agrees_with_the_per_packet_read(tmp_path):
    from wiry import wrpcap, rdpcap

    h = bare_bootp()
    h[44:50] = bytes([12, 3, ord("p"), ord("c"), ord("1"), 255])
    frames = [
        dhcp_frame(bytes(h), bytes([53, 1, 5, 52, 1, 2, 255])),
        Ether(over_tcp(QUERY)),
    ]
    path = str(tmp_path / "depth.pcap")
    wrpcap(path, frames)
    pl = rdpcap(path)

    cols = pl.columns(
        [("DHCP", "options"), ("DNS", "id"), ("DNS", "length")]
    )
    assert cols["DHCP.options"][0] == pl[0][DHCP].options
    assert cols["DNS.id"][1] == pl[1][DNS].id == 0x1234
    assert cols["DNS.length"][1] == pl[1][DNS].length == len(QUERY)


def test_a_bulk_read_of_a_framed_only_field_refuses_the_unframed_layer(tmp_path):
    """`length` exists only over TCP, so a UDP-carried DNS packet must answer
    None rather than decoding the two octets `id` occupies there."""
    from wiry import wrpcap, rdpcap

    path = str(tmp_path / "both.pcap")
    wrpcap(path, [Ether(over_udp(QUERY)), Ether(over_tcp(QUERY))])
    pl = rdpcap(path)

    cols = pl.columns([("DNS", "id"), ("DNS", "length")])
    assert cols["DNS.id"] == [0x1234, 0x1234]
    assert cols["DNS.length"] == [None, len(QUERY)]
    assert pl.field_column("DNS", "length") == [None, len(QUERY)]
    assert not hasattr(pl[0][DNS], "length")

    # A condition on the field selects only the packet that carries it.
    assert len(pl.filter(where=[("DNS", "length", "==", 0x1234)])) == 0
    assert len(pl.filter(where=[("DNS", "length", "==", len(QUERY))])) == 1
    assert len(pl.filter(where=[("DNS", "id", "==", 0x1234)])) == 2


def test_a_second_message_in_the_segment_survives_an_unrelated_write():
    two = QUERY + struct.pack("!H", len(QUERY)) + QUERY
    pkt = Ether(over_tcp(two, claimed=len(QUERY)))
    pkt[IP].ttl = 5
    out = bytes(pkt)
    assert out[-len(two) :] == two
    assert Ether(out)[DNS].length == len(QUERY)


def test_an_option_split_by_rfc_3396_joins_its_octets_not_its_values():
    # A half of an address list, and a half of a nested region, decode to
    # nothing on their own; joining before decoding is what keeps them.
    mid = bytes([53, 1, 5, 3, 2, 10, 0, 3, 2, 0, 1, 255])
    got = dict(Ether(bytes(dhcp_frame(bytes(bare_bootp()), mid)))[DHCP].options)
    assert got["router"] == ["10.0.0.1"]

    split = bytes([53, 1, 5, 82, 4, 1, 4]) + b"et" + bytes([82, 6]) + b"h0" + bytes(
        [2, 2, 0xAB, 0xCD, 255]
    )
    got = dict(Ether(bytes(dhcp_frame(bytes(bare_bootp()), split)))[DHCP].options)
    assert got["relay_agent_information"] == [
        ("agent_circuit_id", b"eth0"),
        ("agent_remote_id", b"\xab\xcd"),
    ]


def test_an_unsplit_option_region_is_unaffected_by_joining():
    whole = bytes([53, 1, 5, 3, 8, 10, 0, 0, 1, 10, 0, 0, 2, 12, 3]) + b"pc1" + bytes(
        [82, 4, 1, 2] + [ord("e"), ord("0")] + [255]
    )
    raw = bytes(dhcp_frame(bytes(bare_bootp()), whole))
    pkt = Ether(raw)
    assert bytes(pkt) == raw
    assert [n for n, _ in pkt[DHCP].options] == [
        "message-type",
        "router",
        "hostname",
        "relay_agent_information",
        "end",
    ]
    assert pkt[DHCP].raw_options() == whole


def test_overload_flags_claiming_regions_that_do_not_decode_are_harmless():
    for value in (0, 1, 2, 3, 255):
        opts = bytes([53, 1, 5, 52, 1, value, 255])
        pkt = Ether(bytes(dhcp_frame(bytes(bare_bootp()), opts)))
        names = [n for n, _ in pkt[DHCP].options]
        assert names[:3] == ["message-type", "overload", "end"]
        assert bytes(pkt) == bytes(dhcp_frame(bytes(bare_bootp()), opts))


def test_an_overloaded_region_setting_overload_again_does_not_recurse():
    h = bare_bootp()
    h[108:116] = bytes([52, 1, 3, 12, 2, ord("x"), ord("y"), 255])
    pkt = Ether(bytes(dhcp_frame(bytes(h), bytes([53, 1, 5, 52, 1, 1, 255]))))
    names = [n for n, _ in pkt[DHCP].options]
    # `sname` is never reached: only the outermost option 52 selects regions.
    assert names.count("hostname") == 1
    assert dict(pkt[DHCP].options)["hostname"] == "xy"
