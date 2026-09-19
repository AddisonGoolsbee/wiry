"""Repeating groups: a header field says how many records follow, or how many
octets they fill, and the records are read in Rust and handed over as data.

Vectors are hand-built from RFC 2453 §4 (RIP route entries), Cisco's "NetFlow
Export Datagram Formats" version 5 record, RFC 3376 §4.2 (IGMPv3 membership
reports) and RFC 2328 §A.3.6 / §A.4.1 (OSPF acknowledgements).
"""

import struct

import pytest

from wiry import IGMP, IP, NetflowHeaderV5, OSPF_Hdr, RIP, UDP, rdpcap, wrpcap


def rip_entry(af=2, addr="0.0.0.0", mask="0.0.0.0", nexthop="0.0.0.0", metric=1):
    quad = lambda s: bytes(int(x) for x in s.split("."))  # noqa: E731
    return (
        struct.pack("!HH", af, 0)
        + quad(addr)
        + quad(mask)
        + quad(nexthop)
        + struct.pack("!I", metric)
    )


def rip_message(*entries):
    return b"\x02\x02\x00\x00" + b"".join(entries)


def netflow_record(src, dst, dpkts):
    quad = lambda s: bytes(int(x) for x in s.split("."))  # noqa: E731
    return (
        quad(src)
        + quad(dst)
        + bytes(4)
        + struct.pack("!HH", 0, 0)
        + struct.pack("!II", dpkts, 60)
        + bytes(48 - 24)
    )


def netflow_export(claimed, records):
    head = struct.pack("!HH", 5, claimed) + bytes(20)
    return head + b"".join(records)


def igmp_group_record(rtype, maddr, srcs=(), auxwords=0):
    quad = lambda s: bytes(int(x) for x in s.split("."))  # noqa: E731
    body = bytes([rtype, auxwords]) + struct.pack("!H", len(srcs)) + quad(maddr)
    return body + b"".join(quad(s) for s in srcs) + bytes(4 * auxwords)


def igmp_report(records):
    return b"\x22\x00\x00\x00\x00\x00" + struct.pack("!H", len(records)) + b"".join(records)


def lsa_header(lsid, lstype=1):
    quad = lambda s: bytes(int(x) for x in s.split("."))  # noqa: E731
    return (
        struct.pack("!HBB", 1, 0, lstype)
        + quad(lsid)
        + bytes([1, 1, 1, 1])
        + struct.pack("!IHH", 0x80000001, 0, 36)
    )


def ospf_ack(headers, padding=0):
    body = b"".join(headers)
    head = bytearray(24)
    head[0], head[1] = 2, 5
    struct.pack_into("!H", head, 2, 24 + len(body))
    return bytes(head) + body + bytes(padding)


def named(record, field):
    return dict(record[1])[field]


# ---------------------------------------------------------------- read path


def test_rip_entries_read_as_named_records():
    pkt = IP() / UDP(sport=520, dport=520) / RIP(rip_message(
        rip_entry(addr="192.168.1.0", mask="255.255.255.0", metric=1),
        rip_entry(addr="10.0.0.0", mask="255.0.0.0", metric=16),
    ))
    entries = pkt[RIP].entries
    assert [e[0] for e in entries] == ["RIPEntry", "RIPEntry"]
    assert named(entries[0], "addr") == "192.168.1.0"
    assert named(entries[0], "mask") == "255.255.255.0"
    assert named(entries[1], "metric") == 16


def test_rip_entries_run_to_the_end_of_the_datagram():
    for n in range(4):
        pkt = IP() / UDP(sport=520, dport=520) / RIP(rip_message(*[rip_entry()] * n))
        assert len(pkt[RIP].entries) == n


def test_a_partial_trailing_rip_entry_is_dropped():
    raw = rip_message(rip_entry(), rip_entry())[:-1]
    assert len(RIP(raw)[RIP].entries) == 1


def test_netflow_count_drives_the_record_list():
    recs = [netflow_record("1.2.3.4", "5.6.7.8", 3), netflow_record("9.9.9.9", "8.8.8.8", 1)]
    pkt = NetflowHeaderV5(netflow_export(2, recs))[NetflowHeaderV5]
    records = pkt.records
    assert len(records) == 2
    assert named(records[0], "src") == "1.2.3.4"
    assert named(records[0], "dpkts") == 3
    assert named(records[1], "dst") == "8.8.8.8"


@pytest.mark.parametrize("claimed,present,want", [(0, 2, 0), (1, 2, 1), (0xFFFF, 2, 2)])
def test_a_netflow_count_never_reads_past_what_arrived(claimed, present, want):
    recs = [netflow_record("1.2.3.4", "5.6.7.8", 1)] * present
    assert len(NetflowHeaderV5(netflow_export(claimed, recs))[NetflowHeaderV5].records) == want


def test_igmpv3_group_records_carry_a_nested_source_list():
    raw = igmp_report([
        igmp_group_record(4, "224.0.0.251", ["10.0.0.1", "10.0.0.2"]),
        igmp_group_record(3, "239.1.1.1"),
    ])
    pkt = IGMP(raw)[IGMP]
    assert pkt.numgrp == 2
    records = pkt.records
    assert [r[0] for r in records] == ["IGMPv3gr", "IGMPv3gr"]
    assert named(records[0], "maddr") == "224.0.0.251"
    assert named(records[0], "srcaddrs") == [("sa", "10.0.0.1"), ("sa", "10.0.0.2")]
    assert named(records[1], "srcaddrs") == []


def test_igmpv3_auxiliary_data_lengthens_a_record():
    raw = igmp_report([
        igmp_group_record(1, "224.0.0.1", ["10.0.0.1"], auxwords=2),
        igmp_group_record(2, "224.0.0.2"),
    ])
    records = IGMP(raw)[IGMP].records
    assert len(records) == 2
    assert named(records[1], "maddr") == "224.0.0.2"


def test_a_version_two_report_carries_no_records():
    pkt = IGMP(b"\x16\x00\x09\x04\xe0\x00\x00\xfb")[IGMP]
    assert pkt.records == []
    assert pkt.gaddr == "224.0.0.251"


def test_ospf_acknowledgement_lsa_headers_stop_at_the_declared_length():
    raw = ospf_ack([lsa_header("192.168.0.1"), lsa_header("192.168.0.2")], padding=20)
    heads = OSPF_Hdr(raw)[OSPF_Hdr].lsaheaders
    assert [h[0] for h in heads] == ["OSPF_LSA_Hdr", "OSPF_LSA_Hdr"]
    assert named(heads[1], "id") == "192.168.0.2"
    assert named(heads[0], "seq") == 0x80000001


def test_another_ospf_type_leaves_its_body_alone():
    hello = bytearray(24)
    hello[0], hello[1] = 2, 1
    struct.pack_into("!H", hello, 2, 24)
    assert OSPF_Hdr(bytes(hello) + b"\xaa" * 8)[OSPF_Hdr].lsaheaders == []


def test_the_raw_region_is_still_reachable():
    raw = rip_message(rip_entry(addr="10.0.0.0"))
    assert RIP(raw)[RIP].raw_options() == raw[4:]


# --------------------------------------------------------------- write path


def test_rip_entries_build_the_bytes_they_read_back():
    want = rip_message(
        rip_entry(addr="192.168.1.0", mask="255.255.255.0", metric=1),
        rip_entry(addr="10.0.0.0", mask="255.0.0.0", metric=16),
    )
    built = RIP(cmd=2, version=2, entries=[
        ("RIPEntry", [("AF", 2), ("addr", "192.168.1.0"),
                      ("mask", "255.255.255.0"), ("metric", 1)]),
        ("RIPEntry", [("AF", 2), ("addr", "10.0.0.0"),
                      ("mask", "255.0.0.0"), ("metric", 16)]),
    ])
    assert bytes(built) == want
    assert RIP(bytes(built))[RIP].entries == RIP(want)[RIP].entries


def test_building_netflow_records_writes_the_count_field():
    built = NetflowHeaderV5(records=[
        ("NetflowRecordV5", [("src", "1.2.3.4"), ("dst", "5.6.7.8"), ("dpkts", 3)]),
        ("NetflowRecordV5", [("src", "9.9.9.9"), ("dst", "8.8.8.8"), ("dpkts", 1)]),
    ])
    raw = bytes(built)
    assert struct.unpack_from("!H", raw, 2)[0] == 2
    assert len(raw) == 24 + 96
    assert named(NetflowHeaderV5(raw)[NetflowHeaderV5].records[0], "dpkts") == 3


def test_building_igmp_records_writes_both_counts():
    built = IGMP(type=0x22, records=[
        ("IGMPv3gr", [("rtype", 4), ("maddr", "224.0.0.251"),
                      ("srcaddrs", ["10.0.0.1", "10.0.0.2"])]),
        ("IGMPv3gr", [("rtype", 3), ("maddr", "239.1.1.1")]),
    ])
    raw = bytes(built)
    assert struct.unpack_from("!H", raw, 6)[0] == 2
    back = IGMP(raw)[IGMP]
    assert named(back.records[0], "numsrc") == 2
    assert named(back.records[0], "srcaddrs") == [("sa", "10.0.0.1"), ("sa", "10.0.0.2")]
    assert named(back.records[1], "numsrc") == 0


def test_an_unknown_element_or_field_is_refused():
    with pytest.raises(ValueError):
        bytes(RIP(entries=[("NotAnEntry", [("AF", 2)])]))
    with pytest.raises(ValueError):
        bytes(RIP(entries=[("RIPEntry", [("nope", 2)])]))


def test_a_raw_region_still_encodes_verbatim():
    body = rip_entry(addr="10.0.0.0")
    assert bytes(RIP(entries=body)) == b"\x01\x02\x00\x00" + body


# ------------------------------------------------- bulk agrees with per-packet


@pytest.fixture
def capture(tmp_path):
    pkts = [
        IP() / UDP(sport=520, dport=520) / RIP(rip_message()),
        IP() / UDP(sport=520, dport=520) / RIP(rip_message(
            rip_entry(addr="192.168.1.0", metric=1),
            rip_entry(addr="10.0.0.0", metric=16),
        )),
        IP() / UDP(sport=1234, dport=53),
    ]
    path = str(tmp_path / "rip.pcap")
    wrpcap(path, pkts)
    return rdpcap(path)


def test_the_column_agrees_with_the_per_packet_read(capture):
    loop = [p[RIP].entries if p.haslayer(RIP) else None for p in capture]
    assert capture.columns([("RIP", "entries")])["RIP.entries"] == loop
    assert list(capture.field_column("RIP", "entries")) == loop


def test_a_group_column_selects_in_rust(capture):
    rows = capture.columns([("RIP", "entries")], layer="RIP")["RIP.entries"]
    assert len(rows) == 2
    assert all(isinstance(r, list) for r in rows)
