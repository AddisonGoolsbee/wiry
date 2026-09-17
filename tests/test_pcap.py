"""Capture files: writing, reading, and the bulk column APIs."""

import pytest

from wiry import (
    ARP, Dot1Q, Ether, ICMP, IP, IPv6, PacketList, PcapReader, Raw, TCP, UDP,
    rdpcap, wrpcap,
)
from helpers import ETHER_IP_TCP


def sample_packets():
    """A mixed capture, so every bulk query has both hits and misses."""
    pkts = [
        Ether() / IP(dst="10.0.0.%d" % i, ttl=60 + i) / TCP(dport=80 + i)
        for i in range(5)
    ]
    pkts += [
        Ether() / IP(dst="10.1.1.1") / UDP(sport=9, dport=9) / Raw(load=b"hi"),
        Ether() / IP(dst="10.1.1.2") / ICMP(),
        Ether() / Dot1Q(vlan=42) / IP(dst="10.2.2.2") / TCP(dport=22),
        Ether() / ARP(psrc="10.3.3.3"),
        Ether() / IPv6(src="2001:db8::1") / UDP(sport=7, dport=7) / Raw(load=b"v6"),
    ]
    return pkts


@pytest.fixture
def capture(tmp_path):
    pkts = sample_packets()
    path = str(tmp_path / "sample.pcap")
    wrpcap(path, pkts)
    return path, pkts


def test_write_then_read_preserves_count_and_bytes(capture):
    path, pkts = capture
    got = rdpcap(path)
    assert isinstance(got, PacketList)
    assert len(got) == len(pkts)
    for read_back, original in zip(got, pkts):
        assert bytes(read_back) == bytes(original)


def test_a_single_packet_does_not_need_a_list(tmp_path):
    path = str(tmp_path / "one.pcap")
    pkt = Ether() / IP() / TCP()
    wrpcap(path, pkt)
    got = rdpcap(path)
    assert len(got) == 1
    assert bytes(got[0]) == bytes(pkt)


def test_raw_bytes_can_be_written(tmp_path):
    path = str(tmp_path / "raw.pcap")
    wrpcap(path, [ETHER_IP_TCP])
    got = rdpcap(path)
    assert got.raw_at(0) == ETHER_IP_TCP
    assert got[0].layers() == ["Ether", "IP", "TCP"]


def test_an_empty_capture_round_trips(tmp_path):
    path = str(tmp_path / "empty.pcap")
    wrpcap(path, [])
    got = rdpcap(path)
    assert len(got) == 0
    assert list(got) == []
    assert got.times() == []
    assert got.count_layer(TCP) == 0
    assert got.field_column(IP, "dst") == []


def test_linktype_selects_the_starting_protocol(tmp_path):
    path = str(tmp_path / "rawip.pcap")
    inner = bytes(IP(dst="10.0.0.9") / UDP(sport=1, dport=2))
    wrpcap(path, [inner], linktype=101)
    got = rdpcap(path)
    assert got[0].layers() == ["IP", "UDP"]
    assert got[0][IP].dst == "10.0.0.9"


def test_indexing_supports_negatives_and_slices(capture):
    path, pkts = capture
    got = rdpcap(path)
    assert bytes(got[-1]) == bytes(pkts[-1])
    sliced = got[1:4]
    assert [bytes(p) for p in sliced] == [bytes(p) for p in pkts[1:4]]
    with pytest.raises(IndexError):
        got[len(pkts)]


def test_repr_and_times(capture):
    path, pkts = capture
    got = rdpcap(path)
    assert repr(got) == "<PacketList: %d packets>" % len(pkts)
    times = got.times()
    assert len(times) == len(pkts)
    assert all(isinstance(t, float) for t in times)
    assert [p.time for p in got] == times


def test_rdpcap_rejects_the_unimplemented_count_argument(capture):
    path, _ = capture
    with pytest.raises(NotImplementedError):
        rdpcap(path, count=2)


def test_pcapreader_is_a_context_manager_and_iterator(capture):
    path, pkts = capture
    with PcapReader(path) as reader:
        read = [bytes(p) for p in reader]
    assert read == [bytes(p) for p in pkts]


def test_pcapreader_iterator_is_exhausted_once(capture):
    path, pkts = capture
    reader = PcapReader(path)
    assert iter(reader) is reader
    assert len(list(reader)) == len(pkts)
    assert list(reader) == []
    with pytest.raises(StopIteration):
        next(reader)


def test_pcapreader_read_all_gives_the_whole_capture(capture):
    path, pkts = capture
    with PcapReader(path) as reader:
        everything = reader.read_all()
    assert len(everything) == len(pkts)
    assert bytes(everything[0]) == bytes(pkts[0])


@pytest.mark.parametrize("layer", [Ether, IP, IPv6, TCP, UDP, ARP, ICMP, Dot1Q, Raw])
def test_count_layer_agrees_with_a_python_loop(capture, layer):
    path, _ = capture
    got = rdpcap(path)
    slow = sum(1 for pkt in got if pkt.haslayer(layer))
    assert got.count_layer(layer) == slow


@pytest.mark.parametrize(
    "layer,field",
    [
        (Ether, "type"),
        (IP, "dst"),
        (IP, "ttl"),
        (IP, "proto"),
        (TCP, "dport"),
        (TCP, "flags"),
        (UDP, "sport"),
        (ARP, "psrc"),
        (IPv6, "src"),
    ],
)
def test_field_column_agrees_with_a_python_loop(capture, layer, field):
    path, _ = capture
    got = rdpcap(path)
    slow = [
        getattr(pkt.getlayer(layer), field) if pkt.haslayer(layer) else None
        for pkt in got
    ]
    assert got.field_column(layer, field) == slow


def test_field_column_yields_none_where_the_layer_is_absent(capture):
    path, _ = capture
    got = rdpcap(path)
    assert got.field_column(TCP, "dport") == [80, 81, 82, 83, 84, None, None, 22, None, None]
    assert got.field_column(Dot1Q, "vlan") == [None] * 7 + [42, None, None]


def test_field_column_rejects_a_field_the_layer_does_not_have(capture):
    path, _ = capture
    got = rdpcap(path)
    with pytest.raises(KeyError):
        got.field_column(IP, "sport")


def test_bulk_apis_accept_layer_names_as_strings(capture):
    path, _ = capture
    got = rdpcap(path)
    assert got.count_layer("TCP") == got.count_layer(TCP)
    assert got.field_column("IP", "ttl") == got.field_column(IP, "ttl")


def test_raw_at_matches_serialising_the_dissected_packet(capture):
    path, _ = capture
    got = rdpcap(path)
    for i in range(len(got)):
        assert got.raw_at(i) == bytes(got[i])
    with pytest.raises(IndexError):
        got.raw_at(len(got))


def test_reading_a_file_that_is_not_a_pcap_is_an_error(tmp_path):
    path = tmp_path / "junk.bin"
    path.write_bytes(b"not a pcap file at all, honestly" * 4)
    with pytest.raises(ValueError):
        rdpcap(str(path))


def test_reading_a_missing_file_is_an_os_error(tmp_path):
    with pytest.raises(OSError):
        rdpcap(str(tmp_path / "absent.pcap"))
