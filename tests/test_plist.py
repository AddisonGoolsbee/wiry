"""`PacketList` held both ways, `SndRcvList`, and the packet-level surface
that came with them: class adoption, answers, route, pickled metadata and
pcapng annotations."""

import pickle

import pytest

import wiry
from wiry import (
    ARP, ICMP, IP, TCP, UDP, Ether, IPv6, PacketList, Padding, Raw, SndRcvList,
    rdpcap, wrpcap, wrpcapng,
)


def built():
    return [
        Ether() / IP(dst="10.0.0.%d" % i) / TCP(dport=80 + i) for i in range(3)
    ] + [
        Ether() / IP() / UDP(),
        Ether() / IP() / ICMP(),
        Ether() / ARP(),
    ]


@pytest.fixture
def capture(tmp_path):
    path = str(tmp_path / "c.pcap")
    wrpcap(path, built())
    return rdpcap(path)


def test_a_list_built_from_packets_keeps_the_objects():
    pkts = built()
    pl = PacketList(pkts)
    assert pl[0] is pkts[0]
    assert list(pl) == pkts
    assert pl.res is pkts


def test_the_repr_counts_as_scapys_does(capture):
    # rdpcap names the list after the file, as scapy's does.
    assert repr(capture) == "<c.pcap: TCP:3 UDP:1 ICMP:1 Other:1>"
    assert repr(PacketList(built())) == "<PacketList: TCP:3 UDP:1 ICMP:1 Other:1>"


def test_a_layer_and_a_slice_index_give_lists(capture):
    for pl in (capture, PacketList(built())):
        tcp = pl[TCP]
        assert len(tcp) == 3 and all(TCP in p for p in tcp)
        assert tcp.listname == f"TCP from {pl.listname}"
        assert [bytes(p) for p in pl[1:3]] == [bytes(p) for p in built()[1:3]]


def test_the_bulk_path_agrees_with_the_python_list(capture):
    py = PacketList(built())
    assert py.field_column(IP, "dst") == capture.field_column(IP, "dst")
    assert py.count_layer(TCP) == capture.count_layer(TCP) == 3
    assert py.sprintf("%IP.dst%") == capture.sprintf("%IP.dst%")


def test_a_list_that_mixes_link_layers_refuses_the_bulk_path():
    with pytest.raises(ValueError, match="same link"):
        PacketList([Ether() / IP(), IP()]).count_layer(IP)


def test_filter_takes_a_function_as_scapys_does(capture):
    for pl in (capture, PacketList(built())):
        got = pl.filter(lambda p: UDP in p)
        assert len(got) == 1 and got.listname == f"filtered {pl.listname}"


def test_mutating_a_capture_turns_it_into_a_python_list(capture):
    capture.append(Ether() / IP())
    assert len(capture) == 7
    assert capture._rust is None


def test_adding_lists(capture):
    both = capture + PacketList(built())
    assert len(both) == 12 and both.listname == "c.pcap+PacketList"


def test_lists_pickle(capture):
    for pl in (capture, PacketList(built())):
        back = pickle.loads(pickle.dumps(pl))
        assert [bytes(p) for p in back] == [bytes(p) for p in pl]


def test_sr_pairs_each_packet_with_a_later_answer():
    ping = IP(src="1.1.1.1", dst="2.2.2.2") / ICMP(type=8, id=7)
    pong = IP(src="2.2.2.2", dst="1.1.1.1") / ICMP(type=0, id=7)
    other = IP(src="3.3.3.3", dst="4.4.4.4") / UDP()
    answered, rest = PacketList([ping, other, pong]).sr()
    assert isinstance(answered, SndRcvList) and len(answered) == 1
    assert answered[0].query is ping and answered[0].answer is pong
    assert list(rest) == [other]


def test_a_sndrcvlist_summarises_pairs(capsys):
    pairs = SndRcvList([(IP() / ICMP(), IP() / ICMP(type=0))])
    pairs.summary()
    assert "==>" in capsys.readouterr().out


def test_writing_a_sndrcvlist_stamps_the_request_with_its_send_time(tmp_path):
    s, r = Ether() / IP(), Ether() / IP()
    s.sent_time, r.time = 1, 2
    path = str(tmp_path / "sr.pcap")
    wrpcap(path, SndRcvList([(s, r)]))
    assert [p.time for p in rdpcap(path)] == [1.0, 2.0]


def test_hexraw_padding_and_nzpadding_print_scapys_rows(capsys):
    pl = PacketList([IP() / Raw(b"0"), IP() / Padding(b"AB"), IP() / Padding(b"\0\0")])
    pl.hexraw()
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("0000 ") and out[1].startswith("0000  30")
    pl.nzpadding()
    out = capsys.readouterr().out.splitlines()
    assert len(out) == 2 and out[1].startswith("0000  41 42")


def test_afterglow_graphs_source_event_destination():
    pl = PacketList([IP(dst="10.0.0.2") / TCP(dport=i) for i in range(2)])
    dot = pl.afterglow()
    assert dot.startswith('digraph "afterglow" {') and '"evt.0"' in dot


def test_replace_copies_before_it_changes():
    pl = PacketList([IP(ttl=64) / TCP(), IP(ttl=10) / TCP()])
    out = pl.replace(IP.ttl, 64, 1)
    assert [p.ttl for p in out] == [1, 10]
    assert pl[0].ttl == 64


def test_getlayer_drops_the_misses():
    pl = PacketList([IP() / TCP(), IP() / UDP()])
    got = pl.getlayer(TCP)
    assert len(got) == 1


def test_a_packet_takes_its_outermost_layers_class():
    p = Ether() / ARP()
    assert isinstance(p, Ether) and type(p) is Ether
    again = p.__class__(bytes(p))
    assert again.layers() == ["Ether", "ARP"]


def test_stacking_over_a_dissected_packet_writes_the_binding():
    inner = IP(bytes(IP() / ICMP()))
    outer = Ether() / inner
    assert outer.layers() == ["Ether", "IP", "ICMP"] and outer.type == 0x800
    read = IP() / ICMP()
    read.src
    assert (Ether() / read).type == 0x800


def test_answers_uses_the_matcher_sr_does():
    ping = IP(src="1.2.3.4", dst="5.6.7.8") / ICMP(type=8)
    pong = IP(src="5.6.7.8", dst="1.2.3.4") / ICMP(type=0)
    assert pong.answers(ping) and not ping.answers(pong)
    assert ping > pong and pong < ping
    assert Raw(b"x").answers(ping)


def test_route_picks_the_layer_that_names_a_destination():
    assert ARP(ptype=0).route() == (None, None, None)
    assert Raw(b"x").route() == (None, None, None)


def test_metadata_survives_pickling():
    p = IP(src="1.2.3.4") / TCP()
    p.time, p.sent_time, p.direction, p.sniffed_on = 5.0, 6.0, 1, "eth0"
    p.comment = b"c"
    q = pickle.loads(pickle.dumps(p))
    assert (q.time, q.sent_time, q.direction, q.sniffed_on, q.comments) == \
        (5.0, 6.0, 1, "eth0", [b"c"])
    assert type(q) is IP and bytes(q) == bytes(p)


def test_pcapng_annotations_round_trip(tmp_path):
    a = Ether() / IP() / TCP()
    a.time, a.comments, a.direction, a.sniffed_on = 1.5, [b"x", b"y"], 1, "eth7"
    b = Ether() / IP() / UDP()
    b.time = 2.0
    path = str(tmp_path / "a.pcapng")
    wrpcapng(path, [a, b])
    got = rdpcap(path)
    assert got[0].comments == [b"x", b"y"] and got[0].direction == 1
    assert got[0].sniffed_on == "eth7" and got[0].time == 1.5
    assert got[1].comment is None and got[1].sniffed_on is None
    assert [bytes(p) for p in got] == [bytes(a), bytes(b)]
    assert got[1:][0].time == 2.0


def test_an_unannotated_pcapng_still_writes_through_rust(tmp_path):
    path = str(tmp_path / "plain.pcapng")
    wrpcapng(path, built())
    got = rdpcap(path)
    assert len(got) == 6 and got[0].comment is None


def test_a_raw_ip_capture_reads_each_version(tmp_path):
    path = str(tmp_path / "raw.pcap")
    wrpcap(path, [IP() / UDP(), IPv6() / UDP()], linktype=101)
    got = rdpcap(path)
    assert [type(p) for p in got] == [IP, IPv6]
    assert got.filter(where=[("IPv6", "nh", "==", 17)]).count_layer(UDP) == 1


def test_a_bad_filter_is_scapys_exception():
    if not wiry.capture_available():
        pytest.skip("compiling BPF is libpcap's job")
    with pytest.raises(wiry.Scapy_Exception):
        wiry.sniff(offline=IP() / UDP(), filter="not arpand not")


def test_answers_refuses_a_layer_it_has_no_rule_for():
    from wiry import BOOTP

    with pytest.raises(NotImplementedError, match="BOOTP"):
        (IP() / UDP() / BOOTP()).answers(IP() / UDP() / BOOTP())
