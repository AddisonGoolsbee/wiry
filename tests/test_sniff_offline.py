"""The sniff state machine, driven entirely offline.

No privileges, no network and no live backend: the whole of `sniff()` except
the I/O shim is exercised here, because `offline=` drives the same machine the
live drivers will.
"""

import time

import pytest

import wiry as P
from wiry import ARP, Ether, IP, TCP, UDP

# 4 TCP to port 80, 3 UDP to 53, 2 ARP. Chosen so every predicate below has a
# partition it selects and one it rejects.
TCP_N, UDP_N, ARP_N = 4, 3, 2
TOTAL = TCP_N + UDP_N + ARP_N


def _corpus():
    pkts = [
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=1000 + i, dport=80)
        for i in range(TCP_N)
    ]
    pkts += [
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="10.0.0.3", dst="10.0.0.4")
        / UDP(sport=2000 + i, dport=53)
        for i in range(UDP_N)
    ]
    pkts += [Ether(src="00:11:22:33:44:55") / ARP() for _ in range(ARP_N)]
    return pkts


@pytest.fixture(scope="module")
def cap(tmp_path_factory):
    path = tmp_path_factory.mktemp("sniff") / "corpus.pcap"
    P.wrpcap(str(path), _corpus())
    return str(path)


def is_tcp(pkt):
    return "TCP" in pkt.layers()


def is_udp(pkt):
    return "UDP" in pkt.layers()


def test_unfiltered_agrees_with_rdpcap(cap):
    read = P.rdpcap(cap)
    sniffed = P.sniff(offline=cap)
    assert len(sniffed) == len(read) == TOTAL
    assert [bytes(p) for p in sniffed] == [bytes(p) for p in read]
    assert [p.layers() for p in sniffed] == [p.layers() for p in read]
    assert sniffed.times() == read.times()


def test_count_bounds_the_result(cap):
    for n in range(1, TOTAL + 1):
        assert len(P.sniff(offline=cap, count=n)) == n
    assert len(P.sniff(offline=cap, count=TOTAL + 5)) == TOTAL
    assert len(P.sniff(offline=cap, count=0)) == TOTAL


def test_count_takes_the_first_packets(cap):
    read = P.rdpcap(cap)
    got = P.sniff(offline=cap, count=3)
    assert [bytes(p) for p in got] == [bytes(read[i]) for i in range(3)]


def test_store_zero_returns_an_empty_list(cap):
    got = P.sniff(offline=cap, store=0)
    assert isinstance(got, P.PacketList)
    assert len(got) == 0
    assert list(got) == []


def test_store_one_returns_everything(cap):
    assert len(P.sniff(offline=cap, store=1)) == TOTAL


def test_store_zero_still_runs_prn(cap):
    seen = []
    assert len(P.sniff(offline=cap, store=0, prn=seen.append)) == 0
    assert len(seen) == TOTAL


def test_prn_arity_and_order(cap):
    read = P.rdpcap(cap)
    seen = []

    def one_positional(pkt):
        seen.append(pkt)

    P.sniff(offline=cap, prn=one_positional)
    assert len(seen) == TOTAL
    assert all(isinstance(p, P.Packet) for p in seen)
    assert [bytes(p) for p in seen] == [bytes(p) for p in read]
    assert [p.time for p in seen] == read.times()


def test_prn_return_value_is_printed(cap, capsys):
    P.sniff(offline=cap, count=2, prn=lambda p: f"saw {p.layers()[0]}")
    assert capsys.readouterr().out == "saw Ether\nsaw Ether\n"


def test_prn_returning_none_prints_nothing(cap, capsys):
    P.sniff(offline=cap, count=2, prn=lambda p: None)
    assert capsys.readouterr().out == ""


def test_quiet_suppresses_the_printing(cap, capsys):
    P.sniff(offline=cap, count=2, quiet=True, prn=lambda p: "noise")
    assert capsys.readouterr().out == ""


def test_lfilter_selects(cap):
    assert len(P.sniff(offline=cap, lfilter=is_udp)) == UDP_N
    assert len(P.sniff(offline=cap, lfilter=is_tcp)) == TCP_N
    assert len(P.sniff(offline=cap, lfilter=lambda p: False)) == 0


def test_lfilter_runs_before_prn(cap):
    seen = []
    P.sniff(offline=cap, lfilter=is_udp, prn=seen.append)
    assert len(seen) == UDP_N
    assert all(is_udp(p) for p in seen)


def test_count_counts_survivors_not_packets(cap):
    got = P.sniff(offline=cap, lfilter=is_udp, count=2)
    assert len(got) == 2
    assert all(is_udp(p) for p in got)


def test_stop_filter_stops_early(cap):
    # The first UDP packet is at index TCP_N, and the packet that triggers the
    # stop is kept, exactly as scapy keeps it.
    got = P.sniff(offline=cap, stop_filter=is_udp)
    assert len(got) == TCP_N + 1
    assert is_udp(got[-1])


def test_stop_filter_that_never_fires_reads_everything(cap):
    assert len(P.sniff(offline=cap, stop_filter=lambda p: False)) == TOTAL


def test_stop_filter_on_the_first_packet(cap):
    assert len(P.sniff(offline=cap, stop_filter=lambda p: True)) == 1


def test_where_filters_in_rust(cap):
    got = P.sniff(offline=cap, where=[("TCP", "dport", "==", 80)])
    assert len(got) == TCP_N
    assert all(is_tcp(p) for p in got)


def test_where_agrees_with_a_python_loop(cap):
    """The bulk/slow-path invariant: a Rust-side query must select exactly what
    the equivalent Python predicate does."""
    where = [("UDP", "dport", "==", 53)]
    bulk = P.sniff(offline=cap, where=where)
    slow = [p for p in P.rdpcap(cap) if is_udp(p) and p["UDP"].dport == 53]
    assert [bytes(p) for p in bulk] == [bytes(p) for p in slow]
    assert len(bulk) == UDP_N


def test_where_agrees_with_packetlist_filter(cap):
    where = [("IP", "src", "==", "10.0.0.1")]
    a = P.sniff(offline=cap, where=where)
    b = P.rdpcap(cap).filter(where=where)
    assert [bytes(p) for p in a] == [bytes(p) for p in b]


def test_where_on_a_missing_layer_matches_nothing(cap):
    assert len(P.sniff(offline=cap, where=[("TCP", "dport", "==", 9999)])) == 0


def test_filters_and_together(cap):
    got = P.sniff(
        offline=cap,
        where=[("IP", "src", "==", "10.0.0.1")],
        lfilter=lambda p: p["TCP"].sport == 1002,
    )
    assert len(got) == 1
    assert got[0]["TCP"].sport == 1002


def test_bpf_filter(cap):
    """libpcap compiles a filter with no device and no privileges, so this must
    work on a file; without the feature it must say so."""
    if not P.capture_available():
        with pytest.raises(P.CaptureUnavailable) as exc:
            P.sniff(offline=cap, filter="tcp port 80")
        assert "live" in str(exc.value)
        return
    assert len(P.sniff(offline=cap, filter="tcp port 80")) == TCP_N
    assert len(P.sniff(offline=cap, filter="udp")) == UDP_N
    assert len(P.sniff(offline=cap, filter="arp")) == ARP_N
    assert len(P.sniff(offline=cap, filter="tcp port 9999")) == 0


def test_bpf_and_where_and_lfilter_together(cap):
    if not P.capture_available():
        pytest.skip("BPF needs the live feature")
    got = P.sniff(
        offline=cap,
        filter="tcp",
        where=[("TCP", "dport", "==", 80)],
        lfilter=lambda p: p["TCP"].sport % 2 == 0,
    )
    assert len(got) == 2
    assert all(p["TCP"].sport % 2 == 0 for p in got)


def test_a_malformed_bpf_filter_is_refused(cap):
    if not P.capture_available():
        pytest.skip("BPF needs the live feature")
    with pytest.raises(ValueError):
        P.sniff(offline=cap, filter="tcp port")


def test_the_result_is_a_normal_packet_list(cap):
    got = P.sniff(offline=cap, where=[("IP", "src", "==", "10.0.0.1")])
    assert isinstance(got, P.PacketList)
    assert len(got) == TCP_N
    assert isinstance(got[0], P.Packet)
    assert got[-1]["TCP"].sport == 1003
    assert len(list(got)) == TCP_N
    assert len(got[1:3]) == 2
    assert got.raw_at(0) == bytes(got[0])
    assert len(got.head(2)) == 2
    assert got.count_layer("TCP") == TCP_N
    assert got.field_column("TCP", "dport") == [80] * TCP_N
    cols = got.columns([("IP", "src"), ("TCP", "sport")])
    assert cols["IP.src"] == ["10.0.0.1"] * TCP_N
    assert cols["TCP.sport"] == [1000 + i for i in range(TCP_N)]
    assert len(got.filter(where=[("TCP", "sport", "==", 1001)])) == 1
    assert len(got.times()) == TCP_N


def test_result_keeps_positions_in_the_original_capture(cap):
    got = P.sniff(offline=cap, where=[("UDP", "dport", "==", 53)])
    assert got.columns([("Frame", "num")])["Frame.num"] == list(
        range(TCP_N, TCP_N + UDP_N)
    )


def test_timeout_zero_captures_nothing(cap):
    assert len(P.sniff(offline=cap, timeout=0)) == 0


def test_timeout_bounds_the_call(cap):
    """A deadline is checked before each packet, so a slow prn cannot run past
    it. Measured around the call, not after it."""
    started = time.monotonic()
    got = P.sniff(offline=cap, timeout=0.25, prn=lambda p: time.sleep(0.1))
    elapsed = time.monotonic() - started
    assert elapsed < 2.0
    assert 0 < len(got) < TOTAL


def test_a_generous_timeout_captures_everything(cap):
    assert len(P.sniff(offline=cap, timeout=30)) == TOTAL


def test_offline_accepts_a_packet_list(cap):
    read = P.rdpcap(cap)
    got = P.sniff(offline=read, count=3)
    assert [bytes(p) for p in got] == [bytes(read[i]) for i in range(3)]


def test_offline_accepts_a_path_object(cap, tmp_path):
    import pathlib

    assert len(P.sniff(offline=pathlib.Path(cap))) == TOTAL


def test_offline_refuses_a_list_of_packets(cap):
    with pytest.raises(NotImplementedError) as exc:
        P.sniff(offline=_corpus())
    assert "wrpcap" in str(exc.value)


def test_iface_and_snaplen_are_ignored_offline(cap):
    got = P.sniff(offline=cap, iface="eth99", promisc=False, snaplen=128)
    assert len(got) == TOTAL


def test_sniff_is_keyword_only(cap):
    with pytest.raises(TypeError):
        P.sniff(cap)


def test_async_sniffer_runs_and_joins(cap):
    s = P.AsyncSniffer(offline=cap, count=3)
    s.start()
    assert s.join() is s.results
    assert len(s.results) == 3
    assert not s.running


def test_async_sniffer_stop_is_honoured(cap):
    s = P.AsyncSniffer(offline=cap, prn=lambda p: time.sleep(0.05))
    s.start()
    time.sleep(0.02)
    got = s.stop()
    assert len(got) < TOTAL


def test_async_sniffer_reraises(cap):
    s = P.AsyncSniffer(offline=cap, lfilter=lambda p: 1 / 0)
    s.start()
    with pytest.raises(ZeroDivisionError):
        s.join()


def test_async_sniffer_refuses_to_start_twice(cap):
    s = P.AsyncSniffer(offline=cap, prn=lambda p: time.sleep(0.05))
    s.start()
    try:
        with pytest.raises(RuntimeError):
            s.start()
    finally:
        s.stop()
