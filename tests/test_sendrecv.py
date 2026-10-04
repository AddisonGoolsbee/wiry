"""sniff over socket objects, sndrcv, the flood functions and the rest of
sendrecv, all driven offline: no interface, no privileges, no network."""

import errno
import io
import logging
import socket
import subprocess
import sys
import time

import pytest

import wiry as P
from wiry import ARP, ICMP, IP, TCP, UDP, Ether, Raw
from wiry import sendrecv as SR
from wiry import supersocket as SS
from wiry.supersocket import IterSocket, ObjectPipe, OfflineSocket


def _corpus():
    pkts = [
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000 + i, dport=80)
        for i in range(4)
    ]
    pkts += [
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="10.0.0.3", dst="10.0.0.4") / UDP(sport=2000 + i, dport=53)
        for i in range(3)
    ]
    pkts += [Ether(src="00:11:22:33:44:55") / ARP() for _ in range(2)]
    return pkts


@pytest.fixture(scope="module")
def cap(tmp_path_factory):
    path = tmp_path_factory.mktemp("sr") / "corpus.pcap"
    P.wrpcap(str(path), _corpus())
    return str(path)


def is_udp(pkt):
    return "UDP" in pkt.layers()


def octets(pl):
    return [bytes(p) for p in pl]


# The socket path and the Rust path are two implementations of one machine;
# they must never disagree.
@pytest.mark.parametrize("kw", [
    {},
    {"count": 3},
    {"lfilter": is_udp},
    {"lfilter": is_udp, "count": 2},
    {"stop_filter": is_udp},
    {"lfilter": lambda p: "TCP" in p.layers(), "stop_filter": is_udp},
    {"store": 0},
])
def test_socket_path_agrees_with_the_capture_path(cap, kw):
    seen_rust, seen_sock = [], []
    rust = P.sniff(offline=cap, prn=lambda p: seen_rust.append(bytes(p)), **kw)
    sock = P.sniff(opened_socket=OfflineSocket(cap),
                   prn=lambda p: seen_sock.append(bytes(p)), **kw)
    assert octets(sock) == octets(rust)
    assert seen_sock == seen_rust


def test_socket_results_keep_their_timestamps(cap):
    rust = P.sniff(offline=cap)
    sock = P.sniff(opened_socket=OfflineSocket(cap))
    assert [p.time for p in sock] == [p.time for p in rust]


def test_sniffed_on_is_set_before_lfilter():
    class Once(SS.SuperSocket):
        nonblocking_socket = True

        def __init__(self):
            self.packet = Ether() / IP() / UDP()

        def recv(self, x=SS.MTU):
            packet, self.packet = self.packet, None
            return packet

        @staticmethod
        def select(sockets, remain=None):
            return [s for s in sockets if s.packet is not None]

    seen = []
    P.sniff(opened_socket={Once(): "untrusted"},
            lfilter=lambda p: seen.append(p.sniffed_on) or False, timeout=0.01)
    assert seen == ["untrusted"]


def test_a_list_of_sockets_is_labelled_by_position():
    a = OfflineSocket([Ether() / IP() / UDP()])
    b = OfflineSocket([Ether() / IP() / TCP()])
    seen = []
    P.sniff(opened_socket=[a, b], prn=lambda p: seen.append(p.sniffed_on))
    assert sorted(seen) == ["socket0", "socket1"]


def test_a_failing_socket_is_dropped_and_the_rest_still_read(caplog):
    ref = Ether() / IP() / UDP()

    class Breaks(ObjectPipe):
        def recv(self, x=SS.MTU):
            self.i = getattr(self, "i", 0) + 1
            if self.i == 11:
                self.close()
                raise OSError("Giant failure")
            pkt = super().recv(x)
            self.send(ref)
            return pkt

    pipe = Breaks()
    pipe.send(ref)
    with caplog.at_level(logging.WARNING, logger="wiry.runtime"):
        got = P.sniff(opened_socket=[pipe], timeout=3)
    assert len(got) == 10
    assert "Giant failure" in caplog.text


def test_timeout_bounds_a_socket_that_never_delivers():
    pipe = ObjectPipe()
    start = time.monotonic()
    got = P.sniff(opened_socket=pipe, timeout=0.2)
    assert len(got) == 0
    assert time.monotonic() - start < 2
    pipe.close()


def test_async_sniffer_over_a_socket_stops_on_request():
    pipe = ObjectPipe()
    s = P.AsyncSniffer(opened_socket=pipe)
    s.start()
    pipe.send(Ether() / IP() / UDP())
    time.sleep(0.2)
    got = s.stop()
    assert len(got) == 1
    pipe.close()


def test_where_is_refused_on_a_socket():
    with pytest.raises(NotImplementedError, match="where="):
        P.sniff(opened_socket=OfflineSocket([]), where=[("IP", "ttl", "==", 1)])


def test_filter_is_not_applied_to_an_opened_socket():
    got = P.sniff(opened_socket=OfflineSocket([Ether() / IP() / UDP()]),
                  filter="tcp")
    assert len(got) == 1


def test_a_reassembling_session_is_refused_on_a_socket():
    with pytest.raises(NotImplementedError, match="whole capture"):
        P.sniff(opened_socket=OfflineSocket([]), session=P.TCPSession)


def test_a_per_packet_session_runs_on_a_socket():
    class Count(P.DefaultSession):
        n = 0

        def process(self, pkt):
            Count.n += 1
            return pkt

    P.sniff(opened_socket=OfflineSocket(_corpus()), session=Count)
    assert Count.n == len(_corpus())


def test_started_callback_runs_once_before_reading(cap):
    calls = []
    P.sniff(opened_socket=OfflineSocket(cap), started_callback=lambda: calls.append(1),
            prn=lambda p: calls.append(2), count=1)
    P.sniff(offline=cap, started_callback=lambda: calls.append(3), count=1)
    assert calls == [1, 2, 3]


def test_started_callback_is_refused_on_an_interface():
    with pytest.raises(NotImplementedError, match="started_callback"):
        P.sniff(iface="eth0", started_callback=lambda: None)


def test_offline_takes_a_list_of_packets():
    got = P.sniff(offline=[IP() / UDP(), IP() / TCP()], lfilter=lambda p: "TCP" in p)
    assert len(got) == 1 and got[0].layers() == ["IP", "TCP"]


def test_offline_takes_a_template():
    got = P.sniff(offline=IP() / UDP(sport=(10000, 10003)))
    assert [p[UDP].sport for p in got] == [10000, 10001, 10002, 10003]


def test_offline_takes_bytes_as_raw():
    wire = bytes(IP() / UDP())
    got = P.sniff(offline=[wire, wire])
    assert [p.layers() for p in got] == [["Raw"], ["Raw"]]
    assert bytes(got[0]) == wire


def test_offline_takes_a_file_object(cap):
    with open(cap, "rb") as fh:
        got = P.sniff(offline=fh)
    assert octets(got) == octets(P.rdpcap(cap))


def test_offline_packets_of_different_links_are_kept_as_raw():
    with pytest.warns(RuntimeWarning, match="different link"):
        got = P.sniff(offline=[Ether() / IP(), IP() / UDP()])
    assert [p.layers() for p in got] == [["Raw"], ["Raw"]]
    assert bytes(got[1]) == bytes(IP() / UDP())


@pytest.mark.skipif(not P.capture_available(), reason="BPF needs libpcap")
def test_offline_packets_go_through_bpf():
    assert len(P.sniff(offline=IP() / UDP(sport=(10000, 10001)), filter="tcp")) == 0
    assert len(P.sniff(offline=IP() / UDP(sport=(10000, 10001)), filter="udp")) == 2


def test_iter_socket_flattens_pairs_and_ends_with_eof():
    s = IterSocket([(IP(dst="1.2.3.4"), IP(src="1.2.3.4")), b"xy"])
    got = [s.recv(), s.recv(), s.recv()]
    assert got[0].dst == "1.2.3.4" and got[1].src == "1.2.3.4"
    assert got[2].layers() == ["Raw"] and bytes(got[2]) == b"xy"
    with pytest.raises(EOFError):
        s.recv()


def test_iter_socket_redissects_from_octets():
    got = IterSocket(IP() / TCP()).recv()
    assert got._rust is not None
    assert bytes(got) == bytes(IP() / TCP())


def test_select_survives_eintr_and_raises_anything_else(monkeypatch):
    def interrupted(*_):
        raise OSError(errno.EINTR, "interrupted")

    monkeypatch.setattr(SS, "select", interrupted)
    assert SS.SuperSocket.select([]) == []

    def broken(*_):
        raise OSError(0)

    monkeypatch.setattr(SS, "select", broken)
    with pytest.raises(OSError):
        SS.SuperSocket.select([])


def test_simple_socket_reads_a_real_socket_as_packets():
    left, right = socket.socketpair()
    s = SS.SimpleSocket(left)
    right.send(b"hello")
    got = s.recv()
    assert got.layers() == ["Raw"] and bytes(got) == b"hello"
    s.send(Raw(b"back"))
    assert right.recv(10) == b"back"
    s.close()
    right.close()


def test_stream_socket_reports_the_peer_closing():
    left, right = socket.socketpair()
    s = SS.StreamSocketPeekless(left)
    right.close()
    with pytest.raises(EOFError):
        s.recv()
    s.close()
    assert SS.SSLStreamSocket is SS.StreamSocketPeekless


@pytest.mark.skipif(sys.platform.startswith("linux"), reason="Linux has AF_PACKET")
def test_l3_raw_socket_is_refused_off_linux():
    with pytest.raises(NotImplementedError, match="AF_PACKET"):
        SS.L3RawSocket()


def test_pcap_stream_reads_records_as_they_come(tmp_path):
    path = tmp_path / "s.pcap"
    pkts = [Ether() / IP() / UDP(sport=i) for i in range(3)]
    for i, p in enumerate(pkts):
        p.time = 10 + i
    P.wrpcap(str(path), pkts)
    stream = SS._PcapStream(io.BytesIO(path.read_bytes()))
    got = [stream.recv() for _ in range(3)]
    assert [bytes(p) for p in got] == [bytes(p) for p in pkts]
    assert [p.time for p in got] == [10, 11, 12]
    with pytest.raises(EOFError):
        stream.recv()


# Echo requests to three hosts; two answer, out of order, among noise. Built
# afresh per use: reading a field caches the built packet, and stacking a
# cached packet under Ether() does not bind the EtherType.
def reqs():
    return [IP(src="10.0.0.1", dst=f"10.0.0.{i}") / ICMP(id=7, seq=i)
            for i in (2, 3, 4)]


def reps():
    return [IP(src=f"10.0.0.{i}", dst="10.0.0.1") / ICMP(type=0, id=7, seq=i)
            for i in (3, 2)]


def noise():
    return [IP(src="9.9.9.9", dst="10.0.0.1") / UDP()]


def test_sndrcv_pairs_each_reply_with_its_request():
    sock = OfflineSocket(noise() + reps())
    ans, unans = P.sndrcv(sock, reqs(), threaded=False, verbose=0)
    assert [(s[IP].dst, r[IP].src) for s, r in ans] == [
        ("10.0.0.3", "10.0.0.3"), ("10.0.0.2", "10.0.0.2")]
    assert [p[IP].dst for p in unans] == ["10.0.0.4"]
    assert len(sock.sent) == 3


def test_a_frame_caught_at_layer_2_answers_a_datagram_sent_at_layer_3():
    sock = OfflineSocket([Ether() / r for r in reps()])
    ans, unans = P.sndrcv(sock, reqs(), threaded=False, verbose=0)
    assert len(ans) == 2 and len(unans) == 1


def test_sndrcv_threaded_agrees_with_unthreaded():
    ans, unans = P.sndrcv(OfflineSocket(reps()), reqs(), threaded=True,
                          timeout=0.2, verbose=0)
    assert len(ans) == 2 and len(unans) == 1


def test_a_reply_answers_one_request_unless_multi():
    twice = reps()[1:] * 2
    ans, _ = P.sndrcv(OfflineSocket(twice), reqs(), threaded=False, verbose=0)
    assert len(ans) == 1
    ans, unans = P.sndrcv(OfflineSocket(twice), reqs(), threaded=False,
                          verbose=0, multi=True)
    assert len(ans) == 2 and len(unans) == 2


def test_first_stops_at_the_first_answer():
    ans, _ = P.sndrcv(OfflineSocket(reps()), reqs(), threaded=False, verbose=0,
                      first=True)
    assert len(ans) == 1


def test_retry_resends_only_the_unanswered():
    sock = OfflineSocket(reps())
    ans, unans = P.sndrcv(sock, reqs(), threaded=False, verbose=0, retry=2)
    assert len(ans) == 2 and len(unans) == 1
    assert [p[IP].dst for p in sock.sent] == [
        "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.4", "10.0.0.4"]


def test_rcv_pks_receives_while_pks_sends():
    out, back = OfflineSocket(), OfflineSocket(reps())
    ans, _ = P.sndrcv(out, reqs(), rcv_pks=back, threaded=False, verbose=0)
    assert len(out.sent) == 3 and len(ans) == 2


def test_socket_sr_and_sr1():
    ans, unans = OfflineSocket(reps()).sr(reqs(), threaded=False, verbose=0)
    assert len(ans) == 2
    got = OfflineSocket(reps()).sr1(reqs(), verbose=0)
    assert got[IP].src == "10.0.0.3"


def test_sndrcv_reports_like_scapy(capsys):
    P.sndrcv(OfflineSocket(reps() + noise()), reqs(), threaded=False, verbose=1)
    out = capsys.readouterr().out
    assert "Begin emission" in out and "Finished sending 3 packets" in out
    assert "Received 3 packets, got 2 answers, remaining 1 packets" in out


def test_flood_sends_maxretries_passes_one_packet_at_a_time():
    sock = OfflineSocket(reps())
    ans, unans = P.sndrcvflood(sock, reqs(), maxretries=3, verbose=0)
    assert len(sock.sent) == 9
    assert len(ans) == 2 and [p[IP].dst for p in unans] == ["10.0.0.4"]


def test_flood_on_a_live_socket_sends_in_batches():
    class Bulk(OfflineSocket):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self.batches = []

        def send_many(self, pkts, passes=1, inter=0):
            self.batches.append((len(pkts), passes))
            return len(pkts) * passes

    sock = Bulk(reps())
    ans, _ = P.sndrcvflood(sock, reqs(), maxretries=100, verbose=0)
    assert sock.batches == [(3, 64), (3, 36)]
    assert sock.sent == [] and len(ans) == 2


def test_flood_until_timeout_stops():
    sock = OfflineSocket()
    start = time.monotonic()
    P.sndrcvflood(sock, reqs(), timeout=0.2, verbose=0)
    assert time.monotonic() - start < 3
    assert len(sock.sent) >= 3


def test_sr_func_is_sr1_as_in_scapy():
    assert P.sr_func is P.sr1


def test_bridge_forwards_and_transforms():
    a = OfflineSocket([Ether() / IP() / UDP(), Ether() / IP() / TCP()])
    b = OfflineSocket([Ether() / ARP()])
    swapped = Ether() / IP() / UDP(dport=9)
    got = P.bridge_and_sniff(
        a, b, xfrm12=lambda p: swapped if "UDP" in p else True,
        xfrm21=lambda p: False)
    assert len(got) == 3
    assert [bytes(p) for p in b.sent] == [bytes(swapped), bytes(Ether() / IP() / TCP())]
    assert a.sent == []


def test_tshark_prints_numbered_summaries(capsys):
    P.tshark(opened_socket=OfflineSocket([Ether() / IP() / UDP()] * 2))
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("Capturing on")
    assert out[1] == "    0\tEther / IP / UDP"
    assert out[-1] == "2 packets captured"


# tcpreplay 4.3's closing summary, laid out as `tcpreplay --help` documents it.
TCPREPLAY_OUT = b"""Actual: 1 packets (42 bytes) sent in 0.000221 seconds
Rated: 190045.2 Bps, 1.52 Mbps, 4524.88 pps
Flows: 1 flows, 4524.88 fps, 1 flow packets, 0 non-flow
Statistics for network device: lo
	Successful packets:        1
	Failed packets:            0
	Truncated packets:         0
	Retried packets (ENOBUFS): 0
	Retried packets (EAGAIN):  0
"""


def test_tcpreplay_summary_parses():
    got = SR._parse_tcpreplay_result(TCPREPLAY_OUT, b"warn\n", ["tcpreplay", "x"])
    assert got["packets"] == 1 and got["bytes"] == 42 and got["time"] == 0.000221
    assert got["mbps"] == 1.52 and got["pps"] == 4524.88
    assert got["flows"] == 1 and got["non_flow"] == 0
    assert got["successful"] == 1 and got["retried_eagain"] == 0
    assert got["command"] == "tcpreplay x"


def test_sendpfast_without_tcpreplay_logs_and_returns_none(caplog, monkeypatch):
    monkeypatch.setattr(P.conf.prog, "tcpreplay", "/nonexistent/tcpreplay")
    monkeypatch.setattr(P.conf, "iface", "lo0")
    with caplog.at_level(logging.ERROR, logger="wiry.runtime"):
        assert P.sendpfast(Ether() / IP()) is None
    assert "is it installed?" in caplog.text


@pytest.mark.parametrize("kw, flag", [
    ({}, "--topspeed"),
    ({"pps": 10}, "--pps=10.000000"),
    ({"mbps": 2}, "--mbps=2.000000"),
    ({"realtime": 2}, "--multiplier=2.000000"),
])
def test_sendpfast_builds_tcpreplays_command(monkeypatch, kw, flag):
    calls = []

    class Done:
        def __init__(self, argv, **_):
            calls.append(argv)

        def communicate(self):
            return TCPREPLAY_OUT, b""

    monkeypatch.setattr(subprocess, "Popen", Done)
    got = P.sendpfast(Ether() / IP(), iface="eth9", count=3,
                      parse_results=True, **kw)
    argv = calls[0]
    assert argv[1] == "--intf1=eth9" and argv[2] == flag
    assert "--loop=3" in argv and argv[-1].endswith(".pcap")
    assert got["packets"] == 1


def test_sendpfast_refuses_loop_with_count(monkeypatch):
    monkeypatch.setattr(P.conf, "iface", "lo0")
    with pytest.raises(ValueError, match="loop and count"):
        P.sendpfast(Ether(), count=2, loop=1)


def test_debug_keeps_nothing_by_default():
    P.sndrcv(OfflineSocket(reps()), reqs(), threaded=False, verbose=0)
    assert isinstance(SR.debug.recv, list)


def test_tcpreplay_summary_parses_from_text_too():
    got = SR._parse_tcpreplay_result(TCPREPLAY_OUT.decode(), "a\nb\n", ["t"])
    assert got["packets"] == 1 and got["warnings"] == ["a"]
