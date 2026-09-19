"""``session=``: scapy's per-packet contract, and wiry's whole-capture one.

A session is one of two things here and says which. scapy's shape — one packet
in, one packet or ``None`` out — runs per packet between the capture filter and
the callbacks, on an interface as well as over a file: the packet already
exists by then, so nothing Python goes near the dissection loop. Reassembly is
the other shape, a single pass in Rust over a whole capture, and it says so
with ``needs_capture``.
"""

import pytest

from wiry import (
    DefaultSession,
    Ether,
    IP,
    IPSession,
    TCP,
    TCPSession,
    UDP,
    sniff,
    wrpcap,
)


@pytest.fixture
def capture(tmp_path):
    path = tmp_path / "s.pcap"
    wrpcap(str(path), [
        Ether() / IP(dst="10.0.0.1") / TCP(dport=80),
        Ether() / IP(dst="10.0.0.2") / UDP(dport=53),
        Ether() / IP(dst="10.0.0.3") / TCP(dport=443),
    ])
    return str(path)


class DropUDP(DefaultSession):
    """A session in scapy's own shape: it returns the packet, or nothing."""

    def process(self, pkt):
        return None if "UDP" in pkt.layers() else pkt


class Rewrite(DefaultSession):
    def process(self, pkt):
        return Ether() / IP(dst="192.0.2.1") / TCP(dport=9)


def test_the_default_session_passes_every_packet_through(capture):
    plain = [bytes(p) for p in sniff(offline=capture)]
    assert [bytes(p) for p in sniff(offline=capture,
                                    session=DefaultSession)] == plain


def test_a_session_that_drops_a_packet_drops_it_everywhere(capture):
    seen = []
    out = sniff(offline=capture, session=DropUDP, prn=seen.append)
    assert len(out) == 2
    assert [p["IP"].dst for p in out] == ["10.0.0.1", "10.0.0.3"]
    assert len(seen) == 2


def test_count_counts_what_the_session_let_through(capture):
    out = sniff(offline=capture, session=DropUDP, count=2)
    assert [p["IP"].dst for p in out] == ["10.0.0.1", "10.0.0.3"]


def test_lfilter_sees_what_the_session_produced(capture):
    out = sniff(offline=capture, session=DropUDP,
                lfilter=lambda p: p["TCP"].dport == 443)
    assert len(out) == 1 and out[0]["TCP"].dport == 443


def test_the_capture_filter_runs_before_the_session(capture):
    seen = []
    sniff(offline=capture, session=DefaultSession, prn=seen.append,
          where=("TCP", "dport", 80))
    assert len(seen) == 1


def test_a_session_may_be_a_class_or_an_instance(capture):
    assert len(sniff(offline=capture, session=DropUDP())) == 2
    assert len(sniff(offline=capture, session=DropUDP)) == 2


def test_a_supersession_runs_after_the_session_it_is_given_to(capture):
    assert len(sniff(offline=capture,
                     session=DefaultSession(supersession=DropUDP))) == 2


def test_a_session_that_replaces_a_packet_is_refused_rather_than_ignored(capture):
    # A PacketList is a view over the capture buffer, so a synthesised packet
    # cannot go into one. Saying so beats quietly returning the original.
    with pytest.raises(NotImplementedError, match="replaced"):
        sniff(offline=capture, session=Rewrite)


def test_a_replacing_session_works_where_nothing_is_stored(capture):
    seen = []
    out = sniff(offline=capture, session=Rewrite, store=0, prn=seen.append)
    assert len(out) == 0
    assert [p["IP"].dst for p in seen] == ["192.0.2.1"] * 3


def test_an_object_that_is_not_a_session_is_refused(capture):
    with pytest.raises(TypeError, match="process"):
        sniff(offline=capture, session=object())


def test_a_session_that_claims_a_bulk_path_must_have_one(capture):
    class Liar(DefaultSession):
        needs_capture = True

    with pytest.raises(TypeError, match="bulk_process"):
        sniff(offline=capture, session=Liar)


def test_the_reassembling_sessions_are_whole_capture_and_say_so(capture):
    for cls in (TCPSession, IPSession):
        assert cls().needs_capture is True
        with pytest.raises(NotImplementedError, match="per-packet"):
            cls().process(object())


def test_a_reassembling_session_still_runs_over_a_file(capture):
    assert len(sniff(offline=capture, session=IPSession)) == 3
    assert len(sniff(offline=capture, session=TCPSession)) == 3


def test_tcpsession_without_the_message_step_is_a_per_packet_pass_through(capture):
    s = TCPSession(app=False)
    assert s.needs_capture is False
    assert [bytes(p) for p in sniff(offline=capture, session=s)] == \
        [bytes(p) for p in sniff(offline=capture)]


def test_a_whole_capture_session_is_refused_on_an_interface():
    with pytest.raises(NotImplementedError, match="offline"):
        sniff(iface="lo0", session=TCPSession, count=1)
