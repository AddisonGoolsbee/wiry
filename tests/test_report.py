"""The reporting surface: sprintf, show2, and PacketList aggregation.

The load-bearing assertion, as in `test_columnar.py`, is that the bulk paths
agree exactly with a per-packet Python loop.
"""

import gc
import threading

import pytest

from wiry import (
    ARP, Dot1Q, Ether, ICMP, IP, IPv6, Raw, TCP, UDP, rdpcap, wrpcap,
)
from wiry import report


def sample_packets():
    pkts = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.%d" % i, ttl=60 + i)
        / TCP(sport=1000 + i, dport=80 + i)
        for i in range(4)
    ]
    pkts += [
        Ether() / IP(src="10.1.1.1", dst="10.1.1.2") / UDP(sport=9, dport=9) / Raw(load=b"hi"),
        Ether() / IP(src="10.1.1.1", dst="10.1.1.2") / UDP(sport=9, dport=9),
        Ether() / IP(src="10.2.2.1", dst="10.2.2.2") / ICMP(),
        Ether() / Dot1Q(vlan=42) / IP(src="10.3.3.1", dst="10.3.3.2") / TCP(dport=22),
        Ether() / ARP(psrc="10.4.4.1", pdst="10.4.4.2"),
        Ether(type=0x9000),
        Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=7, dport=7),
        Ether() / IPv6(src="2001:db8::1", dst="2001:db8::3"),
    ]
    return pkts


@pytest.fixture
def capture(tmp_path):
    path = str(tmp_path / "sample.pcap")
    wrpcap(path, sample_packets())
    return rdpcap(path)


@pytest.fixture
def pkt():
    return Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=1234, dport=80)


# --- sprintf -----------------------------------------------------------------


def test_the_canonical_form(pkt):
    assert pkt.sprintf("%IP.src% > %IP.dst%") == "1.2.3.4 > 5.6.7.8"


def test_literal_text_survives(pkt):
    assert pkt.sprintf("src=%IP.src%, dst=%IP.dst%!") == "src=1.2.3.4, dst=5.6.7.8!"
    assert pkt.sprintf("100%% done") == "100% done"
    assert pkt.sprintf("no directives here") == "no directives here"


def test_a_bare_field_searches_the_layers(pkt):
    assert pkt.sprintf("%ttl%") == "64"
    assert pkt.sprintf("%dport%") == "80"


def test_an_occurrence_number_picks_the_layer():
    p = Ether() / IP(ttl=9) / IP(ttl=4) / UDP()
    assert p.sprintf("%IP.ttl% %IP:1.ttl% %IP:2.ttl%") == "9 9 4"


def test_the_colon_spelling_names_a_field(pkt):
    assert pkt.sprintf("%IP:src%") == pkt.sprintf("%IP.src%")


def test_format_modifiers(pkt):
    assert pkt.sprintf("%02x,IP.ttl%") == "40"
    assert pkt.sprintf("%#05x,TCP.sport%") == "0x4d2"
    assert pkt.sprintf("%-6s,IP.ttl%|") == "64    |"
    assert pkt.sprintf("%05d,TCP.dport%") == "00080"


def test_the_raw_flag_is_accepted_after_a_modifier(pkt):
    assert pkt.sprintf("%#05xr,TCP.sport%") == pkt.sprintf("%#05x,TCP.sport%")
    assert pkt.sprintf("%r,TCP.flags%") == "S"


def test_a_flags_field_formats_as_its_name_and_its_bits(pkt):
    assert pkt.sprintf("%TCP.flags%") == "S"
    assert pkt.sprintf("%d,TCP.flags%") == "2"


def test_a_missing_layer_or_field_is_two_question_marks(pkt):
    assert pkt.sprintf("%UDP.sport%") == "??"
    assert pkt.sprintf("%IP.nosuchfield%") == "??"
    assert pkt.sprintf("%nosuchfield%") == "??"
    assert pkt.sprintf("%NoSuchLayer.x%") == "??"
    # A modifier over a missing value is dropped rather than raising.
    assert pkt.sprintf("%05d,UDP.sport%") == "??"


def test_conditional_blocks(pkt):
    assert pkt.sprintf("{TCP:tcp}{UDP:udp}") == "tcp"
    assert pkt.sprintf("{IP:{TCP:flags=%TCP.flags%}{UDP:p=%UDP.sport%} %IP.src%}") == (
        "flags=S 1.2.3.4"
    )
    assert (Ether() / IP() / UDP()).sprintf("{TCP:tcp}{UDP:udp}") == "udp"


def test_a_conditional_block_on_a_field(pkt):
    assert pkt.sprintf("{IP.src:yes}{IP.nosuch:no}") == "yes"
    assert pkt.sprintf("{UDP.sport:no}") == ""


def test_a_conditional_field_absent_from_this_header_is_absent():
    """ICMP's `id` exists only for the types RFC 792 gives it one."""
    echo = Ether() / IP() / ICMP(type=8)
    unreach = Ether() / IP() / ICMP(type=3)
    assert echo.sprintf("{ICMP.id:has id}") == "has id"
    assert unreach.sprintf("{ICMP.id:has id}") == ""


def test_unbalanced_punctuation_is_literal(pkt):
    assert pkt.sprintf("50% off") == "50% off"
    assert pkt.sprintf("{not a block") == "{not a block"
    assert pkt.sprintf("a {IP unterminated") == "a {IP unterminated"


@pytest.mark.parametrize(
    "fmt",
    ["%", "%%%", "{", "}", "{}", "{:}", "%,%", "%,IP.src%", "%IP.%", "%.%",
     "%IP:0.ttl%", "%IP:x.ttl%", "{IP:", "{IP:}", "}{IP:x}{", "%{IP:x}%"],
)
def test_a_malformed_format_renders_rather_than_raising(pkt, fmt):
    assert isinstance(pkt.sprintf(fmt), str)


def test_the_time_directive(pkt):
    pkt.time = 0.5
    out = pkt.sprintf("%.time%")
    assert out.count(":") == 2 and out.endswith("500000")


def test_an_impossible_modifier_names_itself(pkt):
    with pytest.raises(ValueError, match="cannot format"):
        pkt.sprintf("%05d,IP.src%")


# --- bulk sprintf ------------------------------------------------------------


FORMATS = [
    "%IP.src% -> %IP.dst%",
    "{TCP:tcp %TCP.sport%}{UDP:udp %UDP.sport%}{ARP:arp}",
    "%IP.src%|%02x,IP.ttl%|{IP:{TCP:%TCP.flags%}}",
    "%d,TCP.flags% %TCP.flags%",
    "%.time% %IP.src%",
    "no directives",
]


@pytest.mark.parametrize("fmt", FORMATS)
def test_the_bulk_path_agrees_with_the_per_packet_path(capture, fmt):
    assert capture.sprintf(fmt) == [p.sprintf(fmt) for p in capture]


def test_a_format_needing_the_layer_chain_falls_back(capture):
    """A bare field and a second occurrence both depend on the packet's own
    chain, which a column does not carry."""
    for fmt in ("%ttl%", "%IP:2.ttl%"):
        assert capture.sprintf(fmt) == [p.sprintf(fmt) for p in capture]


def test_a_name_the_engine_does_not_know_falls_back(capture):
    """A column for an unknown name raises where a packet renders `??`."""
    for fmt in ("%NoSuchLayer.x%", "%IP.nosuchfield%", "{NoSuchLayer:x}"):
        assert capture.sprintf(fmt) == [p.sprintf(fmt) for p in capture]


def test_bulk_sprintf_crosses_once(capture, monkeypatch):
    calls = []
    original = type(capture._list).columns

    def counted(self, *a, **kw):
        calls.append(1)
        return original(self, *a, **kw)

    monkeypatch.setattr(type(capture._list), "columns", counted, raising=False)
    capture.sprintf("%IP.src% {TCP:%TCP.dport%}")
    assert len(calls) == 1


# --- show2 -------------------------------------------------------------------


def test_show2_fills_in_what_building_computes():
    p = IP(src="1.2.3.4", dst="5.6.7.8") / TCP()
    built = p.show2_str()
    assert "len        = 40" in built
    assert "chksum     = 0" not in built


def test_show2_of_a_dissected_packet_is_its_show(capture):
    for p in capture:
        assert p.show2_str() == p.show_str()


def test_show2_prints(capsys):
    (IP() / TCP()).show2()
    assert "###[ IP ]###" in capsys.readouterr().out


def test_show2_of_an_empty_packet_is_refused():
    from wiry import Packet

    with pytest.raises(ValueError):
        Packet().show2_str()


# --- sessions ----------------------------------------------------------------


def test_the_default_key_is_the_address_tuple(capture):
    keys = list(capture.sessions())
    assert "TCP 10.0.0.1:1000 > 10.0.0.0:80" in keys
    assert "UDP 10.1.1.1:9 > 10.1.1.2:9" in keys
    assert "ICMP 10.2.2.1 > 10.2.2.2 type=8 code=0 id=0x0" in keys
    assert "ARP 10.4.4.1 > 10.4.4.2" in keys
    assert "Ethernet type=9000" in keys
    assert "UDP 2001:db8::1:7 > 2001:db8::2:7" in keys
    assert "IPv6 2001:db8::1 > 2001:db8::3 nh=59" in keys


def test_every_packet_lands_in_exactly_one_session(capture):
    s = capture.sessions()
    assert sum(len(v) for v in s.values()) == len(capture)
    seen = [bytes(p) for v in s.values() for p in v]
    assert sorted(seen) == sorted(bytes(p) for p in capture)


def test_a_session_view_holds_the_right_packets(capture):
    s = capture.sessions()
    flow = s["UDP 10.1.1.1:9 > 10.1.1.2:9"]
    assert len(flow) == 2
    assert all(p[UDP].sport == 9 for p in flow)


def test_a_session_view_is_a_packet_list_sharing_the_buffer(capture):
    from wiry import PacketList

    flow = capture.sessions()["TCP 10.0.0.1:1000 > 10.0.0.0:80"]
    assert isinstance(flow, PacketList)
    assert flow.columns([("TCP", "dport")])["TCP.dport"] == [80]


def test_sessions_is_a_mapping(capture):
    s = capture.sessions()
    assert len(s) == len(list(s))
    assert "no such flow" not in s
    assert s.get("no such flow") is None
    with pytest.raises(KeyError):
        s["no such flow"]
    assert repr(s).startswith("<Sessions:")


def test_the_same_view_comes_back_twice(capture):
    s = capture.sessions()
    key = next(iter(s))
    assert s[key] is s[key]


def test_a_custom_extractor_groups_by_whatever_it_returns(capture):
    s = capture.sessions(lambda p: p.layers()[-1])
    assert set(s) == {p.layers()[-1] for p in capture}
    assert sum(len(v) for v in s.values()) == len(capture)
    assert all(p.layers()[-1] == "TCP" for p in s["TCP"])


def test_the_default_paths_never_touch_python_per_packet(capture, monkeypatch):
    def refuse(self, i):
        raise AssertionError("a default path materialised a packet")

    monkeypatch.setattr(type(capture._list), "__getitem__", refuse, raising=False)
    assert len(capture.sessions()) > 1
    assert capture.conversations().startswith("digraph")
    assert len(capture.sprintf("%IP.src%")) == len(capture)
    assert len(list(report.summary_lines(capture))) == len(capture)


def test_a_callback_path_crosses_per_packet_because_that_is_its_contract(capture):
    """make_table and plot take a per-packet fn; only the default paths are
    columnar."""
    seen = []
    capture.make_table(lambda p: (1, 2, seen.append(p)))
    assert len(seen) == len(capture)


def test_sessions_of_an_empty_capture(tmp_path):
    path = str(tmp_path / "empty.pcap")
    wrpcap(path, [])
    assert len(rdpcap(path).sessions()) == 0


# --- summary -----------------------------------------------------------------


def test_summary_prints_one_line_per_packet(capture, capsys):
    capture.summary()
    lines = capsys.readouterr().out.splitlines()
    assert lines == [p.summary() for p in capture]


def test_nsummary_numbers_the_lines(capture, capsys):
    capture.nsummary()
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith("0000 ")
    assert lines[0][5:] == capture[0].summary()


def test_show_is_nsummary(capture, capsys):
    capture.show()
    shown = capsys.readouterr().out
    capture.nsummary()
    assert shown == capsys.readouterr().out


def test_a_prn_replaces_the_line(capture, capsys):
    capture.summary(prn=lambda p: p.sprintf("%IP.src%"))
    lines = capsys.readouterr().out.splitlines()
    assert lines == [p.sprintf("%IP.src%") for p in capture]


def test_an_lfilter_drops_packets_but_keeps_their_numbers(capture, capsys):
    capture.nsummary(lfilter=lambda p: "TCP" in p.layers())
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == capture.count_layer(TCP)
    kept = [i for i, p in enumerate(capture) if "TCP" in p.layers()]
    assert [int(l.split()[0]) for l in lines] == kept


def test_the_bulk_summary_agrees_with_the_per_packet_one(capture):
    assert list(report.summary_lines(capture)) == [p.summary() for p in capture]


# --- conversations and make_table --------------------------------------------


def test_conversations_counts_the_edges(capture):
    dot = capture.conversations()
    assert dot.startswith("digraph")
    assert '"10.1.1.1" -> "10.1.1.2" [label="2"];' in dot
    assert "10.4.4.1" not in dot


def test_conversations_takes_a_custom_extractor(capture):
    dot = capture.conversations(
        lambda p: (p[Ether].src, p[Ether].dst) if "Ether" in p.layers() else None
    )
    assert "ff:ff:ff:ff:ff:ff" in dot


def test_conversations_without_graphviz_says_so(capture, monkeypatch):
    import shutil

    monkeypatch.setattr(shutil, "which", lambda *a, **kw: None)
    with pytest.raises(RuntimeError, match="not on PATH"):
        capture.conversations(target="/dev/null")


def test_make_table_lays_out_rows_and_columns(capture):
    table = capture.make_table(
        lambda p: (p.layers()[-1], len(p.layers()), "x"), lfilter=lambda p: True
    )
    lines = table.splitlines()
    assert lines[0].split() == sorted({p.layers()[-1] for p in capture})
    assert all(line.split()[0].isdigit() for line in lines[1:])


def test_make_table_takes_the_last_cell_for_a_repeated_coordinate(capture):
    table = capture.make_table(lambda p: ("c", "r", p.layers()[-1]))
    assert table.splitlines()[1].split() == ["r", capture[len(capture) - 1].layers()[-1]]


def test_plot_without_matplotlib_says_how_to_install_it(capture, monkeypatch):
    import importlib

    def refuse(name):
        raise ImportError(name)

    monkeypatch.setattr(importlib, "import_module", refuse)
    with pytest.raises(ImportError, match="matplotlib"):
        capture.plot(lambda p: len(p))


# --- hostile formats and lazy views ------------------------------------------


def _within(seconds, fn, *args):
    """A timing assertion after the call it measures cannot catch a hang."""
    out = []
    t = threading.Thread(target=lambda: out.append(fn(*args)), daemon=True)
    t.start()
    t.join(seconds)
    assert not t.is_alive(), f"{fn.__name__} did not finish in {seconds}s"
    return out[0]


@pytest.mark.parametrize("fmt", [
    "{a:" * 40,          # unclosed blocks: one re-parse each is exponential
    "{a:" * 40 + "}",
    "{" * 1_000_000,     # no head at all: one scan each is quadratic
    "%" * 200_000,
    "%a" * 100_000,
    "x" * 1_000_000,
    "{IP:" * 300 + "x" + "}" * 300,
    "a\x00b%IP.src%",
    "你好 %IP.src% \U0001f600",
    "%ÍP.src%",
    "{IP:%IP.src%",
    "%IP.src",
    "%", "{", "}", "",
])
def test_a_hostile_format_is_bounded(pkt, fmt):
    assert isinstance(_within(5.0, pkt.sprintf, fmt), str)


def test_nesting_past_the_cap_is_literal_text_not_a_deeper_stack(pkt):
    from wiry.report import _MAX_NEST

    inner = pkt.sprintf("{IP:" * _MAX_NEST + "x" + "}" * _MAX_NEST)
    assert inner == "x"
    past = pkt.sprintf("{IP:" * (_MAX_NEST + 1) + "x" + "}" * (_MAX_NEST + 1))
    assert past == "{IP:x}"


def test_an_unclosed_block_is_literal_and_its_body_still_renders(pkt):
    assert pkt.sprintf("{IP:%IP.src%") == "{IP:1.2.3.4"
    assert pkt.sprintf("{a:x{IP:y}z") == "{a:xyz"
    assert pkt.sprintf("{a:{IP:x}") == "{a:x"


# RFC 1035 §4.1: header with one question, QNAME example.com, QTYPE A, QCLASS IN.
DNS_QUERY = (
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    b"\x07example\x03com\x00\x00\x01\x00\x01"
)


@pytest.fixture
def dns_capture(tmp_path):
    path = str(tmp_path / "dns.pcap")
    wrpcap(path, [
        Ether() / IP(src="10.5.5.1", dst="10.5.5.2") / UDP(sport=53, dport=53)
        / Raw(load=DNS_QUERY),
        Ether() / IP(src="10.5.5.1", dst="10.5.5.2") / TCP(sport=1, dport=2),
    ])
    return rdpcap(path)


@pytest.mark.parametrize("fmt", [
    "%DNS.qd%", "%DNS.an%", "{DNS:%DNS.qd%}", "{DNS.qd:has}", "%DNS.id% %DNS.qd%",
])
def test_a_parser_backed_accessor_falls_back_rather_than_raising(dns_capture, fmt):
    """`layer_fields` lists qd/an/ns/ar; no column can carry them (E8)."""
    assert dns_capture.sprintf(fmt) == [p.sprintf(fmt) for p in dns_capture]


AWKWARD = [
    "{TCP:{IP:%IP.src%:%TCP.sport%}}",
    "{IP:a}{IP:b}{IP:c}",
    "%IP:2.src%",
    "%s,TCP.flags% %#x,TCP.flags% %02d,TCP.flags% %d,TCP.flags%",
    "%TCP.options%|%IP.options%",
    "{TCP.options:%TCP.options%}",
    "%Raw.load%{Raw:!}",
    "{IP.frag:F}%IP.len%",
    "%Frame.time%%Frame.len%",
    "{nosuchlayer:x}%nosuchlayer.f%%IP.nosuchfield%",
    "{IP:%IP.src%}{IPv6:%IPv6.src%}",
    "%.time%|%IP.src%|{ICMP:%ICMP.id%}",
    "%c,IP.ttl%%o,IP.ttl%%5.2f,IP.ttl%%-6s,IP.src%|",
    "plain literal only", "%%", "{TCP:}",
]


@pytest.mark.parametrize("fmt", AWKWARD)
def test_the_awkward_formats_agree_too(capture, fmt):
    assert capture.sprintf(fmt) == [p.sprintf(fmt) for p in capture]


def test_show2_of_a_zero_length_record_answers_as_show_does(tmp_path):
    path = str(tmp_path / "zero.pcap")
    wrpcap(path, [Raw(load=b"")])
    pkt = rdpcap(path)[0]
    assert pkt.layers() == []
    assert pkt.show2_str() == pkt.show_str() == ""


def test_a_flow_view_outlives_the_capture_it_came_from(tmp_path):
    path = str(tmp_path / "gc.pcap")
    wrpcap(path, sample_packets())

    def mint():
        cap = rdpcap(path)
        s = cap.sessions()
        return s[next(iter(s))], cap.sessions(lambda p: "one")["one"]

    default, extracted = mint()
    gc.collect()
    assert len(default) and bytes(default[0])
    assert len(extracted) == len(sample_packets())


def test_a_flow_per_packet_keys_every_packet_separately(tmp_path):
    path = str(tmp_path / "many.pcap")
    pkts = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=i, dport=i)
        for i in range(1, 2001)
    ]
    wrpcap(path, pkts)
    cap = rdpcap(path)
    s = _within(20.0, cap.sessions)
    assert len(s) == len(pkts)
    assert sum(len(s[k]) for k in s) == len(pkts)
    assert [p[TCP].sport for p in s[next(iter(s))]] == [1]
