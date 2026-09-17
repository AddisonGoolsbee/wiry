"""The columnar API: many fields, one pass, and the dataframe exports.

The load-bearing assertion here is that the bulk path agrees exactly with a
per-packet Python loop. If they ever disagree, the bulk path is wrong.
"""

import sys

import pytest

from wiry import (
    ARP, Dot1Q, Ether, ICMP, IP, IPv6, PacketList, Raw, TCP, UDP, rdpcap, wrpcap,
)
from wiry import columnar


def sample_packets():
    """A mixed capture, so every column has both hits and misses."""
    pkts = [
        Ether() / IP(dst="10.0.0.%d" % i, ttl=60 + i) / TCP(sport=1000 + i, dport=80 + i)
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
    path = str(tmp_path / "sample.pcap")
    wrpcap(path, sample_packets())
    return rdpcap(path)


@pytest.fixture
def empty(tmp_path):
    path = str(tmp_path / "empty.pcap")
    wrpcap(path, [])
    return rdpcap(path)


def loop_column(cap, layer, field):
    """The slow path, written the obvious way, as the oracle."""
    out = []
    for pkt in cap:
        out.append(getattr(pkt[layer], field) if pkt.haslayer(layer) else None)
    return out


def test_a_single_spec_matches_field_column(capture):
    got = capture.columns([("IP", "dst")])
    assert list(got) == ["IP.dst"]
    assert got["IP.dst"] == capture.field_column(IP, "dst")


def test_many_fields_come_back_in_spec_order(capture):
    got = capture.columns([("TCP", "dport"), ("IP", "dst"), ("Ether", "src")])
    assert list(got) == ["TCP.dport", "IP.dst", "Ether.src"]
    assert all(len(col) == len(capture) for col in got.values())


def test_columns_agree_exactly_with_a_per_packet_loop(capture):
    specs = [
        ("Ether", "src"), ("Ether", "dst"), ("IP", "src"), ("IP", "dst"),
        ("IP", "ttl"), ("IP", "proto"), ("IP", "flags"), ("TCP", "sport"),
        ("TCP", "dport"), ("TCP", "flags"), ("UDP", "sport"), ("ARP", "psrc"),
        ("IPv6", "src"),
        ("Dot1Q", "vlan"),
    ]
    bulk = capture.columns(specs)
    for layer, field in specs:
        assert bulk[f"{layer}.{field}"] == loop_column(capture, layer, field)


def test_a_missing_layer_yields_none(capture):
    got = capture.columns([("TCP", "dport"), ("UDP", "dport")])
    tcp, udp = got["TCP.dport"], got["UDP.dport"]
    assert all(t is None or u is None for t, u in zip(tcp, udp))
    assert None in tcp and None in udp
    assert tcp[:5] == [80, 81, 82, 83, 84]


def test_specs_accept_strings_classes_and_aliases(capture):
    got = capture.columns(["IP.dst", (TCP, "dport"), ("IP", "ttl", "hops")])
    assert list(got) == ["IP.dst", "TCP.dport", "hops"]
    assert got["hops"] == loop_column(capture, "IP", "ttl")


def test_frame_columns_carry_time_and_length(capture):
    got = capture.columns([("Frame", "time"), ("Frame", "len"), ("Frame", "num")])
    assert got["Frame.time"] == capture.times()
    assert got["Frame.len"] == [len(bytes(p)) for p in capture]
    assert got["Frame.num"] == list(range(len(capture)))


def test_unknown_layers_and_fields_are_rejected(capture):
    with pytest.raises(ValueError):
        capture.columns([("NOPE", "x")])
    with pytest.raises(KeyError):
        capture.columns([("IP", "nope")])
    with pytest.raises(KeyError):
        capture.columns([("Frame", "nope")])
    with pytest.raises(ValueError):
        capture.columns([("IP", "src"), ("IP", "src")])


def test_an_empty_capture_gives_empty_columns(empty):
    got = empty.columns([("IP", "src"), ("Frame", "time")])
    assert got == {"IP.src": [], "Frame.time": []}
    assert all(col == [] for col in empty.to_dict().values())
    assert empty.filter_indices("TCP") == []
    assert len(empty.filter("TCP")) == 0


def test_filter_by_layer_presence(capture):
    tcp = capture.filter(TCP)
    assert isinstance(tcp, PacketList)
    assert len(tcp) == capture.count_layer(TCP)
    assert all(p.haslayer(TCP) for p in tcp)


def test_filter_indices_point_back_into_the_capture(capture):
    idx = capture.filter_indices(UDP)
    assert idx == [i for i, p in enumerate(capture) if p.haslayer(UDP)]
    assert [bytes(capture[i]) for i in idx] == [bytes(p) for p in capture.filter(UDP)]


def test_filter_by_field_equality(capture):
    got = capture.filter(where=[("TCP", "dport", "==", 22)])
    assert [p[TCP].dport for p in got] == [22]


def test_filter_by_comparison(capture):
    got = capture.filter(where=[("IP", "ttl", ">", 62)])
    assert [p[IP].ttl for p in got] == [
        p[IP].ttl for p in capture if p.haslayer(IP) and p[IP].ttl > 62
    ]
    assert 0 < len(got) < len(capture)


def test_filter_by_address_string(capture):
    got = capture.filter(where=[("IP", "dst", "==", "10.0.0.3")])
    assert [p[IP].dst for p in got] == ["10.0.0.3"]


def test_conditions_combine_and_a_missing_layer_never_matches(capture):
    got = capture.columns(
        [("TCP", "dport")], where=[("TCP", "dport", ">=", 80), ("IP", "ttl", "<", 62)]
    )
    assert got["TCP.dport"] == [80, 81]
    # "!=" on a layer the packet lacks is false, not true.
    assert capture.filter_indices(where=[("TCP", "dport", "!=", 0)]) == (
        capture.filter_indices(TCP)
    )


def test_a_bare_condition_tuple_is_accepted(capture):
    assert capture.filter_indices(where=("TCP", "dport", "==", 22)) == (
        capture.filter_indices(where=[("TCP", "dport", 22)])
    )


def test_filtered_extraction_matches_the_slow_path(capture):
    got = capture.columns(
        [("Frame", "num"), ("TCP", "sport"), ("TCP", "dport")], layer="TCP"
    )
    want_idx, want_sport, want_dport = [], [], []
    for i, pkt in enumerate(capture):
        if pkt.haslayer(TCP):
            want_idx.append(i)
            want_sport.append(pkt[TCP].sport)
            want_dport.append(pkt[TCP].dport)
    assert got["Frame.num"] == want_idx
    assert got["TCP.sport"] == want_sport
    assert got["TCP.dport"] == want_dport


def test_a_filtered_view_keeps_its_original_positions(capture):
    tcp = capture.filter(TCP)
    assert tcp.columns([("Frame", "num")])["Frame.num"] == capture.filter_indices(TCP)
    assert tcp.filter(where=[("TCP", "dport", "==", 22)]).columns(
        [("Frame", "num")]
    )["Frame.num"] == capture.filter_indices(where=[("TCP", "dport", "==", 22)])


def test_head_takes_a_prefix_and_keeps_its_positions(capture):
    first = capture.head(3)
    assert [bytes(p) for p in first] == [bytes(p) for p in capture[:3]]
    assert first.columns([("Frame", "num")])["Frame.num"] == [0, 1, 2]
    assert len(capture.head(len(capture) + 10)) == len(capture)
    assert capture.filter(TCP).head(2).columns([("Frame", "num")])["Frame.num"] == (
        capture.filter_indices(TCP)[:2]
    )


def test_a_bad_operator_is_rejected(capture):
    with pytest.raises(ValueError):
        capture.filter(where=[("TCP", "dport", "~=", 1)])
    with pytest.raises(ValueError):
        capture.filter(where=[("IP", "dst", "==", "not-an-address")])


def test_to_dict_is_the_dependency_free_export(capture):
    got = capture.to_dict([("IP", "dst")])
    assert isinstance(got, dict)
    assert got["IP.dst"] == loop_column(capture, "IP", "dst")


def test_the_default_spec_covers_the_usual_columns(capture):
    got = capture.to_dict()
    assert list(got) == [
        "Frame.time", "Frame.len", "Ether.src", "Ether.dst", "IP.src", "IP.dst",
        "IP.proto", "TCP.sport", "TCP.dport", "UDP.sport", "UDP.dport",
    ]
    assert got["Frame.len"] == [len(bytes(p)) for p in capture]
    assert got["IP.dst"] == loop_column(capture, "IP", "dst")


@pytest.mark.parametrize(
    "func,module",
    [("to_arrow", "pyarrow"), ("to_polars", "polars"), ("to_pandas", "pandas")],
)
def test_exports_explain_themselves_when_the_library_is_missing(
    capture, monkeypatch, func, module
):
    # None in sys.modules makes the import fail as an absent package does.
    monkeypatch.setitem(sys.modules, module, None)
    with pytest.raises(ImportError) as exc:
        getattr(columnar, func)(capture)
    text = str(exc.value)
    assert module in text and "pip install" in text


def test_the_exports_are_reachable_from_the_package():
    import wiry

    for name in ("to_arrow", "to_polars", "to_pandas"):
        assert name in wiry.__all__
        assert getattr(wiry, name) is getattr(columnar, name)


def test_arrow_export(capture):
    pa = pytest.importorskip("pyarrow")
    table = columnar.to_arrow(capture, [("IP", "dst"), ("TCP", "dport")])
    assert isinstance(table, pa.Table)
    assert table.column_names == ["IP.dst", "TCP.dport"]
    assert table.num_rows == len(capture)
    assert table.column("IP.dst").to_pylist() == loop_column(capture, "IP", "dst")


def test_polars_export(capture):
    pl = pytest.importorskip("polars")
    df = columnar.to_polars(capture, [("IP", "dst"), ("TCP", "dport")])
    assert isinstance(df, pl.DataFrame)
    assert df.columns == ["IP.dst", "TCP.dport"]
    assert df["IP.dst"].to_list() == loop_column(capture, "IP", "dst")


def test_pandas_export(capture):
    pd = pytest.importorskip("pandas")
    df = columnar.to_pandas(capture, [("IP", "dst"), ("TCP", "dport")])
    assert isinstance(df, pd.DataFrame)
    assert list(df.columns) == ["IP.dst", "TCP.dport"]
    # pandas renders a missing value as NaN rather than None.
    want = loop_column(capture, "IP", "dst")
    assert df["IP.dst"].isna().tolist() == [v is None for v in want]
    assert df["IP.dst"].dropna().tolist() == [v for v in want if v is not None]


def test_filter_reads_a_condition_list_as_the_predicate(capture):
    """`columns()` takes specs first and `filter()` takes a layer, so the
    natural call raised "not a layer" instead of filtering."""
    positional = capture.filter([("TCP", "dport", "==", 22)])
    keyword = capture.filter(where=[("TCP", "dport", "==", 22)])
    assert [bytes(p) for p in positional] == [bytes(p) for p in keyword]

    assert capture.filter_indices([("TCP", "dport", "==", 22)]) == \
        capture.filter_indices(where=[("TCP", "dport", "==", 22)])

    assert len(capture.filter("TCP")) == len(capture.filter(layer="TCP"))
