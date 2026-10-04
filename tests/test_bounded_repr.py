"""Printing a large result at a prompt must not render all of it: one column
of a real capture has a repr of thirteen million characters."""

import pickle

import pytest

from wiry import IP, TCP, UDP, Ether, Raw, rdpcap, wrpcap
from wiry.columnar import Column, Columns


@pytest.fixture(scope="module")
def big(tmp_path_factory):
    path = str(tmp_path_factory.mktemp("big") / "big.pcap")
    pkts = [Ether() / IP(ttl=i % 256) / TCP(dport=i % 65536) / Raw(b"x" * 500)
            for i in range(3000)]
    pkts.append(Ether() / IP() / UDP())
    wrpcap(path, pkts)
    return rdpcap(path)


@pytest.mark.parametrize("make", [
    lambda c: c.columns(["IP.ttl", "TCP.dport", "Raw.load"]),
    lambda c: c.to_dict(["IP.ttl", "Raw.load"]),
    lambda c: c.field_column("Raw", "load"),
    lambda c: c.filter_indices([("TCP", "dport", ">", 0)]),
    lambda c: c.sessions(),
    lambda c: c.streams(),
])
def test_a_large_result_prints_its_shape_and_a_head(big, make):
    out = make(big)
    text = repr(out)
    assert len(text) < 1200
    assert str(len(out) if not isinstance(out, dict) else len(big)) in text


def test_the_bounded_containers_are_still_lists_and_dicts(big):
    cols = big.columns(["IP.ttl", "UDP.dport"])
    assert isinstance(cols, dict) and isinstance(cols["IP.ttl"], list)
    assert cols["IP.ttl"][:3] == [0, 1, 2]
    assert cols["UDP.dport"][-1] == 53
    assert pickle.loads(pickle.dumps(cols)) == cols
    assert Column([1, 2]) == [1, 2]
    assert repr(Columns()) == "<Columns: 0 rows x 0 columns>"


def test_ipython_prints_the_bounded_form(big):
    class P:
        def __init__(self):
            self.out = []

        def text(self, s):
            self.out.append(s)

    p = P()
    col = big.field_column("IP", "ttl")
    col._repr_pretty_(p, False)
    assert p.out == [repr(col)]
