"""IP fragmentation and reassembly, RFC 791 §3.2 and RFC 8200 §4.5."""

import os
import struct
import tempfile

import pytest

from helpers import checksum
from wiry import (
    IP,
    IPv6,
    UDP,
    Ether,
    PacketList,
    Raw,
    defrag,
    defragment,
    defragment6,
    fragment,
    fragment6,
    rdpcap,
    wrpcap,
)

BODY = bytes(range(256)) * 3


def datagram(n=300, **kw):
    return Ether() / IP(dst="10.0.0.2", **kw) / UDP() / Raw(load=BODY[:n])


def v6_datagram(n=300):
    return Ether() / IPv6(dst="2001:db8::2") / UDP() / Raw(load=BODY[:n])


def ip_of(pkt):
    return pkt[IP]


def test_a_short_datagram_is_not_split():
    p = datagram(40)
    assert [bytes(f) for f in fragment(p, 1480)] == [bytes(p)]


def test_more_fragments_is_set_on_all_but_the_last():
    frags = fragment(datagram(300), 64)
    assert len(frags) == 5
    assert [int(ip_of(f).flags) & 1 for f in frags] == [1, 1, 1, 1, 0]


def test_offsets_count_eight_octet_units():
    frags = fragment(datagram(300), 64)
    assert [ip_of(f).frag for f in frags] == [0, 8, 16, 24, 32]
    assert [ip_of(f).len for f in frags] == [84, 84, 84, 84, 72]


def test_every_fragment_carries_a_valid_header_checksum():
    for f in fragment(datagram(300), 64):
        raw = bytes(f)[14:]
        assert checksum(raw[: ip_of(f).ihl * 4]) == 0


def test_dont_fragment_is_honoured():
    p = datagram(300, flags="DF")
    assert [bytes(f) for f in fragment(p, 64)] == [bytes(p)]


def test_only_copied_options_reach_the_later_fragments():
    # RFC 791 §3.1: Loose Source Route (131) is copied, Record Route (7) is not.
    opts = bytes([0x83, 0x07, 0x04, 10, 0, 0, 9, 0x07, 0x07, 0x04, 0, 0, 0, 0, 0, 0])
    frags = fragment(datagram(300, options=opts), 64)
    assert ip_of(frags[0]).raw_options() == opts
    for f in frags[1:]:
        assert f[IP].raw_options() == bytes([0x83, 0x07, 0x04, 10, 0, 0, 9, 0])


@pytest.mark.parametrize("size", [1, 8, 9, 16, 24, 100, 1480])
@pytest.mark.parametrize("length", [9, 64, 300, 700])
@pytest.mark.parametrize("opts", [b"", bytes([0x83, 0x07, 0x04, 10, 0, 0, 9, 0])])
def test_defragment_undoes_fragment(size, length, opts):
    p = datagram(length, options=opts)
    back = defragment(fragment(p, size))
    assert len(back) == 1
    assert bytes(back[0]) == bytes(p)


def test_a_size_smaller_than_the_header_still_splits_by_one_unit():
    frags = fragment(datagram(20), 4)
    assert len(frags) == 4
    assert bytes(defragment(frags)[0]) == bytes(datagram(20))


def test_fragments_reassemble_out_of_order():
    p = datagram(300)
    frags = fragment(p, 64)[::-1]
    assert bytes(defragment(frags)[0]) == bytes(p)


def test_an_overlapping_fragment_never_rewrites_what_arrived_first():
    p = datagram(300)
    frags = fragment(p, 64)
    evil = frags[1].copy()
    evil[Raw].load = b"\xff" * 64
    assert bytes(defragment(frags[:2] + [evil] + frags[2:])[0]) == bytes(p)


def test_an_incomplete_datagram_keeps_its_fragments():
    frags = fragment(datagram(300), 64)
    nofrag, done, missing = defrag(frags[:-1])
    assert not nofrag and not done
    assert [bytes(p) for p in missing] == [bytes(p) for p in frags[:-1]]


def test_a_missing_first_fragment_completes_nothing():
    frags = fragment(datagram(300), 64)
    assert not defrag(frags[1:])[1]


def test_unfragmented_packets_pass_through_in_place():
    plain = datagram(20)
    p = datagram(300)
    mixed = [plain] + fragment(p, 64) + [plain]
    out = defragment(mixed)
    assert [bytes(x) for x in out] == [bytes(plain), bytes(p), bytes(plain)]
    nofrag, done, missing = defrag(mixed)
    assert len(nofrag) == 2 and len(done) == 1 and not missing


def test_two_interleaved_datagrams_stay_apart():
    a, b = datagram(300, id=1), datagram(200, id=2)
    fa, fb = fragment(a, 64), fragment(b, 64)
    mixed = [x for pair in zip(fa, fb + [None] * 9) for x in pair if x is not None]
    done = defrag(mixed)[1]
    assert sorted(bytes(p) for p in done) == sorted([bytes(a), bytes(b)])


def test_the_bulk_path_agrees_with_the_per_packet_path():
    plain = datagram(20)
    mixed = [plain] + fragment(datagram(300), 64) + fragment(datagram(500, id=9), 128)
    mixed += fragment(datagram(300, id=7), 64)[1:]
    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    try:
        wrpcap(path, mixed)
        cap = rdpcap(path)
        assert isinstance(defragment(cap), PacketList)
        assert [bytes(p) for p in defragment(cap)] == [
            bytes(p) for p in defragment(mixed)
        ]
        bulk = defrag(cap)
        loose = defrag(mixed)
        for got, want in zip(bulk, loose):
            assert [bytes(p) for p in got] == [bytes(p) for p in want]
    finally:
        os.unlink(path)


def test_reassembly_keeps_the_time_of_the_first_fragment():
    frags = fragment(datagram(300), 64)
    for i, f in enumerate(frags):
        f.time = 100.0 + i
    assert defragment(frags)[0].time == 100.0


def test_a_teardrop_offset_is_refused_rather_than_buffered():
    frags = fragment(datagram(300), 64)
    evil = frags[1].copy()
    evil[IP].frag = 8191
    nofrag, done, missing = defrag([evil])
    assert not nofrag and not done and len(missing) == 1


def test_a_flood_of_unfinished_datagrams_is_bounded():
    firsts = []
    for i in range(1200):
        firsts.append(fragment(datagram(300, id=i % 65535), 64)[0])
    nofrag, done, missing = defrag(firsts)
    assert not nofrag and not done
    assert len(missing) == len(firsts)


def test_an_empty_list_reassembles_to_nothing():
    assert defragment([]) == []
    assert defrag([]) == ([], [], [])


def test_a_frame_with_no_ip_layer_is_left_alone():
    p = Ether(type=0x88B5) / Raw(load=b"opaque")
    assert [bytes(f) for f in fragment(p, 8)] == [bytes(p)]
    assert [bytes(f) for f in defragment([p])] == [bytes(p)]


@pytest.mark.parametrize("size", [8, 16, 128, 1232])
@pytest.mark.parametrize("length", [9, 300, 700])
def test_ipv6_round_trips(size, length):
    p = v6_datagram(length)
    back = defragment(fragment6(p, size))
    assert len(back) == 1
    assert bytes(back[0]) == bytes(p)


def test_an_ipv6_fragment_header_displaces_the_next_header():
    frags = fragment6(v6_datagram(300), 64)
    assert len(frags) == 5
    for i, f in enumerate(frags):
        raw = bytes(f)[14:]
        assert raw[6] == 44
        assert raw[40] == 17
        word = struct.unpack("!H", raw[42:44])[0]
        assert word >> 3 == i * 8
        assert word & 1 == int(i < 4)
    ids = {bytes(f)[14 + 44 : 14 + 48] for f in frags}
    assert len(ids) == 1


def test_defragment6_answers_with_the_one_datagram():
    p = v6_datagram(300)
    frags = fragment6(p, 64)
    assert bytes(defragment6(frags)) == bytes(p)
    assert defragment6(frags[1:]) is None


def test_a_list_mixing_link_types_still_reassembles_each():
    bare = IP(dst="10.0.0.2") / UDP() / Raw(load=BODY[:300])
    framed = Ether() / IP(dst="10.0.0.3") / UDP() / Raw(load=BODY[:200])
    out = defragment(fragment(bare, 64) + fragment(framed, 64))
    assert [bytes(p) for p in out] == [bytes(bare), bytes(framed)]


def hop_by_hop_chain(n, payload=BODY[:300]):
    """Ether/IPv6 with `n` eight-octet Hop-by-Hop headers ahead of UDP."""
    inner = bytes(Ether() / IPv6(dst="2001:db8::2") / UDP() / Raw(load=payload))
    body = bytearray()
    for i in range(n):
        body += bytes([0 if i + 1 < n else 17, 0, 1, 4, 0, 0, 0, 0])
    body += inner[54:]
    head = bytearray(inner[:54])
    head[14 + 6] = 0
    head[14 + 4 : 14 + 6] = len(body).to_bytes(2, "big")
    return Ether(bytes(head) + bytes(body))


@pytest.mark.parametrize("n", [1, 6, 7, 8, 9, 20])
def test_an_ipv6_chain_too_deep_to_walk_back_is_not_split(n):
    # Reassembly walks a bounded number of extension headers, so fragmenting
    # past that bound would emit fragments this module could not put back.
    p = hop_by_hop_chain(n)
    frags = fragment(p, 64)
    if n >= 8:
        assert [bytes(f) for f in frags] == [bytes(p)]
    else:
        assert len(frags) > 1
        assert bytes(defragment(frags)[0]) == bytes(p)


def raw_fragment(payload, off=0, mf=0, ident=1):
    """A hand-built IPv4 fragment, so a test can claim what `fragment` never
    would: an impossible offset, an unreachable extent, a flood of one id."""
    return Ether() / IP(id=ident, frag=off // 8, flags="MF" if mf else 0) / Raw(load=payload)


def test_reassembly_holds_its_stated_bounds():
    # Each cap gets its own hostile shape, and in every one the fragments come
    # back reported rather than quietly dropped.
    cases = {
        # More buffered bytes than MAX_BUFFERED, spread over many datagrams.
        "buffered": [
            raw_fragment(b"A" * 1400, off=o, mf=1, ident=i)
            for i in range(1400)
            for o in (0, 64000)
        ],
        # More fragments to one datagram than MAX_FRAGS.
        "frags": [raw_fragment(b"A" * 8, off=i * 8, mf=1, ident=7) for i in range(20000)],
        # More in-flight datagrams than MAX_INFLIGHT.
        "inflight": [raw_fragment(b"A" * 40, off=0, mf=1, ident=i) for i in range(4000)],
    }
    for name, frames in cases.items():
        nofrag, done, missing = defrag(frames)
        assert not nofrag and not done, name
        assert len(missing) == len(frames), name
        assert [bytes(p) for p in missing] == [bytes(p) for p in frames], name


def test_a_datagram_reassembling_past_the_length_field_is_refused():
    frames = [raw_fragment(b"P" * 1400, off=o, mf=1) for o in range(0, 65528, 1400)]
    frames.append(raw_fragment(b"P" * 1400, off=65512, mf=0))
    nofrag, done, missing = defrag(frames)
    assert not nofrag and not done
    assert len(missing) == len(frames)


def test_the_bulk_path_agrees_with_the_per_packet_path_on_hostile_input(tmp_path):
    import random

    rnd = random.Random(0x5eed)
    frames = []
    for _ in range(600):
        k = rnd.randrange(4)
        if k == 0:
            frames.append(
                raw_fragment(BODY[: rnd.randrange(0, 48)], off=rnd.randrange(8192) * 8,
                             mf=rnd.randrange(2), ident=rnd.randrange(6))
            )
        elif k == 1:
            frames.append(raw_fragment(b"", off=rnd.randrange(4) * 8, mf=1, ident=rnd.randrange(6)))
        elif k == 2:
            frames.extend(fragment(datagram(rnd.randrange(1, 400), id=rnd.randrange(6)),
                                   rnd.choice([8, 16, 64, 1480])))
        else:
            good = fragment(datagram(200, id=rnd.randrange(6)), 32)
            evil = good[1].copy()
            evil[Raw].load = b"\xee" * 32
            good.insert(rnd.randrange(len(good)), evil)
            frames.extend(good)
    path = str(tmp_path / "hostile.pcap")
    wrpcap(path, frames)
    cap = rdpcap(path)
    assert [bytes(p) for p in defragment(cap)] == [bytes(p) for p in defragment(frames)]
    for got, want in zip(defrag(cap), defrag(frames)):
        assert [bytes(p) for p in got] == [bytes(p) for p in want]


@pytest.mark.parametrize("kw", [{"flags": "MF"}, {"frag": 10}])
def test_splitting_something_that_is_itself_a_fragment_does_not_round_trip(kw):
    # Legal per RFC 791 §3.2 and deliberately still allowed, but nothing in the
    # pieces says where the outer datagram ends, so reassembly cannot know it
    # has them all and reports them incomplete rather than guessing.
    p = datagram(300, **kw)
    frags = fragment(p, 64)
    assert len(frags) > 1
    nofrag, done, missing = defrag(frags)
    assert not nofrag and not done
    assert [bytes(x) for x in missing] == [bytes(x) for x in frags]
