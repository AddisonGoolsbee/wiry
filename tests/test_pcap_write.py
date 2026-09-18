"""Writing capture files: the streaming writer, pcapng output, and gzip.

The block layouts asserted here come from libpcap-savefile(5) and the IETF
pcapng draft (draft-ietf-opsawg-pcapng), not from any other library's output.
"""

import gzip
import io
import struct
import zlib
from decimal import Decimal

import pytest

from wiry import (
    Ether, IP, IPv6, Loopback, PacketList, PcapNgWriter, PcapReader, PcapWriter,
    Raw, TCP, UDP, rdpcap, wrpcap, wrpcapng,
)
from helpers import ETHER_IP_TCP

SHB = 0x0A0D0D0A
IDB = 0x00000001
EPB = 0x00000006


def sample(n=4):
    pkts = [Ether() / IP(dst="10.0.0.%d" % i) / TCP(dport=80 + i) for i in range(n)]
    for i, p in enumerate(pkts):
        p.time = 1_700_000_000.5 + i
    return pkts


def blocks(path):
    """Walk a pcapng file the way the format says to: type, total length, body,
    and the same total length again."""
    data = open(path, "rb").read()
    out, off = [], 0
    while off + 12 <= len(data):
        btype, total = struct.unpack_from("<II", data, off)
        assert total % 4 == 0, "block length is not a multiple of 4"
        assert off + total <= len(data), "block runs past the file"
        (trailing,) = struct.unpack_from("<I", data, off + total - 4)
        assert trailing == total, "trailing length disagrees with the leading one"
        out.append((btype, data[off + 8 : off + total - 4]))
        off += total
    assert off == len(data), "file does not end on a block boundary"
    return out


# --- the streaming writer ------------------------------------------------


def test_the_stream_and_the_bulk_path_write_the_same_file(tmp_path):
    """CLAUDE.md's invariant. The bulk path stays in Rust, so only an equality
    check keeps the two from drifting apart."""
    pkts = sample()
    bulk = str(tmp_path / "bulk.pcap")
    wrpcap(bulk, pkts)

    stream = str(tmp_path / "stream.pcap")
    with PcapWriter(stream) as writer:
        for pkt in pkts:
            writer.write(pkt)

    from_list = str(tmp_path / "fromlist.pcap")
    wrpcap(from_list, rdpcap(bulk))

    first = open(bulk, "rb").read()
    assert open(stream, "rb").read() == first
    assert open(from_list, "rb").read() == first


def test_the_two_paths_agree_in_pcapng_too(tmp_path):
    pkts = sample()
    bulk = str(tmp_path / "bulk.pcapng")
    wrpcapng(bulk, pkts)
    stream = str(tmp_path / "stream.pcapng")
    with PcapNgWriter(stream) as writer:
        for pkt in pkts:
            writer.write(pkt)
    assert open(stream, "rb").read() == open(bulk, "rb").read()


def test_the_writer_takes_a_packet_a_list_or_raw_bytes(tmp_path):
    path = str(tmp_path / "mixed.pcap")
    with PcapWriter(path) as writer:
        writer.write(Ether() / IP())
        writer.write([Ether() / IP() / TCP(), Ether() / IP() / UDP()])
        writer.write(ETHER_IP_TCP)
    got = rdpcap(path)
    assert len(got) == 4
    assert got.raw_at(3) == ETHER_IP_TCP


def test_a_capture_can_be_copied_without_minting_a_packet(tmp_path):
    src = str(tmp_path / "src.pcap")
    wrpcap(src, sample())
    dst = str(tmp_path / "dst.pcap")
    with PcapWriter(dst) as writer:
        writer.write(rdpcap(src))
    assert open(dst, "rb").read() == open(src, "rb").read()


def test_timestamps_survive_the_round_trip(tmp_path):
    path = str(tmp_path / "t.pcap")
    pkts = sample(3)
    wrpcap(path, pkts)
    assert rdpcap(path).times() == [p.time for p in pkts]


def test_nanosecond_timestamps_keep_their_last_three_digits(tmp_path):
    for name in ("n.pcap", "n.pcapng"):
        path = str(tmp_path / name)
        pkt = Ether() / IP()
        pkt.time = 1_700_000_000.000_000_123
        wrpcap(path, [pkt], nano=True)
        assert abs(rdpcap(path).times()[0] - pkt.time) < 1e-9
    assert open(str(tmp_path / "n.pcap"), "rb").read(4) == b"\x4d\x3c\xb2\xa1"


def test_flush_makes_what_was_written_readable(tmp_path):
    path = str(tmp_path / "live.pcap")
    writer = PcapWriter(path)
    writer.write(Ether() / IP())
    writer.flush()
    assert len(rdpcap(path)) == 1
    writer.write(Ether() / IP() / TCP())
    writer.close()
    assert len(rdpcap(path)) == 2


def test_closing_twice_is_harmless_and_writing_after_it_is_not(tmp_path):
    path = str(tmp_path / "closed.pcap")
    writer = PcapWriter(path)
    writer.write(Ether() / IP())
    writer.close()
    writer.close()
    with pytest.raises(ValueError):
        writer.write(Ether() / IP())
    assert len(rdpcap(path)) == 1


def test_a_writer_that_never_saw_a_packet_still_leaves_a_readable_file(tmp_path):
    path = str(tmp_path / "empty.pcap")
    PcapWriter(path).close()
    assert len(rdpcap(path)) == 0
    ng = str(tmp_path / "empty.pcapng")
    PcapWriter(ng).close()
    assert len(rdpcap(ng)) == 0
    assert [b[0] for b in blocks(ng)] == [SHB, IDB]


def test_a_file_object_is_an_acceptable_target(tmp_path):
    buf = io.BytesIO()
    buf.close = lambda: None
    wrpcap(buf, sample(2))
    path = tmp_path / "fromobj.pcap"
    path.write_bytes(buf.getvalue())
    assert len(rdpcap(str(path))) == 2


def test_big_endian_output_is_refused_rather_than_ignored(tmp_path):
    with pytest.raises(NotImplementedError):
        PcapWriter(str(tmp_path / "be.pcap"), endianness=">")


# --- pcapng --------------------------------------------------------------


def test_the_extension_picks_the_format(tmp_path):
    ng = str(tmp_path / "by_name.pcapng")
    wrpcap(ng, sample(2))
    assert open(ng, "rb").read(4) == struct.pack("<I", SHB)

    classic = str(tmp_path / "by_name.pcap")
    wrpcap(classic, sample(2))
    assert open(classic, "rb").read(4) == b"\xd4\xc3\xb2\xa1"

    forced = str(tmp_path / "forced.pcap")
    wrpcapng(forced, sample(2))
    assert open(forced, "rb").read(4) == struct.pack("<I", SHB)


def test_a_written_pcapng_has_the_blocks_the_spec_requires(tmp_path):
    path = str(tmp_path / "shape.pcapng")
    wrpcapng(path, sample(3))
    got = blocks(path)
    assert [b[0] for b in got] == [SHB, IDB, EPB, EPB, EPB]

    magic, major, minor, seclen = struct.unpack_from("<IHHq", got[0][1], 0)
    assert (magic, major, minor, seclen) == (0x1A2B3C4D, 1, 0, -1)

    linktype, reserved, snaplen = struct.unpack_from("<HHI", got[1][1], 0)
    assert (linktype, reserved, snaplen) == (1, 0, 65535)

    iface, ts_hi, ts_lo, caplen, origlen = struct.unpack_from("<IIIII", got[2][1], 0)
    assert iface == 0
    assert caplen == origlen == 54
    assert ((ts_hi << 32) | ts_lo) == 1_700_000_000_500_000


def test_packet_data_is_padded_but_the_length_fields_are_not(tmp_path):
    for n in range(0, 9):
        path = str(tmp_path / ("pad%d.pcapng" % n))
        wrpcapng(path, [Raw(load=b"\x5a" * n)], linktype=101)
        epb = [b for b in blocks(path) if b[0] == EPB][0][1]
        caplen, origlen = struct.unpack_from("<II", epb, 12)
        assert (caplen, origlen) == (n, n)
        assert len(epb) == 20 + (n + 3) // 4 * 4
        assert rdpcap(path).raw_at(0) == b"\x5a" * n


def test_a_pcapng_declares_nanoseconds_with_if_tsresol(tmp_path):
    plain = str(tmp_path / "usec.pcapng")
    wrpcapng(plain, sample(1))
    assert len(blocks(plain)[1][1]) == 8

    nano = str(tmp_path / "nsec.pcapng")
    wrpcapng(nano, sample(1), nano=True)
    idb = blocks(nano)[1][1]
    code, length, value = struct.unpack_from("<HHB", idb, 8)
    assert (code, length, value) == (9, 1, 9)


def test_a_pcapng_round_trips_every_link_type_it_can_express(tmp_path):
    for pkt, dlt in [
        (Ether() / IP() / TCP(), 1),
        (IP() / TCP(), 228),
        (IPv6() / UDP(), 229),
        (Loopback() / IP(), 0),
    ]:
        path = str(tmp_path / ("lt%d.pcapng" % dlt))
        wrpcapng(path, [pkt])
        got = rdpcap(path)
        assert got._list.dlt == dlt
        assert bytes(got[0]) == bytes(pkt)
        assert got[0].layers() == pkt.layers()


def test_pcapng_refuses_a_link_type_its_field_cannot_hold(tmp_path):
    with pytest.raises(ValueError):
        wrpcapng(str(tmp_path / "wide.pcapng"), [Ether()], linktype=70000)


def test_the_reader_and_the_writer_agree_over_a_mixed_capture(tmp_path):
    pkts = sample(3) + [Ether() / IP() / UDP() / Raw(load=b"hi"), Ether() / IP()]
    ng = str(tmp_path / "mixed.pcapng")
    wrpcapng(ng, pkts)
    classic = str(tmp_path / "mixed.pcap")
    wrpcap(classic, pkts)
    a, b = rdpcap(ng), rdpcap(classic)
    assert [bytes(p) for p in a] == [bytes(p) for p in b] == [bytes(p) for p in pkts]
    assert a.times() == b.times()


# --- appending -----------------------------------------------------------


def test_append_adds_to_a_file_instead_of_truncating_it(tmp_path):
    path = str(tmp_path / "grow.pcap")
    wrpcap(path, sample(2))
    wrpcap(path, sample(3), append=True)
    got = rdpcap(path)
    assert len(got) == 5
    assert bytes(got[2]) == bytes(sample(3)[0])
    # One file header only.
    assert open(path, "rb").read().count(b"\xd4\xc3\xb2\xa1") == 1


def test_append_to_a_missing_file_creates_it(tmp_path):
    path = str(tmp_path / "new.pcap")
    wrpcap(path, sample(1), append=True)
    assert len(rdpcap(path)) == 1


def test_appending_a_pcapng_opens_a_new_section(tmp_path):
    path = str(tmp_path / "sections.pcapng")
    wrpcapng(path, sample(2))
    wrpcapng(path, sample(1), append=True)
    assert [b[0] for b in blocks(path)] == [SHB, IDB, EPB, EPB, SHB, IDB, EPB]
    assert len(rdpcap(path)) == 3


def test_appending_a_different_link_type_is_refused(tmp_path):
    """The header at the front of the file describes every record behind it, so
    a mismatched frame would be read as something it is not."""
    path = str(tmp_path / "eth.pcap")
    wrpcap(path, [Ether() / IP()])
    before = open(path, "rb").read()
    with pytest.raises(ValueError, match="link type"):
        wrpcap(path, [IP() / TCP()], append=True)
    assert open(path, "rb").read() == before

    ng = str(tmp_path / "eth.pcapng")
    wrpcapng(ng, [Ether() / IP()])
    with pytest.raises(ValueError, match="link type"):
        wrpcapng(ng, [IP() / TCP()], append=True)


def test_appending_across_formats_or_resolutions_is_refused(tmp_path):
    classic = str(tmp_path / "a.pcap")
    wrpcap(classic, [Ether() / IP()])
    with pytest.raises(ValueError, match="pcapng"):
        wrpcapng(classic, [Ether() / IP()], append=True)
    with pytest.raises(ValueError, match="nanoseconds"):
        wrpcap(classic, [Ether() / IP()], append=True, nano=True)

    ng = str(tmp_path / "a.pcapng")
    wrpcapng(ng, [Ether() / IP()])
    with pytest.raises(ValueError, match="pcapng"):
        wrpcap(ng, [Ether() / IP()], append=True, pcapng=False)


def test_appending_to_a_big_endian_pcap_is_refused(tmp_path):
    path = tmp_path / "be.pcap"
    path.write_bytes(struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    with pytest.raises(ValueError, match="big-endian"):
        wrpcap(str(path), [Ether() / IP()], append=True)


def test_appending_to_something_that_is_not_a_capture_is_refused(tmp_path):
    path = tmp_path / "junk.pcap"
    path.write_bytes(b"not a capture file, honestly" * 4)
    with pytest.raises(ValueError):
        wrpcap(str(path), [Ether() / IP()], append=True)


# --- gzip ----------------------------------------------------------------


def test_a_gzipped_capture_reads_by_path_and_by_stream(tmp_path):
    plain = str(tmp_path / "plain.pcap")
    pkts = sample(3)
    wrpcap(plain, pkts)
    blob = gzip.compress(open(plain, "rb").read())

    path = tmp_path / "zipped.pcap.gz"
    path.write_bytes(blob)
    assert [bytes(p) for p in rdpcap(str(path))] == [bytes(p) for p in pkts]
    assert [bytes(p) for p in rdpcap(io.BytesIO(blob))] == [bytes(p) for p in pkts]
    with PcapReader(str(path)) as reader:
        assert len(list(reader)) == 3


def test_a_gzipped_pcapng_reads_too(tmp_path):
    plain = str(tmp_path / "plain.pcapng")
    wrpcapng(plain, sample(2))
    path = tmp_path / "zipped.pcapng.gz"
    path.write_bytes(gzip.compress(open(plain, "rb").read()))
    assert len(rdpcap(str(path))) == 2


def test_the_extension_compresses_the_output(tmp_path):
    path = str(tmp_path / "out.pcap.gz")
    pkts = sample(3)
    wrpcap(path, pkts)
    assert open(path, "rb").read(2) == b"\x1f\x8b"
    assert [bytes(p) for p in rdpcap(path)] == [bytes(p) for p in pkts]

    forced = str(tmp_path / "forced.pcap")
    wrpcap(forced, pkts, gz=True)
    assert open(forced, "rb").read(2) == b"\x1f\x8b"
    assert len(rdpcap(forced)) == 3


def test_a_gzipped_pcapng_is_written_by_both_extensions(tmp_path):
    path = str(tmp_path / "out.pcapng.gz")
    wrpcapng(path, sample(2))
    assert open(path, "rb").read(2) == b"\x1f\x8b"
    assert len(rdpcap(path)) == 2


def test_appending_to_a_gzipped_capture_keeps_what_was_there(tmp_path):
    path = str(tmp_path / "grow.pcap.gz")
    wrpcap(path, sample(2))
    wrpcap(path, sample(1), append=True)
    assert len(rdpcap(path)) == 3


def test_a_whole_capture_can_be_written_to_a_compressed_target(tmp_path):
    """The bulk path writes into the in-memory sink a gzipped target uses, not
    only into a file."""
    src = str(tmp_path / "src.pcap")
    wrpcap(src, sample(4))
    out = str(tmp_path / "copy.pcap.gz")
    wrpcap(out, rdpcap(src))
    assert open(out, "rb").read(2) == b"\x1f\x8b"
    assert zlib.decompressobj(wbits=31).decompress(open(out, "rb").read()) == open(
        src, "rb"
    ).read()


def test_a_truncated_gzip_tail_still_yields_its_packets(tmp_path):
    """A capture cut off mid-transfer keeps the records that arrived; the reader
    already stops cleanly at a partial one."""
    plain = str(tmp_path / "plain.pcap")
    wrpcap(plain, sample(4))
    blob = bytearray(gzip.compress(open(plain, "rb").read()))
    blob[-8] ^= 1
    path = tmp_path / "bad_crc.pcap.gz"
    path.write_bytes(blob)
    assert len(rdpcap(str(path))) == 4

    cut = tmp_path / "cut.pcap.gz"
    cut.write_bytes(blob[: len(blob) // 2])
    assert len(rdpcap(str(cut))) <= 4


def test_gzip_that_decompresses_to_nothing_useful_is_an_error(tmp_path):
    path = tmp_path / "junk.pcap.gz"
    path.write_bytes(b"\x1f\x8b" + b"\x00" * 40)
    with pytest.raises(ValueError):
        rdpcap(str(path))


def test_two_gzip_members_read_as_one_capture(tmp_path):
    plain = str(tmp_path / "plain.pcap")
    wrpcap(plain, sample(2))
    data = open(plain, "rb").read()
    # A second member holding only records continues the first.
    path = tmp_path / "two.pcap.gz"
    path.write_bytes(gzip.compress(data[:24]) + gzip.compress(data[24:]))
    assert len(rdpcap(str(path))) == 2


def test_gzip_output_is_ordinary_gzip(tmp_path):
    path = str(tmp_path / "out.pcap.gz")
    wrpcap(path, sample(2))
    raw = zlib.decompressobj(wbits=31).decompress(open(path, "rb").read())
    assert raw[:4] == b"\xd4\xc3\xb2\xa1"


# --- robustness ----------------------------------------------------------


def test_a_zero_length_packet_round_trips(tmp_path):
    for name in ("zero.pcap", "zero.pcapng"):
        path = str(tmp_path / name)
        wrpcap(path, [b"", ETHER_IP_TCP, b""])
        got = rdpcap(path)
        assert [got.raw_at(i) for i in range(3)] == [b"", ETHER_IP_TCP, b""]


def test_a_packet_larger_than_the_snaplen_is_written_whole(tmp_path):
    big = Ether() / IP() / UDP() / Raw(load=b"\xab" * 4000)
    for name in ("big.pcap", "big.pcapng"):
        path = str(tmp_path / name)
        wrpcap(path, [big], snaplen=128)
        got = rdpcap(path)
        assert got.raw_at(0) == bytes(big)


@pytest.mark.parametrize(
    "when", [-1.0, 0.0, float("nan"), float("inf"), 1e30, 2 ** 32 + 5.0]
)
def test_a_timestamp_outside_the_epoch_clamps_rather_than_wrapping(tmp_path, when):
    for name in ("ts.pcap", "ts.pcapng"):
        path = str(tmp_path / name)
        pkt = Ether() / IP()
        pkt.time = when
        wrpcap(path, [pkt])
        got = rdpcap(path)
        assert len(got) == 1
        assert 0.0 <= got.times()[0] <= 2 ** 32
        assert bytes(got[0]) == bytes(pkt)


def test_writing_to_a_directory_is_an_os_error(tmp_path):
    with pytest.raises(OSError):
        wrpcap(str(tmp_path), [Ether() / IP()])


def test_an_empty_packet_list_writes_a_header_only_file(tmp_path):
    path = str(tmp_path / "none.pcapng")
    wrpcapng(path, [])
    assert [b[0] for b in blocks(path)] == [SHB, IDB]
    assert len(rdpcap(path)) == 0


def test_writing_an_empty_capture_object_keeps_its_link_type(tmp_path):
    src = str(tmp_path / "src.pcap")
    wrpcap(src, [IP() / TCP()])
    empty = rdpcap(src).head(0)
    assert isinstance(empty, PacketList) and len(empty) == 0
    out = str(tmp_path / "out.pcap")
    wrpcap(out, empty)
    assert rdpcap(out)._list.dlt == 228


def test_the_two_paths_agree_over_records_built_to_disagree(tmp_path):
    """CLAUDE.md's invariant, where it is most likely to break: an empty frame,
    one past the snaplen, and a list whose link types do not agree."""
    hostile = [
        b"",
        Ether() / IP() / UDP() / Raw(load=b"\xab" * 4000),
        IP() / TCP(),
        b"\x00",
        Ether(),
    ]
    for pcapng in (False, True):
        bulk = str(tmp_path / ("hb%d.pcap" % pcapng))
        stream = str(tmp_path / ("hs%d.pcap" % pcapng))
        with pytest.warns(UserWarning, match="Inconsistent linktypes"):
            wrpcap(bulk, hostile, snaplen=128, pcapng=pcapng)
        with pytest.warns(UserWarning, match="Inconsistent linktypes"):
            with PcapWriter(stream, snaplen=128, pcapng=pcapng) as writer:
                for pkt in hostile:
                    writer.write(pkt)
        assert open(stream, "rb").read() == open(bulk, "rb").read()
        assert len(rdpcap(bulk)) == 5


def test_the_wire_length_of_a_clipped_record_survives_a_copy(tmp_path):
    """A snaplen-clipped record knows it was clipped only through `origlen`.
    Copying a capture that drops it turns a truncated frame into a short one."""
    src = tmp_path / "clipped.pcap"
    body = bytes(Ether() / IP() / UDP() / Raw(load=b"x" * 200))
    src.write_bytes(
        struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 128, 1)
        + struct.pack("<IIII", 5, 6, 64, len(body))
        + body[:64]
    )
    assert rdpcap(str(src))[0].wirelen == len(body)

    out = str(tmp_path / "copy.pcap")
    wrpcap(out, rdpcap(str(src)))
    assert struct.unpack_from("<I", open(out, "rb").read(), 36)[0] == len(body)

    ng = str(tmp_path / "copy.pcapng")
    wrpcapng(ng, rdpcap(str(src)))
    epb = [b for b in blocks(ng) if b[0] == EPB][0][1]
    assert struct.unpack_from("<II", epb, 12) == (64, len(body))

    one = str(tmp_path / "one.pcap")
    with PcapWriter(one) as writer:
        for pkt in rdpcap(str(src)):
            writer.write(pkt)
    assert open(one, "rb").read() == open(out, "rb").read()


def test_a_wire_length_set_by_hand_is_what_gets_written(tmp_path):
    pkt = Ether() / IP()
    pkt.wirelen = 1500
    path = str(tmp_path / "wl.pcap")
    wrpcap(path, [pkt])
    caplen, origlen = struct.unpack_from("<II", open(path, "rb").read(), 32)
    assert (caplen, origlen) == (len(bytes(pkt)), 1500)


# --- appending must not damage what is already there ----------------------


def test_appending_after_a_half_written_block_is_refused(tmp_path):
    """A pcapng block repeats its total length at both ends, so a file cut off
    mid-block is detectable — and appending would hide the damage inside a
    block header that swallows whatever follows."""
    path = str(tmp_path / "cut.pcapng")
    wrpcapng(path, sample(3))
    whole = open(path, "rb").read()
    for cut in (1, 4, 8, 9, 12, 40, len(whole) - 30):
        damaged = whole[:-cut]
        (tmp_path / "cut.pcapng").write_bytes(damaged)
        with pytest.raises(ValueError):
            wrpcapng(path, sample(1), append=True)
        assert open(path, "rb").read() == damaged

    # A cut that still leaves a readable header is refused for the tail, not
    # for anything the header probe happened to notice first.
    (tmp_path / "cut.pcapng").write_bytes(whole[:-8])
    with pytest.raises(ValueError, match="mid-block"):
        wrpcapng(path, sample(1), append=True)

    # The undamaged file still appends, so the check is not refusing everything.
    (tmp_path / "cut.pcapng").write_bytes(whole)
    wrpcapng(path, sample(1), append=True)
    assert len(rdpcap(path)) == 4


def test_a_failed_delivery_leaves_the_existing_capture_intact(tmp_path, monkeypatch):
    """The compressed path rewrites the whole file. Truncating it first would
    destroy a capture whenever the replacement write fails."""
    import wiry

    path = str(tmp_path / "grow.pcap.gz")
    wrpcap(path, sample(2))
    before = open(path, "rb").read()

    def boom(*a, **k):
        raise OSError("no space left on device")

    monkeypatch.setattr(wiry.os, "replace", boom)
    with pytest.raises(OSError):
        wrpcap(path, sample(1), append=True)
    assert open(path, "rb").read() == before
    assert [p.name for p in tmp_path.iterdir()] == ["grow.pcap.gz"]


# --- gzip is a walk over an attacker-controlled length --------------------


def test_a_gzip_bomb_is_refused_instead_of_being_expanded(tmp_path):
    """CLAUDE.md §5: every walk over an attacker-controlled length is bounded.
    A decompressor is exactly that."""
    path = tmp_path / "bomb.pcap.gz"
    path.write_bytes(gzip.compress(b"\x00" * (96 << 20)))
    with pytest.raises(ValueError):
        rdpcap(str(path))

    # The same bomb wearing a capture's magic still stops at the ceiling.
    import wiry

    big = b"\xd4\xc3\xb2\xa1" + b"\x00" * (96 << 20)
    path.write_bytes(gzip.compress(big))
    monkeypatch_limit = wiry._MAX_GUNZIP
    try:
        wiry._MAX_GUNZIP = 1 << 20
        with pytest.raises(ValueError, match="expands past"):
            rdpcap(str(path))
    finally:
        wiry._MAX_GUNZIP = monkeypatch_limit


def test_a_gzip_stream_that_is_not_a_capture_stops_at_its_first_bytes(tmp_path):
    path = tmp_path / "notacapture.pcap.gz"
    path.write_bytes(gzip.compress(b"PK\x03\x04" + b"\x00" * (64 << 20)))
    with pytest.raises(ValueError):
        rdpcap(str(path))


# --- the writer at the end of its life ------------------------------------


def test_a_writer_dropped_without_close_still_delivers_its_packets(tmp_path):
    import gc

    for name in ("dropped.pcap", "dropped.pcap.gz"):
        path = str(tmp_path / name)

        def leak():
            writer = PcapWriter(path)
            writer.write(Ether() / IP())

        leak()
        gc.collect()
        assert len(rdpcap(path)) == 1


def test_a_writer_alive_at_interpreter_shutdown_neither_crashes_nor_drops(tmp_path):
    """CLAUDE.md warns that anything reaching into Python after finalisation is
    a segfault; a `__del__` that silently swallowed the packets would be worse."""
    import subprocess
    import sys

    path = str(tmp_path / "shutdown.pcap.gz")
    source = (
        "import sys, wiry\n"
        "w = wiry.PcapWriter(sys.argv[1])\n"
        "w.write(wiry.Ether() / wiry.IP() / wiry.TCP())\n"
    )
    done = subprocess.run(
        [sys.executable, "-c", source, path], capture_output=True, text=True
    )
    assert done.returncode == 0, done.stderr
    assert done.stderr == ""
    assert len(rdpcap(path)) == 1


# --- the bytes, against the specification rather than against a reader ----


def options(body, start):
    """Walk an option list per pcapng §3.5: code, length, value padded to four,
    terminated by opt_endofopt. Returns the options and where the list ended."""
    out, off = [], start
    while off < len(body):
        assert off % 4 == 0, "an option did not start on a 4-byte boundary"
        code, length = struct.unpack_from("<HH", body, off)
        value = body[off + 4 : off + 4 + length]
        assert len(value) == length, "option value runs past the block"
        padded = (length + 3) // 4 * 4
        assert body[off + 4 + length : off + 4 + padded] == b"\x00" * (padded - length)
        off += 4 + padded
        if code == 0:
            assert length == 0, "opt_endofopt carries a value"
            return out, off
        out.append((code, value))
    assert not out, "an option list that has options must end with opt_endofopt"
    return out, off


def test_the_written_octets_say_what_the_pcapng_specification_says(tmp_path):
    """tshark is not on this machine, and a file wiry writes and wiry reads back
    proves only that wiry agrees with itself. These are the raw octets checked
    against the format, which is what a second reader would be checking."""
    for nano in (False, True):
        path = str(tmp_path / ("spec%d.pcapng" % nano))
        pkt = Ether() / IP() / UDP() / Raw(load=b"\xa5" * 3)  # an odd length
        pkt.time = 1_632_568_366.384_185
        wrpcapng(path, [pkt], nano=nano, snaplen=262144)
        data = open(path, "rb").read()

        seen, off = [], 0
        while off < len(data):
            assert off % 4 == 0, "a block did not start on a 4-byte boundary"
            btype, total = struct.unpack_from("<II", data, off)
            assert total >= 12, "a block is shorter than its own framing"
            assert total % 4 == 0, "block total length is not a multiple of four"
            assert off + total <= len(data), "a block runs past the file"
            (trailing,) = struct.unpack_from("<I", data, off + total - 4)
            assert trailing == total, "the two total lengths disagree"
            seen.append((btype, data[off + 8 : off + total - 4]))
            off += total
        assert off == len(data), "the file does not end on a block boundary"
        assert [b[0] for b in seen] == [SHB, IDB, EPB]

        shb = seen[0][1]
        assert shb[:4] == b"\x4d\x3c\x2b\x1a", "byte-order magic is not 0x1A2B3C4D LE"
        major, minor, seclen = struct.unpack_from("<HHq", shb, 4)
        assert (major, minor) == (1, 0)
        assert seclen == -1, "a stream writer cannot know the section length"
        assert options(shb, 16) == ([], len(shb))

        idb = seen[1][1]
        linktype, reserved, snaplen = struct.unpack_from("<HHI", idb, 0)
        assert (linktype, reserved, snaplen) == (1, 0, 262144)
        opts, end = options(idb, 8)
        assert end == len(idb), "the option list did not fill the block body"
        if nano:
            # if_tsresol: the high bit clear means 10^-value ticks per second.
            assert opts == [(9, b"\x09")]
            assert not opts[0][1][0] & 0x80
            ticks_per_second = 10 ** opts[0][1][0]
        else:
            assert opts == [], "10^-6 is the default and needs no option"
            ticks_per_second = 10 ** 6

        epb = seen[2][1]
        iface, hi, lo, caplen, origlen = struct.unpack_from("<IIIII", epb, 0)
        assert iface == 0, "the only interface this section describes is 0"
        assert caplen == len(bytes(pkt)) == origlen
        # The double cannot hold every decimal, so the faithful claim is that
        # the ticks land within one of the value actually stored.
        assert abs(((hi << 32) | lo) - Decimal(pkt.time) * ticks_per_second) <= 1
        assert epb[20 : 20 + caplen] == bytes(pkt)
        pad = -caplen % 4
        assert epb[20 + caplen :] == b"\x00" * pad, "packet padding is not zeroed"
        assert len(epb) == 20 + caplen + pad


def test_the_written_octets_say_what_libpcap_savefile_says(tmp_path):
    for nano in (False, True):
        path = str(tmp_path / ("spec%d.pcap" % nano))
        pkt = Ether() / IP() / UDP() / Raw(load=b"\xa5" * 3)
        pkt.time = 1_632_568_366.384_185
        wrpcap(path, [pkt], nano=nano, snaplen=262144)
        data = open(path, "rb").read()

        assert data[:4] == (b"\x4d\x3c\xb2\xa1" if nano else b"\xd4\xc3\xb2\xa1")
        major, minor, zone, sigfigs, snaplen, linktype = struct.unpack_from(
            "<HHiIII", data, 4
        )
        assert (major, minor) == (2, 4)
        assert (zone, sigfigs) == (0, 0)
        assert (snaplen, linktype) == (262144, 1)

        sec, frac, caplen, origlen = struct.unpack_from("<IIII", data, 24)
        scale = 10 ** 9 if nano else 10 ** 6
        assert frac < scale, "a fraction at or past one second is malformed"
        assert abs(sec * scale + frac - Decimal(pkt.time) * scale) <= 1
        assert caplen == origlen == len(bytes(pkt))
        assert data[40:] == bytes(pkt), "records are not padded in this format"


def test_the_tail_check_covers_the_compressed_path_too(tmp_path):
    """A gzipped target is appended to through the in-memory sink, which is a
    second code path with the same invariant to keep."""
    path = str(tmp_path / "cut.pcapng.gz")
    wrpcapng(path, sample(2))
    whole = gzip.decompress(open(path, "rb").read())
    (tmp_path / "cut.pcapng.gz").write_bytes(gzip.compress(whole[:-8]))
    damaged = open(path, "rb").read()
    with pytest.raises(ValueError, match="mid-block"):
        wrpcapng(path, sample(1), append=True)
    assert open(path, "rb").read() == damaged


def test_a_timestamp_the_double_holds_exactly_is_written_exactly(tmp_path):
    for nano in (False, True):
        path = str(tmp_path / ("exact%d.pcap" % nano))
        pkt = Ether() / IP()
        pkt.time = 1_632_568_366.5
        wrpcap(path, [pkt], nano=nano)
        scale = 10 ** 9 if nano else 10 ** 6
        sec, frac = struct.unpack_from("<II", open(path, "rb").read(), 24)
        assert (sec, frac) == (1_632_568_366, scale // 2)
        assert rdpcap(path).times()[0] == pkt.time


def test_a_gzipped_capture_reads_from_a_stream_that_cannot_seek(tmp_path):
    """`open` may hand back a pipe, so the gzip probe must not rewind."""
    import os
    from unittest.mock import patch

    plain = str(tmp_path / "plain.pcap")
    wrpcap(plain, sample(2))
    blob = gzip.compress(open(plain, "rb").read())

    read_fd, write_fd = os.pipe()
    assert os.write(write_fd, blob) == len(blob)
    os.close(write_fd)
    with patch("builtins.open", return_value=os.fdopen(read_fd, "rb")):
        got = rdpcap("whatever.pcap.gz")
    assert len(got) == 2
