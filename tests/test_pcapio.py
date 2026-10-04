"""Record-level capture I/O: the raw readers and writers, pcapng metadata, ERF.

Every input is assembled by hand from the format's own layout: the libpcap file
format, draft-ietf-opsawg-pcapng, and Endace's ERF type 2 record.
"""

import gzip
import io
import struct

import pytest

from wiry import (
    Ether, IP, PacketList, PcapReader, Raw, TCP, UDP, rdpcap, wrpcap,
)
from wiry.error import Scapy_Exception
from wiry.pcapio import (
    ERFEthernetReader, ERFEthernetWriter, PcapNgReader, RawPcapNgReader,
    RawPcapNgWriter, RawPcapReader, RawPcapWriter, rderf, wrerf,
)

FRAME_A = bytes(Ether(dst="00:00:00:00:00:02") / IP() / TCP())
FRAME_B = bytes(Ether(dst="00:00:00:00:00:03") / IP() / UDP())


def pcap(records, magic=0xA1B2C3D4, linktype=1, endian="<"):
    out = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 0xFFFF, linktype)
    for sec, frac, data, wirelen in records:
        out += struct.pack(endian + "IIII", sec, frac, len(data), wirelen) + data
    return out


def block(btype, body, endian="<"):
    body += b"\x00" * (-len(body) % 4)
    total = struct.pack(endian + "I", 12 + len(body))
    return struct.pack(endian + "I", btype) + total + body + total


def option(code, value, endian="<"):
    return struct.pack(endian + "HH", code, len(value)) + value + b"\x00" * (-len(value) % 4)


END = struct.pack("<HH", 0, 0)
SHB = block(0x0A0D0D0A, b"\x4d\x3c\x2b\x1a" + struct.pack("<HHq", 1, 0, -1))


def idb(linktype=1, opts=b""):
    return block(1, struct.pack("<HHI", linktype, 0, 0xFFFF) + opts)


def epb(ifid, ticks, data, opts=b""):
    body = struct.pack("<5I", ifid, ticks >> 32, ticks & 0xFFFFFFFF, len(data), len(data))
    body += data + b"\x00" * (-len(data) % 4) + opts
    return block(6, body)


def test_raw_pcap_reader_yields_bytes_and_the_record_header():
    data = pcap([(10, 20, FRAME_A, len(FRAME_A) + 4), (11, 0, FRAME_B, len(FRAME_B))])
    with RawPcapReader(io.BytesIO(data)) as r:
        assert r.linktype == 1 and r.snaplen == 0xFFFF and not r.nano
        got = list(r)
    assert [d for d, _ in got] == [FRAME_A, FRAME_B]
    assert got[0][1] == (10, 20, len(FRAME_A) + 4, len(FRAME_A))
    assert got[0][1].usec == 20 and got[1][1].sec == 11


def test_a_big_endian_nanosecond_header_is_read_as_such():
    data = pcap([(1, 999999999, FRAME_A, len(FRAME_A))], magic=0xA1B23C4D, endian=">")
    r = RawPcapReader(io.BytesIO(data))
    assert r.endian == ">" and r.nano
    assert next(r)[1].usec == 999999999


def test_raw_reader_size_truncates_and_recv_and_dispatch_work():
    data = pcap([(0, 0, FRAME_A, len(FRAME_A))] * 3)
    r = RawPcapReader(io.BytesIO(data))
    assert r._read_packet(size=6)[0] == FRAME_A[:6]
    assert r.recv() == FRAME_A
    seen = []
    r.dispatch(seen.append)
    assert len(seen) == 1
    with pytest.raises(EOFError):
        r._read_packet()
    with pytest.raises(Exception, match="_read_packet"):
        r.read_packet()


def test_either_reader_opens_either_format():
    ng = SHB + idb() + epb(0, 5_000_001, FRAME_A)
    assert type(RawPcapReader(io.BytesIO(ng))) is RawPcapNgReader
    assert type(PcapReader(io.BytesIO(ng))) is PcapNgReader
    plain = pcap([(0, 0, FRAME_A, len(FRAME_A))])
    assert type(RawPcapNgReader(io.BytesIO(plain))) is RawPcapReader
    assert type(PcapNgReader(io.BytesIO(plain))) is PcapReader


def test_pcapng_metadata_comes_from_the_block_the_index_points_at():
    flags = struct.pack("<I", 2)
    opts = option(1, b"one") + option(1, b"two") + option(2, flags) + END
    named = idb(1, option(2, b"eth9") + option(9, b"\x09") + END)
    data = SHB + idb() + named + epb(1, 7_000_000_123, FRAME_A, opts) + epb(0, 3_000_000, FRAME_B)
    r = RawPcapNgReader(io.BytesIO(data))
    (d1, m1), (d2, m2) = list(r)
    assert d1 == FRAME_A and d2 == FRAME_B
    assert m1.ifname == b"eth9" and m1.tsresol == 10 ** 9
    assert (m1.tshigh << 32) + m1.tslow == 7_000_000_123
    assert m1.comments == [b"one", b"two"] and m1.direction == 2
    assert m2.ifname is None and m2.comments is None and m2.tsresol == 10 ** 6
    assert len(r.interfaces) == 2


def test_pcapng_reader_names_the_interface_a_packet_arrived_on():
    named = idb(1, option(2, b"en0") + END)
    pkt = next(iter(PcapNgReader(io.BytesIO(SHB + named + epb(0, 0, FRAME_A)))))
    assert pkt.sniffed_on == "en0" and bytes(pkt) == FRAME_A


def test_the_obsolete_packet_block_is_read():
    body = struct.pack("<HH4I", 0, 0, 0, 2_000_000, len(FRAME_A), len(FRAME_A)) + FRAME_A
    pkts = rdpcap(io.BytesIO(SHB + idb() + block(2, body)))
    assert len(pkts) == 1 and bytes(pkts[0]) == FRAME_A and pkts[0].time == 2.0


def test_process_information_block_is_attached_to_its_packets():
    pib = block(0x80000001, struct.pack("<I", 77) + option(2, b"trustd") + END)
    opts = option(0x8001, struct.pack("<I", 0)) + END
    _, meta = next(RawPcapNgReader(io.BytesIO(SHB + idb() + pib + epb(0, 0, FRAME_A, opts))))
    assert meta.process_information == {"proc": {"id": 77, "name": "trustd"}}


def test_option_walk_never_copies_the_unread_suffix():
    class NoSuffix(bytes):
        def __getitem__(self, key):
            if isinstance(key, slice) and key.start and key.stop is None:
                raise AssertionError("copied the unread options")
            return super().__getitem__(key)

    reader = object.__new__(RawPcapNgReader)
    reader.endian = "<"
    opts = NoSuffix(struct.pack("<HHc3x", 1, 1, b"x") * 32 + END)
    assert len(reader._read_options(opts)[1]) == 32


def test_pcap_reader_read_all_takes_what_is_left():
    data = pcap([(i, 0, FRAME_A, len(FRAME_A)) for i in range(5)])
    r = PcapReader(io.BytesIO(data))
    assert r.LLcls is Ether
    next(r)
    rest = r.read_all(count=2)
    assert isinstance(rest, PacketList) and [p.time for p in rest] == [1.0, 2.0]
    assert [p.time for p in r.read_all()] == [3.0, 4.0]
    assert len(r.read_all()) == 0


def test_rdpcap_count():
    data = pcap([(i, 0, FRAME_A, len(FRAME_A)) for i in range(4)])
    assert len(rdpcap(io.BytesIO(data), count=3)) == 3
    assert len(rdpcap(io.BytesIO(data), count=-1)) == 4


def test_a_malformed_file_is_both_exceptions_it_is_caught_as():
    with pytest.raises(Scapy_Exception):
        rdpcap(io.BytesIO(b"\x00" * 40))
    with pytest.raises(ValueError):
        rdpcap(io.BytesIO(b"\x00" * 40))
    with pytest.raises(Scapy_Exception):
        RawPcapReader(io.BytesIO(b""))


def test_raw_pcap_writer_writes_what_the_rust_writer_writes(tmp_path):
    pkts = [Ether() / IP() / TCP(), Ether() / IP() / UDP() / Raw(b"x" * 9)]
    for i, p in enumerate(pkts):
        p.time = 1_600_000_000 + i + 0.25
    fast, slow = str(tmp_path / "fast.pcap"), str(tmp_path / "slow.pcap")
    wrpcap(fast, pkts)
    with RawPcapWriter(slow) as w:
        w.write(pkts)
    assert open(fast, "rb").read() == open(slow, "rb").read()


def test_raw_pcap_writer_on_bytes_defaults_to_ethernet(tmp_path):
    path = str(tmp_path / "b.pcap")
    with RawPcapWriter(path) as w:
        w.write(b"test")
        assert w.linktype == 1
    assert [d for d, _ in RawPcapReader(path)] == [b"test"]
    with RawPcapWriter(path, linktype=101) as w:
        w.write(b"test")
    assert RawPcapReader(path).linktype == 101


def test_raw_pcapng_writer_block_builders_round_trip(tmp_path):
    path = str(tmp_path / "w.pcapng")
    w = RawPcapNgWriter(path)
    w._write_block_shb()
    w._write_block_idb(linktype=1)
    frame = bytes(Ether() / Raw(b"Hello wiry!!!!"))
    w._write_block_epb(frame, ifid=0, timestamp=1632568366.384185,
                       comments=[b"c"], flags=1)
    w.f.close()
    _, meta = next(RawPcapNgReader(path))
    assert meta.comments == [b"c"] and meta.direction == 1
    got = rdpcap(path)
    assert bytes(got[0]) == frame and got[0].time == 1632568366.384185


def test_pcap_writer_writes_through_a_file_object_and_waits_on_nothing():
    f = io.BytesIO()
    f.close = lambda: None
    from wiry import PcapWriter

    w = PcapWriter(f)
    w.write([])
    assert f.getvalue() == b""
    w.write(Ether() / IP())
    assert len(f.getvalue()) > 24
    w.close()
    f.seek(0)
    assert PcapReader(f).linktype == 1


def erf_record(ts, frame, wlen, rtype=2):
    return (struct.pack("<Q", ts)
            + struct.pack(">BBHHH", rtype, 0, len(frame) + 18, 0, wlen)
            + b"\x00\x00" + frame)


def test_erf_records_read_with_their_time_and_wire_length():
    # 0x8000_0000 of 2^32 is half a second.
    data = erf_record((1_600_000_000 << 32) | 0x80000000, FRAME_A, 99)
    data += struct.pack("<Q", 0) + struct.pack(">BBHHH", 2, 0, 0, 0, 0)
    data += erf_record(1 << 32, FRAME_B, len(FRAME_B))
    got = rderf(io.BytesIO(data))
    assert len(got) == 3
    assert bytes(got[0]) == FRAME_A and got[0].time == 1_600_000_000.5
    assert got[0].wirelen == 99
    assert bytes(got[1]) == b""
    assert TCP not in got[2] and UDP in got[2] and got[2].time == 1.0
    assert len(rderf(io.BytesIO(gzip.compress(data)), count=1)) == 1


def test_erf_refuses_a_record_that_is_not_ethernet():
    with pytest.raises(Scapy_Exception):
        rderf(io.BytesIO(erf_record(0, FRAME_A, 1, rtype=1)))


def test_erf_round_trips_and_appends(tmp_path):
    src = rderf(io.BytesIO(erf_record((5 << 32) | 0x40000000, FRAME_A, 70)
                           + erf_record(6 << 32, FRAME_B, len(FRAME_B))))
    path = str(tmp_path / "out.erf")
    wrerf(path, src)
    back = rderf(path)
    assert [bytes(p) for p in back] == [bytes(p) for p in src]
    assert [p.time for p in back] == [5.25, 6.0]
    assert back[0].wirelen == 70
    wrerf(path, src, append=True)
    assert len(rderf(path)) == 4
    assert type(ERFEthernetReader(path)) is ERFEthernetReader
    assert issubclass(ERFEthernetWriter, RawPcapWriter)
