# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from scapy: scapy/utils.py (the pcap, pcapng and ERF readers and
#   writers)
#   scapy 2.7.0
#   Copyright (C) Philippe Biondi <phil@secdev.org>
#   Copyright (C) the scapy contributors
#
# Changed by the wiry authors:
#   2026-10-03 — readers index the whole file in Rust once and hand records out
#                by lookup; pcapng metadata is read from the blocks that index
#                points at; option lists are walked by offset; ERF is indexed
#                in one pass and served by the pcap reader.

"""Capture-file readers and writers with scapy's record-level interface.

`rdpcap` and `PcapWriter` are the fast paths. These are for code that wants a
file a record at a time, with the metadata each record carries.
"""

from __future__ import annotations

import collections
import gzip
import os
import struct
import time
import zlib
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from . import PacketList, _as_path, _b, _linktype_of, _MAX_GUNZIP
from .error import Scapy_Exception

__all__ = [
    "PcapReader_metaclass", "RawPcapReader", "PcapReader", "RawPcapNgReader",
    "PcapNgReader", "GenericPcapWriter", "GenericRawPcapWriter",
    "RawPcapWriter", "RawPcapNgWriter", "ERFEthernetReader_metaclass",
    "ERFEthernetReader", "ERFEthernetWriter", "rderf", "wrerf",
]

_MTU = 0xFFFF
_DLT_EN10MB = 1

_PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4": (">", False),
    b"\xd4\xc3\xb2\xa1": ("<", False),
    b"\xa1\xb2\x3c\x4d": (">", True),
    b"\x4d\x3c\xb2\xa1": ("<", True),
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


class _BadCapture(Scapy_Exception, ValueError):
    """Both, so scapy's `except Scapy_Exception` and wiry's `except
    ValueError` catch the same malformed file."""


def _warning(msg: str) -> None:
    # Looked up at the call, so that patching `wiry.utils.warning` sees it.
    from . import utils
    from .error import warning

    getattr(utils, "warning", warning)(msg)


def _pad4(n: int) -> int:
    return n + (-n) % 4


class _Loaded:
    """One read of a source: the Rust index, plus the octets a pcapng walk
    needs. A stream can be read only once, so the reader class is chosen from
    this rather than from a second read."""

    __slots__ = ("name", "f", "rust", "head", "blob")

    def __init__(self, src: Any):
        self.f = src if hasattr(src, "read") else None
        self.name = (getattr(src, "name", "No name") if self.f is not None
                     else os.fspath(src))
        try:
            with _as_path(src) as real:
                with open(real, "rb") as fh:
                    self.head = fh.read(24)
                    if not self.head:
                        raise _BadCapture("No data could be read!")
                    self.blob = (self.head + fh.read()
                                 if self.head[:4] == _PCAPNG_MAGIC else None)
                self.rust = _b.read_pcap(real)
        except _BadCapture:
            raise
        except ValueError as exc:
            raise _BadCapture(str(exc)) from exc

    @property
    def pcapng(self) -> bool:
        return self.head[:4] == _PCAPNG_MAGIC


class PcapReader_metaclass(type):
    """Picks the pcap or pcapng variant from the file's magic, so either
    reader opens either format, as scapy's do."""

    def __new__(mcs, name: str, bases: tuple, dct: Dict[str, Any]) -> Any:
        newcls = super().__new__(mcs, name, bases, dct)
        if "alternative" in dct:
            dct["alternative"].alternative = newcls
        return newcls

    def __call__(cls, filename: Any, fdesc: Any = None, magic: Any = None) -> Any:
        loaded = fdesc if isinstance(fdesc, _Loaded) else _Loaded(
            filename if fdesc is None else fdesc)
        target = cls
        if loaded.pcapng != cls._ng:
            target = cls.__dict__.get("alternative")
            if target is None:
                raise _BadCapture("Not a supported capture file")
        return type.__call__(target, filename, loaded)


class RawPcapReader(metaclass=PcapReader_metaclass):
    """A capture a record at a time, each as ``(bytes, metadata)``."""

    nonblocking_socket = True
    PacketMetadata = collections.namedtuple(
        "PacketMetadata", ["sec", "usec", "wirelen", "caplen"])
    _ng = False

    def __init__(self, filename: Any, fdesc: Any = None, magic: Any = None):
        self._load(fdesc if isinstance(fdesc, _Loaded) else _Loaded(
            filename if fdesc is None else fdesc))

    def _load(self, loaded: _Loaded) -> None:
        self.filename = loaded.name
        self.f = loaded.f
        self._rust = loaded.rust
        self._index = loaded.rust.index()
        self._i = 0
        self.linktype = loaded.rust.dlt
        self.nano = loaded.rust.nanos
        if not loaded.pcapng:
            if len(loaded.head) < 24:
                raise _BadCapture("Invalid pcap file (too short)")
            self.endian, self.nano = _PCAP_MAGICS.get(
                loaded.head[:4], ("<", self.nano))
            self.snaplen, self.linktype = struct.unpack(
                self.endian + "II", loaded.head[16:24])

    def __enter__(self) -> Any:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def __iter__(self) -> Any:
        return self

    def __next__(self) -> Any:
        try:
            return self._read_packet()
        except EOFError:
            raise StopIteration from None

    def _next_index(self) -> int:
        if self._i >= len(self._index):
            raise EOFError
        self._i += 1
        return self._i - 1

    def _read_packet(self, size: int = _MTU) -> Tuple[bytes, Any]:
        i = self._next_index()
        _, caplen, sec, frac, origlen = self._index[i]
        return (self._rust.raw_at(i)[:size],
                RawPcapReader.PacketMetadata(sec=sec, usec=frac,
                                             wirelen=origlen, caplen=caplen))

    def read_packet(self, size: int = _MTU) -> Any:
        raise Exception(
            "Cannot call read_packet() in RawPcapReader. Use _read_packet()")

    def dispatch(self, callback: Callable[[Any], Any]) -> None:
        for p in self:
            callback(p)

    def _read_all(self, count: int = -1) -> List[Any]:
        res = []
        while count != 0:
            count -= 1
            try:
                res.append(self.read_packet())
            except EOFError:
                break
        return res

    def recv(self, size: int = _MTU) -> Any:
        return self._read_packet(size=size)[0]

    def fileno(self) -> int:
        """Negative: the records are already in memory, so a wait never has
        to block on this source."""
        return -1

    def close(self) -> None:
        if self.f is not None:
            self.f.close()

    @staticmethod
    def select(sockets: List[Any], remain: Optional[float] = None) -> List[Any]:
        return sockets


class PcapReader(RawPcapReader):
    """A capture a packet at a time. ``read_all()`` takes whatever is left in
    one crossing, as ``rdpcap`` takes the whole file."""

    @property
    def LLcls(self) -> type:
        from . import _LAYERS

        return _LAYERS.get(self._rust.linktype) or _LAYERS["Raw"]

    def read_packet(self, size: int = _MTU, **kwargs: Any) -> Any:
        return PacketList(self._rust)[self._next_index()]

    def recv(self, size: int = _MTU, **kwargs: Any) -> Any:
        return self.read_packet(size=size, **kwargs)

    def __next__(self) -> Any:
        try:
            return self.read_packet()
        except EOFError:
            raise StopIteration from None

    def read_all(self, count: int = -1) -> PacketList:
        total = len(self._index)
        stop = total if count < 0 else min(total, self._i + count)
        start, self._i = self._i, stop
        if start == 0 and stop == total:
            return PacketList(self._rust)
        if start == 0:
            return PacketList(self._rust.head(stop))
        return PacketList(self._rust.view(list(range(start, stop))))


_REPEATABLE = (1, 2988, 2989, 19372, 19373)


class RawPcapNgReader(RawPcapReader):
    """A pcapng capture a record at a time.

    Which records exist is the Rust index's answer. Each one's metadata — its
    interface, comments, flags and process — is read from the block that index
    points at, so the two cannot disagree about the records themselves.
    """

    alternative = RawPcapReader
    _ng = True
    PacketMetadata = collections.namedtuple(  # type: ignore[assignment]
        "PacketMetadataNg",
        ["linktype", "tsresol", "tshigh", "tslow", "wirelen", "comments",
         "ifname", "direction", "process_information"])

    def _load(self, loaded: _Loaded) -> None:
        super()._load(loaded)
        self.endian = "<"
        self.interfaces: List[Tuple[int, int, Dict[str, Any]]] = []
        self.default_options: Dict[str, Any] = {"tsresol": 1000000}
        self.process_information: List[Dict[str, Any]] = []
        self._meta: Dict[int, tuple] = {}
        self._walk(loaded.blob or b"")

    def _read_options(self, options: bytes) -> Dict[int, Any]:
        opts: Dict[int, Any] = {}
        at, end = 0, len(options)
        while end - at >= 4:
            code, length = struct.unpack(self.endian + "HH", options[at:at + 4])
            if code != 0 and at + 4 + length <= end:
                value = options[at + 4:at + 4 + length]
                if code in _REPEATABLE:
                    opts.setdefault(code, []).append(value)
                else:
                    opts[code] = value
            if code == 0:
                if length != 0:
                    _warning("PcapNg: invalid option length %d for "
                             "end-of-option" % length)
                break
            at += 4 + _pad4(length)
        return opts

    def _walk(self, blob: bytes) -> None:
        """Each block header once. Every step advances by a length its
        trailing copy confirmed, or the walk stops."""
        n, at = len(blob), 0
        section: List[Tuple[int, int, Dict[str, Any]]] = []
        while at + 12 <= n:
            if blob[at:at + 4] == _PCAPNG_MAGIC:
                bom = blob[at + 8:at + 12]
                if bom == b"\x1a\x2b\x3c\x4d":
                    self.endian = ">"
                elif bom == b"\x4d\x3c\x2b\x1a":
                    self.endian = "<"
                else:
                    return
                section = []
            btype, declared = struct.unpack(self.endian + "II", blob[at:at + 8])
            # Padded as the Rust reader pads it; see `read_block_at` there.
            total = _pad4(declared)
            if declared < 12 or at + total > n or struct.unpack(
                    self.endian + "I", blob[at + total - 4:at + total])[0] != declared:
                return
            body = blob[at + 8:at + total - 4]
            if btype == 1:
                iface = self._idb(body)
                if iface is not None:
                    section.append(iface)
                    self.interfaces.append(iface)
            elif btype in (2, 6):
                self._packet_block(btype, body, at + 28, section)
            elif btype == 3 and section and len(body) >= 4:
                linktype, _, opts = section[0]
                wirelen = struct.unpack(self.endian + "I", body[:4])[0]
                self._meta[at + 12] = (linktype, opts["tsresol"], None, None,
                                       wirelen, None, None, None, {})
            elif btype == 0x80000001:
                self._pib(body)
            at += total

    def _idb(self, body: bytes) -> Optional[Tuple[int, int, Dict[str, Any]]]:
        if len(body) < 8:
            return None
        options = self.default_options.copy()
        for code, v in self._read_options(body[8:]).items():
            if isinstance(v, list):
                v = v[0]
            if code == 9 and len(v) == 1:
                options["tsresol"] = (2 if v[0] & 128 else 10) ** (v[0] & 127)
            elif code == 2:
                options["name"] = v
            elif code == 1:
                options["comment"] = v
        linktype, snaplen = struct.unpack(self.endian + "HxxI", body[:8])
        return linktype, snaplen, options

    def _packet_block(self, btype: int, body: bytes, data_at: int,
                      section: List[Tuple[int, int, Dict[str, Any]]]) -> None:
        if len(body) < 20:
            return
        if btype == 2:
            intid, _, tshigh, tslow, caplen, wirelen = struct.unpack(
                self.endian + "HH4I", body[:20])
        else:
            intid, tshigh, tslow, caplen, wirelen = struct.unpack(
                self.endian + "5I", body[:20])
        if intid >= len(section):
            return
        linktype, _, ifopts = section[intid]
        comments, direction, proc = None, None, {}
        if btype == 6:
            options = self._read_options(body[20 + _pad4(caplen):])
            comments = options.get(1)
            flags = options.get(2)
            if isinstance(flags, bytes) and len(flags) == 4:
                direction = struct.unpack(self.endian + "I", flags)[0] & 3
            for code, key in ((0x8001, "proc"), (0x8003, "eproc")):
                value = options.get(code)
                if isinstance(value, bytes) and len(value) == 4:
                    idx = struct.unpack(self.endian + "I", value)[0]
                    if idx < len(self.process_information):
                        proc[key] = self.process_information[idx]
        self._meta[data_at] = (linktype, ifopts["tsresol"], tshigh, tslow,
                               wirelen, comments, ifopts.get("name"),
                               direction, proc)

    def _pib(self, body: bytes) -> None:
        """Apple's Process Information Block."""
        if len(body) < 4:
            return
        info: Dict[str, Any] = {"id": struct.unpack(self.endian + "I", body[:4])[0]}
        for code, value in self._read_options(body[4:]).items():
            if isinstance(value, list):
                value = value[0]
            if code == 2:
                info["name"] = value.decode("ascii", "backslashreplace")
            elif code == 4 and len(value) == 16:
                import uuid

                info["uuid"] = str(uuid.UUID(bytes=value))
        self.process_information.append(info)

    def _read_packet(self, size: int = _MTU) -> Tuple[bytes, Any]:
        i = self._next_index()
        off, _, sec, frac, origlen = self._index[i]
        meta = self._meta.get(off)
        if meta is None:
            res = 10 ** 9 if self.nano else 10 ** 6
            ticks = sec * res + frac
            meta = (self.linktype, res, ticks >> 32, ticks & 0xFFFFFFFF,
                    origlen, None, None, None, {})
        linktype, tsresol, hi, lo, wirelen, comments, ifname, direction, proc = meta
        return (self._rust.raw_at(i)[:size],
                RawPcapNgReader.PacketMetadata(
                    linktype=linktype, tsresol=tsresol, tshigh=hi, tslow=lo,
                    wirelen=wirelen, comments=comments, ifname=ifname,
                    direction=direction, process_information=dict(proc)))


def _annotate(pkt: Any, meta: Optional[tuple]) -> None:
    """What scapy's PcapNgReader sets on a packet from its record."""
    if meta is None:
        return
    _, _, _, _, _, comments, ifname, direction, proc = meta
    pkt.comments = comments
    pkt.direction = direction
    pkt.process_information = dict(proc)
    if ifname is not None:
        pkt.sniffed_on = ifname.decode("utf-8", "backslashreplace")


def pcapng_metadata(blob: bytes) -> Dict[int, tuple]:
    """Each record's annotations — interface name, comments, direction,
    process — keyed by the offset of its data in ``blob``, a whole pcapng
    file. The same walk the readers make."""
    walker = RawPcapNgReader.__new__(RawPcapNgReader)
    walker.endian = "<"
    walker.interfaces = []
    walker.default_options = {"tsresol": 1000000}
    walker.process_information = []
    walker._meta = {}
    walker._walk(blob)
    return walker._meta


class PcapNgReader(RawPcapNgReader, PcapReader):
    alternative = PcapReader

    def read_packet(self, size: int = _MTU, **kwargs: Any) -> Any:
        i = self._next_index()
        pkt = PacketList(self._rust)[i]
        _annotate(pkt, self._meta.get(self._index[i][0]))
        return pkt


class GenericPcapWriter:
    nano = False
    linktype: int

    def _write_header(self, pkt: Any) -> None:
        raise NotImplementedError

    def _write_packet(self, packet: Any, linktype: int, sec: Any = None,
                      usec: Any = None, caplen: Any = None, wirelen: Any = None,
                      ifname: Any = None, direction: Any = None,
                      comments: Any = None) -> None:
        raise NotImplementedError

    def _get_time(self, packet: Any, sec: Any, usec: Any) -> Tuple[Any, Any]:
        if hasattr(packet, "time") and sec is None:
            t = float(packet.time)
            usec = int(round((t - int(t)) * (1000000000 if self.nano else 1000000)))
            sec = t
        if sec is not None and usec is None:
            usec = 0
        return sec, usec

    def write_header(self, pkt: Any) -> None:
        if not hasattr(self, "linktype"):
            lt = None if pkt is None or isinstance(pkt, bytes) else _linktype_of(pkt)
            if lt is None:
                _warning("%s: unknown LL type for %s. Using type 1 (Ethernet)"
                         % (type(self).__name__, type(pkt).__name__))
                lt = _DLT_EN10MB
            self.linktype = lt
        self._write_header(pkt)

    def write_packet(self, packet: Any, sec: Any = None, usec: Any = None,
                     caplen: Any = None, wirelen: Any = None) -> None:
        f_sec, usec = self._get_time(packet, sec, usec)
        rawpkt = packet.encode("latin-1") if isinstance(packet, str) else bytes(packet)
        caplen = len(rawpkt) if caplen is None else caplen
        if wirelen is None:
            # wiry's 0 is "not truncated", where scapy's is None.
            wirelen = getattr(packet, "wirelen", None) or caplen
        ifname = getattr(packet, "sniffed_on", None)
        linktype = self.linktype
        if not isinstance(packet, (bytes, bytearray, str)):
            linktype = _linktype_of(packet) or self.linktype
        self._write_packet(
            rawpkt, sec=f_sec, usec=usec, caplen=caplen, wirelen=wirelen,
            ifname=None if ifname is None else str(ifname).encode("utf-8"),
            direction=getattr(packet, "direction", None), linktype=linktype,
            comments=getattr(packet, "comments", None))


def _records_of(pkt: Any) -> Iterator[Any]:
    """Each record a writer is handed: a template expands, and a
    request/answer pair is its two packets."""
    from . import Packet, expand

    if isinstance(pkt, (bytes, bytearray, str)):
        yield pkt
        return
    if isinstance(pkt, Packet):
        yield from expand(pkt)
        return
    for p in pkt:
        if isinstance(p, tuple):
            yield from p
        elif isinstance(p, Packet):
            yield from expand(p)
        else:
            yield p


class GenericRawPcapWriter(GenericPcapWriter):
    header_present = False
    sync = False
    f: Any = None

    def fileno(self) -> int:
        return self.f.fileno()

    def flush(self) -> Any:
        return self.f.flush()

    def close(self) -> Any:
        if not self.header_present:
            self.write_header(None)
        return self.f.close()

    def __enter__(self) -> Any:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.flush()
        self.close()

    def write(self, pkt: Any) -> None:
        if isinstance(pkt, bytes):
            if not self.header_present:
                self.write_header(pkt)
            self.write_packet(pkt)
            return
        for p in _records_of(pkt):
            if not self.header_present:
                self.write_header(p)
            if not isinstance(p, (bytes, bytearray, str)) and \
                    _linktype_of(p) != self.linktype:
                _warning("Inconsistent linktypes detected! The resulting file "
                         "might contain invalid packets.")
            self.write_packet(p)


def _open_target(filename: Any, mode: str, gz: bool, bufsz: int) -> Tuple[Any, str]:
    if hasattr(filename, "write"):
        return filename, getattr(filename, "name", "No name")
    name = os.fspath(filename)
    if gz:
        return gzip.open(name, mode, 9), name
    return open(name, mode, bufsz), name


class RawPcapWriter(GenericRawPcapWriter):
    """A pcap writer that writes each record through a Python file object.

    It encodes what `PcapWriter` encodes in Rust, and the suite holds the two
    to the same bytes.
    """

    def __init__(self, filename: Any, linktype: Optional[int] = None,
                 gz: bool = False, endianness: str = "", append: bool = False,
                 sync: bool = False, nano: bool = False, snaplen: int = _MTU,
                 bufsz: int = 4096):
        if linktype:
            self.linktype = linktype
        self.snaplen = snaplen
        self.append = append
        self.gz = gz
        self.endian = endianness
        self.sync = sync
        self.nano = nano
        self.f, self.filename = _open_target(
            filename, "ab" if append else "wb", gz, 0 if sync else bufsz)

    def _write_header(self, pkt: Any) -> None:
        self.header_present = True
        if self.append and not hasattr(self.f, "getvalue"):
            opener: Any = gzip.open if self.gz else open
            try:
                with opener(self.filename, "rb") as g:
                    if g.read(16):
                        return
            except OSError:
                pass
        if not hasattr(self, "linktype"):
            raise ValueError("linktype could not be guessed. Please pass a "
                             "linktype while creating the writer")
        self.f.write(struct.pack(
            self.endian + "IHHIIII", 0xA1B23C4D if self.nano else 0xA1B2C3D4,
            2, 4, 0, 0, self.snaplen, self.linktype))
        self.f.flush()

    def _write_packet(self, packet: Any, linktype: int, sec: Any = None,
                      usec: Any = None, caplen: Any = None, wirelen: Any = None,
                      ifname: Any = None, direction: Any = None,
                      comments: Any = None) -> None:
        if caplen is None:
            caplen = len(packet)
        if wirelen is None:
            wirelen = caplen
        if sec is None or usec is None:
            t = time.time()
            if sec is None:
                sec = int(t)
                usec = int(round((t - sec) * (1000000000 if self.nano else 1000000)))
            else:
                usec = 0
        # A wire length below the captured one describes a frame shorter than
        # its own bytes; raised, as the Rust writer raises it.
        self.f.write(struct.pack(self.endian + "IIII", int(sec), usec, caplen,
                                 max(wirelen, caplen)))
        self.f.write(bytes(packet))
        if self.sync:
            self.f.flush()


class RawPcapNgWriter(GenericRawPcapWriter):
    """A pcapng writer exposing the block builders. Always little-endian,
    which is what tcpdump reads."""

    def __init__(self, filename: Any):
        self.header_present = False
        self.tsresol = 1000000
        self.interfaces2id: Dict[Optional[bytes], int] = {None: 0}
        self.endian = "<"
        self.endian_magic = b"\x4d\x3c\x2b\x1a"
        self.f, self.filename = _open_target(filename, "wb", False, 4096)

    def _get_time(self, packet: Any, sec: Any, usec: Any) -> Tuple[Any, Any]:
        if hasattr(packet, "time") and sec is None:
            sec = float(packet.time)
        return sec, 0 if usec is None else usec

    def _add_padding(self, raw_data: bytes) -> bytes:
        return raw_data + (-len(raw_data)) % 4 * b"\x00"

    def build_block(self, block_type: bytes, block_body: bytes,
                    options: Optional[bytes] = None) -> bytes:
        block_body = self._add_padding(block_body)
        if options:
            block_body += options
        total = struct.pack(self.endian + "I", 12 + len(block_body))
        return block_type + total + block_body + total

    def _write_header(self, pkt: Any) -> None:
        if not self.header_present:
            self.header_present = True
            self._write_block_shb()
            self._write_block_idb(linktype=self.linktype)

    def _write_block_shb(self) -> None:
        body = self.endian_magic + struct.pack(self.endian + "HHq", 1, 0, -1)
        self.f.write(self.build_block(b"\x0A\x0D\x0D\x0A", body))

    def _write_block_idb(self, linktype: int, ifname: Optional[bytes] = None) -> None:
        body = struct.pack(self.endian + "HHI", linktype, 0, 262144)
        opts = None
        if ifname is not None:
            opts = (struct.pack(self.endian + "HH", 2, len(ifname))
                    + self._add_padding(ifname)
                    + struct.pack(self.endian + "HH", 0, 0))
        self.f.write(self.build_block(struct.pack(self.endian + "I", 1), body,
                                      options=opts))

    def _write_block_spb(self, raw_pkt: bytes) -> None:
        body = struct.pack(self.endian + "I", len(raw_pkt)) + raw_pkt
        self.f.write(self.build_block(struct.pack(self.endian + "I", 3), body))

    def _write_block_epb(self, raw_pkt: bytes, ifid: int, timestamp: Any = None,
                         caplen: Optional[int] = None, orglen: Optional[int] = None,
                         comments: Optional[List[bytes]] = None,
                         flags: Optional[int] = None) -> None:
        ticks = int(round(timestamp * self.tsresol)) if timestamp else 0
        body = struct.pack(self.endian + "5I", ifid, ticks >> 32 & 0xFFFFFFFF,
                           ticks & 0xFFFFFFFF, caplen or len(raw_pkt),
                           orglen or len(raw_pkt)) + raw_pkt
        opts = b""
        for c in comments or ():
            c = c.encode("utf-8") if isinstance(c, str) else bytes(c)
            opts += struct.pack(self.endian + "HH", 1, len(c)) + self._add_padding(c)
        if type(flags) is int:
            opts += struct.pack(self.endian + "HHI", 2, 4, flags)
        if opts:
            opts += struct.pack(self.endian + "HH", 0, 0)
        self.f.write(self.build_block(struct.pack(self.endian + "I", 6), body,
                                      options=opts))

    def _write_packet(self, packet: Any, linktype: int, sec: Any = None,
                      usec: Any = None, caplen: Any = None, wirelen: Any = None,
                      ifname: Any = None, direction: Any = None,
                      comments: Any = None) -> None:
        if caplen is None:
            caplen = len(packet)
        if wirelen is None:
            wirelen = caplen
        ifid = self.interfaces2id.get(ifname)
        if ifid is None:
            ifid = max(self.interfaces2id.values()) + 1
            self.interfaces2id[ifname] = ifid
            self._write_block_idb(linktype=linktype, ifname=ifname)
        flags = direction & 3 if type(direction) is int else None
        self._write_block_epb(packet, timestamp=sec, caplen=caplen,
                              orglen=wirelen, comments=comments, ifid=ifid,
                              flags=flags)
        if self.sync:
            self.f.flush()


def _erf_ns(frac: int) -> int:
    """ERF's binary fraction of a second as nanoseconds, rounded half up."""
    frac *= 10 ** 9
    frac += (frac & 0x80000000) << 1
    return frac >> 32


def _gunzip_bounded(data: bytes) -> bytes:
    out = bytearray()
    member = zlib.decompressobj(wbits=31)
    pending = data
    while pending:
        chunk = member.decompress(pending, 1 << 20)
        pending = member.unconsumed_tail
        if not chunk:
            break
        out += chunk
        if len(out) > _MAX_GUNZIP:
            raise _BadCapture(f"gzipped capture expands past {_MAX_GUNZIP} bytes")
    return bytes(out)


def _erf_index(data: bytes) -> List[Tuple[bytes, float, int]]:
    """Every Ethernet record as (frame, time, wire length).

    A record length shorter than its own header is read as no body rather
    than as the end of the file, so the records after it survive.
    """
    from decimal import Decimal

    out = []
    at, n = 0, len(data)
    while at + 16 <= n:
        ts = struct.unpack("<Q", data[at:at + 8])[0]
        rtype, _, rlen, _, wlen = struct.unpack(">BBHHH", data[at + 8:at + 16])
        if rtype & 0x02 == 0:
            raise _BadCapture("Invalid ERF Type (Not TYPE_ETH)")
        head = 24 if rtype & 0x80 else 16
        frame = data[at + head + 2:min(n, at + max(rlen, head))]
        # Through Decimal, so the float is the one nearest the exact time.
        t = float(Decimal(ts >> 32) + Decimal(_erf_ns(ts & 0xFFFFFFFF)) / 10 ** 9)
        out.append((frame, t, wlen))
        at += max(rlen, 16)
    return out


class _BytesSource:
    __slots__ = ("_data", "name")

    def __init__(self, data: bytes, name: str):
        self._data, self.name = data, name

    def read(self) -> bytes:
        return self._data


def _erf_loaded(src: Any) -> _Loaded:
    """ERF indexed in Python, then handed to Rust as one nanosecond pcap in a
    single crossing, so the reader serving it is the pcap reader."""
    if hasattr(src, "read"):
        data, name, f = src.read(), getattr(src, "name", "No name"), src
    else:
        name, f = os.fspath(src), None
        with open(name, "rb") as fh:
            data = fh.read()
    if data[:2] == b"\x1f\x8b":
        data = _gunzip_bounded(data)
    writer = _b.CaptureWriter(None, False, _DLT_EN10MB, 262144, True, False,
                              False, None)
    writer.write_records(_erf_index(data))
    loaded = _Loaded(_BytesSource(bytes(writer.close()), name))
    loaded.f = f
    return loaded


class ERFEthernetReader_metaclass(PcapReader_metaclass):
    def __call__(cls, filename: Any, fdesc: Any = None) -> Any:  # type: ignore[override]
        return type.__call__(cls, filename, _erf_loaded(
            filename if fdesc is None else fdesc))


class ERFEthernetReader(PcapReader, metaclass=ERFEthernetReader_metaclass):
    """Endace ERF, Ethernet records (type 2) only."""


def rderf(filename: Any, count: int = -1) -> PacketList:
    with ERFEthernetReader(filename) as fdesc:
        return fdesc.read_all(count=count)


class ERFEthernetWriter(RawPcapWriter):
    """Endace ERF, Ethernet records only. ERF has no file header."""

    def __init__(self, filename: Any, gz: bool = False, append: bool = False,
                 sync: bool = False):
        super().__init__(filename, gz=gz, append=append, sync=sync)

    def write(self, pkt: Any) -> None:
        for p in _records_of(pkt):
            self.write_packet(p)

    def write_packet(self, pkt: Any) -> None:  # type: ignore[override]
        raw = bytes(pkt)
        if hasattr(pkt, "time"):
            t = float(pkt.time)
            sec = int(t)
            frac = (int(round((t - sec) * 10 ** 9)) << 32) // 10 ** 9
        else:
            sec, frac = int(time.time()), 0
        # ERF's wlen is the frame's length on the wire; scapy writes the
        # record length there instead.
        wirelen = getattr(pkt, "wirelen", 0) or len(raw)
        self.f.write(struct.pack("<Q", (sec << 32) + frac))
        self.f.write(struct.pack(">BBHHHH", 2, 0, len(raw) + 18, 0, wirelen, 0))
        self.f.write(raw)
        self.f.flush()

    def close(self) -> Any:
        return self.f.close()


def wrerf(filename: Any, pkt: Any, *args: Any, **kargs: Any) -> None:
    with ERFEthernetWriter(filename, *args, **kargs) as fdesc:
        fdesc.write(pkt)
