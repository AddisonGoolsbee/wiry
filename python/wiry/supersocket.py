# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from scapy: scapy/automaton.py (ObjectPipe, select_objects) and
#   scapy/supersocket.py (SuperSocket, StreamSocket)
#   scapy 2.7.0, upstream commit 7d69454
#   Copyright (C) Philippe Biondi and the scapy contributors
#
# Changed by the wiry authors:
#   2026-09-18 — cut to the socket surface Automaton actually uses, rebuilt the
#                live sockets on wiry's capture backend, and added
#                OfflineSocket so a state machine can be driven from canned
#                packets with no interface and no privileges.
#   2026-10-03 — added IterSocket, SimpleSocket, StreamSocketPeekless,
#                L3RawSocket, L2ListenTcpdump, the socket-level sr/sr1/sniff/
#                tshark/am, and scapy's SuperSocket.select error handling.

"""Selectable packet sources, the thing a state machine listens on.

``Automaton`` waits on file descriptors. That is the whole reason this module
exists: wiry's capture backend hands packets to a callback, and a callback is
not something ``select`` can wait for. Each socket here turns its source into
one descriptor that goes ready when a packet is there.

`OfflineSocket` is the one that matters for testing. It reads a capture file or
a `PacketList` and records what was sent instead of transmitting it, so a whole
state machine — transitions, timeouts, replies — runs with no interface, no
root and no live feature. The privileged sockets are the same interface over
libpcap. Any of them can feed ``sniff(opened_socket=...)`` and ``sndrcv``.
"""

from __future__ import annotations

import atexit
import ctypes
import errno
import os
import select as _select
import socket
import struct
import sys
import threading
import weakref
from collections import deque
from select import error as select_error
from select import select
from typing import Any, Callable, Iterable, Iterator, Optional

__all__ = [
    "MTU", "ObjectPipe", "select_objects", "SuperSocket", "OfflineSocket",
    "StreamSocket", "L2Socket", "L2ListenSocket", "L3Socket", "IterSocket",
    "SimpleSocket", "StreamSocketPeekless", "SSLStreamSocket", "L3RawSocket",
    "L3RawSocket6", "L2ListenTcpdump", "ETH_P_IP", "ETH_P_IPV6",
    "ETH_P_8021Q", "SOL_PACKET", "PACKET_AUXDATA", "SO_TIMESTAMPNS",
    "TP_STATUS_VLAN_VALID", "TP_STATUS_VLAN_TPID_VALID", "tpacket_auxdata",
]

#: The largest frame any of these sockets will read in one go.
MTU = 0xFFFF

WINDOWS = sys.platform == "win32"
LINUX = sys.platform.startswith("linux")
DARWIN = sys.platform == "darwin"

# <linux/if_ether.h>, <linux/socket.h>, <linux/if_packet.h>, <asm/socket.h>
ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_8021Q = 0x8100
SOL_PACKET = 263
PACKET_AUXDATA = 8
SO_TIMESTAMPNS = 35
TP_STATUS_VLAN_VALID = 1 << 4
TP_STATUS_VLAN_TPID_VALID = 1 << 6


class tpacket_auxdata(ctypes.Structure):
    _fields_ = [
        ("tp_status", ctypes.c_uint),
        ("tp_len", ctypes.c_uint),
        ("tp_snaplen", ctypes.c_uint),
        ("tp_mac", ctypes.c_ushort),
        ("tp_net", ctypes.c_ushort),
        ("tp_vlan_tci", ctypes.c_ushort),
        ("tp_vlan_tpid", ctypes.c_ushort),
    ]

# winsock.h
FD_READ = 0x00000001


def select_objects(inputs: Iterable[Any], remain: Optional[float]) -> list:
    """``select.select(inputs, [], [], remain)``, also on Windows.

    An object whose ``fileno()`` is negative is not selectable and is reported
    ready every time, which is how a source with no descriptor of its own joins
    a wait.
    """
    inputs = list(inputs)
    always = [i for i in inputs if i.fileno() < 0]
    if always:
        inputs = [i for i in inputs if i.fileno() >= 0]
        remain = 0
    if not WINDOWS:
        if not inputs:
            return always
        return _select.select(inputs, [], [], remain)[0] + always
    import ctypes

    events = []
    created = []
    results = set(always)
    for i in inputs:
        if getattr(i, "__selectable_force_select__", False):
            evt = ctypes.windll.ws2_32.WSACreateEvent()
            created.append(evt)
            res = ctypes.windll.ws2_32.WSAEventSelect(
                ctypes.c_void_p(i.fileno()), evt, FD_READ)
            events.append(evt if res == 0 else i.fileno())
        else:
            events.append(i.fileno())
    if events:
        remainms = int(remain * 1000 if remain is not None else 0xFFFFFFFF)
        if len(events) == 1:
            res = ctypes.windll.kernel32.WaitForSingleObject(
                ctypes.c_void_p(events[0]), remainms)
        else:
            res = ctypes.windll.kernel32.WaitForMultipleObjects(
                len(events),
                (ctypes.c_void_p * len(events))(*events),
                False,
                remainms,
            )
        if res != 0xFFFFFFFF and res != 0x00000102:  # neither failed nor timed out
            results.add(inputs[res])
            if len(events) > 1:
                for i, evt in enumerate(events):
                    if ctypes.windll.kernel32.WaitForSingleObject(
                            ctypes.c_void_p(evt), 0) == 0:
                        results.add(inputs[i])
    for evt in created:
        ctypes.windll.ws2_32.WSACloseEvent(evt)
    return list(results)


#: Default for a `select` nobody gave a wait to: read from `conf` at the call
#: rather than baked in, so `conf.recv_poll_rate` is a live knob.
_POLL = object()


def _poll_rate(remain: Any) -> Optional[float]:
    if remain is not _POLL:
        return remain
    from .capture import conf

    return conf.recv_poll_rate


class ObjectPipe:
    """A queue of Python objects that ``select`` can wait on.

    The objects stay in a deque; the pipe carries one byte each so the
    descriptor goes ready. Nothing is serialised, so a `Packet` crosses without
    being rebuilt.
    """

    def __init__(self, name: Optional[str] = None):
        self.name = name or "ObjectPipe"
        self.closed = False
        self.__rd, self.__wr = os.pipe()
        self.__queue: deque = deque()
        if WINDOWS:
            self._wincreate()

    if WINDOWS:
        def _wincreate(self) -> None:
            import ctypes
            import random
            self._fd = ctypes.windll.kernel32.CreateEventA(
                None, True, False,
                ctypes.create_string_buffer(b"ObjectPipe %f" % random.random()))

        def _winevent(self, fn: str) -> None:
            import ctypes
            getattr(ctypes.windll.kernel32, fn)(ctypes.c_void_p(self._fd))

    def fileno(self) -> int:
        if WINDOWS:
            return self._fd
        return self.__rd

    def send(self, obj: Any) -> int:
        self.__queue.append(obj)
        if WINDOWS:
            self._winevent("SetEvent")
        os.write(self.__wr, b"X")
        return 1

    def write(self, obj: Any) -> None:
        self.send(obj)

    def empty(self) -> bool:
        return not self.__queue

    def flush(self) -> None:
        pass

    def recv(self, n: Optional[int] = 0, options: int = 0) -> Any:
        if self.closed:
            raise EOFError
        if options & getattr(socket, "MSG_PEEK", 2):
            return self.__queue[0] if self.__queue else None
        os.read(self.__rd, 1)
        elt = self.__queue.popleft()
        if WINDOWS and not self.__queue:
            self._winevent("ResetEvent")
        return elt

    def read(self, n: Optional[int] = 0) -> Any:
        return self.recv(n)

    def clear(self) -> None:
        if not self.closed:
            while not self.empty():
                self.recv()

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            os.close(self.__rd)
            os.close(self.__wr)
            if WINDOWS:
                try:
                    self._winevent("CloseHandle")
                except ImportError:  # the interpreter is finalising
                    pass

    def __repr__(self) -> str:
        return f"<{self.name} at {id(self)}>"

    def __del__(self) -> None:
        self.close()

    @staticmethod
    def select(sockets: list, remain: Any = _POLL) -> list:
        ready = [s for s in sockets if getattr(s, "closed", False)]
        if ready:  # let the read raise EOF
            return ready
        return select_objects(sockets, _poll_rate(remain))


class SuperSocket:
    """What a state machine listens on: one descriptor and a packet at a time.

    A subclass either overrides ``recv`` or sets ``ins`` to an object with a
    ``recv(n)`` returning octets, which are read as ``Raw``.
    """

    closed = False
    #: Reported ready by every wait, for a source that has no descriptor.
    nonblocking_socket = False
    auxdata_available = False
    desc: Optional[str] = None

    def send(self, x: Any) -> int:
        outs = getattr(self, "outs", None)
        if outs is None:
            raise NotImplementedError(f"{type(self).__name__} cannot send")
        _stamp(x)
        return outs.send(bytes(x))

    def recv_raw(self, x: int = MTU) -> tuple:
        """``(layer class, octets, timestamp)`` for one read."""
        ins = getattr(self, "ins", None)
        if ins is None:
            raise NotImplementedError(f"{type(self).__name__} cannot receive")
        from . import Raw

        return Raw, ins.recv(x), None

    def recv(self, x: int = MTU, **kwargs: Any) -> Any:
        cls, val, ts = self.recv_raw(x)
        if not val or not cls:
            return None
        pkt = cls(val)
        if ts:
            pkt.time = ts
        return pkt

    def fileno(self) -> int:
        ins = getattr(self, "ins", None)
        if ins is None:
            raise NotImplementedError(f"{type(self).__name__} has no descriptor")
        return ins.fileno()

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        ins, outs = getattr(self, "ins", None), getattr(self, "outs", None)
        for sock in (outs, ins) if outs is not ins else (ins,):
            close = getattr(sock, "close", None)
            if close is not None:
                try:
                    close()
                except OSError:
                    pass

    def sr(self, *args: Any, **kargs: Any) -> tuple:
        """Send and receive over this socket. See ``sndrcv``."""
        from .sendrecv import sndrcv

        return sndrcv(self, *args, **kargs)

    def sr1(self, *args: Any, **kargs: Any) -> Any:
        from .sendrecv import sndrcv

        kargs.setdefault("threaded", False)
        ans = sndrcv(self, *args, **kargs)[0]
        return ans[0][1] if len(ans) > 0 else None

    def sniff(self, *args: Any, **kargs: Any) -> Any:
        from .capture import sniff

        return sniff(*args, opened_socket=self, **kargs)

    def tshark(self, *args: Any, **kargs: Any) -> None:
        from .sendrecv import tshark

        tshark(*args, opened_socket=self, **kargs)

    def am(self, cls: Any, *args: Any, **kwargs: Any) -> Any:
        """An answering machine that listens and replies on this socket."""
        return cls(*args, opened_socket=self, socket=self, **kwargs)

    def __enter__(self) -> "SuperSocket":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    @staticmethod
    def select(sockets: list, remain: Any = _POLL) -> list:
        """The sockets with a packet waiting. An interrupted wait is an empty
        answer; any other failure of the wait is raised."""
        remain = _poll_rate(remain)
        if WINDOWS or any(s.fileno() < 0 for s in sockets):
            return select_objects(sockets, remain)
        try:
            return select(sockets, [], [], remain)[0]
        except (OSError, select_error) as exc:
            if not exc.args or exc.args[0] != errno.EINTR:
                raise
        return []


def _stamp(x: Any) -> None:
    import time

    try:
        x.sent_time = time.time()
    except AttributeError:
        pass


class OfflineSocket(SuperSocket):
    """A capture standing in for a wire.

    Hands out packets in capture order and records what was written to it in
    ``sent`` instead of transmitting. That is what makes an ``Automaton``
    testable: its states, transitions, timeouts and replies are pure logic, and
    this drives all of them without an interface or a privilege.

    ``fileno()`` is negative, so every wait reports it ready and reads drain it
    as fast as the machine consumes them. Once it is empty ``recv`` raises
    ``EOFError``, which is the same end-of-source an ``ATMT.eof`` condition sees
    from a closed socket.
    """

    nonblocking_socket = True

    def __init__(self, source: Any = None, *, filter: Optional[str] = None,
                 send_hook: Optional[Callable[[Any], None]] = None,
                 **_: Any):
        self.sent: list = []
        self.send_hook = send_hook
        self._packets = iter(self._read(source, filter))

    @staticmethod
    def _read(source: Any, bpf: Optional[str]) -> list:
        from . import Packet, PacketList, rdpcap

        if source is None:
            return []
        if isinstance(source, (str, os.PathLike)):
            source = rdpcap(os.fspath(source))
        if isinstance(source, PacketList):
            if bpf is not None:
                raise NotImplementedError(
                    "OfflineSocket(filter=) needs a capture file: a BPF filter "
                    "over a PacketList is PacketList.filter()"
                )
            return list(source)
        if isinstance(source, Packet):
            return [source]
        return list(source)

    def fileno(self) -> int:
        return -1

    def recv(self, x: int = MTU, **kwargs: Any) -> Any:
        if self.closed:
            raise EOFError
        try:
            return next(self._packets)
        except StopIteration:
            raise EOFError("offline source exhausted") from None

    def send(self, x: Any) -> int:
        self.sent.append(x)
        if self.send_hook is not None:
            self.send_hook(x)
        return len(bytes(x))

    @staticmethod
    def select(sockets: list, remain: Any = None) -> list:
        return select_objects(sockets, 0)

    def __repr__(self) -> str:
        return f"<OfflineSocket: {len(self.sent)} sent>"


class SimpleSocket(SuperSocket):
    """An ordinary socket read as packets of ``basecls``, one ``recv`` each."""

    desc = "wrapper around a classic socket"
    __selectable_force_select__ = True

    def __init__(self, sock: Any, basecls: Any = None):
        from . import Raw

        self.ins = sock
        self.outs = sock
        self.basecls = basecls or Raw

    def recv_raw(self, x: int = MTU) -> tuple:
        return self.basecls, self.ins.recv(x), None


class StreamSocket(SimpleSocket):
    """A byte stream read as packets, one ``recv`` at a time.

    Used by ``Automaton.spawn`` for each accepted client. A read of zero octets
    is the peer closing, which raises ``EOFError`` so an ``ATMT.eof`` condition
    can see it. Each read is one packet: a message split across reads is not
    joined, which scapy does by asking the layer for its length (E27).
    """

    desc = "transforms a stream socket into a layer 2"

    def __init__(self, sock: Any, basecls: Any = None):
        super().__init__(sock, basecls)
        self.__selectable_force_select__ = isinstance(sock, socket.socket)

    def recv(self, x: Optional[int] = MTU, **kwargs: Any) -> Any:
        data = self.ins.recv(MTU if x is None else x)
        if not data:
            raise EOFError("stream closed by peer")
        return self.basecls(data)

    def send(self, x: Any) -> int:
        _stamp(x)
        return self.ins.send(bytes(x))


class StreamSocketPeekless(StreamSocket):
    """A `StreamSocket` that never peeks, for sockets that cannot (TLS)."""

    desc = "StreamSocket that doesn't use MSG_PEEK"

    def recv(self, x: Optional[int] = MTU, **kwargs: Any) -> Any:
        try:
            return super().recv(x, **kwargs)
        except OSError:
            raise EOFError("stream failed") from None


SSLStreamSocket = StreamSocketPeekless


class IterSocket(SuperSocket):
    """Packets, bytes, a list or any iterable of them, read as a socket.

    Each packet is rebuilt from its octets, as a wire would hand it over; a
    ``(sent, received)`` pair yields both, sent first. Bytes come back as
    ``Raw``. Exhausted, it raises ``EOFError``.
    """

    desc = "wrapper around an iterable"
    nonblocking_socket = True

    def __init__(self, obj: Any):
        self.iter = _flatten(obj)

    @staticmethod
    def select(sockets: list, remain: Any = None) -> list:
        return sockets

    def fileno(self) -> int:
        return -1

    def recv(self, x: Optional[int] = None, **kwargs: Any) -> Any:
        try:
            item = next(self.iter)
        except StopIteration:
            raise EOFError("iterable exhausted") from None
        return _redissect(item)

    def send(self, x: Any) -> int:
        raise NotImplementedError("an IterSocket only reads")

    def close(self) -> None:
        self.closed = True


def _flatten(obj: Any) -> Iterator[Any]:
    from . import Packet

    if obj is None:
        return iter(())
    if isinstance(obj, IterSocket):
        return obj.iter
    if isinstance(obj, (bytes, bytearray, str, Packet)):
        obj = [obj]

    def walk() -> Iterator[Any]:
        for item in obj:
            if isinstance(item, tuple) and len(item) == 2:
                yield from item
            elif isinstance(item, Packet):
                yield from item
            else:
                yield item

    return walk()


def _redissect(item: Any) -> Any:
    from . import Packet, Raw
    from . import _wiry as _b

    if isinstance(item, str):
        item = item.encode("latin-1")
    if isinstance(item, (bytes, bytearray, memoryview)):
        return Raw(load=bytes(item))
    if not isinstance(item, Packet):
        return item
    names = item.layers()
    if not names:
        return item
    pkt = Packet(_rust=_b.dissect(bytes(item), names[0]),
                 time=item.time, wirelen=item.wirelen)
    pkt.sent_time = item.sent_time
    return pkt


class L3RawSocket(SuperSocket):
    """Layer 3 over the kernel's raw sockets: ``PF_INET``/``SOCK_RAW`` out,
    ``AF_PACKET`` in. Linux only, as scapy's is, and needs root."""

    desc = "Layer 3 using Raw sockets (PF_INET/SOCK_RAW)"
    _family = socket.AF_INET
    _proto = ETH_P_IP

    def __init__(self, type: Optional[int] = None, filter: Optional[str] = None,
                 iface: Any = None, promisc: Any = None, nofilter: int = 0):
        if not LINUX:
            raise NotImplementedError(
                f"{type_name(self)} needs AF_PACKET, which only Linux has; "
                "use L3Socket, which runs on libpcap"
            )
        proto = self._proto if type is None else type
        self.outs = socket.socket(self._family, socket.SOCK_RAW,
                                  socket.IPPROTO_RAW)
        if self._family == socket.AF_INET:
            self.outs.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
        self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                 socket.htons(proto))
        self.iface = "any" if iface is None else str(iface)
        if iface is not None:
            self.ins.bind((self.iface, proto))
        try:
            self.ins.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
            self.ins.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
            self.auxdata_available = True
        except OSError:
            pass

    def recv(self, x: int = MTU, **kwargs: Any) -> Any:
        from . import Packet
        from . import _wiry as _b

        data, sa_ll, ts = _recv_aux(self.ins, x, self.auxdata_available)
        if sa_ll[2] == socket.PACKET_OUTGOING:
            return None
        # ARPHRD_ETHER and ARPHRD_LOOPBACK both carry an Ethernet header.
        if sa_ll[3] in (1, 772) and len(data) >= 14:
            data = data[14:]
        if not data:
            return None
        first = "IPv6" if data[0] >> 4 == 6 else "IP"
        pkt = Packet(_rust=_b.dissect(bytes(data), first))
        if ts is not None:
            pkt.time = ts
        return pkt

    def send(self, x: Any) -> int:
        from . import Packet

        dst = None
        if isinstance(x, Packet):
            names = x.layers()
            if names and names[0] in ("IP", "IPv6"):
                dst = x[names[0]].dst
        if dst is None:
            raise ValueError(
                "Missing 'dst' attribute in the first layer to be sent using "
                "a native L3 socket ! (make sure you passed the IP layer)"
            )
        _stamp(x)
        return self.outs.sendto(bytes(x), (dst, 0))


class L3RawSocket6(L3RawSocket):
    _family = socket.AF_INET6 if hasattr(socket, "AF_INET6") else 0
    _proto = ETH_P_IPV6


def type_name(obj: Any) -> str:
    return type(obj).__name__


def _recv_aux(sock: Any, x: int, auxdata: bool) -> tuple:
    """One read with its VLAN tag put back and its kernel timestamp, which
    is what ``PACKET_AUXDATA`` and ``SO_TIMESTAMPNS`` carry."""
    if not auxdata:
        pkt, _, _, sa_ll = sock.recvmsg(x)
        return pkt, sa_ll, None
    pkt, ancdata, _, sa_ll = sock.recvmsg(x, socket.CMSG_LEN(4096))
    ts = None
    for level, kind, data in ancdata:
        if level == SOL_PACKET and kind == PACKET_AUXDATA:
            try:
                aux = tpacket_auxdata.from_buffer_copy(data)
            except ValueError:
                continue
            if aux.tp_vlan_tci != 0 or aux.tp_status & TP_STATUS_VLAN_VALID:
                tpid = ETH_P_8021Q
                if aux.tp_status & TP_STATUS_VLAN_TPID_VALID:
                    tpid = aux.tp_vlan_tpid
                pkt = pkt[:12] + struct.pack("!HH", tpid, aux.tp_vlan_tci) + pkt[12:]
        elif level == socket.SOL_SOCKET and kind == SO_TIMESTAMPNS:
            if len(data) == 16:
                sec, nsec = struct.unpack("ll", data)
            elif len(data) == 8:
                sec, nsec = struct.unpack("ii", data)
            else:
                continue
            ts = sec + nsec * 1e-9
    return pkt, sa_ll, ts


class _PcapStream:
    """A pcap byte stream read one record at a time, as tcpdump writes it.

    The header's link type picks the first layer, as `rdpcap` would; each
    record is dissected as it arrives, since the stream never ends.
    """

    _LINK = {0: "Loopback", 1: "Ether", 12: "IP", 101: "IP", 105: "Dot11",
             108: "Loopback", 113: "CookedLinux", 127: "RadioTap",
             228: "IP", 229: "IPv6", 276: "CookedLinuxV2"}

    def __init__(self, fh: Any):
        self.fh = fh
        head = self._read(24)
        magic = head[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            self.endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            self.endian = ">"
        else:
            raise ValueError("not a pcap stream")
        self.nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        self.linktype = struct.unpack(self.endian + "I", head[20:24])[0]
        self.first = self._LINK.get(self.linktype, "Raw")

    def _read(self, n: int) -> bytes:
        out = b""
        while len(out) < n:
            chunk = self.fh.read(n - len(out))
            if not chunk:
                raise EOFError("pcap stream ended")
            out += chunk
        return out

    def recv(self, x: int = MTU, **kwargs: Any) -> Any:
        from . import Packet
        from . import _wiry as _b

        sec, frac, caplen, wirelen = struct.unpack(
            self.endian + "IIII", self._read(16))
        data = self._read(caplen)
        pkt = Packet(_rust=_b.dissect(data, self.first),
                     time=sec + frac / (1e9 if self.nano else 1e6),
                     wirelen=wirelen)
        return pkt

    def fileno(self) -> int:
        return self.fh.fileno()

    def close(self) -> None:
        self.fh.close()


class L2ListenTcpdump(SuperSocket):
    """Receive layer-2 frames through a tcpdump child process.

    tcpdump is not a dependency: where it is missing this raises naming it.
    """

    desc = "read packets at layer 2 using tcpdump"

    def __init__(self, iface: Any = None, promisc: Any = None,
                 filter: Optional[str] = None, nofilter: bool = False,
                 prog: Optional[str] = None, quiet: bool = False,
                 *arg: Any, **karg: Any):
        from .capture import conf
        from .external import tcpdump

        self.outs = None
        args = ["-w", "-", "-s", "65535"]
        self.iface = "any"
        if iface is None and (WINDOWS or DARWIN):
            iface = conf.iface
        if iface is not None:
            self.iface = str(iface)
            args.extend(["-i", self.iface])
        if not (conf.sniff_promisc if promisc is None else promisc):
            args.append("-p")
        if filter is not None:
            args.append(filter)
        self.tcpdump_proc = tcpdump(None, prog=prog, args=args, getproc=True,
                                    quiet=quiet)
        if self.tcpdump_proc is None:
            raise OSError("tcpdump could not be started")
        try:
            self.ins = _PcapStream(self.tcpdump_proc.stdout)
        except EOFError:
            status = self.tcpdump_proc.wait()
            self.closed = True
            raise OSError(
                f"tcpdump exited with status {status} before it began "
                "capturing; capturing usually needs privileges"
            ) from None

    def recv(self, x: int = MTU, **kwargs: Any) -> Any:
        return self.ins.recv(x)

    def close(self) -> None:
        if self.closed:
            return
        SuperSocket.close(self)
        self.tcpdump_proc.kill()
        self.tcpdump_proc.wait()


_OPEN: "weakref.WeakSet[_LiveSocket]" = weakref.WeakSet()


def _close_live_sockets() -> None:
    """A capture thread still pushing packets when the interpreter finalises
    segfaults, which is the failure `panic = "abort"` is kept off to prevent."""
    for s in list(_OPEN):
        try:
            s.close()
        except BaseException:
            pass


atexit.register(_close_live_sockets)


class _LiveSocket(SuperSocket):
    """A capture on an interface, made selectable.

    wiry's capture backend calls a callback per packet, so the packets land in
    an `ObjectPipe` and the pipe is what a wait sees. The crossing is one per
    packet, which is this path's contract exactly as ``sniff``'s ``prn`` is —
    it is not a bulk path and must not become one.
    """

    l2 = True

    def __init__(self, iface: Any = None, filter: Optional[str] = None,
                 promisc: Any = None, nofilter: int = 0, type: int = 3,
                 **_: Any):
        from . import capture as C

        C._b.capture_check()
        self.iface = C._iface_name(iface)
        self.filter = filter
        self._pipe = ObjectPipe("recv")
        self._lock = threading.Lock()
        self._sniffer = C.AsyncSniffer(
            iface=self.iface, filter=filter, store=0, promisc=promisc,
            prn=self._push,
        )
        self._sniffer.start()
        _OPEN.add(self)

    def _push(self, pkt: Any) -> None:
        # Returning a value would make sniff() print it once per packet.
        if not self._pipe.closed:
            self._pipe.send(pkt)

    def fileno(self) -> int:
        return self._pipe.fileno()

    def recv(self, x: int = MTU, **kwargs: Any) -> Any:
        return self._pipe.recv()

    def close(self) -> None:
        with self._lock:
            if self.closed:
                return
            self.closed = True
        try:
            self._sniffer.stop()
        except BaseException:
            pass
        self._pipe.close()

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self.iface}>"


class L2ListenSocket(_LiveSocket):
    """Receive layer-2 frames. Sending is refused: this one only listens."""


class L2Socket(_LiveSocket):
    """Send and receive layer-2 frames on one interface."""

    def send(self, x: Any) -> int:
        from . import capture as C

        C.sendp(x, iface=self.iface, verbose=0)
        return len(bytes(x))

    def _on_wire(self, pkt: Any) -> Any:
        """The packet as ``send`` puts it on the wire, its unset source
        addresses filled from this interface (E9)."""
        from . import capture as C

        return C._with_src(pkt, *C._local_addrs(self.iface))

    def send_many(self, pkts: list, passes: int = 1, inter: float = 0) -> int:
        """Every packet ``passes`` times over, in one crossing: the flood
        functions' send path, paced in Rust."""
        from . import capture as C

        mac, ip = C._local_addrs(self.iface)
        frames = [C._octets(C._with_src(p, mac, ip)) for p in pkts]
        return C._b.send_frames(frames, self.iface, int(passes),
                                C._pause(inter), False)


class L3Socket(_LiveSocket):
    """Receive layer-2 frames, send layer-3 datagrams the kernel routes."""

    l2 = False

    def send(self, x: Any) -> int:
        from . import capture as C

        C.send(x, verbose=0)
        return len(bytes(x))

    def _on_wire(self, pkt: Any) -> Any:
        from . import capture as C

        return C._with_src(pkt, None, C._local_addrs(self.iface)[1])

    def send_many(self, pkts: list, passes: int = 1, inter: float = 0) -> int:
        """See `L2Socket.send_many`."""
        from . import capture as C

        _, ip = C._local_addrs(self.iface)
        frames = [C._octets(C._with_src(p, None, ip)) for p in pkts]
        C._refuse_ipv6(pkts, frames, "send")
        return C._b.send_datagrams(frames, int(passes), C._pause(inter),
                                   False)
