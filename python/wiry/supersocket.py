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

"""Selectable packet sources, the thing a state machine listens on.

``Automaton`` waits on file descriptors. That is the whole reason this module
exists: wiry's capture backend hands packets to a callback, and a callback is
not something ``select`` can wait for. Each socket here turns its source into
one descriptor that goes ready when a packet is there.

`OfflineSocket` is the one that matters for testing. It reads a capture file or
a `PacketList` and records what was sent instead of transmitting it, so a whole
state machine — transitions, timeouts, replies — runs with no interface, no
root and no live feature. The privileged sockets are the same interface over
libpcap.
"""

from __future__ import annotations

import atexit
import os
import select
import socket
import sys
import threading
import weakref
from collections import deque
from typing import Any, Callable, Iterable, Optional

__all__ = [
    "MTU", "ObjectPipe", "select_objects", "SuperSocket", "OfflineSocket",
    "StreamSocket", "L2Socket", "L2ListenSocket", "L3Socket",
]

#: The largest frame any of these sockets will read in one go.
MTU = 0xFFFF

WINDOWS = sys.platform == "win32"

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
        return select.select(inputs, [], [], remain)[0] + always
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
    """What a state machine listens on: one descriptor and a packet at a time."""

    closed = False
    #: Reported ready by every wait, for a source that has no descriptor.
    nonblocking_socket = False

    def send(self, x: Any) -> int:
        raise NotImplementedError(f"{type(self).__name__} cannot send")

    def recv(self, x: int = MTU, **kwargs: Any) -> Any:
        raise NotImplementedError(f"{type(self).__name__} cannot receive")

    def fileno(self) -> int:
        raise NotImplementedError(f"{type(self).__name__} has no descriptor")

    def close(self) -> None:
        self.closed = True

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
        return select_objects(sockets, _poll_rate(remain))


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

    def __repr__(self) -> str:
        return f"<OfflineSocket: {len(self.sent)} sent>"


class StreamSocket(SuperSocket):
    """A byte stream read as packets, one ``recv`` at a time.

    Used by ``Automaton.spawn`` for each accepted client. A read of zero octets
    is the peer closing, which raises ``EOFError`` so an ``ATMT.eof`` condition
    can see it.
    """

    def __init__(self, sock: Any, basecls: Any = None):
        from . import Raw

        self.ins = sock
        self.basecls = basecls or Raw
        if isinstance(sock, socket.socket):
            self.__selectable_force_select__ = True

    def fileno(self) -> int:
        return self.ins.fileno()

    def recv(self, x: int = MTU, **kwargs: Any) -> Any:
        data = self.ins.recv(x)
        if not data:
            raise EOFError("stream closed by peer")
        return self.basecls(data)

    def send(self, x: Any) -> int:
        return self.ins.send(bytes(x))

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            try:
                self.ins.close()
            except OSError:
                pass


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


class L3Socket(_LiveSocket):
    """Receive layer-2 frames, send layer-3 datagrams the kernel routes."""

    l2 = False

    def send(self, x: Any) -> int:
        from . import capture as C

        C.send(x, verbose=0)
        return len(bytes(x))
