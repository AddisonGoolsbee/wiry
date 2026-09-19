# SPDX-License-Identifier: GPL-2.0-only
#
# The session protocol below — `DefaultSession`, `supersession`, and the
# `process(pkt) -> Packet | None` contract `sniff(session=)` drives — is derived
# from scapy: scapy/sessions.py
#   scapy 2.7.0, upstream commit 7d69454
#   Copyright (C) Philippe Biondi and the scapy contributors
#
# Changed by the wiry authors:
#   2026-09-18 — reassembly is a whole-capture pass in Rust behind
#                `bulk_process`, and the per-packet contract rides `sniff`'s
#                wrap hook rather than a Python read loop.

"""TCP stream reassembly, and the session objects built on it.

RFC 9293 §3.4 and §3.7. `PacketList.streams()` reassembles a whole capture in
one crossing with the GIL released and hands back a lazy mapping of flow key to
`TCPStream`; nothing is materialised per packet.

`sessions()` says which packets belong to a flow. This says what the flow
*said*: octets in sequence order, retransmissions dropped, out-of-order arrival
put back, and holes named rather than filled in. That is what makes an HTTP
message or a TLS record that crossed a segment boundary parseable at all.

The bounds every part of this works inside, and the rule it resolves
overlapping octets by, are stated in `crates/wiry-core/src/stream.rs` and
repeated in DEVIATIONS E25.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Iterator

from . import PacketList, Packet
from . import _wiry as _b

__all__ = [
    "TCPStream",
    "Streams",
    "streams",
    "TCPSession",
    "IPSession",
    "DefaultSession",
]

SAW_SYN = 1
SAW_FIN = 2
SAW_RST = 4
#: Octets a bound refused, so the direction has a hole `gaps` does not name.
LOSSY = 8
#: The direction reached its size bound and stopped accepting.
TRUNCATED = 16

#: Octets of framing `TCPSession` may add to the capture it was given. Every
#: message it frames costs one frame of headers, so the splice is the one part
#: of reassembly that can outgrow its input; past this, messages are left
#: unframed and their packets pass through as captured.
MAX_REFRAME_GROWTH = 64 << 20


class Half:
    """One direction of a reassembled stream."""

    __slots__ = ("_s", "_i", "_d", "_sum")

    def __init__(self, s: Any, i: int, d: int):
        self._s, self._i, self._d = s, i, d
        self._sum: tuple[int, int, int, int] | None = None

    def _summary(self) -> tuple[int, int, int, int]:
        """`data` is a copy of the whole direction, so everything answerable
        from four numbers is answered from four numbers."""
        if self._sum is None:
            self._sum = self._s.summary(self._i, self._d)
        return self._sum

    @property
    def data(self) -> bytes:
        return self._s.data(self._i, self._d)

    def __len__(self) -> int:
        return self._summary()[0]

    def __bytes__(self) -> bytes:
        return self.data

    @property
    def segments(self) -> list[tuple[int, int, int]]:
        """`(offset, length, packet)` per contributing packet."""
        return self._s.segments(self._i, self._d)

    @property
    def gaps(self) -> list[tuple[int, int]]:
        """`(offset, missing octets)`. Nothing stands in for what is missing,
        so the octets either side of a gap are adjacent in `data`."""
        return self._s.gaps(self._i, self._d)

    @property
    def flags(self) -> int:
        return self._summary()[2]

    @property
    def dropped(self) -> int:
        """Octets a bound refused."""
        return self._summary()[3]

    @property
    def complete(self) -> bool:
        """No hole and no octet given up on."""
        _, gaps, flags, _ = self._summary()
        return not gaps and not flags & (LOSSY | TRUNCATED)

    def packet_at(self, offset: int) -> int | None:
        """Position of the packet the octet at `offset` came from."""
        return self._s.packet_at(self._i, self._d, offset)

    @property
    def app(self) -> str | None:
        """The application protocol, by the same port table and content guards
        one segment goes through."""
        return self._s.app(self._i, self._d)

    def messages(self) -> list[bytes]:
        """Complete application messages, each one whole however many segments
        carried it. Empty where no application protocol is recognised."""
        d = self.data
        return [d[a : a + n] for a, n in self._s.messages(self._i, self._d)]

    def parsed(self) -> list[Packet]:
        """Every complete application message, dissected. This is what a single
        segment could not answer: the first segment of a split request is not
        an HTTP message and does not dissect as one."""
        return [Packet(_rust=p) for p in self._s.parsed(self._i, self._d)]

    def __repr__(self) -> str:
        n, gaps, _, _ = self._summary()
        return f"<Half: {n} bytes, {gaps} gaps>"


class TCPStream:
    """One reassembled connection. Direction 0 is the side that opened it where
    a SYN says so, and otherwise the side the first captured packet came from."""

    __slots__ = ("_s", "_i", "_ends")

    def __init__(self, s: Any, i: int):
        self._s, self._i = s, i
        self._ends: tuple[str, int, str, int, bool, bool] | None = None

    def _endpoints(self) -> tuple[str, int, str, int, bool, bool]:
        if self._ends is None:
            self._ends = self._s.endpoints(self._i)
        return self._ends

    @property
    def key(self) -> str:
        return self._s.key(self._i)

    @property
    def src(self) -> str:
        return self._endpoints()[0]

    @property
    def sport(self) -> int:
        return self._endpoints()[1]

    @property
    def dst(self) -> str:
        return self._endpoints()[2]

    @property
    def dport(self) -> int:
        return self._endpoints()[3]

    @property
    def v6(self) -> bool:
        return self._endpoints()[4]

    @property
    def evicted(self) -> bool:
        """The stream was given up on to stay inside the concurrent-stream
        bound; packets on the same addresses after that start another."""
        return self._endpoints()[5]

    @property
    def client(self) -> Half:
        return Half(self._s, self._i, 0)

    @property
    def server(self) -> Half:
        return Half(self._s, self._i, 1)

    forward = client
    backward = server

    def __iter__(self) -> Iterator[Half]:
        return iter((self.client, self.server))

    def packets(self) -> PacketList:
        """A view over the packets that contributed octets: no copy."""
        return PacketList(self._s.packets(self._i))

    @property
    def complete(self) -> bool:
        return self.client.complete and self.server.complete

    def __repr__(self) -> str:
        return (
            f"<TCPStream {self.key}: {len(self.client)} up, "
            f"{len(self.server)} down>"
        )


class Streams(Mapping):
    """Flow key to `TCPStream`, minted on demand. Two connections between the
    same addresses and ports come back under one key; iterate `all()` for both."""

    __slots__ = ("_s", "_at")

    def __init__(self, s: Any):
        self._s = s
        self._at: dict[str, int] = {}
        for i, k in enumerate(s.keys()):
            self._at.setdefault(k, i)

    def __len__(self) -> int:
        return len(self._at)

    def __iter__(self) -> Iterator[str]:
        return iter(self._at)

    def __getitem__(self, key: str) -> TCPStream:
        return TCPStream(self._s, self._at[key])

    def all(self) -> list[TCPStream]:
        """Every stream, in capture order, including a key seen more than once."""
        return [TCPStream(self._s, i) for i in range(len(self._s))]

    def __repr__(self) -> str:
        return f"<Streams: {len(self._s)} streams>"


def streams(pl: Any) -> Streams:
    """Reassemble every TCP stream in a capture. One crossing, GIL released."""
    return Streams(pl._list.streams())


class DefaultSession:
    """scapy's pass-through session: every packet as it was captured.

    `process` is scapy's contract — one packet in, one packet or `None` out —
    and wiry drives it per packet, on an interface as well as over a file. The
    crossing is this path's contract exactly as `sniff`'s `prn` is: the session
    sees a packet the dissector has already produced, and no Python runs inside
    the dissection loop.

    A `supersession` runs after this one, as scapy's does.
    """

    #: Whether the session has to see every packet before any of them. True
    #: means it reassembles in bulk and so is offline only; `sniff(iface=...)`
    #: asks this, not the class's name.
    needs_capture = False

    def __init__(self, supersession: Any = None):
        if isinstance(supersession, type):
            supersession = supersession()
        self.supersession = supersession

    def process(self, pkt: Any) -> Any:
        if self.supersession is not None:
            return self.supersession.process(pkt)
        return pkt


class _BulkSession(DefaultSession):
    """A session whose work is a whole-capture pass in Rust.

    scapy's incremental `process(pkt)` is refused by name rather than
    approximated: what these do is reassembly, the engine that does it is
    incremental in Rust but reaches Python only in bulk, and a per-packet
    Python stand-in would be a second implementation that could disagree with
    the first. DEVIATIONS E25 states the consequence.
    """

    needs_capture = True

    def process(self, pkt: Any) -> Any:
        raise NotImplementedError(
            f"{type(self).__name__} reassembles over a whole capture and has "
            "no per-packet form: use sniff(offline=...), or PacketList methods"
        )


class IPSession(_BulkSession):
    """Reassembles fragmented IP datagrams, leaving everything else in place.

    The same engine `defragment()` uses, so the two cannot disagree.
    """

    def bulk_process(self, pl: Any) -> Any:
        from .frag import defragment

        return defragment(pl)


class TCPSession(_BulkSession):
    """Reassembles TCP streams, so a packet handed on carries a whole
    application message rather than one segment of one.

    Every complete HTTP message and TLS record a stream reassembled to comes
    back as a packet carrying its first segment's own Ethernet, IP and TCP
    headers with the reassembled octets as payload; the lengths are recomputed
    and so is the IPv4 header checksum. A packet whose octets went into such a
    message is replaced by it. Everything else — every other protocol, and the
    trailing octets of a message that never completed — passes through exactly
    as captured, because reassembly that threw packets away would be a worse
    answer than the capture.

    ``app=False`` turns the message-level step off and leaves the capture
    alone; ``PacketList.streams()`` is the surface for the octets themselves.
    """

    def __init__(self, app: bool = True, supersession: Any = None):
        super().__init__(supersession)
        self.app = app
        self.needs_capture = app

    def process(self, pkt: Any) -> Any:
        if self.app:
            return super().process(pkt)
        return DefaultSession.process(self, pkt)

    def bulk_process(self, pl: Any) -> Any:
        new, _ = pl._list.reassembled()
        return PacketList(new)


def as_session(session: Any) -> Any:
    """`session` may be a class or an instance, as scapy's `sniff` takes it."""
    if session is None:
        return None
    if isinstance(session, type):
        session = session()
    if not callable(getattr(session, "process", None)):
        raise TypeError(
            f"{type(session).__name__} is not a session: it has no process()"
        )
    return session


def needs_capture(session: Any) -> bool:
    """Whether this session's work is a whole-capture pass."""
    return bool(getattr(session, "needs_capture", True))


def bulk_hook(session: Any) -> Any:
    """The whole-capture entry point, where the session has one."""
    if session is None or not needs_capture(session):
        return None
    hook = getattr(session, "bulk_process", None)
    if hook is None:
        raise TypeError(
            f"{type(session).__name__} says needs_capture but has no "
            "bulk_process(): a session is one or the other"
        )
    return hook


def apply_session(session: Any, pl: Any) -> Any:
    """Run a whole-capture session over a capture."""
    hook = bulk_hook(as_session(session))
    return pl if hook is None else hook(pl)
