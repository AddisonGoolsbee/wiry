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

    __slots__ = ("_s", "_i", "_d")

    def __init__(self, s: Any, i: int, d: int):
        self._s, self._i, self._d = s, i, d

    @property
    def data(self) -> bytes:
        return self._s.data(self._i, self._d)

    def __len__(self) -> int:
        return len(self.data)

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
        return self._s.state(self._i, self._d)[0]

    @property
    def dropped(self) -> int:
        """Octets a bound refused."""
        return self._s.state(self._i, self._d)[1]

    @property
    def complete(self) -> bool:
        """No hole and no octet given up on."""
        return not self.gaps and not self.flags & (LOSSY | TRUNCATED)

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
        app = self.app
        if app is None:
            return []
        return [Packet(_rust=_b.dissect(m, app)) for m in self.messages()]

    def __repr__(self) -> str:
        return f"<Half: {len(self)} bytes, {len(self.gaps)} gaps>"


class TCPStream:
    """One reassembled connection. Direction 0 is the side that opened it where
    a SYN says so, and otherwise the side the first captured packet came from."""

    __slots__ = ("_s", "_i")

    def __init__(self, s: Any, i: int):
        self._s, self._i = s, i

    @property
    def key(self) -> str:
        return self._s.keys()[self._i]

    @property
    def src(self) -> str:
        return self._s.endpoints(self._i)[0]

    @property
    def sport(self) -> int:
        return self._s.endpoints(self._i)[1]

    @property
    def dst(self) -> str:
        return self._s.endpoints(self._i)[2]

    @property
    def dport(self) -> int:
        return self._s.endpoints(self._i)[3]

    @property
    def evicted(self) -> bool:
        """The stream was given up on to stay inside the concurrent-stream
        bound; packets on the same addresses after that start another."""
        return self._s.endpoints(self._i)[5]

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
    """scapy's pass-through session: every packet as it was captured."""

    def __init__(self, **kw: Any):
        self.kw = kw

    def process(self, pl: Any) -> Any:
        return pl


class IPSession:
    """Reassembles fragmented IP datagrams, leaving everything else in place.

    The same engine `defragment()` uses, so the two cannot disagree.
    """

    def __init__(self, **kw: Any):
        self.kw = kw

    def process(self, pl: Any) -> Any:
        from .frag import defragment

        return defragment(pl)


class TCPSession:
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

    def __init__(self, app: bool = True, **kw: Any):
        self.app = app
        self.kw = kw

    def process(self, pl: Any) -> Any:
        if not self.app:
            return pl
        new, _ = pl._list.reassembled()
        return PacketList(new)


def apply_session(session: Any, pl: Any) -> Any:
    """`session` may be a class or an instance, as scapy's `sniff` takes it."""
    if session is None:
        return pl
    if isinstance(session, type):
        session = session()
    process = getattr(session, "process", None)
    if process is None:
        raise TypeError(
            f"{type(session).__name__} is not a session: it has no process()"
        )
    return process(pl)
