"""IP fragmentation and reassembly.

IPv4 from RFC 791 §3.2, IPv6 from RFC 8200 §4.5. ``fragsize`` counts the
payload octets one fragment carries, rounded down to the 8-octet unit a
fragment offset is measured in.

Reassembly stays in Rust for a ``PacketList`` and for a plain list alike, and
the two must agree byte for byte.
"""

from __future__ import annotations

from typing import Any

from . import PacketList, Packet
from . import _wiry as _b

__all__ = ["fragment", "fragment6", "defragment", "defrag", "defragment6"]

# RFC 894: 1500-octet Ethernet MTU less the 20-octet IPv4 header.
FRAGSIZE = 1480

# RFC 8200 §5: 1280-octet minimum link MTU, less the IPv6 header and the
# Fragment header this inserts.
FRAGSIZE6 = 1232


def _link_of(pkt: Any) -> str:
    names = pkt.layers()
    if not names:
        raise ValueError("empty packet")
    return names[0]


def _dissected(data: bytes, link: str, when: float) -> Packet:
    return Packet(_rust=_b.dissect(data, link), time=when)


def fragment(pkt: Any, fragsize: int = FRAGSIZE) -> list[Packet]:
    """Split an IP datagram into fragments.

    A datagram short enough already, or one with Don't Fragment set, comes back
    as a single packet.
    """
    link = _link_of(pkt)
    frames = _b.fragment_frame(bytes(pkt), link, int(fragsize))
    when = getattr(pkt, "time", 0.0)
    return [_dissected(f, link, when) for f in frames]


def fragment6(pkt: Any, fragsize: int = FRAGSIZE6) -> list[Packet]:
    """`fragment`, with the default RFC 8200 §5 minimum-MTU payload."""
    return fragment(pkt, fragsize)


def _reassembled(packets: Any) -> tuple[Any, list[int]]:
    """The pieces in input order, and one kind per piece: 0 carried no
    fragment, 1 was reassembled, 2 is a fragment whose datagram never
    completed. Both backends answer in this one shape, so the split below
    cannot drift between them."""
    if isinstance(packets, PacketList):
        new, kinds = packets._list.defragmented()
        return PacketList(new), list(kinds)
    items = list(packets)
    rows: list = [None] * len(items)
    # The engine is told a link type rather than guessing one, so a list that
    # mixes them takes one call each; anything else dissects all but the first
    # group as the wrong protocol and quietly reassembles nothing.
    by_link: dict[str, list[int]] = {}
    for i, p in enumerate(items):
        by_link.setdefault(_link_of(p), []).append(i)
    for link, at in by_link.items():
        whole, done, missing = _b.defragment_frames([bytes(items[i]) for i in at], link)
        for k in whole:
            rows[at[k]] = (items[at[k]], 0)
        for k, f in done:
            rows[at[k]] = (_dissected(f, link, items[at[k]].time), 1)
        for k in missing:
            rows[at[k]] = (items[at[k]], 2)
    kept = [r for r in rows if r is not None]
    return [p for p, _ in kept], [k for _, k in kept]


def _take(pieces: Any, kinds: list[int], want: int) -> Any:
    at = [i for i, k in enumerate(kinds) if k == want]
    if isinstance(pieces, PacketList):
        return PacketList(pieces._list.select(at))
    return [pieces[i] for i in at]


def defragment(plist: Any) -> Any:
    """Reassemble every fragmented datagram, leaving everything else in place.

    A reassembled datagram takes the position of its first fragment; fragments
    that never completed are kept as they were.
    """
    return _reassembled(plist)[0]


def defrag(plist: Any) -> tuple:
    """`(not fragmented, reassembled, still incomplete)`."""
    pieces, kinds = _reassembled(plist)
    return tuple(_take(pieces, kinds, want) for want in (0, 1, 2))


def defragment6(packets: Any) -> Packet | None:
    """The one datagram these fragments reassemble to, or `None`."""
    done = _take(*_reassembled(packets), 1)
    return done[0] if len(done) == 1 else None
