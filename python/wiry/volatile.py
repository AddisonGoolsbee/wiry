# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from scapy: scapy/utils.py (`corrupt_bytes`, `corrupt_bits` only)
#   scapy 2.7.0
#   Copyright (C) Philippe Biondi and the scapy contributors
#
# Changed by the wiry authors:
#   2026-09-18 — transcribed the two corruption helpers, whose draw order from
#     the interpreter's `random` is their interface; clamped `p` to a fraction
#     and `n` to the number of positions, and made empty input return empty
#     rather than raise.
"""Generators: one declaration that multiplies into many packets.

Each class below carries a small spec tuple; the whole set crosses into Rust
once and the product is walked there.
"""

from __future__ import annotations

import ipaddress
import random
from typing import Any, Iterator, Optional, Sequence

from . import _wiry as _b

__all__ = [
    "VolatileValue", "RandNum", "RandByte", "RandShort", "RandInt", "RandLong",
    "RandIP", "RandIP6", "RandMAC", "RandString", "RandBin", "RandChoice",
    "RandEnumKeys", "Net", "Net6", "fuzz", "corrupt_bytes", "corrupt_bits",
    "set_rand_seed",
]

STRING_CHARS = (b"abcdefghijklmnopqrstuvwxyz"
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")


def set_rand_seed(seed: int) -> None:
    """Seed every volatile value, so a fuzz run repeats exactly.

    Two streams, because they answer to different things. Templates draw from a
    splitmix64 in Rust, which is what keeps a sixteen-million-packet expansion
    out of Python. `corrupt_bytes` and `corrupt_bits` draw from the
    interpreter's `random`, where scapy's draw order is the interface rather
    than an implementation detail — so **this reseeds the process-wide `random`
    module**, and `random.seed(n)` alone also steers the two corrupt helpers.
    """
    _b.set_rand_seed(int(seed) & 0xFFFFFFFFFFFFFFFF)
    random.seed(seed)


class VolatileValue:
    """A value that is drawn afresh every time it is realised."""

    __slots__ = ("_spec",)

    def __init__(self, spec: tuple):
        self._spec = spec

    def _gen(self) -> tuple:
        return self._spec

    def _draw(self) -> Any:
        return _b.rand_value(self._spec)

    def __int__(self) -> int:
        v = self._draw()
        if isinstance(v, int):
            return v
        if isinstance(v, bytes):
            return int.from_bytes(v, "big")
        return int(v)

    def __index__(self) -> int:
        return int(self)

    def __bytes__(self) -> bytes:
        v = self._draw()
        if isinstance(v, bytes):
            return v
        if isinstance(v, int):
            return str(v).encode()
        return str(v).encode("latin-1")

    def __str__(self) -> str:
        v = self._draw()
        if isinstance(v, bytes):
            return v.decode("latin-1")
        return str(v)

    def __len__(self) -> int:
        return len(bytes(self))

    def __eq__(self, other: object) -> bool:
        """Compares one fresh draw, so two reads of the same field differ."""
        if isinstance(other, VolatileValue):
            other = other._draw()
        return self._draw() == other

    __hash__ = object.__hash__

    def __repr__(self) -> str:
        return f"<{type(self).__name__}>"


class RandNum(VolatileValue):
    """A random integer in ``[min, max]``."""

    __slots__ = ()

    def __init__(self, min: int, max: int):
        lo, hi = int(min), int(max)
        if lo > hi:
            lo, hi = hi, lo
        super().__init__(("rnum", lo, hi))


class RandByte(RandNum):
    """A random octet."""

    __slots__ = ()

    def __init__(self) -> None:
        super().__init__(0, 0xFF)


class RandShort(RandNum):
    """A random 16-bit integer."""

    __slots__ = ()

    def __init__(self) -> None:
        super().__init__(0, 0xFFFF)


class RandInt(RandNum):
    """A random 32-bit integer."""

    __slots__ = ()

    def __init__(self) -> None:
        super().__init__(0, 0xFFFFFFFF)


class RandLong(RandNum):
    """A random 64-bit integer."""

    __slots__ = ()

    def __init__(self) -> None:
        super().__init__(0, 0xFFFFFFFFFFFFFFFF)


class RandString(VolatileValue):
    """Random text of `size` octets, or of a random length when unset."""

    __slots__ = ()

    def __init__(self, size: Optional[int] = None, chars: bytes = STRING_CHARS):
        lo, hi = (1, 20) if size is None else (int(size), int(size))
        super().__init__(("rbytes", max(lo, 0), max(hi, 0), bytes(chars)))


class RandBin(VolatileValue):
    """Random octets, any value."""

    __slots__ = ()

    def __init__(self, size: Optional[int] = None):
        lo, hi = (1, 20) if size is None else (int(size), int(size))
        super().__init__(("rbytes", max(lo, 0), max(hi, 0), None))


class RandChoice(VolatileValue):
    """One of the given values, drawn afresh each time."""

    __slots__ = ()

    def __init__(self, *args: Any):
        if not args:
            raise ValueError("RandChoice needs at least one value")
        super().__init__(("rpick", list(args)))


class RandEnumKeys(RandChoice):
    """One key of a mapping, which is how an enumerated field is fuzzed."""

    __slots__ = ()

    def __init__(self, enum: Any):
        RandChoice.__init__(self, *list(enum))


def _addr_int(family: int, text: Any) -> int:
    cls = ipaddress.IPv4Address if family == 4 else ipaddress.IPv6Address
    return int(cls(str(text).strip()))


class Net:
    """A range of IPv4 addresses: a CIDR block, or a first and last address.

    Iterating yields address strings. A packet field holding one is a template
    whose expansion walks the range, so ``IP(dst=Net("10.0.0.0/8"))`` is
    sixteen million packets that are never all built at once.

    A hostname is deliberately not accepted: resolving one would put DNS in the
    build path (DEVIATIONS E13).
    """

    __slots__ = ("lo", "hi", "scope")

    _family = 4
    _width = 4
    _bits = 32

    def __init__(self, net: Any, stop: Any = None, scope: Any = None):
        if stop is not None:
            self.lo = _addr_int(self._family, net)
            self.hi = _addr_int(self._family, stop)
            if self.lo > self.hi:
                self.lo, self.hi = self.hi, self.lo
        else:
            text = str(net)
            if "%" in text:
                text, _, inline = text.partition("%")
                scope = inline if scope is None else scope
            self.lo, self.hi = self._parse_cidr(text)
        self.scope = scope

    @classmethod
    def _parse_cidr(cls, text: str) -> tuple[int, int]:
        addr, sep, plen = text.partition("/")
        base = _addr_int(cls._family, addr)
        if not sep:
            return base, base
        try:
            bits = int(plen)
        except ValueError as exc:
            raise ValueError(f"bad prefix length in {text!r}") from exc
        if not 0 <= bits <= cls._bits:
            raise ValueError(f"bad prefix length in {text!r}")
        host = (1 << (cls._bits - bits)) - 1
        return base & ~host, (base & ~host) | host

    def _gen(self) -> tuple:
        return ("addrs", self.lo, self.hi, self._width)

    def _str(self, n: int) -> str:
        cls = ipaddress.IPv4Address if self._family == 4 else ipaddress.IPv6Address
        return str(cls(n))

    def __iter__(self) -> Iterator[str]:
        for n in range(self.lo, self.hi + 1):
            yield self._str(n)

    def __iterlen__(self) -> int:
        """The exact count, which ``len()`` cannot report past ``sys.maxsize``."""
        return self.hi - self.lo + 1

    def __len__(self) -> int:
        return self.__iterlen__()

    def __getitem__(self, i: int) -> str:
        n = self.__iterlen__()
        if not -n <= i < n:
            raise IndexError("address out of range")
        return self._str(self.lo + (i % n))

    def _as_net(self, other: Any) -> Optional["Net"]:
        if isinstance(other, Net):
            return other if type(other) is type(self) else None
        try:
            return type(self)(other)
        except (ValueError, TypeError):
            return None

    def __contains__(self, other: Any) -> bool:
        net = self._as_net(other)
        return net is not None and self.lo <= net.lo and net.hi <= self.hi

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Net):
            return NotImplemented
        return (type(self), self.lo, self.hi) == (type(other), other.lo, other.hi)

    def __hash__(self) -> int:
        return hash((type(self).__name__, self.lo, self.hi))

    def __repr__(self) -> str:
        span = self.__iterlen__()
        bits = span.bit_length() - 1
        if span == 1 << bits and self.lo & (span - 1) == 0:
            return f'{type(self).__name__}("{self._str(self.lo)}/{self._bits - bits}")'
        return f'{type(self).__name__}("{self._str(self.lo)}", "{self._str(self.hi)}")'

    def __str__(self) -> str:
        return self._str(self.lo)


class Net6(Net):
    """A range of IPv6 addresses. See ``Net``."""

    __slots__ = ()

    _family = 6
    _width = 16
    _bits = 128


def _pair_gen(value: Sequence[Any]) -> Optional[tuple]:
    if len(value) != 2:
        return None
    a, b = value
    if isinstance(a, bool) or isinstance(b, bool):
        return None
    if isinstance(a, int) and isinstance(b, int):
        return ("range", min(a, b), max(a, b))
    if isinstance(a, str) and isinstance(b, str):
        for cls in (Net, Net6):
            try:
                lo, hi = _addr_int(cls._family, a), _addr_int(cls._family, b)
            except ValueError:
                continue
            return ("addrs", min(lo, hi), max(lo, hi), cls._width)
    return None


def as_generator(value: Any, kind: str = "") -> Any:
    """A CIDR string is a ``Net`` only in an address field: elsewhere a slash
    is just a character."""
    if isinstance(value, (VolatileValue, Net)):
        return value
    if isinstance(value, (list, tuple)):
        return value
    if isinstance(value, str) and "/" in value:
        if kind == "ipv4":
            return _net_or_none(Net, value)
        if kind == "ipv6":
            return _net_or_none(Net6, value)
    return None


def _net_or_none(cls: type, text: str) -> Any:
    try:
        return cls(text)
    except ValueError:
        return None


def gen_spec(value: Any, kind: str = "") -> Optional[tuple]:
    """The generator description a field value crosses the boundary as."""
    gen = as_generator(value, kind)
    if gen is None:
        return None
    if isinstance(gen, (VolatileValue, Net)):
        return gen._gen()
    if isinstance(gen, tuple):
        pair = _pair_gen(gen)
        if pair is not None:
            return pair
    if not gen:
        raise ValueError("an empty list generates no packets")
    return ("seq", [gen_spec(v, kind) or ("one", v) for v in gen])


class _RandAddr(VolatileValue):
    """An address is an integer on the wire and text to a reader."""

    __slots__ = ()

    _width = 4

    def _text(self, n: int) -> str:
        raise NotImplementedError

    def __bytes__(self) -> bytes:
        return int(self).to_bytes(self._width, "big")

    def __str__(self) -> str:
        return self._text(int(self))


class RandIP(_RandAddr):
    """A random IPv4 address, from the whole space or from one block."""

    __slots__ = ()

    def __init__(self, template: Any = "0.0.0.0/0"):
        net = template if isinstance(template, Net) else Net(template)
        super().__init__(("raddr", net.lo, net.hi, 4))

    def _text(self, n: int) -> str:
        return str(ipaddress.IPv4Address(n))


class RandIP6(_RandAddr):
    """A random IPv6 address, from the whole space or from one block."""

    __slots__ = ()

    _width = 16

    def __init__(self, template: Any = "::/0"):
        net = template if isinstance(template, Net6) else Net6(template)
        super().__init__(("raddr", net.lo, net.hi, 16))

    def _text(self, n: int) -> str:
        return str(ipaddress.IPv6Address(n))


class RandMAC(_RandAddr):
    """A random MAC address. A template fixes a leading run of octets:
    ``RandMAC("00:11:22")`` randomises the low three."""

    __slots__ = ()

    _width = 6

    def __init__(self, template: str = "*"):
        fixed = [p for p in str(template).split(":") if p not in ("", "*")]
        if len(fixed) > 6:
            raise ValueError(f"not a MAC template: {template!r}")
        try:
            prefix = [int(p, 16) for p in fixed]
        except ValueError as exc:
            raise ValueError(f"not a MAC template: {template!r}") from exc
        if any(not 0 <= p <= 0xFF for p in prefix):
            raise ValueError(f"not a MAC template: {template!r}")
        free = (6 - len(prefix)) * 8
        base = 0
        for p in prefix:
            base = base << 8 | p
        lo = base << free
        super().__init__(("raddr", lo, lo | ((1 << free) - 1), 6))

    def _text(self, n: int) -> str:
        return ":".join(f"{b:02x}" for b in n.to_bytes(6, "big"))


def _fuzz_gen(kind: str, bits: int) -> Optional[Any]:
    if kind == "ipv4":
        return RandIP()
    if kind == "ipv6":
        return RandIP6()
    if kind == "mac":
        return RandMAC()
    if kind in ("uint", "le_uint", "flags"):
        return RandNum(0, (1 << bits) - 1) if 0 < bits <= 64 else None
    if kind == "bytes" and 0 < bits <= 1 << 16:
        return RandBin(bits // 8)
    return None


def _how_many(positions: int, p: float, n: Optional[int]) -> int:
    """How many positions to touch, never more than there are.

    `p` is a fraction, so it clamps to one: unclamped, `p=1e9` used to spin for
    a minute and a half with the GIL held. At least one position is touched,
    which is scapy's contract and why its own default corrupts a five-octet
    string that 1% of would round to nothing.
    """
    if n is None:
        n = max(1, int(min(max(float(p), 0.0), 1.0) * positions))
    return min(max(int(n), 0), positions)


def _octets(data: Any) -> bytes:
    return data.encode("latin-1") if isinstance(data, str) else bytes(data)


def corrupt_bytes(data: Any, p: float = 0.01, n: Optional[int] = None) -> bytes:
    """Replace whole octets at random: `n` of them, or a fraction `p`.

    The positions are distinct and every one of them changes, so `n` octets
    asked for is `n` octets different.
    """
    raw = bytearray(_octets(data))
    if not raw:
        return b""
    for i in random.sample(range(len(raw)), _how_many(len(raw), p, n)):
        raw[i] = (raw[i] + random.randint(1, 255)) % 256
    return bytes(raw)


def corrupt_bits(data: Any, p: float = 0.01, n: Optional[int] = None) -> bytes:
    """Flip single bits at random: `n` of them, or a fraction `p`."""
    raw = bytearray(_octets(data))
    if not raw:
        return b""
    for i in random.sample(range(len(raw) * 8), _how_many(len(raw) * 8, p, n)):
        raw[i // 8] ^= 1 << (i % 8)
    return bytes(raw)


def fuzz(pkt: Any) -> Any:
    """A template whose unset, non-computed fields are randomised.

    Lengths, checksums and anything the caller pinned are left alone, so the
    result is a well-formed packet with random contents rather than noise.
    """
    from . import Packet, _OPAQUE

    if not isinstance(pkt, Packet):
        raise TypeError(f"fuzz() takes a packet, not {type(pkt).__name__}")
    if not pkt._spec_live:
        raise NotImplementedError(
            "fuzz() takes a packet being built; a dissected one, or one whose "
            "fields have been written through, cannot go back to a field spec"
        )
    stack = []
    for lname, fields in pkt._stack:
        chosen = dict(fields)
        if lname not in _OPAQUE:
            for fname, bits, kind, computed, conditional in _b.field_specs(lname):
                if computed or conditional or fname in chosen:
                    continue
                gen = _fuzz_gen(kind, bits)
                if gen is not None:
                    chosen[fname] = gen
        stack.append((lname, chosen))
    return Packet(_stack=stack, _payload=pkt._payload)
