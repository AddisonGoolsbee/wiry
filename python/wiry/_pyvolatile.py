# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from scapy: scapy/volatile.py
#   scapy master, upstream commit e2e35c0
#   Copyright (C) Philippe Biondi and the scapy contributors
#
# Changed by the wiry authors:
#   2026-10-04 — transcribed the random values the Python-modelled layers'
#     fields fuzz with, drawing from Python's `random` as scapy's do.
"""Random values for the Python-modelled layers.

wiry's own volatile values draw in Rust from a spec, which is what lets a
template expand millions of packets without Python. These draw from Python's
`random`, in scapy's order, over ranges and kinds the Rust spec cannot hold.
Each subclasses wiry's class of the same name where there is one, so an
`isinstance` check written against either holds.
"""

from __future__ import annotations

import random
import string
import time
import uuid
from typing import Any, Optional

from . import volatile as _v


def _bytes(x: Any) -> bytes:
    if isinstance(x, bytes):
        return x
    if isinstance(x, str):
        return x.encode()
    return bytes(x)


class PyVolatile(_v.VolatileValue):
    """A value drawn in Python by `_fix`, rather than from a Rust spec."""

    __slots__ = ()

    def __init__(self) -> None:
        super().__init__(("python",))

    def _draw(self) -> Any:
        return self._fix()

    def _fix(self) -> Any:
        raise NotImplementedError

    def __repr__(self) -> str:
        return "<%s>" % type(self).__name__


class _Numeral(PyVolatile):
    __slots__ = ()

    def __int__(self) -> int:
        return int(self._fix())

    def __index__(self) -> int:
        return int(self)

    def __bool__(self) -> bool:
        return bool(self._fix())

    def __add__(self, other: Any) -> Any:
        return self._fix() + other

    def __radd__(self, other: Any) -> Any:
        return other + self._fix()

    def __sub__(self, other: Any) -> Any:
        return self._fix() - other

    def __rsub__(self, other: Any) -> Any:
        return other - self._fix()

    def __mul__(self, other: Any) -> Any:
        return self._fix() * other

    def __rmul__(self, other: Any) -> Any:
        return other * self._fix()

    def __lt__(self, other: Any) -> bool:
        return self._fix() < other

    def __le__(self, other: Any) -> bool:
        return self._fix() <= other

    def __gt__(self, other: Any) -> bool:
        return self._fix() > other

    def __ge__(self, other: Any) -> bool:
        return self._fix() >= other


class RandNum(_Numeral, _v.RandNum):
    """`random.randrange(min, max + 1)`, over any range."""

    __slots__ = ("min", "max")

    def __init__(self, min: int, max: int):
        PyVolatile.__init__(self)
        self.min = min
        self.max = max

    def _fix(self) -> int:
        return random.randrange(self.min, self.max + 1)


class RandNumExpo(RandNum):
    __slots__ = ("lambd", "base")

    def __init__(self, lambd: float, base: int = 0):
        PyVolatile.__init__(self)
        self.lambd = lambd
        self.base = base

    def _fix(self) -> int:
        return self.base + int(round(random.expovariate(self.lambd)))


class RandFloat(_Numeral):
    __slots__ = ("min", "max")

    def __init__(self, min: float, max: float):
        super().__init__()
        self.min = min
        self.max = max

    def _fix(self) -> float:
        return random.uniform(self.min, self.max)


def _ranged(name: str, lo: int, hi: int, base: type = RandNum) -> type:
    def __init__(self) -> None:
        RandNum.__init__(self, lo, hi)
    return type(name, (base,), {"__slots__": (), "__init__": __init__})


RandByte = _ranged("RandByte", 0, 2**8 - 1)
RandSByte = _ranged("RandSByte", -2**7, 2**7 - 1)
RandShort = _ranged("RandShort", 0, 2**16 - 1)
RandSShort = _ranged("RandSShort", -2**15, 2**15 - 1)
RandInt = _ranged("RandInt", 0, 2**32 - 1)
RandSInt = _ranged("RandSInt", -2**31, 2**31 - 1)
RandLong = _ranged("RandLong", 0, 2**64 - 1)
RandSLong = _ranged("RandSLong", -2**63, 2**63 - 1)


class RandEnumKeys(RandNum):
    """One key of a mapping."""

    __slots__ = ("enum",)

    def __init__(self, enum: Any, seed: Any = None):
        self.enum = list(enum)
        RandNum.__init__(self, 0, len(self.enum) - 1)

    def _fix(self) -> Any:
        return self.enum[RandNum._fix(self)]


class RandChoice(PyVolatile, _v.RandChoice):
    __slots__ = ("_choice",)

    def __init__(self, *args: Any):
        if not args:
            raise TypeError("RandChoice needs at least one choice")
        PyVolatile.__init__(self)
        self._choice = list(args)

    def _fix(self) -> Any:
        return random.choice(self._choice)


class _RandString(PyVolatile):
    __slots__ = ()

    def __str__(self) -> str:
        v = self._fix()
        return v.decode(errors="backslashreplace") if isinstance(v, bytes) else str(v)

    def __bytes__(self) -> bytes:
        return _bytes(self._fix())

    def __mul__(self, n: int) -> Any:
        return self._fix() * n


class RandString(_RandString, _v.RandString):
    """`size` characters of `chars`, the size itself drawn when volatile."""

    __slots__ = ("size", "chars")

    def __init__(self, size: Any = None,
                 chars: Any = string.ascii_uppercase + string.ascii_lowercase + string.digits):
        PyVolatile.__init__(self)
        self.size = RandNumExpo(0.01) if size is None else size
        self.chars = chars

    def _fix(self) -> bytes:
        out = b""
        for _ in range(int(self.size)):
            c = random.choice(self.chars)
            out += c.encode() if isinstance(c, str) else bytes([c])
        return out


class RandBin(RandString, _v.RandBin):
    __slots__ = ()

    def __init__(self, size: Any = None, chars: bytes = bytes(range(256))):
        RandString.__init__(self, size, chars)


class RandTermString(RandBin):
    __slots__ = ("term",)

    def __init__(self, size: Any, term: Any):
        self.term = _bytes(term)
        RandBin.__init__(self, size)
        self.chars = self.chars.replace(self.term, b"")

    def _fix(self) -> bytes:
        return RandBin._fix(self) + self.term


class RandIP(_RandString, _v.RandIP):
    __slots__ = ()

    def __init__(self, iptemplate: str = "0.0.0.0/0"):
        PyVolatile.__init__(self)

    def _fix(self) -> str:
        n = random.getrandbits(32)
        return ".".join(str(n >> s & 0xFF) for s in (24, 16, 8, 0))


class RandIP6(_RandString, _v.RandIP6):
    __slots__ = ()

    def __init__(self, ip6template: str = "**"):
        PyVolatile.__init__(self)

    def _fix(self) -> str:
        n = random.getrandbits(128)
        return ":".join("%x" % (n >> s & 0xFFFF) for s in range(112, -1, -16))


class RandMAC(_RandString, _v.RandMAC):
    __slots__ = ()

    def __init__(self, _template: str = "*"):
        PyVolatile.__init__(self)

    def _fix(self) -> str:
        return ":".join("%02x" % random.getrandbits(8) for _ in range(6))


class RandUUID(_RandString):
    __slots__ = ()

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__()

    def _fix(self) -> uuid.UUID:
        return uuid.UUID(int=random.getrandbits(128), version=4)


class RandOID(_RandString):
    """Depth and arcs drawn from exponential distributions, as scapy's are."""

    __slots__ = ()

    def _fix(self) -> str:
        depth = int(round(random.expovariate(0.1)))
        return ".".join(
            str(int(round(random.expovariate(0.01)))) for _ in range(1 + depth))


class _AutoTime(_Numeral):
    __slots__ = ("diff",)

    def __init__(self, base: Optional[float] = None, diff: Optional[float] = None):
        super().__init__()
        self.diff = diff if diff is not None else (
            0 if base is None else time.time() - base)


class AutoTime(_AutoTime):
    __slots__ = ()

    def _fix(self) -> float:
        return time.time() - self.diff


class IntAutoTime(_AutoTime):
    __slots__ = ()

    def _fix(self) -> int:
        return int(time.time() - self.diff)


class ZuluTime(_RandString):
    __slots__ = ("diff",)

    def __init__(self, diff: float = 0):
        super().__init__()
        self.diff = diff

    def _fix(self) -> str:
        return time.strftime("%y%m%d%H%M%SZ", time.gmtime(time.time() + self.diff))


class GeneralizedTime(_RandString):
    __slots__ = ("diff",)

    def __init__(self, diff: float = 0):
        super().__init__()
        self.diff = diff

    def _fix(self) -> str:
        return time.strftime("%Y%m%d%H%M%SZ", time.gmtime(time.time() + self.diff))
