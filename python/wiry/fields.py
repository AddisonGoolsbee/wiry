# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from scapy: scapy/fields.py
#   scapy 2.7.0
#   Copyright (C) Philippe Biondi and the scapy contributors
#
# Changed by the wiry authors:
#   2026-10-03 — enumerated fields: a dict or list of names, a default given by name

"""Field classes for declaring your own layer.

A field carries a name, a width in bits, a kind and a default. Subclassing
``Packet`` with a ``fields_desc`` hands the description to Rust once, at
class-definition time. Widths are summed in declaration order to give each
field its bit offset, so bit fields may straddle byte boundaries as long as the
layer as a whole is a whole number of bytes.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Sequence

__all__ = [
    "Field", "ByteField", "XByteField", "ShortField", "XShortField",
    "LEShortField", "IntField", "XIntField", "LEIntField", "LongField",
    "XLongField", "LELongField", "BitField", "IPField", "IP6Field", "MACField",
    "StrFixedLenField", "StrField", "FlagsField", "ByteEnumField",
    "XByteEnumField", "ShortEnumField", "XShortEnumField", "IntEnumField",
    "XIntEnumField", "LEShortEnumField", "LEIntEnumField", "BitEnumField",
]


class Field:
    """A named, fixed-width integer. The base of every other field class."""

    kind = "uint"

    __slots__ = ("name", "default", "size", "i2s")

    def __init__(self, name: str, default: Any = 0, size: int = 8):
        self.name = name
        self.default = default
        self.size = size
        self.i2s: dict[int, str] = {}

    def spec(self) -> tuple:
        """What Rust needs: name, bits, kind, default, wide default, flags."""
        return (self.name, self.size, self.kind, int(self.default or 0), None, [])

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self.name}>"


class ByteField(Field):
    def __init__(self, name: str, default: Any = 0):
        super().__init__(name, default, 8)


class XByteField(ByteField):
    pass


class ShortField(Field):
    def __init__(self, name: str, default: Any = 0):
        super().__init__(name, default, 16)


class XShortField(ShortField):
    pass


class IntField(Field):
    def __init__(self, name: str, default: Any = 0):
        super().__init__(name, default, 32)


class XIntField(IntField):
    pass


class LongField(Field):
    def __init__(self, name: str, default: Any = 0):
        super().__init__(name, default, 64)


class XLongField(LongField):
    pass


class LEShortField(ShortField):
    kind = "le_uint"


class LEIntField(IntField):
    kind = "le_uint"


class LELongField(LongField):
    kind = "le_uint"


class BitField(Field):
    def __init__(self, name: str, default: Any = 0, size: int = 1):
        super().__init__(name, default, size)


class IPField(Field):
    kind = "ipv4"

    def __init__(self, name: str, default: Any = "0.0.0.0"):
        super().__init__(name, default, 32)

    def spec(self) -> tuple:
        v = self.default
        n = v if isinstance(v, int) else int(ipaddress.IPv4Address(v))
        return (self.name, 32, self.kind, n, None, [])


class IP6Field(Field):
    kind = "ipv6"

    def __init__(self, name: str, default: Any = "::"):
        super().__init__(name, default, 128)

    def spec(self) -> tuple:
        v = self.default
        b = bytes(v) if isinstance(v, (bytes, bytearray)) else ipaddress.IPv6Address(v).packed
        return (self.name, 128, self.kind, 0, b, [])


class MACField(Field):
    kind = "mac"

    def __init__(self, name: str, default: Any = "00:00:00:00:00:00"):
        super().__init__(name, default, 48)

    def spec(self) -> tuple:
        v = self.default
        if isinstance(v, (bytes, bytearray)):
            b = bytes(v)
        else:
            b = bytes(int(p, 16) for p in str(v).replace("-", ":").split(":"))
        if len(b) != 6:
            raise ValueError(f"{self.name}: {self.default!r} is not a MAC address")
        return (self.name, 48, self.kind, 0, b, [])


#: Bit offsets are a u16, so this is the widest field Rust can describe.
#: Checked here because padding a default to the declared width would
#: otherwise allocate that much first.
MAX_FIELD_OCTETS = 0xFFFF // 8


class StrFixedLenField(Field):
    kind = "bytes"

    def __init__(self, name: str, default: Any = b"", length: int = 0):
        if isinstance(length, bool) or not isinstance(length, int) or length < 0:
            raise ValueError(
                f"{name}: length must be a non-negative integer, not {length!r}"
            )
        if length > MAX_FIELD_OCTETS:
            raise ValueError(
                f"{name}: length {length} is over the {MAX_FIELD_OCTETS} octets "
                "a declared field can describe"
            )
        super().__init__(name, default, length * 8)
        self.length = length

    __slots__ = ("length",)

    def spec(self) -> tuple:
        v = self.default or b""
        b = v.encode() if isinstance(v, str) else bytes(v)
        b = b[: self.length].ljust(self.length, b"\x00")
        return (self.name, self.size, self.kind, 0, b, [])


class StrField(Field):
    """Bytes running to the end of the packet. Must come last."""

    kind = "varbytes"

    def __init__(self, name: str, default: Any = b""):
        super().__init__(name, default, 0)

    def spec(self) -> tuple:
        return (self.name, 0, self.kind, 0, None, [])


class FlagsField(Field):
    kind = "flags"

    __slots__ = ("names",)

    def __init__(self, name: str, default: Any = 0, size: int = 8, names: Any = ()):
        super().__init__(name, default, size)
        self.names = list(names)

    def spec(self) -> tuple:
        v = self.default
        if isinstance(v, str):
            from . import _bits_from

            v = _bits_from(v, self.names)
        return (self.name, self.size, self.kind, int(v or 0), None, list(self.names))


class _EnumField(Field):
    """An integer whose values have names: a dict of value to name, or a list
    naming 0, 1, 2 and so on. Reading gives the integer, rendering the name,
    and assigning accepts either."""

    def __init__(self, name: str, default: Any, size: int, enum: Any):
        super().__init__(name, default, size)
        if isinstance(enum, (list, tuple)):
            enum = dict(enumerate(enum))
        self.i2s = {int(k): str(v) for k, v in dict(enum).items()}
        if isinstance(default, str):
            s2i = {v: k for k, v in self.i2s.items()}
            if default not in s2i:
                raise ValueError(f"{name}: default {default!r} is not one of its names")
            self.default = s2i[default]


def _sized(size: int, kind: str = "uint"):
    def __init__(self, name: str, default: Any, enum: Any):
        _EnumField.__init__(self, name, default, size, enum)

    return type("", (_EnumField,), {"__init__": __init__, "kind": kind, "__slots__": ()})


class ByteEnumField(_sized(8)):
    __slots__ = ()


class XByteEnumField(ByteEnumField):
    __slots__ = ()


class ShortEnumField(_sized(16)):
    __slots__ = ()


class XShortEnumField(ShortEnumField):
    __slots__ = ()


class IntEnumField(_sized(32)):
    __slots__ = ()


class XIntEnumField(IntEnumField):
    __slots__ = ()


class LEShortEnumField(_sized(16, "le_uint")):
    __slots__ = ()


class LEIntEnumField(_sized(32, "le_uint")):
    __slots__ = ()


class BitEnumField(_EnumField):
    __slots__ = ()

    def __init__(self, name: str, default: Any, size: int, enum: Any):
        super().__init__(name, default, size, enum)


def specs(fields_desc: Sequence[Any]) -> list[tuple]:
    """The wire description of a whole ``fields_desc``."""
    return [(*f.spec(), sorted(f.i2s.items())) for f in fields_desc]
