# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from scapy: scapy/fields.py (MultipleTypeField, PacketField, Field,
#   FieldLenField, StrLenField)
#   scapy master, upstream commit e2e35c0
#   Copyright (C) Philippe Biondi and the scapy contributors
#
# Changed by the wiry authors:
#   2026-10-03 — transcribed the generic fields X.509 and LDAP build on.
"""The generic scapy fields Python-modelled layers need beyond ASN.1."""

from __future__ import annotations

import inspect
import struct
from typing import Any

from ._pylayer import PyField, PyPacket, PyPadding, fuzz


class MultipleTypeField:
    """A field whose type depends on the packet holding it: the first
    `(field, condition)` whose condition holds, else `dflt`."""

    __slots__ = ["flds", "dflt", "hints", "name", "default"]
    isconditional = False
    ismayend = False

    def __init__(self, flds: list, dflt: Any) -> None:
        self.hints = {x[0]: x[2] for x in flds if len(x) == 3}
        self.flds = [(x[0], x[1]) for x in flds]
        self.dflt = dflt
        self.default = None
        self.name = self.dflt.name

    def _iterate_fields_cond(self, pkt: Any, val: Any, use_val: bool) -> Any:
        for fld, cond in self.flds:
            if isinstance(cond, tuple):
                if use_val:
                    if val is None:
                        val = self.dflt.default
                    if cond[1](pkt, val):
                        return fld
                    continue
                cond = cond[0]
            if cond(pkt):
                return fld
        return self.dflt

    def _find_fld_pkt(self, pkt: Any) -> Any:
        return self._iterate_fields_cond(pkt, None, False)

    def _find_fld_pkt_val(self, pkt: Any, val: Any) -> tuple:
        fld = self._iterate_fields_cond(pkt, val, True)
        if val is None:
            val = fld.default
        return fld, val

    def _find_fld(self) -> Any:
        """The field for whichever packet is up the call stack.

        scapy's own hack, kept because its API hands a field no packet in
        the places that call this."""
        frame = inspect.currentframe().f_back.f_back
        while frame is not None:
            pkt = frame.f_locals.get("self")
            if pkt is not None and isinstance(pkt, tuple(self.dflt.owners)):
                if not pkt.default_fields:
                    return self.dflt
                return self._find_fld_pkt(pkt)
            frame = frame.f_back
        return self.dflt

    def __getattr__(self, attr: str) -> Any:
        return getattr(self._find_fld(), attr)

    @property
    def fld(self) -> Any:
        return self._find_fld()

    def getfield(self, pkt: Any, s: bytes) -> tuple:
        return self._find_fld_pkt(pkt).getfield(pkt, s)

    def addfield(self, pkt: Any, s: bytes, val: Any) -> bytes:
        fld, val = self._find_fld_pkt_val(pkt, val)
        return fld.addfield(pkt, s, val)

    def any2i(self, pkt: Any, val: Any) -> Any:
        fld, val = self._find_fld_pkt_val(pkt, val)
        return fld.any2i(pkt, val)

    def h2i(self, pkt: Any, val: Any) -> Any:
        fld, val = self._find_fld_pkt_val(pkt, val)
        return fld.h2i(pkt, val)

    def i2h(self, pkt: Any, val: Any) -> Any:
        fld, val = self._find_fld_pkt_val(pkt, val)
        return fld.i2h(pkt, val)

    def i2m(self, pkt: Any, val: Any) -> Any:
        fld, val = self._find_fld_pkt_val(pkt, val)
        return fld.i2m(pkt, val)

    def i2len(self, pkt: Any, val: Any) -> int:
        fld, val = self._find_fld_pkt_val(pkt, val)
        return fld.i2len(pkt, val)

    def i2repr(self, pkt: Any, val: Any) -> str:
        fld, val = self._find_fld_pkt_val(pkt, val)
        hint = " (%s)" % self.hints[fld] if fld in self.hints else ""
        return fld.i2repr(pkt, val) + hint

    def register_owner(self, cls: type) -> None:
        for fld, _ in self.flds:
            fld.owners.append(cls)
        self.dflt.owners.append(cls)

    def get_fields_list(self) -> list:
        return [self]


class PacketField(PyField):
    """One packet of class `cls`, taking what follows it as its own payload
    and handing back whatever that packet called padding."""

    holds_packets = 1

    def __init__(self, name: str, default: Any, pkt_cls: Any):
        super().__init__(name, default)
        self.cls = pkt_cls

    def i2m(self, pkt: Any, i: Any) -> bytes:
        return b"" if i is None else bytes(i)

    def m2i(self, pkt: Any, m: bytes) -> Any:
        try:
            return self.cls(m, _parent=pkt)
        except TypeError:
            return self.cls(m)

    def any2i(self, pkt: Any, x: Any) -> Any:
        if x and pkt and hasattr(x, "add_parent"):
            x.add_parent(pkt)
        return x

    def addfield(self, pkt: Any, s: bytes, val: Any) -> bytes:
        return s + self.i2m(pkt, val)

    def getfield(self, pkt: Any, s: bytes) -> tuple:
        i = self.m2i(pkt, s)
        remain = b""
        r = i.lastlayer() if isinstance(i, PyPacket) else None
        if isinstance(r, PyPadding):
            del r.underlayer.payload
            remain = r.load
        return remain, i

    def randval(self) -> Any:
        return fuzz(self.cls())



class Field(PyField):
    """A fixed-width value packed with a `struct` format."""

    def __init__(self, name: str, default: Any, fmt: str = "H"):
        super().__init__(name, default)
        self.fmt = fmt if fmt[0] in "@=<>!" else "!" + fmt
        self.struct = struct.Struct(self.fmt)
        self.sz = self.struct.size

    def i2m(self, pkt: Any, x: Any) -> Any:
        return 0 if x is None else x

    def m2i(self, pkt: Any, x: Any) -> Any:
        return x

    def i2len(self, pkt: Any, x: Any) -> int:
        return self.sz

    def addfield(self, pkt: Any, s: bytes, val: Any) -> bytes:
        return s + self.struct.pack(self.i2m(pkt, val))

    def getfield(self, pkt: Any, s: bytes) -> tuple:
        return s[self.sz:], self.m2i(pkt, self.struct.unpack_from(s)[0])


class FieldLenField(Field):
    """The length of another field, computed when left as None."""

    def __init__(self, name: str, default: Any, length_of: Any = None,
                 fmt: str = "H", count_of: Any = None,
                 adjust: Any = lambda pkt, x: x):
        super().__init__(name, default, fmt)
        self.length_of = length_of
        self.count_of = count_of
        self.adjust = adjust

    def i2m(self, pkt: Any, x: Any) -> Any:
        if x is None and pkt is not None:
            if self.length_of is not None:
                fld, fval = pkt.getfield_and_val(self.length_of)
                f = fld.i2len(pkt, fval)
            elif self.count_of is not None:
                fld, fval = pkt.getfield_and_val(self.count_of)
                f = fld.i2count(pkt, fval)
            else:
                raise ValueError("Field should have either length_of or count_of")
            x = self.adjust(pkt, f)
        elif x is None:
            x = 0
        return x


class StrLenField(PyField):
    """Octets whose length another field gives."""

    def __init__(self, name: str, default: Any, length_from: Any = None,
                 max_length: Any = None):
        super().__init__(name, default)
        self.length_from = length_from
        self.max_length = max_length

    def any2i(self, pkt: Any, x: Any) -> Any:
        return x.encode() if isinstance(x, str) else x

    def i2m(self, pkt: Any, x: Any) -> bytes:
        return b"" if x is None else bytes(x)

    def i2len(self, pkt: Any, x: Any) -> int:
        return len(self.i2m(pkt, x))

    def addfield(self, pkt: Any, s: bytes, val: Any) -> bytes:
        return s + self.i2m(pkt, val)

    def getfield(self, pkt: Any, s: bytes) -> tuple:
        n = (self.length_from or (lambda x: 0))(pkt)
        if n == 0:
            return s, b""
        return s[n:], s[:n]
