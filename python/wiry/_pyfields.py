# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from scapy: scapy/fields.py (MultipleTypeField, PacketField)
#   scapy master, upstream commit e2e35c0
#   Copyright (C) Philippe Biondi and the scapy contributors
#
# Changed by the wiry authors:
#   2026-10-03 — transcribed the two generic fields X.509 builds on.
"""The generic scapy fields Python-modelled layers need beyond ASN.1."""

from __future__ import annotations

import inspect
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

