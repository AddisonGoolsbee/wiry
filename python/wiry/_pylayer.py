# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from scapy: scapy/packet.py (Packet, NoPayload, Raw, Padding),
#   scapy/base_classes.py (Packet_metaclass, SetGen), scapy/fields.py (RawVal)
#   scapy master, upstream commit e2e35c0
#   Copyright (C) Philippe Biondi and the scapy contributors
#
# Changed by the wiry authors:
#   2026-10-03 — transcribed the object model for layers whose contract is a
#     tree of Python objects (ASN.1 first), as a subclass of wiry's Packet;
#     dropped colour themes, canvas dumps and conf.layers registration.
#   2026-10-04 — dissection, building and generator expansion follow scapy's
#     field contract in full (conditional, may-end, mutable, RawVal); SetGen
#     and RawVal came along.
"""Layers modelled in Python, the way scapy models every layer.

A wiry packet is octets in Rust plus a table of spans. That is the wrong shape
for a protocol whose contract is a tree of objects, an X.509 certificate or an
LDAP filter, so those layers are `PyPacket`s: one Python object per layer, with
scapy's fields, payload chain, show(), repr() and building. They stack on top of
a Rust chain (`IP()/UDP()/SNMP()`) as its last layer; see `wiry.Packet`.
"""

from __future__ import annotations

import copy as _copy
import itertools
import json as _json
import time as _time
import types
from typing import Any, Iterator, Optional

from . import Packet, _PacketMeta, VolatileValue


def bytes_encode(x: Any) -> bytes:
    if isinstance(x, bytes):
        return x
    if isinstance(x, (bytearray, memoryview)):
        return bytes(x)
    if isinstance(x, str):
        return x.encode()
    return bytes(x)


def _fix(value: Any) -> Any:
    """One draw of a volatile value."""
    fix = getattr(value, "_fix", None)
    return fix() if fix is not None else value._draw()


class RawVal:
    """Octets inserted as they are, past the field that would encode them:
    `IP(len=RawVal(b"##"))`."""

    def __init__(self, val: Any = b""):
        self.val = bytes_encode(val)

    def __str__(self) -> str:
        return str(self.val)

    def __bytes__(self) -> bytes:
        return self.val

    def __len__(self) -> int:
        return len(self.val)

    def __repr__(self) -> str:
        return "<RawVal [%r]>" % self.val


def _is_gen(x: Any) -> bool:
    """scapy's `Gen`: something a field value iterates over to make one
    packet per element."""
    from .volatile import Net
    return isinstance(x, (PyPacket, Net, SetGen))


def _get_values(value: Any) -> Any:
    """A (start, stop[, step]) tuple of integers is the inclusive range."""
    if (isinstance(value, tuple) and 2 <= len(value) <= 3
            and all(hasattr(i, "__int__") for i in value)):
        return range(*((int(value[0]), int(value[1]) + 1)
                       + tuple(int(v) for v in value[2:])))
    return value


class SetGen:
    def __init__(self, values: Any, _iterpacket: int = 1):
        self._iterpacket = _iterpacket
        if isinstance(values, list):
            self.values = [_get_values(v) for v in values]
        else:
            self.values = [_get_values(values)]

    def __iter__(self) -> Iterator[Any]:
        for i in self.values:
            if ((_is_gen(i) and (self._iterpacket or not isinstance(i, PyPacket)))
                    or isinstance(i, (range, types.GeneratorType))):
                yield from i
            else:
                yield i

    def __len__(self) -> int:
        return sum(1 for _ in self)

    def __repr__(self) -> str:
        return "<SetGen %r>" % self.values


class PyField:
    """The attributes scapy's packet machinery reads off any field."""

    holds_packets = 0
    islist = 0
    ismutable = False
    isconditional = 0
    ismayend = 0

    def __init__(self, name: str, default: Any):
        self.name = name
        self.default = default
        self.owners: list = []

    def register_owner(self, cls: type) -> None:
        self.owners.append(cls)

    def i2h(self, pkt: Any, x: Any) -> Any:
        return x

    def any2i(self, pkt: Any, x: Any) -> Any:
        return x

    def i2repr(self, pkt: Any, x: Any) -> str:
        return repr(self.i2h(pkt, x))

    def do_copy(self, x: Any) -> Any:
        if isinstance(x, list):
            x = x[:]
            for i, v in enumerate(x):
                if isinstance(v, PyPacket):
                    x[i] = v.copy()
            return x
        if hasattr(x, "copy"):
            return x.copy()
        return x

    def copy(self) -> "PyField":
        return _copy.copy(self)

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self.name}>"


class StrField(PyField):
    """Every remaining octet, which is what Raw and Padding are."""

    def any2i(self, pkt: Any, x: Any) -> Any:
        return bytes_encode(x) if isinstance(x, str) else x

    def addfield(self, pkt: Any, s: bytes, val: Any) -> bytes:
        return s + (b"" if val is None else bytes_encode(val))

    def getfield(self, pkt: Any, s: bytes) -> tuple:
        return b"", s


class PyPacketMeta(_PacketMeta):
    """scapy's Packet_metaclass. It deliberately skips `_PacketMeta.__new__`,
    which would register `fields_desc` with Rust as a flat layer."""

    def __new__(mcls, name, bases, dct):
        if "fields_desc" in dct:
            resolved = []
            for f in dct["fields_desc"]:
                if isinstance(f, PyPacketMeta):
                    resolved.extend(f.fields_desc)
                else:
                    resolved.append(f)
        else:
            resolved = next(
                (b.fields_desc for b in bases
                 if isinstance(getattr(b, "fields_desc", None), list)), [])
        if resolved:
            final = []
            for f in resolved:
                if f.name in dct:
                    f = f.copy()
                    f.default = dct.pop(f.name)
                final.append(f)
            dct["fields_desc"] = final
        dct.setdefault("__slots__", ())
        for attr in ("name", "overload_fields"):
            if attr in dct:
                dct["_" + attr] = dct.pop(attr)
        cls = type.__new__(mcls, name, bases, dct)
        cls.__all_slots__ = {
            a for c in cls.__mro__ for a in getattr(c, "__slots__", ())
        }
        cls.aliastypes = [cls] + getattr(cls, "aliastypes", [])
        for f in cls.fields_desc:
            if hasattr(f, "register_owner"):
                f.register_owner(cls)
        return cls

    def __getattr__(cls, attr):
        for base in cls.__mro__:
            desc = base.__dict__.get("fields_desc")
            if isinstance(desc, list):
                for f in desc:
                    if f.name == attr:
                        return f
                break
        raise AttributeError(attr)

    def __dir__(cls):
        return sorted(set(type.__dir__(cls)) | {f.name for f in cls.fields_desc})

    def __call__(cls, *args, **kw):
        if "dispatch_hook" in cls.__dict__:
            try:
                cls = cls.dispatch_hook(*args, **kw)
            except Exception:
                if _debug_dissector():
                    raise
                cls = PyRaw
        return type.__call__(cls, *args, **kw)


def _FlagValue() -> type:
    from ._pyfields import FlagValue
    return FlagValue


def _debug_dissector() -> bool:
    from .capture import conf
    return bool(conf.debug_dissector)


# The Python-side counterparts of `conf.raw_layer` and `conf.padding_layer`.
PyRaw: Any = None
PyPadding: Any = None


class PyPacket(Packet, metaclass=PyPacketMeta):
    __slots__ = (
        "name", "default_fields", "fields", "fieldtype", "overload_fields",
        "overloaded_fields", "packetfields", "original", "explicit",
        "raw_packet_cache", "raw_packet_cache_fields", "post_transforms",
        "stop_dissection_after", "payload", "underlayer", "parent",
        "direction", "comments",
    )
    _name: Optional[str] = None
    _overload_fields: dict = {}
    fields_desc: list = []
    deprecated_fields: dict = {}
    payload_guess: list = []
    show_indent = 1
    show_summary = True
    match_subclass = False
    _class_cache: dict = {}

    def __init__(self, _pkt: Any = b"", post_transform: Any = None,
                 _internal: int = 0, _underlayer: Any = None,
                 _parent: Any = None, stop_dissection_after: Any = None,
                 **fields: Any):
        sa = object.__setattr__
        sa(self, "_stack", [])
        sa(self, "_payload", None)
        sa(self, "_rust", None)
        sa(self, "_written", False)
        sa(self, "time", 0.0 if _internal else _time.time())
        sa(self, "sent_time", None)
        sa(self, "name", type(self).__name__ if self._name is None else self._name)
        sa(self, "default_fields", {})
        sa(self, "overload_fields", self._overload_fields)
        sa(self, "overloaded_fields", {})
        sa(self, "fields", {})
        sa(self, "fieldtype", {})
        sa(self, "packetfields", [])
        sa(self, "payload", NoPayload())
        self.init_fields(bool(_pkt))
        sa(self, "underlayer", _underlayer)
        sa(self, "parent", _parent)
        if isinstance(_pkt, (bytearray, memoryview)):
            _pkt = bytes(_pkt)
        sa(self, "original", _pkt)
        sa(self, "explicit", 0)
        sa(self, "raw_packet_cache", None)
        sa(self, "raw_packet_cache_fields", None)
        sa(self, "wirelen", None)
        sa(self, "direction", None)
        sa(self, "sniffed_on", None)
        sa(self, "comments", None)
        sa(self, "stop_dissection_after", stop_dissection_after)
        if _pkt:
            self.dissect(_pkt)
            if not _internal:
                self.dissection_done(self)
        # Declaration order, which a MultipleTypeField's condition relies on.
        for f in self.fields_desc:
            if f.name in fields:
                value = fields.pop(f.name)
                self.fields[f.name] = value if isinstance(value, RawVal) else \
                    self.get_field(f.name).any2i(self, value)
        for fname, value in fields.items():
            if fname not in self.deprecated_fields:
                raise AttributeError(fname)
            fname = self.deprecated_fields[fname][0]
            self.fields[fname] = value if isinstance(value, RawVal) else \
                self.get_field(fname).any2i(self, value)
        if isinstance(post_transform, list):
            self.post_transforms = post_transform
        elif post_transform is None:
            self.post_transforms = []
        else:
            self.post_transforms = [post_transform]


    def init_fields(self, for_dissect_only: bool = False) -> None:
        cached = PyPacket._class_cache.get(type(self))
        # A MultipleTypeField's default depends on the packet, so a class
        # holding one is set up afresh every time, as scapy does.
        if cached is None or cached is False:
            defaults, fieldtype, packetfields, refs = {}, {}, [], []
            for f in self.fields_desc:
                defaults[f.name] = _copy.deepcopy(f.default)
                fieldtype[f.name] = f
                if f.holds_packets:
                    packetfields.append(f)
                if isinstance(f.default, (list, dict, set, VolatileValue, Packet)):
                    refs.append(f.name)
            cached = (defaults, fieldtype, packetfields, refs)
            if PyPacket._class_cache.get(type(self)) is not False:
                multiple = any(hasattr(f, "flds") for f in self.fields_desc)
                PyPacket._class_cache[type(self)] = False if multiple else cached
        defaults, fieldtype, packetfields, refs = cached
        self.default_fields = defaults
        self.fieldtype = fieldtype
        self.packetfields = packetfields
        if for_dissect_only:
            return
        for fname in refs:
            value = defaults[fname]
            try:
                self.fields[fname] = value.copy()
            except AttributeError:
                self.fields[fname] = value[:]

    def get_field(self, fld: str) -> Any:
        return self.fieldtype[fld]

    def getfieldval(self, attr: str) -> Any:
        if self.deprecated_fields and attr in self.deprecated_fields:
            attr = self.deprecated_fields[attr][0]
        for d in (self.fields, self.overloaded_fields, self.default_fields):
            if attr in d:
                return d[attr]
        return self.payload.getfieldval(attr)

    def getfield_and_val(self, attr: str) -> tuple:
        if self.deprecated_fields and attr in self.deprecated_fields:
            attr = self.deprecated_fields[attr][0]
        for d in (self.fields, self.overloaded_fields, self.default_fields):
            if attr in d:
                return self.fieldtype[attr], d[attr]
        raise ValueError(attr)

    def __getattr__(self, attr: str) -> Any:
        try:
            fld, v = self.getfield_and_val(attr)
        except ValueError:
            return self.payload.__getattr__(attr)
        if fld is None or isinstance(v, RawVal):
            return v
        return fld.i2h(self, v)

    def setfieldval(self, attr: str, val: Any) -> None:
        if self.deprecated_fields and attr in self.deprecated_fields:
            attr = self.deprecated_fields[attr][0]
        if attr in self.default_fields:
            fld = self.get_field(attr)
            if isinstance(val, RawVal) or fld is None:
                self.fields[attr] = val
            else:
                self.fields[attr] = fld.any2i(self, val)
            self.explicit = 0
            self.raw_packet_cache = None
            self.raw_packet_cache_fields = None
            self.wirelen = None
        elif attr == "payload":
            self.remove_payload()
            self.add_payload(val)
        else:
            self.payload.setfieldval(attr, val)

    def __setattr__(self, attr: str, val: Any) -> None:
        if attr in self.__all_slots__:
            object.__setattr__(self, attr, val)
            return
        try:
            self.setfieldval(attr, val)
        except AttributeError:
            # A property a layer defines, LDAP's `serverCreds` for one.
            object.__setattr__(self, attr, val)

    def delfieldval(self, attr: str) -> None:
        if attr in self.fields:
            del self.fields[attr]
            self.explicit = 0
            self.raw_packet_cache = None
            self.raw_packet_cache_fields = None
            self.wirelen = None
        elif attr in self.default_fields:
            pass
        elif attr == "payload":
            self.remove_payload()
        else:
            self.payload.delfieldval(attr)

    def __delattr__(self, attr: str) -> None:
        if attr == "payload":
            self.remove_payload()
        elif attr in self.__all_slots__:
            object.__delattr__(self, attr)
        else:
            try:
                self.delfieldval(attr)
            except AttributeError:
                object.__delattr__(self, attr)

    def __dir__(self) -> list:
        return sorted(set(super().__dir__()) | set(self.default_fields))

    def copy_fields_dict(self, fields: Any) -> Any:
        if fields is None:
            return None
        return {k: self.fieldtype[k].do_copy(v) for k, v in fields.items()}

    def hide_defaults(self) -> None:
        for k, v in list(self.fields.items()):
            if k in self.default_fields and self.default_fields[k] == v:
                del self.fields[k]
        self.payload.hide_defaults()

    def clear_cache(self) -> None:
        self.raw_packet_cache = None
        for fname, fval in self.fields.items():
            if self.get_field(fname).holds_packets:
                if isinstance(fval, PyPacket):
                    fval.clear_cache()
                elif isinstance(fval, list):
                    for sub in fval:
                        if isinstance(sub, PyPacket):
                            sub.clear_cache()
        self.payload.clear_cache()


    def add_payload(self, payload: Any) -> None:
        if payload is None:
            return
        if not isinstance(self.payload, NoPayload):
            self.payload.add_payload(payload)
            return
        if isinstance(payload, PyPacket):
            self.payload = payload
            payload.add_underlayer(self)
            for t in self.aliastypes:
                if t in payload.overload_fields:
                    self.overloaded_fields = payload.overload_fields[t]
                    break
        elif isinstance(payload, (bytes, str, bytearray, memoryview, Packet)):
            # A Rust-modelled layer cannot carry the payload protocol this
            # chain relies on, so it rides along as its octets.
            self.payload = PyRaw(load=bytes_encode(payload))
            self.payload.add_underlayer(self)
        else:
            raise TypeError(
                "payload must be 'Packet', 'bytes', 'str', 'bytearray', or "
                f"'memoryview', not [{payload!r}]")

    def remove_payload(self) -> None:
        self.payload.remove_underlayer(self)
        self.payload = NoPayload()
        self.overloaded_fields = {}

    def add_underlayer(self, underlayer: Any) -> None:
        self.underlayer = underlayer

    def remove_underlayer(self, other: Any) -> None:
        self.underlayer = None

    def add_parent(self, parent: Any) -> None:
        self.parent = parent

    def remove_parent(self, other: Any) -> None:
        self.parent = None

    def copy(self) -> "PyPacket":
        clone = type(self)()
        clone.fields = self.copy_fields_dict(self.fields)
        clone.default_fields = self.copy_fields_dict(self.default_fields)
        clone.overloaded_fields = self.overloaded_fields.copy()
        clone.underlayer = self.underlayer
        clone.parent = self.parent
        clone.explicit = self.explicit
        clone.raw_packet_cache = self.raw_packet_cache
        clone.raw_packet_cache_fields = self.copy_fields_dict(
            self.raw_packet_cache_fields)
        clone.wirelen = self.wirelen
        clone.post_transforms = self.post_transforms[:]
        clone.payload = self.payload.copy()
        clone.payload.add_underlayer(clone)
        clone.time = self.time
        clone.comments = self.comments
        clone.direction = self.direction
        clone.sniffed_on = self.sniffed_on
        return clone

    def __deepcopy__(self, memo: Any) -> "PyPacket":
        return self.copy()

    def clone_with(self, payload: Any = None, **kargs: Any) -> "PyPacket":
        pkt = type(self)()
        pkt.explicit = 1
        pkt.fields = kargs
        pkt.default_fields = self.copy_fields_dict(self.default_fields)
        pkt.overloaded_fields = self.overloaded_fields.copy()
        pkt.time = self.time
        pkt.underlayer = self.underlayer
        pkt.parent = self.parent
        pkt.post_transforms = self.post_transforms
        pkt.raw_packet_cache = self.raw_packet_cache
        pkt.raw_packet_cache_fields = self.copy_fields_dict(
            self.raw_packet_cache_fields)
        pkt.wirelen = self.wirelen
        pkt.comments = self.comments
        pkt.sniffed_on = self.sniffed_on
        pkt.direction = self.direction
        if payload is not None:
            pkt.add_payload(payload)
        return pkt

    def __truediv__(self, other: Any) -> "PyPacket":
        if isinstance(other, PyPacket):
            a, b = self.copy(), other.copy()
            a.add_payload(b)
            return a
        if isinstance(other, (bytes, str, bytearray, memoryview, Packet)):
            return self / PyRaw(load=bytes_encode(other))
        return NotImplemented

    __div__ = __truediv__

    def __rtruediv__(self, other: Any) -> "PyPacket":
        if isinstance(other, (bytes, str, bytearray, memoryview)):
            return PyRaw(load=bytes_encode(other)) / self
        return NotImplemented

    def __mul__(self, other: Any) -> list:
        if isinstance(other, int):
            return [self] * other
        raise TypeError

    __rmul__ = __mul__

    def __bool__(self) -> bool:
        return True

    def __len__(self) -> int:
        return len(bytes(self))


    def _raw_packet_cache_field_value(self, fld: Any, val: Any,
                                      copy: bool = False) -> Any:
        """What, of a mutable field's value, tells a change from none."""
        if fld.holds_packets:
            if fld.islist:
                if copy:
                    return [(fld.do_copy(x.fields), x.payload.raw_packet_cache)
                            for x in val]
                return [(x.fields, x.payload.raw_packet_cache) for x in val]
            if copy:
                return (fld.do_copy(val.fields), val.payload.raw_packet_cache)
            return (val.fields, val.payload.raw_packet_cache)
        if fld.islist or getattr(fld, "ismutable", False):
            return fld.do_copy(val) if copy else val
        return None

    def self_build(self) -> bytes:
        if self.raw_packet_cache is not None and \
                self.raw_packet_cache_fields is not None:
            for fname, fval in self.raw_packet_cache_fields.items():
                fld, val = self.getfield_and_val(fname)
                if self._raw_packet_cache_field_value(fld, val) != fval:
                    self.raw_packet_cache = None
                    self.raw_packet_cache_fields = None
                    self.wirelen = None
                    break
            if self.raw_packet_cache is not None:
                return self.raw_packet_cache
        p = b""
        for f in self.fields_desc:
            val = self.getfieldval(f.name)
            if isinstance(val, RawVal):
                p += bytes(val)
                continue
            try:
                p = f.addfield(self, p, val)
            except Exception as ex:
                try:
                    ex.args = ("While building field '%s': " % f.name
                               + ex.args[0],) + ex.args[1:]
                except (AttributeError, IndexError, TypeError):
                    pass
                raise ex
        return p

    def do_build_payload(self) -> bytes:
        return self.payload.do_build()

    def do_build(self) -> bytes:
        if not self.explicit:
            self = next(iter(self))
        pkt = self.self_build()
        for t in self.post_transforms:
            pkt = t(pkt)
        pay = self.do_build_payload()
        if self.raw_packet_cache is None:
            return self.post_build(pkt, pay)
        return pkt + pay

    def build_padding(self) -> bytes:
        return self.payload.build_padding()

    def build(self) -> bytes:
        p = self.do_build()
        p += self.build_padding()
        return self.build_done(p)

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        return pkt + pay

    def build_done(self, p: bytes) -> bytes:
        return self.payload.build_done(p)

    def __bytes__(self) -> bytes:
        return self.build()

    def __iter__(self) -> Iterator["PyPacket"]:
        """Every packet this one describes: one per element of each
        generator field, with each volatile value drawn."""
        def loop(todo: list, done: dict) -> Iterator["PyPacket"]:
            if todo:
                eltname = todo.pop()
                elt = self.getfieldval(eltname)
                if not _is_gen(elt):
                    if self.get_field(eltname).islist:
                        elt = SetGen([elt])
                    else:
                        elt = SetGen(elt)
                for e in elt:
                    done[eltname] = e
                    yield from loop(todo[:], done)
                return
            payloads = SetGen([None]) if isinstance(self.payload, NoPayload) \
                else self.payload
            for payl in payloads:
                fixed = {
                    k: _fix(v) if isinstance(v, VolatileValue) else v
                    for k, v in done.items()
                }
                yield self.clone_with(payload=payl, **fixed)

        if self.explicit or self.raw_packet_cache is not None:
            todo, done = [], self.fields
        else:
            todo = [k for k, v in itertools.chain(
                self.default_fields.items(), self.overloaded_fields.items())
                if isinstance(v, VolatileValue)] + list(self.fields)
            done = {}
        return loop(todo, done)

    def extract_padding(self, s: bytes) -> tuple:
        return s, None

    def post_dissect(self, s: bytes) -> bytes:
        return s

    def pre_dissect(self, s: bytes) -> bytes:
        return s

    def do_dissect(self, s: bytes) -> bytes:
        raw = s
        self.raw_packet_cache_fields = {}
        for f in self.fields_desc:
            s, fval = f.getfield(self, s)
            if f.isconditional and fval is None:
                continue
            # Kept to notice a change inside a mutable value later, which
            # must drop raw_packet_cache.
            if (f.islist or f.holds_packets or getattr(f, "ismutable", False)) \
                    and fval is not None:
                self.raw_packet_cache_fields[f.name] = \
                    self._raw_packet_cache_field_value(f, fval, copy=True)
            self.fields[f.name] = fval
            if not s and (f.ismayend or (fval is not None and f.isconditional
                                         and f.fld.ismayend)):
                break
        self.raw_packet_cache = raw[:-len(s)] if s else raw
        self.explicit = 1
        return s

    def do_dissect_payload(self, s: bytes) -> None:
        if not s:
            return
        if self.stop_dissection_after and isinstance(self, self.stop_dissection_after):
            self.add_payload(PyRaw(s, _internal=1, _underlayer=self))
            return
        cls = self.guess_payload_class(s)
        try:
            p = cls(s, stop_dissection_after=self.stop_dissection_after,
                    _internal=1, _underlayer=self)
        except KeyboardInterrupt:
            raise
        except Exception:
            if _debug_dissector():
                raise
            p = PyRaw(s, _internal=1, _underlayer=self)
        self.add_payload(p)

    def dissect(self, s: bytes) -> None:
        s = self.pre_dissect(s)
        s = self.do_dissect(s)
        s = self.post_dissect(s)
        payl, pad = self.extract_padding(s)
        self.do_dissect_payload(payl)
        if pad:
            self.add_payload(PyPadding(pad))

    def dissection_done(self, pkt: Any) -> None:
        self.post_dissection(pkt)
        self.payload.dissection_done(pkt)

    def post_dissection(self, pkt: Any) -> None:
        pass

    def guess_payload_class(self, payload: bytes) -> type:
        for t in self.aliastypes:
            for fval, cls in t.payload_guess:
                try:
                    if all(v == self.getfieldval(k) for k, v in fval.items()):
                        return cls
                except AttributeError:
                    pass
        return self.default_payload_class(payload)

    def default_payload_class(self, payload: bytes) -> type:
        return PyRaw

    def decode_payload_as(self, cls: type) -> None:
        s = bytes(self.payload)
        self.payload = cls(s, _internal=1, _underlayer=self)
        pp = self
        while pp.underlayer is not None:
            pp = pp.underlayer
        self.payload.dissection_done(pp)


    def _matches(self, cls: Any, subclass: Any) -> bool:
        if cls is None:
            return True
        if isinstance(cls, str):
            return cls in (type(self).__name__, self._name)
        if subclass:
            return isinstance(cls, type) and isinstance(self, cls)
        if type(self) is cls:
            return True
        # wiry.Raw names the Rust layer; inside a Python chain the same name
        # is this module's Raw.
        return (isinstance(cls, type) and not issubclass(cls, PyPacket)
                and getattr(cls, "_name", None) == self._name is not None)

    def _subpackets(self) -> Iterator["PyPacket"]:
        for f in self.packetfields:
            val = self.getfieldval(f.name)
            if val is None:
                continue
            for sub in (val if f.islist and isinstance(val, list) else [val]):
                if isinstance(sub, PyPacket):
                    yield sub

    def layers(self) -> list:
        out, lyr = [], self
        while lyr:
            out.append(type(lyr))
            lyr = lyr.payload.getlayer(0, _subclass=True)
        return out

    def haslayer(self, cls: Any, _subclass: Any = None) -> bool:
        if _subclass is None:
            _subclass = self.match_subclass or None
        if self._matches(cls, _subclass):
            return True
        for sub in self._subpackets():
            if sub.haslayer(cls, _subclass=_subclass):
                return True
        return self.payload.haslayer(cls, _subclass=_subclass)

    def getlayer(self, cls: Any, nb: int = 1, _track: Any = None,
                 _subclass: Any = None, **flt: Any) -> Any:
        if _subclass is None:
            _subclass = self.match_subclass or None
        if isinstance(cls, int):
            nb, cls = cls + 1, None
        fld = None
        if isinstance(cls, str) and "." in cls:
            cls, fld = cls.split(".", 1)
        if self._matches(cls or None, _subclass):
            if all(self.getfieldval(k) == v for k, v in flt.items()):
                if nb == 1:
                    return self if fld is None else self.getfieldval(fld)
                nb -= 1
        for sub in self._subpackets():
            track: list = []
            ret = sub.getlayer(cls, nb=nb, _track=track, _subclass=_subclass, **flt)
            if ret is not None:
                return ret
            nb = track[0]
        return self.payload.getlayer(cls, nb=nb, _track=_track,
                                     _subclass=_subclass, **flt)

    def firstlayer(self) -> "PyPacket":
        q = self
        while q.underlayer is not None:
            q = q.underlayer
        return q

    def lastlayer(self, layer: Any = None) -> "PyPacket":
        return self.payload.lastlayer(self)

    def iterpayloads(self) -> Iterator["PyPacket"]:
        yield self
        current = self
        while current.payload:
            current = current.payload
            yield current

    def __getitem__(self, cls: Any) -> Any:
        if isinstance(cls, slice):
            lname = cls.start
            ret = self.getlayer(cls.start, nb=cls.stop or 1, **(cls.step or {}))
        else:
            lname = cls
            ret = self.getlayer(cls)
        if ret is None:
            name = lname.__name__ if isinstance(lname, type) else repr(lname)
            raise IndexError(f"Layer [{name}] not found")
        return ret

    def __delitem__(self, cls: Any) -> None:
        del self[cls].underlayer.payload

    def __setitem__(self, cls: Any, val: Any) -> None:
        self[cls].underlayer.payload = val

    def __contains__(self, cls: Any) -> bool:
        return bool(self.haslayer(cls))


    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, type(self)):
            return False
        for f in self.fields_desc:
            if f not in other.fields_desc:
                return False
            if self.getfieldval(f.name) != other.getfieldval(f.name):
                return False
        return self.payload == other.payload

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    __hash__ = None

    def __gt__(self, other: Any) -> Any:
        if isinstance(other, Packet):
            return other < self
        if isinstance(other, bytes):
            return 1
        raise TypeError((self, other))

    def __lt__(self, other: Any) -> Any:
        if isinstance(other, Packet):
            return self.answers(other)
        if isinstance(other, bytes):
            return 1
        raise TypeError((self, other))

    def hashret(self) -> bytes:
        return self.payload.hashret()

    def answers(self, other: Any) -> Any:
        if type(other) is type(self):
            return self.payload.answers(other.payload)
        return 0


    def __repr__(self) -> str:
        s = ""
        for f in self.fields_desc:
            if f.isconditional and not f._evalcond(self):
                continue
            for d in (self.fields, self.overloaded_fields):
                if f.name in d:
                    v = d[f.name]
                    if not (isinstance(v, (list, dict, set)) and len(v) == 0):
                        s += f" {f.name}={f.i2repr(self, v)}"
                    break
        return f"<{type(self).__name__} {s} |{self.payload!r}>"

    def __str__(self) -> str:
        return self.summary()

    def _show_or_dump(self, dump: bool = False, indent: int = 3, lvl: str = "",
                      label_lvl: str = "", first_call: bool = True) -> Optional[str]:
        s = f"{label_lvl}###[ {self.name} ]###\n"
        fields = list(self.fields_desc)
        while fields:
            f = fields.pop(0)
            if f.isconditional and not f._evalcond(self):
                continue
            if hasattr(f, "fields") and isinstance(f.fields, list):
                s += f"{label_lvl + lvl}  {f.name} =\n"
                lvl += " " * indent * self.show_indent
                for i, sub in enumerate(x for x in f.fields if hasattr(self, x.name)):
                    fields.insert(i, sub)
                continue
            pad = max(0, 10 - len(f.name)) * " "
            fvalue = self.getfieldval(f.name)
            if isinstance(fvalue, PyPacket) or (
                    f.islist and f.holds_packets and isinstance(fvalue, list)):
                s += f"{label_lvl + lvl}  \\{f.name}{pad}\\\n"
                for sub in (fvalue if isinstance(fvalue, list) else [fvalue]):
                    s += sub._show_or_dump(dump=dump, indent=indent,
                                           label_lvl=label_lvl + lvl + "   |",
                                           first_call=False)
            else:
                reprval = f.i2repr(self, fvalue)
                if isinstance(reprval, str):
                    reprval = reprval.replace(
                        "\n", "\n" + " " * (len(label_lvl) + len(lvl) + len(f.name) + 4))
                s += f"{label_lvl + lvl}  {f.name}{pad}= {reprval}\n"
        if self.payload:
            s += self.payload._show_or_dump(
                dump=dump, indent=indent,
                lvl=lvl + " " * indent * self.show_indent,
                label_lvl=label_lvl, first_call=False)
        if first_call and not dump:
            print(s)
            return None
        return s

    def show(self, dump: bool = False, indent: int = 3, lvl: str = "",
             label_lvl: str = "") -> Optional[str]:
        return self._show_or_dump(dump, indent, lvl, label_lvl)

    def show_str(self) -> str:
        return self._show_or_dump(dump=True)

    def show2(self, dump: bool = False, indent: int = 3, lvl: str = "",
              label_lvl: str = "") -> Optional[str]:
        return type(self)(bytes(self)).show(dump, indent, lvl, label_lvl)

    def show2_str(self) -> str:
        return type(self)(bytes(self)).show_str()

    def display(self, *args: Any, **kargs: Any) -> None:
        self.show(*args, **kargs)

    def mysummary(self) -> Any:
        return ""

    def _do_summary(self) -> tuple:
        found, s, needed = self.payload._do_summary()
        ret = ""
        if not found or type(self) in needed:
            ret = self.mysummary()
            if isinstance(ret, tuple):
                ret, n = ret
                needed += n
        if ret or needed:
            found = 1
        if not ret:
            ret = type(self).__name__ if self.show_summary else ""
        ret = f"{ret} / {s}" if ret and s else f"{ret}{s}"
        return found, ret, needed

    def summary(self, intern: int = 0) -> str:
        return self._do_summary()[1]

    def sprintf(self, fmt: str, relax: int = 1) -> str:
        escape = {"%": "%", "(": "{", ")": "}"}
        while "{" in fmt:
            i = fmt.rindex("{")
            j = fmt[i + 1:].index("}")
            cond = fmt[i + 1:i + j + 1]
            k = cond.find(":")
            if k < 0:
                raise ValueError(f"Bad condition in format string: [{cond}]")
            cond, format_ = cond[:k], cond[k + 1:]
            res = False
            if cond[0] == "!":
                res, cond = True, cond[1:]
            if self.haslayer(cond):
                res = not res
            if not res:
                format_ = ""
            fmt = fmt[:i] + format_ + fmt[i + j + 2:]
        s = ""
        while "%" in fmt:
            i = fmt.index("%")
            s += fmt[:i]
            fmt = fmt[i + 1:]
            if fmt and fmt[0] in escape:
                s += escape[fmt[0]]
                fmt = fmt[1:]
                continue
            try:
                i = fmt.index("%")
                sfclsfld = fmt[:i]
                parts = sfclsfld.split(",")
                if len(parts) == 1:
                    f, clsfld = "s", parts[0]
                elif len(parts) == 2:
                    f, clsfld = parts
                else:
                    raise ValueError
                if "." in clsfld:
                    cls, fld = clsfld.split(".")
                else:
                    cls, fld = type(self).__name__, clsfld
                num = 1
                if ":" in cls:
                    cls, snum = cls.split(":")
                    num = int(snum)
                fmt = fmt[i + 1:]
            except Exception:
                raise ValueError(f"Bad format string [%{fmt[:25]}{fmt[25:] and '...'}]")
            if fld == "time":
                val = _time.strftime("%H:%M:%S.%%06i", _time.localtime(float(self.time))) \
                    % int((self.time - int(self.time)) * 1000000)
            elif cls == type(self).__name__ and hasattr(self, fld):
                if num > 1:
                    val = self.payload.sprintf(f"%{f},{cls}:{num - 1}.{fld}%", relax)
                    f = "s"
                else:
                    try:
                        val = self.getfieldval(fld)
                    except AttributeError:
                        val = getattr(self, fld)
                    if f[-1] == "r":
                        f = f[:-1] or "s"
                    elif fld in self.fieldtype:
                        val = self.fieldtype[fld].i2repr(self, val)
            else:
                val = self.payload.sprintf(f"%{sfclsfld}%", relax)
                f = "s"
            s += ("%" + f) % val
        return s + fmt

    def _command(self, json: bool = False) -> list:
        out = []
        items = ((x.name, self.getfieldval(x.name)) for x in self.fields_desc) \
            if json else iter(self.fields.items())
        for fn, fv in items:
            fld = self.get_field(fn)
            if isinstance(fv, (list, dict, set)) and not fv and not fld.default:
                continue
            if isinstance(fv, PyPacket):
                fv = dict(fv._command(json=True)) if json else fv.command()
            elif fld.islist and fld.holds_packets and isinstance(fv, list):
                if json:
                    fv = [dict(PyPacket._command(y, json=True)) for y in fv]
                else:
                    fv = "[%s]" % ",".join(map(PyPacket.command, fv))
            elif fld.islist and isinstance(fv, list):
                cmds = [getattr(x, "command", lambda x=x: repr(x))() for x in fv]
                fv = cmds if json else "[%s]" % ",".join(cmds)
            elif isinstance(fv, _FlagValue()):
                fv = int(fv)
            elif callable(getattr(fv, "command", None)):
                fv = fv.command(json=json)
            elif json:
                fv = fv.decode("utf-8", errors="backslashreplace") \
                    if isinstance(fv, bytes) else fld.i2h(self, fv)
            else:
                fv = repr(fld.i2h(self, fv))
            out.append((fn, fv))
        return out

    def command(self) -> str:
        c = "%s(%s)" % (type(self).__name__,
                        ", ".join("%s=%s" % x for x in self._command()))
        pc = self.payload.command()
        return c + "/" + pc if pc else c

    def json(self) -> str:
        dump = _json.dumps(dict(self._command(json=True)))
        pc = self.payload.json()
        return dump[:-1] + ', "payload": %s}' % pc if pc else dump

    def fragment(self, *args: Any, **kargs: Any) -> list:
        return self.payload.fragment(*args, **kargs)


    @classmethod
    def _rebuild_pkt(cls, raw: bytes) -> "PyPacket":
        return cls(raw)

    def __reduce__(self) -> tuple:
        state = {"time": self.time, "sent_time": self.sent_time,
                 "direction": self.direction, "sniffed_on": self.sniffed_on,
                 "wirelen": self.wirelen, "comments": self.comments}
        return type(self)._rebuild_pkt, (self.build(),), state

    def __setstate__(self, state: dict) -> "PyPacket":
        for k, v in state.items():
            setattr(self, k, v)
        return self

    # wiry's Rust-side helpers have nothing to hand back for a Python layer.
    def template(self, args: Any = None) -> None:
        return None

    def _spec(self) -> list:
        raise TypeError(f"{type(self).__name__} is modelled in Python")


class NoPayload(PyPacket):
    __slots__ = ()
    __singl__: Any = None

    def __new__(cls, *args: Any, **kargs: Any) -> "NoPayload":
        singl = cls.__dict__.get("__singl__")
        if singl is None:
            singl = Packet.__new__(cls)
            cls.__singl__ = singl
            PyPacket.__init__(singl)
        return singl

    def __init__(self, *args: Any, **kargs: Any) -> None:
        pass

    def dissection_done(self, pkt: Any) -> None:
        pass

    def add_payload(self, payload: Any) -> None:
        raise ValueError("Can't add payload to NoPayload instance")

    def remove_payload(self) -> None:
        pass

    def add_underlayer(self, underlayer: Any) -> None:
        pass

    def remove_underlayer(self, other: Any) -> None:
        pass

    def add_parent(self, parent: Any) -> None:
        pass

    def remove_parent(self, other: Any) -> None:
        pass

    def copy(self) -> "NoPayload":
        return self

    def clear_cache(self) -> None:
        pass

    def __repr__(self) -> str:
        return ""

    def __str__(self) -> str:
        return ""

    def __bytes__(self) -> bytes:
        return b""

    def __bool__(self) -> bool:
        return False

    def do_build(self) -> bytes:
        return b""

    def build(self) -> bytes:
        return b""

    def build_padding(self) -> bytes:
        return b""

    def build_done(self, p: bytes) -> bytes:
        return p

    def getfieldval(self, attr: str) -> Any:
        raise AttributeError(attr)

    def getfield_and_val(self, attr: str) -> Any:
        raise AttributeError(attr)

    def __getattr__(self, attr: str) -> Any:
        raise AttributeError(attr)

    def setfieldval(self, attr: str, val: Any) -> None:
        raise AttributeError(attr)

    def delfieldval(self, attr: str) -> None:
        raise AttributeError(attr)

    def hide_defaults(self) -> None:
        pass

    def __iter__(self) -> Iterator[Any]:
        return iter([])

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, NoPayload)

    __hash__ = None

    def hashret(self) -> bytes:
        return b""

    def answers(self, other: Any) -> bool:
        return isinstance(other, (NoPayload, PyPadding))

    def haslayer(self, cls: Any, _subclass: Any = None) -> bool:
        return False

    def getlayer(self, cls: Any, nb: int = 1, _track: Any = None,
                 _subclass: Any = None, **flt: Any) -> None:
        if _track is not None:
            _track.append(nb)
        return None

    def fragment(self, *args: Any, **kargs: Any) -> list:
        raise ValueError("cannot fragment this packet")

    def show(self, *args: Any, **kargs: Any) -> None:
        pass

    def sprintf(self, fmt: str, relax: int = 1) -> str:
        if relax:
            return "??"
        raise ValueError(f"Format not found [{fmt}]")

    def _do_summary(self) -> tuple:
        return 0, "", []

    def layers(self) -> list:
        return []

    def lastlayer(self, layer: Any = None) -> Any:
        return layer or self

    def command(self) -> str:
        return ""

    def json(self) -> str:
        return ""


class Raw(PyPacket):
    name = "Raw"
    fields_desc = [StrField("load", b"")]

    def __init__(self, _pkt: Any = b"", *args: Any, **kwargs: Any):
        if _pkt and not isinstance(_pkt, bytes):
            _pkt = bytes_encode(_pkt)
        super().__init__(_pkt, *args, **kwargs)

    def answers(self, other: Any) -> int:
        return 1


class Padding(Raw):
    name = "Padding"

    def self_build(self) -> bytes:
        return b""

    def build_padding(self) -> bytes:
        load = bytes_encode(self.load) if self.raw_packet_cache is None \
            else self.raw_packet_cache
        return load + self.payload.build_padding()


PyRaw = Raw
PyPadding = Padding


def fuzz(p: PyPacket, _inplace: int = 0) -> PyPacket:
    """Replace every default this chain still uses with a random value."""
    if not _inplace:
        p = p.copy()
    q = p
    while not isinstance(q, NoPayload):
        fresh = {}
        for f in q.fields_desc:
            if f.default is not None:
                rnd = f.randval()
                if rnd is not None:
                    fresh[f.name] = rnd
        q.default_fields.update(fresh)
        q = q.payload
    return p
