"""wiry: fast packet dissection and crafting with a familiar API."""

from __future__ import annotations

import atexit
import contextlib
import gzip
import os
import sys
import tempfile
import warnings
import weakref
import zlib
from typing import Any, Iterator, Optional, Sequence

from . import _wiry as _b

__version__ = _b.__version__

_COLUMNAR = ("to_arrow", "to_polars", "to_pandas")

_FRAG = ("fragment", "fragment6", "defragment", "defrag", "defragment6")

_STREAM = (
    "streams", "TCPStream", "Streams", "TCPSession", "IPSession",
    "DefaultSession",
)

_CAPTURE = (
    "sniff", "AsyncSniffer", "send", "sendp", "sr", "sr1", "srp", "srp1",
    "get_if_list", "get_if_addr", "get_if_hwaddr", "get_working_if",
    "interfaces", "conf", "capture_available", "capture_backend",
    "CaptureUnavailable",
)

_TOOLS = (
    "traceroute", "TracerouteResult", "arping", "srloop", "srploop",
    "getmacbyip",
)

_SOCKETS = (
    "SuperSocket", "OfflineSocket", "StreamSocket", "L2Socket",
    "L2ListenSocket", "L3Socket", "ObjectPipe", "select_objects", "MTU",
    "IterSocket", "SimpleSocket", "StreamSocketPeekless", "SSLStreamSocket",
    "L3RawSocket", "L3RawSocket6", "L2ListenTcpdump", "ETH_P_IP",
    "ETH_P_IPV6", "ETH_P_8021Q", "SOL_PACKET", "PACKET_AUXDATA",
    "SO_TIMESTAMPNS", "TP_STATUS_VLAN_VALID", "TP_STATUS_VLAN_TPID_VALID",
    "tpacket_auxdata",
)

_AUTOMATON = ("ATMT", "Automaton")

_ANSMACHINE = ("AnsweringMachine", "AnsweringMachineTCP", "AnsweringMachineUDP")

_ROUTE = ("Route", "Route6", "read_routes", "read_routes6", "in6_getifaddr")

_DISCOVER = ("ls", "lsc", "explore", "field_table", "FieldInfo")

_CONSOLE = ("interact", "save_session", "load_session")

from ._pynames import EXPORTS as _PY_EXPORTS, PY_MODELLED as _PY_MODELLED  # noqa: E402

_EAGER = (
    "Packet", "PacketList", "SndRcvList", "QueryAnswer", "FlagValue", "rdpcap", "wrpcap", "wrpcapng",
    "PcapReader", "PcapWriter", "PcapNgWriter", "raw", "known_layers",
    "bind_layers", "bind_bottom_up", "bind_top_down",
    "VolatileValue", "RandNum", "RandByte", "RandShort", "RandInt", "RandLong",
    "RandIP", "RandIP6", "RandMAC", "RandString", "RandBin", "RandChoice",
    "RandEnumKeys", "Net", "Net6", "fuzz", "corrupt_bytes", "corrupt_bits",
    "set_rand_seed", "expand", "NoPayload",
)

_SENDRECV = (
    "sndrcv", "sr_func", "SndRcvHandler", "srflood", "srpflood", "sr1flood",
    "srp1flood", "sndrcvflood", "sendpfast", "bridge_and_sniff", "tshark",
    "debug",
)

_ANSWERING = (
    "ARP_am", "BOOTP_am", "DHCP_am", "DNS_am", "ICMPEcho_am", "LLMNR_am",
    "mDNS_am", "NBNS_am", "ReferenceAM",
    "farpd", "bootpd", "dhcpd", "dnsd", "icmpechod", "llmnrd", "mdnsd",
    "nbnsd",
)

_CONFIG = (
    "Conf", "VERSION", "isPyPy", "isCryptographyValid", "isCryptographyAdvanced",
    "isCryptographyBackendCompatible", "crypto_validator",
    "scapy_delete_temp_files",
)

_ARCH = (
    "get_if_addr6", "get_if_raw_addr", "get_if_raw_addr6", "read_nameservers",
    "SIOCGIFHWADDR",
)

# Module -> the names it exports lazily: importing wiry touches none of them.
_LAZY = {
    "discover": _DISCOVER, "console": _CONSOLE, "columnar": _COLUMNAR,
    "capture": _CAPTURE, "frag": _FRAG, "stream": _STREAM,
    "tools": _TOOLS, "supersocket": _SOCKETS,
    "automaton": _AUTOMATON, "ansmachine": _ANSMACHINE, "route": _ROUTE,
    "sendrecv": _SENDRECV, "answering": _ANSWERING, "config": _CONFIG,
    "arch": _ARCH, **_PY_EXPORTS,
}

_HOME = {name: mod for mod, names in _LAZY.items() for name in names}

# Derived, because __dir__ answers from it: a lazy name missing here would be
# invisible to dir(wiry) and to anything probing it for capability.
__all__ = list(_EAGER) + list(_HOME)


def __getattr__(name: str) -> Any:
    mod = _HOME.get(name)
    if mod is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib
    return getattr(importlib.import_module(f".{mod}", __name__), name)


def __dir__() -> list[str]:
    """Lazily exported names never enter the module globals, so dir() omits
    them without this."""
    return sorted(set(globals()) | set(__all__))


def _is_bytes(x: Any) -> bool:
    return isinstance(x, (bytes, bytearray, memoryview))


def _to_bytes(x: Any, what: str = "value") -> bytes:
    """Byte-oriented strings encode as latin-1. Anything else is refused,
    because `bytes(n)` would allocate n zero octets instead of failing."""
    if isinstance(x, str):
        return x.encode("latin-1")
    if _is_bytes(x):
        return bytes(x)
    if _is_py(x):
        return bytes(x)
    raise TypeError(f"{what} must be bytes or str, not {type(x).__name__}")


class GroupItem(tuple):
    """One element of a repeating group. Still the `(name, fields)` pair it
    always was, so it compares equal to one; its fields also read as
    attributes, as the elements of scapy's PacketListField do."""

    __slots__ = ()

    def __getattr__(self, name: str) -> Any:
        for k, v in self[1]:
            if k == name:
                return v
        raise AttributeError(f"{self[0]} has no field {name!r}")


def _group_item(x: Any) -> Any:
    if (isinstance(x, tuple) and len(x) == 2 and isinstance(x[0], str)
            and isinstance(x[1], list)
            and all(isinstance(p, tuple) and len(p) == 2 and isinstance(p[0], str)
                    for p in x[1])):
        return GroupItem((x[0], [(k, _nested(v)) for k, v in x[1]]))
    return x


def _nested(v: Any) -> Any:
    return [_group_item(x) for x in v] if isinstance(v, list) else v


_FLAG_NAMES: dict[tuple[str, str], tuple[str, ...] | None] = {}

# Tested first on every field read, so a non-flag field costs one set lookup.
_FLAG_FIELDS: set[str] = set()

# Layer name -> the field whose read returns its parsed item list. Line-oriented
# and BER layers answer under their own name rather than "options".
_PARSED_FIELD: dict[str, str] = {}


def _bits_from(text: str, names: Sequence[str]) -> int:
    """Parse a flag string into its bits.

    Substring containment is wrong here: with names `a`, `ab`, `b` the string
    `"ab"` sets all three. Tokenise instead, longest name first, so a name that
    starts with another still matches whole.
    """
    if not text:
        return 0
    if "+" in text:
        bits = 0
        for tok in text.split("+"):
            if not tok or tok not in names:
                raise ValueError(f"unknown flag {tok!r}")
            bits |= 1 << list(names).index(tok)
        return bits
    bits, at = 0, 0
    while at < len(text):
        best, width = -1, 0
        for i, n in enumerate(names):
            if n and len(n) > width and text.startswith(n, at):
                best, width = i, len(n)
        if best < 0:
            raise ValueError(f"unknown flag in {text!r} at offset {at}")
        bits |= 1 << best
        at += width
    return bits


def _flag_names(layer: str, field: str) -> tuple[str, ...] | None:
    names = _FLAG_NAMES.get((layer, field), ())
    if names == ():
        got = _b.flag_names(layer, field)
        names = tuple(got) if got else None
        _FLAG_NAMES[(layer, field)] = names
    return names


class FlagValue:
    """A flag field: an integer, a set of named bits and a string at once.

    `.SA` is the AND of the two bits, not an equality test. Assigning to a bit
    writes through to the packet the value was read from.
    """

    __slots__ = ("_names", "_bits", "_owner", "_layer", "_field")

    def __init__(self, bits: int, names: Sequence[str], owner: Any = None,
                 layer: int = 0, field: str = ""):
        object.__setattr__(self, "_bits", int(bits))
        object.__setattr__(self, "_names", tuple(names))
        object.__setattr__(self, "_owner", owner)
        object.__setattr__(self, "_layer", layer)
        object.__setattr__(self, "_field", field)

    @classmethod
    def from_str(cls, text: str, names: Sequence[str], owner: Any = None,
                 layer: int = 0, field: str = "") -> "FlagValue":
        return cls(_bits_from(text, names), names, owner, layer, field)

    def _coerce(self, other: Any) -> int:
        if isinstance(other, FlagValue):
            return other._bits
        if isinstance(other, str):
            return _bits_from(other, self._names)
        return int(other)

    def _mask(self, attr: str) -> int | None:
        """Longest name first, so a name starting with another still matches
        whole."""
        mask = 0
        at = 0
        while at < len(attr):
            best, width = -1, 0
            for i, n in enumerate(self._names):
                if n and len(n) > width and attr.startswith(n, at):
                    best, width = i, len(n)
            if best < 0:
                return None
            mask |= 1 << best
            at += width
        return mask if attr else None

    def __getattr__(self, attr: str) -> bool:
        if attr.startswith("_"):
            raise AttributeError(attr)
        mask = self._mask(attr)
        if mask is None:
            raise AttributeError(f"no flag {attr!r}")
        return self._bits & mask == mask

    def __setattr__(self, attr: str, value: Any) -> None:
        if attr.startswith("_"):
            object.__setattr__(self, attr, value)
            return
        mask = self._mask(attr)
        if mask is None:
            raise AttributeError(f"no flag {attr!r}")
        self._replace(self._bits | mask if value else self._bits & ~mask)

    def _replace(self, bits: int) -> "FlagValue":
        object.__setattr__(self, "_bits", bits)
        if self._owner is not None:
            self._owner._set(self._layer, self._field, bits)
        return self

    def _detached(self, bits: int) -> "FlagValue":
        return FlagValue(bits, self._names)

    def __int__(self) -> int:
        return self._bits

    def __index__(self) -> int:
        return self._bits

    def __bool__(self) -> bool:
        return self._bits != 0

    def __str__(self) -> str:
        sep = "+" if any(len(n) > 1 for n in self._names) else ""
        return sep.join(self)

    def __repr__(self) -> str:
        return f"<Flag {self._bits} ({self})>"

    def __iter__(self) -> Iterator[str]:
        return (n for i, n in enumerate(self._names) if n and self._bits >> i & 1)

    def __eq__(self, other: object) -> bool:
        try:
            return self._bits == self._coerce(other)
        except (TypeError, ValueError):
            return NotImplemented

    def __hash__(self) -> int:
        return hash(self._bits)

    def __and__(self, other: Any) -> "FlagValue":
        return self._detached(self._bits & self._coerce(other))

    def __or__(self, other: Any) -> "FlagValue":
        return self._detached(self._bits | self._coerce(other))

    def __xor__(self, other: Any) -> "FlagValue":
        return self._detached(self._bits ^ self._coerce(other))

    __rand__ = __and__
    __ror__ = __or__
    __rxor__ = __xor__

    def __iand__(self, other: Any) -> "FlagValue":
        return self._replace(self._bits & self._coerce(other))

    def __ior__(self, other: Any) -> "FlagValue":
        return self._replace(self._bits | self._coerce(other))

    def __ixor__(self, other: Any) -> "FlagValue":
        return self._replace(self._bits ^ self._coerce(other))


class NoPayload:
    """What follows the last layer: nothing, which is false and empty."""

    __slots__ = ()

    def __bool__(self) -> bool:
        return False

    def __len__(self) -> int:
        return 0

    def __bytes__(self) -> bytes:
        return b""

    def __repr__(self) -> str:
        return ""

    __str__ = __repr__

    def summary(self) -> str:
        return ""

    def __eq__(self, other: object) -> bool:
        return isinstance(other, NoPayload) or other == b""

    def __hash__(self) -> int:
        return hash(b"")

    @property
    def payload(self) -> "NoPayload":
        return self


class _LayerView:
    """One layer of a packet and everything above it, as scapy's `pkt[IP]` and
    `pkt.payload` are. Reads and writes go to the packet it is part of."""

    __slots__ = ("_pkt", "_idx", "_name")

    def __init__(self, pkt: "Packet", idx: int, name: str):
        object.__setattr__(self, "_pkt", pkt)
        object.__setattr__(self, "_idx", idx)
        object.__setattr__(self, "_name", name)

    @property
    def __class__(self) -> type:
        """The layer's class, so `isinstance(pkt.payload, IP)` and
        `layer.__class__(octets)` read as they do for scapy's packets."""
        return _LAYERS.get(self._name, _LayerView)

    @property
    def name(self) -> str:
        return self._name

    def layers(self) -> list[str]:
        return self._pkt.layers()[self._idx:]

    @property
    def payload(self) -> Any:
        if self._idx + 1 < len(self._pkt.layers()):
            return self._pkt.getlayer(self._idx + 1)
        return NoPayload()

    @property
    def underlayer(self) -> Any:
        if self._idx == 0:
            return None
        return _LayerView(self._pkt, self._idx - 1, self._pkt.layers()[self._idx - 1])

    def haslayer(self, layer: Any) -> bool:
        return _layer_name(layer) in self.layers()

    __contains__ = haslayer

    def getlayer(self, layer: Any, nb: int = 1, **flt: Any) -> Any:
        if type(layer) is int:
            return self._pkt.getlayer(self._idx + layer if layer >= 0 else layer, nb, **flt)
        seen = 0
        name = _layer_name(layer)
        for i, n in enumerate(self.layers(), self._idx):
            if n != name:
                continue
            view = _LayerView(self._pkt, i, n)
            if any(getattr(view, k, None) != v for k, v in flt.items()):
                continue
            seen += 1
            if seen == nb:
                return view
        return None

    def __getitem__(self, layer: Any) -> "_LayerView":
        if type(layer) is slice:
            view = self.getlayer(layer.start, layer.stop or 1, **(layer.step or {}))
        else:
            view = self.getlayer(layer)
        if view is None:
            raise IndexError(f"no matching layer {layer!r} in packet")
        return view

    def __bytes__(self) -> bytes:
        return self._pkt._materialize().to_bytes_from(self._idx)

    def __len__(self) -> int:
        return len(bytes(self))

    def show_str(self) -> str:
        text = self._pkt._materialize().show(self._pkt._given(), self._idx)
        return _with_py_show(self._pkt, text, self._idx)

    def show(self, dump: bool = False) -> str | None:
        # scapy prints the dump with print(), whose newline is the blank line
        # that ends every show(); dump=True returns the text without it.
        if dump:
            return self.show_str()
        print(self.show_str())
        return None

    def show2_str(self) -> str:
        return _b.dissect(bytes(self), self._name).show()

    def show2(self, dump: bool = False) -> str | None:
        if dump:
            return self.show2_str()
        print(self.show2_str())
        return None

    def sprintf(self, fmt: str) -> str:
        from .report import sprintf
        return sprintf(self, fmt)

    def fields(self) -> list[str]:
        """Field names this layer carries, conditional fields included only
        where this particular header has them."""
        return self._pkt._materialize().field_names(self._idx)

    @property
    def fields_desc(self) -> list:
        """What this layer declares, conditional fields included."""
        from .discover import field_table
        return field_table(self._name)

    @property
    def default_fields(self) -> dict:
        from .discover import _defaults
        return dict(_defaults(self._name))

    def get_field(self, field: str) -> Any:
        """The field's declaration, as `fields_desc` carries it."""
        for info in self.fields_desc:
            if info.name == field:
                return info
        raise KeyError(f"{self._name} has no field {field!r}")

    def getfield_and_val(self, field: str) -> tuple:
        """The declaration and the value, which is what a caller inspecting an
        unfamiliar layer needs at once."""
        return self.get_field(field), getattr(self, field)

    def summary(self) -> str:
        return self._pkt._materialize().summary(self._idx)

    def __dir__(self) -> list[str]:
        names = set(super().__dir__())
        names.update(_b.layer_fields(self._name))
        return sorted(names)

    def __getattr__(self, field: str) -> Any:
        if field.startswith("_"):
            raise AttributeError(field)
        gen = self._pkt._generator_at(self._idx, field)
        if gen is not None:
            return gen
        rust = self._pkt._materialize()
        if field == _PARSED_FIELD.get(self._name, "options"):
            parsed = rust.options(self._idx)
            if parsed is not None:
                return [_group_item(x) for x in parsed]
        if field in ("qd", "an", "ns", "ar"):
            recs = rust.dns_records(self._idx)
            if recs is not None:
                return recs[field]
        try:
            value = rust.get_field(self._idx, field)
        except KeyError as exc:
            raise AttributeError(
                f"{self._name} has no field {field!r}"
            ) from exc
        if field in _FLAG_FIELDS:
            names = _flag_names(self._name, field)
            if names is not None:
                return FlagValue.from_str(
                    value, names, self._pkt, self._idx, field
                )
        scale = _scale(self._name, field)
        return value / scale if scale else value

    def __bytes__(self) -> bytes:
        """This layer and everything after it, as scapy's `raw(pkt[X])` is."""
        whole = bytes(self._pkt)
        return whole[self._pkt._materialize().layer_offset(self._idx) or 0:]

    def __len__(self) -> int:
        return len(bytes(self))

    def raw_options(self) -> Any:
        """The unparsed option bytes, for layers whose options are parsed."""
        return self._pkt._materialize().get_field(
            self._idx, _PARSED_FIELD.get(self._name, "options")
        )

    def __setattr__(self, field: str, value: Any) -> None:
        if field.startswith("_"):
            object.__setattr__(self, field, value)
            return
        self._pkt._set(self._idx, field, value)

    def __repr__(self) -> str:
        return self._pkt._materialize().repr(self._pkt._given(), self._idx)

    def __str__(self) -> str:
        return self.summary()

    def __eq__(self, other: object) -> bool:
        if isinstance(other, _LayerView) and other._pkt is self._pkt:
            return self._idx == other._idx
        if isinstance(other, (_LayerView, Packet)) or _is_bytes(other):
            return bytes(self) == bytes(other)
        return NotImplemented

    def __hash__(self) -> int:
        return hash((id(self._pkt), self._idx))


def _as_layer_and_where(layer: Any, where: Any) -> tuple:
    """Accept a condition list as the first positional argument.

    `columns()` takes its specs first and `filter()` takes a layer, so the
    natural `filter([("TCP", "dport", "==", 80)])` raised "not a layer". A list
    is never a layer, so reading one as the predicate costs nothing.
    """
    if where is None and isinstance(layer, (list, tuple)):
        return None, layer
    return layer, where


def _layer_name(x: Any) -> str:
    """Accept a layer class, an instance, or a plain string."""
    if isinstance(x, str):
        return x
    name = getattr(x, "_name", None)
    if isinstance(name, str):
        return name
    name = getattr(type(x), "_name", None)
    if isinstance(name, str):
        return name
    raise TypeError(f"not a layer: {x!r}")


# Layer name -> (field, default) of a trailing variable-length field, appended
# at build time like an option region rather than written into a fixed slot.
_VAR_FIELD: dict[str, tuple[str, Any]] = {}

_OPAQUE = ("Raw", "Padding")

# Packets per crossing while walking a template. Big enough that the crossing
# disappears, small enough that an unbounded template stays lazy.
_ITER_CHUNK = 256

# Above this a helper that must hand back real packets refuses rather than
# materialising; sendp streams and has no such limit.
_MAX_EXPAND = 1 << 20

_FIELD_KINDS: dict[str, dict[str, str]] = {}


def _is_plain_field(lname: str, key: str, value: Any) -> bool:
    """Whether the build path writes this into a fixed slot; the rest are
    option regions and payloads."""
    if _is_py(value):
        return key != "load" or lname not in _OPAQUE
    if key == _PARSED_FIELD.get(lname, "options") and not _is_bytes(value):
        return False
    if key == "load" and lname in _OPAQUE:
        return False
    var = _VAR_FIELD.get(lname)
    return var is None or key != var[0]


def _field_kind(layer: str, field: str) -> str:
    """A field's kind, cached per layer: one crossing, not one per lookup."""
    kinds = _FIELD_KINDS.get(layer)
    if kinds is None:
        try:
            kinds = {f[0]: f[2] for f in _b.field_specs(layer)}
        except ValueError:
            kinds = {}
        _FIELD_KINDS[layer] = kinds
    return kinds.get(field, "")


_ENUMS: dict[str, dict[str, dict[int, str]]] = {}
_S2I: dict[tuple[str, str], dict[str, int]] = {}


def _enum_table(layer: str) -> dict[str, dict[int, str]]:
    """Each enumerated field's names, cached per layer. A field whose names
    another field selects maps to an empty table."""
    table = _ENUMS.get(layer)
    if table is None:
        try:
            table = {f: dict(pairs) for f, pairs in _b.enum_names(layer)}
        except ValueError:
            table = {}
        _ENUMS[layer] = table
    return table


_SCALES: dict[str, dict[str, int]] = {}


def _scale(layer: str, field: str) -> int:
    """The fixed-point scale a field's octets are read through, or 0."""
    table = _SCALES.get(layer)
    if table is None:
        try:
            table = dict(_b.scaled_fields(layer))
        except ValueError:
            table = {}
        _SCALES[layer] = table
    return table.get(field, 0)


def _named(layer: str, field: str, value: Any) -> Any:
    """A name resolved to its value, so it is written in the same pass as the
    integers it may decide the layout for. A name this table does not know is
    left for the engine, which reports it."""
    scale = _scale(layer, field)
    if scale and isinstance(value, (int, float)) and not isinstance(value, bool):
        return int(scale * value)
    s2i = _S2I.get((layer, field))
    if s2i is None:
        s2i = {n: v for v, n in _enum_table(layer).get(field, {}).items()}
        _S2I[(layer, field)] = s2i
    if isinstance(value, str):
        return s2i.get(value, value)
    if isinstance(value, list) and s2i:
        return [s2i.get(x, x) if isinstance(x, str) else x for x in value]
    return value


def _chunks(tmpl: Any, frames: bool) -> Iterator[list]:
    fetch = tmpl.frames if frames else tmpl.packets
    total, at = tmpl.count, 0
    while at < total:
        chunk = fetch(at, _ITER_CHUNK)
        if not chunk:
            return
        yield chunk
        at += len(chunk)


def _all_of(tmpl: Any, frames: bool) -> list:
    n = tmpl.count
    if n > _MAX_EXPAND:
        raise ValueError(
            f"this template is {n} packets, more than the {_MAX_EXPAND} a "
            "list may hold; iterate it instead, which stays lazy"
        )
    return [one for chunk in _chunks(tmpl, frames) for one in chunk]


def expand(pkt: Any) -> list:
    """A template as a list of packets, or ``[pkt]`` for anything else."""
    tmpl = pkt.template() if isinstance(pkt, Packet) else None
    if tmpl is None:
        return [pkt]
    return [Packet(_rust=r) for r in _all_of(tmpl, False)]


def _expand_frames(pkt: Any) -> list:
    """The same expansion, serialised, without building Python packets."""
    if not isinstance(pkt, Packet) or pkt._rust is not None or not pkt._stack:
        return [bytes(pkt)]
    args = pkt._build_args()
    tmpl = pkt.template(args)
    return _all_of(tmpl, True) if tmpl is not None else [pkt._serialize(args)]


def _is_py(x: Any) -> bool:
    """Whether `x` is a Python-modelled layer; nothing can be until the
    module defining them has been imported."""
    mod = sys.modules.get(__name__ + "._pylayer")
    return mod is not None and isinstance(x, mod.PyPacket)


def _is_py_class(x: Any) -> bool:
    mod = sys.modules.get(__name__ + "._pylayer")
    return mod is not None and isinstance(x, type) and issubclass(x, mod.PyPacket)


def _py_model(wire: str) -> Any:
    """The Python class modelling the Rust layer `wire`, if it has one."""
    home = _PY_MODELLED.get(wire)
    if home is None:
        return None
    import importlib
    return getattr(importlib.import_module("." + home, __name__), wire)


def _bound_py(rust: Any, i: int, lower: str) -> Any:
    """The Python class `bind_bottom_up` put above layer `i`, if any."""
    for low, fval, cls in _PY_BOUND:
        if low != lower:
            continue
        try:
            if all(rust.get_field(i, k) == v for k, v in fval.items()):
                return cls
        except KeyError:
            continue
    return None


def _held(obj: Any) -> "Packet":
    """A one-layer packet carrying a Python-modelled layer: under the Rust
    layer it models, which keeps that layer's binding (UDP port 161 for
    SNMP), or as Raw octets where it models none."""
    wire = type(obj).__name__ if type(obj).__name__ in _PY_MODELLED else None
    if wire is None:
        wire = getattr(type(obj), "_name", None)
        wire = wire if wire in _PY_MODELLED else "Raw"
    field = "load" if wire == "Raw" else _PARSED_FIELD.get(wire, "load")
    return Packet(_stack=[(wire, {field: obj})])


def _copy_fields(fields: dict) -> dict:
    return {k: v.copy() if _is_py(v) else v for k, v in fields.items()}


def _float_padding(stack: list[tuple[str, dict]]) -> list[tuple[str, dict]]:
    """Padding is assembled after every other payload, wherever it was stacked,
    so that it lands at the end of the frame the way a pad does on the wire."""
    for name, _ in stack:
        if name == "Padding":
            return [s for s in stack if s[0] != "Padding"] + [
                s for s in stack if s[0] == "Padding"
            ]
    return stack


def _layer_init(name: str):
    def __init__(self, _data: Any = None, **kw: Any) -> None:
        if _data is not None and (_is_bytes(_data) or isinstance(_data, str)):
            # An opaque layer keeps its bytes as a field, so stacking it under
            # another one still produces a layer rather than a payload.
            if name in _OPAQUE:
                kw.setdefault("load", _to_bytes(_data))
            else:
                Packet.__init__(self, _rust=_b.dissect(_to_bytes(_data), name))
                return
        Packet.__init__(self, _stack=[(name, dict(kw))])

    return __init__


def _signature_of(name: str):
    import inspect

    params = [inspect.Parameter(
        "_data", inspect.Parameter.POSITIONAL_OR_KEYWORD, default=None)]
    params += [
        inspect.Parameter(f, inspect.Parameter.KEYWORD_ONLY, default=None)
        for f in _b.layer_fields(name)
    ]
    return inspect.Signature(params)


class _PacketMeta(type):
    """Registers a subclass declaring ``fields_desc`` as a real layer."""

    def __dir__(cls):
        """Field names complete after a layer class, which is where a user at a
        prompt reaches for them."""
        names = set(super().__dir__())
        if cls._name is not None:
            names.update(_b.layer_fields(cls._name))
        return sorted(names)

    def __getattr__(cls, attr):
        """`IP.ttl` is the field's declaration; `__signature__` makes the
        keyword arguments complete and `help(IP)` name them."""
        name = cls.__dict__.get("_name")
        if name is None:
            raise AttributeError(attr)
        if attr == "__signature__":
            return _signature_of(name)
        if attr.startswith("__"):
            raise AttributeError(attr)
        from .discover import field_table

        for info in field_table(name):
            if info.name == attr:
                return info
        raise AttributeError(attr)

    def __new__(mcls, cname, bases, ns):
        desc = ns.get("fields_desc")
        # `Packet` itself carries a `fields_desc` property, which declares
        # nothing; only a real table registers a layer.
        if not isinstance(desc, (list, tuple)):
            return super().__new__(mcls, cname, bases, ns)
        from .fields import specs

        lname = ns.get("name", cname)
        _b.register_layer(lname, specs(desc))
        _FLAG_FIELDS.update(
            f.name for f in desc if getattr(f, "kind", None) == "flags"
        )
        var = [f for f in desc if getattr(f, "kind", None) == "varbytes"]
        if var:
            _VAR_FIELD[lname] = (var[-1].name, var[-1].default)
        ns.setdefault("__slots__", ())
        ns["_name"] = lname
        ns["__init__"] = _layer_init(lname)
        cls = super().__new__(mcls, cname, bases, ns)
        _register(lname, cls)
        return cls


class Packet(metaclass=_PacketMeta):
    """A packet: either a stack you are building, or one you dissected."""

    _name: str | None = None

    __slots__ = ("_stack", "_payload", "_rust", "_written", "time", "wirelen",
                 "sent_time", "sniffed_on", "comments", "direction",
                 "process_information", "_py", "_original")

    def __init__(
        self,
        _stack: list[tuple[str, dict]] | None = None,
        _payload: bytes | None = None,
        _rust: Any = None,
        time: float = 0.0,
        wirelen: int = 0,
    ):
        self._stack = _stack if _stack is not None else []
        self._payload = _payload
        self._rust = _rust
        # A dissected packet is an instance of its outermost layer's class, so
        # `isinstance(pkt, Ether)` and `pkt.__class__(octets)` read as scapy's.
        if _rust is not None and type(self) is Packet:
            names = _rust.layer_names()
            cls = _LAYERS.get(names[0]) if names else None
            if cls is not None:
                object.__setattr__(self, "__class__", cls)
        self._written = False
        self.time = time
        self.wirelen = wirelen
        self.sent_time = None
        self.sniffed_on = None
        self._py = None
        self._original = None
        self.comments = None
        self.direction = None
        self.process_information = None
        if type(self) is Packet:
            self._adopt_class()

    @property
    def comment(self) -> Optional[bytes]:
        """The first of pcapng's comments on this packet."""
        return self.comments[0] if self.comments else None

    @comment.setter
    def comment(self, value: Optional[bytes]) -> None:
        self.comments = None if value is None else [value]

    def _adopt_class(self) -> None:
        """Take the class of the outermost layer, as a scapy packet is an
        instance of it: ``isinstance(p, Ether)`` holds and
        ``p.__class__(bytes(p))`` dissects. A layer that declared slots of its
        own has another layout and is left alone."""
        if self._stack:
            name = self._stack[0][0]
        elif self._rust is not None:
            names = self._rust.layer_names()
            name = names[0] if names else None
        else:
            return
        cls = _LAYERS.get(name)
        if cls is not None and cls.__dict__.get("__slots__") == ():
            object.__setattr__(self, "__class__", cls)

    def __truediv__(self, other: "Packet") -> "Packet":
        """Stack another layer beneath this one."""
        if not isinstance(other, Packet):
            if _is_bytes(other) or isinstance(other, str):
                other = Raw(load=_to_bytes(other))
            else:
                return NotImplemented

        # Above a Python-modelled layer everything is that layer's payload,
        # as it is in scapy.
        if self._py_top() is not None:
            clone = self.copy()
            clone._py_top()[1].add_payload(other.copy() if _is_py(other) else other)
            return clone
        if _is_py(other):
            bound = _PY_OVERLOAD.get(type(other))
            if bound is not None and self._spec_live and self._stack[-1][0] == bound[0]:
                self = self.copy()
                for k, v in bound[1].items():
                    self._stack[-1][1].setdefault(k, v)
            other = _held(other.copy())

        mine = self._rust is None or self._spec_live
        theirs = other._rust is None or other._spec_live
        if mine and theirs:
            return Packet(_stack=_float_padding(self._spec() + other._spec()))
        # A dissected packet cannot be turned back into a field spec: variable-
        # length header content does not survive the build path. Its octets go
        # in as the payload instead, behind a stand-in of its first layer so
        # the binding below it (EtherType, protocol, port) is written.
        if mine and not any(n == "Padding" for n, _ in self._stack):
            first = other.layers()[:1]
            head = Packet(_stack=self._spec() + [(first[0], {})] if first else self._spec())
            new = head._materialize().copy()
            new.set_payload(len(self._stack) - 1, bytes(other))
            return Packet(_rust=new, time=self.time, wirelen=self.wirelen)
        new = self._materialize().copy()
        n = len(new.layer_names())
        if n:
            new.set_payload(n - 1, bytes(other))
        return Packet(_rust=new, time=self.time, wirelen=self.wirelen)

    def __rtruediv__(self, other: Any) -> "Packet":
        if _is_bytes(other) or isinstance(other, str):
            return Raw(load=_to_bytes(other)) / self
        return NotImplemented

    def add_payload(self, other: Any) -> None:
        """Stack a layer, or bytes, beneath this one, in place."""
        joined = self / other
        self._stack = joined._stack
        self._payload = joined._payload
        self._rust = joined._rust

    def _spec(self) -> list[tuple[str, dict]]:
        """The layer stack as (name, fields) pairs, dissecting if needed."""
        if self._stack:
            return [(n, _copy_fields(f)) for n, f in self._stack]
        if self._rust is not None:
            return [(n, {}) for n in self._rust.layer_names()]
        return []

    def _split_fields(self):
        ints: list[tuple[int, str, int]] = []
        strs: list[tuple[int, str, str]] = []
        raws: list[tuple[int, str, bytes]] = []
        gens: list[tuple[int, str, tuple]] = []
        for i, (lname, fields) in enumerate(self._stack):
            for k, v in fields.items():
                if not _is_plain_field(lname, k, v):
                    continue
                if _is_py(v):
                    raws.append((i, k, bytes(v)))
                    continue
                v = _named(lname, k, v)
                spec = gen_spec(v, _field_kind(lname, k))
                if spec is not None:
                    gens.append((i, k, spec))
                elif isinstance(v, (bool, FlagValue)):
                    ints.append((i, k, int(v)))
                elif isinstance(v, int):
                    ints.append((i, k, v))
                elif isinstance(v, str):
                    strs.append((i, k, v))
                elif _is_bytes(v):
                    raws.append((i, k, bytes(v)))
                else:
                    raise TypeError(
                        f"unsupported value for field {k!r}: {type(v).__name__}"
                    )
        return ints, strs, raws, gens

    def _opt_blobs(self) -> list[tuple[int, str | None, Any]]:
        """Each layer's option region, as (layer index, name, value) entries.
        An entry with no name is bytes to append verbatim; a named one is
        encoded by the protocol's table in Rust."""
        out: list[tuple[int, str | None, Any]] = []
        for i, (lname, fields) in enumerate(self._stack):
            if lname in ("Raw", "Padding"):
                load = fields.get("load")
                if load is not None:
                    blob = _to_bytes(load, f"{lname}.load")
                    if blob:
                        out.append((i, None, blob))
                continue
            var = _VAR_FIELD.get(lname)
            if var is not None:
                blob = fields.get(var[0], var[1]) or b""
                if blob:
                    out.append((i, None, _to_bytes(blob, f"{lname}.{var[0]}")))
                continue
            v = fields.get(_PARSED_FIELD.get(lname, "options"))
            if _is_py(v):
                continue
            if v is None or _is_bytes(v):
                if _is_bytes(v) and v:
                    out.append((i, None, bytes(v)))
                continue
            for opt in v:
                # A bare name, ("MSS", 1460), or DHCP's ("router", a, b).
                if isinstance(opt, (str, int)):
                    name, value = opt, None
                else:
                    name = opt[0]
                    value = opt[1] if len(opt) == 2 else list(opt[1:])
                out.append((i, str(name), value))
        return out

    def _generator_at(self, layer: int, field: str) -> Any:
        """A generator field reads back as the generator, not as one draw."""
        if self._rust is not None or layer >= len(self._stack):
            return None
        lname, fields = self._stack[layer]
        if field not in fields or not _is_plain_field(lname, field, fields[field]):
            return None
        return as_generator(fields[field], _field_kind(lname, field))

    def _build_args(self):
        """The one field split every build path shares."""
        return ([n for n, _ in self._stack], *self._split_fields())

    def _serialize(self, args) -> bytes:
        names, ints, strs, raws, _ = args
        return _b.build_and_serialize(
            names, ints, strs, raws, self._payload, self._opt_blobs()
        )

    def template(self, args=None) -> Any:
        """The expansion this packet describes, or ``None`` if it is one packet."""
        if self._rust is not None or not self._stack:
            return None
        names, ints, strs, raws, gens = args or self._build_args()
        if not gens:
            return None
        return _b.make_template(
            names, ints, strs, raws, self._payload, self._opt_blobs(), gens
        )

    def _materialize(self):
        """Build the Rust packet if this is still just a spec.

        A template is realised afresh and not cached: caching would freeze one
        draw of its volatile fields as the packet.
        """
        if self._rust is None:
            args = self._build_args()
            if not args[0]:
                raise ValueError("empty packet")
            tmpl = self.template(args)
            if tmpl is not None:
                return tmpl.packet(0)
            names, ints, strs, raws, _ = args
            rust = _b.build_packet(
                names, ints, strs, raws, self._payload, self._opt_blobs()
            )
            # Not cached: the Python layer it was built from stays mutable.
            if self._py_top() is not None:
                return rust
            self._rust = rust
        elif type(self._py) is tuple:
            self._sync_py()
        return self._rust

    def _py_top(self) -> Any:
        """(index, object) of the Python-modelled layer this chain ends in.

        A dissected packet decodes it from the Rust layer on first ask and
        keeps it; one that fails to decode stays the Rust layer, as scapy
        leaves an undecodable payload Raw."""
        if self._spec_live:
            for i, (_, fields) in enumerate(self._stack):
                for v in fields.values():
                    if _is_py(v):
                        return i, v
            return None
        # An int records that nothing decoded while that many Python
        # bindings existed; importing a layer module adds some.
        if self._py is None or (type(self._py) is int and self._py != len(_PY_BOUND)):
            self._py = self._decode_py() or len(_PY_BOUND)
        return self._py[:2] if type(self._py) is tuple else None

    def _decode_py(self) -> Any:
        rust = self._rust
        if rust is None:
            return None
        names = rust.layer_names()
        for i, n in enumerate(names):
            cls = _py_model(n) if n in _PY_MODELLED else None
            if cls is None and n == "Raw" and i:
                cls = _bound_py(rust, i - 1, names[i - 1])
            if cls is None:
                continue
            data = rust.payload(i - 1) if i else rust.to_bytes()
            try:
                obj = cls(data)
            except Exception:
                from .capture import conf
                if conf.debug_dissector:
                    raise
                return None
            # Compared against the object's own encoding, not the octets it
            # came from, so reading a non-canonical message never rewrites it.
            return i, obj, bytes(obj)
        return None

    def _keep_original(self) -> None:
        if self._original is None and not self._stack and self._rust is not None:
            self._original = self._rust.to_bytes()

    @property
    def original(self) -> bytes:
        """The octets this packet was dissected from, before any change."""
        if self._original is not None:
            return self._original
        if self._rust is not None and not self._stack:
            return self._rust.to_bytes()
        return b""

    def clear_cache(self) -> None:
        """Re-encode a Python-modelled layer from its fields on the next build;
        the Rust layers have no cache, their octets being the packet."""
        top = self._py_top()
        if top is not None:
            top[1].clear_cache()

    def _sync_py(self) -> None:
        """Write a changed Python layer back into the octets."""
        i, obj, built = self._py
        now = bytes(obj)
        if now == built:
            return
        self._keep_original()
        if i:
            self._rust.set_payload(i - 1, now)
        else:
            self._rust = _b.dissect(now, self._rust.layer_names()[0])
        self._py = (i, obj, now)
        self._written = True

    @property
    def _spec_live(self) -> bool:
        """Whether the layer stack is still what this packet means.

        Reading a field builds the packet and caches it, which is a cache, not
        a change. Writing one through that cache is a change, and from then on
        the octets are the truth and the stack is stale.
        """
        return bool(self._stack) and not self._written

    def _edit_spec(self) -> list:
        """The stack, for a caller about to change it. The built packet is
        dropped so the next serialisation sees the change."""
        if not self._spec_live:
            raise NotImplementedError(
                "this takes a packet being built; one whose fields have been "
                "written through keeps no record of which values were assigned"
            )
        self._rust = None
        return self._stack

    def _set(self, layer: int, field: str, value: Any) -> None:
        if self._rust is not None:
            self._keep_original()
            value = _named(self.layers()[layer], field, value)
            self._written = True
            if isinstance(value, (bool, FlagValue)):
                self._rust.set_field(layer, field, int(value))
            elif isinstance(value, int):
                self._rust.set_field(layer, field, value)
            elif _is_bytes(value):
                self._rust.set_field_bytes(layer, field, bytes(value))
            elif isinstance(value, str):
                self._rust.set_field_str(layer, field, value)
            else:
                raise TypeError(f"unsupported value for {field!r}")
            return
        if layer >= len(self._stack):
            raise IndexError("layer out of range")
        self._stack[layer][1][field] = value

    def __bytes__(self) -> bytes:
        if self._rust is None and self._stack:
            args = self._build_args()
            tmpl = self.template(args)
            return tmpl.frame(0) if tmpl is not None else self._serialize(args)
        return self._materialize().to_bytes()

    def build(self) -> bytes:
        return bytes(self)

    def __len__(self) -> int:
        return len(bytes(self))

    def layers(self) -> list[str]:
        if self._rust is not None:
            return list(self._rust.layer_names())
        return [n for n, _ in self._stack]

    def haslayer(self, layer: Any) -> bool:
        if self._wants_py(layer):
            top = self._py_top()
            return top is not None and bool(top[1].haslayer(layer))
        name = _layer_name(layer)
        if self._rust is not None:
            return self._rust.haslayer(name)
        return any(n == name for n, _ in self._stack)

    def getlayer(self, layer: Any, nb: int = 1, **flt: Any) -> _LayerView | None:
        """The `nb`-th layer of this kind whose every named field matches, or
        the layer at that position when `layer` is an integer."""
        names = self.layers()
        if type(layer) is int:
            if not -len(names) <= layer < len(names):
                return None
            layer %= len(names)
            top = self._py_top()
            if top is not None and layer >= top[0]:
                return top[1].getlayer(layer - top[0])
            return _LayerView(self, layer, names[layer])
        if self._wants_py(layer, names):
            top = self._py_top()
            return None if top is None else top[1].getlayer(layer, nb, **flt)
        name = _layer_name(layer)
        if nb == 1 and not flt:
            return _LayerView(self, names.index(name), name) if name in names else None
        seen = 0
        for i, n in enumerate(names):
            if n != name:
                continue
            view = _LayerView(self, i, name)
            if any(getattr(view, k, None) != v for k, v in flt.items()):
                continue
            seen += 1
            if seen == nb:
                return view
        return None

    def __contains__(self, layer: Any) -> bool:
        return self.haslayer(layer)

    def _wants_py(self, layer: Any, names: Any = None) -> bool:
        """Whether `layer` names something only the Python model can answer:
        a Python class, the Rust layer it models, or a name no Rust layer in
        this chain has."""
        if _is_py_class(layer):
            return True
        if not isinstance(layer, str):
            return False
        if layer in _PY_MODELLED:
            return True
        if layer in (names if names is not None else self.layers()):
            return False
        return self._py_top() is not None
    @property
    def name(self) -> str:
        """The outermost layer's name, which is what a packet answers to."""
        names = self.layers()
        return names[0] if names else "Packet"

    @property
    def fields_desc(self) -> list:
        """What the outermost layer declares. A layer further up answers
        through ``pkt[Layer].fields_desc``."""
        names = self.layers()
        if not names:
            return []
        from .discover import field_table
        return field_table(names[0])

    @property
    def fields(self) -> dict:
        """The outermost layer's values: what was assigned while building, or
        what the header holds once it exists."""
        view = self.getlayer(0)
        if view is None:
            return {}
        if self._spec_live:
            return dict(self._stack[0][1])
        return {f: getattr(view, f) for f in view.fields()}

    @property
    def default_fields(self) -> dict:
        names = self.layers()
        if not names:
            return {}
        from .discover import _defaults
        return dict(_defaults(names[0]))

    def iterpayloads(self) -> Iterator[Any]:
        """Each layer of the chain in turn, outermost first."""
        top = self._py_top()
        for i, n in enumerate(self.layers()):
            if top is not None and i == top[0]:
                yield from top[1].iterpayloads()
                return
            yield _LayerView(self, i, n)

    def firstlayer(self) -> Any:
        """The bottom layer: the one the frame starts with."""
        return self.getlayer(0)

    def lastlayer(self) -> Any:
        """The top layer: the one carrying the payload."""
        top = self._py_top()
        return top[1].lastlayer() if top is not None else self.getlayer(-1)

    def get_field(self, field: str) -> Any:
        """The declaration of a field, wherever in the chain it lives."""
        for i, n in enumerate(self.layers()):
            if field in _b.layer_fields(n):
                return _LayerView(self, i, n).get_field(field)
        raise KeyError(f"no field {field!r} in {' / '.join(self.layers())}")

    def getfield_and_val(self, field: str) -> tuple:
        return self.get_field(field), getattr(self, field)

    def getfieldval(self, field: str) -> Any:
        return getattr(self, field)

    def setfieldval(self, field: str, value: Any) -> None:
        setattr(self, field, value)

    def delfieldval(self, field: str) -> None:
        """Unset a field, so the build path writes its default again.

        Only a packet still being built can do this: once the octets exist
        there is no record of which of them the caller chose (E12).
        """
        for _, fields in self._edit_spec():
            if field in fields:
                del fields[field]
                return
        raise AttributeError(f"no field {field!r} was set on this packet")

    def hide_defaults(self) -> None:
        """Drop every assigned value that equals the layer's default, so
        `command()` prints only what the caller actually chose."""
        from .discover import _defaults

        for lname, fields in self._edit_spec():
            if lname in _OPAQUE:
                continue
            defaults = _defaults(lname)
            for key in [k for k in fields if k in defaults]:
                if fields[key] == defaults[key]:
                    del fields[key]

    def clone_with(self, payload: Any = None, **fields: Any) -> "Packet":
        """A copy whose outermost layer carries exactly these field values."""
        if not self._spec_live:
            raise NotImplementedError(
                "clone_with() takes a packet being built; one whose fields "
                "have been written through cannot go back to a field spec"
            )
        stack = [(n, dict(f)) for n, f in self._stack]
        stack[0] = (stack[0][0], dict(fields))
        clone = Packet(_stack=stack, _payload=self._payload,
                       time=self.time, wirelen=self.wirelen)
        return clone if payload is None else clone / payload

    def remove_payload(self) -> None:
        """Drop everything above the bottom layer, in place."""
        del self._edit_spec()[1:]
        self._payload = None

    @classmethod
    def from_hexcap(cls, text: str | None = None) -> "Packet":
        """A packet from a pasted hex dump, as tcpdump and Wireshark print one.

        With no argument it reads from stdin until a blank line, which is what
        makes it useful at a prompt: `Ether.from_hexcap()`, paste, blank line.
        """
        if cls._name is None:
            raise TypeError(
                "call from_hexcap() on a layer, which says how to read the "
                "first header: Ether.from_hexcap()"
            )
        from .describe import from_hexcap
        return cls(from_hexcap(text))

    def display(self, dump: bool = False) -> str | None:
        """Deprecated spelling of `show()`, kept because scripts use it."""
        return self.show(dump)

    def __getitem__(self, layer: Any) -> _LayerView:
        # pkt[IP:2] is the second IP layer; pkt[IP::{"ttl": 3}] filters on
        # field values.
        if type(layer) is slice:
            view = self.getlayer(
                layer.start, layer.stop or 1, **(layer.step or {})
            )
        else:
            view = self.getlayer(layer)
        if view is None:
            raise IndexError(f"no matching layer {layer!r} in packet")
        return view

    def __iter__(self) -> Iterator["Packet"]:
        """One packet per generator combination, in scapy's order.

        Lazy, and in chunks: `IP(src=Net("10.0.0.0/8"), dst=Net("10.0.0.0/8"))`
        is 2^48 packets, so `next(iter(pkt))` must not build them all.
        """
        tmpl = self.template()
        if tmpl is None:
            yield self.copy()
            return
        for chunk in _chunks(tmpl, False):
            for rust in chunk:
                yield Packet(_rust=rust)

    def copy(self) -> "Packet":
        """An independent packet carrying the same layers and values."""
        if self._rust is not None:
            return Packet(_rust=self._materialize().copy(), time=self.time,
                          wirelen=self.wirelen)
        return Packet(
            _stack=[(n, _copy_fields(f)) for n, f in self._stack],
            _payload=self._payload,
            time=self.time,
            wirelen=self.wirelen,
        )

    def __dir__(self) -> list[str]:
        """Every field of every layer in the chain, because that is what
        `pkt.<tab>` reaches."""
        names = set(super().__dir__())
        for n in self.layers():
            names.update(_b.layer_fields(n))
        return sorted(names)

    def __getattr__(self, field: str) -> Any:
        if field.startswith("_"):
            raise AttributeError(field)
        names = self.layers()
        for i, n in enumerate(names):
            if field in _b.layer_fields(n):
                return getattr(_LayerView(self, i, n), field)
        top = self._py_top()
        if top is not None:
            try:
                return getattr(top[1], field)
            except AttributeError:
                pass
        raise AttributeError(f"no field {field!r} in {' / '.join(names)}")

    def __setattr__(self, field: str, value: Any) -> None:
        if field in Packet.__slots__ or field == "comment":
            object.__setattr__(self, field, value)
            return
        names = self.layers()
        for i, n in enumerate(names):
            if field in _b.layer_fields(n):
                self._set(i, field, value)
                return
        top = self._py_top()
        if top is not None:
            top[1].setfieldval(field, value)
            return
        raise AttributeError(f"no field {field!r} in {' / '.join(names)}")

    @property
    def payload(self) -> Any:
        """The next layer and everything above it, or `NoPayload` after the
        last one."""
        if len(self.layers()) > 1:
            return self.getlayer(1)
        return NoPayload()

    @property
    def underlayer(self) -> None:
        return None

    def show(self, dump: bool = False) -> str | None:
        # scapy prints the dump with print(), whose newline is the blank line
        # that ends every show(); dump=True returns the text without it.
        if dump:
            return self.show_str()
        print(self.show_str())
        return None

    def _given(self) -> list[list[str]] | None:
        """What each layer of a packet still being built was assigned, which
        is all its `repr()` shows; `None` once the octets are the truth."""
        if not self._spec_live:
            return None
        return [list(fields) for _, fields in self._stack]

    def show_str(self) -> str:
        return _with_py_show(self, self._materialize().show(self._given()))

    def show2(self, dump: bool = False) -> str | None:
        if dump:
            return self.show2_str()
        print(self.show2_str())
        return None

    def show2_str(self) -> str:
        """As it will be sent: the lengths and checksums are the computed ones."""
        from .report import show2_str
        return show2_str(self)

    def sprintf(self, fmt: str) -> str:
        """See `wiry.report` for the format language."""
        from .report import sprintf
        return sprintf(self, fmt)

    def summary(self) -> str:
        return self._materialize().summary()

    def command(self) -> str:
        """The Python expression that rebuilds this packet, byte for byte."""
        from .describe import command
        return command(self)

    def json(self, **kw: Any) -> str:
        from .describe import json_str
        return json_str(self, **kw)

    def answers(self, other: Any) -> bool:
        """Whether this packet is a reply to ``other``, by the rules ``sr``
        pairs with (E14). A packet that is only Raw answers anything, as
        scapy's Raw does."""
        if self.layers()[:1] == ["Raw"]:
            return True
        names = other.layers() if isinstance(other, Packet) else []
        if not names:
            return False
        for pkt in (self, other):
            top = [n for n in pkt.layers() if n not in _OPAQUE][-1:]
            if top and top[0] not in _REPLY_RULES:
                raise NotImplementedError(
                    f"wiry has no reply rule for {top[0]}: answers() knows "
                    "echo, ICMP errors, TCP, UDP, DNS and ARP (E14)"
                )
        from .capture import conf

        pairs, _ = _b.pair_replies([bytes(other)], [bytes(self)], names[0],
                                   False, bool(conf.checkIPaddr))
        return bool(pairs)

    def __lt__(self, other: Any) -> bool:
        """``a < b``: a answers b."""
        return self.answers(other)

    def __gt__(self, other: Any) -> bool:
        """``a > b``: b answers a."""
        return other.answers(self)

    def route(self) -> tuple:
        """``(iface, source, gateway)`` for the first layer that names a
        destination: IP, IPv6, or ARP over either; ``(None, None, None)``
        when none does."""
        from .capture import conf

        for i, name in enumerate(self.layers()):
            view = _LayerView(self, i, name)
            if name == "IP":
                return conf.route.route(_first_address(view.dst))
            if name == "IPv6":
                return conf.route6.route(_first_address(view.dst))
            if name == "ARP":
                ptype = view.ptype
                if ptype == 0x0800:
                    return conf.route.route(_first_address(view.pdst))
                if ptype == 0x86DD:
                    return conf.route6.route(_first_address(view.pdst))
                return None, None, None
        return None, None, None

    def fragment(self, fragsize: int | None = None) -> list["Packet"]:
        """Split this datagram per RFC 791 §3.2."""
        from .frag import FRAGSIZE, fragment
        return fragment(self, FRAGSIZE if fragsize is None else fragsize)

    def __repr__(self) -> str:
        return self._materialize().repr(self._given())

    def __str__(self) -> str:
        return self.summary()

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Packet):
            return bytes(self) == bytes(other)
        if _is_bytes(other):
            return bytes(self) == bytes(other)
        return NotImplemented

    def __hash__(self) -> int:
        return hash(bytes(self))

    def __reduce__(self) -> tuple:
        """A dissected packet travels as its octets and the layer to read them
        as; one still being built travels as its spec, so its generators
        survive the trip undrawn."""
        meta = {k: getattr(self, k) for k in _META}
        if self._spec_live:
            return (_from_stack, (self._stack, self._payload, meta))
        names = self._rust.layer_names()
        return (_from_bytes, (self._rust.to_bytes(), names[0] if names else "", meta))


def _with_py_show(pkt: Packet, text: str, idx: int = 0) -> str:
    """A Rust `show()` from layer `idx` on, with a Python-modelled layer in
    the chain drawn by its own `show()` in place of the Rust one."""
    top = pkt._py_top()
    if top is None or top[0] < idx:
        return text
    head, lvl = _show_head(text, top[0] - idx)
    return head + top[1].show(dump=True, lvl=lvl)


def _show_head(text: str, upto: int) -> tuple:
    """The part of a Rust `show()` before layer `upto`, and the indent that
    layer's fields would have had."""
    starts = [i for i, line in enumerate(text.splitlines(keepends=True))
              if line.lstrip().startswith("###[")]
    lines = text.splitlines(keepends=True)
    if upto >= len(starts):
        return text, ""

    def indent(layer: int) -> int:
        for line in lines[starts[layer] + 1:]:
            if line.lstrip().startswith("###["):
                break
            return max(len(line) - len(line.lstrip()) - 2, 0)
        return 0

    lvl = 0
    if upto >= 1:
        lvl = indent(upto - 1)
        if upto >= 2:
            lvl += lvl - indent(upto - 2)
    return "".join(lines[:starts[upto]]), " " * lvl


# What a packet carries besides its octets: when it was captured and sent,
# its true length on the wire, and pcapng's per-packet annotations.
_META = ("time", "wirelen", "sent_time", "sniffed_on", "comments", "direction",
         "process_information")


def _with_meta(pkt: Packet, meta: dict) -> Packet:
    for k, v in meta.items():
        setattr(pkt, k, v)
    return pkt


# The layers answers.rs can pair a reply on, as the innermost of a packet.
_REPLY_RULES = frozenset({
    "Ether", "Dot1Q", "Loopback", "CookedLinux", "CookedLinuxV2", "IP", "IPv6",
    "ICMP", "ICMPv6", "TCP", "UDP", "DNS", "ARP",
})


def _first_address(value: Any) -> Any:
    """A generator field routes by its first address, as scapy's does."""
    if isinstance(value, (str, bytes)):
        return value
    try:
        return next(iter(value))
    except (TypeError, StopIteration):
        return value


def _from_stack(stack, payload, meta) -> Packet:
    return _with_meta(Packet(_stack=stack, _payload=payload), meta)


def _from_bytes(data, first, meta) -> Packet:
    return _with_meta(Packet(_rust=_b.dissect(data, first) if first else None), meta)


def _make_layer(name: str) -> type:
    return _PacketMeta(name, (Packet,), {
        "__init__": _layer_init(name),
        "_name": name,
        "__doc__": f"{name} layer.",
        "__slots__": (),
    })


_LAYERS: dict[str, type] = {}


def _register(name: str, cls: type) -> None:
    """Record a layer under its name, and drop what `discover` cached about it.

    A declared layer (E3) reaches here too, and one declared twice under the
    same name replaces the first, so the cached field table and defaults would
    otherwise describe the layer that is gone.
    """
    _LAYERS[name] = cls
    _PARSED_FIELD[name] = _b.parsed_field(name)
    discover = sys.modules.get(f"{__name__}.discover")
    if discover is not None:
        discover._TABLES.pop(name, None)
        discover._DEFAULTS.pop(name, None)


for _n in _b.known_layers():
    _LAYERS[_n] = _make_layer(_n)
    if _n not in _PY_MODELLED:
        globals()[_n] = _LAYERS[_n]
        __all__.append(_n)
    _FLAG_FIELDS.update(f for f in _b.layer_fields(_n) if _b.flag_names(_n, f))
    _PARSED_FIELD[_n] = _b.parsed_field(_n)


def known_layers() -> list[str]:
    """Every layer this build can dissect, custom ones included."""
    return list(_b.known_layers())


# The built-in chain is static dispatch in Rust and cannot be enumerated;
# what was added at runtime can be, and `explore()` reports exactly that.
_RUNTIME_BINDS: list[tuple[str, str, list]] = []


def bind_layers(lower: Any, upper: Any, **conds: Any) -> None:
    """Make dissection reach `upper` from `lower` when every named field of
    `lower` holds the given value, and stacking write those values back."""
    if _is_py_class(upper):
        bind_top_down(lower, upper, **conds)
        bind_bottom_up(lower, upper, **conds)
        return
    low, up = _layer_name(lower), _layer_name(upper)
    _b.bind_layer(low, up, list(conds.items()))
    _RUNTIME_BINDS.append((low, up, list(conds.items())))


# Python-modelled layers reached from a Rust layer, as (lower layer name,
# field values, class): a dissected packet decodes the Raw payload of such a
# lower layer as that class on first ask. Kept in Python, so the bulk paths
# see that payload as Raw.
_PY_BOUND: list = []

# Python-modelled class -> (lower layer name, field values written into that
# layer when the class is stacked on it, unless set already).
_PY_OVERLOAD: dict = {}


def bind_bottom_up(lower: Any, upper: Any, **fval: Any) -> None:
    """Dissection only: reach `upper` from `lower` when `fval` holds."""
    if not _is_py_class(upper):
        raise NotImplementedError(
            "a binding between Rust layers goes both ways; use bind_layers")
    if _is_py_class(lower):
        lower.payload_guess = lower.payload_guess[:] + [(fval, upper)]
    else:
        _PY_BOUND.append((_layer_name(lower), dict(fval), upper))


def bind_top_down(lower: Any, upper: Any, **fval: Any) -> None:
    """Building only: stacking `upper` on `lower` writes `fval` into it."""
    if not _is_py_class(upper):
        raise NotImplementedError(
            "a binding between Rust layers goes both ways; use bind_layers")
    if _is_py_class(lower):
        upper._overload_fields = {**upper._overload_fields, lower: fval}
    else:
        _PY_OVERLOAD[upper] = (_layer_name(lower), dict(fval))


_GZIP_MAGIC = b"\x1f\x8b"

_GZIP_CHUNK = 1 << 20

# A decompressor is a walk over an attacker-controlled length: 200 KB of gzip
# expands to a gigabyte of zeros.
_MAX_GUNZIP = 4 << 30

_CAPTURE_MAGICS = (
    b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",  # pcap, either byte order
    b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",  # the nanosecond variants
    b"\x0a\x0d\x0d\x0a",  # pcapng, whose block type reads the same both ways
)


def _gzip_body(data: bytes) -> int:
    """Offset of the deflate stream inside a member, per RFC 1952 §2.3."""
    flg = data[3]
    off = 10
    if flg & 4:
        off += 2 + int.from_bytes(data[off : off + 2], "little")
    for name in (8, 16):
        if flg & name:
            off = data.index(b"\x00", off) + 1
    return off + 2 if flg & 2 else off


def _gunzip_into(write: Any, data: bytes) -> int:
    """Expand every member, keeping what a truncated or CRC-broken tail left.

    A capture cut short still holds the packets that made it, and the reader
    already stops cleanly at a partial record, so the 8-byte trailer is read
    past rather than enforced.
    """
    total = 0
    while data[:2] == _GZIP_MAGIC:
        try:
            pending = data[_gzip_body(data) :]
        except (ValueError, IndexError):
            break
        member = zlib.decompressobj(wbits=-15)
        try:
            while True:
                out = member.decompress(pending, _GZIP_CHUNK)
                pending = member.unconsumed_tail
                if not out:
                    break
                if not total and not out.startswith(_CAPTURE_MAGICS):
                    raise ValueError("gzipped data is not a capture file")
                total += len(out)
                if total > _MAX_GUNZIP:
                    raise ValueError(
                        f"gzipped capture expands past {_MAX_GUNZIP} bytes"
                    )
                write(out)
        except zlib.error:
            break
        data = member.unused_data[8:]
    if not total:
        raise ValueError("capture is not readable gzip data")
    return total


@contextlib.contextmanager
def _as_path(source: Any) -> Iterator[str]:
    """Yield a filesystem path for a path or a file-like object.

    The reader memory-maps a file and indexes records by offset into it, so a
    stream has to land on disk before it can be read, and a gzipped capture has
    to be expanded there.
    """
    read = getattr(source, "read", None)
    if read is None:
        with open(source, "rb") as fh:
            # Rewinding is not an option: `open` may hand back a pipe, which
            # scapy's own suite does. The probe is put back by concatenation.
            probe = fh.read(2)
            data = probe + fh.read() if probe == _GZIP_MAGIC else None
        if data is None:
            yield str(source)
            return
    else:
        data = read()
        if isinstance(data, str):
            raise ValueError("capture stream must be opened in binary mode")
    fd, tmp = tempfile.mkstemp(suffix=".pcap")
    try:
        with os.fdopen(fd, "wb") as fh:
            if data[:2] == _GZIP_MAGIC:
                _gunzip_into(fh.write, data)
            else:
                fh.write(data)
        yield tmp
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def rdpcap(path: Any, count: int = -1) -> PacketList:
    """Read a pcap or pcapng file, by path or from a binary stream.

    Records are indexed, not dissected, so this is cheap; ``count`` keeps the
    first that many as a view over the same buffer."""
    from .pcapio import _BadCapture

    try:
        with _as_path(path) as real:
            got = _b.read_pcap(real)
            fd = os.open(real, os.O_RDONLY)
            try:
                pcapng = os.read(fd, 4) == b"\x0a\x0d\x0d\x0a"
            finally:
                os.close(fd)
    except ValueError as exc:
        raise _BadCapture(str(exc)) from exc
    if count is not None and count >= 0:
        got = got.head(count)
    # scapy names the list after the file, which is what its repr prints.
    source = path if isinstance(path, (str, os.PathLike)) else getattr(path, "name", None)
    name = os.path.basename(os.fspath(source)) if isinstance(source, (str, os.PathLike)) else ""
    out = PacketList(got, name or "PacketList")
    if pcapng:
        from .plist import _NgMeta

        out._meta = _NgMeta(got)
    return out


# A pcap file declares one link type for every record in it, so the writer has
# to pick one. Keyed by the name of a packet's outermost layer.
_LINKTYPE_OF = {
    "Ether": 1,
    "Loopback": 0,
    "IP": 228,
    "IPv6": 229,
    "CookedLinux": 113,
    "CookedLinuxV2": 276,
}


def _linktype_of(pkt: Any) -> Optional[int]:
    layers = getattr(pkt, "layers", None)
    if layers is None:
        return None
    try:
        names = layers()
    except Exception:
        return None
    return _LINKTYPE_OF.get(names[0]) if names else None


from .plist import PacketList, QueryAnswer, SndRcvList  # noqa: E402

_PCAPNG_SUFFIXES = (".pcapng", ".ntar")

_DEFAULT_LINKTYPE = 1

_OPEN_WRITERS: Any = weakref.WeakSet()


@atexit.register
def _close_open_writers() -> None:
    """Deliver buffered captures while the interpreter can still import.

    `__del__` alone runs too late: `tempfile` and `gzip` import lazily, which
    fails once `sys.meta_path` is gone, and the packets would go silently.
    """
    for writer in list(_OPEN_WRITERS):
        with contextlib.suppress(Exception):
            writer.close()


class PcapWriter:
    """Streaming capture writer, in either format.

    The header is written from the first packet's link type unless `linktype`
    says otherwise, so a writer opened before its packets exist still declares
    what it ends up holding. `.pcapng` names a pcapng file and `.gz` a gzipped
    one, either of which `pcapng=` and `gz=` can also force.

    A whole `PacketList` goes out in one crossing, copied straight from the
    buffer it was read into. `write()` of a single packet is a crossing per
    packet, which is what a streaming writer is for; both paths encode through
    the same Rust code, so the files agree byte for byte.
    """

    __slots__ = (
        "_target", "_path", "_gz", "_pcapng", "_append", "_sync", "_nano",
        "_snaplen", "_linktype", "_fixed", "_w", "_warned", "_closed", "_ng",
        "__weakref__",
    )

    def __init__(
        self,
        filename: Any,
        linktype: Optional[int] = None,
        gz: bool = False,
        endianness: str = "",
        append: bool = False,
        sync: bool = False,
        nano: bool = False,
        snaplen: int = 65535,
        bufsz: int = 4096,
        pcapng: Optional[bool] = None,
    ):
        if endianness not in ("", "<"):
            raise NotImplementedError("wiry writes little-endian capture files only")
        self._target = filename if hasattr(filename, "write") else None
        name = "" if self._target is not None else str(filename)
        lowered = name.lower()
        self._gz = bool(gz) or lowered.endswith(".gz")
        stem = lowered[:-3] if lowered.endswith(".gz") else lowered
        self._pcapng = stem.endswith(_PCAPNG_SUFFIXES) if pcapng is None else bool(pcapng)
        self._path = name
        self._append = bool(append)
        self._sync = bool(sync)
        self._nano = bool(nano)
        self._snaplen = int(snaplen)
        self._linktype = None if linktype is None else int(linktype)
        self._fixed = linktype is not None
        self._warned = False
        self._closed = False
        self._w: Any = None
        self._ng: Any = None
        if self._fixed:
            self._open()

    @property
    def nano(self) -> bool:
        return self._nano

    @property
    def linktype(self) -> Optional[int]:
        return self._linktype

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def write(self, pkt: Any) -> None:
        """Write a packet, a capture, an iterable of packets, or raw bytes.

        Writing nothing writes nothing, header included, and leaves the link
        type to whatever comes next.
        """
        if isinstance(pkt, PacketList) and pkt._res is None and not (
                self._pcapng and pkt._meta is not None and pkt._meta.annotated()):
            self._settle({pkt._list.dlt})
            if not len(pkt):
                return
            self._open().write_list(pkt._list)
            self._pass_through()
            return
        if isinstance(pkt, Packet) or _is_bytes(pkt):
            pkt = [pkt]
        else:
            pkt = [q for p in pkt for q in _pair_records(p)]
        if not pkt:
            return
        self._settle({lt for lt in map(_linktype_of, pkt) if lt is not None})
        if self._ng is None and self._w is None and self._pcapng and \
                not self._append and any(map(_annotated, pkt)):
            self._start_annotated()
        if self._ng is not None:
            self._write_annotated(pkt)
            return
        self._open().write_records([r for p in pkt for r in _records(p)])
        self._pass_through()

    def _start_annotated(self) -> None:
        """pcapng's per-packet comments, direction and interface go through
        the block writer in `pcapio`, which emits them as options; the Rust
        writer writes bare records. Chosen before anything is written, and
        kept for the whole file."""
        import io

        from .pcapio import RawPcapNgWriter

        buf = io.BytesIO()
        w = RawPcapNgWriter(buf)
        w.sync = False
        w.linktype = self._linktype
        w._write_header(None)
        self._ng = (w, buf)
        _OPEN_WRITERS.add(self)

    def _write_annotated(self, pkts: list) -> None:
        w, _ = self._ng
        for p in pkts:
            name = getattr(p, "sniffed_on", None)
            for frame in _expand_frames(p):
                w._write_packet(
                    frame, linktype=_linktype_of(p) or self._linktype,
                    sec=float(getattr(p, "time", 0) or 0),
                    wirelen=int(getattr(p, "wirelen", 0) or 0) or None,
                    ifname=None if name is None else str(name).encode(),
                    direction=getattr(p, "direction", None),
                    comments=getattr(p, "comments", None),
                )

    def _pass_through(self) -> None:
        """A plain file object gets each write as it happens, as scapy's
        does; only a gzipped one has to wait for the whole stream."""
        if self._target is not None and not self._gz and self._w is not None:
            data = self._w.take()
            if data:
                self._target.write(data)

    def flush(self) -> None:
        if self._w is not None:
            self._w.flush()

    def close(self) -> None:
        if self._closed:
            return
        if self._ng is not None:
            self._closed = True
            _OPEN_WRITERS.discard(self)
            self._deliver(self._ng[1].getvalue())
            return
        writer = self._open()
        self._closed = True
        self._w = None
        _OPEN_WRITERS.discard(self)
        buffered = writer.close()
        if buffered is not None:
            self._deliver(buffered)

    def _settle(self, seen: set) -> None:
        """Pick the file's link type, warning if the packets disagree with it."""
        if self._fixed:
            return
        if self._linktype is not None:
            seen = seen | {self._linktype}
        if len(seen) > 1 and not self._warned:
            self._warned = True
            msg = ("Inconsistent linktypes detected! The resulting file "
                   "might contain invalid packets.")
            warnings.warn(msg, stacklevel=3)
            # scapy reports it through its logger, and scripts patch that.
            from .pcapio import _warning

            _warning(msg)
        if self._linktype is None:
            self._linktype = seen.pop() if len(seen) == 1 else _DEFAULT_LINKTYPE

    def _open(self) -> Any:
        if self._closed:
            raise ValueError("the capture file is closed")
        if self._w is not None:
            return self._w
        if self._linktype is None:
            self._linktype = _DEFAULT_LINKTYPE
        path, existing = self._path, None
        if self._gz or self._target is not None:
            path = None
            if self._append and self._target is None and os.path.exists(self._path):
                with open(self._path, "rb") as fh:
                    existing = fh.read()
                if existing[:2] == _GZIP_MAGIC:
                    held = bytearray()
                    _gunzip_into(held.extend, existing)
                    existing = held
        try:
            self._w = _b.CaptureWriter(
                path, self._pcapng, self._linktype, self._snaplen,
                self._nano, self._sync, self._append, existing,
            )
        except Exception:
            # A writer that could not open its file has nothing left to close,
            # and retrying at close() would only mask the real error.
            self._closed = True
            raise
        _OPEN_WRITERS.add(self)
        return self._w

    def _deliver(self, data: bytes) -> None:
        """A compressed or file-like target is written whole: the appended part
        was folded into the buffer when the writer opened."""
        if self._target is not None:
            self._encode(self._target, data)
            close = getattr(self._target, "close", None)
            if close is not None:
                close()
            return
        # One rename rather than a truncating write: appending to a capture
        # rewrites all of it, and a write that fails partway through would
        # otherwise leave the user with none of it.
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(self._path) or ".", prefix=".wiry-")
        try:
            with os.fdopen(fd, "wb") as fh:
                self._encode(fh, data)
            os.replace(tmp, self._path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise

    def _encode(self, fh: Any, data: bytes) -> None:
        if not self._gz:
            fh.write(data)
            return
        # Streamed rather than compressed whole, so the buffered capture does
        # not have to coexist with a compressed copy of itself.
        with gzip.GzipFile(fileobj=fh, mode="wb", mtime=0) as gz:
            gz.write(data)


class PcapNgWriter(PcapWriter):
    """`PcapWriter` fixed to pcapng, whatever the file is called."""

    __slots__ = ()

    def __init__(self, filename: Any, **kw: Any):
        kw["pcapng"] = True
        super().__init__(filename, **kw)


def _record(pkt: Any) -> tuple:
    """(bytes, timestamp, wire length). A wire length of 0 means untruncated."""
    return (
        bytes(pkt),
        float(getattr(pkt, "time", 0.0) or 0.0),
        int(getattr(pkt, "wirelen", 0) or 0),
    )


def _annotated(p: Any) -> bool:
    """Whether a packet carries what only pcapng options can hold."""
    return bool(getattr(p, "comments", None)) or \
        getattr(p, "direction", None) is not None or \
        getattr(p, "sniffed_on", None) is not None


def _pair_records(p: Any) -> tuple:
    """A request/answer pair is two records, as scapy writes it, the request
    stamped with when it was sent."""
    if not isinstance(p, tuple):
        return (p,)
    if p and getattr(p[0], "sent_time", None):
        p[0].time = p[0].sent_time
    return p


def _records(pkt: Any) -> list:
    """One record per frame, so a template writes every packet it declares."""
    ts = float(getattr(pkt, "time", 0.0) or 0.0)
    wirelen = int(getattr(pkt, "wirelen", 0) or 0)
    return [(frame, ts, wirelen) for frame in _expand_frames(pkt)]


def wrpcap(filename: Any, pkt: Any, *args: Any, **kargs: Any) -> None:
    """Write packets to a pcap file. A whole capture costs one crossing."""
    with PcapWriter(filename, *args, **kargs) as writer:
        writer.write(pkt)


def wrpcapng(filename: Any, pkt: Any, **kargs: Any) -> None:
    """Write packets to a pcapng file."""
    kargs["pcapng"] = True
    with PcapWriter(filename, **kargs) as writer:
        writer.write(pkt)


# The reader classes need Packet and PacketList, defined above; scapy's
# record-level interface lives with them.
from .pcapio import PcapReader  # noqa: E402


def raw(pkt: Any) -> bytes:
    """Serialise a packet to bytes."""
    return bytes(pkt)


# Eager, unlike the capture and columnar facades: `IP(dst=[...])` has to work
# without the caller touching a name from this module first.
from .volatile import (  # noqa: E402
    Net, Net6, RandBin, RandByte, RandChoice, RandEnumKeys, RandIP, RandIP6,
    RandInt, RandLong, RandMAC, RandNum, RandShort, RandString, VolatileValue,
    as_generator, corrupt_bits, corrupt_bytes, fuzz, gen_spec, set_rand_seed,
)


def _export(module: str) -> None:
    """Publish a module's ``__all__`` lazily: the module is imported to read
    its names, and each value is fetched on first touch, so a database it
    loads on demand stays unloaded until somebody asks."""
    import importlib

    for name in importlib.import_module(f".{module}", __name__).__all__:
        if name not in globals() and name not in _HOME:
            _HOME[name] = module
            __all__.append(name)


for _m in ("compat", "consts", "error", "utils", "utils6", "data", "plist",
           "pcapio", "external", "pton_ntop"):
    _export(_m)
