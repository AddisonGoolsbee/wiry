"""wiry: fast packet dissection and crafting with a familiar API."""

from __future__ import annotations

import atexit
import contextlib
import gzip
import os
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

_DESCRIBE = ("hexdiff", "hexdiff_str")

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
)

_AUTOMATON = ("ATMT", "Automaton")

_ANSMACHINE = ("AnsweringMachine", "AnsweringMachineTCP", "AnsweringMachineUDP")

_ROUTE = ("Route", "Route6", "read_routes", "read_routes6", "in6_getifaddr")

_EAGER = (
    "Packet", "PacketList", "FlagValue", "rdpcap", "wrpcap", "wrpcapng",
    "PcapReader", "PcapWriter", "PcapNgWriter", "raw", "hexdump",
    "hexdump_str", "ls", "known_layers", "bind_layers",
    "VolatileValue", "RandNum", "RandByte", "RandShort", "RandInt", "RandLong",
    "RandIP", "RandIP6", "RandMAC", "RandString", "RandBin", "RandChoice",
    "RandEnumKeys", "Net", "Net6", "fuzz", "corrupt_bytes", "corrupt_bits",
    "set_rand_seed", "expand",
)

# Derived, because __dir__ answers from it: a lazy name missing here would be
# invisible to dir(wiry) and to anything probing it for capability.
__all__ = list(
    _EAGER + _COLUMNAR + _FRAG + _STREAM + _DESCRIBE + _CAPTURE + _TOOLS
    + _SOCKETS + _AUTOMATON + _ANSMACHINE + _ROUTE
)


def __getattr__(name: str) -> Any:
    if name in _COLUMNAR:
        from . import columnar
        return getattr(columnar, name)
    if name in _CAPTURE:
        from . import capture
        return getattr(capture, name)
    if name in _FRAG:
        from . import frag
        return getattr(frag, name)
    if name in _STREAM:
        from . import stream
        return getattr(stream, name)
    if name in _DESCRIBE:
        from . import describe
        return getattr(describe, name)
    if name in _TOOLS:
        from . import tools
        return getattr(tools, name)
    if name in _SOCKETS:
        from . import supersocket
        return getattr(supersocket, name)
    if name in _AUTOMATON:
        from . import automaton
        return getattr(automaton, name)
    if name in _ANSMACHINE:
        from . import ansmachine
        return getattr(ansmachine, name)
    if name in _ROUTE:
        from . import route
        return getattr(route, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


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
    raise TypeError(f"{what} must be bytes or str, not {type(x).__name__}")


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


class _LayerView:
    """A single layer of a packet. Field reads go straight to Rust."""

    __slots__ = ("_pkt", "_idx", "_name")

    def __init__(self, pkt: "Packet", idx: int, name: str):
        object.__setattr__(self, "_pkt", pkt)
        object.__setattr__(self, "_idx", idx)
        object.__setattr__(self, "_name", name)

    @property
    def name(self) -> str:
        return self._name

    def fields(self) -> list[str]:
        """Field names this layer carries, conditional fields included only
        where this particular header has them."""
        return self._pkt._materialize().field_names(self._idx)

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
                return parsed
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
        return value

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
        return f"<{self._name} layer {self._idx}>"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, _LayerView):
            return self._name == other._name and self._idx == other._idx
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self._name, self._idx))


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


class _PacketMeta(type):
    """Registers a subclass declaring ``fields_desc`` as a real layer."""

    def __new__(mcls, cname, bases, ns):
        desc = ns.get("fields_desc")
        if desc is None:
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
        return super().__new__(mcls, cname, bases, ns)


class Packet(metaclass=_PacketMeta):
    """A packet: either a stack you are building, or one you dissected."""

    _name: str | None = None

    __slots__ = ("_stack", "_payload", "_rust", "time", "wirelen", "sent_time")

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
        self.time = time
        self.wirelen = wirelen
        self.sent_time = None

    def __truediv__(self, other: "Packet") -> "Packet":
        """Stack another layer beneath this one."""
        if not isinstance(other, Packet):
            if _is_bytes(other) or isinstance(other, str):
                other = Raw(load=_to_bytes(other))
            else:
                return NotImplemented

        # A materialised packet cannot be turned back into a field spec:
        # variable-length header content does not survive the build path, so
        # reconstructing would reset every field to its default.
        if self._rust is not None or other._rust is not None:
            new = self._materialize().copy()
            n = len(new.layer_names())
            if n:
                new.set_payload(n - 1, bytes(other))
            return Packet(_rust=new, time=self.time, wirelen=self.wirelen)

        return Packet(_stack=_float_padding(self._spec() + other._spec()))

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
            return [(n, dict(f)) for n, f in self._stack]
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
            self._rust = _b.build_packet(
                names, ints, strs, raws, self._payload, self._opt_blobs()
            )
        return self._rust

    def _set(self, layer: int, field: str, value: Any) -> None:
        if self._rust is not None:
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
            return _LayerView(self, layer, names[layer])
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
            return Packet(_rust=self._rust.copy(), time=self.time, wirelen=self.wirelen)
        return Packet(
            _stack=[(n, dict(f)) for n, f in self._stack],
            _payload=self._payload,
            time=self.time,
            wirelen=self.wirelen,
        )

    def __getattr__(self, field: str) -> Any:
        if field.startswith("_"):
            raise AttributeError(field)
        names = self.layers()
        for i, n in enumerate(names):
            if field in _b.layer_fields(n):
                gen = self._generator_at(i, field)
                if gen is not None:
                    return gen
                value = self._materialize().get_field(i, field)
                if field in _FLAG_FIELDS:
                    flags = _flag_names(n, field)
                    if flags is not None:
                        return FlagValue.from_str(value, flags, self, i, field)
                return value
        raise AttributeError(f"no field {field!r} in {' / '.join(names)}")

    def __setattr__(self, field: str, value: Any) -> None:
        if field in Packet.__slots__:
            object.__setattr__(self, field, value)
            return
        names = self.layers()
        for i, n in enumerate(names):
            if field in _b.layer_fields(n):
                self._set(i, field, value)
                return
        raise AttributeError(f"no field {field!r} in {' / '.join(names)}")

    @property
    def payload(self) -> bytes:
        rust = self._materialize()
        n = len(rust.layer_names())
        return rust.payload(n - 1) if n else b""

    def show(self) -> None:
        print(self.show_str(), end="")

    def show_str(self) -> str:
        return self._materialize().show()

    def show2(self) -> None:
        print(self.show2_str(), end="")

    def show2_str(self) -> str:
        """As it will be sent: the lengths and checksums are the computed ones."""
        from .report import show2_str
        return show2_str(self)

    def sprintf(self, fmt: str) -> str:
        """See `wiry.report` for the format language."""
        from .report import sprintf
        return sprintf(self, fmt)

    def summary(self) -> str:
        if self._rust is None and self._stack:
            return " / ".join(n for n, _ in self._stack)
        return self._materialize().summary()

    def command(self) -> str:
        """The Python expression that rebuilds this packet, byte for byte."""
        from .describe import command
        return command(self)

    def json(self, **kw: Any) -> str:
        from .describe import json_str
        return json_str(self, **kw)

    def fragment(self, fragsize: int | None = None) -> list["Packet"]:
        """Split this datagram per RFC 791 §3.2."""
        from .frag import FRAGSIZE, fragment
        return fragment(self, FRAGSIZE if fragsize is None else fragsize)

    def __repr__(self) -> str:
        return f"<{self.summary()}>"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Packet):
            return bytes(self) == bytes(other)
        if _is_bytes(other):
            return bytes(self) == bytes(other)
        return NotImplemented

    def __hash__(self) -> int:
        return hash(bytes(self))


def _make_layer(name: str) -> type:
    return _PacketMeta(name, (Packet,), {
        "__init__": _layer_init(name),
        "_name": name,
        "__doc__": f"{name} layer.",
        "__slots__": (),
    })


_LAYERS: dict[str, type] = {}
for _n in _b.known_layers():
    _LAYERS[_n] = _make_layer(_n)
    globals()[_n] = _LAYERS[_n]
    __all__.append(_n)
    _FLAG_FIELDS.update(f for f in _b.layer_fields(_n) if _b.flag_names(_n, f))
    _PARSED_FIELD[_n] = _b.parsed_field(_n)


def known_layers() -> list[str]:
    """Every layer this build can dissect, custom ones included."""
    return list(_b.known_layers())


def bind_layers(lower: Any, upper: Any, **conds: Any) -> None:
    """Make dissection reach `upper` from `lower` when every named field of
    `lower` holds the given value, and stacking write those values back."""
    _b.bind_layer(_layer_name(lower), _layer_name(upper), list(conds.items()))


class PacketList:
    """A capture. Packets stay in Rust until indexed."""

    __slots__ = ("_list",)

    def __init__(self, rust_list: Any):
        self._list = rust_list

    def __len__(self) -> int:
        return len(self._list)

    def __getitem__(self, i: Any) -> Any:
        if isinstance(i, slice):
            return [self[k] for k in range(*i.indices(len(self)))]
        rust = self._list[i]
        return Packet(_rust=rust, time=rust.time, wirelen=rust.wirelen)

    def __iter__(self) -> Iterator[Packet]:
        for i in range(len(self)):
            yield self[i]

    def count_layer(self, layer: Any) -> int:
        """Count packets containing a layer. One crossing for the whole capture."""
        return self._list.count_layer(_layer_name(layer))

    def field_column(self, layer: Any, field: str) -> list[Any]:
        """Pull one field from every packet in a single crossing."""
        return self._list.field_column(_layer_name(layer), field)

    def columns(self, specs: Any = None, where: Any = None, layer: Any = None) -> dict:
        """Several fields from the whole capture in one pass. See `columnar`."""
        from .columnar import columns
        return columns(self, specs, where=where, layer=layer)

    def to_dict(self, specs: Any = None, where: Any = None, layer: Any = None) -> dict:
        """The capture as a plain dict of lists, with no extra dependency."""
        from .columnar import to_dict
        return to_dict(self, specs, where=where, layer=layer)

    def filter(self, layer: Any = None, where: Any = None) -> "PacketList":
        """A view over matching packets. The predicate is evaluated in Rust."""
        from .columnar import filter_packets
        layer, where = _as_layer_and_where(layer, where)
        return filter_packets(self, layer, where)

    def filter_indices(self, layer: Any = None, where: Any = None) -> list[int]:
        """Positions of the matching packets."""
        from .columnar import filter_indices
        layer, where = _as_layer_and_where(layer, where)
        return filter_indices(self, layer, where)

    def head(self, n: int) -> "PacketList":
        """The first n packets, as a view. Shares the capture buffer."""
        return PacketList(self._list.head(n))

    def sprintf(self, fmt: str) -> list[str]:
        """Every packet through one format string, in one pass."""
        from .report import sprintf_list
        return sprintf_list(self, fmt)

    def summary(self, prn: Any = None, lfilter: Any = None) -> None:
        """Prints; `report.summary_lines` returns the lines instead."""
        from .report import summary_lines
        for line in summary_lines(self, prn, lfilter):
            print(line)

    def nsummary(self, prn: Any = None, lfilter: Any = None) -> None:
        from .report import summary_lines
        for line in summary_lines(self, prn, lfilter, numbered=True):
            print(line)

    def show(self, prn: Any = None, lfilter: Any = None) -> None:
        self.nsummary(prn, lfilter)

    def sessions(self, session_extractor: Any = None) -> Any:
        """Which packets belong to a flow. `streams()` is what the flow said."""
        from .report import sessions
        return sessions(self, session_extractor)

    def streams(self) -> Any:
        """Reassembled TCP streams, keyed as `sessions()` keys its flows.

        One crossing for the whole capture. See `wiry.stream`.
        """
        from .stream import streams
        return streams(self)

    def conversations(self, getsrcdst: Any = None, **kw: Any) -> Any:
        """DOT source for the conversations. See `wiry.report`."""
        from .report import conversations
        return conversations(self, getsrcdst, **kw)

    def make_table(self, fn: Any, lfilter: Any = None) -> str:
        """`fn` returns (column, row, cell) per packet."""
        from .report import make_table
        return make_table(self, fn, lfilter)

    def plot(self, fn: Any, lfilter: Any = None, **kw: Any) -> Any:
        """matplotlib is optional and imported only here."""
        from .report import plot
        return plot(self, fn, lfilter, **kw)

    def times(self) -> list[float]:
        return self._list.times()

    def raw_at(self, i: int) -> bytes:
        return self._list.raw_at(i)

    def __repr__(self) -> str:
        return f"<PacketList: {len(self)} packets>"


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
    """Read a pcap file, by path or from a binary stream.

    Records are indexed, not dissected, so this is cheap."""
    if count is not None and count >= 0:
        raise NotImplementedError(
            "count= is not implemented yet; slice the PacketList instead"
        )
    with _as_path(path) as real:
        return PacketList(_b.read_pcap(real))


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
        "_snaplen", "_linktype", "_fixed", "_w", "_warned", "_closed",
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
        """Write a packet, a capture, an iterable of packets, or raw bytes."""
        if isinstance(pkt, PacketList):
            self._settle({pkt._list.dlt})
            self._open().write_list(pkt._list)
            return
        if isinstance(pkt, Packet) or _is_bytes(pkt):
            pkt = [pkt]
        else:
            pkt = list(pkt)
        self._settle({lt for lt in map(_linktype_of, pkt) if lt is not None})
        self._open().write_records([r for p in pkt for r in _records(p)])

    def flush(self) -> None:
        if self._w is not None:
            self._w.flush()

    def close(self) -> None:
        if self._closed:
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
            warnings.warn(
                "Inconsistent linktypes detected! The resulting file might "
                "contain invalid packets.",
                stacklevel=3,
            )
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


class PcapReader:
    """Streaming reader. Context-manager and iterator, like the familiar one."""

    __slots__ = ("_pl", "_i")

    def __init__(self, path: Any):
        with _as_path(path) as real:
            self._pl = PacketList(_b.read_pcap(real))
        self._i = 0

    def __enter__(self) -> "PcapReader":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        pass

    def __iter__(self) -> Iterator[Packet]:
        return self

    def __next__(self) -> Packet:
        if self._i >= len(self._pl):
            raise StopIteration
        pkt = self._pl[self._i]
        self._i += 1
        return pkt

    def read_all(self) -> PacketList:
        return self._pl


def raw(pkt: Any) -> bytes:
    """Serialise a packet to bytes."""
    return bytes(pkt)


def hexdump(pkt: Any, width: int = 16) -> None:
    print(hexdump_str(pkt, width), end="")


def hexdump_str(pkt: Any, width: int = 16) -> str:
    data = bytes(pkt)
    out = []
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{off:04x}  {hexpart:<{width * 3}} {text}\n")
    return "".join(out)


def ls(layer: Any = None, verbose: bool = False) -> None:
    """List known layers, the fields of one, or the fields of a packet.

    `verbose` keeps the fields a header's own contents make inactive.
    """
    if layer is None:
        for n in _b.known_layers():
            print(n)
        return
    if isinstance(layer, Packet):
        for i, n in enumerate(layer.layers()):
            print(f"###[ {n} ]###")
            for f in _ls_fields(layer, i, n, verbose):
                print(f"  {f}")
        return
    for f in _b.layer_fields(_layer_name(layer)):
        print(f"{f}")


def _ls_fields(pkt: Packet, i: int, name: str, verbose: bool) -> Sequence[str]:
    if verbose or pkt._rust is None:
        return _b.layer_fields(name)
    return pkt._rust.field_names(i)


# Eager, unlike the capture and columnar facades: `IP(dst=[...])` has to work
# without the caller touching a name from this module first.
from .volatile import (  # noqa: E402
    Net, Net6, RandBin, RandByte, RandChoice, RandEnumKeys, RandIP, RandIP6,
    RandInt, RandLong, RandMAC, RandNum, RandShort, RandString, VolatileValue,
    as_generator, corrupt_bits, corrupt_bytes, fuzz, gen_spec, set_rand_seed,
)
