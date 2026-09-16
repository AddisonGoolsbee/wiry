"""packetry: fast packet dissection and crafting with a familiar API."""

from __future__ import annotations

from typing import Any, Iterator, Sequence

from . import _packetry as _b

__version__ = _b.__version__

__all__ = [
    "Packet", "PacketList", "FlagValue", "rdpcap", "wrpcap", "PcapReader",
    "raw", "hexdump", "hexdump_str", "ls", "known_layers", "bind_layers",
    "to_arrow", "to_polars", "to_pandas",
]

_COLUMNAR = ("to_arrow", "to_polars", "to_pandas")


def __getattr__(name: str) -> Any:
    if name in _COLUMNAR:
        from . import columnar
        return getattr(columnar, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def _is_bytes(x: Any) -> bool:
    return isinstance(x, (bytes, bytearray, memoryview))


def _to_bytes(x: Any, what: str = "value") -> bytes:
    """Byte-oriented strings encode as latin-1, so every code point below 256
    survives as the octet of the same value. Anything else is refused, because
    `bytes(n)` would allocate n zero octets instead of failing."""
    if isinstance(x, str):
        return x.encode("latin-1")
    if _is_bytes(x):
        return bytes(x)
    raise TypeError(f"{what} must be bytes or str, not {type(x).__name__}")


_FLAG_NAMES: dict[tuple[str, str], tuple[str, ...] | None] = {}

# Tested first on every field read, so a non-flag field costs one set lookup.
_FLAG_FIELDS: set[str] = set()


def _bits_from(text: str, names: Sequence[str]) -> int:
    # An unassigned bit carries an empty name, which every string contains.
    return sum(1 << i for i, n in enumerate(names) if n and n in text)


def _flag_names(layer: str, field: str) -> tuple[str, ...] | None:
    names = _FLAG_NAMES.get((layer, field), ())
    if names == ():
        got = _b.flag_names(layer, field)
        names = tuple(got) if got else None
        _FLAG_NAMES[(layer, field)] = names
    return names


class FlagValue:
    """A flag field: an integer, a set of named bits and a string at once.

    Naming bits is what the wire format means, so `.SA` is the AND of the two
    bits rather than an equality test. Assigning to a bit writes through to the
    packet the value was read from.
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
        """The bits named by a run of concatenated flag names, longest first so
        a name that starts with another still matches whole."""
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
        rust = self._pkt._materialize()
        if field == "options":
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
        return self._pkt._materialize().get_field(self._idx, "options")

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


# (code, payload width, or None for variable). Codes from the IANA TCP Option
# Kind and IP Option Number registries.
#
# EOL and NOP occupy a single octet with no length field, but SAckOK still
# carries a length octet despite an empty payload; emitting it as one bare byte
# desynchronises every option after it.
_SINGLE_BYTE = {0, 1}
_TCP_OPT = {
    "EOL": (0, 0), "NOP": (1, 0), "MSS": (2, 2), "WScale": (3, 1),
    "SAckOK": (4, 0), "SAck": (5, None), "Timestamp": (8, 8),
    "UTO": (28, 2), "AO": (29, None), "TFO": (34, None),
}
_IP_OPT = {
    "EOL": (0, 0), "NOP": (1, 0), "RR": (7, None), "Timestamp": (68, None),
    "Security": (130, None), "LSRR": (131, None), "SID": (136, 2),
    "SSRR": (137, None), "RA": (148, 2),
}


# RFC 2132 option codes and payload shapes; an integer entry means a fixed-width
# big-endian integer of that many bytes.
#
# The length octet here counts ONLY the option data (RFC 2132 §2), the opposite
# of the TCP/IPv4 convention above where it also counts the code and length
# octets. Using one rule for the other desynchronises every following option.
_DHCP_OPT: dict[str, tuple[int, Any]] = {
    "pad": (0, "flag"),
    "subnet_mask": (1, "ip"),
    "router": (3, "ip"),
    "name_server": (6, "ip"),
    "hostname": (12, "text"),
    "domain": (15, "text"),
    "broadcast_address": (28, "ip"),
    "requested_addr": (50, "ip"),
    "lease_time": (51, 4),
    "message-type": (53, 1),
    "server_id": (54, "ip"),
    "param_req_list": (55, "bytes"),
    "max_dhcp_size": (57, 2),
    "renewal_time": (58, 4),
    "rebinding_time": (59, 4),
    "client_id": (61, "bytes"),
    "relay_agent_information": (82, "bytes"),
    "end": (255, "flag"),
}

# RFC 2132 §9.6.
_DHCP_MSGTYPE = {
    "discover": 1, "offer": 2, "request": 3, "decline": 4,
    "ack": 5, "nak": 6, "release": 7, "inform": 8,
}

# RFC 2132 §3.1, §3.2: Pad and End are a bare octet, no length and no data.
_DHCP_BARE = {0, 255}


def _ipv4_bytes(v: Any) -> bytes:
    if _is_bytes(v):
        return bytes(v)
    if isinstance(v, int):
        return int(v).to_bytes(4, "big")
    return bytes(int(p) for p in str(v).split("."))


def _dhcp_payload(kind: Any, values: tuple) -> bytes:
    flat: list[Any] = []
    for v in values:
        if isinstance(v, (list, tuple)):
            flat.extend(v)
        else:
            flat.append(v)
    if kind == "ip":
        return b"".join(_ipv4_bytes(v) for v in flat)
    if kind == "text":
        return b"".join(
            v.encode() if isinstance(v, str) else bytes(v) for v in flat
        )
    if kind == "bytes":
        if len(flat) == 1 and _is_bytes(flat[0]):
            return bytes(flat[0])
        if len(flat) == 1 and isinstance(flat[0], str):
            return flat[0].encode()
        return bytes(int(v) & 0xFF for v in flat)
    v = flat[0] if flat else 0
    if isinstance(v, str):
        v = _DHCP_MSGTYPE.get(v.lower(), v)
    return int(v).to_bytes(kind, "big")


def _opt_code(name: Any) -> int | None:
    """An option the parser could not name comes back labelled with its code in
    decimal, so that label has to encode as that code again."""
    if isinstance(name, int):
        return name
    if isinstance(name, str) and name.isdigit() and 0 <= int(name) <= 255:
        return int(name)
    return None


def _encode_dhcp_options(items: Any) -> bytes:
    """Encode a DHCP option list (RFC 2132) into wire bytes.

    Accepts what the parser gives back and what people type: "end",
    ("end", None), ("message-type", 1), ("message-type", "discover"),
    ("server_id", "10.0.0.1"), ("router", ["10.0.0.1", "10.0.0.2"]),
    (224, b"raw"), ("60", b"raw").
    """
    out = bytearray()
    for item in items:
        if isinstance(item, (str, int)):
            name, values = item, ()
        else:
            name, values = item[0], tuple(item[1:])
        if values == (None,):
            values = ()
        if name in _DHCP_OPT:
            code, kind = _DHCP_OPT[name]
        elif (c := _opt_code(name)) is not None:
            code, kind = c, "bytes"
        else:
            raise ValueError(f"unknown DHCP option {name!r}")
        if code in _DHCP_BARE:
            out.append(code)
            continue
        payload = _dhcp_payload(kind, values)
        if len(payload) > 255:
            raise ValueError(f"DHCP option {name!r} is too long to encode")
        out.append(code)
        out.append(len(payload))
        out += payload
    return bytes(out)


def _encode_options(layer: str, items: Any) -> bytes:
    """Encode an option list into wire bytes.

    Accepts the same shapes the parser produces: ("MSS", 1460),
    ("SAckOK", None), ("Timestamp", (tsval, tsecr)), or (code, b"raw").
    """
    if _is_bytes(items):
        return bytes(items)
    if layer == "DHCP":
        return _encode_dhcp_options(items)
    table = _TCP_OPT if layer == "TCP" else _IP_OPT if layer == "IP" else None
    if table is None:
        raise ValueError(f"{layer} does not take an encodable option list")

    out = bytearray()
    for item in items:
        name, value = item if isinstance(item, tuple) else (item, None)
        if name in table:
            code, width = table[name]
        elif (c := _opt_code(name)) is not None:
            code, width = c, None
        else:
            raise ValueError(f"unknown {layer} option {name!r}")

        if code in _SINGLE_BYTE:
            out.append(code)
            continue
        if isinstance(value, tuple):
            payload = b"".join(int(v).to_bytes(4, "big") for v in value)
        elif isinstance(value, int):
            payload = int(value).to_bytes(width or 4, "big")
        elif _is_bytes(value):
            payload = bytes(value)
        elif value is None:
            payload = b""
        else:
            raise TypeError(f"cannot encode option {name!r} value {value!r}")
        # The length octet counts the code and length octets themselves.
        out.append(code)
        out.append(len(payload) + 2)
        out += payload
    return bytes(out)


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


# Layer name -> (field, default) of a trailing variable-length field, which is
# appended at build time like an option region, not written into a fixed slot.
_VAR_FIELD: dict[str, tuple[str, Any]] = {}

_OPAQUE = ("Raw", "Padding")


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
            # An opaque layer keeps its bytes as a field, so that stacking it
            # under another one still produces a layer rather than a payload.
            if name in _OPAQUE:
                kw.setdefault("load", _to_bytes(_data))
            else:
                Packet.__init__(self, _rust=_b.dissect(_to_bytes(_data), name))
                return
        Packet.__init__(self, _stack=[(name, dict(kw))])

    return __init__


class _PacketMeta(type):
    """Registers a subclass that declares ``fields_desc`` as a real layer, so
    it behaves exactly like a generated built-in one."""

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

    __slots__ = ("_stack", "_payload", "_rust", "time")

    def __init__(
        self,
        _stack: list[tuple[str, dict]] | None = None,
        _payload: bytes | None = None,
        _rust: Any = None,
        time: float = 0.0,
    ):
        self._stack = _stack if _stack is not None else []
        self._payload = _payload
        self._rust = _rust
        self.time = time

    def __truediv__(self, other: "Packet") -> "Packet":
        """Stack another layer beneath this one."""
        if not isinstance(other, Packet):
            if _is_bytes(other) or isinstance(other, str):
                other = Raw(load=_to_bytes(other))
            else:
                return NotImplemented

        # A materialised packet cannot be turned back into a field spec:
        # variable-length header content does not survive the build path, so
        # reconstructing would reset every field to its default. Append to the
        # real bytes instead, as happens on the wire.
        if self._rust is not None or other._rust is not None:
            new = self._materialize().copy()
            n = len(new.layer_names())
            if n:
                new.set_payload(n - 1, bytes(other))
            return Packet(_rust=new, time=self.time)

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
        for i, (lname, fields) in enumerate(self._stack):
            var = _VAR_FIELD.get(lname)
            for k, v in fields.items():
                # A list of options is encoded and appended to the header rather
                # than written into a fixed-width field.
                if k == "options" and not _is_bytes(v):
                    continue
                if k == "load" and lname in ("Raw", "Padding"):
                    continue
                if var is not None and k == var[0]:
                    continue
                if isinstance(v, (bool, FlagValue)):
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
        return ints, strs, raws

    def _opt_blobs(self) -> list[tuple[int, bytes]]:
        """Encoded option regions, as (layer index, bytes)."""
        out: list[tuple[int, bytes]] = []
        for i, (lname, fields) in enumerate(self._stack):
            if lname in ("Raw", "Padding"):
                load = fields.get("load")
                if load is not None:
                    blob = _to_bytes(load, f"{lname}.load")
                    if blob:
                        out.append((i, blob))
                continue
            var = _VAR_FIELD.get(lname)
            if var is not None:
                blob = fields.get(var[0], var[1]) or b""
                if blob:
                    out.append((i, _to_bytes(blob, f"{lname}.{var[0]}")))
                continue
            v = fields.get("options")
            if v is None or _is_bytes(v):
                if _is_bytes(v) and v:
                    out.append((i, bytes(v)))
                continue
            blob = _encode_options(lname, v)
            if blob:
                out.append((i, blob))
        return out

    def _materialize(self):
        """Build the Rust packet if this is still just a spec."""
        if self._rust is None:
            names = [n for n, _ in self._stack]
            if not names:
                raise ValueError("empty packet")
            ints, strs, raws = self._split_fields()
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
        # A pure spec serialises in one crossing, with no Rust object kept.
        if self._rust is None and self._stack:
            names = [n for n, _ in self._stack]
            ints, strs, raws = self._split_fields()
            return _b.build_and_serialize(
                names, ints, strs, raws, self._payload, self._opt_blobs()
            )
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
        # field values, which is the shape scapy's own suite uses.
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
        yield self.copy()

    def copy(self) -> "Packet":
        """An independent packet carrying the same layers and values."""
        if self._rust is not None:
            return Packet(_rust=self._rust.copy(), time=self.time)
        return Packet(
            _stack=[(n, dict(f)) for n, f in self._stack],
            _payload=self._payload,
            time=self.time,
        )

    def __getattr__(self, field: str) -> Any:
        if field.startswith("_"):
            raise AttributeError(field)
        names = self.layers()
        for i, n in enumerate(names):
            if field in _b.layer_fields(n):
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

    def summary(self) -> str:
        if self._rust is None and self._stack:
            return " / ".join(n for n, _ in self._stack)
        return self._materialize().summary()

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
        return Packet(_rust=rust, time=rust.time)

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
        return filter_packets(self, layer, where)

    def filter_indices(self, layer: Any = None, where: Any = None) -> list[int]:
        """Positions of the matching packets."""
        from .columnar import filter_indices
        return filter_indices(self, layer, where)

    def head(self, n: int) -> "PacketList":
        """The first n packets, as a view. Shares the capture buffer."""
        return PacketList(self._list.head(n))

    def times(self) -> list[float]:
        return self._list.times()

    def raw_at(self, i: int) -> bytes:
        return self._list.raw_at(i)

    def __repr__(self) -> str:
        return f"<PacketList: {len(self)} packets>"


def rdpcap(path: str, count: int = -1) -> PacketList:
    """Read a pcap file. Records are indexed, not dissected, so this is cheap."""
    pl = PacketList(_b.read_pcap(str(path)))
    if count is not None and count >= 0:
        raise NotImplementedError(
            "count= is not implemented yet; slice the PacketList instead"
        )
    return pl


def wrpcap(path: str, packets: Any, linktype: int = 1) -> None:
    """Write packets to a pcap file."""
    if isinstance(packets, (Packet, bytes, bytearray)):
        packets = [packets]
    blobs = [bytes(p) for p in packets]
    _b.write_pcap(str(path), blobs, linktype)


class PcapReader:
    """Streaming reader. Context-manager and iterator, like the familiar one."""

    __slots__ = ("_pl", "_i")

    def __init__(self, path: str):
        self._pl = PacketList(_b.read_pcap(str(path)))
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

    `verbose` keeps the fields a header's own contents make inactive, which are
    otherwise left out for a packet that has been built.
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
