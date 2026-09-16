"""blitzpkt: fast packet dissection and crafting with a familiar API.

The engine is Rust. This module is a thin facade whose job is to look like the
packet library people already know, while crossing into Rust as rarely as
possible. Construction accumulates a layer stack in Python and hands the whole
thing over in a single call; dissection keeps the capture in Rust and mints
Python objects only for packets you actually touch.
"""

from __future__ import annotations

from typing import Any, Iterator, Sequence

from . import _blitzpkt as _b

__version__ = _b.__version__

__all__ = [
    "Packet", "PacketList", "rdpcap", "wrpcap", "PcapReader", "raw", "hexdump",
    "hexdump_str", "ls", "known_layers",
]


def _is_bytes(x: Any) -> bool:
    return isinstance(x, (bytes, bytearray, memoryview))


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
        return _b.layer_fields(self._name)

    def __getattr__(self, field: str) -> Any:
        if field.startswith("_"):
            raise AttributeError(field)
        rust = self._pkt._materialize()
        try:
            return rust.get_field(self._idx, field)
        except KeyError as exc:
            raise AttributeError(
                f"{self._name} has no field {field!r}"
            ) from exc

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


class Packet:
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

    # ---- construction -------------------------------------------------

    def __truediv__(self, other: "Packet") -> "Packet":
        """Stack another layer beneath this one."""
        if not isinstance(other, Packet):
            if _is_bytes(other):
                other = Raw(load=bytes(other))
            else:
                return NotImplemented

        # A dissected packet cannot be rebuilt from a field spec: variable-length
        # header content (options, Raw payloads) does not survive the build path,
        # so reconstructing would silently reset every field to its default.
        # Append to the real bytes instead, which is also what happens on the wire.
        if self._rust is not None:
            new = self._rust.copy()
            n = len(new.layer_names())
            if n:
                new.set_payload(n - 1, bytes(other))
            return Packet(_rust=new, time=self.time)

        left = self._spec()
        right = other._spec()
        payload = other._payload if other._payload is not None else self._payload
        return Packet(_stack=left + right, _payload=payload)

    def __rtruediv__(self, other: Any) -> "Packet":
        if _is_bytes(other):
            return Raw(load=bytes(other)) / self
        return NotImplemented

    def _spec(self) -> list[tuple[str, dict]]:
        """The layer stack as (name, fields) pairs, dissecting if needed."""
        if self._stack:
            return [(n, dict(f)) for n, f in self._stack]
        if self._rust is not None:
            return [(n, {}) for n in self._rust.layer_names()]
        return []

    # ---- materialisation ----------------------------------------------

    def _split_fields(self):
        ints: list[tuple[int, str, int]] = []
        strs: list[tuple[int, str, str]] = []
        raws: list[tuple[int, str, bytes]] = []
        for i, (_, fields) in enumerate(self._stack):
            for k, v in fields.items():
                if isinstance(v, bool):
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

    def _materialize(self):
        """Build the Rust packet if this is still just a spec."""
        if self._rust is None:
            names = [n for n, _ in self._stack]
            if not names:
                raise ValueError("empty packet")
            ints, strs, raws = self._split_fields()
            self._rust = _b.build_packet(names, ints, strs, raws, self._payload)
        return self._rust

    def _set(self, layer: int, field: str, value: Any) -> None:
        # Writing invalidates any cached Rust packet only if we are still a spec;
        # once materialised we write through to Rust directly.
        if self._rust is not None:
            if isinstance(value, bool):
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

    # ---- serialisation -------------------------------------------------

    def __bytes__(self) -> bytes:
        # Fast path: a pure spec serialises in one crossing, no Rust object kept.
        if self._rust is None and self._stack:
            names = [n for n, _ in self._stack]
            ints, strs, raws = self._split_fields()
            return _b.build_and_serialize(names, ints, strs, raws, self._payload)
        return self._materialize().to_bytes()

    def build(self) -> bytes:
        return bytes(self)

    def __len__(self) -> int:
        return len(bytes(self))

    # ---- layer access ---------------------------------------------------

    def layers(self) -> list[str]:
        if self._rust is not None:
            return list(self._rust.layer_names())
        return [n for n, _ in self._stack]

    def haslayer(self, layer: Any) -> bool:
        name = _layer_name(layer)
        if self._rust is not None:
            return self._rust.haslayer(name)
        return any(n == name for n, _ in self._stack)

    def getlayer(self, layer: Any) -> _LayerView | None:
        name = _layer_name(layer)
        names = self.layers()
        if name not in names:
            return None
        return _LayerView(self, names.index(name), name)

    def __contains__(self, layer: Any) -> bool:
        return self.haslayer(layer)

    def __getitem__(self, layer: Any) -> _LayerView:
        view = self.getlayer(layer)
        if view is None:
            raise IndexError(f"layer {_layer_name(layer)} not in packet")
        return view

    def __getattr__(self, field: str) -> Any:
        # Only called when normal lookup fails, so this is the field path.
        if field.startswith("_"):
            raise AttributeError(field)
        names = self.layers()
        for i, n in enumerate(names):
            if field in _b.layer_fields(n):
                return self._materialize().get_field(i, field)
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

    # ---- payload ---------------------------------------------------------

    @property
    def payload(self) -> bytes:
        rust = self._materialize()
        n = len(rust.layer_names())
        return rust.payload(n - 1) if n else b""

    # ---- display ---------------------------------------------------------

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


# ---- generated layer classes ---------------------------------------------


def _make_layer(name: str, doc: str = "") -> type:
    def __init__(self, _data: Any = None, **kw: Any) -> None:
        if _data is not None and _is_bytes(_data):
            # Dissecting from bytes, the way a layer class accepts raw input.
            Packet.__init__(self, _rust=_b.dissect(bytes(_data), name))
            return
        payload = None
        if name in ("Raw", "Padding") and "load" in kw:
            payload = bytes(kw.pop("load"))
        Packet.__init__(self, _stack=[(name, dict(kw))], _payload=payload)

    cls = type(name, (Packet,), {
        "__init__": __init__,
        "_name": name,
        "__doc__": doc or f"{name} layer.",
        "__slots__": (),
    })
    return cls


_LAYER_NAMES = list(_b.known_layers())
_LAYERS: dict[str, type] = {}
for _n in _LAYER_NAMES:
    _LAYERS[_n] = _make_layer(_n)
    globals()[_n] = _LAYERS[_n]
    __all__.append(_n)

# Conventional aliases.
Dot1Q = _LAYERS.get("Dot1Q")
IPv6 = _LAYERS.get("IPv6")


def known_layers() -> list[str]:
    """Every layer this build can dissect."""
    return list(_LAYER_NAMES)


# ---- capture files ---------------------------------------------------------


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
        """Pull one field from every packet in a single crossing.

        This is the API that keeps the speedup on bulk work. Prefer it over a
        Python loop when you want one field across a whole capture.
        """
        return self._list.field_column(_layer_name(layer), field)

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


# ---- helpers ---------------------------------------------------------------


def raw(pkt: Any) -> bytes:
    """Serialise a packet to bytes."""
    return bytes(pkt)


def hexdump(pkt: Any, width: int = 16) -> None:
    print(hexdump_str(pkt, width), end="")


def hexdump_str(pkt: Any, width: int = 16) -> str:
    data = bytes(pkt) if not _is_bytes(pkt) else bytes(pkt)
    out = []
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{off:04x}  {hexpart:<{width * 3}} {text}\n")
    return "".join(out)


def ls(layer: Any = None) -> None:
    """List known layers, or the fields of one."""
    if layer is None:
        for n in _LAYER_NAMES:
            print(n)
        return
    name = _layer_name(layer)
    for f in _b.layer_fields(name):
        print(f"{f}")
