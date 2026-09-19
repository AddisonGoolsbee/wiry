"""`ls()`, `lsc()` and `explore()`: the discovery surface.

Ninety-one layers is more than anyone remembers. At a prompt these three are
how a user finds a layer, finds its fields, and finds the function that does
the thing — so they are part of the API, not a convenience.

Shaped after scapy's, which they derive from; what they print is wiry's own
field model rather than scapy's `Field` classes, so the type column names a
kind and a width instead of a class.
"""

from __future__ import annotations

import re
import sys
from typing import Any, Iterator, Optional, Sequence

from . import _b, _layer_name

__all__ = ["ls", "lsc", "explore", "commands", "field_table", "FieldInfo"]


class FieldInfo:
    """One field of a layer, as the engine declares it.

    `bits` is the declared width; a `varbytes` field has none, because it runs
    to the end of the header it is in.
    """

    __slots__ = ("name", "bits", "kind", "computed", "conditional", "flags")

    def __init__(self, name: str, bits: int, kind: str, computed: bool,
                 conditional: bool, flags: Optional[tuple]):
        self.name = name
        self.bits = bits
        self.kind = kind
        self.computed = computed
        self.conditional = conditional
        self.flags = flags

    @property
    def type(self) -> str:
        """The type column: a kind, a width where the width is not implied,
        and the markers that change how a value is treated."""
        extra = []
        if self.kind in ("uint", "le_uint", "flags", "bytes"):
            if self.bits % 8:
                extra.append(f"{self.bits} bits")
            else:
                n = self.bits // 8
                extra.append(f"{n} byte" if n == 1 else f"{n} bytes")
        if self.computed:
            extra.append("computed")
        if self.conditional:
            extra.append("Cond")
        return f"{self.kind} ({', '.join(extra)})" if extra else self.kind

    def __repr__(self) -> str:
        return f"<Field {self.name}: {self.type}>"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, FieldInfo):
            return self.name == other.name and self.kind == other.kind
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.name, self.kind))


_TABLES: dict[str, list[FieldInfo]] = {}


def field_table(layer: Any) -> list[FieldInfo]:
    """Every field a layer declares, in header order. Cached: one crossing per
    layer, not one per lookup."""
    name = _layer_name(layer)
    table = _TABLES.get(name)
    if table is None:
        table = [
            FieldInfo(f, bits, kind, computed, cond,
                      tuple(_b.flag_names(name, f) or ()) or None)
            for f, bits, kind, computed, cond in _b.field_specs(name)
        ]
        _TABLES[name] = table
    return table


_DEFAULTS: dict[str, dict[str, Any]] = {}


def _defaults(name: str) -> dict[str, Any]:
    """What a bare layer holds. Read off one built instance rather than from a
    table, so it is the value the build path actually writes.

    A computed field reads as `None`: it has no default, it has whatever the
    octets around it make it.
    """
    known = _DEFAULTS.get(name)
    if known is not None:
        return known
    from . import _LAYERS

    out: dict[str, Any] = {}
    try:
        rust = _LAYERS[name]()._materialize()
        active = set(rust.field_names(0))
    except Exception:
        rust, active = None, set()
    for info in field_table(name):
        if info.computed or rust is None or info.name not in active:
            out[info.name] = None
            continue
        try:
            out[info.name] = rust.get_field(0, info.name)
        except Exception:
            out[info.name] = None
    _DEFAULTS[name] = out
    return out


def _layer_line(name: str) -> str:
    table = field_table(name)
    from . import _LAYERS

    try:
        size = len(bytes(_LAYERS[name]()))
    except Exception:
        size = 0
    plural = "" if len(table) == 1 else "s"
    return f"{len(table)} field{plural}, {size} octets"


def _matching(pattern: str, case_sensitive: bool) -> list[str]:
    """Relevance first, then length, as scapy's search does: an exact prefix
    beats a name that merely contains the text."""
    flags = 0 if case_sensitive else re.I
    try:
        rx = re.compile(pattern, flags)
    except re.error as exc:
        raise ValueError(f"bad layer pattern {pattern!r}: {exc}") from exc
    hits = [n for n in _b.known_layers() if rx.search(n)]
    needle = pattern if case_sensitive else pattern.lower()

    def rank(n: str) -> tuple:
        hay = n if case_sensitive else n.lower()
        at = hay.find(needle)
        return (len(n) if at < 0 else at, len(n), n)

    return sorted(hits, key=rank)


def _value_rows(pkt: Any, idx: int, name: str,
                verbose: bool) -> Iterator[tuple[FieldInfo, Any]]:
    rust = pkt._materialize()
    active = set(rust.field_names(idx))
    for info in field_table(name):
        if not verbose and info.name not in active:
            continue
        gen = pkt._generator_at(idx, info.name)
        if gen is not None:
            yield info, gen
            continue
        try:
            yield info, rust.get_field(idx, info.name)
        except Exception:
            yield info, None


def _print_fields(rows: Sequence[tuple], with_value: bool,
                  verbose: bool) -> None:
    """Columns are sized from the rows, so a long field name shifts the table
    rather than breaking it, which is a wart scapy's fixed widths have."""
    if not rows:
        return
    wide = max(12, max(len(f.name) for f, _, _ in rows))
    kind = max(20, max(len(f.type) for f, _, _ in rows))
    for info, value, default in rows:
        head = f"{info.name:<{wide}} : {info.type:<{kind}} ="
        if with_value:
            print(f"{head} {value!r:<15} ({default!r})")
        else:
            print(f"{head} ({default!r})")
        if verbose and info.flags:
            print(f"{'':<{wide + 3}}{', '.join(info.flags)}")


def _print_layer(pkt: Any, idx: int, name: str, verbose: bool) -> None:
    # scapy separates layers with a bare `--`; naming each one costs nothing
    # and is what a reader is looking for.
    print(f"###[ {name} ]###")
    defaults = _defaults(name)
    _print_fields(
        [(f, v, defaults.get(f.name))
         for f, v in _value_rows(pkt, idx, name, verbose)],
        True, verbose,
    )


def ls(obj: Any = None, case_sensitive: bool = False,
       verbose: bool = False) -> None:
    """List the layers, search them, or show what one layer holds.

    `ls()` lists every layer, `ls("tcp")` the ones whose name matches,
    `ls(IP)` the fields IP declares with their defaults, and `ls(pkt)` those
    fields with the values this packet carries. `verbose` adds the flag names
    of a flags field and keeps the fields a header's own contents made
    inactive.
    """
    from . import Packet, _LayerView

    if isinstance(obj, _LayerView):
        _print_layer(obj._pkt, obj._idx, obj._name, verbose)
        return

    if obj is None or isinstance(obj, str):
        names = _b.known_layers() if obj is None else _matching(obj, case_sensitive)
        for n in (sorted(names) if obj is None else names):
            print("%-14s : %s" % (n, _layer_line(n)))
        if obj is None:
            print("\nTIP: explore(Layer) shows one layer in full; "
                  "lsc() lists the commands.")
        return

    if isinstance(obj, Packet):
        for i, n in enumerate(obj.layers()):
            _print_layer(obj, i, n, verbose)
        return

    try:
        name = _layer_name(obj)
        table = field_table(name)
    except (TypeError, ValueError):
        print("Not a packet class or name. Type 'ls()' to list packet classes.")
        return
    defaults = _defaults(name)
    _print_fields([(f, None, defaults.get(f.name)) for f in table],
                  False, verbose)


def commands() -> list[tuple[str, str]]:
    """Every function wiry exports, with the first line of its documentation.

    Functions only: a class here is a layer, a value like `RandIP`, or a
    reader, and none of those is what "what can I call" means.
    """
    import wiry

    out = []
    for name in sorted(set(wiry.__all__)):
        try:
            obj = getattr(wiry, name)
        except (AttributeError, ImportError):
            continue
        if isinstance(obj, type) or not callable(obj):
            continue
        doc = (obj.__doc__ or "--").lstrip().split("\n", 1)[0]
        out.append((name, doc))
    return out


def lsc(match: Optional[str] = None) -> None:
    """List the commands wiry exports, or those whose name matches."""
    for name, doc in commands():
        if match is None or match.lower() in name.lower():
            print("%-22s: %s" % (name, doc))


def _bindings(name: str) -> list[str]:
    """Bindings `bind_layers()` registered on this layer. The built-in chain is
    static dispatch in Rust and is not enumerable, so this lists what was added
    at runtime and says nothing about the rest."""
    from . import _RUNTIME_BINDS

    out = []
    for parent, child, conds in _RUNTIME_BINDS:
        if parent == name:
            terms = ", ".join(f"{k}={v!r}" for k, v in conds) or "always"
            out.append(f"  {name} -> {child:<14} when {terms}")
        elif child == name:
            terms = ", ".join(f"{k}={v!r}" for k, v in conds) or "always"
            out.append(f"  {parent:<14} -> {name} when {terms}")
    return out


def _pick_layer() -> Optional[str]:
    """A picker when prompt_toolkit is there, a printed list when it is not.
    Neither is an install-time dependency."""
    names = sorted(_b.known_layers())
    try:
        from prompt_toolkit.shortcuts import radiolist_dialog
    except ImportError:
        print(f"{len(names)} layers:\n")
        width = max(len(n) for n in names) + 2
        per = max(1, 78 // width)
        for i in range(0, len(names), per):
            print("".join(n.ljust(width) for n in names[i : i + per]))
        print("\nexplore(Layer) shows one in full. prompt_toolkit, which "
              "IPython brings, turns this into a picker.")
        return None
    if not sys.stdin.isatty():
        raise RuntimeError("explore() with no argument needs a terminal; "
                           "pass a layer instead")
    return radiolist_dialog(
        title="wiry",
        text="Choose a layer:",
        values=[(n, f"{n:<14} {_layer_line(n)}") for n in names],
    ).run()


def explore(layer: Any = None) -> None:
    """Show one layer in full: its fields, its flag names, its option support
    and the bindings registered on it. With no argument, pick one."""
    if layer is None:
        layer = _pick_layer()
        if layer is None:
            return
    name = _layer_name(layer)
    if name not in _b.known_layers():
        raise ValueError(f"no layer named {name!r}; ls() lists them")
    table = field_table(name)
    print(f"###[ {name} ]### {_layer_line(name)}\n")
    ls(_lookup(name), verbose=True)
    parsed = _b.parsed_field(name)
    if any(f.name == parsed for f in table):
        print(f"\nVariable-length region: {parsed} "
              f"(pkt[{name}].{parsed} parses it, raw_options() does not)")
    binds = _bindings(name)
    if binds:
        print("\nBindings registered at runtime:")
        for line in binds:
            print(line)


def _lookup(name: str) -> Any:
    from . import _LAYERS

    return _LAYERS[name]
