"""Reporting: `sprintf`, per-packet summaries, and flow aggregation.

The format language is the familiar one: ``%[fmt][r],[Layer[:nb].]field%``, the
bare ``%field%`` form, ``%.time%``, ``%%`` for a literal percent, and
``{Layer:...}`` conditional blocks, which nest. A layer or field the packet does
not carry renders as ``??``.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping
from datetime import datetime
from functools import lru_cache
from typing import Any, Callable, Iterable, Iterator, Sequence

from . import FlagValue, PacketList, _LayerView, _b, _flag_names

__all__ = [
    "sprintf", "sprintf_list", "show2_str", "Sessions", "sessions",
    "summary_lines", "conversations", "make_table", "plot",
]


class _Missing:
    __slots__ = ()

    def __repr__(self) -> str:
        return "??"

    __str__ = __repr__


_MISS = _Missing()

_HEAD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?:")

# A `{` past this depth is literal text. Rendering recurses once per level, and
# a format string can come from anywhere.
_MAX_NEST = 64


@lru_cache(maxsize=256)
def _fields_of(layer: str) -> frozenset[str]:
    return frozenset(_b.layer_fields(layer))


@lru_cache(maxsize=256)
def _column_fields(layer: str) -> frozenset[str] | None:
    """Narrower than `layer_fields`: the DNS record sections are served by a
    parser and have no fixed offset, so `columns()` cannot resolve them."""
    try:
        return frozenset(_b.column_fields(layer))
    except ValueError:
        return None


def _directive(body: str) -> tuple | None:
    """`fmt[r],[Layer[:nb].]field`, or None where it is not one, in which case
    the surrounding percent signs are literal text."""
    if not body:
        return None
    spec, sep, ref = body.partition(",")
    if not sep:
        ref, spec = spec, ""
    # The raw flag changes nothing here, since wiry renders no enum names, but
    # it has to come off: `%r` is Python's repr conversion.
    if spec.endswith("r"):
        spec = spec[:-1]
    if ref.startswith("."):
        return ("time", spec) if ref == ".time" else None
    layer: str | None = None
    nb = 1
    if "." in ref:
        head, _, field = ref.partition(".")
        layer, _, num = head.partition(":")
        if num:
            if not num.isdigit():
                return None
            nb = int(num)
    elif ":" in ref:
        # The colon means an occurrence number only when a dot follows it.
        layer, _, field = ref.partition(":")
    else:
        field = ref
    if not field.isidentifier() or (layer is not None and not layer.isidentifier()):
        return None
    return ("fld", layer, nb, field, spec)


@lru_cache(maxsize=256)
def _parse(fmt: str) -> list:
    """One left-to-right pass with an explicit stack of open blocks.

    A `{Layer:` that is never closed is literal text whose body still parses.
    A recursive descent can only deliver that by re-parsing the remainder of
    the string once per unclosed brace, which is exponential in the number of
    them, on a string the caller does not control.
    """
    stack: list[tuple[str, list]] = []
    parts: list = []
    lit: list[str] = []

    def flush() -> None:
        if lit:
            parts.append(("lit", "".join(lit)))
            lit.clear()

    i, n = 0, len(fmt)
    while i < n:
        c = fmt[i]
        if c == "%":
            if fmt.startswith("%%", i):
                lit.append("%")
                i += 2
                continue
            j = fmt.find("%", i + 1)
            d = None if j < 0 else _directive(fmt[i + 1 : j])
            if d is not None:
                flush()
                parts.append(d)
                i = j + 1
                continue
        elif c == "{" and len(stack) < _MAX_NEST:
            head = _HEAD.match(fmt, i + 1)
            if head is not None:
                flush()
                stack.append((head.group(), parts))
                parts = []
                i = head.end()
                continue
        elif c == "}" and stack:
            flush()
            name, outer = stack.pop()
            lname, _, lfield = name[:-1].partition(".")
            outer.append(("cond", lname, lfield or None, parts))
            parts = outer
            i += 1
            continue
        lit.append(c)
        i += 1
    flush()
    while stack:
        name, outer = stack.pop()
        outer.append(("lit", "{" + name))
        outer.extend(parts)
        parts = outer
    return parts


def _apply(value: Any, spec: str) -> str:
    # A modifier over a value the packet does not carry is dropped rather than
    # raising, where scapy raises TypeError.
    if value is _MISS or not spec:
        return str(value)
    try:
        return ("%" + spec) % value
    except (TypeError, ValueError) as exc:
        raise ValueError(f"cannot format {value!r} with %{spec}: {exc}") from exc


def _clock(t: Any) -> str:
    return datetime.fromtimestamp(float(t)).strftime("%H:%M:%S.%f")


class _PktSource:
    """One packet's values, with its layer chain read once."""

    __slots__ = ("pkt", "names")

    def __init__(self, pkt: Any):
        self.pkt = pkt
        self.names = pkt.layers()

    def time(self) -> Any:
        return self.pkt.time

    def value(self, layer: str | None, nb: int, field: str) -> Any:
        seen = 0
        for i, name in enumerate(self.names):
            if layer is None:
                if field not in _fields_of(name):
                    continue
            elif name != layer:
                continue
            else:
                seen += 1
                if seen != nb:
                    continue
            return getattr(_LayerView(self.pkt, i, name), field, _MISS)
        return _MISS

    def present(self, layer: str, field: str | None) -> bool:
        if field is None:
            return layer in self.names
        return self.value(layer, 1, field) is not _MISS


class _ColSource:
    """The same values read from columns; `row` walks the capture."""

    __slots__ = ("cols", "flags", "row")

    def __init__(self, cols: dict, flags: dict):
        self.cols = cols
        self.flags = flags
        self.row = 0

    def time(self) -> Any:
        return self.cols[("Frame", "time")][self.row]

    def value(self, layer: str | None, nb: int, field: str) -> Any:
        v = self.cols[(layer, field)][self.row]
        if v is None:
            return _MISS
        names = self.flags.get((layer, field))
        # A column gives a flags field as its string where a packet gives the
        # rich value; a format modifier would otherwise disagree.
        return v if names is None else FlagValue.from_str(v, names)

    def present(self, layer: str, field: str | None) -> bool:
        if field is None:
            return bool(self.cols[(layer, "")][self.row])
        return self.cols[(layer, field)][self.row] is not None


def _render(parts: Sequence, src: Any) -> str:
    out: list[str] = []
    for p in parts:
        if p[0] == "lit":
            out.append(p[1])
        elif p[0] == "cond":
            if src.present(p[1], p[2]):
                out.append(_render(p[3], src))
        elif p[0] == "time":
            out.append(_apply(_clock(src.time()), p[1]))
        else:
            _, layer, nb, field, spec = p
            out.append(_apply(src.value(layer, nb, field), spec))
    return "".join(out)


def sprintf(pkt: Any, fmt: str) -> str:
    """Render a packet through a format string."""
    return _render(_parse(fmt), _PktSource(pkt))


def show2_str(pkt: Any) -> str:
    """Built, then dissected back, so the lengths and checksums shown are the
    ones that get sent."""
    names = pkt.layers()
    if not names:
        # A zero-length record is ordinary in a truncated capture. Answer it
        # exactly as show() does rather than raising where show() would not.
        return pkt.show_str()
    return _b.dissect(bytes(pkt), names[0]).show()


def _plan(parts: Sequence, need: dict[tuple[str, str], None]) -> bool:
    """Collect the columns a format string needs, or say it needs a packet.

    A bare `%field%` and an occurrence other than the first both depend on the
    layer chain of the individual packet, which a column does not carry.
    """
    for p in parts:
        if p[0] == "lit":
            continue
        if p[0] == "time":
            need[("Frame", "time")] = None
        elif p[0] == "cond":
            known = _column_fields(p[1])
            if known is None or (p[2] is not None and p[2] not in known):
                return False
            # A named field is Null wherever its layer is absent, so it answers
            # presence on its own and the layer column is only needed without.
            need[(p[1], p[2] or "")] = None
            if not _plan(p[3], need):
                return False
        else:
            _, layer, nb, field, _spec = p
            known = None if layer is None else _column_fields(layer)
            if nb != 1 or known is None or field not in known:
                return False
            need[(layer, field)] = None
    return True


def sprintf_list(pl: Any, fmt: str) -> list[str]:
    """Render every packet of a capture through one format string.

    One pass and one crossing: the fields the format names are pulled as
    columns, and no packet is materialised. A format that depends on a
    packet's own layer chain, or names something no column can carry, falls
    back to the per-packet path.
    """
    parts = _parse(fmt)
    need: dict[tuple[str, str], None] = {}
    if not _plan(parts, need):
        return [_render(parts, _PktSource(p)) for p in pl]
    specs = list(need)
    cols = dict(zip(specs, pl._list.columns(specs, None, [])))
    flags = {}
    for layer, field in specs:
        if field and layer != "Frame":
            names = _flag_names(layer, field)
            if names is not None:
                flags[(layer, field)] = names
    src = _ColSource(cols, flags)
    out = []
    for row in range(len(pl)):
        src.row = row
        out.append(_render(parts, src))
    return out


def summary_lines(
    pl: Any,
    prn: Callable[[Any], Any] | None = None,
    lfilter: Callable[[Any], Any] | None = None,
    numbered: bool = False,
) -> Iterator[str]:
    """The number is the packet's position in this list, not in what it was
    filtered from."""
    if prn is None and lfilter is None:
        lines: Iterable[tuple[int, str]] = enumerate(pl._list.summaries())
    else:
        lines = (
            (i, pkt.summary() if prn is None else str(prn(pkt)))
            for i, pkt in enumerate(pl)
            if lfilter is None or lfilter(pkt)
        )
    for i, line in lines:
        yield f"{i:04d} {line}" if numbered else line


class Sessions(Mapping):
    """Flows keyed by address tuple; a flow's view is minted on access."""

    __slots__ = ("_index", "_at", "_cache")

    def __init__(self, keys: Iterable[Any], at: Callable[[int], Any]):
        self._index = {k: i for i, k in enumerate(keys)}
        self._at = at
        self._cache: dict[int, Any] = {}

    def __len__(self) -> int:
        return len(self._index)

    def __iter__(self) -> Iterator[Any]:
        return iter(self._index)

    def __getitem__(self, key: Any) -> Any:
        i = self._index[key]
        view = self._cache.get(i)
        if view is None:
            view = self._cache[i] = PacketList(self._at(i))
        return view

    def __repr__(self) -> str:
        return f"<Sessions: {len(self._index)} flows>"


def sessions(pl: Any, session_extractor: Callable[[Any], Any] | None = None) -> Sessions:
    """Flows, not streams: wiry does not reassemble TCP."""
    rust = pl._list
    if session_extractor is None:
        grouped = rust.sessions()
        return Sessions(grouped.keys(), grouped.at)
    members: dict[Any, list[int]] = {}
    for i, pkt in enumerate(pl):
        members.setdefault(session_extractor(pkt), []).append(i)
    groups = list(members.values())
    return Sessions(members, lambda i: rust.view(groups[i]))


def _endpoints(pl: Any, getsrcdst: Callable[[Any], Any] | None) -> Counter:
    if getsrcdst is None:
        src, dst = pl._list.columns([("IP", "src"), ("IP", "dst")], None, [])
        pairs = ((a, b) for a, b in zip(src, dst) if a is not None and b is not None)
    else:
        pairs = ((p[0], p[1]) for p in map(getsrcdst, pl) if p is not None)
    return Counter(pairs)


def _quote(s: Any) -> str:
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'


def conversations(
    pl: Any,
    getsrcdst: Callable[[Any], Any] | None = None,
    target: Any = None,
    type: str = "svg",
    prog: str = "dot",
) -> Any:
    """Returns DOT source. Graphviz is not a dependency: pass `target` (a path
    or a binary file object) to render through the `dot` program."""
    counts = _endpoints(pl, getsrcdst)
    lines = ['digraph "conversations" {', "  node [shape=box];"]
    for (src, dst), n in counts.items():
        lines.append(f"  {_quote(src)} -> {_quote(dst)} [label={_quote(n)}];")
    lines.append("}")
    dot = "\n".join(lines) + "\n"
    if target is None:
        return dot
    return _render_graph(dot, target, type, prog)


def _render_graph(dot: str, target: Any, type: str, prog: str) -> None:
    import shutil
    import subprocess

    exe = shutil.which(prog)
    if exe is None:
        raise RuntimeError(
            f"{prog} is needed to render a graph but is not on PATH. "
            "Install graphviz, or call conversations() without target= to get "
            "the DOT source."
        )
    out = subprocess.run(
        [exe, f"-T{type}"], input=dot.encode(), stdout=subprocess.PIPE, check=True
    ).stdout
    write = getattr(target, "write", None)
    if write is None:
        with open(target, "wb") as fh:
            fh.write(out)
    else:
        write(out)


def _ordered(values: Iterable[Any]) -> list[Any]:
    vals = list(values)
    try:
        return sorted(vals)
    except TypeError:
        return sorted(vals, key=str)


def make_table(
    pl: Any,
    fn: Callable[[Any], Any],
    lfilter: Callable[[Any], Any] | None = None,
) -> str:
    """`fn` returns `(column, row, cell)` per packet."""
    cells: dict[tuple[Any, Any], str] = {}
    xs: dict[Any, None] = {}
    ys: dict[Any, None] = {}
    for pkt in pl:
        if lfilter is not None and not lfilter(pkt):
            continue
        x, y, z = fn(pkt)
        xs[x] = ys[y] = None
        cells[(x, y)] = str(z)
    cols = _ordered(xs)
    rows = _ordered(ys)
    head = [""] + [str(x) for x in cols]
    body = [[str(y)] + [cells.get((x, y), "") for x in cols] for y in rows]
    width = [max(len(r[c]) for r in [head] + body) for c in range(len(head))]
    return "".join(
        "  ".join(cell.ljust(w) for cell, w in zip(line, width)).rstrip() + "\n"
        for line in [head] + body
    )


def plot(
    pl: Any,
    fn: Callable[[Any], Any],
    lfilter: Callable[[Any], Any] | None = None,
    **kwargs: Any,
) -> Any:
    """matplotlib is imported only if you call this, and is not a dependency."""
    from .columnar import _require

    plt = _require("matplotlib.pyplot", "plot")
    data = [fn(p) for p in pl if lfilter is None or lfilter(p)]
    return plt.plot(data, **kwargs)
