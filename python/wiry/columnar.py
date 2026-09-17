"""Columnar access: a whole capture as columns in one crossing of the boundary.

A spec is ``(layer, field)``, ``(layer, field, name)`` or ``"IP.src"``. The
pseudo-layer ``Frame`` carries per-record metadata: ``time`` (seconds), ``len``
(captured bytes) and ``num`` (position in the capture this one was filtered
from).

Rows are selected with ``layer=`` and ``where=``, both evaluated in Rust.
``where`` is data, not code: ``[("TCP", "dport", "==", 443)]``. Operators are
``== != < <= > >=``. A condition on a layer the packet does not have is false.
"""

from __future__ import annotations

import importlib
from typing import Any, Iterable

from . import _layer_name

__all__ = [
    "DEFAULT_SPECS", "columns", "to_dict", "filter_packets", "filter_indices",
    "to_arrow", "to_polars", "to_pandas",
]

Spec = Any
Where = Any

DEFAULT_SPECS: list[tuple[str, str]] = [
    ("Frame", "time"),
    ("Frame", "len"),
    ("Ether", "src"),
    ("Ether", "dst"),
    ("IP", "src"),
    ("IP", "dst"),
    ("IP", "proto"),
    ("TCP", "sport"),
    ("TCP", "dport"),
    ("UDP", "sport"),
    ("UDP", "dport"),
]


def _rust(cap: Any) -> Any:
    inner = getattr(cap, "_list", None)
    return cap if inner is None else inner


def _split_spec(spec: Spec) -> tuple[str, str, str]:
    if isinstance(spec, str):
        layer, dot, field = spec.partition(".")
        if not dot or not field:
            raise ValueError(f"bad column spec {spec!r}; expected 'Layer.field'")
        return layer, field, spec
    parts = tuple(spec)
    if len(parts) == 2:
        layer, field = parts
        name = f"{_layer_name(layer)}.{field}"
    elif len(parts) == 3:
        layer, field, name = parts
    else:
        raise ValueError(
            f"bad column spec {spec!r}; expected (layer, field) or (layer, field, name)"
        )
    return _layer_name(layer), str(field), str(name)


def _normalize_specs(specs: Iterable[Spec] | None) -> tuple[list[tuple[str, str]], list[str]]:
    if specs is None:
        specs = DEFAULT_SPECS
    pairs: list[tuple[str, str]] = []
    names: list[str] = []
    for spec in specs:
        layer, field, name = _split_spec(spec)
        pairs.append((layer, field))
        names.append(name)
    if len(set(names)) != len(names):
        dupes = sorted({n for n in names if names.count(n) > 1})
        raise ValueError(f"duplicate column names: {', '.join(dupes)}")
    return pairs, names


def _normalize_where(where: Where) -> list[tuple[str, str, str, Any]]:
    if where is None:
        return []
    if isinstance(where, tuple) and where and isinstance(where[0], (str, type)):
        where = [where]
    out: list[tuple[str, str, str, Any]] = []
    for cond in where:
        parts = tuple(cond)
        if len(parts) == 3:
            layer, field, value = parts
            op = "=="
        elif len(parts) == 4:
            layer, field, op, value = parts
        else:
            raise ValueError(
                f"bad condition {cond!r}; expected (layer, field, op, value)"
            )
        out.append((_layer_name(layer), str(field), str(op), value))
    return out


def columns(
    cap: Any,
    specs: Iterable[Spec] | None = None,
    where: Where = None,
    layer: Any = None,
) -> dict[str, list[Any]]:
    """Extract several fields from a whole capture in one pass.

    Returns a dict of column name to list; a packet lacking a layer yields None
    for its fields. ``layer`` and ``where`` select rows in Rust, so a rejected
    packet is never materialised.
    """
    pairs, names = _normalize_specs(specs)
    cols = _rust(cap).columns(
        pairs,
        None if layer is None else _layer_name(layer),
        _normalize_where(where),
    )
    return dict(zip(names, cols))


def to_dict(
    cap: Any,
    specs: Iterable[Spec] | None = None,
    where: Where = None,
    layer: Any = None,
) -> dict[str, list[Any]]:
    """The capture as a plain dict of lists. No third-party dependency."""
    return columns(cap, specs, where=where, layer=layer)


def filter_indices(cap: Any, layer: Any = None, where: Where = None) -> list[int]:
    """Positions of the packets matching the query, evaluated in Rust."""
    return list(
        _rust(cap).filter_indices(
            None if layer is None else _layer_name(layer), _normalize_where(where)
        )
    )


def filter_packets(cap: Any, layer: Any = None, where: Where = None) -> Any:
    """A PacketList over the matching packets, sharing the capture buffer."""
    from . import PacketList

    return PacketList(
        _rust(cap).filter(
            None if layer is None else _layer_name(layer), _normalize_where(where)
        )
    )


def _require(module: str, extra: str) -> Any:
    try:
        return importlib.import_module(module)
    except ImportError as exc:
        raise ImportError(
            f"{module} is needed for this export but is not installed. "
            f"Install it with `pip install 'wiry[{extra}]'` "
            f"or `pip install {module}`."
        ) from exc


def to_arrow(
    cap: Any,
    specs: Iterable[Spec] | None = None,
    where: Where = None,
    layer: Any = None,
) -> Any:
    """The capture as a `pyarrow.Table`."""
    pa = _require("pyarrow", "arrow")
    return pa.table(columns(cap, specs, where=where, layer=layer))


def to_polars(
    cap: Any,
    specs: Iterable[Spec] | None = None,
    where: Where = None,
    layer: Any = None,
) -> Any:
    """The capture as a `polars.DataFrame`."""
    pl = _require("polars", "polars")
    return pl.DataFrame(columns(cap, specs, where=where, layer=layer))


def to_pandas(
    cap: Any,
    specs: Iterable[Spec] | None = None,
    where: Where = None,
    layer: Any = None,
) -> Any:
    """The capture as a `pandas.DataFrame`."""
    pd = _require("pandas", "pandas")
    return pd.DataFrame(columns(cap, specs, where=where, layer=layer))
