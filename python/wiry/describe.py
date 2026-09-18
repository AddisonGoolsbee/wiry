"""A packet as data, as the expression that rebuilds it, and as a diff.

`command()` is the strong one: `eval(pkt.command())` must produce the same
octets, which makes it a self-check on the whole build path as well as a way to
turn a captured packet into a script.
"""

from __future__ import annotations

import difflib
import json as _json
from typing import Any

from . import _wiry as _b

__all__ = ["command", "json_str", "to_dict", "hexdiff", "hexdiff_str"]

# Aligning two byte strings is quadratic, and a diff of two 64 KB datagrams is
# not what anyone means by hexdiff. Past this, the columns line up by offset.
ALIGN_LIMIT = 4096


def _settled(pkt: Any) -> Any:
    """A packet still being built carries zeroes where its lengths and
    checksums will go; serialising once fills them in, so what is read back is
    what the octets say."""
    rust = pkt._materialize()
    rust.to_bytes()
    return rust


def _values(rust: Any, i: int, name: str, numeric_flags: bool) -> list[tuple[str, Any]]:
    """A parser-backed accessor (`DNS.an`) is listed among a layer's names but
    has no octets of its own, so it is asked for by name rather than discovered
    by catching the lookup failure, which would hide every other one."""
    out = []
    backed = set(rust.accessor_names(i))
    for f in rust.field_names(i):
        if f in backed:
            continue
        v = rust.get_field(i, f)
        if numeric_flags and isinstance(v, str) and _b.flag_names(name, f):
            v = rust.field_uint(i, f)
        out.append((f, v))
    return out


def _spec_command(stack: list) -> str:
    """Rebuilding the recorded assignments reproduces the octets, because
    everything else was already a default."""
    from . import FlagValue

    parts = []
    for name, fields in stack:
        order = {n: i for i, n in enumerate(_b.layer_fields(name))}
        ranked = sorted(
            fields.items(), key=lambda kv: (order.get(kv[0], len(order)), kv[0])
        )
        args = [
            f"{f}={int(v) if isinstance(v, FlagValue) else v!r}" for f, v in ranked
        ]
        parts.append(f"{name}({', '.join(args)})")
    return "/".join(parts)


def command(pkt: Any) -> str:
    """The Python expression that rebuilds this packet.

    A dissected packet names every field, computed ones included, because a
    value the caller supplies is honoured rather than recomputed, which is what
    makes `eval` of the result byte-identical rather than merely equivalent. A
    packet still under construction names only what was assigned to it, since
    the rest is what construction fills in anyway.
    """
    if pkt._rust is None and pkt._stack:
        return _spec_command(pkt._stack)
    rust = _settled(pkt)
    parts = []
    for i, name in enumerate(rust.layer_names()):
        args = []
        suffix = rust.bound_suffix(i)
        for f, v in _values(rust, i, name, numeric_flags=True):
            if isinstance(v, (bytes, bytearray)):
                if suffix and bytes(v).endswith(suffix):
                    v = bytes(v)[: -len(suffix)]
                if not v:
                    continue
            args.append(f"{f}={v!r}")
        parts.append(f"{name}({', '.join(args)})")
    parts += _tail_part(rust)
    return "/".join(parts)


def _tail_part(rust: Any) -> list[str]:
    """Dissection stops at a depth bound, so a chain deeper than that leaves a
    tail no layer named. Dropping it would describe a shorter packet."""
    tail = rust.tail()
    return [f"Raw(load={tail!r})"] if tail else []


def to_dict(pkt: Any) -> dict:
    """The packet's layers and fields as plain JSON-able data. Byte values are
    hex, since JSON has no bytes; a layer name that repeats is suffixed with its
    position."""
    rust = _settled(pkt)
    out: dict[str, Any] = {}
    for i, name in enumerate(rust.layer_names()):
        fields = {
            f: v.hex() if isinstance(v, (bytes, bytearray)) else v
            for f, v in _values(rust, i, name, numeric_flags=False)
        }
        out[name if name not in out else f"{name} {i}"] = fields
    tail = rust.tail()
    if tail:
        out["Raw" if "Raw" not in out else "Raw tail"] = {"load": tail.hex()}
    return out


def json_str(pkt: Any, **kw: Any) -> str:
    return _json.dumps(to_dict(pkt), **kw)


def _aligned(a: bytes, b: bytes) -> tuple[list, list]:
    """Two equal-length rows of octets and gaps. A gap is `None`."""
    left: list = []
    right: list = []
    # difflib's autojunk heuristic stays on: without it a run of one byte
    # (zero padding, which most packets carry) makes the match quadratic —
    # 1.7s for a 4 KB pair here, against 1.2ms with it, for the same opcodes.
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(a=a, b=b).get_opcodes():
        x, y = list(a[i1:i2]), list(b[j1:j2])
        if tag in ("equal", "replace"):
            n = max(len(x), len(y))
            x += [None] * (n - len(x))
            y += [None] * (n - len(y))
        elif tag == "delete":
            y = [None] * len(x)
        else:
            x = [None] * len(y)
        left += x
        right += y
    return left, right


def _col(off: int, cells: list, width: int) -> str:
    hexes = " ".join("  " if c is None else f"{c:02x}" for c in cells)
    text = "".join(
        " " if c is None else (chr(c) if 32 <= c < 127 else ".") for c in cells
    )
    return f"{off:04x}  {hexes:<{width * 3 - 1}}  {text:<{width}}"


def _padded(a: bytes, b: bytes) -> tuple[list, list]:
    left, right = list(a), list(b)
    n = max(len(left), len(right))
    left += [None] * (n - len(left))
    right += [None] * (n - len(right))
    return left, right


def hexdiff_str(a: Any, b: Any, width: int = 16) -> str:
    """Two packets side by side, aligned so an inserted or deleted run does not
    shift everything after it. A row that differs is marked."""
    x, y = bytes(a), bytes(b)
    if max(len(x), len(y)) > ALIGN_LIMIT:
        left, right = _padded(x, y)
    else:
        left, right = _aligned(x, y)
    rows = []
    at_a = at_b = 0
    for at in range(0, len(left), width):
        row_a, row_b = left[at : at + width], right[at : at + width]
        # The marker leads the row: every printable octet can appear in the text
        # column, so a mark between the columns would be ambiguous.
        mark = " " if row_a == row_b else "|"
        rows.append(f"{mark} {_col(at_a, row_a, width)}  {_col(at_b, row_b, width)}".rstrip())
        at_a += sum(1 for c in row_a if c is not None)
        at_b += sum(1 for c in row_b if c is not None)
    return "".join(r + "\n" for r in rows)


def hexdiff(a: Any, b: Any, width: int = 16) -> None:
    print(hexdiff_str(a, b, width), end="")
