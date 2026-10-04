"""A packet as data, and as the expression that rebuilds it.

`command()` is the strong one: `eval(pkt.command())` must produce the same
octets, which makes it a self-check on the whole build path as well as a way to
turn a captured packet into a script.
"""

from __future__ import annotations

import json as _json
import re
import sys
import warnings
from typing import Any

from . import _wiry as _b

__all__ = ["command", "json_str", "to_dict", "from_hexcap"]


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

    from . import _is_py

    parts = []
    for name, fields in stack:
        held = [v for v in fields.values() if _is_py(v)]
        if held:
            parts.append(held[0].command())
            continue
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
    if pkt._spec_live:
        return _spec_command(pkt._stack)
    rust = _settled(pkt)
    top = pkt._py_top()
    parts = []
    for i, name in enumerate(rust.layer_names()):
        if top is not None and i == top[0]:
            return "/".join(parts + [top[1].command()])
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


# An offset column, then up to 16 hex pairs, then whatever ASCII the tool put
# on the right; tcpdump, Wireshark and `hexdump -C` all fit this.
#
# The offset is recognised only when a colon or two spaces follow it, which
# every dumper emits. scapy accepts one space, and so reads the first octet of
# a pasted bare hex run as an offset and drops it.
_HEXCAP = re.compile(
    r"^\s*(?:(?:0x)?[0-9a-fA-F]{2,}(?::[ \t]*|[ \t]{2,}))?"
    r"((?:[0-9a-fA-F]{2}[ \t]{0,2}){1,16})"
)


def from_hexcap(text: str | None = None) -> bytes:
    """The octets of a pasted hex dump.

    With no argument it reads stdin until a blank line, so a paste at a prompt
    ends by pressing enter twice. A line it cannot read is skipped with a
    warning rather than aborting the paste.
    """
    if text is None:
        lines = []
        for line in sys.stdin:
            if not line.strip():
                break
            lines.append(line)
    else:
        lines = text.splitlines()
    out = bytearray()
    for line in lines:
        if not line.strip():
            continue
        m = _HEXCAP.match(line)
        if m is None:
            warnings.warn(f"skipped an unreadable hexcap line: {line.strip()!r}",
                          stacklevel=2)
            continue
        out += bytes.fromhex(re.sub(r"\s", "", m.group(1)))
    return bytes(out)
