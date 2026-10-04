"""Convert scapy layer classes into protogen specs.

Run:  python dev/protogen/scapy2spec.py scapy.layers.ppp --id-base 1100
      python dev/protogen/scapy2spec.py --all --report-only --report r.json

A dev tool, like protogen itself: it imports scapy, which nothing shipped may.
Each `Packet` subclass a module defines is introspected at run time — the field
objects already carry their widths, defaults, enum tables and length links, so
nothing is parsed out of scapy's source — and written out as a spec under
`specs/scapy/<module>/`, which `protogen.py` then turns into Rust.

Three outcomes per class, and the report says which and why:

  clean     every field maps, and the spec agrees with scapy on every input the
            verifier tried, in both directions
  partial   the layout is right but something scapy does is not reproduced (an
            enum the engine cannot name yet, a signed value read unsigned, a
            subclass chosen by code); written only with `--emit partial`
  refused   the format cannot express it; nothing is written

The verifier is what makes "clean" mean something. Lambdas are not parsed but
run, against a stand-in packet whose fields are symbols, with every branch they
take explored; the expression that comes back is what the spec says. Then the
spec is decoded in Python the way the engine decodes it and compared with
scapy's own dissection of a few hundred inputs, and with scapy's default build.
A spec that disagrees with scapy anywhere is refused, not emitted.

wiry derives from scapy under GPL-2.0-only; each emitted spec carries a
`[provenance]` block, and `NOTICE` records the converter itself.
"""

from __future__ import annotations

import argparse
import importlib
import json
import pkgutil
import random
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPECS = Path(__file__).resolve().parent / "specs"
OUT = SPECS / "scapy"

import scapy  # noqa: E402
import scapy.fields as F  # noqa: E402
from scapy.packet import Packet  # noqa: E402
from scapy.volatile import VolatileValue  # noqa: E402

SCAPY_VERSION = f"scapy {scapy.__version__}"
TODAY = "2026-10-03"


class Refuse(Exception):
    """The format cannot express this; `code` is the report's machine key."""

    def __init__(self, code: str, why: str):
        super().__init__(why)
        self.code = code
        self.why = why


# --------------------------------------------------------------------------
# symbolic evaluation of scapy's lambdas


class Explorer:
    """Every `bool()` of a symbol is a branch. Forcing a prefix of decisions and
    defaulting the rest to True enumerates each path exactly once."""

    active: "Explorer | None" = None

    def __init__(self, forced: list[bool]):
        self.forced = forced
        self.taken: list[tuple[tuple, bool]] = []

    def decide(self, e: tuple) -> bool:
        i = len(self.taken)
        d = self.forced[i] if i < len(self.forced) else True
        self.taken.append((e, d))
        return d


def lift(o) -> tuple:
    if isinstance(o, Sym):
        return o.e
    if isinstance(o, bool):
        return ("const", int(o))
    if isinstance(o, int):
        return ("const", o)
    raise Refuse("lambda_value", f"a lambda mixes a field with {type(o).__name__}")


def _bin(op):
    def f(self, o):
        return Sym(("bin", op, self.e, lift(o)))

    def r(self, o):
        return Sym(("bin", op, lift(o), self.e))

    return f, r


def _cmp(op):
    def f(self, o):
        return Sym(("cmp", op, self.e, lift(o)))

    return f


class Sym:
    """A field's value inside a lambda. Arithmetic and comparison build an
    expression; anything else — an attribute, a hash, a call — refuses."""

    __slots__ = ("e",)

    def __init__(self, e):
        object.__setattr__(self, "e", e)

    __add__, __radd__ = _bin("+")
    __sub__, __rsub__ = _bin("-")
    __mul__, __rmul__ = _bin("*")
    __floordiv__, __rfloordiv__ = _bin("//")
    __mod__, __rmod__ = _bin("%")
    __and__, __rand__ = _bin("&")
    __or__, __ror__ = _bin("|")
    __xor__, __rxor__ = _bin("^")
    __lshift__, __rlshift__ = _bin("<<")
    __rshift__, __rrshift__ = _bin(">>")
    __eq__ = _cmp("==")
    __ne__ = _cmp("!=")
    __lt__ = _cmp("<")
    __le__ = _cmp("<=")
    __gt__ = _cmp(">")
    __ge__ = _cmp(">=")

    def __neg__(self):
        return Sym(("bin", "-", ("const", 0), self.e))

    def __invert__(self):
        return Sym(("inv", self.e))

    def __bool__(self):
        if Explorer.active is None:
            raise Refuse("lambda_branch", "a lambda branches outside exploration")
        return Explorer.active.decide(self.e)

    def __truediv__(self, o):
        raise Refuse("lambda_float", "a lambda divides into a float")

    __rtruediv__ = __truediv__

    def __hash__(self):
        raise Refuse("lambda_hash", "a lambda looks a field up in a table")

    def __index__(self):
        raise Refuse("lambda_index", "a lambda uses a field as an index")

    __int__ = __index__

    def __len__(self):
        raise Refuse("lambda_len", "a lambda takes the length of a field")

    def __getattr__(self, name):
        raise Refuse("lambda_attr", f"a lambda reads .{name} of a field")

    def __iter__(self):
        raise Refuse("lambda_iter", "a lambda iterates a field")


class StandIn:
    """The `pkt` a lambda is handed. Only the fields the flat layout can read at
    a fixed place answer; everything else names what the lambda needed."""

    def __init__(self, readable: set[str], extra: dict | None = None):
        object.__setattr__(self, "_readable", readable)
        object.__setattr__(self, "_extra", extra or {})

    def __getattr__(self, name):
        if name in self._extra:
            return self._extra[name]
        if name in self._readable:
            return Sym(("field", name))
        raise Refuse("lambda_reads", f"a lambda reads pkt.{name}")

    def getfieldval(self, name):
        return self.__getattr__(name)

    def __setattr__(self, k, v):
        raise Refuse("lambda_writes", "a lambda writes to the packet")


MAX_PATHS = 64


def explore(fn, *args) -> list[tuple[list, object]]:
    """Every path through `fn`, as (decisions, result)."""
    out = []
    todo: list[list[bool]] = [[]]
    while todo:
        if len(out) >= MAX_PATHS:
            raise Refuse("lambda_paths", "a lambda has too many branches")
        forced = todo.pop()
        ex = Explorer(forced)
        prev, Explorer.active = Explorer.active, ex
        try:
            val = fn(*args)
        except Refuse:
            raise
        except Exception as e:  # noqa: BLE001
            raise Refuse("lambda_error", f"a lambda raised {type(e).__name__}: {e}")
        finally:
            Explorer.active = prev
        for i in range(len(forced), len(ex.taken)):
            todo.append([d for _, d in ex.taken[:i]] + [not ex.taken[i][1]])
        out.append((ex.taken, val))
    return out


def render(e: tuple) -> str:
    k = e[0]
    if k == "field":
        return e[1]
    if k == "const":
        return str(e[1])
    if k == "bin":
        return f"({render(e[2])} {e[1]} {render(e[3])})"
    if k == "cmp":
        return f"({render(e[2])} {e[1]} {render(e[3])})"
    if k == "inv":
        return f"(~{render(e[1])})"
    if k == "not":
        return f"(not {render(e[1])})"
    if k == "and":
        return "(" + " and ".join(render(x) for x in e[1]) + ")"
    if k == "or":
        return "(" + " or ".join(render(x) for x in e[1]) + ")"
    if k == "if":
        return f"({render(e[2])} if {render(e[1])} else {render(e[3])})"
    raise ValueError(e)


def fields_in(e: tuple) -> set[str]:
    if e[0] == "field":
        return {e[1]}
    out: set[str] = set()
    for x in e[1:]:
        if isinstance(x, tuple):
            out |= fields_in(x)
        elif isinstance(x, list):
            for y in x:
                out |= fields_in(y)
    return out


def consts_in(e: tuple) -> set[int]:
    if e[0] == "const":
        return {e[1]}
    out: set[int] = set()
    for x in e[1:]:
        if isinstance(x, tuple):
            out |= consts_in(x)
        elif isinstance(x, list):
            for y in x:
                out |= consts_in(y)
    return out


def path_cond(taken) -> tuple:
    terms = [e if d else ("not", e) for e, d in taken]
    if not terms:
        return ("const", 1)
    return terms[0] if len(terms) == 1 else ("and", terms)


def predicate(fn, readable: set[str]) -> tuple:
    """A condition lambda as one boolean expression."""
    alts = []
    for taken, val in explore(fn, StandIn(readable)):
        if isinstance(val, Sym):
            alts.append(("and", [path_cond(taken), val.e]) if taken else val.e)
        elif val:
            alts.append(path_cond(taken))
    if not alts:
        return ("const", 0)
    return alts[0] if len(alts) == 1 else ("or", alts)


def quantity(fn, *args) -> tuple:
    """A length or count lambda as one integer expression."""
    paths = explore(fn, *args)
    vals = []
    for taken, val in paths:
        if isinstance(val, bool) or not isinstance(val, (int, Sym)):
            raise Refuse("lambda_value", f"a length lambda returns {type(val).__name__}")
        vals.append((taken, lift(val)))
    e = vals[-1][1]
    for taken, v in reversed(vals[:-1]):
        e = ("if", path_cond(taken), v, e)
    return e


def unclamp(e: tuple) -> tuple:
    """`max(0, x)` as `x`, for a consumer that clamps at zero itself."""
    if e[0] == "if" and e[1][0] == "cmp" and e[1][3] == ("const", 0):
        op, a = e[1][1], e[1][2]
        if op in (">", ">=") and e[2] == a and e[3] == ("const", 0):
            return unclamp(a)
        if op in ("<", "<=") and e[2] == ("const", 0) and e[3] == a:
            return unclamp(a)
    return e


def linear(e: tuple, var: str | None = None) -> tuple[str | None, int, int] | None:
    """`a * f + b` over one field, or None."""
    e = unclamp(e)
    k = e[0]
    if k == "const":
        return (None, 0, e[1])
    if k == "field":
        if var is not None and e[1] != var:
            return None
        return (e[1], 1, 0)
    if k != "bin" or e[1] not in "+-*":
        return None
    a, b = linear(e[2], var), linear(e[3], var)
    if a is None or b is None:
        return None
    if e[1] in "+-":
        s = 1 if e[1] == "+" else -1
        if a[0] and b[0] and a[0] != b[0]:
            return None
        return (a[0] or b[0], a[1] + s * b[1], a[2] + s * b[2])
    if a[0] and b[0]:
        return None
    if a[0] is None:
        a, b = b, a
    return (a[0], a[1] * b[2], a[2] * b[2]) if a[0] else (None, 0, a[2] * b[2])


def evaluate(e: tuple, env: dict[str, int]) -> int:
    """The engine's arithmetic: integers, floor division, nothing raises."""
    k = e[0]
    if k == "field":
        return env.get(e[1], 0)
    if k == "const":
        return e[1]
    if k == "inv":
        return ~evaluate(e[1], env)
    if k == "not":
        return int(not evaluate(e[1], env))
    if k == "and":
        return int(all(evaluate(x, env) for x in e[1]))
    if k == "or":
        return int(any(evaluate(x, env) for x in e[1]))
    if k == "if":
        return evaluate(e[2], env) if evaluate(e[1], env) else evaluate(e[3], env)
    a, b = evaluate(e[2], env), evaluate(e[3], env)
    op = e[1]
    if k == "cmp":
        return int({"==": a == b, "!=": a != b, "<": a < b, "<=": a <= b,
                    ">": a > b, ">=": a >= b}[op])
    if op == "+":
        return a + b
    if op == "-":
        return a - b
    if op == "*":
        return a * b
    if op == "//":
        return a // b if b else 0
    if op == "%":
        return a % b if b else 0
    if op == "&":
        return a & b
    if op == "|":
        return a | b
    if op == "^":
        return a ^ b
    if op == "<<":
        return a << b if 0 <= b < 64 else 0
    if op == ">>":
        return a >> b if 0 <= b < 64 else 0
    raise ValueError(op)


# --------------------------------------------------------------------------
# field mapping

BE_UINT = {
    "ByteField", "XByteField", "ShortField", "XShortField", "IntField",
    "XIntField", "LongField", "XLongField", "ByteEnumField", "XByteEnumField",
    "ShortEnumField", "XShortEnumField", "IntEnumField", "XIntEnumField",
    "LongEnumField", "FieldLenField", "UTCTimeField", "LenField",
}
LE_UINT = {
    "LEShortField", "LEIntField", "LELongField", "XLEShortField", "XLEIntField",
    "XLELongField", "LEShortEnumField", "LEIntEnumField", "LEFieldLenField",
}
SIGNED = {"SignedByteField", "SignedShortField", "SignedIntField", "SignedLongField",
          "LESignedShortField", "LESignedIntField", "LESignedLongField",
          "SignedByteEnumField", "SignedShortEnumField", "SignedIntEnumField"}
THREE = {"ThreeBytesField": False, "X3BytesField": False, "OUIField": False,
         "LEThreeBytesField": True, "XLE3BytesField": True, "LEX3BytesField": True}
BITS = {"BitField", "XBitField", "BitEnumField", "BitFieldLenField", "FlagsField",
        "FixedPointField", "TimeStampField", "BitMultiEnumField"}
IPV4 = {"IPField", "SourceIPField", "DestIPField"}
IPV6 = {"IP6Field", "SourceIP6Field", "DestIP6Field"}
MAC = {"MACField", "SourceMACField", "DestMACField"}
FIXED_BYTES = {"StrFixedLenField", "XStrFixedLenField", "StrFixedLenEnumField"}
TAIL_BYTES = {"StrField", "XStrField"}
LEN_BYTES = {"StrLenField", "XStrLenField"}
LISTS = {"PacketListField", "FieldListField"}
WRAPPERS = {"ConditionalField", "PadField", "MayEnd", "Emph", "ReversePadField"}

# A field class the report should name precisely, because its refusal is a
# category phase 2 will plan around rather than a one-off.
REFUSAL_CODE = {
    "MultipleTypeField": "multiple_type",
    "PacketField": "packet_field",
    "PacketLenField": "packet_field",
    "StrNullField": "null_terminated",
    "DNSStrField": "dns_name",
}


def refusal_code(cls_name: str) -> str:
    if cls_name.startswith("ASN1F_"):
        return "asn1"
    if cls_name.startswith("NDR"):
        return "ndr"
    return REFUSAL_CODE.get(cls_name, f"field:{cls_name}")


def constant_len(fn) -> int | None:
    try:
        n = fn(StandIn(set()))
    except Refuse:
        return None
    except Exception:  # noqa: BLE001
        return None
    return n if isinstance(n, int) and not isinstance(n, bool) else None


class Layout:
    """The analysis of one class: what protogen will be told, plus everything
    the verifier needs to decode the same bytes the engine will."""

    def __init__(self, cls):
        self.cls = cls
        self.fields: list[dict] = []
        self.partial: list[tuple[str, str]] = []
        self.notes: list[str] = []
        self.group: dict | None = None
        self.header_len = None  # int | "rest" | {"base", "expr"}
        self.set_len: dict | None = None
        self.min_len = 0
        self.length_links: dict[str, dict] = {}
        self.truncated_tail = False

    def gap(self, code, why):
        if (code, why) not in self.partial:
            self.partial.append((code, why))


def unwrap(f):
    """Peel the wrappers off a field: (inner field, condition, pad, may_end)."""
    cond = None
    pad = 1
    may_end = False
    while type(f).__name__ in WRAPPERS:
        n = type(f).__name__
        if n == "ConditionalField":
            if cond is not None:
                raise Refuse("nested_cond", "a ConditionalField inside another")
            cond = f.cond
        elif n in ("PadField", "ReversePadField"):
            if n == "ReversePadField":
                raise Refuse("field:ReversePadField", "padding ahead of a field")
            pad = f._align
            if getattr(f, "_padwith", b"\x00") not in (b"\x00", None):
                raise Refuse("pad_bytes", "padding with something other than zeros")
        elif n == "MayEnd":
            may_end = True
        f = f.fld
    return f, cond, pad, may_end


def int_default(f, d, bits: int, lay: Layout) -> int:
    if d is None:
        return 0
    if isinstance(d, VolatileValue):
        lay.gap("random_default", f"{f.name} defaults to a random {type(d).__name__}")
        return 0
    try:
        v = int(d)
    except Exception:  # noqa: BLE001
        try:
            v = int(f.any2i(None, d))
        except Exception:  # noqa: BLE001
            raise Refuse("default", f"{f.name}'s default {d!r} is not an integer")
    return v & ((1 << bits) - 1) if bits else v


HOST_ENUMS = ("ETHER_TYPES", "IP_PROTOS", "TCP_SERVICES", "UDP_SERVICES", "SCTP_SERVICES")


def host_enum(i2s: dict) -> str | None:
    """A table scapy loads from the host, which protogen names rather than
    copies, so wiry reads the same /etc files scapy does."""
    import scapy.data as D

    for name in HOST_ENUMS:
        table = getattr(D, name, None)
        try:
            if len(i2s) == len(table) and all(table[k] == v for k, v in i2s.items()):
                return name
        except Exception:  # noqa: BLE001
            continue
    return None


def enum_of(f, bits: int, lay: Layout) -> dict[int, str] | str | None:
    """The engine takes non-negative integer keys that fit the field and
    non-empty names; scapy's tables sometimes hold others, which no value of
    this field can reach."""
    i2s = getattr(f, "i2s", None)
    if getattr(f, "i2s_cb", None) is not None or not i2s:
        return None
    try:
        items = dict(i2s).items()
    except Exception:  # noqa: BLE001
        return None
    host = host_enum(dict(items))
    if host:
        return host
    out = {}
    dropped = []
    for k, v in items:
        if not isinstance(k, int) or isinstance(k, bool):
            return None
        if not isinstance(v, str) or not v or k < 0 or k >> bits:
            dropped.append(k)
            continue
        out[k] = v
    if dropped:
        lay.notes.append(f"{f.name}'s enum names {len(dropped)} value(s) its "
                         f"{bits} bits cannot hold: {sorted(dropped)[:4]}")
    return out or None


def map_field(f, raw_f, fd: dict, last: bool, readable: set[str], lay: Layout,
              defaults: dict) -> int | None:
    """Fill `fd` for one field; the width in bits, or None for a variable one."""
    kind_name = type(f).__name__
    d = defaults.get(raw_f.name, f.default)
    if kind_name in BE_UINT or kind_name in LE_UINT or kind_name in SIGNED:
        width = int(f.sz) * 8
        fd["kind"] = "le_uint" if f.fmt.startswith("<") else "uint"
        fd["len"] = width
        fd["default"] = int_default(f, d, width, lay)
        if kind_name in SIGNED:
            lay.gap("signed", f"{f.name} is signed and is read unsigned")
        return width
    if kind_name in THREE:
        fd["kind"] = "le_uint" if THREE[kind_name] else "uint"
        fd["len"] = 24
        fd["default"] = int_default(f, d, 24, lay)
        return 24
    if kind_name == "NBytesField":
        width = int(f.sz) * 8
        if width > 64:
            raise Refuse("wide_int", f"{f.name} is {width} bits, wider than 64")
        fd["kind"] = "uint"
        fd["len"] = width
        fd["default"] = int_default(f, d, width, lay)
        return width
    if kind_name in BITS:
        if f.size < 0 or getattr(f, "rev", False):
            raise Refuse("le_bitfield", f"{f.name} is a little-endian bit field")
        width = f.size
        if width > 64:
            raise Refuse("wide_int", f"{f.name} is {width} bits, wider than 64")
        fd["len"] = width
        fd["kind"] = "uint"
        if kind_name == "FlagsField":
            names = [str(n) for n in f.names]
            if any(not n for n in names):
                raise Refuse("flags", f"{f.name} has an unnamed flag")
            if len(names) > width:
                lay.notes.append(f"scapy names {len(names)} flags for the {width}-bit "
                                 f"{f.name}; the ones past bit {width - 1} can never be set")
                names = names[:width]
            fd["kind"] = "flags"
            fd["flags"] = names
        fd["default"] = int_default(f, d, width, lay)
        if kind_name in ("FixedPointField", "TimeStampField"):
            lay.gap("fixed_point", f"{f.name} is fixed-point; scapy shows a float")
        if kind_name == "BitMultiEnumField":
            lay.gap("multi_enum", f"{f.name}'s names depend on another field")
        return width
    if kind_name in IPV4:
        fd["kind"] = "ipv4"
        if d is None:
            if kind_name != "IPField":
                lay.gap("routed_default", f"{f.name} defaults from the routing table")
            d = "0.0.0.0"
        try:
            fd["default"] = int.from_bytes(F.inet_aton(str(d)), "big")
        except Exception:  # noqa: BLE001
            raise Refuse("default", f"{f.name}'s default {d!r} is not an address")
        return 32
    if kind_name in IPV6:
        fd["kind"] = "ipv6"
        if d is None:
            if kind_name != "IP6Field":
                lay.gap("routed_default", f"{f.name} defaults from the routing table")
            d = "::"
        b = F.inet_pton(F.socket.AF_INET6, str(d))
        if any(b):
            fd["default_bytes"] = list(b)
        return 128
    if kind_name in MAC:
        fd["kind"] = "mac"
        if d is None:
            if kind_name != "MACField":
                lay.gap("routed_default", f"{f.name} defaults from the interface")
            d = "00:00:00:00:00:00"
        b = F.mac2str(str(d))
        if any(b):
            fd["default_bytes"] = list(b)
        return 48
    if kind_name in FIXED_BYTES:
        n = constant_len(f.length_from)
        if n is None:
            raise Refuse("lambda_length", f"{f.name}'s fixed length depends on the packet")
        fd["kind"] = "bytes"
        fd["len"] = n * 8
        if isinstance(d, str):
            d = d.encode("latin-1")
        if isinstance(d, bytes) and any(d[:n]):
            fd["default_bytes"] = list(d[:n].ljust(n, b"\x00"))
        return n * 8
    if kind_name in TAIL_BYTES:
        if getattr(f, "remain", 0):
            raise Refuse("str_remain", f"{f.name} stops short of the end")
        if not last:
            raise Refuse("var_not_last", f"{f.name} runs to the end but is not last")
        fd["kind"] = "var_bytes"
        fd["length"] = "rest"
        if d not in (b"", None, ""):
            lay.gap("bytes_default", f"{f.name} has a non-empty default")
        return None
    if kind_name in LEN_BYTES:
        if not last:
            raise Refuse("var_not_last", f"{f.name} has a length from another field and is not last")
        fd["kind"] = "var_bytes"
        fd["length"] = quantity(f.length_from, StandIn(readable))
        if d not in (b"", None, ""):
            lay.gap("bytes_default", f"{f.name} has a non-empty default")
        if getattr(f, "max_length", None):
            lay.gap("max_length", f"{f.name} is capped at {f.max_length} octets")
        return None
    if kind_name in LISTS:
        if not last:
            raise Refuse("list_not_last", f"{f.name} is a list and is not last")
        fd["kind"] = "var_bytes"
        fd["list"] = f
        return None
    raise Refuse(refusal_code(kind_name), f"{f.name} is a {kind_name}")


def analyse(cls) -> Layout:
    """Lay the fields out at static bit offsets.

    A conditional field moves everything after it, which a static offset cannot
    follow. Two shapes survive that: a run of fields sharing one condition (a
    block), and blocks that are alternatives — no two can hold at once — laid
    over the same octets. Fields after a run are placed only if exactly one
    block always holds and every block has the same width; a run that ends the
    header instead gives a header length that depends on which block held."""
    lay = Layout(cls)
    off = 0
    readable: set[str] = set()
    widths: dict[str, int] = {}
    fields = list(cls.fields_desc)
    if not fields:
        raise Refuse("no_fields", "no fields of its own (an abstract or dispatching base)")
    try:
        defaults = dict(cls().default_fields)
    except Exception:  # noqa: BLE001
        defaults = {}
    run: dict | None = None
    tail_expr = None  # the variable part of the header, in octets past `off`

    def close_run(at_end: bool):
        nonlocal off, run, tail_expr
        blocks = run["blocks"]
        names = set()
        for b in blocks:
            names |= fields_in(b["cond"])
        always = covers([b["cond"] for b in blocks], {n: widths[n] for n in names})
        sizes = {b["bits"] for b in blocks if b["var"] is None}
        if not at_end:
            if not always or len(sizes) != 1 or any(b["var"] is not None for b in blocks):
                raise Refuse("cond_shift", "a field follows a conditional one whose presence "
                             "or width depends on the packet")
            off = run["start"] + sizes.pop()
            run = None
            return
        if run["start"] % 8 or any(b["bits"] % 8 for b in blocks):
            raise Refuse("unaligned", "a conditional tail does not fill whole octets")
        if always and len(sizes) == 1 and all(b["var"] is None for b in blocks):
            off = run["start"] + sizes.pop()
        else:
            e = blocks[-1] if always else None
            expr = block_len(e) if e else ("const", 0)
            for b in reversed(blocks[:-1] if always else blocks):
                expr = ("if", b["cond"], block_len(b), expr)
            tail_expr = expr
            off = run["start"]
        run = None

    for i, raw_f in enumerate(fields):
        last = i == len(fields) - 1
        f, cond, pad, may_end = unwrap(raw_f)
        if may_end and lay.min_len == 0:
            lay.min_len = (run["start"] if run else off) // 8
        fd: dict = {"name": raw_f.name}
        cexpr = None
        if cond is not None:
            cexpr = predicate(cond, readable)
            if cexpr == ("const", 0):
                lay.notes.append(f"{raw_f.name} is never present")
                continue
            if cexpr == ("const", 1):
                cexpr = None
        if cexpr is None and run is not None:
            close_run(False)
        if cexpr is not None:
            if run is None:
                run = {"start": off, "blocks": []}
            blocks = run["blocks"]
            if not blocks or blocks[-1]["cond"] != cexpr:
                for b in blocks:
                    if b["cond"] == cexpr or not exclusive(
                            b["cond"], cexpr, {n: widths[n] for n in
                                               fields_in(b["cond"]) | fields_in(cexpr)}):
                        raise Refuse("cond_shift", f"{raw_f.name} and an earlier conditional "
                                     "field can both be present")
                blocks.append({"cond": cexpr, "bits": 0, "var": None})
            block = blocks[-1]
            if block["var"] is not None:
                raise Refuse("var_not_last", f"{raw_f.name} follows a variable-length field")
            fd["off"] = run["start"] + block["bits"]
            fd["cond"] = cexpr
            if len(blocks) > 1:
                fd["overlaps"] = True
        else:
            if tail_expr is not None or lay.group is not None:
                raise Refuse("var_not_last", f"{raw_f.name} follows a variable-length field")
            fd["off"] = off
        at = fd["off"]

        width = map_field(f, raw_f, fd, last, readable, lay, defaults)

        if enum := (enum_of(f, fd["len"], lay) if fd.get("kind") in ("uint", "le_uint") else None):
            fd["enum"] = enum
        elif hasattr(f, "i2s") and getattr(f, "i2s_cb", None) is not None:
            lay.gap("enum_code", f"{f.name}'s names come from code")
        elif kind_is(f, "MultiEnumField"):
            lay.gap("multi_enum", f"{f.name}'s names depend on another field")

        if width is None:
            if at % 8:
                raise Refuse("unaligned", f"{f.name} does not start on an octet")
            if pad != 1:
                raise Refuse("pad_var", f"{f.name} is padded and variable")
            if "list" in fd:
                if cexpr is not None:
                    raise Refuse("cond_list", f"{f.name} is a conditional list")
                lay.group = list_group(fd.pop("list"), at // 8, readable, lay)
                var = ("group",)
            else:
                var = fd.pop("length")
            if cexpr is not None:
                run["blocks"][-1]["var"] = var
            else:
                tail_expr = var
            lay.fields.append(fd)
            continue

        if pad != 1:
            if at % (pad * 8):
                raise Refuse("pad_offset", f"{f.name}'s padding depends on its offset")
            width = -(-width // (pad * 8)) * pad * 8
        if fd["kind"] in ("bytes", "ipv4", "ipv6", "mac") and at % 8:
            raise Refuse("unaligned", f"{f.name} does not start on an octet")
        if at + width > 0xFFFF:
            raise Refuse("too_long", "the header is too long for a 16-bit bit offset")
        lay.fields.append(fd)
        if cexpr is not None:
            run["blocks"][-1]["bits"] += width
        else:
            off += width
            if fd["kind"] in ("uint", "le_uint", "flags"):
                readable.add(fd["name"])
                widths[fd["name"]] = fd["len"]

    if run is not None:
        close_run(True)
    if off % 8:
        raise Refuse("unaligned", "the header does not end on an octet")
    if tail_expr is None:
        lay.header_len = off // 8
    elif tail_expr == "rest" or tail_expr == ("group",) and lay.header_len == "rest":
        lay.header_len = "rest"
    elif tail_expr == ("group",):
        pass  # list_group set it
    elif contains_rest(tail_expr):
        raise Refuse("cond_rest", "a conditional field runs to the end of the packet")
    else:
        lay.header_len = {"base": off // 8, "expr": tail_expr}
    return lay


def contains_rest(e) -> bool:
    if e == "rest" or e == ("group",):
        return True
    return isinstance(e, tuple) and any(contains_rest(x) for x in e[1:] if isinstance(x, (tuple, str)))


def block_len(b: dict):
    """A block's width in octets, as an expression."""
    if b["var"] is None:
        return ("const", b["bits"] // 8)
    if b["var"] in ("rest", ("group",)):
        return b["var"]
    return ("bin", "+", ("const", b["bits"] // 8), b["var"]) if b["bits"] else b["var"]


def kind_is(f, name: str) -> bool:
    return any(c.__name__ == name for c in type(f).__mro__)


def envs(widths: dict[str, int], consts: set[int]):
    """Every assignment when the fields are narrow enough to enumerate, and the
    constants the conditions name plus their neighbours otherwise."""
    import itertools

    names = sorted(widths)
    if sum(widths.values()) <= 16:
        ranges = [range(1 << widths[n]) for n in names]
    else:
        probe = {0, 1}
        for c in consts:
            probe |= {c - 1, c, c + 1}
        ranges = [sorted(v for v in probe if 0 <= v < 1 << widths[n]) for n in names]
    for vals in itertools.product(*ranges):
        yield dict(zip(names, vals))


def exclusive(a: tuple, b: tuple, widths: dict[str, int]) -> bool:
    return not any(evaluate(a, env) and evaluate(b, env)
                   for env in envs(widths, consts_in(a) | consts_in(b)))


def covers(conds: list[tuple], widths: dict[str, int]) -> bool:
    cs = set()
    for c in conds:
        cs |= consts_in(c)
    return all(any(evaluate(c, env) for c in conds) for env in envs(widths, cs))


def list_group(f, start: int, readable: set[str], lay: Layout) -> dict:
    g: dict = {"start": start}
    if type(f).__name__ == "FieldListField":
        inner, cond, pad, _ = unwrap(f.field)
        if cond is not None or pad != 1:
            raise Refuse("list_elem", f"{f.name}'s element is conditional or padded")
        sub = Layout(lay.cls)
        n = type(inner).__name__
        if n in BE_UINT or n in LE_UINT or n in SIGNED:
            w = int(inner.sz) * 8
            kind = "le_uint" if inner.fmt.startswith("<") else "uint"
        elif n in BITS and n != "FlagsField" and inner.size % 8 == 0:
            w, kind = inner.size, "uint"
        elif n in IPV4:
            w, kind = 32, "ipv4"
        elif n in IPV6:
            w, kind = 128, "ipv6"
        elif n in MAC:
            w, kind = 48, "mac"
        else:
            raise Refuse(refusal_code(n), f"{f.name} is a list of {n}")
        if n in SIGNED:
            lay.gap("signed", f"{f.name} holds signed values read unsigned")
        if n in ("FixedPointField", "TimeStampField"):
            lay.gap("fixed_point", f"{f.name} holds fixed-point values scapy shows as floats")
        g["name"] = f.name
        fd = {"name": inner.name or f.name, "off": 0, "kind": kind}
        if kind in ("uint", "le_uint"):
            fd["len"] = w
        g["fields"] = [fd]
        g["elem_len"] = w // 8
        g["elem_cls"] = None
        g["elem_field"] = inner
        del sub
    else:
        ecls = f.cls
        if not (isinstance(ecls, type) and issubclass(ecls, Packet)):
            raise Refuse("list_dispatch", f"{f.name}'s element class is chosen by code")
        if getattr(f, "next_cls_cb", None):
            raise Refuse("list_dispatch", f"{f.name}'s next element class is chosen by code")
        try:
            el = analyse(ecls)
        except Refuse as r:
            raise Refuse("list_elem", f"{f.name}'s element {ecls.__name__}: {r.why}")
        if el.group or any("cond" in x for x in el.fields):
            raise Refuse("list_elem", f"{f.name}'s element {ecls.__name__} is not flat")
        if "dispatch_hook" in vars(ecls) or any(
            "dispatch_hook" in vars(b) for b in ecls.__mro__[1:] if b is not Packet
        ):
            lay.gap("list_dispatch", f"{f.name}'s elements are {ecls.__name__} subclasses "
                    "chosen by code; the base layout is used")
        for code, why in el.partial:
            lay.gap(code, f"{f.name} element: {why}")
        g["name"] = ecls.__name__
        g["fields"] = el.fields
        g["elem_cls"] = ecls
        hl = el.header_len
        if isinstance(hl, int):
            g["elem_len"] = hl
        elif isinstance(hl, dict):
            lin = linear(hl["expr"])
            if lin is None or lin[0] is None or lin[1] <= 0:
                raise Refuse("list_elem", f"{f.name}'s element length is not one field, scaled")
            fname, a, b = lin
            base = hl["base"] + b
            ef = next(x for x in el.fields if x["name"] == fname)
            if base < 0 or ef["kind"] not in ("uint",):
                raise Refuse("list_elem", f"{f.name}'s element length cannot be expressed")
            g["elem_base"] = base
            g["elem_min"] = hl["base"]
            g["terms"] = [{"off": ef["off"], "len": ef["len"], "scale": a}]
            g["elem_hl"] = hl
        else:
            raise Refuse("list_elem", f"{f.name}'s element runs to the end of the list")
        g["elem_layout"] = el
    # How many, or how far.
    cnt = getattr(f, "count_from", None)
    lng = getattr(f, "length_from", None)
    if getattr(f, "max_count", None):
        lay.gap("max_count", f"{f.name} is capped at {f.max_count} elements")
    if cnt is not None and lng is not None:
        raise Refuse("list_extent", f"{f.name} has both a count and a length")
    if cnt is not None:
        e = quantity(cnt, StandIn(readable))
        if e[0] != "field":
            raise Refuse("list_extent", f"{f.name}'s count is not a plain field")
        src = next(x for x in lay.fields if x["name"] == e[1])
        g["extent"] = "count"
        g["count_off"], g["count_len"] = src["off"], src["len"]
        if "elem_len" in g:
            lay.header_len = {"base": start, "expr": ("bin", "*", e, ("const", g["elem_len"]))}
        else:
            lay.header_len = "rest"
            lay.gap("count_tail", f"bytes after the last of {f.name} stay in the header")
        g["src"] = e[1]
    elif lng is not None:
        e = quantity(lng, StandIn(readable))
        lin = linear(e)
        if lin is None or lin[0] is None or lin[1] <= 0 or lin[2] > 0:
            raise Refuse("list_extent", f"{f.name}'s length is not one field, scaled, minus a constant")
        fname, a, b = lin
        src = next(x for x in lay.fields if x["name"] == fname)
        g["extent"] = "length"
        g["len_off"], g["len_len"] = src["off"], src["len"]
        g["len_scale"], g["len_covers"] = a, -b
        lay.header_len = {"base": start, "expr": e}
        g["src"] = fname
    else:
        g["extent"] = "rest"
        lay.header_len = "rest"
    return g


# --------------------------------------------------------------------------
# length links: which field FieldLenField fills in, and how


def length_links(lay: Layout) -> None:
    """A FieldLenField scapy fills in at build time. The engine fills a group's
    extent itself (`repeat::sync`) and a trailing region's length through
    `set_hlen`; any other target is a value wiry would emit as zero."""
    by_name = {f.name: f for f in lay.cls.fields_desc}
    for fd in lay.fields:
        raw_f = by_name.get(fd["name"])
        f = unwrap(raw_f)[0] if raw_f else None
        if f is None or type(f).__name__ not in ("FieldLenField", "LEFieldLenField",
                                                 "BitFieldLenField"):
            continue
        target = f.length_of or f.count_of
        if f.default is not None:
            continue
        g = lay.group
        if g and g.get("src") == fd["name"] and target == lay.fields[-1]["name"]:
            if g["extent"] == "length":
                adj = quantity(f.adjust, StandIn(set()), Sym(("field", "x")))
                lin = linear(adj, "x")
                # sync writes (region + covers) / scale; scapy writes adjust(region).
                if lin is None or not (lin[1] == 1 and g["len_scale"] == 1
                                       and lin[2] == g["len_covers"]):
                    lay.gap("computed_len", f"{fd['name']} is computed by a rule the "
                            "group's extent does not reproduce")
            elif g["extent"] == "count" and f.count_of != target:
                lay.gap("computed_len", f"{fd['name']} counts octets, not elements")
            continue
        hl = lay.header_len
        if isinstance(hl, dict) and target == lay.fields[-1]["name"] and not lay.group:
            adj = quantity(f.adjust, StandIn(set()), Sym(("field", "x")))
            lin = linear(adj, "x")
            if lin is None:
                lay.gap("computed_len", f"{fd['name']}'s adjust is not linear")
                continue
            lay.set_len = {"field": fd["name"], "expr": adj}
            continue
        lay.gap("computed_len", f"{fd['name']} is computed at build time "
                f"(the length of {target}) and wiry emits it as given")
    for fd in lay.fields:
        raw_f = by_name.get(fd["name"])
        f = unwrap(raw_f)[0] if raw_f else None
        if f is not None and type(f).__name__ == "LenField" and f.default is None:
            lay.gap("computed_len", f"{fd['name']} is the payload length, computed at build time")


# --------------------------------------------------------------------------
# class-level behaviour scapy expresses in code


OVERRIDES = {
    "dispatch_hook": ("dispatch_hook", "the class picks a subclass from the bytes in code"),
    "guess_payload_class": ("guess_payload", "the payload class is chosen in code"),
    "post_build": ("post_build", "post_build rewrites the built bytes"),
    "do_build": ("do_build", "do_build is overridden"),
    "self_build": ("do_build", "self_build is overridden"),
    "post_dissect": ("post_dissect", "post_dissect rewrites the dissected bytes"),
    "pre_dissect": ("pre_dissect", "pre_dissect rewrites the bytes before dissection"),
    "do_dissect": ("do_dissect", "do_dissect is overridden"),
    "do_dissect_payload": ("do_dissect", "do_dissect_payload is overridden"),
    "extract_padding": ("extract_padding", "extract_padding splits the payload in code"),
    "answers": ("answers", "answers() is code (sr matching only)"),
    "hashret": ("answers", "hashret() is code (sr matching only)"),
    "mysummary": ("summary", "mysummary() is code (display only)"),
}
# Display and reply-matching only: noted, never a reason to withhold a layout.
NOTE_ONLY = {"answers", "summary"}


def overrides(cls) -> list[tuple[str, str]]:
    out = []
    for attr, (code, why) in OVERRIDES.items():
        # A subclass inherits its base's hook, but only the base dispatches:
        # the subclass is what the hook returns.
        if attr == "dispatch_hook":
            if attr in vars(cls):
                out.append((code, why))
            continue
        for b in cls.__mro__:
            if b is Packet:
                break
            if attr in vars(b):
                out.append((code, why))
                break
    return out


def padding_rule(cls) -> str | None:
    """`extract_padding` is code, but its commonest body — everything after the
    header is padding — is one the engine has a name for."""
    try:
        p = cls()
        a, b = p.extract_padding(b"\x01\x02\x03")
    except Exception:  # noqa: BLE001
        return None
    if a in (b"", "", None) and b == b"\x01\x02\x03":
        return "header"
    if a == b"\x01\x02\x03" and b in (b"", "", None):
        return "none"
    return None


# --------------------------------------------------------------------------
# verification: decode as the engine will, compare with scapy


def read_bits(buf: bytes, off: int, n: int) -> int:
    if n == 0 or off + n > len(buf) * 8:
        return 0
    v = int.from_bytes(buf, "big")
    return (v >> (len(buf) * 8 - off - n)) & ((1 << n) - 1)


def write_bits(buf: bytearray, off: int, n: int, val: int) -> None:
    if n == 0 or off + n > len(buf) * 8:
        return
    total = len(buf) * 8
    v = int.from_bytes(buf, "big")
    shift = total - off - n
    mask = ((1 << n) - 1) << shift
    v = (v & ~mask) | ((val << shift) & mask)
    buf[:] = v.to_bytes(len(buf), "big")


def le_swap(v: int, bits: int) -> int:
    n = bits // 8
    return int.from_bytes(v.to_bytes(n, "big"), "little")


def field_value(fd: dict, hdr: bytes):
    k = fd["kind"]
    o = fd["off"]
    if k in ("uint", "flags"):
        return read_bits(hdr, o, fd["len"])
    if k == "le_uint":
        return le_swap(read_bits(hdr, o, fd["len"]), fd["len"])
    if k in ("ipv4", "ipv6", "mac", "bytes"):
        n = {"ipv4": 4, "ipv6": 16, "mac": 6}.get(k, fd.get("len", 0) // 8)
        b = hdr[o // 8: o // 8 + n]
        return b if len(b) == n or k == "bytes" else bytes(n)
    if k == "var_bytes":
        return hdr[o // 8:]
    raise ValueError(k)


def env_of(lay_fields, hdr: bytes) -> dict[str, int]:
    env = {}
    for fd in lay_fields:
        if fd["kind"] in ("uint", "le_uint", "flags") and "cond" not in fd:
            env[fd["name"]] = field_value(fd, hdr)
    return env


def model_header_len(lay: Layout, rest: bytes) -> int:
    hl = lay.header_len
    fixed_min = lay.spec_min_len
    if isinstance(hl, int):
        n = hl
    elif hl == "rest":
        n = len(rest)
    else:
        v = evaluate(hl["expr"], env_of(lay.fields, rest))
        n = hl["base"] + max(0, min(v, len(rest)))
    return min(max(n, fixed_min), len(rest))


def model_group(g: dict, hdr: bytes) -> list:
    """repeat.rs's walk, for the verifier: element boundaries and values."""
    region = hdr[g["start"]:]
    if g["extent"] == "length":
        claimed = read_bits(hdr, g["len_off"], g["len_len"]) * g["len_scale"] - g["len_covers"]
        region = region[:max(0, claimed)]
    want = read_bits(hdr, g["count_off"], g["count_len"]) if g["extent"] == "count" else None
    out = []
    i = 0
    while i < len(region) and len(out) < 512:
        if want is not None and len(out) >= want:
            break
        e = region[i:]
        if "elem_len" in g:
            n = g["elem_len"]
        else:
            n = g["elem_base"] + sum(read_bits(e, t["off"], t["len"]) * t["scale"]
                                     for t in g["terms"])
            n = max(n, g.get("elem_min", 0))
        if n == 0 or i + n > len(region):
            break
        out.append(region[i:i + n])
        i += n
    return out


def scapy_machine(fd: dict, f, pkt, val):
    k = fd["kind"]
    if k in ("uint", "le_uint", "flags"):
        m = f.i2m(pkt, val)
        if isinstance(m, (bytes, bytearray)):
            m = int.from_bytes(m, "big")
        return int(m) & ((1 << fd["len"]) - 1)
    if k in ("ipv4", "ipv6", "mac", "bytes", "var_bytes"):
        m = f.i2m(pkt, val)
        if isinstance(m, str):
            m = m.encode("latin-1")
        return bytes(m)
    raise ValueError(k)


def compare_fields(lay_fields, hdr: bytes, pkt, where: str) -> str | None:
    by = {}
    for raw_f in pkt.fields_desc:
        by[raw_f.name] = unwrap(raw_f)[0]
    env = env_of(lay_fields, hdr)
    for fd in lay_fields:
        if fd["kind"] == "var_bytes" and lay_fields is not None and fd.get("_group"):
            continue
        active = "cond" not in fd or bool(evaluate(fd["cond"], env))
        present = fd["name"] in pkt.fields
        if active != present:
            # scapy keeps a conditional field out of `fields` when its
            # condition fails; a short read leaves an unconditional one out.
            if active and fd["off"] + fd.get("len", 0) > len(hdr) * 8:
                continue
            return f"{where}: {fd['name']} present={present} but the spec says {active}"
        if not active:
            continue
        f = by[fd["name"]]
        mine = field_value(fd, hdr)
        try:
            theirs = scapy_machine(fd, f, pkt, pkt.fields[fd["name"]])
        except Exception as e:  # noqa: BLE001
            return f"{where}: scapy cannot re-encode {fd['name']}: {e}"
        if fd["kind"] == "bytes" and isinstance(theirs, bytes):
            theirs = theirs[: len(mine)].ljust(len(mine), b"\x00") if len(theirs) >= len(mine) else theirs
        if fd["kind"] in ("ipv4", "ipv6", "mac") and len(hdr) * 8 < fd["off"] + fd["len"] if "len" in fd else False:
            continue
        if mine != theirs:
            return f"{where}: {fd['name']} is {mine!r} here and {theirs!r} in scapy"
    return None


def scapy_dissect(cls, buf: bytes):
    """scapy's own reading of `buf` as `cls`: the header it consumed, the
    payload and padding it split off, and the field values."""
    p = cls.__new__(cls)
    Packet.__init__(p)
    rest = p.do_dissect(buf)
    payl, pad = p.extract_padding(rest)
    payl = payl or b""
    pad = pad or b""
    return p, len(buf) - len(rest), len(payl), len(pad)


def mutate(lay: Layout, rng: random.Random, base: bytes, consts: dict[str, list[int]]) -> bytes:
    n = max(len(base), lay.spec_min_len) + rng.choice([0, 0, 1, 2, 4, 8, 16, 33])
    buf = bytearray(rng.getrandbits(8) for _ in range(n))
    if rng.random() < 0.3:
        buf[: len(base)] = base[: len(buf)]
    for fd in lay.fields:
        if fd["kind"] not in ("uint", "le_uint", "flags") or "cond" in fd:
            continue
        cs = consts.get(fd["name"])
        if cs and rng.random() < 0.7:
            v = rng.choice(cs) & ((1 << fd["len"]) - 1)
            write_bits(buf, fd["off"], fd["len"], v)
        elif fd["name"] in lay.small_fields and rng.random() < 0.7:
            v = rng.randrange(0, min(64, 1 << fd["len"]))
            if fd["kind"] == "le_uint":
                v = le_swap(v, fd["len"])
            write_bits(buf, fd["off"], fd["len"], v)
    return bytes(buf)


def verify(lay: Layout, content: str | None, trials: int = 300) -> str | None:
    """None, or the first input on which the spec and scapy disagree."""
    cls = lay.cls
    consts: dict[str, list[int]] = {}
    exprs = [f["cond"] for f in lay.fields if "cond" in f]
    if isinstance(lay.header_len, dict):
        exprs.append(lay.header_len["expr"])
    for e in exprs:
        cs = sorted(consts_in(e))
        for name in fields_in(e):
            consts.setdefault(name, [])
            consts[name] += [c + d for c in cs for d in (-1, 0, 1)] + [0]
    lay.small_fields = set(fields_in(lay.header_len["expr"])) if isinstance(lay.header_len, dict) else set()
    if lay.group:
        lay.small_fields.add(lay.group.get("src", ""))
        el = lay.group.get("elem_layout")
        if el is not None and isinstance(el.header_len, dict):
            lay.small_fields |= fields_in(el.header_len["expr"])
    try:
        base = bytes(cls())
    except Exception:  # noqa: BLE001
        base = b""
    rng = random.Random(0x5CA9)
    for t in range(trials):
        buf = base if t == 0 else mutate(lay, rng, base, consts)
        if lay.group and t % 2 == 1:
            buf = with_elements(lay, rng, buf)
        if len(buf) < lay.spec_min_len or negative_length(lay, buf):
            continue
        try:
            pkt, consumed, npay, npad = scapy_dissect(cls, buf)
        except Exception:  # noqa: BLE001
            # scapy itself cannot read this input; the engine returns what it
            # managed, which is not a disagreement about the layout.
            continue
        hlen = model_header_len(lay, buf)
        where = f"input {buf.hex()}"
        if hlen != consumed:
            return f"{where}: header is {hlen} octets here and {consumed} in scapy"
        tail = len(buf) - hlen
        my_pad = tail if content == "header" else 0
        if my_pad != npad:
            return f"{where}: {my_pad} octets of padding here and {npad} in scapy"
        hdr = buf[:hlen]
        bad = compare_fields([f for f in lay.fields if f["kind"] != "var_bytes" or not lay.group],
                             hdr, pkt, where)
        if bad:
            return bad
        if lay.group:
            bad = verify_group(lay, hdr, pkt, where)
            if bad:
                return bad
    return None


def negative_length(lay: Layout, buf: bytes) -> bool:
    """scapy slices with a negative length as Python does, from the end; the
    engine reads nothing. That is scapy misreading a malformed packet, not a
    layout to agree with."""
    hl = lay.header_len
    if isinstance(hl, dict) and evaluate(hl["expr"], env_of(lay.fields, buf)) < 0:
        return True
    g = lay.group
    el = g.get("elem_layout") if g else None
    if el is not None and isinstance(el.header_len, dict):
        region = buf[g["start"]:]
        for e in model_group(g, buf[:model_header_len(lay, buf)]) + [region]:
            if evaluate(el.header_len["expr"], env_of(el.fields, e)) < 0:
                return True
    return False


def with_elements(lay: Layout, rng: random.Random, buf: bytes) -> bytes:
    """Random bytes rarely form a list scapy can walk, so build one: a few
    elements of plausible length, then set the count or length to match."""
    g = lay.group
    start = g["start"]
    out = bytearray(buf[:start].ljust(start, b"\x00"))
    elems = []
    for _ in range(rng.randrange(0, 4)):
        if "elem_len" in g:
            elems.append(bytes(rng.getrandbits(8) for _ in range(g["elem_len"])))
        else:
            t = g["terms"][0]
            body = rng.randrange(0, 6)
            total = max(g["elem_min"], g["elem_base"] + body)
            # Solve base + v * scale = total for v.
            if (total - g["elem_base"]) % t["scale"]:
                continue
            v = (total - g["elem_base"]) // t["scale"]
            if v >= 1 << t["len"]:
                continue
            e = bytearray(rng.getrandbits(8) for _ in range(total))
            write_bits(e, t["off"], t["len"], v)
            elems.append(bytes(e))
    region = b"".join(elems)
    if g["extent"] == "count":
        write_bits(out, g["count_off"], g["count_len"], len(elems))
    elif g["extent"] == "length":
        v = (len(region) + g["len_covers"])
        if v % g["len_scale"] == 0:
            write_bits(out, g["len_off"], g["len_len"], v // g["len_scale"])
    return bytes(out) + region + bytes(rng.getrandbits(8) for _ in range(rng.choice([0, 0, 3])))


def verify_group(lay: Layout, hdr: bytes, pkt, where: str) -> str | None:
    g = lay.group
    mine = model_group(g, hdr)
    theirs = pkt.fields.get(lay.fields[-1]["name"]) or []
    used = sum(len(m) for m in mine)
    region = len(hdr) - g["start"]
    if len(theirs) == len(mine) + 1 and used < region:
        # scapy keeps an element its own length says runs past the list; the
        # engine stops at the last whole one.
        lay.truncated_tail = True
        theirs = theirs[:-1]
    if len(mine) != len(theirs):
        return f"{where}: {len(mine)} list elements here and {len(theirs)} in scapy"
    for i, (m, t) in enumerate(zip(mine, theirs)):
        if g["elem_cls"] is None:
            fd = g["fields"][0]
            v = field_value(fd, m)
            tv = scapy_machine(fd, g["elem_field"], pkt, t)
            if v != tv:
                return f"{where}: element {i} is {v!r} here and {tv!r} in scapy"
            continue
        if not isinstance(t, Packet):
            return f"{where}: scapy's element {i} is not a packet"
        if type(t) is not g["elem_cls"]:
            # A subclass chosen by dispatch: its layout is its own, and the
            # partial status already says so.
            continue
        if len(bytes(t)) != len(m) and not t.payload:
            pass
        bad = compare_fields(g["fields"], m, t, f"{where} element {i}")
        if bad:
            return bad
    return None


def model_build(lay: Layout, content: str | None) -> bytes:
    """What `Packet::build_with` emits for a default construction."""
    n = lay.spec_build_len
    buf = bytearray(n)
    for fd in lay.fields:
        if fd["kind"] == "var_bytes":
            continue
        if "cond" in fd and not evaluate(fd["cond"], env_of(lay.fields, bytes(buf))):
            continue
        if fd.get("default_bytes"):
            a = fd["off"] // 8
            b = bytes(fd["default_bytes"])
            buf[a:a + len(b)] = b[: max(0, n - a)]
        elif fd.get("default"):
            v = fd["default"]
            if fd["kind"] == "le_uint":
                v = le_swap(v, fd["len"])
            write_bits(buf, fd["off"], FIX_BITS.get(fd["kind"], fd.get("len", 0)), v)
    if lay.set_len:
        fd = next(f for f in lay.fields if f["name"] == lay.set_len["field"])
        v = evaluate(lay.set_len["expr"], {"x": 0})
        if v >= 0:
            if fd["kind"] == "le_uint":
                v = le_swap(v, fd["len"])
            write_bits(buf, fd["off"], fd["len"], v)
    g = lay.group
    if g:
        if g["extent"] == "count":
            write_bits(buf, g["count_off"], g["count_len"], 0)
        elif g["extent"] == "length":
            write_bits(buf, g["len_off"], g["len_len"], g["len_covers"] // max(1, g["len_scale"]))
    return bytes(buf)


FIX_BITS = {"ipv4": 32, "ipv6": 128, "mac": 48}


# --------------------------------------------------------------------------
# bindings


SELECTORS = {
    ("UDP", "sport"): "udp_port", ("UDP", "dport"): "udp_port",
    ("TCP", "sport"): "tcp_port", ("TCP", "dport"): "tcp_port",
    ("IP", "proto"): "ipproto", ("IPv6", "nh"): "ipproto",
    ("Ether", "type"): "ethertype", ("Dot1Q", "type"): "ethertype",
    ("CookedLinux", "proto"): "ethertype",
    ("LLC", "dsap"): "llc_sap", ("LLC", "ssap"): "llc_sap",
}


def wiry_layers() -> dict[str, list]:
    import wiry._wiry as b

    return {n: b.field_specs(n) for n in b.known_layers()}


def field_place(specs: list, name: str) -> tuple[int, int] | None:
    """A built-in layer's field, placed by summing the widths before it — valid
    only while nothing before it is conditional or variable. protogen emits a
    test that checks the answer against the engine's own table."""
    off = 0
    for fname, bits, kind, _computed, conditional in specs:
        if conditional or kind == "var_bytes" or bits == 0:
            return None
        if fname == name:
            return (off, bits)
        off += bits
    return None


# --------------------------------------------------------------------------
# spec emission


def id_of(name: str) -> str:
    parts = [p for p in re.split(r"[^A-Za-z0-9]+", name) if p]
    out = "".join(p[0].upper() + p[1:] for p in parts)
    if not out or not out[0].isalpha():
        out = "L" + out
    return out


def snake(name: str) -> str:
    """Lower case, underscores kept: guessing word breaks in `PPPoETag` or
    `NTPInfoIfStatsIPv4` gives worse names than not guessing."""
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def toml_str(s: str) -> str:
    return json.dumps(s, ensure_ascii=False)


def toml_val(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return toml_str(v)
    if isinstance(v, list):
        return "[" + ", ".join(toml_val(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{ " + ", ".join(f"{k} = {toml_val(x)}" for k, x in v.items()) + " }"
    raise TypeError(type(v))


def enum_toml(e: dict[int, str]) -> str:
    return "{ " + ", ".join(f"{k} = {toml_str(v)}" for k, v in sorted(e.items())) + " }"


def field_toml(fd: dict, table: str) -> list[str]:
    out = [f"[[{table}]]", f"name = {toml_str(fd['name'])}", f"off = {fd['off']}"]
    k = fd["kind"]
    if "len" in fd and k not in ("ipv4", "ipv6", "mac", "var_bytes"):
        out.append(f"len = {fd['len']}")
    if k != "uint":
        out.append(f"kind = {toml_str(k)}")
    if fd.get("default"):
        out.append(f"default = {fd['default']}")
    if fd.get("flags"):
        out.append(f"flags = {toml_val(fd['flags'])}")
    if fd.get("default_bytes"):
        out.append(f"default_bytes = {toml_val(fd['default_bytes'])}")
    if fd.get("cond"):
        out.append(f"cond = {toml_str(strip_parens(render(fd['cond'])))}")
    if fd.get("overlaps"):
        out.append("overlaps = true")
    if isinstance(fd.get("enum"), str):
        out.append(f"enum = {toml_str(fd['enum'])}")
    elif fd.get("enum"):
        out.append(f"enum = {enum_toml(fd['enum'])}")
    out.append("")
    return out


def strip_parens(s: str) -> str:
    if s.startswith("(") and s.endswith(")"):
        depth = 0
        for i, c in enumerate(s):
            depth += c == "("
            depth -= c == ")"
            if depth == 0 and i != len(s) - 1:
                return s
        return s[1:-1]
    return s


def rfcs(cls, mod) -> list[str]:
    text = " ".join(filter(None, [cls.__doc__, mod.__doc__]))
    seen = []
    for m in re.finditer(r"RFC\s?-?(\d{3,4})", text):
        r = f"RFC {m.group(1)}"
        if r not in seen:
            seen.append(r)
    return seen


def source_path(mod) -> str:
    return "scapy/" + mod.__name__.split(".", 1)[1].replace(".", "/") + ".py"


def emit(res: dict, mod) -> str:
    lay: Layout = res["layout"]
    cls = lay.cls
    refs = rfcs(cls, mod)
    cite = (f"{source_path(mod)}, class {cls.__name__} ({SCAPY_VERSION}), converted by "
            "dev/protogen/scapy2spec.py from the field objects scapy builds at run time.")
    cite += (" " + ", ".join(refs) + (" is" if len(refs) == 1 else " are")
             + " what scapy's docstring cites for it." if refs else
             " scapy's docstring cites no RFC for it.")
    lines = [
        "# Generated by dev/protogen/scapy2spec.py; re-run it rather than editing.",
        f"name = {toml_str(cls.__name__)}",
        f"id = {toml_str(res['id'])}",
        f"num = {res['num']}",
        f"module = {toml_str(res['module'])}",
        'citation = """',
        wrap(cite).rstrip("\n"),
        '"""',
        f"min_len = {lay.spec_min_len}",
    ]
    hl = lay.header_len
    if isinstance(hl, dict):
        lines.append(f"header_len = {{ base = {hl['base']}, expr = "
                     f"{toml_str(strip_parens(render(hl['expr'])))} }}")
    else:
        lines.append(f"header_len = {toml_val(hl)}")
    lines.append(f"build_len = {lay.spec_build_len}")
    if lay.set_len:
        lines.append(f"set_len = {{ field = {toml_str(lay.set_len['field'])}, expr = "
                     f"{toml_str(strip_parens(render(lay.set_len['expr'])))} }}")
    nx = res["next"]
    if isinstance(nx, str):
        lines.append(f"next = {toml_str(nx)}")
    if res.get("content") == "header":
        lines.append('content_len = "header"')
    if lay.group:
        lines.append(f"parsed_field = {toml_str(lay.fields[-1]['name'])}")
    lines.append("")
    for fd in lay.fields:
        lines += field_toml(fd, "fields")
    g = lay.group
    if g:
        lines.append("[group]")
        lines.append(f"name = {toml_str(g['name'])}")
        lines.append(f"start = {g['start']}")
        lines.append(f"extent = {toml_str(g['extent'])}")
        if g["extent"] == "count":
            lines.append(f"count_off = {g['count_off']}")
            lines.append(f"count_len = {g['count_len']}")
        if g["extent"] == "length":
            lines.append(f"len_off = {g['len_off']}")
            lines.append(f"len_len = {g['len_len']}")
            if g["len_scale"] != 1:
                lines.append(f"len_scale = {g['len_scale']}")
            if g["len_covers"]:
                lines.append(f"len_covers = {g['len_covers']}")
        if "elem_len" in g:
            lines.append(f"elem_len = {g['elem_len']}")
        else:
            lines.append(f"elem_base = {g['elem_base']}")
            lines.append(f"elem_min = {g['elem_min']}")
        lines.append("")
        for t in g.get("terms", []):
            lines += ["[[group.terms]]", f"off = {t['off']}", f"len = {t['len']}",
                      f"scale = {t['scale']}", ""]
        for fd in g["fields"]:
            lines += field_toml(fd, "group.fields")
    if isinstance(nx, dict):
        lines.append("[next]")
        for k in ("proto", "off", "len", "fallback"):
            if k in nx:
                lines.append(f"{k} = {toml_val(nx[k])}")
        lines.append("")
        for a in nx.get("arms", []):
            lines += ["[[next.arms]]", f"value = {a['value']}", f"proto = {toml_str(a['proto'])}", ""]
    for p in res["parents"]:
        lines.append("[[parents]]")
        for k, v in p.items():
            lines.append(f"{k} = {toml_val(v)}")
        lines.append("")
    lines += [
        "[provenance]",
        f"source = {toml_str(source_path(mod))}",
        f"version = {toml_str(SCAPY_VERSION)}",
        f"changed = [{toml_str(TODAY + ' — field table, defaults, enum names and bindings of ' + cls.__name__ + ' converted mechanically from the field objects by dev/protogen/scapy2spec.py')}]",
        "",
    ]
    return "\n".join(lines)


def wrap(s: str, width: int = 78) -> str:
    out, line = [], ""
    for w in s.split():
        if line and len(line) + 1 + len(w) > width:
            out.append(line)
            line = w
        else:
            line = f"{line} {w}" if line else w
    out.append(line)
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------
# driving


def classes_of(mod) -> list[type]:
    return [v for v in vars(mod).values()
            if isinstance(v, type) and issubclass(v, Packet) and v.__module__ == mod.__name__]


SUPPORTED = (set(BE_UINT) | LE_UINT | SIGNED | set(THREE) | BITS | IPV4 | IPV6 | MAC
             | FIXED_BYTES | TAIL_BYTES | LEN_BYTES | LISTS | {"NBytesField"})


def field_blockers(cls) -> list[str]:
    """Every field family in `cls` the converter refuses, not only the first
    one `analyse` stopped at; lambdas and verification are not visible here."""
    out = set()
    try:
        fields = list(cls.fields_desc)
    except Exception:  # noqa: BLE001
        return []
    while fields:
        f = fields.pop()
        while type(f).__name__ in WRAPPERS:
            f = f.fld
        n = type(f).__name__
        if n == "MultipleTypeField":
            out.add("multiple_type")
            fields.extend(fl for fl, _ in f.flds)
            fields.append(f.dflt)
        elif n in BITS and (f.size < 0 or getattr(f, "rev", False)):
            out.add("le_bitfield")
        elif n not in SUPPORTED:
            out.add(refusal_code(n))
    return sorted(out)


def convert_class(cls, existing: set[str]) -> dict:
    res: dict = {"class": cls.__name__, "display": str(getattr(cls(), "name", cls.__name__))
                 if _constructible(cls) else cls.__name__, "notes": [], "partial": []}
    if cls.__name__ in existing:
        res["status"] = "exists"
        res["why"] = "a layer of this name is already in wiry"
        return res
    try:
        lay = analyse(cls)
        length_links(lay)
    except Refuse as r:
        res.update(status="refused", code=r.code, why=r.why, blockers=field_blockers(cls))
        return res
    gaps = list(lay.partial)
    for code, why in overrides(cls):
        if code == "extract_padding":
            rule = padding_rule(cls)
            if rule == "header":
                res["content"] = "header"
                continue
            if rule == "none":
                continue
        if code in NOTE_ONLY:
            res["notes"].append(why)
        else:
            gaps.append((code, why))
    hl = lay.header_len
    fixed = hl if isinstance(hl, int) else None
    first_var = next((f["off"] // 8 for f in lay.fields if f["kind"] == "var_bytes"), None)
    lay.spec_build_len = fixed if fixed is not None else (first_var if first_var is not None else 0)
    if lay.min_len:
        lay.spec_min_len = lay.min_len
    else:
        lay.spec_min_len = lay.spec_build_len
    if lay.group:
        lay.spec_build_len = lay.group["start"]
    res["layout"] = lay
    bad = verify(lay, res.get("content"))
    if bad:
        res.update(status="refused", code="verify", why=f"disagrees with scapy: {bad}")
        return res
    try:
        built = bytes(cls())
    except Exception as e:  # noqa: BLE001
        built = None
        gaps.append(("default_build", f"scapy cannot build a default {cls.__name__}: {e}"))
    if built is not None:
        mine = model_build(lay, res.get("content"))
        if mine != built:
            gaps.append(("default_build", f"default build is {mine.hex()} here and "
                         f"{built.hex()} in scapy"))
    if lay.truncated_tail:
        res["notes"].append("a last list element that runs past the list is dropped, "
                            "where scapy keeps it truncated")
    res["partial"] = [{"code": c, "why": w} for c, w in gaps]
    res["status"] = "partial" if gaps else "clean"
    return res


def _constructible(cls) -> bool:
    try:
        cls()
        return True
    except Exception:  # noqa: BLE001
        return False


def bindings(results: dict[str, dict], wl: dict[str, list], module_classes: list[type],
             emitted: set[str]) -> None:
    """Fill each result's `parents` and `next` from scapy's payload_guess tables,
    keeping only bindings both ends of which will exist in wiry."""
    import scapy.config

    universe = set(wl) | emitted
    for cls in module_classes:
        r = results[cls.__name__]
        r.setdefault("parents", [])
        r.setdefault("dropped", [])
        if r["status"] not in ("clean", "partial"):
            continue
        has_children = False
        for parent in scapy.config.conf.layers:
            for fval, child in getattr(parent, "payload_guess", []):
                if child is cls:
                    p = binding(parent, fval, cls, results, wl, universe)
                    if isinstance(p, dict):
                        taken = claim(r, p, p.get("field"))
                        if taken:
                            p = f"under {parent.__name__}: {taken}"
                    if isinstance(p, str):
                        r["dropped"].append(p)
                    elif p:
                        merge_parent(r["parents"], p)
                if parent is cls and child.__name__ in universe:
                    has_children = True
        r["next"] = "raw"
        if not has_children and r.get("content") == "header":
            r["next"] = "end"
        # A child that is already in wiry has no spec to declare its parent in,
        # so the parent names it.
        arms: list[tuple[str, int, str]] = []
        for fval, child in cls.payload_guess:
            cname = child.__name__
            if cname not in wl or cname in emitted:
                continue
            if not fval:
                arms.append(("", 0, WIRY_IDS.get(cname, "")))
            elif len(fval) == 1 and isinstance(next(iter(fval.values())), int):
                (k, v), = fval.items()
                arms.append((k, v, WIRY_IDS.get(cname, "")))
            else:
                r["dropped"].append(f"over {cname} on {sorted(fval)}")
        arms = [a for a in arms if a[2]]
        if arms:
            r["next"] = next_table(r, arms)


def next_table(r: dict, arms: list[tuple[str, int, str]]):
    if arms[0][0] == "":
        return {"proto": arms[0][2]}
    field = arms[0][0]
    fd = next((f for f in r["layout"].fields if f["name"] == field), None)
    if fd is None or "cond" in fd or fd["kind"] not in ("uint", "flags"):
        r["dropped"].append(f"children on {field}, not a plain field")
        return "raw"
    keep = [a for a in arms if a[0] == field]
    r["dropped"] += [f"a child on {a[0]} beside children on {field}" for a in arms if a[0] != field]
    return {"off": fd["off"], "len": fd["len"], "fallback": "raw",
            "arms": [{"value": v, "proto": p} for _, v, p in keep]}


def merge_parent(ps: list, p: dict) -> None:
    for q in ps:
        if all(q.get(k) == p.get(k) for k in ("from", "layer", "field")):
            for v in p.get("values", []):
                if v not in q["values"]:
                    q["values"].append(v)
            return
    ps.append(p)


def binding(parent, fval: dict, cls, results, wl, universe):
    pname = parent.__name__
    if pname not in universe:
        return f"under {pname}, which wiry does not have"
    if len(fval) > 1:
        sel = {SELECTORS.get((pname, k)) for k in fval}
        if len(sel) == 1 and None not in sel and len(set(fval.values())) == 1:
            fval = {next(iter(fval)): next(iter(fval.values()))}
        else:
            return f"under {pname} on {sorted(fval)}, more than one field"
    if not fval:
        return {"from": "layer", "layer": layer_id(pname, results)}
    (k, v), = fval.items()
    if not isinstance(v, int) or isinstance(v, bool):
        return f"under {pname} on {k}={v!r}, not an integer"
    sel = SELECTORS.get((pname, k))
    if sel:
        return {"from": sel, "values": [v]}
    if pname in results and "layout" in results[pname]:
        fd = next((f for f in results[pname]["layout"].fields if f["name"] == k), None)
        if fd is None or "cond" in fd or fd["kind"] not in ("uint", "flags"):
            return f"under {pname} on {k}, not a plain field there"
        place = (fd["off"], fd["len"])
    else:
        place = field_place(wl.get(pname, []), k)
        if place is None:
            return f"under {pname} on {k}, which is not at a fixed place there"
    return {"from": "layer", "layer": layer_id(pname, results), "field": k,
            "off": place[0], "len": place[1], "values": [v]}


# Who already answers a selector value: (kind, value) or ("layer", parent id,
# bit offset, bit length, value), mapped to the layer name that owns it.
CLAIMS: dict[tuple, str] = {}


def load_claims(skip: set[Path]) -> None:
    """Claims the specs on disk make, except those about to be regenerated."""
    import tomllib

    for spec in sorted(SPECS.rglob("*.toml")):
        if any(spec.is_relative_to(d) for d in skip):
            continue
        s = tomllib.loads(spec.read_text())
        for p in s.get("parents", []):
            for key in claim_keys(p):
                CLAIMS.setdefault(key, s["name"])


def claim_keys(p: dict) -> list[tuple]:
    if p["from"] != "layer":
        return [(p["from"], v) for v in p["values"]]
    if "field" not in p:
        return [("layer", p["layer"], None, None, None)]
    return [("layer", p["layer"], p["off"], p["len"], v) for v in p["values"]]


PROBE_PAYLOAD = b"\x00" * 48


def probe(key: tuple) -> str | None:
    """What the built engine dissects after a selector value with nothing
    declared for it: hand-written dispatch (DNS on 53, BOOTP on 67) is not in
    any spec, so the engine is asked."""
    import wiry

    W = wiry
    kind, v = key[0], key[-1]
    try:
        if kind == "udp_port":
            pkt, outer, at = W.IP() / W.UDP(sport=v, dport=v) / W.Raw(load=PROBE_PAYLOAD), W.IP, 2
        elif kind == "tcp_port":
            pkt, outer, at = W.IP() / W.TCP(sport=v, dport=v) / W.Raw(load=PROBE_PAYLOAD), W.IP, 2
        elif kind == "ipproto":
            pkt, outer, at = W.IP(proto=v) / W.Raw(load=PROBE_PAYLOAD), W.IP, 1
        elif kind == "ethertype":
            pkt, outer, at = W.Ether(type=v) / W.Raw(load=PROBE_PAYLOAD), W.Ether, 1
        elif kind == "llc_sap":
            pkt, outer, at = W.LLC(dsap=v, ssap=v) / W.Raw(load=PROBE_PAYLOAD), W.LLC, 1
        elif kind == "layer":
            name = next((n for n, i in WIRY_IDS.items() if i == key[1]), None)
            if name is None or not hasattr(W, name):
                return None
            parent = getattr(W, name)
            field = key[5] if len(key) > 5 else None
            pkt = (parent(**{field: v}) if field else parent()) / W.Raw(load=PROBE_PAYLOAD)
            outer, at = parent, 1
        else:
            return None
        names = outer(bytes(pkt)).layers()
    except Exception:  # noqa: BLE001
        return None
    got = names[at] if len(names) > at else None
    return got if got not in (None, "Raw", "Padding") else None


def claim(r: dict, p: dict, field: str | None = None) -> str | None:
    """Take the selector values a binding needs, or say who has them."""
    keys = claim_keys(p)
    for key in keys:
        owner = CLAIMS.get(key)
        if owner is None:
            owner = probe(key + ((field,) if key[0] == "layer" else ()))
        if owner is not None and owner != r["class"]:
            return f"{key[0]} {key[-1] if key[-1] is not None else ''} is already {owner}'s".strip()
    for key in keys:
        CLAIMS[key] = r["class"]
    return None


def layer_id(name: str, results: dict) -> str:
    if name in results and results[name].get("id"):
        return results[name]["id"]
    return WIRY_IDS.get(name) or id_of(name)


WIRY_IDS: dict[str, str] = {}


def load_wiry_ids() -> None:
    text = (ROOT / "crates/wiry-core/src/proto.rs").read_text()
    consts = dict(re.findall(r"pub const (\w+): ProtoId = ProtoId\((\d+)\);", text))
    import wiry._wiry as b

    names = b.known_layers()
    # The engine's name for an id is in its descriptor; match through the
    # numbering, which known_layers lists in BUILTINS order.
    by_num = {int(v): k for k, v in consts.items()}
    for spec in SPECS.rglob("*.toml"):
        import tomllib

        s = tomllib.loads(spec.read_text())
        WIRY_IDS[s["name"]] = s["id"]
    hand = {
        "Ether": "Ether", "Dot1Q": "Dot1Q", "ARP": "Arp", "IP": "Ipv4", "IPv6": "Ipv6",
        "TCP": "Tcp", "UDP": "Udp", "ICMP": "Icmp", "ICMPv6": "Icmpv6", "DNS": "Dns",
        "BOOTP": "Bootp", "DHCP": "Dhcp", "Loopback": "Null", "CookedLinux": "LinuxSll",
        "CookedLinuxV2": "LinuxSll2", "Raw": "Raw", "Padding": "Padding",
        "IPv6ExtHdrHopByHop": "HopByHop", "IPv6ExtHdrRouting": "Routing",
        "IPv6ExtHdrFragment": "Fragment", "IPv6ExtHdrDestOpt": "DestOpt", "GRE": "Gre",
        "VXLAN": "Vxlan", "GENEVE": "Geneve", "MPLS": "Mpls", "PPPoED": "PppoeDisc",
        "PPPoE": "Pppoe", "PPP": "Ppp", "GTP_U_Header": "GtpU", "ERSPAN_II": "ErspanII",
        "ERSPAN_III": "ErspanIII",
    }
    for k, v in hand.items():
        if k in names:
            WIRY_IDS.setdefault(k, v)
    del by_num


def convert_module(modname: str, id_base: int | None, existing: set[str],
                   wl: dict[str, list]) -> tuple[list[dict], object]:
    mod = importlib.import_module(modname)
    classes = classes_of(mod)
    results: dict[str, dict] = {}
    short = modname.split(".", 2)[2].replace(".", "_")
    import tomllib

    regenerated = {tomllib.loads(p.read_text())["id"] for p in (OUT / short).glob("*.toml")}
    used_ids = set(WIRY_IDS.values()) - regenerated
    for i, cls in enumerate(classes):
        r = convert_class(cls, existing)
        r["module_index"] = i
        if id_base is not None:
            r["num"] = id_base + i
        if r["status"] == "exists":
            r["id"] = WIRY_IDS.get(cls.__name__)
        else:
            ident = id_of(cls.__name__)
            while ident in used_ids:
                ident += "X"
            used_ids.add(ident)
            r["id"] = ident
        r["module"] = f"{short}_{snake(cls.__name__)}"
        results[cls.__name__] = r
    return [results[c.__name__] for c in classes], mod


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("modules", nargs="*")
    ap.add_argument("--all", action="store_true", help="every module under scapy.layers")
    ap.add_argument("--id-base", type=int)
    ap.add_argument("--emit", choices=["clean", "partial"], default="clean")
    ap.add_argument("--report-only", action="store_true")
    ap.add_argument("--report", type=Path)
    ap.add_argument("--table", action="store_true", help="print a per-module coverage table")
    ap.add_argument("--coverage", type=Path, help="write the per-module coverage document")
    a = ap.parse_args(argv)

    mods = list(a.modules)
    if a.all:
        import scapy.layers

        mods = sorted(m.name for m in pkgutil.walk_packages(scapy.layers.__path__, "scapy.layers."))
    if not mods:
        ap.error("name a module or pass --all")
    if not a.report_only and a.id_base is None:
        ap.error("--id-base is required unless --report-only")

    import scapy.all  # noqa: F401  (every binding scapy registers)

    load_wiry_ids()
    wl = wiry_layers()
    existing = set(wl) - {WIRY_REVERSE.get(m, "") for m in []}
    # A previous run's output is ours to replace, not a layer that exists.
    ours = {}
    for spec in OUT.rglob("*.toml") if OUT.exists() else []:
        import tomllib

        s = tomllib.loads(spec.read_text())
        ours[s["name"]] = spec
    existing -= set(ours)

    shorts = {m.split(".", 2)[2].replace(".", "_") for m in mods if m.count(".") >= 2}
    load_claims({OUT / sh for sh in shorts})
    report = []
    base = a.id_base
    for m in mods:
        try:
            rs, mod = convert_module(m, base, existing, wl)
        except Exception as e:  # noqa: BLE001
            report.append({"module": m, "error": f"{type(e).__name__}: {e}", "classes": []})
            continue
        if base is not None:
            base += len(rs)
        emit_set = {r["class"] for r in rs if r["status"] == "clean"
                    or (a.emit == "partial" and r["status"] == "partial")}
        bindings({r["class"]: r for r in rs}, wl, classes_of(mod), emit_set)
        short = m.split(".", 2)[2].replace(".", "_")
        if not a.report_only:
            d = OUT / short
            for old in d.glob("*.toml") if d.exists() else []:
                old.unlink()
            for r in rs:
                if r["class"] in emit_set:
                    d.mkdir(parents=True, exist_ok=True)
                    (d / f"{snake(r['class'])}.toml").write_text(emit(r, mod))
        report.append({"module": m, "classes": [public(r, r["class"] in emit_set) for r in rs]})

    if a.report:
        a.report.write_text(json.dumps(report, indent=1) + "\n")
    if a.coverage:
        write_coverage(report, a.coverage)
    print_table(report, a.table)
    return 0


HAND_MARK = "<!-- hand-written below; scapy2spec.py --coverage keeps it -->"


def top_module(name: str) -> str:
    return name.split(".")[2]


def write_coverage(report: list[dict], path: Path) -> None:
    import collections
    import subprocess

    keys = ("clean", "partial", "refused", "exists")
    mods: dict[str, dict] = {}
    first = collections.Counter()
    family = collections.Counter()
    only = collections.Counter()
    gaps = collections.Counter()
    for m in report:
        if m["module"].count(".") < 2:
            continue
        row = mods.setdefault(top_module(m["module"]), {
            **{k: 0 for k in keys}, "first": collections.Counter(),
            "gaps": collections.Counter()})
        for r in m["classes"]:
            row[r["status"]] += 1
            if r["status"] == "refused":
                row["first"][r["code"]] += 1
                first[r["code"]] += 1
                b = r.get("blockers", [])
                family.update(b)
                if len(b) == 1:
                    only[b[0]] += 1
            for g in {p["code"] for p in r.get("partial", [])}:
                row["gaps"][g] += 1
                gaps[g] += 1
    tot = {k: sum(r[k] for r in mods.values()) for k in keys}
    n = sum(tot.values())
    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                            capture_output=True, text=True).stdout.strip()

    def top(c, k=3):
        return ", ".join(f"{code} {v}" for code, v in c.most_common(k))

    out = [
        "# scapy.layers coverage of the spec converter",
        "",
        f"Generated by `dev/protogen/scapy2spec.py --all --report-only --coverage "
        f"dev/protogen/COVERAGE.md` against {SCAPY_VERSION}, at wiry `{commit}`. "
        "Re-run it rather than editing the tables.",
        "",
        "- **clean**: every field maps, and the spec agrees with scapy's dissection "
        "and default build on every input the verifier tried.",
        "- **partial**: the layout verifies, but scapy does something in code "
        "(a `guess_payload_class`, `post_build`, a computed length) that needs a "
        "hand hook.",
        "- **refused**: the spec format cannot express a field, or the spec "
        "disagreed with scapy. The code is the first blocker the converter hit.",
        "- **exists**: wiry already has a layer of that name.",
        "",
        f"**{n} classes: {tot['clean']} clean, {tot['partial']} partial, "
        f"{tot['refused']} refused, {tot['exists']} already in wiry.**",
        "",
        "## Per module",
        "",
        "| module | classes | clean | partial | refused | exists | first refusals | hooks partials need |",
        "|---|--:|--:|--:|--:|--:|---|---|",
    ]
    for name, r in sorted(mods.items(), key=lambda kv: -sum(kv[1][k] for k in keys)):
        c = sum(r[k] for k in keys)
        if not c:
            continue
        out.append(f"| {name} | {c} | {r['clean']} | {r['partial']} | {r['refused']} "
                   f"| {r['exists']} | {top(r['first'])} | {top(r['gaps'])} |")
    empty = sorted(k for k, r in mods.items() if not sum(r[x] for x in keys))
    out += ["", f"Modules defining no `Packet` class of their own: {', '.join(empty)}.", "",
            "## Refusals, by the first blocker hit", "",
            "| code | classes |", "|---|--:|"]
    out += [f"| {k} | {v} |" for k, v in first.most_common()]
    out += ["", "## Field families that block a refused class, counting every one",
            "",
            "A refused class usually has more than one blocker. `classes` counts every "
            "refused class containing the family; `sole` counts those where it is the "
            "only unsupported field family, the classes that supporting it alone could "
            "unblock unless a lambda or the verifier then refuses them.",
            "", "| family | classes | sole |", "|---|--:|--:|"]
    out += [f"| {k} | {v} | {only[k]} |" for k, v in family.most_common()]
    out += ["", "## What partial classes need", "", "| hook | classes |", "|---|--:|"]
    out += [f"| {k} | {v} |" for k, v in gaps.most_common()]
    hand = ""
    if path.exists() and HAND_MARK in path.read_text():
        hand = path.read_text().split(HAND_MARK, 1)[1]
    path.write_text("\n".join(out) + "\n\n" + HAND_MARK + hand)


WIRY_REVERSE: dict[str, str] = {}


def public(r: dict, emitted: bool) -> dict:
    out = {k: v for k, v in r.items() if k not in ("layout",)}
    out["emitted"] = emitted
    return out


def print_table(report: list[dict], full: bool) -> None:
    tot = {"clean": 0, "partial": 0, "refused": 0, "exists": 0}
    rows = []
    reasons: dict[str, int] = {}
    for m in report:
        c = {"clean": 0, "partial": 0, "refused": 0, "exists": 0}
        for r in m["classes"]:
            c[r["status"]] += 1
            if r["status"] == "refused":
                reasons[r["code"]] = reasons.get(r["code"], 0) + 1
            for p in r.get("partial", []):
                reasons["partial:" + p["code"]] = reasons.get("partial:" + p["code"], 0) + 1
        for k in tot:
            tot[k] += c[k]
        rows.append((m["module"], len(m["classes"]), c, m.get("error")))
    if full:
        print(f"{'module':40} {'classes':>7} {'clean':>6} {'partial':>7} {'refused':>7} {'exists':>6}")
        for name, n, c, err in rows:
            if err:
                print(f"{name:40} import failed: {err}")
                continue
            print(f"{name:40} {n:7} {c['clean']:6} {c['partial']:7} {c['refused']:7} {c['exists']:6}")
    n = sum(r[1] for r in rows)
    print(f"{'TOTAL':40} {n:7} {tot['clean']:6} {tot['partial']:7} {tot['refused']:7} {tot['exists']:6}")
    if full:
        print("\nreasons:")
        for k, v in sorted(reasons.items(), key=lambda kv: -kv[1])[:40]:
            print(f"  {v:5}  {k}")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
