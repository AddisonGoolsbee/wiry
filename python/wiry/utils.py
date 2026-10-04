# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from scapy: scapy/utils.py
#   scapy 2.7.0
#   Copyright (C) Philippe Biondi <phil@secdev.org>
#   Copyright (C) the scapy contributors
#
# Changed by the wiry authors:
#   2026-10-03 — the general helpers, transcribed; colour themes dropped, the
#                hexcap reader kept on wiry's stricter offset rule, and the
#                capture-file and external-tool names forwarded to the modules
#                that implement them.

"""The general helpers scapy scripts call by name: dumps, checksums, address
arithmetic, tables, temporary files."""

from __future__ import annotations

import argparse
import array
import decimal
import difflib
import enum
import inspect
import locale
import math
import os
import random
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from decimal import Decimal
from io import StringIO
from itertools import zip_longest
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from .compat import bytes_encode, chb, hex_bytes, inet_pton, orb, plain_str
from .consts import WINDOWS
from .error import Scapy_Exception, log_interactive, log_runtime, warning

__all__ = [
    "issubtype", "EDecimal", "get_temp_file", "get_temp_dir", "sane", "lhex",
    "hexdump", "hexdump_str", "linehexdump", "chexdump", "hexstr",
    "repr_hex", "hexdiff", "hexdiff_str", "checksum",
    "checksum_endian_transform", "fletcher16_checksum",
    "fletcher16_checkbytes", "mac2str", "valid_mac", "str2mac", "randstring",
    "zerofree_randstring", "stror", "strxor", "strand", "strrot",
    "inet_aton", "inet_ntoa", "atol", "valid_ip", "valid_net", "valid_ip6",
    "valid_net6", "ltoa", "itom", "in4_cidr2mask", "in4_isincluded",
    "in4_ismaddr", "in4_ismlladdr", "in4_ismgladdr", "in4_ismlsaddr",
    "in4_isaddrllallnodes", "in4_getnsmac", "decode_locale_str",
    "ContextManagerCaptureOutput", "do_graph", "tex_escape", "colgen",
    "incremental_label", "binrepr", "long_converter", "EnumElement",
    "Enum_metaclass", "import_hexcap", "get_terminal_width", "pretty_list",
    "human_size", "make_table", "make_lined_table", "make_tex_table",
    "whois", "CLIUtil", "AutoArgparse", "PeriodicSenderThread",
    "SingleConversationSocket", "restart",
]


def issubtype(x: Any, t: Any) -> bool:
    if isinstance(t, str):
        return t in (z.__name__ for z in x.__bases__)
    return isinstance(x, type) and issubclass(x, t)


class EDecimal(Decimal):
    """A Decimal that also does arithmetic and comparison with floats, which
    is what a packet's timestamp has to accept."""

    def __add__(self, other, context=None):
        return EDecimal(Decimal.__add__(self, Decimal(other)))

    def __radd__(self, other):
        return EDecimal(Decimal.__add__(self, Decimal(other)))

    def __sub__(self, other):
        return EDecimal(Decimal.__sub__(self, Decimal(other)))

    def __rsub__(self, other):
        return EDecimal(Decimal.__rsub__(self, Decimal(other)))

    def __mul__(self, other):
        return EDecimal(Decimal.__mul__(self, Decimal(other)))

    def __rmul__(self, other):
        return EDecimal(Decimal.__mul__(self, Decimal(other)))

    def __truediv__(self, other):
        return EDecimal(Decimal.__truediv__(self, Decimal(other)))

    def __floordiv__(self, other):
        return EDecimal(Decimal.__floordiv__(self, Decimal(other)))

    def __divmod__(self, other):
        r = Decimal.__divmod__(self, Decimal(other))
        return EDecimal(r[0]), EDecimal(r[1])

    def __mod__(self, other):
        return EDecimal(Decimal.__mod__(self, Decimal(other)))

    def __rmod__(self, other):
        return EDecimal(Decimal.__rmod__(self, Decimal(other)))

    def __pow__(self, other, modulo=None):
        return EDecimal(Decimal.__pow__(self, Decimal(other), modulo))

    def __eq__(self, other):
        if isinstance(other, Decimal):
            return super().__eq__(other)
        return bool(float(self) == other)

    __hash__ = Decimal.__hash__

    def normalize(self, precision):  # type: ignore[override]
        with decimal.localcontext() as ctx:
            ctx.prec = precision
            return EDecimal(super().normalize(ctx))


def _conf() -> Any:
    from . import config

    return config.conf


def get_temp_file(keep: bool = False, autoext: str = "", fd: bool = False) -> Any:
    """A temporary file's path, or the open file with ``fd=True``. Unless
    ``keep``, it is removed by ``scapy_delete_temp_files()`` and at exit."""
    f = tempfile.NamedTemporaryFile(prefix="wiry", suffix=autoext, delete=False)
    if not keep:
        _conf().temp_files.append(f.name)
    if fd:
        return f
    f.close()
    return f.name


def get_temp_dir(keep: bool = False) -> str:
    dname = tempfile.mkdtemp(prefix="wiry")
    if not keep:
        _conf().temp_files.append(dname)
    return dname


def sane(x: Any, color: bool = False) -> str:
    """Printable ASCII as itself, anything else as a dot. wiry has no colour
    themes, so ``color`` changes nothing."""
    return "".join(chr(j) if 32 <= j < 127 else "." for j in map(orb, bytes_encode(x)))


def restart() -> None:
    """Re-execute the running console."""
    if not _conf().interactive or not os.path.isfile(sys.argv[0]):
        raise OSError("wiry was not started from its console")
    if WINDOWS:
        res_code = 1
        try:
            res_code = subprocess.call([sys.executable] + sys.argv)
        finally:
            os._exit(res_code)
    os.execv(sys.executable, [sys.executable] + sys.argv)


def lhex(x: Any) -> str:
    from .volatile import VolatileValue

    if isinstance(x, VolatileValue):
        return repr(x)
    if isinstance(x, int):
        return hex(x)
    if isinstance(x, tuple):
        return "(%s)" % ", ".join(lhex(v) for v in x)
    if isinstance(x, list):
        return "[%s]" % ", ".join(lhex(v) for v in x)
    return str(x)


def _hexdump_lines(x: bytes, width: int) -> List[str]:
    return [
        "%04x  " % i
        + "".join("%02X " % b for b in x[i:i + width])
        + "   " * (width - len(x[i:i + width]))
        + " " + sane(x[i:i + width])
        for i in range(0, len(x), width)
    ]


def hexdump(p: Any, dump: bool = False) -> Optional[str]:
    """Offset, sixteen hex octets and their text, one line each, as tcpdump
    prints them. Prints, or returns the text with ``dump=True``."""
    s = "\n".join(_hexdump_lines(bytes_encode(p), 16))
    if dump:
        return s
    print(s)
    return None


def hexdump_str(p: Any, width: int = 16) -> str:
    """What ``hexdump()`` prints, newline included, at any line width."""
    lines = _hexdump_lines(bytes_encode(p), width)
    return "".join(line + "\n" for line in lines) or "\n"


def linehexdump(p: Any, onlyasc: int = 0, onlyhex: int = 0, dump: bool = False) -> Optional[str]:
    s = hexstr(p, onlyasc=onlyasc, onlyhex=onlyhex)
    if dump:
        return s
    print(s)
    return None


def chexdump(p: Any, dump: bool = False) -> Optional[str]:
    s = ", ".join("%#04x" % b for b in bytes_encode(p))
    if dump:
        return s
    print(s)
    return None


def hexstr(p: Any, onlyasc: int = 0, onlyhex: int = 0, color: bool = False) -> str:
    x = bytes_encode(p)
    s = []
    if not onlyasc:
        s.append(" ".join("%02X" % b for b in x))
    if not onlyhex:
        s.append(sane(x))
    return "  ".join(s)


def repr_hex(s: bytes) -> str:
    return "".join("%02x" % orb(x) for x in s)


def _backtrack(xb: bytes, yb: bytes, algo: Optional[str], autojunk: bool) -> Tuple[list, list]:
    if algo is None:
        complexity = len(xb) * len(yb)
        if complexity < 1e7:
            algo = "wagnerfischer"
            if complexity > 1e6:
                log_interactive.info(
                    "Complexity is a bit high. hexdiff will take a few seconds."
                )
        else:
            algo = "difflib"
            # Without autojunk a run of one octet, which zero padding is, makes
            # difflib quadratic: minutes for two 64 KB frames.
            autojunk = autojunk or complexity > 1e8
    backtrackx: list = []
    backtracky: list = []
    if algo == "wagnerfischer":
        backtrackx, backtracky = _wagner_fischer(xb[::-1], yb[::-1])
    elif algo == "difflib":
        sm = difflib.SequenceMatcher(a=xb, b=yb, autojunk=autojunk)
        xarr = [xb[i:i + 1] for i in range(len(xb))]
        yarr = [yb[i:i + 1] for i in range(len(yb))]
        for typ, x0, x1, y0, y1 in sm.get_opcodes():
            if typ == "delete":
                backtrackx += xarr[x0:x1]
                backtracky += [b""] * (x1 - x0)
            elif typ == "insert":
                backtrackx += [b""] * (y1 - y0)
                backtracky += yarr[y0:y1]
            else:
                backtrackx += xarr[x0:x1]
                backtracky += yarr[y0:y1]
        if autojunk:
            lbx, lby = len(backtrackx), len(backtracky)
            backtrackx += [b""] * (max(lbx, lby) - lbx)
            backtracky += [b""] * (max(lbx, lby) - lby)
    else:
        raise ValueError("Unknown algorithm '%s'" % algo)
    return backtrackx, backtracky


def _wagner_fischer(xb: bytes, yb: bytes) -> Tuple[list, list]:
    """scapy's edit-distance alignment, ties broken as its ``min()`` over
    ``(cost, step)`` tuples breaks them: diagonal, then up, then left. One
    octet of direction per cell instead of a dict entry, so the 10^7 cells the
    default allows cost 10 MB rather than a gigabyte."""
    n, m = len(xb), len(yb)
    steps = [bytearray(m) for _ in range(n)]
    prev = [j + 1 for j in range(m)]
    for i in range(n):
        corner = i + 1 if i else 0
        left = i + 2
        cur = [0] * m
        row = steps[i]
        x = xb[i]
        for j in range(m):
            diag = corner + (x != yb[j])
            up = prev[j] + 1
            side = left + 1
            if diag <= up and diag <= side:
                left = diag
            elif up <= side:
                left = up
                row[j] = 1
            else:
                left = side
                row[j] = 2
            cur[j] = left
            corner = prev[j]
        prev = cur
    bx: list = []
    by: list = []
    i, j = n - 1, m - 1
    while not (i == j == -1):
        if i == -1:
            i2, j2 = -1, j - 1
        elif j == -1:
            i2, j2 = i - 1, -1
        else:
            step = steps[i][j]
            i2, j2 = (i - 1, j - 1) if step == 0 else (i - 1, j) if step == 1 else (i, j - 1)
        bx.append(xb[i2 + 1:i + 1])
        by.append(yb[j2 + 1:j + 1])
        i, j = i2, j2
    return bx, by


def hexdiff(a: Any, b: Any, algo: Optional[str] = None, autojunk: bool = False) -> None:
    """Print two byte strings or packets side by side, aligned by edit
    distance (``wagnerfischer``) or by ``difflib``; by default the first
    unless the product of the lengths reaches 10^7."""
    print(hexdiff_str(a, b, algo, autojunk), end="")


def hexdiff_str(a: Any, b: Any, algo: Optional[str] = None, autojunk: bool = False) -> str:
    """What ``hexdiff()`` prints."""
    backtrackx, backtracky = _backtrack(bytes_encode(a), bytes_encode(b), algo, autojunk)
    out: List[str] = []
    x = y = i = 0
    dox, doy = 1, 0
    btx_len = len(backtrackx)
    while i < btx_len:
        linex = backtrackx[i:i + 16]
        liney = backtracky[i:i + 16]
        xx = sum(len(k) for k in linex)
        yy = sum(len(k) for k in liney)
        if dox and not xx:
            dox, doy = 0, 1
        if dox and linex == liney:
            doy = 1
        row = ""
        if dox:
            xd, j = y, 0
            while not linex[j]:
                j += 1
                xd -= 1
            row += "%04x " % xd
            x += xx
            line = linex
        else:
            row += "     "
        if doy:
            yd, j = y, 0
            while not liney[j]:
                j += 1
                yd -= 1
            row += "%04x " % yd
            y += yy
            line = liney
        else:
            row += "     "
        row += "  "
        cl = ""
        for j in range(16):
            if i + j < min(len(backtrackx), len(backtracky)):
                if line[j]:
                    row += "%02X " % orb(line[j])
                    cl += sane(line[j])
                else:
                    row += "   "
                    cl += " "
            else:
                row += "   "
            if j == 7:
                row += " "
        out.append(row + "  " + cl + "\n")
        if doy or not yy:
            dox, doy = 1, 0
            i += 16
        elif yy:
            dox, doy = 0, 1
        else:
            i += 16
    return "".join(out)


if struct.pack("H", 1) == b"\x00\x01":
    def checksum_endian_transform(chk: int) -> int:
        return chk
else:
    def checksum_endian_transform(chk: int) -> int:
        return ((chk >> 8) & 0xFF) | chk << 8


def checksum(pkt: bytes) -> int:
    """RFC 1071's internet checksum."""
    if len(pkt) % 2 == 1:
        pkt += b"\0"
    s = sum(array.array("H", pkt))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    s = ~s
    return checksum_endian_transform(s) & 0xFFFF


def _fletcher16(charbuf: bytes) -> Tuple[int, int]:
    c0 = c1 = 0
    for char in charbuf:
        c0 += char
        c1 += c0
    return c0 % 255, c1 % 255


def fletcher16_checksum(binbuf: bytes) -> int:
    """Zero over a buffer that carries its own check octets."""
    c0, c1 = _fletcher16(binbuf)
    return (c1 << 8) | c0


def fletcher16_checkbytes(binbuf: bytes, offset: int) -> bytes:
    """The two octets that, written at ``offset``, make the buffer's
    Fletcher-16 sum zero (RFC 2328 §12.1.7, RFC 905 Annex B)."""
    if len(binbuf) < offset:
        raise Exception("Packet too short for checkbytes %d" % len(binbuf))
    binbuf = binbuf[:offset] + b"\x00\x00" + binbuf[offset + 2:]
    c0, c1 = _fletcher16(binbuf)
    x = ((len(binbuf) - offset - 1) * c0 - c1) % 255
    if x <= 0:
        x += 255
    y = 510 - c0 - x
    if y > 255:
        y -= 255
    return chb(x) + chb(y)


def mac2str(mac: Any) -> bytes:
    return b"".join(chb(int(x, 16)) for x in plain_str(mac).split(":"))


def valid_mac(mac: Any) -> bool:
    try:
        return len(mac2str(mac)) == 6
    except ValueError:
        return False


def str2mac(s: Any) -> str:
    if isinstance(s, str):
        return ("%02x:" * len(s))[:-1] % tuple(map(ord, s))
    return ("%02x:" * len(s))[:-1] % tuple(s)


def randstring(length: int) -> bytes:
    return bytes(random.randint(0, 255) for _ in range(length))


def zerofree_randstring(length: int) -> bytes:
    return bytes(random.randint(1, 255) for _ in range(length))


def stror(s1: bytes, s2: bytes) -> bytes:
    return bytes(x | y for x, y in zip(s1, s2))


def strxor(s1: bytes, s2: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(s1, s2))


def strand(s1: bytes, s2: bytes) -> bytes:
    return bytes(x & y for x, y in zip(s1, s2))


def strrot(s1: bytes, count: int, right: bool = True) -> bytes:
    off = count % len(s1)
    if right:
        return s1[-off:] + s1[:-off]
    return s1[off:] + s1[:off]


inet_aton = socket.inet_aton
inet_ntoa = socket.inet_ntoa


def atol(x: str) -> int:
    try:
        ip = inet_aton(x)
    except socket.error:
        raise ValueError("Bad IP format: %s" % x)
    return struct.unpack("!I", ip)[0]


def valid_ip(addr: Any) -> bool:
    try:
        atol(plain_str(addr))
    except (OSError, ValueError, UnicodeDecodeError):
        return False
    return True


def valid_net(addr: Any) -> bool:
    try:
        addr = plain_str(addr)
    except UnicodeDecodeError:
        return False
    if "/" in addr:
        ip, mask = addr.split("/", 1)
        return valid_ip(ip) and mask.isdigit() and 0 <= int(mask) <= 32
    return valid_ip(addr)


def valid_ip6(addr: Any) -> bool:
    try:
        inet_pton(socket.AF_INET6, plain_str(addr))
    except (OSError, ValueError, UnicodeDecodeError):
        return False
    return True


def valid_net6(addr: Any) -> bool:
    try:
        addr = plain_str(addr)
    except UnicodeDecodeError:
        return False
    if "/" in addr:
        ip, mask = addr.split("/", 1)
        return valid_ip6(ip) and mask.isdigit() and 0 <= int(mask) <= 128
    return valid_ip6(addr)


def ltoa(x: int) -> str:
    return inet_ntoa(struct.pack("!I", x & 0xFFFFFFFF))


def itom(x: int) -> int:
    return (0xFFFFFFFF00000000 >> x) & 0xFFFFFFFF


def in4_cidr2mask(m: int) -> bytes:
    if m > 32 or m < 0:
        raise Scapy_Exception(
            "value provided to in4_cidr2mask outside [0, 32] domain (%d)" % m
        )
    return strxor(b"\xff" * 4, struct.pack(">I", 2 ** (32 - m) - 1))


def in4_isincluded(addr: str, prefix: str, mask: int) -> bool:
    temp = inet_pton(socket.AF_INET, addr)
    pref = in4_cidr2mask(mask)
    return inet_pton(socket.AF_INET, prefix) == strand(temp, pref)


def in4_ismaddr(addr: str) -> bool:
    """RFC 5771: 224.0.0.0/4."""
    return in4_isincluded(addr, "224.0.0.0", 4)


def in4_ismlladdr(addr: str) -> bool:
    """RFC 5771 §4, the Local Network Control Block: 224.0.0.0/24."""
    return in4_isincluded(addr, "224.0.0.0", 24)


def in4_ismgladdr(addr: str) -> bool:
    """Multicast that is neither link-local nor administratively scoped."""
    return (
        in4_isincluded(addr, "224.0.0.0", 4)
        and not in4_isincluded(addr, "224.0.0.0", 24)
        and not in4_isincluded(addr, "239.0.0.0", 8)
    )


def in4_ismlsaddr(addr: str) -> bool:
    """RFC 2365's administratively scoped block: 239.0.0.0/8."""
    return in4_isincluded(addr, "239.0.0.0", 8)


def in4_isaddrllallnodes(addr: str) -> bool:
    return inet_pton(socket.AF_INET, "224.0.0.1") == inet_pton(socket.AF_INET, addr)


def in4_getnsmac(a: bytes) -> str:
    """RFC 1112 §6.4: the low 23 bits of the group under 01:00:5e."""
    return "01:00:5e:%.2x:%.2x:%.2x" % (a[1] & 0x7F, a[2], a[3])


def decode_locale_str(x: bytes) -> str:
    return x.decode(encoding=locale.getlocale()[1] or "utf-8", errors="replace")


class ContextManagerCaptureOutput:
    """Collects what is printed inside the block."""

    def __init__(self) -> None:
        self.result_export_object = ""

    def __enter__(self) -> "ContextManagerCaptureOutput":
        from unittest import mock

        def write(s: str, decorator: "ContextManagerCaptureOutput" = self) -> None:
            decorator.result_export_object += s

        mock_stdout = mock.Mock()
        mock_stdout.write = write
        self.bck_stdout = sys.stdout
        sys.stdout = mock_stdout
        return self

    def __exit__(self, *exc: Any) -> bool:
        sys.stdout = self.bck_stdout
        return False

    def get_output(self, eval_bytes: bool = False) -> str:
        if self.result_export_object.startswith("b'") and eval_bytes:
            return plain_str(eval(self.result_export_object))
        return self.result_export_object


def do_graph(graph: str, prog: Optional[str] = None, format: Optional[str] = None,
             target: Any = None, type: Optional[str] = None,
             string: Optional[bool] = None, options: Optional[List[str]] = None) -> Optional[str]:
    """Render DOT source through graphviz.

    Returns the source untouched when ``string`` is true, and also when it is
    left unset and no ``target`` or ``format`` is given: the DOT text is the
    result, and graphviz and ImageMagick stay optional (E24). A ``target`` is
    a path, ``"|command"``, ``">path"`` or a binary file object.
    """
    if string or (string is None and target is None and format is None
                  and type is None):
        return graph
    if type is not None:
        format = type
    format = format or "svg"
    conf = _conf()
    prog = prog or conf.prog.dot
    if shutil.which(prog) is None:
        raise _missing(prog, "graphviz")
    if target is None:
        if shutil.which(conf.prog.display) is None:
            raise _missing(conf.prog.display, "ImageMagick")
        target = subprocess.Popen([conf.prog.display], stdin=subprocess.PIPE).stdin
    if isinstance(target, str):
        if target.startswith("|"):
            target = subprocess.Popen(target[1:].lstrip(), shell=True,
                                      stdin=subprocess.PIPE).stdin
        elif target.startswith(">"):
            target = open(target[1:].lstrip(), "wb")
        else:
            target = open(os.path.abspath(target), "wb")
    proc = subprocess.Popen(
        [prog] + list(options or []) + ["-T%s" % format],
        stdin=subprocess.PIPE, stdout=target, stderr=subprocess.PIPE,
    )
    _, stderr = proc.communicate(bytes_encode(graph))
    if proc.returncode != 0:
        raise OSError("GraphViz call failed:\n" + plain_str(stderr))
    try:
        target.close()
    except Exception:
        pass
    return None


def _missing(prog: str, package: str) -> OSError:
    return OSError(
        f"{prog} is needed to render a graph but is not on PATH. Install "
        f"{package}, or leave target= and format= unset to get the DOT source."
    )


_TEX_TR = {
    "{": "{\\tt\\char123}",
    "}": "{\\tt\\char125}",
    "\\": "{\\tt\\char92}",
    "^": "\\^{}",
    "$": "\\$",
    "#": "\\#",
    "_": "\\_",
    "&": "\\&",
    "%": "\\%",
    "|": "{\\tt\\char124}",
    "~": "{\\tt\\char126}",
    "<": "{\\tt\\char60}",
    ">": "{\\tt\\char62}",
}


def tex_escape(x: str) -> str:
    return "".join(_TEX_TR.get(c, c) for c in x)


def colgen(*lstcol: Any, **kargs: Any) -> Iterator[Any]:
    """Mixes the given quantities forever, three at a time, through
    ``trans``."""
    if len(lstcol) < 2:
        lstcol *= 2
    trans = kargs.get("trans", lambda x, y, z: (x, y, z))
    n = len(lstcol)
    while True:
        for i in range(n):
            for j in range(n):
                for k in range(n):
                    if i != j or j != k or k != i:
                        yield trans(lstcol[(i + j) % n], lstcol[(j + k) % n],
                                    lstcol[(k + i) % n])


def incremental_label(label: str = "tag%05i", start: int = 0) -> Iterator[str]:
    while True:
        yield label % start
        start += 1


def binrepr(val: int) -> str:
    return bin(val)[2:]


def long_converter(s: str) -> int:
    return int(s.replace("\n", "").replace(" ", ""), 16)


class EnumElement:
    def __init__(self, key: str, value: int) -> None:
        self._key = key
        self._value = value

    def __repr__(self) -> str:
        return "<%s %s[%r]>" % (self.__dict__.get("_name", self.__class__.__name__),
                                self._key, self._value)

    def __getattr__(self, attr: str) -> Any:
        return getattr(self._value, attr)

    def __str__(self) -> str:
        return self._key

    def __bytes__(self) -> bytes:
        return bytes_encode(self.__str__())

    def __hash__(self) -> int:
        return self._value

    def __int__(self) -> int:
        return int(self._value)

    def __eq__(self, other: Any) -> bool:
        return self._value == int(other)

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)


class Enum_metaclass(type):
    element_class = EnumElement

    def __new__(cls, name: str, bases: Any, dct: Dict[str, Any]) -> Any:
        rdict = {}
        for k, v in list(dct.items()):
            if isinstance(v, int):
                v = cls.element_class(k, v)
                dct[k] = v
                rdict[v] = k
        dct["__rdict__"] = rdict
        return super().__new__(cls, name, bases, dct)

    def __getitem__(self, attr: Any) -> Any:
        return self.__rdict__[attr]

    def __contains__(self, val: Any) -> bool:
        return val in self.__rdict__

    def get(self, attr: Any, val: Any = None) -> Any:
        return self.__rdict__.get(attr, val)

    def __repr__(self) -> str:
        return "<%s>" % self.__dict__.get("name", self.__name__)


def import_hexcap(input_string: Optional[str] = None) -> bytes:
    """The octets of a pasted hex dump: tcpdump's, Wireshark's "export as
    hex", or ``hexdump()``'s. With no argument, lines are read from stdin
    until a blank one.

    An offset is recognised only when a colon or two spaces follow it, as
    every dumper writes one; scapy accepts one space, and so reads the first
    octet of a bare hex run as an offset and drops it.
    """
    from .describe import _HEXCAP

    p = ""
    read = StringIO(input_string).readline if input_string else input
    try:
        while True:
            line = read().strip()
            if not line:
                break
            m = _HEXCAP.match(line)
            if m is None:
                warning("Parsing error during hexcap")
                continue
            p += m.group(1)
    except EOFError:
        pass
    return hex_bytes(re.sub(r"\s", "", p))


def get_terminal_width() -> Optional[int]:
    sizex = shutil.get_terminal_size(fallback=(0, 0))[0]
    if sizex:
        return sizex
    try:
        sizex = int(os.environ["COLUMNS"])
    except (KeyError, ValueError):
        pass
    return sizex or 79


def pretty_list(rtlst: list, header: list, sortBy: Optional[int] = 0,
                borders: bool = False) -> str:
    """Rows under a header, cropped to the terminal when
    ``conf.auto_crop_tables``. A cell holding a list spreads over as many
    lines as it has items."""
    _space = "|" if borders else "  "
    cols = len(header[0])
    _spacelen = len(_space) * (cols - 1) + int(WINDOWS)
    _croped = False
    if sortBy is not None:
        rtlst.sort(key=lambda x: x[sortBy])
    for i, line in enumerate(list(rtlst)):
        ids = []
        values = []
        for j, val in enumerate(line):
            if isinstance(val, list):
                ids.append(j)
                values.append(val or " ")
        if values:
            del rtlst[i]
            for k, ex_vals in enumerate(zip_longest(*values, fillvalue=" ")):
                extra_line = [" "] * cols if k else list(line)
                for j, h in enumerate(ids):
                    extra_line[h] = ex_vals[j]
                rtlst.insert(i + k, tuple(extra_line))
    rtslst = header + rtlst
    colwidth = [max(len(y) for y in x) for x in zip(*rtslst)]
    width = get_terminal_width()
    if _conf().auto_crop_tables and width:
        width = width - _spacelen
        while sum(colwidth) > width:
            _croped = True
            i = colwidth.index(max(colwidth))
            row = [len(x[i]) for x in rtslst]
            j = row.index(max(row))
            t = list(rtslst[j])
            t[i] = t[i][:-2] + "_"
            rtslst[j] = tuple(t)
            row[j] = len(t[i])
            colwidth[i] = max(row)
    if _croped:
        log_runtime.info("Table cropped to fit the terminal (conf.auto_crop_tables==True)")
    fmt = _space.join(["%%-%ds" % x for x in colwidth])
    if borders:
        rtslst.insert(1, tuple("-" * x for x in colwidth))
    return "\n".join(fmt % x for x in rtslst)


def human_size(x: int, fmt: str = ".1f") -> str:
    units = ["K", "M", "G", "T", "P", "E"]
    if not x:
        return "0B"
    i = int(math.log(x, 2 ** 10))
    if i and i < len(units):
        return format(x / 2 ** (10 * i), fmt) + units[i - 1]
    return str(x) + "B"


def _make_table(yfmtfunc: Callable, fmtfunc: Callable, endline: str, data: Any,
                fxyz: Callable, sortx: Optional[Callable] = None,
                sorty: Optional[Callable] = None,
                seplinefunc: Optional[Callable] = None,
                dump: bool = False) -> Optional[str]:
    vx: Dict[str, int] = {}
    vy: Dict[str, None] = {}
    vz: Dict[Tuple[str, str], str] = {}
    vxf: Dict[str, str] = {}
    tmp_len = 0
    for e in data:
        xx, yy, zz = [str(s) for s in fxyz(*_as_args(e))]
        tmp_len = max(len(yy), tmp_len)
        vx[xx] = max(vx.get(xx, 0), len(xx), len(zz))
        vy[yy] = None
        vz[(xx, yy)] = zz
    vxk = _sorted_axis(list(vx), sortx)
    vyk = _sorted_axis(list(vy), sorty)
    s = ""
    sepline = ""
    if seplinefunc:
        sepline = seplinefunc(tmp_len, [vx[x] for x in vxk])
        s += sepline + "\n"
    fmt = yfmtfunc(tmp_len)
    s += fmt % "" + " "
    for x in vxk:
        vxf[x] = fmtfunc(vx[x])
        s += vxf[x] % x + " "
    s += endline + "\n"
    if seplinefunc:
        s += sepline + "\n"
    for y in vyk:
        s += fmt % y + " "
        for x in vxk:
            s += vxf[x] % vz.get((x, y), "-") + " "
        s += endline + "\n"
    if seplinefunc:
        s += sepline + "\n"
    if dump:
        return s
    print(s, end="")
    return None


def _as_args(e: Any) -> tuple:
    """A query/answer pair spreads over two arguments; a packet is one."""
    return tuple(e) if isinstance(e, tuple) else (e,)


def _sorted_axis(keys: list, key: Optional[Callable]) -> list:
    if key:
        keys.sort(key=key)
        return keys
    for k in (int, atol):
        try:
            return sorted(keys, key=k)
        except Exception:
            pass
    keys.sort()
    return keys


def make_table(*args: Any, **kargs: Any) -> Optional[str]:
    """``make_table(data, fn)``: ``fn`` gives each element's column, row and
    cell. Prints, or returns the text with ``dump=True``."""
    return _make_table(lambda n: "%%-%is" % n, lambda n: "%%-%is" % n, "",
                       *args, **kargs)


def make_lined_table(*args: Any, **kargs: Any) -> Optional[str]:
    return _make_table(
        lambda n: "%%-%is |" % n, lambda n: "%%-%is |" % n, "", *args,
        seplinefunc=lambda a, x: "+".join("-" * (y + 2) for y in [a - 1] + x + [-2]),
        **kargs,
    )


def make_tex_table(*args: Any, **kargs: Any) -> Optional[str]:
    """Every cell is escaped: packet contents are attacker-chosen, and a raw
    backslash in one is a LaTeX command."""
    data, fxyz = args[0], args[1]

    def escaped(*e: Any) -> tuple:
        return tuple(tex_escape(str(v)) for v in fxyz(*e))

    return _make_table(lambda n: "%s", lambda n: "& %s", "\\\\", data, escaped,
                       *args[2:], seplinefunc=lambda a, x: "\\hline", **kargs)


def whois(ip_address: Any) -> bytes:
    """Ask whois.ripe.net about an address."""
    whois_ip = str(ip_address)
    try:
        query = socket.gethostbyname(whois_ip)
    except Exception:
        query = whois_ip
    with socket.create_connection(("whois.ripe.net", 43)) as s:
        s.send(query.encode("utf8") + b"\r\n")
        answer = b""
        while True:
            d = s.recv(4096)
            answer += d
            if not d:
                break
    lines = [line for line in answer.split(b"\n")
             if not line or not line.startswith(b"remarks:")]
    for i in range(1, len(lines)):
        if not lines[-i].strip():
            del lines[-i]
        else:
            break
    return b"\n".join(lines[3:])


class _CLIUtilMetaclass(type):
    class TYPE(enum.Enum):
        COMMAND = 0
        OUTPUT = 1
        COMPLETE = 2

    def __new__(cls, name: str, bases: Tuple[type, ...], dct: Dict[str, Any]) -> Any:
        kind = _CLIUtilMetaclass.TYPE
        dct["commands"] = {
            x.__name__: x for x in dct.values()
            if getattr(x, "cliutil_type", None) == kind.COMMAND
        }
        dct["commands_output"] = {
            x.cliutil_ref.__name__: x for x in dct.values()
            if getattr(x, "cliutil_type", None) == kind.OUTPUT
        }
        dct["commands_complete"] = {
            x.cliutil_ref.__name__: x for x in dct.values()
            if getattr(x, "cliutil_type", None) == kind.COMPLETE
        }
        return type.__new__(cls, name, bases, dct)


class CLIUtil(metaclass=_CLIUtilMetaclass):
    """A small command shell that is also an API: override ``ps1()``,
    register commands with ``@CLIUtil.addcommand()``, call ``loop()``.
    prompt_toolkit is needed only by the interactive loop."""

    commands: Dict[str, Callable[..., Any]] = {}
    commands_output: Dict[str, Callable[..., str]] = {}
    commands_complete: Dict[str, Callable[..., List[str]]] = {}

    def _depcheck(self) -> None:
        try:
            import prompt_toolkit  # noqa: F401
        except ImportError:
            raise ImportError(
                "the interactive shell needs prompt_toolkit: "
                "pip install prompt_toolkit"
            )

    def __init__(self, cli: bool = True, debug: bool = False) -> None:
        if cli:
            self._depcheck()
            self.loop(debug=debug)

    @staticmethod
    def _inspectkwargs(func: Any) -> None:
        func._flagnames = [
            x.name for x in inspect.signature(func).parameters.values()
            if x.kind == inspect.Parameter.KEYWORD_ONLY
        ]
        func._flags = [("-%s" % x) if len(x) == 1 else ("--%s" % x)
                       for x in func._flagnames]

    @staticmethod
    def _parsekwargs(func: Any, args: List[str]) -> Tuple[List[str], Dict[str, bool]]:
        kwargs: Dict[str, bool] = {}
        if func._flags:
            i = 0
            for arg in args:
                if arg in func._flags:
                    i += 1
                    kwargs[func._flagnames[func._flags.index(arg)]] = True
                    continue
                break
            args = args[i:]
        return args, kwargs

    @classmethod
    def _parseallargs(cls, func: Any, cmd: str, args: List[str]) -> Tuple[list, dict, dict]:
        args, kwargs = cls._parsekwargs(func, args)
        outkwargs: Dict[str, bool] = {}
        if cmd in cls.commands_output:
            args, outkwargs = cls._parsekwargs(cls.commands_output[cmd], args)
        return args, kwargs, outkwargs

    @classmethod
    def addcommand(cls, spaces: bool = False, globsupport: bool = False) -> Callable:
        def func(cmd: Any) -> Any:
            cmd.cliutil_type = _CLIUtilMetaclass.TYPE.COMMAND
            cmd._spaces = spaces
            cmd._globsupport = globsupport
            cls._inspectkwargs(cmd)
            if cmd._globsupport and not cmd._spaces:
                raise ValueError("Cannot use globsupport without spaces.")
            return cmd
        return func

    @classmethod
    def addoutput(cls, cmd: Any) -> Callable:
        def func(processor: Any) -> Any:
            processor.cliutil_type = _CLIUtilMetaclass.TYPE.OUTPUT
            processor.cliutil_ref = cmd
            cls._inspectkwargs(processor)
            return processor
        return func

    @classmethod
    def addcomplete(cls, cmd: Any) -> Callable:
        def func(processor: Any) -> Any:
            processor.cliutil_type = _CLIUtilMetaclass.TYPE.COMPLETE
            processor.cliutil_ref = cmd
            return processor
        return func

    def ps1(self) -> str:
        return "> "

    def close(self) -> None:
        print("Exited")

    def help(self, cmd: Optional[str] = None) -> None:
        def _args(func: Any) -> str:
            flags = func._flags.copy()
            if func.__name__ in self.commands_output:
                flags += self.commands_output[func.__name__]._flags
            return " %s%s" % (
                "%s " % " ".join("[%s]" % x for x in flags) if flags else "",
                " ".join(
                    "<%s%s>" % (x.name, "?" if (x.default is None or
                                                x.default != inspect.Parameter.empty) else "")
                    for x in list(inspect.signature(func).parameters.values())[1:]
                    if x.name not in func._flagnames and x.name[0] != "_"
                ),
            )

        if cmd:
            if cmd not in self.commands:
                print("Unknown command '%s'" % cmd)
                return
            func = self.commands[cmd]
            print("%s%s: %s" % (cmd, _args(func), func.__doc__ and func.__doc__.strip()))
            return
        header = "│ %s - Help │" % self.__class__.__name__
        print("┌" + "─" * (len(header) - 2) + "┐")
        print(header)
        print("└" + "─" * (len(header) - 2) + "┘")
        print(pretty_list(
            [(c, _args(f), f.__doc__ and f.__doc__.strip().split("\n")[0] or "")
             for c, f in self.commands.items()],
            [("Command", "Arguments", "Description")],
        ))

    def _completer(self) -> Any:
        from prompt_toolkit.completion import Completer, Completion

        outer = self

        class CLICompleter(Completer):
            def get_completions(self, document: Any, complete_event: Any) -> Any:
                if not complete_event.completion_requested:
                    return
                parts = document.text.split(" ")
                cmd = parts[0].lower()
                if cmd not in outer.commands:
                    for possible in (x for x in outer.commands if x.startswith(cmd)):
                        yield Completion(possible, start_position=-len(cmd))
                elif len(parts) > 1:
                    args, _, _ = outer._parseallargs(outer.commands[cmd], cmd, parts[1:])
                    arg = " ".join(args)
                    if cmd in outer.commands_complete:
                        for possible in outer.commands_complete[cmd](outer, arg):
                            yield Completion(possible, start_position=-len(arg))

        return CLICompleter()

    def loop(self, debug: int = 0) -> None:
        from prompt_toolkit import PromptSession

        session = PromptSession(completer=self._completer())
        while True:
            try:
                cmd = session.prompt(self.ps1()).strip()
            except KeyboardInterrupt:
                continue
            except EOFError:
                self.close()
                break
            args = cmd.split(" ")[1:]
            cmd = cmd.split(" ")[0].strip().lower()
            if not cmd:
                continue
            if cmd in ["help", "h", "?"]:
                self.help(" ".join(args))
                continue
            if cmd in "exit":
                break
            if cmd not in self.commands:
                print("Unknown command. Type help or ?")
                continue
            func = self.commands[cmd]
            args, kwargs, outkwargs = self._parseallargs(func, cmd, args)
            calls = [args]
            if func._spaces:
                args = [" ".join(args)]
                calls = [args]
                if func._globsupport and "*" in args[0]:
                    if args[0].count("*") > 1:
                        print("More than 1 glob star (*) is currently unsupported.")
                        continue
                    before, after = args[0].split("*", 1)
                    reg = re.compile(re.escape(before) + r".*" + after)
                    calls = [[x] for x in self.commands_complete[cmd](self, before)
                             if reg.match(x)]
            for args in calls:
                res = None
                try:
                    res = func(self, *args, **kwargs)
                except TypeError:
                    print("Bad number of arguments !")
                    self.help(cmd=cmd)
                    continue
                except Exception as ex:
                    print("Command failed with error: %s" % ex)
                    if debug:
                        traceback.print_exception(ex)
                try:
                    if res and cmd in self.commands_output:
                        self.commands_output[cmd](self, res, **outkwargs)
                except Exception as ex:
                    print("Output processor failed with error: %s" % ex)


def AutoArgparse(func: Any, _parseonly: bool = False) -> Optional[Tuple[List[str], List[str]]]:
    """Build an argparse command line from a typed function and its Sphinx
    docstring, then call the function with what was parsed."""
    argsdoc = {}
    desc = ""
    if func.__doc__:
        m = re.match(
            r"((?:.|\n)*?)(\n\s*:(?:param|type|raises|return|rtype)(?:.|\n)*)",
            func.__doc__.strip(),
        )
        if not m:
            desc = func.__doc__.strip()
        else:
            desc = m.group(1)
            for argtype, argparam, argdesc in re.findall(
                r"\s*:(param|type|raises|return|rtype)\s*([^:]*):(.*)", m.group(2)
            ):
                argparam, argdesc = argparam.strip(), argdesc.strip()
                if argtype == "param":
                    if not argparam:
                        raise ValueError(":param: without a name !")
                    argsdoc[argparam] = argdesc
    positional = []
    noargument = []
    hexarguments = []
    parameters: Dict[str, Dict[str, Any]] = {}
    for param in inspect.signature(func).parameters.values():
        if not param.annotation:
            continue
        noarg = False
        parname = param.name.replace("_", "-")
        paramkwargs: Dict[str, Any] = {}
        if param.annotation is bool:
            if param.default is True:
                parname = "no-" + parname
                paramkwargs["action"] = "store_false"
            else:
                paramkwargs["action"] = "store_true"
            noarg = True
        elif param.annotation is bytes:
            paramkwargs["type"] = str
            hexarguments.append(parname)
        elif param.annotation in [str, int, float]:
            paramkwargs["type"] = param.annotation
        else:
            continue
        if param.default != inspect.Parameter.empty:
            if param.kind == inspect.Parameter.POSITIONAL_ONLY:
                positional.append(param.name)
                paramkwargs["nargs"] = "?"
            else:
                parname = "--" + parname
            paramkwargs["default"] = param.default
        else:
            positional.append(param.name)
        if param.kind == inspect.Parameter.VAR_POSITIONAL:
            paramkwargs["action"] = "append"
        if param.name in argsdoc:
            if param.annotation is bytes:
                prefix = "(hex) "
            elif param.annotation is bool:
                prefix = "(flag) "
            else:
                prefix = "(%s) " % param.annotation.__name__
            paramkwargs["help"] = prefix + argsdoc[param.name]
        parameters[parname] = paramkwargs
        if noarg:
            noargument.append(parname)
    if _parseonly:
        return (
            [x for x in parameters if x not in positional] + ["--help"],
            [x for x in noargument if x not in positional] + ["--help"],
        )
    parser = argparse.ArgumentParser(
        prog=func.__name__, description=desc,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    for parname, paramkwargs in parameters.items():
        parser.add_argument(parname, **paramkwargs)
    params = vars(parser.parse_args())
    for p in hexarguments:
        if params[p] is not None:
            try:
                params[p] = bytes.fromhex(params[p])
            except ValueError:
                print("ERROR: the value of parameter %s '%s' is not valid "
                      "hexadecimal !" % (p, params[p]))
                return None
    try:
        func(*[params.pop(x) for x in positional],
             **{(k[3:] if k.startswith("no_") else k): v for k, v in params.items()})
    except AssertionError as ex:
        print("ERROR: " + str(ex))
        parser.print_help()
    return None


class PeriodicSenderThread(threading.Thread):
    """Sends ``pkt`` (or each of a list) on ``sock`` every ``interval``
    seconds until ``stop()`` or the socket closes."""

    def __init__(self, sock: Any, pkt: Any, interval: float = 0.5,
                 ignore_exceptions: bool = True) -> None:
        self._pkts = pkt if isinstance(pkt, list) else [pkt]
        self._socket = sock
        self._stopped = threading.Event()
        self._enabled = threading.Event()
        self._enabled.set()
        self._interval = interval
        self._ignore_exceptions = ignore_exceptions
        threading.Thread.__init__(self, daemon=True)

    def enable(self) -> None:
        self._enabled.set()

    def disable(self) -> None:
        self._enabled.clear()

    def run(self) -> None:
        while not self._stopped.is_set() and not self._socket.closed:
            for p in self._pkts:
                try:
                    if self._enabled.is_set():
                        self._socket.send(p)
                except (OSError, TimeoutError):
                    if self._ignore_exceptions:
                        return
                    raise
                self._stopped.wait(timeout=self._interval)
                if self._stopped.is_set() or self._socket.closed:
                    break

    def stop(self) -> None:
        self._stopped.set()
        self.join(self._interval * 2)


class SingleConversationSocket:
    """Serialises the sends and exchanges of several threads on one socket."""

    def __init__(self, o: Any) -> None:
        self._inner = o
        self._tx_mutex = threading.RLock()

    @property
    def __dict__(self) -> Any:  # type: ignore[override]
        return self._inner.__dict__

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def sr1(self, *args: Any, **kargs: Any) -> Any:
        with self._tx_mutex:
            return self._inner.sr1(*args, **kargs)

    def sr(self, *args: Any, **kargs: Any) -> Any:
        with self._tx_mutex:
            return self._inner.sr(*args, **kargs)

    def send(self, x: Any) -> Any:
        with self._tx_mutex:
            try:
                return self._inner.send(x)
            except (ConnectionError, OSError):
                self._inner.close()
                raise


# scapy.utils is also where scripts import these from.
_FORWARD = dict.fromkeys(
    ("rdpcap", "wrpcap", "wrpcapng", "PcapWriter", "PcapNgWriter",
     "corrupt_bytes", "corrupt_bits"), "wiry")
_FORWARD.update(dict.fromkeys(
    ("PcapReader_metaclass", "RawPcapReader", "PcapReader", "RawPcapNgReader",
     "PcapNgReader", "GenericPcapWriter", "GenericRawPcapWriter",
     "RawPcapWriter", "RawPcapNgWriter", "ERFEthernetReader_metaclass",
     "ERFEthernetReader", "ERFEthernetWriter", "rderf", "wrerf"), "wiry.pcapio"))
_FORWARD.update(dict.fromkeys(
    ("tcpdump", "wireshark", "tdecode", "hexedit", "ContextManagerSubprocess"),
    "wiry.external"))


def __getattr__(name: str) -> Any:
    module = _FORWARD.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    return getattr(importlib.import_module(module), name)
