"""Differential harness: run real scapy code against wiry and diff the output.

The question is not "do our own examples pass" but "does code written for scapy
produce the same thing under wiry". Each script runs twice under `scapy.all` and
once under `wiry`, in lockstep, one top-level statement at a time. After every
statement the three runs are compared on printed output, the repr of a bare
expression, every name the statement bound (repr, summary, show, raw bytes,
every field of every layer) and any exception.

Three corpora, none of them vendored:

  scripts  `dev/scripts/*.py`, idiomatic tasks written from the public API.
  doc      `>>>` transcripts from scapy's documentation. The recorded output in
           the docs is ignored; live scapy is the oracle, not the prose.
  uts      scapy's regression campaigns: `test/*.uts`, `test/scapy/*.uts` and
           everything under `test/scapy/layers/`. `dev/scapy_suite.py` asks
           whether they pass; this asks whether they print the same thing.

A doc page and a `.uts` file are each one session: their blocks share a
namespace, as they do for a reader following the page and for UTScapy.

    git clone --depth 1 https://github.com/secdev/scapy.git /tmp/scapy-src
    python dev/script_parity.py --report dev/script_parity_report.md

    --source scripts|doc|uts|all   which corpora to run
    --only SUBSTR                  only sessions whose name contains SUBSTR
    --pcap FILE                    a real capture; its first 200 packets are
                                   exposed to scripts as REAL_PCAP
    --causes N                     rows of the ranked table to print
    --show ID                      print every difference found in one script
    --report FILE                  also write the ranked table as Markdown
    --jobs N                       sessions run in parallel, one process each

Verdicts. `pass`: every comparable statement agreed. `differ`: at least one
cause was found. `cascade`: wiry failed only because an earlier block in the
session failed under wiry and left a name unbound; counted against the pass
rate but not ranked, so one defect is not counted once per later block.
`skip`: never judged, with the reason. A `.uts` block that scapy 2.7.0 itself
fails is a skip unless wiry already differed before the failing line, since
the campaigns are written against scapy master.

Statements whose output differs between the two scapy runs are not compared,
so time, randomness and identity never count against wiry.
"""

import argparse
import ast
import builtins
import contextlib
import datetime
import gc
import importlib
import importlib.metadata
import io
import logging
import multiprocessing
import multiprocessing.connection
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import types
from pathlib import Path

import wiry

try:
    import scapy.all as scapy
    from scapy.config import conf as scapy_conf
except ImportError:
    sys.exit("scapy not installed; this is a dev-only oracle")

# scapy_suite answers every `scapy.*` import with wiry, process-wide, the
# moment it is imported. Here real scapy is the oracle, so its finder is
# removed again and scapy's modules put back; the wiry run gets the same
# substitution per namespace from `_wiry_import` instead.
sys.path.insert(0, str(Path(__file__).resolve().parent))
_meta, _mods = list(sys.meta_path), dict(sys.modules)
import scapy_suite  # noqa: E402
sys.meta_path[:] = _meta
sys.modules.update(_mods)
del _meta, _mods
from scapy_suite import environment_block, parse_uts  # noqa: E402
from scapy.tools.UTscapy import import_UTscapy_tools  # noqa: E402

SCRIPT_DIR = Path(__file__).resolve().parent / "scripts"
TIMEOUT_SECONDS = 10
SESSION_TIMEOUT = 600
SCAPY_SRC = "/tmp/scapy-src"

# Each of these reaches the wire, blocks on an interface, starts threads that
# outlive the statement, or loads code wiry does not ship.
FORBIDDEN = {
    "send", "sendp", "sendpfast", "sr", "sr1", "srp", "srp1", "srloop",
    "srploop", "srflood", "srpflood", "sniff", "AsyncSniffer", "tcpdump",
    "wireshark", "traceroute", "traceroute6", "arping", "arpcachepoison",
    "promiscping", "arp_mitm", "psdump", "pdfdump", "voip_play", "input",
    "raw_input", "exit", "quit", "load_contrib", "load_layer", "restart",
    "subprocess", "Automaton", "AnsweringMachine", "PipeEngine", "sniff_offline",
    "interact", "bridge_and_sniff", "srbt", "srbt1", "tshark", "nmap_fp",
}

FORBIDDEN_METHODS = {
    "pdfdump", "psdump", "svgdump", "canvas_dump", "graph", "conversations",
    "plot", "afterglow", "timeskew_graph", "hexedit", "show3d", "psend",
    "send", "sr", "sr1", "srp", "srp1", "recv", "make_table", "diffplot",
    "multiplot", "rawhexdump",
}

FORBIDDEN_CALLS = re.compile(
    r"\bos\.(system|popen|exec\w*|fork|kill|spawn\w*)\b|\bsocket\.socket\("
)

# `sniff(offline=...)` is pure file work and the commonest way to drive a
# capture, so it is let through.
SNIFF_OFFLINE = re.compile(r"\bsniff\s*\(\s*(?:[^()]*,\s*)?offline\s*=")
IDENT = re.compile(r"(?<![\w.])([A-Za-z_][A-Za-z0-9_]*)\b")
ADDR = re.compile(r"0x[0-9a-fA-F]{6,}")

# scapy.VERSION falls back to a file date when it finds no VERSION file or
# git checkout, so the installed distribution's metadata is the authority.
SCAPY_VERSION = importlib.metadata.version("scapy")
SCAPY_NAMES = frozenset(dir(scapy))
WIRY_LAYERS = frozenset(wiry.known_layers())


class Timeout(Exception):
    pass


@contextlib.contextmanager
def deadline(seconds):
    def fire(_sig, _frm):
        raise Timeout(f"exceeded {seconds}s")

    old = signal.signal(signal.SIGALRM, fire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)




class Script:
    def __init__(self, source, session, name, code, keywords=()):
        self.source = source
        self.session = session
        self.name = name
        self.code = code
        self.keywords = set(keywords)

    @property
    def ident(self):
        return f"{self.source}:{self.session}#{self.name}"


def load_scripts():
    for path in sorted(SCRIPT_DIR.glob("*.py")):
        yield [Script("scripts", path.stem, "1", path.read_text())]


PROMPT = re.compile(r"^(\s*)(>>>|\.\.\.) ?(.*)$")


def doc_transcripts(rst):
    """Each `>>>` run of an rst file, as the input lines only.

    Inside a literal block anything at or past the prompt's indentation is
    echoed output; only a dedent ends the transcript.
    """
    blocks = []
    cur = []
    indent = None
    for line in rst.splitlines():
        m = PROMPT.match(line)
        if m:
            if indent is None:
                indent = len(m.group(1))
            cur.append(m.group(3))
            continue
        if not cur:
            continue
        if not line.strip() or len(line) - len(line.lstrip()) >= indent:
            continue
        blocks.append("\n".join(cur))
        cur = []
        indent = None
    if cur:
        blocks.append("\n".join(cur))
    return blocks


def load_doc(scapy_src):
    docdir = Path(scapy_src) / "doc" / "scapy"
    for path in sorted(docdir.rglob("*.rst")):
        rel = str(path.relative_to(docdir))
        blocks = doc_transcripts(path.read_text(errors="replace"))
        session = [Script("doc", rel, str(i), b)
                   for i, b in enumerate(blocks, 1) if b.strip()]
        if session:
            yield session


def uts_files(scapy_src):
    test = Path(scapy_src) / "test"
    files = sorted(test.glob("*.uts")) + sorted((test / "scapy").glob("*.uts"))
    files += sorted((test / "scapy" / "layers").rglob("*.uts"))
    return [(f, str(f.relative_to(test))) for f in files]


def load_uts(scapy_src):
    for path, rel in uts_files(scapy_src):
        session = []
        for i, (campaign, name, kw, code) in enumerate(parse_uts(path), 1):
            if code.strip():
                session.append(Script("uts", rel, f"{i} {name[:50]}", code, kw))
        if session:
            yield session


def blocked(script):
    env = environment_block(script.keywords)
    if env:
        return env
    hit = set(IDENT.findall(script.code)) & FORBIDDEN
    if hit == {"sniff"} and SNIFF_OFFLINE.search(script.code):
        hit = set()
    if hit:
        return f"uses {sorted(hit)[0]}"
    called = set(re.findall(r"\.([A-Za-z_]\w*)\s*\(", script.code))
    called &= FORBIDDEN_METHODS
    if called:
        return f"calls .{sorted(called)[0]}()"
    if FORBIDDEN_CALLS.search(script.code):
        return "spawns a process or opens a socket"
    return None




class Side:
    """One of the three runs: a module supplying the names, and a namespace
    that persists across the blocks of a session."""

    def __init__(self, module, env):
        self.module = module
        self.ns = {k: getattr(module, k) for k in dir(module)
                   if not k.startswith("_")}
        self.ns.update(env)
        self.ns["__name__"] = "script_parity"
        self.ns["__builtins__"] = WIRY_BUILTINS if module is wiry else builtins
        self.seeded = set(self.ns)


class Step:
    def __init__(self):
        self.out = ""
        self.value = None
        self.has_value = False
        self.error = None
        self.lineno = None


class _WiryView(types.ModuleType):
    """`scapy.x.y` as the wiry run sees it: every attribute is wiry's.

    A name wiry lacks raises AttributeError, which `from scapy.x import name`
    turns into the ImportError a real missing name gives. A name that is one
    of scapy's own submodules resolves to another view, so `import
    scapy.layers.inet` and `scapy.layers.inet.IP` behave.
    """

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        if hasattr(wiry, name):
            return getattr(wiry, name)
        sub = f"{self.__name__}.{name}"
        if sub in sys.modules:
            return _WiryView(sub)
        raise AttributeError(f"module {self.__name__!r} has no attribute {name!r}")


def _wiry_import(name, globals=None, locals=None, fromlist=(), level=0):
    """`__import__` for the wiry run, at every depth a script imports from.

    Real scapy is loaded in this process as the oracle, so an unintercepted
    `from scapy.layers.inet import IP` anywhere in a script, including inside
    a function or a `try`, would hand scapy's own class to the wiry run.
    """
    if level == 0 and (name == "scapy" or name.startswith("scapy.")):
        return _WiryView(name if fromlist else "scapy")
    return builtins.__import__(name, globals, locals, fromlist, level)


WIRY_BUILTINS = dict(vars(builtins), __import__=_wiry_import)


def run_statement(side, node, ident):
    step = Step()
    out = io.StringIO()
    try:
        with deadline(TIMEOUT_SECONDS), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(io.StringIO()):
            if isinstance(node, ast.Expr):
                value = eval(compile(ast.Expression(node.value), ident, "eval"),
                             side.ns)
                side.ns["_"] = value
                step.value, step.has_value = value, value is not None
            else:
                exec(compile(ast.Module(body=[node], type_ignores=[]), ident,
                             "exec"), side.ns)
    except KeyboardInterrupt:
        raise
    except BaseException as exc:
        step.error = (type(exc).__name__, str(exc)[:300])
        for frame, lineno in traceback.walk_tb(exc.__traceback__):
            if frame.f_code.co_filename == ident:
                step.lineno = lineno
    step.out = out.getvalue()
    return step


def evaluate(side, node, ident):
    try:
        with deadline(TIMEOUT_SECONDS), contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            return True, eval(compile(ast.Expression(node), ident, "eval"), side.ns)
    except KeyboardInterrupt:
        raise
    except BaseException:
        return False, None


def stored_names(node):
    """Names a statement binds, and names whose object it mutates."""
    names, roots = set(), set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
            names.add(n.id)
        elif isinstance(n, (ast.Attribute, ast.Subscript)) and isinstance(
                n.ctx, (ast.Store, ast.Del)):
            root = n
            while isinstance(root, (ast.Attribute, ast.Subscript)):
                root = root.value
            if isinstance(root, ast.Name):
                roots.add(root.id)
    return names, roots - names




def is_packet(v):
    return hasattr(v, "summary") and hasattr(v, "show") and hasattr(v, "layers")


def is_packet_list(v):
    return (hasattr(v, "summary") and hasattr(v, "nsummary")
            and hasattr(v, "__getitem__") and not is_packet(v))


def captured(fn):
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            fn()
    except Exception as exc:
        return f"<{type(exc).__name__}: {exc}>"
    return buf.getvalue()


def layer_names(pkt):
    try:
        raw = pkt.layers()
    except Exception:
        return []
    return [x.__name__ if isinstance(x, type) else str(x) for x in raw]


def field_map(pkt):
    """Every field of every layer, keyed `Layer.field`.

    Keyed off `layers()`, not the Python class: wiry's layers are views onto
    one buffer and share a class.
    """
    out = {}
    names = layer_names(pkt)
    try:
        layers = list(pkt.iterpayloads())
    except Exception:
        layers = [pkt]
    for i, layer in enumerate(layers[:16]):
        cls = names[i] if i < len(names) else f"layer{i}"
        if names.count(cls) > 1:
            cls = f"{cls}#{i}"
        try:
            descs = list(layer.fields_desc)
        except Exception:
            descs = []
        for d in descs:
            fname = getattr(d, "name", None) or str(d)
            try:
                out[f"{cls}.{fname}"] = ADDR.sub("0xADDR",
                                                 repr(getattr(layer, fname)))
            except Exception as exc:
                out[f"{cls}.{fname}"] = f"<{type(exc).__name__}>"
    return out


def safe(fn):
    try:
        return ADDR.sub("0xADDR", fn())
    except Exception as exc:
        return f"<{type(exc).__name__}: {exc}>"


def canon(v, depth=0):
    with contextlib.redirect_stdout(io.StringIO()):
        return _canon(v, depth)


def _canon(v, depth):
    if depth > 3:
        return "<deep>"
    if isinstance(v, type) or isinstance(v, (type(len), type(canon))):
        return None
    if v is None or isinstance(v, (bool, int, float, str)):
        return repr(v)
    if isinstance(v, (bytes, bytearray)):
        return "hex:" + bytes(v).hex()
    if is_packet(v):
        return {
            "kind": "packet",
            "repr": safe(lambda: repr(v)),
            "summary": safe(v.summary),
            "show": safe(lambda: captured(v.show)),
            "bytes": safe(lambda: bytes(v).hex()),
            "layers": layer_names(v),
            "fields": field_map(v),
        }
    if is_packet_list(v):
        try:
            items = list(v)
        except Exception:
            items = []
        return {
            "kind": "plist",
            "repr": safe(lambda: repr(v)),
            "len": repr(len(items)),
            "items": [canon(x, depth + 1) for x in items[:25]],
        }
    if isinstance(v, (list, tuple, set, frozenset)):
        seq = sorted(v, key=repr) if isinstance(v, (set, frozenset)) else list(v)
        return [canon(x, depth + 1) for x in seq[:40]]
    if isinstance(v, dict):
        return {"kind": "dict", "items": {
            ADDR.sub("0xADDR", repr(k)): canon(x, depth + 1)
            for k, x in list(v.items())[:40]}}
    if callable(v) and not hasattr(v, "fields_desc"):
        return None
    return safe(lambda: repr(v))


# A cause is (key, instance). The key names a defect generically enough that
# every script hitting it lands in one bucket; the instance says where (a
# field, a layer, a name), so the ranked table can show what to fix first.

NUM = re.compile(r"-?\d+")
MAC_LIKE = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){2,}\b")
QUOTED = re.compile(r"(['\"]).*?\1")
CHAIN_ONLY = re.compile(r"^<\w+(?: / \w+)*>$")
PKT_REPR = re.compile(r"<\w[\w.]*  \w+=|<\w[\w.]* +\|")
SHOW_HEADER = re.compile(r"^[\s|]*###\[\s*(.+?)\s*\]###")
SHOW_FIELD = re.compile(r"^[\s|]*(\\?[\w.\[\]-]+\\?)\s*=\s?(.*)$")
HEX_LINE = re.compile(r"^[0-9a-fA-F]{4}  [0-9a-fA-F]{2} ")


def blur(text):
    text = MAC_LIKE.sub("<mac>", str(text))
    text = QUOTED.sub("<str>", text)
    text = re.sub(r"\b\d+(?:\.\d+){3}\b", "<ip>", text)
    text = re.sub(r"\b0x[0-9a-fA-F]+\b", "<hex>", text)
    text = re.sub(r"\b\d+\b", "<n>", text)
    return " ".join(text.split())[:70]


def fmt_kind(a, b):
    """How a rendered value differs, independent of which field it is."""
    a, b = a.strip(), b.strip()
    if a == b:
        return "spacing differs"
    if a == "None":
        return "unset value printed as computed"
    if b == "None":
        return "value printed as None"
    if a.lower().startswith("0x") and NUM.fullmatch(b):
        try:
            if int(a, 16) == int(b):
                return "hex value printed in decimal"
            return "value differs (and printed in decimal, scapy uses hex)"
        except ValueError:
            pass
    if NUM.fullmatch(b) and not NUM.fullmatch(a):
        return "enum or flag printed as a number"
    if NUM.fullmatch(a) and not NUM.fullmatch(b):
        return "number printed as a name"
    if a.startswith(("b'", 'b"')) and b.startswith("["):
        return "bytes printed as a list of integers"
    if a.startswith(("b'", 'b"')) != b.startswith(("b'", 'b"')):
        return "bytes and str rendered differently"
    if a.startswith("[") or b.startswith("["):
        return "list value rendered differently"
    if a.startswith("<") or b.startswith("<"):
        return "nested object rendered differently"
    return "value differs"


def parse_repr(text):
    """[(layer, {field: value})] from a scapy-style `<A  f=v |<B  ... |>>`."""
    text = text.strip()
    layers = []
    for seg in re.split(r"\s*\|<", text):
        seg = seg.lstrip("<").rstrip(">").rstrip()
        seg = re.sub(r"\s*\|$", "", seg)
        if not seg:
            continue
        name, _, rest = seg.partition(" ")
        fields = {}
        keys = list(re.finditer(r"(?:^|\s)([A-Za-z_]\w*)=", rest))
        for i, m in enumerate(keys):
            end = keys[i + 1].start() if i + 1 < len(keys) else len(rest)
            fields[m.group(1)] = rest[m.end():end].strip()
        layers.append((name, fields))
    return layers


def diff_repr(a, b, skip=()):
    if CHAIN_ONLY.match(b.strip()):
        return [("RENDER: repr() shows only the layer chain, no field values",
                 b.strip()[1:-1])]
    la, lb = parse_repr(a), parse_repr(b)
    causes = []
    for (na, fa), (nb, fb) in zip(la, lb):
        if na != nb:
            causes.append(("RENDER: repr() layer name differs", f"{nb} for {na}"))
            break
        for k in fa:
            if f"{na}.{k}" in skip:
                continue
            if k not in fb:
                causes.append(("RENDER: repr() omits a field scapy shows",
                               f"{na}.{k}"))
            elif fa[k] != fb[k]:
                causes.append((f"RENDER: repr() {fmt_kind(fa[k], fb[k])}",
                               f"{na}.{k}"))
        for k in fb:
            if k not in fa:
                causes.append(("RENDER: repr() shows a field scapy omits",
                               f"{nb}.{k}"))
    if len(la) != len(lb) and not causes:
        causes.append(("RENDER: repr() layer count differs", f"{len(lb)} vs {len(la)}"))
    if not causes:
        causes.append(("RENDER: repr() text differs", blur(a)))
    return causes


def parse_show(text):
    sections = []
    for line in text.splitlines():
        h = SHOW_HEADER.match(line)
        if h:
            sections.append((h.group(1), []))
            continue
        f = SHOW_FIELD.match(line)
        if f and sections:
            sections[-1][1].append((f.group(1).strip("\\"), f.group(2)))
    return sections


def diff_show(label, a, b, skip=()):
    if a.rstrip("\n") == b.rstrip("\n"):
        return [(f"RENDER: {label} trailing blank lines differ",
                 f"{a.count(chr(10)) - a.rstrip(chr(10)).count(chr(10))} "
                 f"vs {b.count(chr(10)) - b.rstrip(chr(10)).count(chr(10))}")]
    sa, sb = parse_show(a), parse_show(b)
    causes = []
    if not sa:
        return [(f"RENDER: {label} text differs", blur(first_diff(a, b)[0]))]
    for (ta, fa), (tb, fb) in zip(sa, sb):
        if ta != tb:
            causes.append((f"RENDER: {label} layer title differs",
                           f"'{tb}' for '{ta}'"))
        da, db = dict(fa), dict(fb)
        for k, v in fa:
            if f"{ta}.{k}" in skip:
                continue
            if k not in db:
                causes.append((f"RENDER: {label} omits a field scapy shows",
                               f"{ta}.{k}"))
            elif v != db[k]:
                causes.append((f"RENDER: {label} {fmt_kind(v, db[k])}",
                               f"{ta}.{k}"))
        for k, _ in fb:
            if k not in da:
                causes.append((f"RENDER: {label} shows a field scapy omits",
                               f"{ta}.{k}"))
        if [k for k, _ in fa if k in db] != [k for k, _ in fb if k in da]:
            causes.append((f"RENDER: {label} field order differs", ta))
    if len(sa) != len(sb):
        causes.append((f"RENDER: {label} layer count differs",
                       " / ".join(t for t, _ in sa)))
    if not causes:
        causes.append((f"RENDER: {label} layout differs",
                       blur(first_diff(a, b)[0])))
    return causes


def diff_summary(a, b):
    a, b = a.strip(), b.strip()
    sa, sb = a.split(" / "), b.split(" / ")
    if all(" " not in s for s in sb) and any(" " in s for s in sa):
        return [("RENDER: summary() has no per-layer text (mysummary)",
                 sb[min(len(sa), len(sb)) - 1])]
    for x, y in zip(sa, sb):
        if x != y:
            return [("RENDER: summary() of a layer differs", y.split(" ")[0])]
    return [("RENDER: summary() layer count differs", a.split(" ")[0])]


def first_diff(a, b):
    la, lb = a.splitlines(), b.splitlines()
    for i in range(max(len(la), len(lb))):
        x = la[i] if i < len(la) else None
        y = lb[i] if i < len(lb) else None
        if x != y:
            return x, y
    return None, None


def classify_line(label, x, y):
    if x is None:
        return [("RENDER: wiry prints lines scapy does not", label)]
    if y is None:
        return [("RENDER: wiry prints fewer lines than scapy", label)]
    if PKT_REPR.search(x):
        return diff_repr(x[x.index("<", PKT_REPR.search(x).start()):],
                         y[y.index("<"):] if "<" in y else y)
    if HEX_LINE.match(x):
        return [("RENDER: hexdump() differs", label)]
    if " / " in x and "=" not in x:
        return diff_summary(x, y)
    if x.strip() in ("True", "False"):
        return [("VALUE: a printed predicate differs", label)]
    tx, ty = x.split(), y.split()
    if len(tx) == len(ty):
        diffs = [(p, q) for p, q in zip(tx, ty) if p != q]
        if len(diffs) == 1:
            return [(f"RENDER: printed value: {fmt_kind(*diffs[0])}", label)]
    return [("RENDER: printed text differs", f"{label}: {blur(x)}")]


def classify_text(label, a, b, skip=()):
    if "###[" in a:
        return diff_show(label if label.endswith(")") else "show()", a, b, skip)
    la, lb = a.splitlines(), b.splitlines()
    if len(la) == len(lb):
        causes = []
        for x, y in zip(la, lb):
            if x != y:
                causes += classify_line(label, x, y)
            if len(causes) > 20:
                break
        return causes or [("RENDER: whitespace differs", label)]
    x, y = first_diff(a, b)
    return classify_line(label, x, y)


def diff_fields(fa, fw):
    causes, bad = [], set()
    for k in fa:
        if k not in fw:
            causes.append(("FIELD: a field scapy has is missing in wiry", k))
            bad.add(k)
            continue
        a, w = fa[k], fw[k]
        if a == w:
            continue
        bad.add(k)
        if w.startswith("<") and w.endswith("Error>"):
            causes.append(("FIELD: reading the field raises under wiry", k))
        elif a == "None":
            causes.append(("FIELD: unset field reads back computed (scapy: None)", k))
        elif w == "None":
            causes.append(("FIELD: field reads None where scapy has a value", k))
        elif a.strip("b'\"") == w.strip("b'\""):
            causes.append(("FIELD: bytes/str type of a field differs", k))
        elif NUM.fullmatch(a) and not NUM.fullmatch(w) or NUM.fullmatch(w) and not NUM.fullmatch(a):
            causes.append(("FIELD: field value has a different Python type", k))
        else:
            causes.append(("FIELD: field value differs", k))
    for k in fw:
        if k not in fa:
            causes.append(("FIELD: a field only wiry has", k))
    return causes, bad


RAISED = re.compile(r"^<(\w+(?:Error|Exception)): (.*)>$", re.S)


def diff_packet(label, a, w):
    m = RAISED.match(w["repr"])
    if m and not RAISED.match(a["repr"]):
        return [("EXC: building or printing the packet raises under wiry",
                 f"{m.group(1)}: {blur(m.group(2))}")]
    if a["layers"] != w["layers"]:
        for i in range(max(len(a["layers"]), len(w["layers"]))):
            x = a["layers"][i] if i < len(a["layers"]) else "-"
            y = w["layers"][i] if i < len(w["layers"]) else "-"
            if x == y:
                continue
            if x == "-":
                return [("DISSECT: wiry dissects a layer past where scapy stops",
                         f"{y} after {a['layers'][i - 1] if i else '-'}")]
            if x not in WIRY_LAYERS:
                return [("DISSECT: a layer scapy dissects is not in wiry", x)]
            if y == "Raw" or y == "-":
                return [("DISSECT: wiry stops early where scapy dissects further",
                         f"{x} after {a['layers'][i - 1] if i else 'nothing'}")]
            return [("DISSECT: layer chain differs", f"{y} where scapy has {x}")]
    causes, bad = diff_fields(a["fields"], w["fields"])
    if a["bytes"] != w["bytes"]:
        chain = "/".join(a["layers"]) or "?"
        if len(a["bytes"]) != len(w["bytes"]):
            causes.append(("BYTES: built packet has a different length", chain))
        else:
            causes.append(("BYTES: built packet has different content", chain))
    if a["summary"] != w["summary"]:
        causes += diff_summary(a["summary"], w["summary"])
    if a["repr"] != w["repr"]:
        causes += diff_repr(a["repr"], w["repr"], bad)
    if a["show"] != w["show"]:
        causes += diff_show("show()", a["show"], w["show"], bad)
    return causes


def unquote(c):
    if c.startswith(("'", '"')):
        try:
            return ast.literal_eval(c)
        except Exception:
            pass
    return c


def label_kind(label):
    m = re.search(r"\.?(\w+)\([^()]*\)$", label)
    return m.group(1) if m else ""


def classify_value(label, a, w, owner=None):
    """Causes of a difference between two canonical values.

    `owner` names the layer when `label` is an attribute read off a packet.
    """
    if type(a) is not type(w) or (isinstance(a, dict) and a["kind"] != w.get("kind")):
        def kind(c):
            return c["kind"] if isinstance(c, dict) else type(c).__name__
        if isinstance(a, dict) and a["kind"] == "packet" and isinstance(w, str):
            return [("VALUE: wiry returns a non-packet where scapy returns a packet",
                     blur(w))]
        return [("VALUE: result has a different type", f"{kind(w)} for {kind(a)}")]
    if isinstance(a, dict) and a["kind"] == "packet":
        return diff_packet(label, a, w)
    if isinstance(a, dict) and a["kind"] == "plist":
        causes = []
        if a["repr"] != w["repr"]:
            causes.append(("RENDER: PacketList repr() differs", blur(a["repr"])))
        if a["len"] != w["len"]:
            causes.append(("VALUE: packet list has a different length", label))
        for x, y in zip(a["items"], w["items"]):
            if x != y:
                causes += classify_value(f"{label}[i]", x, y)
        return causes
    if isinstance(a, dict):
        if set(a["items"]) != set(w["items"]):
            return [("VALUE: dict has different keys", label)]
        causes = []
        for k in a["items"]:
            if a["items"][k] != w["items"][k]:
                causes += classify_value(f"{label}[{k}]", a["items"][k], w["items"][k])
        return causes
    if isinstance(a, list):
        if len(a) != len(w):
            return [("VALUE: list has a different length", label)]
        causes = []
        for x, y in zip(a, w):
            if x != y:
                causes += classify_value(f"{label}[i]", x, y)
        return causes
    if a.startswith("hex:") and w.startswith("hex:"):
        return [("BYTES: a bytes value differs", label)]
    kind = label_kind(label)
    if a.startswith(("'", '"')) and w.startswith(("'", '"')):
        ta, tw = unquote(a), unquote(w)
        if kind == "summary":
            return diff_summary(ta, tw)
        if kind in ("sprintf", "hexdump", "ls", "repr", "show", "command",
                    "json", "mysummary", "nsummary", "hexstr", "linehexdump"):
            if kind == "repr":
                return diff_repr(ta, tw)
            if kind == "show":
                return diff_show("show(dump=True)", ta, tw)
            return [(f"RENDER: {kind}() differs", label)]
        return classify_text(f"str {label}", ta, tw)
    if a in ("True", "False"):
        return [("VALUE: a predicate differs", blur(label))]
    if owner:
        return [(f"FIELD: field reads back differently ({fmt_kind(a, w)})",
                 f"{owner}.{label.rsplit('.', 1)[1]}")]
    return [(f"VALUE: {fmt_kind(a, w)}", blur(label))]


def scapy_module_of(name):
    obj = getattr(scapy, name, None)
    if obj is None:
        return None
    if isinstance(obj, type(scapy)):
        mod = obj.__name__
    else:
        mod = getattr(obj, "__module__", None) or type(obj).__module__
    return mod


def module_group(mod):
    if not mod or not mod.startswith("scapy"):
        return "stdlib names scapy.all re-exports"
    parts = mod.split(".")
    if len(parts) > 2 and parts[1] in ("layers", "asn1", "arch", "modules",
                                       "libs", "contrib"):
        if parts[1] == "layers" and len(parts) > 3:
            return ".".join(parts[:3])
        return ".".join(parts[:3]) if parts[1] == "layers" else ".".join(parts[:2])
    return ".".join(parts[:2])


OWNER = {"_LayerView": "Packet", "Packet": "Packet", "PacketList": "PacketList",
         "_PacketListView": "PacketList", "Conf": "conf", "_Conf": "conf",
         "module": "a module"}


BUILTIN_TYPES = {"bytes", "str", "int", "list", "tuple", "dict", "NoneType",
                 "float", "bool", "set"}


def classify_error(script, a_ns, a_err, w_err, w_side):
    """Causes when wiry raised and scapy did not. Returns None for a cascade."""
    kind, msg = w_err
    if kind in ("NameError", "UnboundLocalError"):
        m = re.search(r"'([\w.]+)'", msg)
        name = m.group(1) if m else "?"
        if name not in SCAPY_NAMES and name in a_ns:
            return None
        if name in SCAPY_NAMES:
            return [(f"API: names missing from {module_group(scapy_module_of(name))}",
                     name)]
        return [("API: a name scapy binds is missing from wiry", name)]
    if kind == "ImportError":
        m = re.search(r"name '([\w.]+)' from '([\w.]+)'", msg)
        if m:
            mod = scapy_module_of(m.group(1)) or m.group(2)
            return [(f"API: names missing from {module_group(mod)}", m.group(1))]
        return [("API: import fails under wiry", blur(msg))]
    if kind == "AttributeError":
        m = re.search(r"'(\w+)' object has no attribute '(\w+)'", msg)
        if m and m.group(1) in BUILTIN_TYPES:
            return [(f"VALUE: wiry returns a {m.group(1)} where scapy returns an "
                     "object", m.group(2))]
        if m:
            owner = OWNER.get(m.group(1), m.group(1))
            cls = getattr(scapy, owner, None)
            if owner in WIRY_LAYERS or (isinstance(cls, type)
                                        and issubclass(cls, scapy.Packet)):
                owner = "Packet"
            return [(f"API: {owner} lacks an attribute scapy has", m.group(2))]
        m = re.search(r"module '([\w.]+)' has no attribute '(\w+)'", msg)
        if m:
            return [("API: scapy submodule paths do not resolve under wiry",
                     f"{m.group(1)}.{m.group(2)}")]
        m = re.search(r"type object '(\w+)' has no attribute '(\w+)'", msg)
        if m:
            return [("API: a layer class lacks a class attribute scapy has",
                     f"{m.group(1)}.{m.group(2)}")]
        m = re.search(r"no field '(\w+)'|has no field '(\w+)'", msg)
        if m:
            return [("API: Packet lacks a field or attribute scapy has",
                     m.group(1) or m.group(2))]
        return [("API: AttributeError under wiry", blur(msg))]
    if kind == "AssertionError":
        return None  # dug into by the caller
    if kind == "TypeError":
        return [("API: TypeError under wiry (signature or type differs)", blur(msg))]
    if kind == "NotImplementedError":
        return [("API: wiry refuses by design (NotImplementedError)", blur(msg))]
    if kind == "Timeout":
        return [("EXC: wiry exceeds the time limit", script.ident)]
    return [(f"EXC: wiry raises {kind} where scapy succeeds", blur(msg))]




ENV_ERRORS = ("permission denied", "/dev/bpf", "operation not permitted",
              "no such device", "sudo", "network is unreachable",
              "no module named", "install cryptography", "need to install")


def environmental(error):
    kind, msg = error
    if kind in ("ModuleNotFoundError",) or kind == "Timeout":
        return True
    low = msg.lower()
    return any(w in low for w in ENV_ERRORS)


class Result:
    def __init__(self, script):
        self.script = script
        self.verdict = "pass"
        self.reason = ""
        self.causes = []
        self.detail = []

    def add(self, causes, what, theirs, mine):
        self.causes += causes
        self.detail.append((what, theirs, mine))


def find_node(tree, lineno, cls):
    for n in ast.walk(tree):
        if isinstance(n, cls) and getattr(n, "lineno", None) == lineno:
            return n
    return None


def operands(node):
    """Sub-expressions worth evaluating to explain why `node` differs."""
    if isinstance(node, ast.Compare):
        return [node.left] + node.comparators
    if isinstance(node, ast.BoolOp):
        return node.values
    if isinstance(node, ast.UnaryOp):
        return [node.operand]
    if isinstance(node, ast.Call):
        args = list(node.args)
        if isinstance(node.func, ast.Name) and node.func.id in ("raw", "bytes",
                                                                 "len", "str"):
            return args
        return args
    return []


def packet_owner(side, node, ident):
    """The layer an attribute expression reads from, if it reads a packet."""
    if not isinstance(node, ast.Attribute):
        return None
    ok, base = evaluate(side, node.value, ident)
    if not ok or not is_packet(base):
        return None
    names = layer_names(base)
    return names[0] if names else None


def dig(node, sides, code, ident, depth=0):
    """Explain a differing expression by its first differing operand."""
    a, _, w = sides
    if depth < 4:
        for sub in operands(node):
            ok_a, va = evaluate(a, sub, ident)
            ok_w, vw = evaluate(w, sub, ident)
            if not ok_a:
                continue
            label = ast.get_source_segment(code, sub) or ast.dump(sub)[:40]
            if not ok_w:
                return [("EXC: a sub-expression raises under wiry only", blur(label))]
            if (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name)
                    and sub.func.id in ("raw", "bytes") and sub.args):
                ok_pa, pa = evaluate(a, sub.args[0], ident)
                ok_pw, pw = evaluate(w, sub.args[0], ident)
                if ok_pa and ok_pw and is_packet(pa) and is_packet(pw):
                    ca, cw = canon(pa), canon(pw)
                    if ca != cw:
                        return classify_value(label, ca, cw)
            ca, cw = canon(va), canon(vw)
            if ca != cw:
                deeper = dig(sub, sides, code, ident, depth + 1)
                return deeper or classify_value(label, ca, cw,
                                                packet_owner(a, sub, ident))
    return []


def stdout_causes(node, sides, code, ident, out_a, out_w):
    """Causes of a statement printing differently."""
    a, _, w = sides
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
        call = node.value
        fn = call.func
        if isinstance(fn, ast.Name) and fn.id == "print":
            for arg in call.args:
                ok_a, va = evaluate(a, arg, ident)
                ok_w, vw = evaluate(w, arg, ident)
                if not (ok_a and ok_w):
                    continue
                label = ast.get_source_segment(code, arg) or "print argument"
                ca, cw = canon(va), canon(vw)
                if ca != cw:
                    if is_packet(va):
                        sa, sw = str(va), str(vw)
                        if sa != sw and not isinstance(ca, dict):
                            return classify_text(f"str({label})", sa, sw)
                    return classify_value(label, ca, cw)
                try:
                    sa, sw = str(va), str(vw)
                except Exception:
                    continue
                if sa != sw:
                    if is_packet(va):
                        return [("RENDER: str(packet) differs", "/".join(layer_names(va)))]
                    return classify_text(f"str({label})", sa, sw)
        name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
        if name in ("show", "show2", "display"):
            return diff_show(f"{name}()", out_a, out_w)
        if name:
            return classify_text(f"{name}()", out_a, out_w)
    return classify_text("printed output", out_a, out_w)


def run_block(script, sides):
    """Execute one block on all three sides in lockstep and judge it."""
    r = Result(script)
    a, b, w = sides
    why = blocked(script)
    if why:
        r.verdict, r.reason = "skip", why
        return r
    try:
        tree = ast.parse(script.code, filename=script.ident)
    except SyntaxError:
        r.verdict, r.reason = "skip", "not valid Python 3"
        return r

    code = script.code
    judging = True
    judged = 0
    w_alive = True
    cascade = False
    unfinished = False
    for node in tree.body:
        sa = run_statement(a, node, script.ident)
        sb = run_statement(b, node, script.ident)
        sw = run_statement(w, node, script.ident) if w_alive else None
        if not judging:
            if sa.error:
                break
            continue

        if sa.error or sb.error:
            judging = False
            if (sa.error or ("", ""))[0] != (sb.error or ("", ""))[0]:
                r.reason = r.reason or "scapy is not deterministic here"
                unfinished = True
                break
            if environmental(sa.error):
                r.reason = r.reason or f"scapy needs its environment ({sa.error[0]})"
                unfinished = True
                break
            if sa.error[0] in ("NameError", "Scapy_Exception", "ImportError") or \
                    script.source == "uts":
                r.reason = r.reason or f"scapy 2.7.0 fails here ({sa.error[0]})"
                unfinished = True
                break
            judged += 1
            if sw is None:
                break
            if sw.error is None:
                r.add([("EXC: scapy raises, wiry succeeds",
                        f"{sa.error[0]}: {blur(sa.error[1])}")],
                      "error", repr(sa.error), "no exception")
            elif sw.error[0] != sa.error[0]:
                causes = None
                if sw.error[0] in ("NameError", "ImportError", "AttributeError",
                                   "TypeError"):
                    causes = classify_error(script, a.ns, sa.error, sw.error, w)
                r.add(causes or [("EXC: wiry raises a different exception",
                                  f"{sw.error[0]} for {sa.error[0]}")],
                      "error", repr(sa.error), repr(sw.error))
            elif sw.error[1] != sa.error[1]:
                r.add([("EXC-MSG: same exception, different message", sa.error[0])],
                      "error", repr(sa.error), repr(sw.error))
            break

        if sw is None:
            break
        judged += 1
        if sw.error:
            w_alive = False
            judging = False
            causes = classify_error(script, a.ns, sa.error, sw.error, w)
            if causes is None and sw.error[0] == "AssertionError":
                target = node if isinstance(node, ast.Assert) else (
                    find_node(node, sw.lineno, ast.Assert) if sw.lineno else None)
                causes = []
                if target is not None:
                    causes = dig(target.test, sides, code, script.ident)
                causes = causes or [("BEHAVIOUR: assertion holds under scapy, "
                                     "fails under wiry",
                                     blur(ast.get_source_segment(code, target)
                                          if target else script.name))]
            if causes is None:
                cascade = True
                continue
            r.add(causes, "error", "no exception", repr(sw.error))
            continue

        if sa.out == sb.out and sa.out != sw.out:
            r.add(stdout_causes(node, sides, code, script.ident, sa.out, sw.out),
                  "stdout", sa.out, sw.out)
        if sa.has_value or sw.has_value:
            ca, cb = canon(sa.value), canon(sb.value)
            if ca == cb:
                cw = canon(sw.value)
                if ca != cw:
                    label = ast.get_source_segment(code, node) or "expression"
                    causes = dig(node.value, sides, code, script.ident)
                    owner = packet_owner(a, node.value, script.ident)
                    r.add(causes or classify_value(label, ca, cw, owner),
                          f"value of {label[:60]}", repr(ca)[:600], repr(cw)[:600])
        bound, mutated = stored_names(node)
        for name in sorted(bound | mutated):
            if name not in a.ns or name not in b.ns:
                continue
            if name in mutated and not (is_packet(a.ns[name]) or is_packet_list(
                    a.ns[name]) or isinstance(a.ns[name], (list, dict))):
                continue
            ca, cb = canon(a.ns[name]), canon(b.ns[name])
            if ca != cb or ca is None:
                continue
            if name not in w.ns:
                r.add([("VALUE: a name is left unbound under wiry", name)],
                      name, "bound", "unbound")
                continue
            cw = canon(w.ns[name])
            if ca != cw:
                r.add(classify_value(name, ca, cw), name, repr(ca)[:600], repr(cw)[:600])

    if r.causes:
        r.verdict = "differ"
        r.causes = list(dict.fromkeys(r.causes))
    elif cascade:
        r.verdict = "cascade"
    elif not judged or unfinished:
        r.verdict = "skip"
        r.reason = r.reason or "nothing comparable"
    return r


def utscapy_session(sides, root):
    """What UTscapy puts in a campaign's namespace beyond `scapy.all`, on
    each side. `scapy_path` resolves against the checkout on both, since the
    installed scapy ships no test captures."""
    a, b, w = sides
    for side in (a, b):
        import_UTscapy_tools(side.ns)
        side.ns["scapy_path"] = lambda f: str(Path(root) / f.lstrip("/"))
    w.ns.update(scapy_suite.utscapy_tools(Path(root)))
    w.ns.update({m: importlib.import_module(m)
                 for m in scapy_suite._SCAPY_ALL_STDLIB})
    for side in sides:
        side.seeded |= set(side.ns)


def run_session(blocks, env):
    sides = (Side(scapy, env), Side(scapy, env), Side(wiry, env))
    if blocks[0].source == "uts":
        utscapy_session(sides, SCAPY_SRC)
    results = []
    for script in blocks:
        try:
            results.append(run_block(script, sides))
        except KeyboardInterrupt:
            raise
        except Exception:
            r = Result(script)
            r.verdict, r.reason = "skip", "harness error"
            r.detail.append(("harness", traceback.format_exc(), ""))
            results.append(r)
    return results


def _session_child(conn, blocks, env, scapy_src):
    global SCAPY_SRC
    SCAPY_SRC = scapy_src
    configure_oracle()
    os.chdir(env["WORKDIR"])
    # One scapy 2.7.0 test allocates without bound in a loop, and a full
    # collection over that runs inside C where the per-statement alarm cannot
    # fire. The process lives for one session, so nothing is lost.
    gc.disable()
    conn.send(run_session(blocks, env))
    conn.close()


def run_isolated(sessions, env, jobs, scapy_src):
    """Run each session in a freshly spawned interpreter, `jobs` at a time.

    scapy keeps layer bindings and `conf` process-wide, so a `.uts` file that
    imports a layer module or calls `bind_layers` would change what scapy
    dissects for every session after it. Spawned rather than forked: a fork
    from a process holding scapy's and libpcap's threads can inherit a held
    lock and hang.
    """
    ctx = multiprocessing.get_context("spawn")
    out = {}
    queue = list(enumerate(sessions))
    running = {}

    def failed(i, why):
        rows = []
        for s in sessions[i]:
            r = Result(s)
            r.verdict, r.reason = "skip", f"session {why}"
            rows.append(r)
        out[i] = rows

    while queue or running:
        while queue and len(running) < jobs:
            i, blocks = queue.pop(0)
            parent, child = ctx.Pipe(duplex=False)
            proc = ctx.Process(target=_session_child,
                               args=(child, blocks, env, scapy_src))
            proc.start()
            child.close()
            running[parent] = (i, proc, time.monotonic())
        ready = multiprocessing.connection.wait(list(running), timeout=5)
        for conn in ready:
            i, proc, _ = running.pop(conn)
            try:
                out[i] = conn.recv()
            except (EOFError, OSError):
                failed(i, f"crashed (exit {proc.exitcode})")
            proc.join(5)
            proc.kill()
        for conn, (i, proc, started) in list(running.items()):
            if time.monotonic() - started > SESSION_TIMEOUT:
                print(f"  {sessions[i][0].session}: over {SESSION_TIMEOUT}s, "
                      "abandoned", file=sys.stderr)
                proc.kill()
                running.pop(conn)
                failed(i, "exceeded the session time limit")
    return [r for i in sorted(out) for r in out[i]]


def build_fixture(workdir, real_pcap):
    """A capture both runs read, written by scapy so neither side authored it."""
    path = Path(workdir) / "capture.pcap"
    ether = {"dst": "00:11:22:33:44:55", "src": "66:77:88:99:aa:bb"}
    s = scapy
    pkts = [
        s.Ether(**ether) / s.IP(src="10.0.0.1", dst="10.0.0.2")
        / s.TCP(sport=1234, dport=80, flags="S", seq=1000),
        s.Ether(dst="66:77:88:99:aa:bb", src="00:11:22:33:44:55")
        / s.IP(src="10.0.0.2", dst="10.0.0.1")
        / s.TCP(sport=80, dport=1234, flags="SA", seq=5000, ack=1001),
        s.Ether(**ether) / s.IP(src="10.0.0.1", dst="10.0.0.2")
        / s.TCP(sport=1234, dport=80, flags="PA", seq=1001, ack=5001)
        / s.Raw(load=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        s.Ether(**ether) / s.IP(src="10.0.0.3", dst="8.8.8.8")
        / s.UDP(sport=33333, dport=53)
        / s.DNS(rd=1, qd=s.DNSQR(qname="example.com")),
        s.Ether(**ether) / s.IP(src="8.8.8.8", dst="10.0.0.3")
        / s.UDP(sport=53, dport=33333)
        / s.DNS(qr=1, qd=s.DNSQR(qname="example.com"),
                an=s.DNSRR(rrname="example.com", rdata="93.184.216.34")),
        s.Ether(**ether) / s.ARP(op=1, psrc="10.0.0.1", pdst="10.0.0.7"),
        s.Ether(**ether) / s.IP(src="10.0.0.1", dst="10.0.0.9") / s.ICMP(),
        s.Ether(**ether) / s.IPv6(src="2001:db8::1", dst="2001:db8::2")
        / s.TCP(sport=4444, dport=443, flags="S"),
        s.Ether(**ether) / s.Dot1Q(vlan=42) / s.IP(src="10.0.0.4", dst="10.0.0.5")
        / s.UDP(sport=5000, dport=6000) / s.Raw(load=b"vlan payload"),
        s.Ether(**ether) / s.IP(src="10.0.0.1", dst="10.0.0.2")
        / s.TCP(sport=1234, dport=80, flags="FA", seq=1050, ack=5001),
    ]
    for i, p in enumerate(pkts):
        p.time = 1700000000 + i
    s.wrpcap(str(path), pkts)

    env = {"PCAP": str(path), "WORKDIR": str(workdir), "REAL_PCAP": None}
    if real_pcap and Path(real_pcap).exists():
        slice_path = Path(workdir) / "real.pcap"
        s.wrpcap(str(slice_path), s.rdpcap(real_pcap, count=200))
        env["REAL_PCAP"] = str(slice_path)
    return env



def area_of(key):
    """Which of the parallel workstreams a cause belongs to."""
    kind = key.split(":")[0]
    if kind == "RENDER":
        return "rendering"
    if kind in ("DISSECT", "FIELD", "BYTES"):
        return "layers"
    if kind != "API":
        return "behaviour"
    low = key.lower()
    if any(n in low for n in ("asn1", "snmp", "x509", "ber")):
        return "asn1"
    if "tls" in low:
        return "tls"
    if "layers" in low or "packet lacks" in low or "layer class" in low:
        return "layers"
    return "utilities"


def tally(results):
    ranked = {}
    for r in results:
        keys = dict.fromkeys(k for k, _ in r.causes)
        for key in keys:
            row = ranked.setdefault(key, {"scripts": [], "sessions": set(),
                                          "sole": 0, "instances": {}})
            row["scripts"].append(r.script.ident)
            row["sessions"].add(f"{r.script.source}:{r.script.session}")
            if len(keys) == 1:
                row["sole"] += 1
        for key, inst in dict.fromkeys(r.causes):
            inst_row = ranked[key]["instances"]
            inst_row[inst] = inst_row.get(inst, 0) + 1
    return sorted(ranked.items(), key=lambda kv: (-len(kv[1]["scripts"]), kv[0]))


def corpus_table(results):
    rows = {}
    for r in results:
        row = rows.setdefault(r.script.source, {"pass": 0, "differ": 0,
                                                "cascade": 0, "skip": 0,
                                                "sessions": set()})
        row[r.verdict] += 1
        row["sessions"].add(r.script.session)
    out = []
    total = {"pass": 0, "differ": 0, "cascade": 0, "skip": 0, "sessions": 0}
    for source in ("scripts", "doc", "uts"):
        if source not in rows:
            continue
        row = rows[source]
        out.append((source, len(row["sessions"]), row))
        for k in ("pass", "differ", "cascade", "skip"):
            total[k] += row[k]
        total["sessions"] += len(row["sessions"])
    return out, total


def rate(row):
    judged = row["pass"] + row["differ"] + row["cascade"]
    return (f"{100 * row['pass'] / judged:.1f}%" if judged else "-"), judged


def top_instances(row, n=6):
    items = sorted(row["instances"].items(), key=lambda kv: (-kv[1], kv[0]))
    shown = ", ".join(f"{k} ({v})" if v > 1 else k for k, v in items[:n])
    if len(items) > n:
        shown += f", +{len(items) - n} more"
    return shown


def print_report(results, causes_shown):
    rows, total = corpus_table(results)
    print(f"\n=== script parity: wiry vs scapy {SCAPY_VERSION} ===\n")
    head = (f"{'corpus':<10}{'sessions':>9}{'scripts':>8}{'pass':>7}"
            f"{'differ':>8}{'cascade':>9}{'skip':>7}{'rate':>8}")
    print(head)
    for source, nsess, row in rows:
        n = sum(row[k] for k in ("pass", "differ", "cascade", "skip"))
        print(f"{source:<10}{nsess:>9}{n:>8}{row['pass']:>7}{row['differ']:>8}"
              f"{row['cascade']:>9}{row['skip']:>7}{rate(row)[0]:>8}")
    print("-" * len(head))
    n = sum(total[k] for k in ("pass", "differ", "cascade", "skip"))
    pct, judged = rate(total)
    print(f"{'TOTAL':<10}{total['sessions']:>9}{n:>8}{total['pass']:>7}"
          f"{total['differ']:>8}{total['cascade']:>9}{total['skip']:>7}{pct:>8}")
    print(f"\n{judged} scripts judged, {total['pass']} identical to scapy ({pct})")

    ranked = tally(results)
    if ranked:
        print(f"\n=== causes, ranked by scripts broken ({len(ranked)} causes) ===")
        print("    sole = scripts this cause alone keeps from passing\n")
        print(f"{'scripts':>8}{'sole':>6}  {'area':<10} cause")
        for key, row in ranked[:causes_shown]:
            print(f"{len(row['scripts']):>8}{row['sole']:>6}  "
                  f"{area_of(key):<10} {key}")
            print(f"{'':>26}{top_instances(row, 4)[:110]}")
        if len(ranked) > causes_shown:
            print(f"\n  ... {len(ranked) - causes_shown} further causes "
                  f"(--causes N to see more)")

    skips = {}
    for r in results:
        if r.verdict == "skip":
            skips[r.reason] = skips.get(r.reason, 0) + 1
    if skips:
        print("\n=== not judged ===\n")
        for why, count in sorted(skips.items(), key=lambda kv: -kv[1])[:15]:
            print(f"{count:>8}  {why}")


def git_head():
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                              capture_output=True, text=True,
                              cwd=Path(__file__).parent).stdout.strip()
    except Exception:
        return "?"


def md_escape(text):
    return str(text).replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")


GENERATED = "<!-- everything below is generated by dev/script_parity.py -->"


def write_markdown(path, results, args):
    """Write the tables below GENERATED, keeping whatever a person wrote above
    it in an existing report."""
    rows, total = corpus_table(results)
    ranked = tally(results)
    head = "# Script parity: wiry against scapy\n\n"
    with contextlib.suppress(OSError):
        old = Path(path).read_text()
        if GENERATED in old:
            head = old[:old.index(GENERATED)]
    lines = [
        GENERATED,
        "",
        f"Generated by `dev/script_parity.py` on {datetime.date.today()} at wiry "
        f"`{git_head()}`, scapy {SCAPY_VERSION} as the oracle, scapy master "
        f"checkout at `{args.scapy_src}` for the doc and `.uts` corpora. "
        "Regenerate with `python dev/script_parity.py --report "
        "dev/script_parity_report.md`.",
        "",
        "A *script* is one idiomatic program, one doc transcript, or one `.uts` "
        "test block. `cascade` means wiry failed only because an earlier block in "
        "the same session failed under wiry; those count against the rate and are "
        "not ranked.",
        "",
        "| corpus | sessions | scripts | pass | differ | cascade | skip | rate |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for source, nsess, row in rows:
        n = sum(row[k] for k in ("pass", "differ", "cascade", "skip"))
        lines.append(f"| {source} | {nsess} | {n} | {row['pass']} | {row['differ']} "
                     f"| {row['cascade']} | {row['skip']} | {rate(row)[0]} |")
    n = sum(total[k] for k in ("pass", "differ", "cascade", "skip"))
    lines.append(f"| **total** | {total['sessions']} | {n} | {total['pass']} | "
                 f"{total['differ']} | {total['cascade']} | {total['skip']} | "
                 f"{rate(total)[0]} |")

    areas = {}
    for key, row in ranked:
        area = area_of(key)
        areas.setdefault(area, set()).update(row["scripts"])
    lines += ["", "## Scripts broken, by owning area", "",
              "A script broken by causes in two areas counts in both.", "",
              "| area | scripts |", "|---|---:|"]
    for area, idents in sorted(areas.items(), key=lambda kv: -len(kv[1])):
        lines.append(f"| {area} | {len(idents)} |")

    lines += ["", "## Causes, ranked by scripts broken", "",
              "`sole`: scripts this cause alone keeps from passing. `cumulative`: "
              "scripts that would pass with this row and every row above it "
              "fixed, on top of today's passes. A cascade is counted as passing "
              "once its session's other causes are gone, which is optimistic.", "",
              "| # | scripts | sole | cumulative | sessions | area | cause | "
              "where (scripts) |",
              "|---:|---:|---:|---:|---:|---|---|---|"]
    keys_by_script = [set(k for k, _ in r.causes) for r in results
                      if r.verdict == "differ"]
    fixed = set()
    for i, (key, row) in enumerate(ranked, 1):
        fixed.add(key)
        cumulative = total["pass"] + sum(1 for ks in keys_by_script if ks <= fixed)
        lines.append(f"| {i} | {len(row['scripts'])} | {row['sole']} | "
                     f"{cumulative} | {len(row['sessions'])} | {area_of(key)} | "
                     f"{md_escape(key)} | {md_escape(top_instances(row, 8))} |")

    skips = {}
    for r in results:
        if r.verdict == "skip":
            skips[r.reason] = skips.get(r.reason, 0) + 1
    lines += ["", "## Not judged", "", "| scripts | reason |", "|---:|---|"]
    for why, count in sorted(skips.items(), key=lambda kv: -kv[1])[:25]:
        lines.append(f"| {count} | {md_escape(why)} |")
    Path(path).write_text(head + "\n".join(lines) + "\n")


def show_one(results, ident):
    for r in results:
        if ident in (r.script.ident, f"{r.script.session}#{r.script.name}") or \
                r.script.ident.startswith(ident):
            print(f"=== {r.script.ident} [{r.verdict}] {r.reason}")
            print("--- code ---")
            print(r.script.code)
            for key, inst in r.causes:
                print(f"--- cause: {key} [{inst}]")
            for what, theirs, mine in r.detail:
                print(f"--- {what}: scapy ---\n{theirs}")
                print(f"--- {what}: wiry ---\n{mine}")
            print()


@contextlib.contextmanager
def quiet_fd2():
    """Silence stderr at the descriptor: tcpdump, which scapy runs to compile
    BPF, and threads scapy starts both write there directly."""
    saved = os.dup(2)
    devnull = os.open(os.devnull, os.O_WRONLY)
    os.dup2(devnull, 2)
    try:
        yield
    finally:
        os.dup2(saved, 2)
        os.close(saved)
        os.close(devnull)


def configure_oracle():
    scapy_conf.verb = 0
    logging.getLogger("scapy").setLevel(logging.CRITICAL)
    threading.excepthook = lambda _args: None
    # Unprivileged, scapy cannot ARP for a destination MAC and raises out of
    # build(). Broadcast is its own fallback, so this pins the oracle rather
    # than changing what it says.
    scapy_conf.neighbor.resolve = lambda l2, l3: "ff:ff:ff:ff:ff:ff"
    for prog in ("display", "pdfreader", "psreader", "svgreader", "hexedit",
                 "universal_open", "wireshark", "sox", "dot"):
        with contextlib.suppress(Exception):
            setattr(scapy_conf.prog, prog, "/usr/bin/true")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scapy-src", default="/tmp/scapy-src")
    ap.add_argument("--source", default="all",
                    choices=("all", "scripts", "doc", "uts"))
    ap.add_argument("--only", default="")
    ap.add_argument("--pcap", default="")
    ap.add_argument("--causes", type=int, default=40)
    ap.add_argument("--show", default="")
    ap.add_argument("--report", default="")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    args = ap.parse_args()

    configure_oracle()
    global SCAPY_SRC
    SCAPY_SRC = args.scapy_src

    workdir = tempfile.mkdtemp(prefix="script-parity-")
    env = build_fixture(workdir, args.pcap)
    report_path = Path(args.report).resolve() if args.report else None
    os.chdir(workdir)

    sessions = []
    if args.source in ("all", "scripts"):
        sessions += list(load_scripts())
    if args.source in ("all", "doc"):
        sessions += list(load_doc(args.scapy_src))
    if args.source in ("all", "uts"):
        sessions += list(load_uts(args.scapy_src))
    if args.only:
        sessions = [s for s in sessions if args.only in s[0].session]

    results = []
    runnable = []
    for blocks in sessions:
        if blocks[0].source == "scripts" and "REAL_PCAP" in blocks[0].code \
                and not env["REAL_PCAP"]:
            for s in blocks:
                r = Result(s)
                r.verdict, r.reason = "skip", "needs --pcap"
                results.append(r)
            continue
        runnable.append(blocks)
    with quiet_fd2():
        results += run_isolated(runnable, env, args.jobs, args.scapy_src)

    if args.show:
        show_one(results, args.show)
        return 0
    print_report(results, args.causes)
    if report_path:
        write_markdown(report_path, results, args)
        print(f"\nwrote {report_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
