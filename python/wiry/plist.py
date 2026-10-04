# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from scapy: scapy/plist.py, and PacketList.timeskew_graph from
#   scapy/layers/inet.py
#   scapy 2.7.0
#   Copyright (C) Philippe Biondi <phil@secdev.org>
#   Copyright (C) the scapy contributors
#
# Changed by the wiry authors:
#   2026-10-03 — a list is held in one of two ways: a capture stays one Rust
#                buffer plus an index, and a list built from packets is a
#                Python list as scapy's is. Bulk operations over the second
#                assemble a Rust capture from it in one crossing.

"""Lists of packets, and lists of query/answer pairs."""

from __future__ import annotations

from typing import Any, Callable, Dict, Iterator, List, NamedTuple, Optional, Tuple

from . import Packet, _b, _layer_name, _LAYERS, _LINKTYPE_OF
from .utils import _as_args, do_graph, hexdump, make_lined_table, make_table, make_tex_table

__all__ = ["PacketList", "SndRcvList", "QueryAnswer"]


class QueryAnswer(NamedTuple):
    query: Any
    answer: Any


# What a list delegates to its Python list, as scapy's does through
# ``__getattr__``. Named, so that a probe like ``hasattr(pl, "x")`` does not
# turn a capture into a million Python objects.
_LIST_READS = frozenset({"count", "index", "copy"})


def _is_layer(x: Any) -> bool:
    return isinstance(x, type) and issubclass(x, Packet) and x._name is not None


def _conf() -> Any:
    from .capture import conf
    return conf


def _frames(pkts: List[Any]) -> Any:
    """A Rust capture holding these packets, for the operations that run over
    one. One link type has to cover them all, as it does in a pcap file."""
    links = set()
    frames = []
    for p in pkts:
        names = p.layers() if isinstance(p, Packet) else []
        links.add(_LINKTYPE_OF.get(names[0]) if names else None)
        frames.append((bytes(p), float(getattr(p, "time", 0) or 0),
                       int(getattr(p, "wirelen", 0) or 0)))
    if len(links) > 1 or None in links:
        raise ValueError(
            "this needs every packet in the list to start with the same link "
            "layer (Ether, IP, IPv6, Loopback, CookedLinux); a list mixing "
            "them has no one link type to read them as"
        )
    return _b.PktList.from_frames(frames, links.pop() if links else 1)


def _plt() -> Tuple[Any, bool]:
    from .columnar import _require

    plt = _require("matplotlib.pyplot", "plot")
    return plt, "inline" in plt.get_backend().lower()


_PLOT_KARGS = {"marker": "+"}


class PacketList:
    """A list of packets.

    Built from packets (``PacketList([p1, p2])``) it is a Python list, as
    scapy's is, and indexing returns the very objects put in. Read from a
    capture it stays in Rust as one buffer plus an index, indexing mints a
    packet, and the bulk methods — ``columns``, ``filter(where=)``,
    ``sprintf``, ``streams`` — cross once. Mutating a capture-backed list
    turns it into a Python list first.
    """

    __slots__ = ("_rust", "_res", "listname", "stats", "_meta", "_offs")

    def __init__(self, res: Any = None, name: str = "PacketList",
                 stats: Optional[list] = None):
        self._meta: Optional[_NgMeta] = None
        self._offs: Optional[List[int]] = None
        if isinstance(res, _b.PktList):
            self._rust, self._res = res, None
        elif isinstance(res, PacketList):
            self._rust, self._res = res._rust, res._res
            self._meta = res._meta
        else:
            self._rust = None
            if res is None:
                self._res = []
            elif isinstance(res, list):
                self._res = res
            else:
                self._res = list(res)
        self.listname = name
        self.stats = stats

    # --- storage ---------------------------------------------------------

    @property
    def _list(self) -> Any:
        if self._rust is not None:
            return self._rust
        return _frames([self._elt2pkt(e) for e in self._res])

    def _own(self) -> List[Any]:
        if self._res is None:
            self._res = list(self)
            self._rust = None
        return self._res

    @property
    def res(self) -> List[Any]:
        return self._own()

    @res.setter
    def res(self, value: List[Any]) -> None:
        self._rust, self._res = None, value

    def _elt2pkt(self, elt: Any) -> Any:
        return elt

    def _elt2sum(self, elt: Any) -> str:
        return elt.summary()

    def _elt2show(self, elt: Any) -> str:
        return self._elt2sum(elt)

    def __len__(self) -> int:
        return len(self._rust) if self._rust is not None else len(self._res)

    def __iter__(self) -> Iterator[Any]:
        if self._rust is None:
            return iter(self._res)
        return (self[i] for i in range(len(self._rust)))

    def _view(self, idx: List[int], name: str) -> "PacketList":
        if self._rust is not None:
            return self._sharing(self._rust.view(idx), name)
        return self.__class__([self._res[i] for i in idx], name=name, stats=self.stats)

    def _sharing(self, rust: Any, name: str) -> "PacketList":
        """A view over part of this capture, keeping its pcapng annotations."""
        out = self.__class__(rust, name=name, stats=self.stats)
        out._meta = self._meta
        return out

    def __getitem__(self, item: Any) -> Any:
        if _is_layer(item):
            name = f"{item.__name__} from {self.listname}"
            if self._rust is not None:
                from .columnar import filter_indices
                return self._view(filter_indices(self, _layer_name(item), None), name)
            return self.__class__([x for x in self._res if item in self._elt2pkt(x)],
                                  name=name, stats=self.stats)
        if isinstance(item, slice):
            return self._view(list(range(*item.indices(len(self)))), f"mod {self.listname}")
        if self._rust is None:
            return self._res[item]
        rust = self._rust[item]
        pkt = Packet(_rust=rust, time=rust.time, wirelen=rust.wirelen)
        if self._meta is not None:
            if self._offs is None:
                self._offs = [r[0] for r in self._rust.index()]
            self._meta.apply(pkt, self._offs[item])
        return pkt

    def __setitem__(self, item: Any, value: Any) -> None:
        self._own()[item] = value

    def __delitem__(self, item: Any) -> None:
        del self._own()[item]

    def __add__(self, other: "PacketList") -> "PacketList":
        return self.__class__(list(self) + list(other),
                              name=f"{self.listname}+{other.listname}")

    def __iadd__(self, other: Any) -> "PacketList":
        self._own().extend(other)
        return self

    def append(self, x: Any) -> None:
        self._own().append(x)

    def extend(self, xs: Any) -> None:
        self._own().extend(xs)

    def insert(self, i: int, x: Any) -> None:
        self._own().insert(i, x)

    def pop(self, i: int = -1) -> Any:
        return self._own().pop(i)

    def remove(self, x: Any) -> None:
        self._own().remove(x)

    def clear(self) -> None:
        self._rust, self._res = None, []

    def sort(self, *args: Any, **kargs: Any) -> None:
        self._own().sort(*args, **kargs)

    def reverse(self) -> None:
        self._own().reverse()

    def __getattr__(self, attr: str) -> Any:
        if attr in _LIST_READS:
            return getattr(self._own(), attr)
        raise AttributeError(attr)

    def __reduce__(self) -> tuple:
        return (self.__class__, (list(self), self.listname, self.stats))

    def __repr__(self) -> str:
        stats = self.stats or _conf().stats_classic_protocols
        counts = [0] * len(stats)
        other = 0
        if self._rust is not None:
            *counts, other = self._rust.stats([_layer_name(p) for p in stats])
        else:
            for r in self._res:
                p = self._elt2pkt(r)
                for k, proto in enumerate(stats):
                    if p.haslayer(proto):
                        counts[k] += 1
                        break
                else:
                    other += 1
        body = "".join(f" {_layer_name(p)}:{n}" for p, n in zip(stats, counts))
        return f"<{self.listname}:{body} Other:{other}>"

    # --- the bulk path ---------------------------------------------------

    def count_layer(self, layer: Any) -> int:
        """Packets containing a layer. One crossing for the whole list."""
        return self._list.count_layer(_layer_name(layer))

    def field_column(self, layer: Any, field: str) -> List[Any]:
        """One field from every packet, in a single crossing."""
        from .columnar import Column
        return Column(self._list.field_column(_layer_name(layer), field))

    def columns(self, specs: Any = None, where: Any = None, layer: Any = None) -> dict:
        """Several fields from the whole list in one pass. See `columnar`."""
        from .columnar import columns
        return columns(self, specs, where=where, layer=layer)

    def to_dict(self, specs: Any = None, where: Any = None, layer: Any = None) -> dict:
        from .columnar import to_dict
        return to_dict(self, specs, where=where, layer=layer)

    def filter(self, layer: Any = None, where: Any = None) -> "PacketList":
        """``filter(func)`` keeps the packets ``func`` accepts, as scapy's
        does. ``filter(layer, where=)`` is the query evaluated in Rust."""
        if callable(layer) and not _is_layer(layer) and where is None:
            name = f"filtered {self.listname}"
            if self._rust is not None:
                keep = [i for i, p in enumerate(self) if layer(p)]
                return self._view(keep, name)
            return self.__class__([x for x in self._res if layer(*_as_args(x))],
                                  name=name, stats=self.stats)
        from . import _as_layer_and_where
        from .columnar import filter_packets
        layer, where = _as_layer_and_where(layer, where)
        out = filter_packets(self, layer, where)
        out._meta = self._meta
        return out

    def filter_indices(self, layer: Any = None, where: Any = None) -> List[int]:
        from . import _as_layer_and_where
        from .columnar import filter_indices
        layer, where = _as_layer_and_where(layer, where)
        return filter_indices(self, layer, where)

    def head(self, n: int) -> "PacketList":
        if self._rust is not None:
            return self._sharing(self._rust.head(n), self.listname)
        return self.__class__(self._res[:n], name=self.listname, stats=self.stats)

    def sprintf(self, fmt: str) -> List[str]:
        """Every packet through one format string, in one pass."""
        from .report import sprintf_list
        return sprintf_list(self, fmt)

    def times(self) -> List[float]:
        if self._rust is not None:
            return self._rust.times()
        return [float(getattr(self._elt2pkt(e), "time", 0) or 0) for e in self._res]

    def raw_at(self, i: int) -> bytes:
        if self._rust is not None:
            return self._rust.raw_at(i)
        return bytes(self._elt2pkt(self._res[i]))

    def sessions(self, session_extractor: Any = None) -> Any:
        """Which packets belong to a flow. `streams()` is what the flow said."""
        from .report import sessions
        return sessions(self, session_extractor)

    def streams(self) -> Any:
        """Reassembled TCP streams, keyed as `sessions()` keys its flows."""
        from .stream import streams
        return streams(self)

    # --- reporting -------------------------------------------------------

    def summary(self, prn: Optional[Callable] = None, lfilter: Optional[Callable] = None) -> None:
        for line in self._summary_lines(prn, lfilter, False):
            print(line)

    def nsummary(self, prn: Optional[Callable] = None, lfilter: Optional[Callable] = None) -> None:
        for line in self._summary_lines(prn, lfilter, True):
            print(line)

    def show(self, *args: Any, **kargs: Any) -> None:
        self.nsummary(*args, **kargs)

    def _summary_lines(self, prn: Optional[Callable], lfilter: Optional[Callable],
                       numbered: bool) -> Iterator[str]:
        if self._rust is not None:
            from .report import summary_lines
            yield from summary_lines(self, prn, lfilter, numbered=numbered)
            return
        for i, r in enumerate(self._res):
            args = _as_args(r)
            if lfilter is not None and not lfilter(*args):
                continue
            line = self._elt2sum(r) if prn is None else str(prn(*args))
            yield f"{i:04d} {line}" if numbered else line

    def make_table(self, *args: Any, **kargs: Any) -> Optional[str]:
        """``fn(pkt)`` gives the column, row and cell. Prints, or returns the
        text with ``dump=True``."""
        return make_table(self._rows(kargs), *args, **kargs)

    def make_lined_table(self, *args: Any, **kargs: Any) -> Optional[str]:
        return make_lined_table(self._rows(kargs), *args, **kargs)

    def make_tex_table(self, *args: Any, **kargs: Any) -> Optional[str]:
        return make_tex_table(self._rows(kargs), *args, **kargs)

    def _rows(self, kargs: dict) -> Any:
        lfilter = kargs.pop("lfilter", None)
        if lfilter is None:
            return self
        return [e for e in self if lfilter(*_as_args(e))]

    def plot(self, f: Callable, lfilter: Optional[Callable] = None,
             plot_xy: bool = False, **kargs: Any) -> Any:
        """matplotlib is optional and imported only here."""
        plt, inlined = _plt()
        data = [f(*_as_args(e)) for e in self if lfilter is None or lfilter(*_as_args(e))]
        kargs = kargs or _PLOT_KARGS
        lines = plt.plot(*zip(*data), **kargs) if plot_xy else plt.plot(data, **kargs)
        if not inlined:
            plt.show()
        return lines

    def diffplot(self, f: Callable, delay: int = 1, lfilter: Optional[Callable] = None,
                 **kargs: Any) -> Any:
        """``f`` over each pair ``(l[i], l[i + delay])``."""
        plt, inlined = _plt()
        res = list(self)
        data = [f(res[i], res[i + delay]) for i in range(len(res) - delay)
                if lfilter is None or lfilter(res[i])]
        lines = plt.plot(data, **(kargs or _PLOT_KARGS))
        if not inlined:
            plt.show()
        return lines

    def multiplot(self, f: Callable, lfilter: Optional[Callable] = None,
                  plot_xy: bool = False, **kargs: Any) -> Any:
        """``f`` returns a label and a value; each label is its own line."""
        plt, inlined = _plt()
        d: Dict[Any, list] = {}
        for e in self:
            if lfilter is None or lfilter(*_as_args(e)):
                k, v = f(*_as_args(e))
                d.setdefault(k, []).append(v)
        kargs = kargs or _PLOT_KARGS
        if plot_xy:
            lines = [plt.plot(*zip(*pl), **dict(kargs, label=k)) for k, pl in d.items()]
        else:
            lines = [plt.plot(pl, **dict(kargs, label=k)) for k, pl in d.items()]
        plt.legend(loc="center right", bbox_to_anchor=(1.5, 0.5))
        if not inlined:
            plt.show()
        return lines

    def timeskew_graph(self, ip: str, **kargs: Any) -> Any:
        """Plot how a host's TCP timestamp clock drifts against capture time."""
        from .error import warning

        c = []
        for e in self:
            p = self._elt2pkt(e)
            if not (p.haslayer("IP") and p.haslayer("TCP") and p["IP"].src == ip):
                continue
            for o in p["TCP"].options or []:
                if o[0] == "Timestamp":
                    c.append((float(p.time), o[1][0]))
        if not c:
            warning("No timestamps found in packet list")
            return []
        ct0, rt0 = c[0]
        data = [(ct % 2000, (ct - ct0) - ((rt - rt0) / 1000.0)) for ct, rt in c]
        plt, inlined = _plt()
        lines = plt.plot(data, **(kargs or _PLOT_KARGS))
        if not inlined:
            plt.show()
        return lines

    def _dump_row(self, i: int, p: Any, r: Any) -> None:
        print("%04i %s %s" % (i, p.sprintf("%.time%"), self._elt2sum(r)))

    def rawhexdump(self) -> None:
        for p in self:
            hexdump(self._elt2pkt(p))

    def hexraw(self, lfilter: Optional[Callable] = None) -> None:
        """``nsummary()``, with each packet's Raw payload hexdumped."""
        for i, r in enumerate(self):
            p = self._elt2pkt(r)
            if lfilter is not None and not lfilter(p):
                continue
            self._dump_row(i, p, r)
            if p.haslayer("Raw"):
                hexdump(p.getlayer("Raw").load)

    def hexdump(self, lfilter: Optional[Callable] = None) -> None:
        for i, r in enumerate(self):
            p = self._elt2pkt(r)
            if lfilter is not None and not lfilter(p):
                continue
            self._dump_row(i, p, r)
            hexdump(p)

    def padding(self, lfilter: Optional[Callable] = None) -> None:
        """``hexraw()`` for the Padding layer."""
        for i, r in enumerate(self):
            p = self._elt2pkt(r)
            if p.haslayer("Padding") and (lfilter is None or lfilter(p)):
                self._dump_row(i, p, r)
                hexdump(p.getlayer("Padding").load)

    def nzpadding(self, lfilter: Optional[Callable] = None) -> None:
        """``padding()``, skipping padding that is one octet repeated."""
        for i, r in enumerate(self):
            p = self._elt2pkt(r)
            if not p.haslayer("Padding"):
                continue
            pad = p.getlayer("Padding").load
            if pad == pad[:1] * len(pad):
                continue
            if lfilter is None or lfilter(p):
                self._dump_row(i, p, r)
                hexdump(pad)

    def conversations(self, getsrcdst: Optional[Callable] = None, **kargs: Any) -> Any:
        """DOT source for who talked to whom, through ``do_graph``: returned
        as text unless a ``target`` or ``format`` asks graphviz to render it.

        ``getsrcdst`` returns the source, the destination and optionally a
        label; by default the IP, IPv6 or ARP addresses, in that order."""
        conv: Dict[tuple, Any] = {}
        for c in self._endpoints(getsrcdst):
            if len(c) == 3:
                conv.setdefault(c[:2], set()).add(c[2])
            else:
                conv[c] = conv.get(c, 0) + 1
        gr = 'digraph "conv" {\n'
        for (s, d), n in conv.items():
            label = ", ".join(str(x) for x in n) if isinstance(n, set) else n
            gr += '\t "%s" -> "%s" [label="%s"]\n' % (_dot(s), _dot(d), _dot(label))
        gr += "}\n"
        return do_graph(gr, **kargs)

    def _endpoints(self, getsrcdst: Optional[Callable]) -> Iterator[tuple]:
        if getsrcdst is None and self._rust is not None:
            cols = self._rust.columns(
                [("IP", "src"), ("IP", "dst"), ("IPv6", "src"), ("IPv6", "dst"),
                 ("ARP", "psrc"), ("ARP", "pdst")], None, [])
            for row in zip(*cols):
                for k in (0, 2, 4):
                    if row[k] is not None:
                        yield (row[k], row[k + 1])
                        break
            return
        fn = getsrcdst or _default_srcdst
        for e in self:
            try:
                yield tuple(fn(self._elt2pkt(e)))
            except Exception:
                continue

    def afterglow(self, src: Optional[Callable] = None, event: Optional[Callable] = None,
                  dst: Optional[Callable] = None, **kargs: Any) -> Any:
        """Each element reduced to ``src -> event -> dst`` and graphed; by
        default IP source, destination port, IP destination."""
        src = src or (lambda *x: x[0]["IP"].src)
        event = event or (lambda *x: x[0].dport)
        dst = dst or (lambda *x: x[0]["IP"].dst)
        sl: Dict[Any, Tuple[int, list]] = {}
        el: Dict[Any, Tuple[int, list]] = {}
        dl: Dict[Any, int] = {}
        for i in self:
            try:
                s, e, d = src(i), event(i), dst(i)
            except Exception:
                continue
            n, lst = sl.get(s, (0, []))
            if e not in lst:
                lst.append(e)
            sl[s] = (n + 1, lst)
            n, lst = el.get(e, (0, []))
            if d not in lst:
                lst.append(d)
            el[e] = (n + 1, lst)
            dl[d] = dl.get(d, 0) + 1

        def minmax(x: Any) -> Tuple[int, int]:
            vals = list(x) or [0]
            m, M = min(vals), max(vals)
            if m == M:
                m = 0
            if M == 0:
                M = 1
            return m, M

        mins, maxs = minmax(x for x, _ in sl.values())
        mine, maxe = minmax(x for x, _ in el.values())
        mind, maxd = minmax(dl.values())
        gr = 'digraph "afterglow" {\n\tedge [len=2.5];\n'
        gr += "# src nodes\n"
        for s, (n, _) in sl.items():
            n = 1 + float(n - mins) / (maxs - mins)
            gr += ('"src.%s" [label = "%s", shape=box, fillcolor="#FF0000", '
                   'style=filled, fixedsize=1, height=%.2f,width=%.2f];\n'
                   % (_dot(repr(s)), _dot(repr(s)), n, n))
        gr += "# event nodes\n"
        for e, (n, _) in el.items():
            n = 1 + float(n - mine) / (maxe - mine)
            gr += ('"evt.%s" [label = "%s", shape=circle, fillcolor="#00FFFF", '
                   'style=filled, fixedsize=1, height=%.2f, width=%.2f];\n'
                   % (_dot(repr(e)), _dot(repr(e)), n, n))
        for d, n in dl.items():
            n = 1 + float(n - mind) / (maxd - mind)
            gr += ('"dst.%s" [label = "%s", shape=triangle, fillcolor="#0000ff", '
                   'style=filled, fixedsize=1, height=%.2f, width=%.2f];\n'
                   % (_dot(repr(d)), _dot(repr(d)), n, n))
        gr += "###\n"
        for s, (_, lst1) in sl.items():
            for e in lst1:
                gr += ' "src.%s" -> "evt.%s";\n' % (_dot(repr(s)), _dot(repr(e)))
        for e, (_, lst2) in el.items():
            for d in lst2:
                gr += ' "evt.%s" -> "dst.%s";\n' % (_dot(repr(e)), _dot(repr(d)))
        gr += "}"
        return do_graph(gr, **kargs)

    def replace(self, *args: Any, **kargs: Any) -> "PacketList":
        """``replace(IP.src, "192.168.1.1", "10.0.0.1")``,
        ``replace(IP.ttl, 64)``, or several ``(field, [old,] new)`` tuples.
        Packets are copied before they are changed."""
        if not isinstance(args[0], tuple):
            args = (args,)
        x = PacketList(name=f"Replaced {self.listname}")
        for e in self:
            p = self._elt2pkt(e)
            copied = False
            for scheme in args:
                fld, old, new = scheme[0], scheme[1], scheme[-1]
                for o in fld.owners:
                    if o in p and (len(scheme) == 2 or getattr(p[o], fld.name) == old):
                        if not copied:
                            p = p.copy()
                            copied = True
                        setattr(p[o], fld.name, new)
            x.append(p)
        return x

    def getlayer(self, cls: Any, nb: Optional[int] = None, flt: Optional[dict] = None,
                 name: Optional[str] = None, stats: Optional[list] = None) -> "PacketList":
        """Each packet's ``getlayer(cls, nb, **flt)``, the misses dropped."""
        if name is None:
            name = f"{self.listname} layer {_layer_name(cls)}"
        kw = dict(flt or {})
        got = (self._elt2pkt(p).getlayer(cls, nb or 1, **kw) for p in self)
        return PacketList([g for g in got if g is not None], name, stats or self.stats)

    def convert_to(self, other_cls: Any, name: Optional[str] = None,
                   stats: Optional[list] = None) -> "PacketList":
        """Each packet's ``convert_to(other_cls)``."""
        return PacketList([self._elt2pkt(p).convert_to(other_cls) for p in self],
                          name or f"{self.listname} converted to {_layer_name(other_cls)}",
                          stats)

    def sr(self, multi: bool = False, lookahead: Optional[int] = None) -> Tuple["SndRcvList", "PacketList"]:
        """Pair each packet with a later one that answers it."""
        remain = list(self)
        answered: List[QueryAnswer] = []
        done: set = set()
        if not lookahead:
            lookahead = len(remain)
        i = 0
        while i < len(remain):
            s = remain[i]
            j = i
            while j < min(lookahead + i, len(remain) - 1):
                j += 1
                r = remain[j]
                if r.answers(s):
                    answered.append(QueryAnswer(s, r))
                    if multi:
                        done.update((id(s), id(r)))
                        continue
                    del remain[j]
                    del remain[i]
                    i -= 1
                    break
            i += 1
        if multi:
            remain = [x for x in remain if id(x) not in done]
        return SndRcvList(answered), PacketList(remain)

    def canvas_dump(self, layer_shift: int = 0, rebuild: int = 1) -> Any:
        """A PyX document, one page per packet. Needs PyX and the packet
        renderer, ``Packet.canvas_dump``."""
        try:
            import pyx
        except ImportError:
            raise ImportError("canvas_dump needs PyX: pip install pyx")
        d = pyx.document.document()
        n = len(self)
        for i, r in enumerate(self):
            p = self._elt2pkt(r)
            dump = getattr(p, "canvas_dump", None)
            if dump is None:
                raise NotImplementedError(
                    "wiry has no Packet.canvas_dump, the per-packet drawing "
                    "psdump/pdfdump/svgdump are built on"
                )
            c = dump(layer_shift=layer_shift, rebuild=rebuild)
            cbb = c.bbox()
            c.text(cbb.left(), cbb.top() + 1,
                   r"\font\cmssfont=cmss12\cmssfont{Frame %i/%i}" % (i, n),
                   [pyx.text.size.LARGE])
            d.append(pyx.document.page(c, paperformat=pyx.document.paperformat.A4,
                                       margin=1 * pyx.unit.t_cm, fittosize=1))
        return d

    def _document(self, filename: Optional[str], suffix: str, write: str,
                  reader: str, **kargs: Any) -> None:
        from .external import _open_viewer
        from .utils import get_temp_file

        canvas = self.canvas_dump(**kargs)
        if filename is None:
            filename = get_temp_file(autoext=kargs.get("suffix", suffix))
            getattr(canvas, write)(filename)
            _open_viewer(getattr(_conf().prog, reader), filename)
        else:
            getattr(canvas, write)(filename)
        print()

    def psdump(self, filename: Optional[str] = None, **kargs: Any) -> None:
        self._document(filename, ".eps", "writeEPSfile", "psreader", **kargs)

    def pdfdump(self, filename: Optional[str] = None, **kargs: Any) -> None:
        self._document(filename, ".pdf", "writePDFfile", "pdfreader", **kargs)

    def svgdump(self, filename: Optional[str] = None, **kargs: Any) -> None:
        self._document(filename, ".svg", "writeSVGfile", "svgreader", **kargs)


class _NgMeta:
    """A pcapng capture's per-packet annotations, read from the file the
    first time a packet is minted from it. The bulk paths never ask, so a
    capture that is only queried never pays for the walk."""

    __slots__ = ("_rust", "_table")

    def __init__(self, rust: Any):
        self._rust = rust
        self._table: Optional[Dict[int, tuple]] = None

    def table(self) -> Dict[int, tuple]:
        if self._table is None:
            from .pcapio import pcapng_metadata

            self._table = pcapng_metadata(self._rust.blob())
            self._rust = None
        return self._table

    def annotated(self) -> bool:
        return any(m[5] or m[6] is not None or m[7] is not None or m[8]
                   for m in self.table().values())

    def apply(self, pkt: Any, off: int) -> None:
        from .pcapio import _annotate

        _annotate(pkt, self.table().get(off))


def _dot(s: Any) -> str:
    """A DOT string body: packet contents are attacker-chosen, and a bare
    quote in one ends the string and starts an attribute."""
    return str(s).replace("\\", "\\\\").replace('"', '\\"')


def _default_srcdst(pkt: Any) -> Tuple[Any, Any]:
    if pkt.haslayer("IP"):
        return pkt["IP"].src, pkt["IP"].dst
    if pkt.haslayer("IPv6"):
        return pkt["IPv6"].src, pkt["IPv6"].dst
    if pkt.haslayer("ARP"):
        return pkt["ARP"].psrc, pkt["ARP"].pdst
    raise TypeError()


class SndRcvList(PacketList):
    """``(query, answer)`` pairs; per-packet methods see the answer."""

    __slots__ = ()

    def __init__(self, res: Any = None, name: str = "Results", stats: Optional[list] = None):
        super().__init__(res, name, stats)

    def _elt2pkt(self, elt: Any) -> Any:
        return elt[1]

    def _elt2sum(self, elt: Any) -> str:
        return "%s ==> %s" % (elt[0].summary(), elt[1].summary())

    def __getitem__(self, item: Any) -> Any:
        if _is_layer(item) or isinstance(item, slice):
            return super().__getitem__(item)
        return self._own()[item]
