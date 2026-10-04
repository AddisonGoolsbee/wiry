# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from scapy: scapy/sendrecv.py (the socket loop of AsyncSniffer._run)
#   scapy 2.7.0, upstream commit 7d69454
#   Copyright (C) Philippe Biondi <phil@secdev.org>
#   Copyright (C) the scapy contributors
#
# Changed by the wiry authors:
#   2026-10-03 — sniff(opened_socket=) reads any SuperSocket with scapy's loop,
#                and sniff(offline=) takes packets as well as captures.

"""Live capture and injection, plus the offline driver for ``sniff``.

Import cost is zero until one of these names is touched: ``wiry`` exports
them through its module ``__getattr__``.

``sniff`` runs one state machine over an interface or a capture. Filters are
ANDed cheapest first: ``filter=`` (BPF, in the kernel's own bytecode) rejects a
packet for nothing, ``where=`` (a wiry extension, evaluated in Rust) rejects
one before it ever becomes a Python object, and only survivors reach
``lfilter=``. A socket handed in as ``opened_socket=`` is read one ``recv`` at a
time in Python instead, because that is what a socket object offers.

Everything except ``sniff(offline=...)`` needs libpcap, which is loaded when a
capture is first asked for rather than linked at build time. Where it is absent
the names still import and raise ``CaptureUnavailable``, which subclasses
``OSError``, naming the package to install. ``capture_backend()`` says which
library was loaded, or why none was.
"""

from __future__ import annotations

import atexit
import math
import os
import threading
import time
import warnings
import weakref
from typing import Any, Callable, Optional

from . import Packet, PacketList, _as_path, expand
from . import _wiry as _b
from .columnar import _normalize_where
from .error import Scapy_Exception
from .error import log_runtime as _log

CaptureUnavailable = _b.CaptureUnavailable

__all__ = [
    "sniff", "AsyncSniffer", "send", "sendp", "sr", "sr1", "srp", "srp1",
    "get_if_list", "get_if_addr", "get_if_hwaddr", "get_working_if", "conf",
    "capture_available", "capture_backend", "CaptureUnavailable",
]


def capture_available() -> bool:
    """Whether this host can capture live traffic. Never raises.

    True once libpcap has been found and loaded, which is a property of the
    machine rather than of the build. It says nothing about privileges: a host
    that can load libpcap and cannot open ``/dev/bpf0`` answers True here and
    raises ``PermissionError`` from ``sniff``.
    """
    return _b.capture_available()


def capture_backend() -> dict:
    """What the capture backend is: ``available``, the ``library`` that was
    loaded, its ``version`` banner, and the ``reason`` where none was.

    Never raises, so it is safe to put in a bug report unconditionally.
    """
    return dict(_b.capture_backend())


def _iface_name(iface: Any) -> str:
    """The interface to work on: what was asked for, else ``conf.iface``."""
    return conf.iface if iface is None else str(iface)


def _wrap(rust: Any) -> Packet:
    return Packet(_rust=rust, time=rust.time, wirelen=rust.wirelen)


def _wrap_from(iface: str) -> Callable:
    """The live path knows which interface a packet arrived on, so it records
    it; a capture file does not, and leaves ``sniffed_on`` None."""

    def wrap(rust: Any) -> Packet:
        pkt = _wrap(rust)
        pkt.sniffed_on = iface
        return pkt

    return wrap


def _printing(prn: Optional[Callable], quiet: bool) -> Optional[Callable]:
    """Scapy prints whatever ``prn`` returns; ``quiet`` suppresses that."""
    if prn is None or quiet:
        return prn

    def show(pkt: Packet) -> None:
        out = prn(pkt)
        if out is not None:
            print(out)

    return show


class _MixedLinks(Exception):
    """Packets one capture cannot hold: they start with different link
    layers, or with a layer no link type names."""

    def __init__(self, pkts: list):
        super().__init__()
        self.pkts = pkts


def _offline_source(offline: Any) -> Any:
    """A capture buffer for whatever ``offline=`` was given: a path, a binary
    file object, a ``PacketList``, or packets, which are written into one so
    that the same machine and the same BPF read them."""
    if isinstance(offline, PacketList) and offline._rust is not None:
        return offline._rust
    if isinstance(offline, (str, os.PathLike)) or hasattr(offline, "read"):
        with _as_path(offline) as real:
            return _b.read_pcap(real)
    from .supersocket import IterSocket

    pkts = []
    sock = IterSocket(offline)
    while True:
        try:
            pkts.append(sock.recv())
        except EOFError:
            break
    links = {_link_of(p) for p in pkts}
    unnamed = any(isinstance(p, Packet) and _link_of(p) == _RAW_LINK
                  and p.layers()[:1] != ["Raw"] for p in pkts)
    if len(links) > 1 or unnamed:
        raise _MixedLinks(pkts)
    return _capture_of(pkts)


# Layer name -> the link type a capture of it declares; the rest are written
# as DLT_USER0 and read back as Raw, so their octets still round-trip.
_LINK_OF = {
    "Ether": 1, "Loopback": 0, "IP": 228, "IPv6": 229, "CookedLinux": 113,
    "CookedLinuxV2": 276, "Dot11": 105, "RadioTap": 127,
}

_RAW_LINK = 147


def _link_of(pkt: Any) -> int:
    if isinstance(pkt, Packet):
        names = pkt.layers()
        if names:
            return _LINK_OF.get(names[0], _RAW_LINK)
    return _RAW_LINK


def _capture_of(pkts: list) -> Any:
    """Python packets that share one link type, as a capture buffer."""
    link = _link_of(pkts[0]) if pkts else 1
    return _b.PktList.from_frames([
        (_octets(p), float(getattr(p, "time", 0.0) or 0.0),
         int(getattr(p, "wirelen", 0) or 0))
        for p in pkts
    ], link)


def _socket_map(opened_socket: Any) -> dict:
    """scapy's three spellings: one socket, a list, or ``{socket: label}``."""
    if isinstance(opened_socket, dict):
        return dict(opened_socket)
    if isinstance(opened_socket, (list, tuple)):
        return {s: f"socket{i}" for i, s in enumerate(opened_socket)}
    return {opened_socket: "socket0"}


def _sniff_sockets(
    socks: dict,
    *,
    count: int = 0,
    store: int = 1,
    prn: Optional[Callable] = None,
    lfilter: Optional[Callable] = None,
    timeout: Optional[float] = None,
    stop_filter: Optional[Callable] = None,
    quiet: bool = False,
    session: Any = None,
    started_callback: Optional[Callable] = None,
    stop_event: Optional[threading.Event] = None,
) -> PacketList:
    """``sniff`` over socket objects, as scapy reads them.

    A packet goes session, then ``lfilter``, then ``prn``, then the stop
    checks, which is the order the Rust machine applies to a capture, and
    ``count`` counts survivors there as here. A socket that raises
    ``EOFError`` is closed and dropped; one that fails otherwise is closed,
    reported on ``scapy.runtime`` and dropped, and the rest are still read.
    """
    from .stream import as_session, bulk_hook

    session = as_session(session)
    if bulk_hook(session) is not None:
        raise NotImplementedError(
            "session= that reassembles needs the whole capture at once; "
            "sniff the socket to a PacketList, then pass it to offline="
        )
    show = _printing(prn, quiet)
    live = dict(socks)
    first = next(iter(live))
    wait = getattr(first, "select", None) or _select_objects()
    deadline = None
    if timeout is not None and math.isfinite(float(timeout)):
        deadline = time.monotonic() + float(timeout)
    out: list = []
    seen = 0
    if started_callback is not None:
        started_callback()
    try:
        while live:
            if stop_event is not None and stop_event.is_set():
                break
            remain = None
            if deadline is not None:
                remain = deadline - time.monotonic()
                if remain <= 0:
                    break
            if stop_event is not None:
                remain = _POLL_SLICE if remain is None else min(remain, _POLL_SLICE)
            done = False
            for s in wait(list(live), remain):
                if s not in live:
                    continue
                try:
                    pkt = s.recv()
                except EOFError:
                    _quietly_close(s)
                    del live[s]
                    continue
                except Exception as exc:
                    _quietly_close(s)
                    del live[s]
                    _log.warning("Socket %s failed with '%s'. It was closed.",
                                 s, exc)
                    # scapy's threshold: 1 is for dissection, 2 for sockets.
                    if conf.debug_dissector >= 2:
                        raise
                    continue
                if pkt is None:
                    continue
                try:
                    pkt.sniffed_on = live[s]
                except AttributeError:
                    pass
                if session is not None:
                    pkt = _run_session(session, pkt)
                    if pkt is None:
                        continue
                if lfilter is not None and not lfilter(pkt):
                    continue
                seen += 1
                if store:
                    out.append(pkt)
                if show is not None:
                    show(pkt)
                if (stop_filter is not None and stop_filter(pkt)) or \
                        0 < count <= seen:
                    done = True
                    break
            if done:
                break
    except KeyboardInterrupt:
        pass
    return PacketList(out)


# How often a sniff that can be stopped from outside looks at its stop flag.
_POLL_SLICE = 0.05


def _select_objects() -> Callable:
    from .supersocket import select_objects
    return select_objects


def _quietly_close(sock: Any) -> None:
    try:
        sock.close()
    except Exception:
        pass


def _run_session(session: Any, pkt: Any) -> Any:
    try:
        return session.process(pkt)
    except Exception as exc:
        if conf.debug_dissector:
            raise
        warnings.warn(
            f"{type(session).__name__}.process failed with {exc!r}; "
            "passing the packet through", RuntimeWarning, stacklevel=3,
        )
        return pkt


def _live_args(
    *,
    iface: Any = None,
    count: int = 0,
    store: int = 1,
    prn: Optional[Callable] = None,
    filter: Optional[str] = None,
    lfilter: Optional[Callable] = None,
    timeout: Optional[float] = None,
    stop_filter: Optional[Callable] = None,
    offline: Any = None,
    quiet: bool = False,
    promisc: Any = None,
    snaplen: int = 262144,
    where: Any = None,
) -> dict:
    """``sniff``'s keywords as the live driver takes them. Mirroring the
    signature is what makes an unknown keyword a ``TypeError`` there too."""
    if offline is not None:
        raise ValueError("the live driver takes no offline source")
    name = _iface_name(iface)
    return dict(
        iface=name,
        count=int(count),
        store=bool(store),
        filter=filter,
        layer=None,
        conds=_normalize_where(where),
        timeout=None if timeout is None else float(timeout),
        promisc=conf.sniff_promisc if promisc is None else bool(promisc),
        snaplen=int(snaplen),
        prn=_printing(prn, quiet),
        lfilter=lfilter,
        stop_filter=stop_filter,
        wrap=_wrap_from(name),
    )


def _add_session(args: dict, session: Any, store: Any) -> None:
    """Put a per-packet session between the capture filter and the callbacks,
    where scapy runs one.

    It rides ``wrap``, so ``lfilter``, ``prn`` and ``stop_filter`` all see what
    the session produced and a packet it drops is never counted. The dissection
    loop is untouched: the session sees a packet that already exists.
    """
    if session is None:
        return
    base, user = args["wrap"], args["lfilter"]

    def wrap(rust: Any) -> Any:
        pkt = base(rust)
        try:
            out = session.process(pkt)
        except Exception as exc:
            # scapy reports and skips past a session's own failure so one bad
            # packet does not end the capture; conf.debug_dissector says no.
            if conf.debug_dissector:
                raise
            warnings.warn(
                f"{type(session).__name__}.process failed with {exc!r}; "
                "passing the packet through",
                RuntimeWarning, stacklevel=2,
            )
            return pkt
        if store and out is not None and out is not pkt:
            raise NotImplementedError(
                f"{type(session).__name__} replaced a packet, and a replaced "
                "packet cannot go into the PacketList sniff() returns: that is "
                "a view over the capture buffer and a synthesised packet was "
                "never in one. Sniff with store=0 and read them through prn=, "
                "or give the session a bulk_process() as TCPSession has"
            )
        return out

    def keep(pkt: Any) -> bool:
        if pkt is None:
            return False
        return user is None or bool(user(pkt))

    args["wrap"], args["lfilter"] = wrap, keep


class BadFilter(Scapy_Exception, ValueError):
    """A BPF expression libpcap would not compile."""


def _filter_errors(fn: Callable) -> Callable:
    """scapy raises its own exception for a filter that does not compile;
    the ValueError base keeps ``except ValueError`` callers working."""
    import functools

    @functools.wraps(fn)
    def call(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except ValueError as exc:
            if str(exc).startswith("invalid capture filter") and \
                    not isinstance(exc, BadFilter):
                raise BadFilter(str(exc)) from exc
            raise

    return call


@_filter_errors
def sniff(
    *,
    iface: Any = None,
    count: int = 0,
    store: int = 1,
    prn: Optional[Callable] = None,
    filter: Optional[str] = None,
    lfilter: Optional[Callable] = None,
    timeout: Optional[float] = None,
    stop_filter: Optional[Callable] = None,
    offline: Any = None,
    quiet: bool = False,
    promisc: Any = None,
    snaplen: int = 262144,
    where: Any = None,
    session: Any = None,
    opened_socket: Any = None,
    started_callback: Optional[Callable] = None,
) -> PacketList:
    """Capture packets, or replay a capture file through the same machine.

    ``count=0`` is unbounded and ``store=0`` returns an empty ``PacketList``.
    ``timeout`` is a wall-clock deadline for the whole call, not libpcap's read
    timeout. ``where=`` is a wiry extension, keyword-only: the same Rust-side
    query ``PacketList.filter(where=...)`` takes, so a packet it rejects is never
    built as a Python object.

    ``iface``, ``promisc`` and ``snaplen`` are ignored when ``offline`` is given,
    as scapy ignores them. ``promisc=None`` reads ``conf.sniff_promisc``.

    ``session=`` takes a session class or instance and runs it between the
    capture filter and the callbacks, where scapy runs one. A session with
    scapy's per-packet ``process(pkt)`` runs on an interface as well as over a
    file: it sees a packet the dissector has already produced, so no Python
    enters the dissection loop. A session that reassembles — ``TCPSession``,
    ``IPSession`` — is a whole-capture pass in Rust instead, one crossing
    rather than a Python loop, and that needs every packet in hand, so those
    are offline only.

    ``offline=`` takes a capture path, a binary file object, a ``PacketList``,
    or packets: a packet, a template, or a list of packets or of bytes, which
    are written into a capture buffer first so the same machine reads them.

    ``opened_socket=`` takes a socket object, a list of them, or a dict
    mapping each to the label ``sniffed_on`` will carry, and reads them one
    ``recv`` at a time, as scapy does. ``filter=`` is not applied to those,
    as scapy does not apply it; ``where=`` is a query over a capture buffer
    and is refused there. ``started_callback`` runs once the source is ready,
    which on an interface would be before Rust opens the handle, so there it
    is refused.
    """
    from .stream import as_session, bulk_hook

    if opened_socket is not None:
        return _sniff_opened(
            opened_socket, iface=iface, count=count, store=store, prn=prn,
            filter=filter, lfilter=lfilter, timeout=timeout,
            stop_filter=stop_filter, offline=offline, quiet=quiet,
            promisc=promisc, where=where, session=session,
            started_callback=started_callback,
        )

    session = as_session(session)
    bulk = bulk_hook(session)
    if offline is None:
        if bulk is not None:
            raise NotImplementedError(
                "session= needs the whole capture at once and so works with "
                "offline= only; sniff to a PacketList, then pass it back in"
            )
        if started_callback is not None:
            raise NotImplementedError(
                "started_callback= cannot be honoured on an interface: the "
                "handle is opened inside the Rust capture loop, so a callback "
                "run before it would let what it provokes go uncaptured. "
                "Use AsyncSniffer and start sending once it is running"
            )
        _b.capture_check()
        args = _live_args(
            iface=iface, count=count, store=store, prn=prn, filter=filter,
            lfilter=lfilter, timeout=timeout, stop_filter=stop_filter,
            quiet=quiet, promisc=promisc, snaplen=snaplen, where=where,
        )
        _add_session(args, session, store)
        return PacketList(_b.sniff_live(**args), "Sniffed")
    try:
        src = _offline_source(offline)
    except _MixedLinks as mixed:
        if bulk is not None or filter is not None or where is not None:
            raise NotImplementedError(
                "these packets start with different link layers, or with one "
                "no link type names, so no one capture holds them, and "
                "session=, filter= and where= all run over a capture. Sniff "
                "them without, or keep the link layers alike"
            ) from None
        from .supersocket import IterSocket

        return _sniff_opened(
            IterSocket(mixed.pkts), iface=None, count=count, store=store,
            prn=prn, filter=None, lfilter=lfilter, timeout=timeout,
            stop_filter=stop_filter, offline=None, quiet=quiet, promisc=None,
            where=None, session=session, started_callback=started_callback,
        )
    if bulk is not None:
        # The capture filter runs first, as libpcap's would, so a session never
        # reassembles a stream the caller filtered out.
        if filter is not None or where is not None:
            src = src.sniff_offline(
                count=0, store=True, bpf=filter, layer=None,
                conds=_normalize_where(where), timeout=None, prn=None,
                lfilter=None, stop_filter=None, wrap=None,
            )
            filter, where = None, None
        src = bulk(PacketList(src))._list
    offline_args = dict(
        count=int(count),
        store=bool(store),
        bpf=filter,
        layer=None,
        conds=_normalize_where(where),
        timeout=None if timeout is None else float(timeout),
        prn=_printing(prn, quiet),
        lfilter=lfilter,
        stop_filter=stop_filter,
        wrap=_wrap,
    )
    if bulk is None:
        _add_session(offline_args, session, store)
    if started_callback is not None:
        started_callback()
    return PacketList(src.sniff_offline(**offline_args), "Sniffed")


def _sniff_opened(opened_socket: Any, *, iface: Any, count: int, store: int,
                  prn: Any, filter: Any, lfilter: Any, timeout: Any,
                  stop_filter: Any, offline: Any, quiet: bool, promisc: Any,
                  where: Any, session: Any, started_callback: Any,
                  stop_event: Optional[threading.Event] = None) -> PacketList:
    """The socket half of ``sniff``. As scapy does, an ``iface`` or
    ``offline`` given alongside is read as one more socket."""
    if where is not None:
        raise NotImplementedError(
            "where= is a query over a capture buffer, and packets read from a "
            "socket object are not in one; use lfilter="
        )
    socks = _socket_map(opened_socket)
    if offline is not None:
        from .supersocket import IterSocket

        try:
            source = PacketList(_offline_source(offline))
        except _MixedLinks as mixed:
            source = mixed.pkts
        socks[IterSocket(source)] = None
    opened = []
    if iface is not None:
        listener = conf.l2listen(iface=iface, filter=filter, promisc=promisc)
        opened.append(listener)
        socks[listener] = str(iface)
    try:
        return _sniff_sockets(
            socks, count=int(count), store=store, prn=prn, lfilter=lfilter,
            timeout=timeout, stop_filter=stop_filter, quiet=quiet,
            session=session, started_callback=started_callback,
            stop_event=stop_event,
        )
    finally:
        for s in opened:
            _quietly_close(s)


def _opened_defaults(args: dict) -> dict:
    """``sniff``'s keywords for the socket path, defaults filled; an unknown
    one is a ``TypeError`` here as it is there."""
    known = dict(
        iface=None, count=0, store=1, prn=None, filter=None, lfilter=None,
        timeout=None, stop_filter=None, offline=None, quiet=False,
        promisc=None, where=None, session=None, started_callback=None,
    )
    extra = set(args) - set(known) - {"snaplen"}
    if extra:
        raise TypeError(f"sniff() got an unexpected keyword argument "
                        f"{sorted(extra)[0]!r}")
    known.update((k, v) for k, v in args.items() if k != "snaplen")
    return known


_RUNNING: "weakref.WeakSet[AsyncSniffer]" = weakref.WeakSet()


def _stop_running_sniffers() -> None:
    """Belt and braces beside the Rust ``Drop``: a capture thread that is still
    calling ``prn`` when the interpreter finalises segfaults."""
    for s in list(_RUNNING):
        try:
            s.stop()
        except BaseException:
            pass


atexit.register(_stop_running_sniffers)


class AsyncSniffer:
    """``sniff`` on a background thread, with the familiar start/stop/join.

    ``.results`` holds the ``PacketList`` once the run ends. ``stop()`` is
    honoured between packets, so it works on the offline driver too.

    On an interface the thread is a Rust one owning the capture handle, so a
    ``prn`` runs on a non-Python thread and reacquires the GIL for every packet
    it sees. That is scapy's contract for async callbacks, not an oversight:
    keep the callback short, or sniff without one and read ``.results``.
    """

    __slots__ = ("args", "_results", "_thread", "_stop", "_exc", "_live",
                 "_lock", "_started", "__weakref__")

    def __init__(self, **kwargs: Any):
        self.args = kwargs
        self._results: Optional[PacketList] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._exc: Optional[BaseException] = None
        self._live: Any = None
        # Guards the start/stop transitions only. It is never held across a
        # wait: a join() holding it would block the stop() meant to end it.
        self._lock = threading.RLock()
        self._started = False

    @property
    def results(self) -> Optional[PacketList]:
        if self._results is None and self._live is not None:
            self._keep(self._live.results())
        return self._results

    @property
    def running(self) -> bool:
        if self._live is not None:
            return self._live.running()
        return self._thread is not None and self._thread.is_alive()

    def _keep(self, rust: Any) -> Optional[PacketList]:
        """One wrapper per run, so ``join() is results`` holds."""
        if rust is not None and self._results is None:
            self._results = PacketList(rust)
        return self._results

    def _stopping(self, user: Optional[Callable]) -> Callable:
        def check(pkt: Packet) -> bool:
            if self._stop.is_set():
                return True
            return user is not None and bool(user(pkt))

        return check

    def _run(self) -> None:
        args = dict(self.args)
        try:
            if args.get("opened_socket") is not None:
                self._results = _sniff_opened(
                    args.pop("opened_socket"), stop_event=self._stop,
                    **_opened_defaults(args),
                )
                return
            args["stop_filter"] = self._stopping(args.get("stop_filter"))
            self._results = sniff(**args)
        except BaseException as exc:  # re-raised out of join()
            self._exc = exc

    def start(self) -> "AsyncSniffer":
        """Begin the capture. One run per sniffer: build another for another.

        Under the lock end to end, so two threads calling this cannot both get
        past the guard and leave one of the two captures orphaned.
        """
        with self._lock:
            if self.running:
                raise RuntimeError("this sniffer is already running")
            if self._started:
                raise RuntimeError(
                    "this sniffer has already run; its .results would be "
                    "discarded. Build another AsyncSniffer"
                )
            self._results = None
            self._exc = None
            if (self.args.get("offline") is None
                    and self.args.get("opened_socket") is None):
                from .stream import as_session, bulk_hook

                _b.capture_check()
                kwargs = dict(self.args)
                session = as_session(kwargs.pop("session", None))
                if bulk_hook(session) is not None:
                    raise NotImplementedError(
                        "session= needs the whole capture at once and so works "
                        "with offline= only"
                    )
                live_args = _live_args(**kwargs)
                _add_session(live_args, session, kwargs.get("store", 1))
                live = _filter_errors(_b.LiveSniffer)(**live_args)
                live.start()
                self._live = live
                self._started = True
                _RUNNING.add(self)
                return self
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
            self._started = True
        return self

    def _refuse_self_join(self, live: Any) -> None:
        """A live ``prn`` runs on the capture thread; waiting for that thread
        from itself would park the only one that can ever end the wait. The
        offline driver is a ``threading.Thread`` and already says this."""
        if live.on_capture_thread():
            raise RuntimeError("cannot join current thread")

    def join(self, timeout: Optional[float] = None) -> Optional[PacketList]:
        with self._lock:
            live, thread = self._live, self._thread
        if live is not None:
            self._refuse_self_join(live)
            try:
                self._keep(live.join(timeout))
            except BaseException as exc:
                self._exc = exc
            if self._exc is not None:
                raise self._exc
            return self._results
        if thread is not None:
            thread.join(timeout)
        if self._exc is not None:
            raise self._exc
        return self._results

    def stop(self, join: bool = True) -> Optional[PacketList]:
        with self._lock:
            live = self._live
        if live is not None:
            # The capture stops either way; only the wait is refused, which is
            # what stop() then join() does on the offline driver.
            selfjoin = bool(join) and live.on_capture_thread()
            try:
                self._keep(live.stop(bool(join) and not selfjoin))
            except BaseException as exc:
                # Sticky, as join()'s is: reap() has already taken the thread,
                # so a second stop() would otherwise return None and explain
                # nothing.
                self._exc = exc
            if selfjoin:
                raise RuntimeError("cannot join current thread")
            if join and self._exc is not None:
                raise self._exc
            return self._results
        self._stop.set()
        if join:
            return self.join()
        return self._results


def _as_list(x: Any) -> list:
    """Whatever was handed in, as a list of packets. A template expands."""
    if isinstance(x, (bytes, bytearray, memoryview, str)):
        return [x]
    if isinstance(x, Packet):
        return expand(x)
    if isinstance(x, PacketList):
        return list(x)
    return [p for item in x for p in expand(item)]


def _octets(pkt: Any) -> bytes:
    """A packet as the bytes that go on the wire. Strings encode as latin-1,
    as they do everywhere else here.

    Anything else is a ``TypeError``: ``bytes(3)`` is three zero octets, so an
    unchecked coercion turns ``sendp([1, 2, 3])`` into three all-zero frames on
    the wire instead of a complaint.
    """
    if isinstance(pkt, str):
        return pkt.encode("latin-1")
    if isinstance(pkt, (Packet, bytes, bytearray, memoryview)):
        return bytes(pkt)
    raise TypeError(
        f"expected a Packet, bytes or str to send, not {type(pkt).__name__}"
    )


def _refuse_ipv6(pkts: list, frames: list, what: str) -> None:
    """Refuse an IPv6 datagram on the layer-3 path, however it was spelt.

    The serialised frame is checked as well as the packet object: raw bytes are
    just as sendable, and past this point the only thing between them and the
    ``AF_INET`` raw socket is a version nibble.
    """
    for p, f in zip(pkts, frames):
        six = isinstance(p, Packet) and "IPv6" in p.layers()
        if not six:
            six = len(f) > 0 and f[0] >> 4 == 6
        if six:
            raise NotImplementedError(
                f"{what}() has no IPv6 layer-3 path: it writes IPv4 datagrams to "
                "a raw socket. Wrap the packet in Ether() and use sendp()."
            )


def _pause(inter: Any) -> float:
    """``inter`` as seconds. Infinity is refused rather than clamped: a pause of
    ``Duration::MAX`` between two packets is a hang, not a long wait."""
    v = float(inter)
    if not math.isfinite(v):
        raise ValueError(
            f"inter= must be a finite number of seconds, not {inter!r}"
        )
    return v


def _wanted_src(name: str, fields: dict, mac: Optional[str],
                ip: Optional[str]) -> tuple:
    """Which source addresses this layer wants filled from the interface."""
    if name == "Ether":
        return (("src", mac),)
    if name == "ARP":
        return (("hwsrc", mac), ("psrc", ip))
    if name == "IP":
        # scapy computes IP.src from the route at build time. wiry's field
        # table has a static default, 127.0.0.1, and a datagram carrying it
        # makes the kernel ARP as 127.0.0.1, which nobody answers: sr1, srloop
        # and traceroute all came back empty against a real peer. Only an
        # explicit, non-loopback destination earns the fill, since the default
        # destination is that same 127.0.0.1 and wants the default source.
        dst = str(fields.get("dst") or "")
        return (("src", ip),) if dst and not dst.startswith("127.") else ()
    return ()


def _with_src(pkt: Any, mac: Optional[str], ip: Optional[str] = None) -> Any:
    """Fill unset source addresses from the outgoing interface (E9).

    At send time only, and on a copy: ``bytes(Ether())`` stays reproducible and
    the build path stays free of the host it happens to run on. ``Ether.src``
    and ``ARP.hwsrc`` take the hardware address, ``ARP.psrc`` and ``IP.src``
    the interface's IPv4 address. Either may be ``None`` where the host will
    not say, and the field is then left alone, which is an ordinary outcome.

    A dissected packet has no field spec to fill, so it goes out as captured.
    """
    if not isinstance(pkt, Packet) or not pkt._stack:
        return pkt
    todo = [
        (i, field, value)
        for i, (name, fields) in enumerate(pkt._stack)
        for field, value in _wanted_src(name, fields, mac, ip)
        if value and not fields.get(field)
    ]
    if not todo:
        return pkt
    stack = [(n, dict(f)) for n, f in pkt._stack]
    for i, field, value in todo:
        stack[i][1][field] = value
    return Packet(_stack=stack, _payload=pkt._payload)


def _local_addrs(iface: str) -> tuple:
    """The interface's hardware and IPv4 addresses, each ``None`` where the
    host does not report one. ``0.0.0.0`` is ``get_if_addr``'s way of saying it
    found nothing, and filling ``psrc`` with it is no better than leaving it."""
    ip = get_if_addr(iface)
    return _b.interface_mac(iface), None if ip == "0.0.0.0" else ip


def _report(sent: int, verbose: Optional[int]) -> None:
    if conf.verb if verbose is None else verbose:
        print(f"Sent {sent} packets.")


def _passes(count: Optional[int]) -> int:
    return 1 if count is None else int(count)


def _refuse_unsupported(realtime: Any) -> None:
    if realtime:
        raise NotImplementedError(
            "realtime= is not supported; inter= paces the send instead"
        )


def _send_on(sock: Any, x: Any, count: Optional[int], loop: int, gap: float,
             verbose: Optional[int], return_packets: bool) -> Any:
    """``socket=``: every packet goes through that socket's ``send``, which
    is a Python call per packet, the socket being a Python object."""
    pkts = _as_list(x)
    sent = 0
    n = 0
    try:
        while loop or n < _passes(count):
            for p in pkts:
                sock.send(p)
                sent += 1
                if gap:
                    time.sleep(gap)
            n += 1
    except KeyboardInterrupt:
        pass
    _report(sent, verbose)
    return pkts if return_packets else None


def send(x: Any, inter: float = 0, loop: int = 0, count: Optional[int] = None,
         verbose: Optional[int] = None, realtime: Optional[bool] = None,
         return_packets: bool = False, socket: Any = None,
         *, iface: Any = None, **kwargs: Any) -> Any:
    """Send layer-3 packets, letting the kernel route and frame them.

    IPv4 only: the raw socket writes datagrams with the header included, and
    IPv6 needs a second address family. ``loop`` repeats until interrupted.
    """
    _refuse_unsupported(realtime)
    gap = _pause(inter)
    if socket is not None:
        return _send_on(socket, x, count, loop, gap, verbose, return_packets)
    _b.capture_check()
    _, ip = _local_addrs(_iface_name(iface))
    if isinstance(x, Packet):
        x = _with_src(x, None, ip)
    tmpl = x.template() if isinstance(x, Packet) else None
    if tmpl is not None:
        _refuse_ipv6([x], [tmpl.frame(0)], "send")
        sent = _b.send_template_l3(tmpl, _passes(count), gap, bool(loop))
        _report(sent, verbose)
        return [x] if return_packets else None
    pkts = _as_list(x)
    frames = [_octets(_with_src(p, None, ip)) for p in pkts]
    _refuse_ipv6(pkts, frames, "send")
    sent = _b.send_datagrams(frames, _passes(count), gap, bool(loop))
    _report(sent, verbose)
    return pkts if return_packets else None


def sendp(x: Any, inter: float = 0, loop: int = 0, iface: Any = None,
          iface_hint: Any = None, count: Optional[int] = None,
          verbose: Optional[int] = None, realtime: Optional[bool] = None,
          return_packets: bool = False, socket: Any = None,
          **kwargs: Any) -> Any:
    """Send layer-2 frames exactly as given, on one interface.

    The whole list is serialised here and crosses into Rust once; the repeat
    and the ``inter`` pacing happen there. ``loop`` repeats until interrupted.
    """
    _refuse_unsupported(realtime)
    gap = _pause(inter)
    if socket is not None:
        return _send_on(socket, x, count, loop, gap, verbose, return_packets)
    _b.capture_check()
    name = _iface_name(iface)
    mac, ip = _local_addrs(name)
    if isinstance(x, Packet):
        x = _with_src(x, mac, ip)
        tmpl = x.template()
        if tmpl is not None:
            sent = _b.send_template(tmpl, name, _passes(count), gap, bool(loop))
            _report(sent, verbose)
            return [x] if return_packets else None
    pkts = _as_list(x)
    frames = [_octets(_with_src(p, mac, ip)) for p in pkts]
    sent = _b.send_frames(frames, name, _passes(count), gap, bool(loop))
    _report(sent, verbose)
    return pkts if return_packets else None


def _exchange(x: Any, l2: bool, iface: Any, filter: Optional[str],
              timeout: Optional[float], retry: int, multi: bool, inter: float,
              promisc: Optional[bool], verbose: Optional[int], what: str) -> tuple:
    """One send-and-receive round. The receive capture opens before anything
    goes out, so a reply at wire speed is not already gone."""
    _b.capture_check()
    if retry < 0:
        raise NotImplementedError(
            "a negative retry= means scapy's 'resend only while nothing at all "
            "has answered'; pass a count of resends instead"
        )
    if timeout is None and (retry or multi):
        # The first round would wait until every probe is answered, so a retry
        # round is reachable only when some probe never is, which is the one
        # case the wait never ends in. multi= never settles at all.
        raise ValueError(
            f"{what}(retry=) and {what}(multi=) need a timeout=: without one "
            "the first round never ends"
        )
    gap = _pause(inter)
    pkts = _as_list(x)
    name = _iface_name(iface)
    if l2:
        mac, ip = _local_addrs(name)
        frames = [_octets(_with_src(p, mac, ip)) for p in pkts]
    else:
        _, ip = _local_addrs(name)
        frames = [_octets(_with_src(p, None, ip)) for p in pkts]
        _refuse_ipv6(pkts, frames, what)
    recv, pairs, unans = _b.sr_live(
        frames, name, l2, filter,
        timeout=None if timeout is None else float(timeout),
        retry=int(retry), multi=bool(multi), inter=gap,
        promisc=conf.promisc if promisc is None else bool(promisc),
        check_addr=bool(conf.checkIPaddr),
    )
    got = PacketList(recv)
    answered = [(pkts[i], got[j]) for i, j in pairs]
    unanswered = [pkts[i] for i in unans]
    if conf.verb if verbose is None else verbose:
        print(f"Received {len(got)} packets, got {len(answered)} answers, "
              f"remaining {len(unanswered)} packets")
    return answered, unanswered


def sr(x: Any, promisc: Optional[bool] = None, filter: Optional[str] = None,
       iface: Any = None, nofilter: int = 0, *, timeout: Optional[float] = None,
       retry: int = 0, multi: bool = False, inter: float = 0,
       verbose: Optional[int] = None, **kwargs: Any) -> Any:
    """Send layer-3 packets and collect ``(answered, unanswered)``.

    ``answered`` pairs each sent packet with the reply ``answers()`` matched;
    anything it does not recognise is dropped rather than guessed at, so an
    unmatched probe is visible in ``unanswered``. ``retry=N`` resends the
    unanswered set N more times; ``multi=True`` keeps collecting after a probe
    has been answered once.
    """
    return _exchange(x, False, iface, filter, timeout, retry, multi, inter,
                     promisc, verbose, "sr")


def sr1(x: Any, promisc: Optional[bool] = None, filter: Optional[str] = None,
        iface: Any = None, nofilter: int = 0, *, timeout: Optional[float] = None,
        retry: int = 0, multi: bool = False, inter: float = 0,
        verbose: Optional[int] = None, **kwargs: Any) -> Any:
    """Send layer-3 packets and return the first answer, or ``None``."""
    answered, _ = sr(x, promisc=promisc, filter=filter, iface=iface,
                     nofilter=nofilter, timeout=timeout, retry=retry,
                     multi=multi, inter=inter, verbose=verbose, **kwargs)
    return answered[0][1] if answered else None


def srp(x: Any, promisc: Optional[bool] = None, iface: Any = None,
        iface_hint: Any = None, filter: Optional[str] = None,
        nofilter: int = 0, type: int = 3, *, timeout: Optional[float] = None,
        retry: int = 0, multi: bool = False, inter: float = 0,
        verbose: Optional[int] = None, **kwargs: Any) -> Any:
    """Send layer-2 frames and collect ``(answered, unanswered)``. See ``sr``."""
    return _exchange(x, True, iface, filter, timeout, retry, multi, inter,
                     promisc, verbose, "srp")


def srp1(x: Any, promisc: Optional[bool] = None, iface: Any = None,
         iface_hint: Any = None, filter: Optional[str] = None,
         nofilter: int = 0, type: int = 3, *, timeout: Optional[float] = None,
         retry: int = 0, multi: bool = False, inter: float = 0,
         verbose: Optional[int] = None, **kwargs: Any) -> Any:
    """Send layer-2 frames and return the first answer, or ``None``."""
    answered, _ = srp(x, promisc=promisc, iface=iface, iface_hint=iface_hint,
                      filter=filter, nofilter=nofilter, type=type,
                      timeout=timeout, retry=retry, multi=multi, inter=inter,
                      verbose=verbose, **kwargs)
    return answered[0][1] if answered else None


def get_if_list() -> list:
    """Every interface name libpcap reports."""
    return [i["name"] for i in _b.list_interfaces()]


def get_if_addr(iface: Any) -> str:
    """The interface's first IPv4 address, or ``0.0.0.0`` as scapy returns."""
    name = str(iface)
    for i in _b.list_interfaces():
        if i["name"] == name:
            for addr in i["addresses"]:
                if ":" not in addr:
                    return addr
    return "0.0.0.0"


def get_if_hwaddr(iface: Any) -> str:
    """The interface's hardware address, as ``aa:bb:cc:dd:ee:ff``.

    Read through getifaddrs, so it works wherever a capture does. An interface
    with none of its own — a loopback, a tunnel — answers all zeros, as scapy
    does: callers iterate `get_if_list()` and would otherwise have to guard
    every interface. `interface_mac()` still distinguishes absent from zero.
    """
    _b.capture_check()
    name = _iface_name(iface)
    mac = _b.interface_mac(name)
    return "00:00:00:00:00:00" if mac is None else mac


def get_working_if() -> str:
    """The interface libpcap would pick by default."""
    return _b.default_interface()


def interfaces() -> list:
    """Every interface with its description, addresses and loopback flag."""
    return list(_b.list_interfaces())


class _Conf:
    """A small stand-in for scapy's ``conf``, carrying the knobs scripts read.

    Every attribute here does something. There is no spare surface to set: a
    name this does not have raises ``AttributeError`` rather than being
    absorbed, and a knob whose only honest value is the one it already has
    refuses the others by name. A setting that silently did nothing would be
    worse than a missing one.
    """

    __slots__ = ("verb", "promisc", "sniff_promisc", "checkIPaddr",
                 "debug_dissector", "recv_poll_rate", "route_autoload",
                 "route6_autoload", "interactive", "histfile", "startup_file",
                 "session", "_iface", "_route", "_route6",
                 "_l3socket", "_l2socket", "_l2listen", "_loopback", "_prog",
                 "warning_threshold", "temp_files", "auto_crop_tables",
                 "_stats", "_manufdb", "_asn1_codec", "ASN1_default_long_size",
                 "_mib", "_netcache", "_nameservers", "max_list_count")

    def __init__(self) -> None:
        self.verb = 2
        # promisc is the sr family's default, sniff_promisc is sniff's.
        self.promisc = True
        self.sniff_promisc = True
        # False drops the address pinning in answers.rs: what DHCP needs, and a
        # looser match everywhere else.
        self.checkIPaddr = True
        # True makes a session's own failure raise rather than be skipped past.
        self.debug_dissector = False
        # The wait a select takes when the caller names none.
        self.recv_poll_rate = 0.05
        self.route_autoload = True
        self.route6_autoload = True
        # True only while `wiry.interact()` is running its prompt.
        self.interactive = False
        # Empty means the console picks its XDG default; a path overrides it.
        self.histfile = ""
        self.startup_file = ""
        self.session = ""
        self._iface: Optional[str] = None
        self._route: Any = None
        self._route6: Any = None
        self._l3socket: Any = None
        self._l2socket: Any = None
        self._l2listen: Any = None
        self._loopback: Optional[str] = None
        self._asn1_codec: Any = None
        # Octets of every long-form BER length the encoder writes; 0 is the
        # shortest form that fits.
        self.ASN1_default_long_size = 0
        self._mib: Any = None
        self._prog: Any = None
        # Seconds within which a third warning from one call site is dropped.
        self.warning_threshold = 5
        # What get_temp_file() made; scapy_delete_temp_files() removes them.
        self.temp_files: list = []
        # Whether pretty_list() crops a table to the terminal's width.
        self.auto_crop_tables = True
        self._stats: Optional[list] = None
        self._manufdb: Any = None
        self._netcache: Any = None
        self._nameservers: Optional[list] = None
        # A list field dissecting more items than this raises
        # MaximumItemsCount: a count is attacker-controlled.
        self.max_list_count = 100

    @property
    def netcache(self) -> Any:
        if self._netcache is None:
            from .config import NetCache

            self._netcache = NetCache()
            self._netcache.new_cache("arp_cache", 120)
            self._netcache.new_cache("dns_cache", 300)
        return self._netcache

    @property
    def nameservers(self) -> list:
        """What ``dns_resolve`` asks, in order: the host's resolvers until
        set."""
        if self._nameservers is None:
            from .arch import read_nameservers

            self._nameservers = read_nameservers()
        return self._nameservers

    @nameservers.setter
    def nameservers(self, value: Any) -> None:
        self._nameservers = list(value)

    @property
    def version(self) -> str:
        return _b.__version__

    @property
    def stats_classic_protocols(self) -> list:
        """The layers a PacketList's repr counts, in priority order."""
        if self._stats is None:
            from . import ICMP, TCP, UDP

            self._stats = [TCP, UDP, ICMP]
        return self._stats

    @stats_classic_protocols.setter
    def stats_classic_protocols(self, value: Any) -> None:
        self._stats = list(value)

    @property
    def raw_layer(self) -> Any:
        from . import Raw

        return Raw

    @property
    def padding_layer(self) -> Any:
        from . import Padding

        return Padding

    @property
    def manufdb(self) -> Any:
        """The OUI database, loaded on first use: Wireshark's ``manuf`` where
        the host has one, wiry's bundled copy where it does not."""
        if self._manufdb is None:
            from . import data

            self._manufdb = data.MANUFDB
        return self._manufdb

    @manufdb.setter
    def manufdb(self, value: Any) -> None:
        self._manufdb = value

    @property
    def protocols(self) -> Any:
        from . import data

        return data.IP_PROTOS

    @property
    def ethertypes(self) -> Any:
        from . import data

        return data.ETHER_TYPES

    @property
    def services_tcp(self) -> Any:
        from . import data

        return data.TCP_SERVICES

    @property
    def services_udp(self) -> Any:
        from . import data

        return data.UDP_SERVICES

    @property
    def services_sctp(self) -> Any:
        from . import data

        return data.SCTP_SERVICES

    @property
    def logLevel(self) -> int:
        from .error import log_scapy

        return log_scapy.level

    @logLevel.setter
    def logLevel(self, value: int) -> None:
        from .error import log_scapy

        log_scapy.setLevel(value)

    @property
    def prog(self) -> Any:
        """Where the external programs are: tcpdump, tshark, tcpreplay and
        the rest. None of them is a dependency; each wrapper says which one is
        missing when it is."""
        if self._prog is None:
            from .external import ProgPath

            self._prog = ProgPath()
        return self._prog

    @property
    def iface(self) -> str:
        """Resolved on first read, so importing never touches the backend."""
        if self._iface is None:
            self._iface = get_working_if()
        return self._iface

    @iface.setter
    def iface(self, value: Any) -> None:
        self._iface = None if value is None else str(value)

    @property
    def loopback_name(self) -> str:
        """What this host calls its loopback interface."""
        from .route import platform_loopback

        return self._loopback or platform_loopback()

    @loopback_name.setter
    def loopback_name(self, value: Any) -> None:
        self._loopback = None if value is None else str(value)

    @property
    def route(self) -> Any:
        """The IPv4 routing table, read from the OS on first use."""
        if self._route is None:
            from .route import Route

            self._route = Route(autoload=self.route_autoload)
        return self._route

    @property
    def route6(self) -> Any:
        """The IPv6 routing table, read from the OS on first use."""
        if self._route6 is None:
            from .route import Route6

            self._route6 = Route6(autoload=self.route6_autoload)
        return self._route6

    @property
    def use_pcap(self) -> bool:
        """Reports rather than chooses: libpcap is the only backend wiry has,
        and this is False only where it could not be loaded."""
        return capture_available()

    @use_pcap.setter
    def use_pcap(self, value: Any) -> None:
        if bool(value) != capture_available():
            raise NotImplementedError(
                "conf.use_pcap cannot be changed: libpcap is the only capture "
                "backend wiry has, and on this host it "
                + ("loaded" if capture_available()
                   else "could not be loaded. " + capture_backend()["reason"])
            )

    @property
    def l3socket(self) -> Any:
        """The class a state machine opens to send layer-3 datagrams.

        Set it to swap in your own; set it to ``None`` to go back to wiry's.
        ``send()`` and ``sr()`` open their own socket in Rust and do not read
        this; ``send(socket=...)`` is how to send through a socket object."""
        from .supersocket import L3Socket

        return self._l3socket or L3Socket

    @l3socket.setter
    def l3socket(self, value: Any) -> None:
        self._l3socket = value

    @property
    def l2socket(self) -> Any:
        """The class a state machine opens to send layer-2 frames."""
        from .supersocket import L2Socket

        return self._l2socket or L2Socket

    @l2socket.setter
    def l2socket(self, value: Any) -> None:
        self._l2socket = value

    @property
    def l2listen(self) -> Any:
        """The class a state machine opens to receive frames."""
        from .supersocket import L2ListenSocket

        return self._l2listen or L2ListenSocket

    @l2listen.setter
    def l2listen(self, value: Any) -> None:
        self._l2listen = value

    @property
    def ASN1_default_codec(self) -> Any:
        """The codec `bytes()` of a bare ASN.1 value encodes with."""
        if self._asn1_codec is None:
            from .asn1.asn1 import ASN1_Codecs

            self._asn1_codec = ASN1_Codecs.BER
        return self._asn1_codec

    @ASN1_default_codec.setter
    def ASN1_default_codec(self, value: Any) -> None:
        self._asn1_codec = value

    @property
    def mib(self) -> Any:
        """OID names, as `ASN1_OID` prints them."""
        if self._mib is None:
            from .asn1 import mib  # noqa: F401  (assigns conf.mib)
        return self._mib

    @mib.setter
    def mib(self, value: Any) -> None:
        self._mib = value

    # scapy's own spelling of the same three.
    L3socket = l3socket
    L2socket = l2socket
    L2listen = l2listen

    def __repr__(self) -> str:
        return (f"<conf iface={self._iface!r} verb={self.verb} "
                f"promisc={self.promisc} checkIPaddr={self.checkIPaddr}>")


conf = _Conf()
