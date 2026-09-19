"""Live capture and injection, plus the offline driver for ``sniff``.

Import cost is zero until one of these names is touched: ``wiry`` exports
them through its module ``__getattr__``.

``sniff`` runs one state machine whatever feeds it. Filters are ANDed cheapest
first: ``filter=`` (BPF, in the kernel's own bytecode) rejects a packet for
nothing, ``where=`` (a wiry extension, evaluated in Rust) rejects one before
it ever becomes a Python object, and only survivors reach ``lfilter=``.

Everything except ``sniff(offline=...)`` needs the live backend. Without it the
names still import and raise ``CaptureUnavailable``, which subclasses
``OSError``, so ``except OSError`` catches a failed library load too.
"""

from __future__ import annotations

import atexit
import math
import os
import threading
import warnings
import weakref
from typing import Any, Callable, Optional

from . import Packet, PacketList, _as_path, expand
from . import _wiry as _b
from .columnar import _normalize_where

CaptureUnavailable = _b.CaptureUnavailable

__all__ = [
    "sniff", "AsyncSniffer", "send", "sendp", "sr", "sr1", "srp", "srp1",
    "get_if_list", "get_if_addr", "get_if_hwaddr", "get_working_if", "conf",
    "capture_available", "CaptureUnavailable",
]


def capture_available() -> bool:
    """Whether this build can capture live traffic. Never raises."""
    return _b.capture_available()


def _iface_name(iface: Any) -> str:
    """The interface to work on: what was asked for, else ``conf.iface``."""
    return conf.iface if iface is None else str(iface)


def _wrap(rust: Any) -> Packet:
    return Packet(_rust=rust, time=rust.time, wirelen=rust.wirelen)


def _printing(prn: Optional[Callable], quiet: bool) -> Optional[Callable]:
    """Scapy prints whatever ``prn`` returns; ``quiet`` suppresses that."""
    if prn is None or quiet:
        return prn

    def show(pkt: Packet) -> None:
        out = prn(pkt)
        if out is not None:
            print(out)

    return show


def _offline_source(offline: Any) -> Any:
    if isinstance(offline, PacketList):
        return offline._list
    if isinstance(offline, (str, os.PathLike)):
        with _as_path(offline) as real:
            return _b.read_pcap(real)
    raise NotImplementedError(
        "offline= takes a capture file path or a PacketList; for a list of "
        "packets, write it with wrpcap() first"
    )


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
    return dict(
        iface=_iface_name(iface),
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
        wrap=_wrap,
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

    ``opened_socket=`` is refused: one state machine drives every source here,
    it lives in Rust, and reading a Python socket through it would mean a
    second one that could disagree. ``Automaton(recvsock=...)`` is the surface
    that listens on a socket object.
    """
    from .stream import as_session, bulk_hook

    if opened_socket is not None:
        raise NotImplementedError(
            "sniff(opened_socket=) is not supported: the sniff state machine "
            "is one implementation in Rust and a socket handed in from Python "
            "cannot feed it. Read the socket directly, or drive it with an "
            "Automaton, whose recvsock= takes exactly such an object"
        )

    session = as_session(session)
    bulk = bulk_hook(session)
    if offline is None:
        if bulk is not None:
            raise NotImplementedError(
                "session= needs the whole capture at once and so works with "
                "offline= only; sniff to a PacketList, then pass it back in"
            )
        _b.capture_check()
        args = _live_args(
            iface=iface, count=count, store=store, prn=prn, filter=filter,
            lfilter=lfilter, timeout=timeout, stop_filter=stop_filter,
            quiet=quiet, promisc=promisc, snaplen=snaplen, where=where,
        )
        _add_session(args, session, store)
        return PacketList(_b.sniff_live(**args))
    src = _offline_source(offline)
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
    return PacketList(src.sniff_offline(**offline_args))


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
        args["stop_filter"] = self._stopping(args.get("stop_filter"))
        try:
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
            if self.args.get("offline") is None:
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
                live = _b.LiveSniffer(**live_args)
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


def _with_src(pkt: Any, mac: Optional[str], ip: Optional[str] = None) -> Any:
    """Fill unset source addresses from the outgoing interface (E9).

    At send time only, and on a copy: ``bytes(Ether())`` stays reproducible and
    the build path stays free of the host it happens to run on. ``Ether.src``
    and ``ARP.hwsrc`` take the hardware address, ``ARP.psrc`` the interface's
    IPv4 address. Either may be ``None`` where the host will not say, and the
    field is then left alone, which is an ordinary outcome.

    A dissected packet has no field spec to fill, so it goes out as captured.
    """
    if not isinstance(pkt, Packet) or not pkt._stack:
        return pkt
    wanted = {"Ether": (("src", mac),), "ARP": (("hwsrc", mac), ("psrc", ip))}
    todo = [
        (i, field, value)
        for i, (name, fields) in enumerate(pkt._stack)
        for field, value in wanted.get(name, ())
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


def _refuse_unsupported(realtime: Any, socket: Any) -> None:
    if socket is not None:
        raise NotImplementedError(
            "socket= is not supported: there is no socket object to hand in"
        )
    if realtime:
        raise NotImplementedError(
            "realtime= is not supported; inter= paces the send instead"
        )


def send(x: Any, inter: float = 0, loop: int = 0, count: Optional[int] = None,
         verbose: Optional[int] = None, realtime: Optional[bool] = None,
         return_packets: bool = False, socket: Any = None,
         *, iface: Any = None, **kwargs: Any) -> Any:
    """Send layer-3 packets, letting the kernel route and frame them.

    IPv4 only: the raw socket writes datagrams with the header included, and
    IPv6 needs a second address family. ``loop`` repeats until interrupted.
    """
    _b.capture_check()
    _refuse_unsupported(realtime, socket)
    gap = _pause(inter)
    tmpl = x.template() if isinstance(x, Packet) else None
    if tmpl is not None:
        _refuse_ipv6([x], [tmpl.frame(0)], "send")
        sent = _b.send_template_l3(tmpl, _passes(count), gap, bool(loop))
        _report(sent, verbose)
        return [x] if return_packets else None
    pkts = _as_list(x)
    frames = [_octets(p) for p in pkts]
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
    _b.capture_check()
    _refuse_unsupported(realtime, socket)
    gap = _pause(inter)
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
        frames = [_octets(p) for p in pkts]
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
    that has no hardware address of its own — a loopback, a tunnel — raises
    rather than returning a plausible-looking zero.
    """
    _b.capture_check()
    name = _iface_name(iface)
    mac = _b.interface_mac(name)
    if mac is None:
        raise ValueError(f"{name} has no hardware address")
    return mac


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
                 "route6_autoload", "_iface", "_route", "_route6",
                 "_l3socket", "_l2socket", "_l2listen", "_loopback")

    def __init__(self) -> None:
        self.verb = 2
        # promisc is the sr family's default, sniff_promisc is sniff's.
        self.promisc = True
        self.sniff_promisc = True
        # False drops the address pinning in answers.rs: what DHCP needs, and a
        # looser match everywhere else.
        self.checkIPaddr = True
        # True makes a session's own failure raise instead of being reported and
        # skipped past; the dissector itself never raises, by design.
        self.debug_dissector = False
        # How long a state machine's select waits before looking at its timers.
        self.recv_poll_rate = 0.05
        self.route_autoload = True
        self.route6_autoload = True
        self._iface: Optional[str] = None
        self._route: Any = None
        self._route6: Any = None
        self._l3socket: Any = None
        self._l2socket: Any = None
        self._l2listen: Any = None
        self._loopback: Optional[str] = None

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
        and this is False only in a build without the ``live`` feature."""
        return capture_available()

    @use_pcap.setter
    def use_pcap(self, value: Any) -> None:
        if bool(value) != capture_available():
            raise NotImplementedError(
                "conf.use_pcap cannot be changed: libpcap is the only capture "
                "backend wiry has, and this build "
                + ("has it" if capture_available()
                   else "was built without the live feature")
            )

    @property
    def l3socket(self) -> Any:
        """The class a state machine opens to send layer-3 datagrams.

        Set it to swap in your own; set it to ``None`` to go back to wiry's.
        The send path of ``send()`` and ``sr()`` opens its own socket in Rust
        and does not read this, which is why ``send(socket=...)`` is still
        refused (E17)."""
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

    # scapy's own spelling of the same three.
    L3socket = l3socket
    L2socket = l2socket
    L2listen = l2listen

    def __repr__(self) -> str:
        return (f"<conf iface={self._iface!r} verb={self.verb} "
                f"promisc={self.promisc} checkIPaddr={self.checkIPaddr}>")


conf = _Conf()
