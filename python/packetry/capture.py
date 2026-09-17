"""Live capture and injection, plus the offline driver for ``sniff``.

Import cost is zero until one of these names is touched: ``packetry`` exports
them through its module ``__getattr__``.

``sniff`` runs one state machine whatever feeds it. Filters are ANDed cheapest
first: ``filter=`` (BPF, in the kernel's own bytecode) rejects a packet for
nothing, ``where=`` (a packetry extension, evaluated in Rust) rejects one before
it ever becomes a Python object, and only survivors reach ``lfilter=``.

Everything except ``sniff(offline=...)`` needs the live backend. Without it the
names still import and raise ``CaptureUnavailable``, which subclasses
``OSError``, so ``except OSError`` catches a failed library load too.
"""

from __future__ import annotations

import os
import threading
from typing import Any, Callable, Optional

from . import Packet, PacketList
from . import _packetry as _b
from .columnar import _normalize_where

CaptureUnavailable = _b.CaptureUnavailable

__all__ = [
    "sniff", "AsyncSniffer", "send", "sendp", "sr", "sr1", "srp", "srp1",
    "get_if_list", "get_if_addr", "get_working_if", "conf",
    "capture_available", "CaptureUnavailable",
]


def capture_available() -> bool:
    """Whether this build can capture live traffic. Never raises."""
    return _b.capture_available()


def _live_only(what: str) -> None:
    """Refuse an operation that has no offline meaning. Raises
    ``CaptureUnavailable`` when the backend is missing, and ``NotImplementedError``
    when it is present but this driver is not written yet."""
    _b.capture_check()
    raise NotImplementedError(
        f"{what} needs the live driver, which this build does not have yet. "
        "Offline work goes through rdpcap(), wrpcap() and sniff(offline=...)."
    )


def _iface_name(iface: Any) -> str:
    """The interface to work on: what was asked for, else ``conf.iface``."""
    return conf.iface if iface is None else str(iface)


def _wrap(rust: Any) -> Packet:
    return Packet(_rust=rust, time=rust.time)


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
        return _b.read_pcap(str(offline))
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
    promisc: bool = True,
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
        promisc=bool(promisc),
        snaplen=int(snaplen),
        prn=_printing(prn, quiet),
        lfilter=lfilter,
        stop_filter=stop_filter,
        wrap=_wrap,
    )


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
    promisc: bool = True,
    snaplen: int = 262144,
    where: Any = None,
) -> PacketList:
    """Capture packets, or replay a capture file through the same machine.

    ``count=0`` is unbounded and ``store=0`` returns an empty ``PacketList``.
    ``timeout`` is a wall-clock deadline for the whole call, not libpcap's read
    timeout. ``where=`` is a packetry extension, keyword-only: the same Rust-side
    query ``PacketList.filter(where=...)`` takes, so a packet it rejects is never
    built as a Python object.

    ``iface``, ``promisc`` and ``snaplen`` are ignored when ``offline`` is given,
    as scapy ignores them.
    """
    if offline is None:
        _b.capture_check()
        return PacketList(_b.sniff_live(**_live_args(
            iface=iface, count=count, store=store, prn=prn, filter=filter,
            lfilter=lfilter, timeout=timeout, stop_filter=stop_filter,
            quiet=quiet, promisc=promisc, snaplen=snaplen, where=where,
        )))
    src = _offline_source(offline)
    return PacketList(
        src.sniff_offline(
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
    )


class AsyncSniffer:
    """``sniff`` on a background thread, with the familiar start/stop/join.

    ``.results`` holds the ``PacketList`` once the run ends. ``stop()`` is
    honoured between packets, so it works on the offline driver too.
    """

    __slots__ = ("args", "results", "_thread", "_stop", "_exc")

    def __init__(self, **kwargs: Any):
        self.args = kwargs
        self.results: Optional[PacketList] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._exc: Optional[BaseException] = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

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
            self.results = sniff(**args)
        except BaseException as exc:  # re-raised out of join()
            self._exc = exc

    def start(self) -> "AsyncSniffer":
        if self.running:
            raise RuntimeError("this sniffer is already running")
        self._stop.clear()
        self._exc = None
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def join(self, timeout: Optional[float] = None) -> Optional[PacketList]:
        if self._thread is not None:
            self._thread.join(timeout)
        if self._exc is not None:
            raise self._exc
        return self.results

    def stop(self, join: bool = True) -> Optional[PacketList]:
        self._stop.set()
        if join:
            return self.join()
        return self.results


def send(x: Any, inter: float = 0, loop: int = 0, count: Optional[int] = None,
         verbose: Optional[int] = None, realtime: Optional[bool] = None,
         return_packets: bool = False, socket: Any = None,
         *, iface: Any = None, **kwargs: Any) -> Any:
    """Send layer-3 packets, letting the kernel route and frame them."""
    _live_only("send()")


def sendp(x: Any, inter: float = 0, loop: int = 0, iface: Any = None,
          iface_hint: Any = None, count: Optional[int] = None,
          verbose: Optional[int] = None, realtime: Optional[bool] = None,
          return_packets: bool = False, socket: Any = None,
          **kwargs: Any) -> Any:
    """Send layer-2 frames exactly as given, on one interface."""
    _live_only("sendp()")


def sr(x: Any, promisc: Optional[bool] = None, filter: Optional[str] = None,
       iface: Any = None, nofilter: int = 0, *args: Any, **kwargs: Any) -> Any:
    """Send layer-3 packets and collect (answered, unanswered)."""
    _live_only("sr()")


def sr1(x: Any, promisc: Optional[bool] = None, filter: Optional[str] = None,
        iface: Any = None, nofilter: int = 0, *args: Any, **kwargs: Any) -> Any:
    """Send layer-3 packets and return the first answer, or None."""
    _live_only("sr1()")


def srp(x: Any, promisc: Optional[bool] = None, iface: Any = None,
        iface_hint: Any = None, filter: Optional[str] = None,
        nofilter: int = 0, type: int = 3, *args: Any, **kwargs: Any) -> Any:
    """Send layer-2 frames and collect (answered, unanswered)."""
    _live_only("srp()")


def srp1(x: Any, promisc: Optional[bool] = None, iface: Any = None,
         iface_hint: Any = None, filter: Optional[str] = None,
         nofilter: int = 0, type: int = 3, *args: Any, **kwargs: Any) -> Any:
    """Send layer-2 frames and return the first answer, or None."""
    _live_only("srp1()")


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


def get_working_if() -> str:
    """The interface libpcap would pick by default."""
    return _b.default_interface()


def interfaces() -> list:
    """Every interface with its description, addresses and loopback flag."""
    return list(_b.list_interfaces())


class _Conf:
    """A deliberately small stand-in for scapy's ``conf``: the interface the
    capture API defaults to, and the verbosity the send helpers read."""

    __slots__ = ("verb", "_iface")

    def __init__(self) -> None:
        self.verb = 2
        self._iface: Optional[str] = None

    @property
    def iface(self) -> str:
        """Resolved on first read, so importing never touches the backend."""
        if self._iface is None:
            self._iface = get_working_if()
        return self._iface

    @iface.setter
    def iface(self, value: Any) -> None:
        self._iface = None if value is None else str(value)

    def __repr__(self) -> str:
        return f"<conf iface={self._iface!r} verb={self.verb}>"


conf = _Conf()
