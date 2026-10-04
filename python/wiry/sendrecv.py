# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from scapy: scapy/sendrecv.py
#   scapy 2.7.0, upstream commit 7d69454
#   Copyright (C) Philippe Biondi <phil@secdev.org>
#   Copyright (C) the scapy contributors
#
# Changed by the wiry authors:
#   2026-10-03 — ported sndrcv, the flood functions, sendpfast,
#                bridge_and_sniff and tshark onto wiry's sockets; replies are
#                matched by wiry's Rust `answers` rather than hashret().

"""Send and receive over socket objects, and the functions built on that.

``sr``, ``srp`` and their kin live in `wiry.capture` and run the whole
exchange in Rust. ``sndrcv`` is the general form: any `SuperSocket` sends and
another (or the same) receives, which is what makes an exchange testable from
an `OfflineSocket` with no interface. Each reply is offered to the packets
still waiting by wiry's own reply matcher (``answers.rs``, E14), one crossing
per received packet.

The flood functions send the same packets over and over while receiving. On
wiry's live sockets the sending is a Rust loop, a batch of passes per
crossing; on any other socket it is one ``send`` per packet.
"""

from __future__ import annotations

import os
import re
import subprocess
import threading
import time
from typing import Any, Callable, Dict, Iterator, List, Optional

from . import Packet, wrpcap
from . import _wiry as _b
from .capture import _sniff_sockets, _socket_map, conf, sniff, sr1
from .error import log_interactive, log_runtime

__all__ = [
    "SndRcvHandler", "sndrcv", "sndrcvflood", "srflood", "sr1flood",
    "srpflood", "srp1flood", "sendpfast", "bridge_and_sniff", "tshark",
    "sr_func", "debug",
]


# A flood sends this many passes of its packets per crossing on a live socket:
# enough that the crossing disappears, few enough that a stop lands promptly.
_FLOOD_PASSES = 64


class debug:
    """What the last exchange received unmatched, sent, and matched, kept
    while ``conf.debug_match`` is true."""

    recv: list = []
    sent: list = []
    match: list = []
    crashed_on: Any = None


def _results(ans: list) -> Any:
    try:
        from .plist import QueryAnswer, SndRcvList
    except ImportError:
        return list(ans)
    return SndRcvList([QueryAnswer(s, r) for s, r in ans])


def _link(pkt: Any) -> str:
    if isinstance(pkt, Packet):
        names = pkt.layers()
        if names:
            return names[0]
    return "Raw"


def _frame_at(pkt: Any, link: str) -> Optional[bytes]:
    """The octets of ``pkt`` from its ``link`` layer on, or None if it has
    none: a frame captured at layer 2 answers a datagram sent at layer 3."""
    if not isinstance(pkt, Packet):
        return bytes(pkt) if isinstance(pkt, (bytes, bytearray)) else None
    names = pkt.layers()
    if not names or link not in names:
        return None
    at = names.index(link)
    frame = bytes(pkt)
    if at == 0:
        return frame
    # Read from the serialised octets: a packet still being built has not
    # computed its inner lengths and checksums yet.
    return _b.dissect(frame, names[0]).payload(at - 1)


class _Sent:
    __slots__ = ("pkt", "frame", "link", "answered")

    def __init__(self, pkt: Any):
        self.pkt = pkt
        self.frame = bytes(pkt)
        self.link = _link(pkt)
        self.answered = False


class _FloodGenerator:
    """The packets to flood, ``maxretries`` passes over or until stopped."""

    def __init__(self, tobesent: Any, maxretries: Optional[int]):
        self.tobesent = _packets(tobesent)
        self.maxretries = maxretries
        self.stopevent = threading.Event()
        self.iterlen = 0

    def passes_left(self, done: int) -> Optional[int]:
        return None if not self.maxretries else self.maxretries - done

    def __iter__(self) -> Iterator[Any]:
        done = 0
        while self.passes_left(done) is None or self.passes_left(done) > 0:
            j = 0
            for p in self.tobesent:
                if self.stopevent.is_set():
                    return
                j += 1
                yield p
            done += 1
            if self.iterlen == 0:
                self.iterlen = j

    def stop(self) -> None:
        self.stopevent.set()


def _packets(pkt: Any) -> list:
    if isinstance(pkt, Packet):
        return list(pkt)
    out = []
    for p in pkt:
        out.extend(p if isinstance(p, Packet) else [p])
    return out


class SndRcvHandler:
    """Send packets on one socket and pair what another receives with them.

    The arguments are scapy's. ``threaded`` sends on a thread while the
    caller's thread receives; unthreaded, everything is sent first and the
    receive follows, which is what a socket whose replies are already queued
    (an `OfflineSocket`) wants. ``retry=N`` resends the unanswered N more
    times, and a negative ``retry`` resends while each round answers at least
    one more. ``multi`` keeps a packet waiting after its first answer;
    ``first`` stops at the first answer to anything.
    """

    def __init__(self, pks: Any, pkt: Any, timeout: Optional[float] = None,
                 inter: float = 0, verbose: Optional[int] = None,
                 chainCC: bool = False, retry: int = 0, multi: bool = False,
                 first: bool = False, rcv_pks: Any = None,
                 prebuild: bool = False, _flood: Any = None,
                 threaded: bool = True, session: Any = None,
                 chainEX: bool = False,
                 stop_filter: Optional[Callable] = None):
        if verbose is None:
            verbose = conf.verb
        self.debug_match = bool(getattr(conf, "debug_match", False))
        if self.debug_match:
            debug.recv, debug.sent, debug.match = [], [], []
        self.nbrecv = 0
        self.ans: List[tuple] = []
        self.pks = pks
        self.rcv_pks = rcv_pks or pks
        self.inter = inter
        self.verbose = verbose
        self.chainCC = chainCC
        self.multi = multi
        self.timeout = None if timeout is not None and timeout < 0 else timeout
        self.first = first
        self.session = session
        self.chainEX = chainEX
        self.stop_filter = stop_filter
        self._flood = _flood
        self.threaded = threaded
        self._lock = threading.Lock()
        self._wire = getattr(pks, "_on_wire", None)
        self.tobesent: Any = pkt if _flood is not None else _packets(pkt)

        autostop = 0
        if retry < 0:
            autostop = retry = -retry

        remain: list = []
        while retry >= 0:
            self.hsent: List[_Sent] = []
            self.notans = 0
            self.noans = 0
            self._send_done = False
            self.breakout = threading.Event()
            self._run_round()
            if multi or _flood is not None:
                remain = [e.pkt for e in self.hsent if not e.answered]
            else:
                remain = [e.pkt for e in self.hsent]
            if autostop and remain and len(remain) != len(self.tobesent):
                retry = autostop
            self.tobesent = remain
            if not remain or _flood is not None:
                break
            retry -= 1

        if self.debug_match:
            debug.sent = list(remain)
            debug.match = list(self.ans)
        if verbose:
            print("\nReceived %i packets, got %i answers, remaining %i packets"
                  % (self.nbrecv + len(self.ans), len(self.ans),
                     max(0, self.notans - self.noans)))
        self.ans_result = _results(self.ans)
        self.unans_result = list(remain)

    def results(self) -> tuple:
        return self.ans_result, self.unans_result

    def _run_round(self) -> None:
        if self.threaded or self._flood is not None:
            snd = threading.Thread(target=self._sndrcv_snd, daemon=True)
            interrupted = None
            try:
                self._sndrcv_rcv(snd.start)
            except KeyboardInterrupt as exc:
                interrupted = exc
            self.breakout.set()
            if self._flood is not None:
                self._flood.stop()
            if snd.ident is not None:
                snd.join()
            if interrupted is not None and self.chainCC:
                raise interrupted
        else:
            try:
                self._sndrcv_rcv(self._sndrcv_snd)
            except KeyboardInterrupt:
                if self.chainCC:
                    raise

    def _settled(self) -> bool:
        return (self._send_done and self.noans >= self.notans
                and not self.multi) or bool(self.first and self.noans)

    def _stop_if_done(self) -> None:
        if self._settled():
            self.breakout.set()

    def _record(self, p: Any) -> Any:
        if self._wire is not None:
            p = self._wire(p)
        with self._lock:
            self.hsent.append(_Sent(p))
        return p

    def _sndrcv_snd(self) -> None:
        i = 0
        try:
            if self.verbose:
                print("Begin emission")
            if self._flood is not None and hasattr(self.pks, "send_many"):
                i = self._flood_bulk()
            elif self._flood is not None:
                i = self._flood_each()
            else:
                for p in self.tobesent:
                    p = self._record(p)
                    _stamp(p)
                    self.pks.send(p)
                    i += 1
                    if self.inter:
                        time.sleep(self.inter)
                    if self.breakout.is_set():
                        break
            if self.verbose:
                print("\nFinished sending %i packets" % i)
        except SystemExit:
            pass
        except Exception:
            if self.chainEX:
                raise
            log_runtime.exception("--- Error sending packets")
        finally:
            if self._flood is not None:
                self.notans = len(self.hsent)
            else:
                self.notans = i
            self._send_done = True
        self._stop_if_done()
        if self.threaded and self.timeout is not None \
                and not self.breakout.is_set():
            self.breakout.wait(timeout=self.timeout)
            self.breakout.set()

    def _flood_each(self) -> int:
        """One ``send`` per packet, for a socket with no bulk path."""
        flood = self._flood
        distinct = {}
        n = 0
        for p in flood:
            key = id(p)
            if key not in distinct:
                distinct[key] = self._record(p)
            wire = distinct[key]
            _stamp(wire)
            self.pks.send(wire)
            n += 1
            if self.inter:
                time.sleep(self.inter)
            if self.breakout.is_set():
                break
        return n

    def _flood_bulk(self) -> int:
        """Batches of passes, each one crossing into Rust's send loop."""
        flood = self._flood
        pkts = [self._record(p) for p in flood.tobesent]
        flood.iterlen = len(pkts)
        done = 0
        while not flood.stopevent.is_set() and not self.breakout.is_set():
            left = flood.passes_left(done)
            if left is not None and left <= 0:
                break
            passes = _FLOOD_PASSES if left is None else min(left, _FLOOD_PASSES)
            self.pks.send_many(pkts, passes, self.inter)
            done += passes
        return done * len(pkts)

    def _match(self, r: Any) -> Optional[_Sent]:
        waiting = [e for e in self.hsent if self.multi or self._flood is not None
                   or not e.answered]
        groups: Dict[str, List[_Sent]] = {}
        for e in waiting:
            groups.setdefault(e.link, []).append(e)
        for link, group in groups.items():
            frame = _frame_at(r, link)
            if frame is None:
                continue
            try:
                pairs, _ = _b.pair_replies(
                    [e.frame for e in group], [frame], link, False,
                    bool(conf.checkIPaddr))
            except ValueError:
                continue
            if pairs:
                return group[pairs[0][0]]
        return None

    def _process_packet(self, r: Any) -> None:
        if r is None:
            return
        with self._lock:
            hit = self._match(r)
            if hit is not None:
                self.ans.append((hit.pkt, r))
                if not hit.answered:
                    self.noans += 1
                hit.answered = True
                if not self.multi and self._flood is None:
                    self.hsent.remove(hit)
            else:
                self.nbrecv += 1
                if self.debug_match:
                    debug.recv.append(r)
        if self.verbose > 1:
            print("*" if hit is not None else ".", end="", flush=True)
        self._stop_if_done()

    def _sndrcv_rcv(self, callback: Callable[[], None]) -> None:
        if isinstance(self.rcv_pks, (dict, list, tuple)):
            socks = _socket_map(self.rcv_pks)
        else:
            socks = {self.rcv_pks: "socket0"}
        threaded = self.threaded and self._flood is None
        _sniff_sockets(
            socks, store=False, prn=self._process_packet,
            timeout=None if threaded else self.timeout,
            session=self.session, stop_filter=self.stop_filter,
            started_callback=callback, stop_event=self.breakout,
        )


def _stamp(p: Any) -> None:
    try:
        p.sent_time = time.time()
    except AttributeError:
        pass


def sndrcv(*args: Any, **kwargs: Any) -> tuple:
    """Send packets on a socket and return ``(answered, unanswered)``.

    The general form of ``sr``: see `SndRcvHandler` for the arguments.
    """
    return SndRcvHandler(*args, **kwargs).results()


def sndrcvflood(pks: Any, pkt: Any, inter: float = 0,
                maxretries: Optional[int] = None,
                verbose: Optional[int] = None, chainCC: bool = False,
                timeout: Optional[float] = None) -> tuple:
    """`sndrcv`, sending the packets over and over until ``timeout``, an
    interrupt, or ``maxretries`` passes. Every answer to any pass is kept;
    ``unanswered`` holds each packet nothing ever answered, once."""
    flood = _FloodGenerator(pkt, maxretries)
    return sndrcv(pks, flood, inter=inter, verbose=verbose, chainCC=chainCC,
                  timeout=timeout, _flood=flood)


def _flood_on(sock: Any, x: Any, args: tuple, kargs: dict) -> tuple:
    try:
        return sndrcvflood(sock, x, *args, **kargs)
    finally:
        sock.close()


def srflood(x: Any, promisc: Any = None, filter: Optional[str] = None,
            iface: Any = None, nofilter: Any = None, *args: Any,
            **kargs: Any) -> tuple:
    """Flood at layer 3 and collect the answers. See `sndrcvflood`."""
    sock = conf.l3socket(promisc=promisc, filter=filter, iface=iface,
                         nofilter=nofilter)
    return _flood_on(sock, x, args, kargs)


def sr1flood(x: Any, promisc: Any = None, filter: Optional[str] = None,
             iface: Any = None, nofilter: int = 0, *args: Any,
             **kargs: Any) -> Any:
    """`srflood`, returning the first answer or None."""
    ans, _ = srflood(x, promisc, filter, iface, nofilter, *args, **kargs)
    return ans[0][1] if len(ans) > 0 else None


def srpflood(x: Any, promisc: Any = None, filter: Optional[str] = None,
             iface: Any = None, iface_hint: Optional[str] = None,
             nofilter: Any = None, *args: Any, **kargs: Any) -> tuple:
    """Flood at layer 2 and collect the answers. See `sndrcvflood`."""
    if iface is None and iface_hint is not None:
        iface = conf.route.route(iface_hint)[0]
    sock = conf.l2socket(promisc=promisc, filter=filter, iface=iface,
                         nofilter=nofilter)
    return _flood_on(sock, x, args, kargs)


def srp1flood(x: Any, promisc: Any = None, filter: Optional[str] = None,
              iface: Any = None, nofilter: int = 0, *args: Any,
              **kargs: Any) -> Any:
    """`srpflood`, returning the first answer or None."""
    sock = conf.l2socket(promisc=promisc, filter=filter, iface=iface,
                         nofilter=nofilter)
    ans, _ = _flood_on(sock, x, args, kargs)
    return ans[0][1] if len(ans) > 0 else None


# scapy's name leaks out of the loop that documents sr, srp, sr1 and srp1,
# and is left holding the last of them.
sr_func = sr1


def sendpfast(x: Any, pps: Optional[float] = None,
              mbps: Optional[float] = None, realtime: Any = False,
              count: Optional[int] = None, loop: int = 0,
              file_cache: bool = False, iface: Any = None,
              replay_args: Optional[List[str]] = None,
              parse_results: bool = False) -> Optional[dict]:
    """Send packets at layer 2 through tcpreplay, as fast as it goes.

    tcpreplay is not a dependency. Where it is missing this logs ``Could not
    execute ..., is it installed?`` and returns None, as scapy's does.
    ``realtime`` is a speed multiplier over the packets' own timestamps.
    """
    from .external import ContextManagerSubprocess, _temp_file

    if iface is None:
        iface = conf.iface
    argv = [conf.prog.tcpreplay, "--intf1=%s" % iface]
    if pps is not None:
        argv.append("--pps=%f" % pps)
    elif mbps is not None:
        argv.append("--mbps=%f" % mbps)
    elif realtime:
        argv.append("--multiplier=%f" % realtime)
    else:
        argv.append("--topspeed")
    if count:
        if loop:
            raise ValueError("Can't use loop and count at the same time in "
                             "sendpfast")
        argv.append("--loop=%i" % count)
    elif loop:
        argv.append("--loop=0")
    if file_cache:
        argv.append("--preload-pcap")
    if replay_args is not None:
        argv.extend(replay_args)

    path = _temp_file()
    argv.append(path)
    wrpcap(path, x)
    results = None
    try:
        with ContextManagerSubprocess(conf.prog.tcpreplay):
            cmd = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
            try:
                stdout, stderr = cmd.communicate()
            except KeyboardInterrupt:
                cmd.terminate()
                stdout, stderr = cmd.communicate()
                log_interactive.info("Interrupted by user")
            if stderr:
                log_runtime.warning(stderr.decode(errors="replace"))
            if parse_results:
                results = _parse_tcpreplay_result(stdout, stderr, argv)
            elif conf.verb > 2:
                log_runtime.info(stdout.decode(errors="replace"))
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    return results


def _parse_tcpreplay_result(stdout_b: Any, stderr_b: Any,
                            argv: List[str]) -> dict:
    """tcpreplay's summary as a dict, as scapy reads versions 3.4 and 4.x."""
    try:
        results: Dict[str, Any] = {}
        stdout = _text(stdout_b).lower()
        stderr = _text(stderr_b).strip().split("\n")
        elements = {
            "actual": (int, int, float),
            "rated": (float, float, float),
            "flows": (int, float, int, int),
            "attempted": (int,),
            "successful": (int,),
            "failed": (int,),
            "truncated": (int,),
            "retried packets (eno": (int,),
            "retried packets (eag": (int,),
        }
        multi = {
            "actual": ("packets", "bytes", "time"),
            "rated": ("bps", "mbps", "pps"),
            "flows": ("flows", "fps", "flow_packets", "non_flow"),
            "retried packets (eno": ("retried_enobufs",),
            "retried packets (eag": ("retried_eagain",),
        }
        float_reg = r"([0-9]*\.[0-9]+|[0-9]+)"
        int_reg = r"([0-9]+)"
        any_reg = r"[^0-9]*"
        r_types = {int: int_reg, float: float_reg}
        for line in stdout.split("\n"):
            line = line.strip()
            for elt, types in elements.items():
                if line.startswith(elt):
                    regex = any_reg.join([r_types[t] for t in types])
                    matches = re.search(regex, line)
                    for i, typ in enumerate(types):
                        name = multi.get(elt, [elt])[i]
                        if matches:
                            results[name] = typ(matches.group(i + 1))
        results["command"] = " ".join(argv)
        results["warnings"] = stderr[:-1]
        return results
    except Exception as exc:
        if not conf.interactive:
            raise
        log_runtime.error("Error parsing output: %s", exc)
        return {}


def _text(x: Any) -> str:
    return x.decode(errors="replace") if isinstance(x, bytes) else str(x)


def bridge_and_sniff(if1: Any, if2: Any, xfrm12: Optional[Callable] = None,
                     xfrm21: Optional[Callable] = None,
                     prn: Optional[Callable] = None, L2socket: Any = None,
                     *args: Any, **kargs: Any) -> Any:
    """Forward frames between two interfaces, or two open sockets, and
    return what crossed.

    ``xfrm12`` sees each frame going from ``if1`` to ``if2`` and returns True
    to forward it as it is, a false value to drop it, or a packet to forward
    instead; ``xfrm21`` the same the other way. The rest is ``sniff``'s.
    """
    for arg in ("opened_socket", "offline", "iface"):
        if arg in kargs:
            log_runtime.warning("Argument %s cannot be used in "
                                "bridge_and_sniff() -- ignoring it.", arg)
            del kargs[arg]

    opened: list = []

    def open_one(iface: Any, n: int) -> tuple:
        from .supersocket import SuperSocket

        if isinstance(iface, SuperSocket):
            return iface, "iface%d" % n
        cls = L2socket or conf.l2socket
        sock = cls(iface=iface or conf.iface)
        opened.append(sock)
        return sock, iface

    sock1, if1 = open_one(if1, 1)
    sock2, if2 = open_one(if2, 2)
    peers = {if1: sock2, if2: sock1}
    xfrms = {}
    if xfrm12 is not None:
        xfrms[if1] = xfrm12
    if xfrm21 is not None:
        xfrms[if2] = xfrm21

    def forward(pkt: Any) -> None:
        sendsock = peers.get(pkt.sniffed_on or "")
        if sendsock is None:
            return
        newpkt = pkt
        if pkt.sniffed_on in xfrms:
            try:
                out = xfrms[pkt.sniffed_on](pkt)
            except Exception:
                log_runtime.warning(
                    "Exception in transformation function for packet [%s] "
                    "received on %s -- dropping",
                    pkt.summary(), pkt.sniffed_on, exc_info=True)
                return
            if isinstance(out, bool):
                if not out:
                    return
            elif not out:
                return
            else:
                newpkt = out
        try:
            sendsock.send(newpkt)
        except Exception:
            log_runtime.warning("Cannot forward packet [%s] received on %s",
                                pkt.summary(), pkt.sniffed_on, exc_info=True)

    if prn is None:
        callback = forward
    else:
        def callback(pkt: Any) -> Any:
            forward(pkt)
            return prn(pkt)

    try:
        return sniff(*args, opened_socket={sock1: if1, sock2: if2},
                     prn=callback, **kargs)
    finally:
        for sock in opened:
            sock.close()


def tshark(*args: Any, **kargs: Any) -> None:
    """Sniff and print one summary line per packet, as tshark does."""
    if "iface" in kargs:
        iface = kargs.get("iface")
    elif "opened_socket" in kargs:
        iface = getattr(kargs.get("opened_socket"), "iface", None)
    else:
        iface = conf.iface
    print("Capturing on '%s'" % iface)
    n = [0]

    def show(pkt: Any) -> None:
        print("%5d\t%s" % (n[0], pkt.summary()))
        n[0] += 1

    sniff(*args, prn=show, store=False, **kargs)
    print("\n%d packet%s captured" % (n[0], "s" if n[0] > 1 else ""))
