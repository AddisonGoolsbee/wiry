# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from scapy: scapy/ansmachine.py
#   scapy 2.7.0, upstream commit 7d69454
#   Copyright (C) Philippe Biondi <phil@secdev.org>
#   Copyright (C) the scapy contributors
#
# Changed by the wiry authors:
#   2026-09-18 — ported onto wiry's sniff/sendp and given an offline= route so
#                a machine's replies can be checked from canned packets.

"""Answering machines: listen for a request, build a reply, send it.

The same shape as `Automaton` and the same contract — a callback per packet,
which is what this is for — but without states. Subclass, say what counts as a
request and what the reply is, and call the instance.

``offline=`` replays a capture through the same code with nothing sent, so
``make_reply`` and ``is_request`` are testable with no interface.
"""

from __future__ import annotations

import abc
import socket
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple

__all__ = ["AnsweringMachine", "AnsweringMachineTCP", "AnsweringMachineUDP"]


class ReferenceAM(abc.ABCMeta):
    """Publishes an answering machine under its ``function_name`` as well, so
    ``ARP_am()`` and ``farpd()`` both reach it, as scapy's do."""

    def __new__(cls, name: str, bases: Tuple[type, ...], dct: Dict[str, Any]):
        obj = super().__new__(cls, name, bases, dct)
        try:
            import inspect
            obj.__signature__ = inspect.signature(obj.parse_options)
        except (ImportError, AttributeError, ValueError):
            pass
        if obj.function_name:
            def func(*args: Any, _cls: Any = obj, **kargs: Any) -> Any:
                return _cls(*args, **kargs)()
            func.__name__ = func.__qualname__ = obj.function_name
            func.__doc__ = obj.__doc__ or obj.parse_options.__doc__
            globals()[obj.function_name] = func
        return obj


class AnsweringMachine(metaclass=ReferenceAM):
    """Reply to every request that arrives.

    Subclasses set ``filter`` (a BPF expression), and override ``is_request``
    and ``make_reply``. Calling the instance sniffs and answers until
    interrupted; ``bg=True`` does it on a background sniffer, which stops on
    ``.sniffer.stop()``.
    """

    function_name = ""
    filter: Optional[str] = None
    sniff_options: Dict[str, Any] = {"store": 0}
    sniff_options_list = ["store", "iface", "count", "promisc", "filter",
                          "type", "prn", "stop_filter", "offline", "where",
                          "timeout", "quiet"]
    send_options: Dict[str, Any] = {"verbose": 0}
    send_options_list = ["iface", "inter", "loop", "verbose"]
    send_function: Any = None

    def __init__(self, **kargs: Any):
        from .capture import conf

        self.mode = 0
        self.verbose = kargs.get("verbose", conf.verb >= 0)
        if self.filter:
            kargs.setdefault("filter", self.filter)
        kargs.setdefault("prn", self.reply)
        self.optam1: Dict[str, Any] = {}
        self.optam2: Dict[str, Any] = {}
        self.optam0: Dict[str, Any] = {}
        doptsend, doptsniff = self.parse_all_options(1, kargs)
        self.defoptsend = self.send_options.copy()
        self.defoptsend.update(doptsend)
        self.defoptsniff = self.sniff_options.copy()
        self.defoptsniff.update(doptsniff)
        self.optsend: Dict[str, Any] = {}
        self.optsniff: Dict[str, Any] = {}

    def __getattr__(self, attr: str) -> Any:
        for dct in (self.__dict__.get("optam2", {}),
                    self.__dict__.get("optam1", {})):
            if attr in dct:
                return dct[attr]
        raise AttributeError(attr)

    def __setattr__(self, attr: str, val: Any) -> None:
        mode = self.__dict__.get("mode", 0)
        if mode == 0:
            self.__dict__[attr] = val
        else:
            [self.optam1, self.optam2][mode - 1][attr] = val

    def parse_options(self) -> None:
        """Where a subclass names its own keywords."""

    def parse_all_options(self, mode: int,
                          kargs: Dict[str, Any]) -> Tuple[Dict, Dict]:
        sniffopt: Dict[str, Any] = {}
        sendopt: Dict[str, Any] = {}
        for k in list(kargs):  # kargs is modified in the loop
            if k in self.sniff_options_list:
                sniffopt[k] = kargs[k]
            if k in self.send_options_list:
                sendopt[k] = kargs[k]
            if k in self.sniff_options_list + self.send_options_list:
                del kargs[k]
        if mode != 2 or kargs:
            if mode == 1:
                self.optam0 = kargs
            elif mode == 2 and kargs:
                k = self.optam0.copy()
                k.update(kargs)
                self.parse_options(**k)
                kargs = k
            omode = self.__dict__.get("mode", 0)
            self.__dict__["mode"] = mode
            self.parse_options(**kargs)
            self.__dict__["mode"] = omode
        return sendopt, sniffopt

    def is_request(self, req: Any) -> Any:
        """Whether this packet is one to answer. The BPF ``filter`` has already
        had its say; this is the part that needs the dissected packet."""
        return True

    @abc.abstractmethod
    def make_reply(self, req: Any) -> Any:
        """The reply to a request, or a false value for no reply."""

    def send_reply(self, reply: Any,
                   send_function: Optional[Callable] = None) -> None:
        if send_function:
            send_function(reply)
            return
        send = self.send_function
        if send is None:
            from .capture import sendp
            send = sendp
        send(reply, **self.optsend)

    def print_reply(self, req: Any, reply: Any) -> None:
        if isinstance(reply, (list, tuple)):
            print("%s ==> %s" % (req.summary(), [r.summary() for r in reply]))
        else:
            print("%s ==> %s" % (req.summary(), reply.summary()))

    def reply(self, pkt: Any, send_function: Optional[Callable] = None,
              address: Any = None) -> None:
        if not self.is_request(pkt):
            return
        if address:  # only AnsweringMachineTCP passes one
            reply = self.make_reply(pkt, address=address)
        else:
            reply = self.make_reply(pkt)
        if not reply:
            return
        self.send_reply(reply, send_function=send_function)
        if self.verbose:
            self.print_reply(pkt, reply)

    def replies_to(self, packets: Any) -> List[Any]:
        """Every reply a capture would have drawn, without sending any.

        The whole point of separating ``is_request`` from the sending: what a
        machine answers is arithmetic over packets and is checkable offline.
        """
        out: List[Any] = []
        self.optsend = self.defoptsend.copy()
        for pkt in packets:
            self.reply(pkt, send_function=out.append)
        return out

    def bg(self, *args: Any, **kwargs: Any) -> Any:
        kwargs.setdefault("bg", True)
        self(*args, **kwargs)
        return self.sniffer

    def __call__(self, *args: Any, **kargs: Any) -> None:
        bg = kargs.pop("bg", False)
        optsend, optsniff = self.parse_all_options(2, kargs)
        self.optsend = self.defoptsend.copy()
        self.optsend.update(optsend)
        self.optsniff = self.defoptsniff.copy()
        self.optsniff.update(optsniff)

        if bg:
            self.sniff_bg()
        else:
            try:
                self.sniff()
            except KeyboardInterrupt:
                print("Interrupted by user")

    def sniff(self) -> None:
        from .capture import sniff

        sniff(**self.optsniff)

    def sniff_bg(self) -> None:
        from .capture import AsyncSniffer

        self.sniffer = AsyncSniffer(**self.optsniff)
        self.sniffer.start()


class AnsweringMachineTCP(AnsweringMachine):
    """An answering machine over ordinary TCP sockets, one sniffer per client."""

    TYPE = socket.SOCK_STREAM

    def parse_options(self, port: int = 80, cls: Any = None) -> None:
        self.port = port
        self.cls = cls

    def close(self) -> None:
        pass

    def make_reply(self, req: Any, address: Any = None) -> Any:
        return req

    def _serve(self, sock: Any, address: Any) -> None:
        try:
            while True:
                self.reply(sock.recv(), send_function=sock.send,
                           address=address)
        except (EOFError, OSError):
            pass
        finally:
            sock.close()

    def sniff(self) -> None:
        """Accept clients and answer each one on its own thread.

        This reads the client socket directly rather than going through
        ``sniff``: the source is a stream, not an interface, and wiry's capture
        backend does not take a socket handed in from Python.
        """
        from .capture import conf, get_if_addr
        from .supersocket import StreamSocket

        ssock = socket.socket(socket.AF_INET, self.TYPE)
        try:
            ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except OSError:
            pass
        ssock.bind((get_if_addr(self.optsniff.get("iface", conf.iface)),
                    self.port))
        ssock.listen()
        clients: List[Any] = []
        try:
            while True:
                clientsocket, address = ssock.accept()
                sock = StreamSocket(clientsocket, self.cls)
                clients.append(sock)
                threading.Thread(target=self._serve, args=(sock, address),
                                 daemon=True).start()
        except (KeyboardInterrupt, OSError):
            pass
        finally:
            for sock in clients:
                sock.close()
            self.close()
            ssock.close()

    def sniff_bg(self) -> None:
        self.sniffer = threading.Thread(target=self.sniff, daemon=True)
        self.sniffer.start()


class AnsweringMachineUDP(AnsweringMachineTCP):
    """The same, over UDP."""

    TYPE = socket.SOCK_DGRAM
