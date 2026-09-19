# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from scapy: scapy/automaton.py
#   scapy 2.7.0, upstream commit 7d69454
#   Copyright (C) Philippe Biondi <phil@secdev.org>
#   Copyright (C) Gabriel Potter
#   Copyright (C) the scapy contributors
#
# Changed by the wiry authors:
#   2026-09-18 — ported onto wiry's sockets and conf, `packets` collected as a
#                plain list because wiry's PacketList is a view over a capture
#                buffer, graph() returns DOT source, and a run is registered so
#                the interpreter never finalises with a control thread live.

"""State machines: states, transitions, timeouts and actions.

This is how a protocol gets written on top of a packet library. A state is a
method, a transition is a method that raises the next state, and an action runs
on the way across.

``Automaton`` is callback-driven and per-packet by contract, exactly as
``sniff``'s ``prn`` is, and the crossing is the feature rather than a cost to
engineer away. That reasoning stops here: it is no licence to put Python in a
bulk path.

Nothing about a state machine needs a wire. Pass ``recvsock=`` an
``OfflineSocket`` and the whole thing — transitions, timers, replies — runs off
a capture file with no interface and no privileges.
"""

from __future__ import annotations

import atexit
import itertools
import logging
import socket
import sys
import threading
import time
import traceback
import weakref
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from .supersocket import (
    MTU,
    ObjectPipe,
    StreamSocket,
    SuperSocket,
    select_objects,
)

__all__ = ["ATMT", "Automaton", "Message", "Timer", "ObjectPipe",
           "select_objects", "SuperSocket"]

log = logging.getLogger("wiry.automaton")


class Message:
    type: str = ""
    pkt: Any = None
    result: Any = None
    state: Any = None
    exc_info: Any = None

    def __init__(self, **args: Any):
        self.__dict__.update(args)

    def __repr__(self) -> str:
        return "<Message %s>" % " ".join(
            f"{k}={v!r}" for k, v in self.__dict__.items()
            if not k.startswith("_"))


class Timer:
    def __init__(self, time: float, prio: int = 0, autoreload: bool = False):
        self._timeout = float(time)
        self._time = 0.0
        self._just_expired = True
        self._expired = True
        self._prio = prio
        self._func: Any = None
        self._autoreload = autoreload

    def get(self) -> float:
        return self._timeout

    def set(self, val: float) -> None:
        self._timeout = val

    def _reset(self) -> None:
        self._time = self._timeout
        self._expired = False
        self._just_expired = False

    def _reset_just_expired(self) -> None:
        self._just_expired = False

    def _running(self) -> bool:
        return self._time > 0

    def _remaining(self) -> float:
        return max(self._time, 0)

    def _decrement(self, elapsed: float) -> None:
        self._time -= elapsed
        if self._time <= 0 and not self._expired:
            self._just_expired = True
            if self._autoreload:
                self._time = self._timeout + self._time  # keep the overshoot
            else:
                self._expired = True
                self._time = 0

    def __lt__(self, obj: "Timer") -> bool:
        return (self._time < obj._time if self._time != obj._time
                else self._prio < obj._prio)

    def __gt__(self, obj: "Timer") -> bool:
        return (self._time > obj._time if self._time != obj._time
                else self._prio > obj._prio)

    def __eq__(self, obj: object) -> bool:
        if not isinstance(obj, Timer):
            return NotImplemented
        return self._time == obj._time and self._prio == obj._prio

    def __hash__(self) -> int:
        return id(self)

    def __repr__(self) -> str:
        return "<Timer %f(%f)>" % (self._time, self._timeout)


class _TimerList:
    def __init__(self) -> None:
        self.timers: List[Timer] = []

    def add_timer(self, timer: Timer) -> None:
        self.timers.append(timer)

    def reset(self) -> None:
        for t in self.timers:
            t._reset()

    def decrement(self, elapsed: float) -> None:
        for t in self.timers:
            t._decrement(elapsed)

    def expired(self) -> List[Timer]:
        lst = [t for t in self.timers if t._just_expired]
        lst.sort(key=lambda x: x._prio, reverse=True)
        for t in lst:
            t._reset_just_expired()
        return lst

    def until_next(self) -> Optional[float]:
        running = [t._remaining() for t in self.timers if t._running()]
        return min(running) if running else None  # None blocks

    def count(self) -> int:
        return len(self.timers)

    def __iter__(self) -> Iterator[Timer]:
        return iter(self.timers)

    def __repr__(self) -> str:
        return repr(self.timers)


class _instance_state:
    def __init__(self, instance: Any):
        self.__self__ = instance.__self__
        self.__func__ = instance.__func__
        self.__self__.__class__ = instance.__self__.__class__

    def __getattr__(self, attr: str) -> Any:
        return getattr(self.__func__, attr)

    def __call__(self, *args: Any, **kargs: Any) -> Any:
        return self.__func__(self.__self__, *args, **kargs)

    def breaks(self) -> Any:
        return self.__self__.add_breakpoints(self.__func__)

    def intercepts(self) -> Any:
        return self.__self__.add_interception_points(self.__func__)

    def unbreaks(self) -> Any:
        return self.__self__.remove_breakpoints(self.__func__)

    def unintercepts(self) -> Any:
        return self.__self__.remove_interception_points(self.__func__)


class ATMT:
    """The decorators a state machine is written with."""

    STATE = "State"
    ACTION = "Action"
    CONDITION = "Condition"
    RECV = "Receive condition"
    TIMEOUT = "Timeout condition"
    EOF = "EOF condition"
    IOEVENT = "I/O event"

    class NewStateRequested(Exception):
        """Raised to move: a transition names its next state by raising it."""

        def __init__(self, state_func: Any, automaton: Any, *args: Any,
                     **kargs: Any):
            self.func = state_func
            self.state = state_func.atmt_state
            self.initial = state_func.atmt_initial
            self.error = state_func.atmt_error
            self.stop = state_func.atmt_stop
            self.final = state_func.atmt_final
            Exception.__init__(self, "Request state [%s]" % self.state)
            self.automaton = automaton
            self.args = args
            self.kargs = kargs
            self.action_parameters()

        def action_parameters(self, *args: Any,
                              **kargs: Any) -> "ATMT.NewStateRequested":
            self.action_args = args
            self.action_kargs = kargs
            return self

        def run(self) -> Any:
            return self.func(self.automaton, *self.args, **self.kargs)

        def __repr__(self) -> str:
            return "NewStateRequested(%s)" % self.state

    @staticmethod
    def state(initial: int = 0, final: int = 0, stop: int = 0,
              error: int = 0) -> Callable:
        def deco(f, initial=initial, final=final):
            f.atmt_type = ATMT.STATE
            f.atmt_state = f.__name__
            f.atmt_initial = initial
            f.atmt_final = final
            f.atmt_stop = stop
            f.atmt_error = error

            def _state_wrapper(self, *args, **kargs):
                return ATMT.NewStateRequested(f, self, *args, **kargs)

            _state_wrapper.__name__ = "%s_wrapper" % f.__name__
            _state_wrapper.atmt_type = ATMT.STATE
            _state_wrapper.atmt_state = f.__name__
            _state_wrapper.atmt_initial = initial
            _state_wrapper.atmt_final = final
            _state_wrapper.atmt_stop = stop
            _state_wrapper.atmt_error = error
            _state_wrapper.atmt_origfunc = f
            return _state_wrapper
        return deco

    @staticmethod
    def action(cond: Any, prio: int = 0) -> Callable:
        def deco(f, cond=cond):
            if not hasattr(f, "atmt_type"):
                f.atmt_cond = {}
            f.atmt_type = ATMT.ACTION
            f.atmt_cond[cond.atmt_condname] = prio
            return f
        return deco

    @staticmethod
    def condition(state: Any, prio: int = 0) -> Callable:
        def deco(f, state=state):
            f.atmt_type = ATMT.CONDITION
            f.atmt_state = state.atmt_state
            f.atmt_condname = f.__name__
            f.atmt_prio = prio
            return f
        return deco

    @staticmethod
    def receive_condition(state: Any, prio: int = 0) -> Callable:
        def deco(f, state=state):
            f.atmt_type = ATMT.RECV
            f.atmt_state = state.atmt_state
            f.atmt_condname = f.__name__
            f.atmt_prio = prio
            return f
        return deco

    @staticmethod
    def ioevent(state: Any, name: str, prio: int = 0,
                as_supersocket: Optional[str] = None) -> Callable:
        def deco(f, state=state):
            f.atmt_type = ATMT.IOEVENT
            f.atmt_state = state.atmt_state
            f.atmt_condname = f.__name__
            f.atmt_ioname = name
            f.atmt_prio = prio
            f.atmt_as_supersocket = as_supersocket
            return f
        return deco

    @staticmethod
    def timeout(state: Any, timeout: float) -> Callable:
        def deco(f, state=state, timeout=Timer(timeout)):
            f.atmt_type = ATMT.TIMEOUT
            f.atmt_state = state.atmt_state
            f.atmt_timeout = timeout
            f.atmt_timeout._func = f
            f.atmt_condname = f.__name__
            return f
        return deco

    @staticmethod
    def timer(state: Any, timeout: float, prio: int = 0) -> Callable:
        """A timeout that reloads itself, so it fires for as long as the state
        lasts rather than once."""
        def deco(f, state=state,
                 timeout=Timer(timeout, prio=prio, autoreload=True)):
            f.atmt_type = ATMT.TIMEOUT
            f.atmt_state = state.atmt_state
            f.atmt_timeout = timeout
            f.atmt_timeout._func = f
            f.atmt_condname = f.__name__
            return f
        return deco

    @staticmethod
    def eof(state: Any) -> Callable:
        def deco(f, state=state):
            f.atmt_type = ATMT.EOF
            f.atmt_state = state.atmt_state
            f.atmt_condname = f.__name__
            return f
        return deco


class _ATMT_Command:
    RUN = "RUN"
    NEXT = "NEXT"
    FREEZE = "FREEZE"
    STOP = "STOP"
    FORCESTOP = "FORCESTOP"
    END = "END"
    EXCEPTION = "EXCEPTION"
    SINGLESTEP = "SINGLESTEP"
    BREAKPOINT = "BREAKPOINT"
    INTERCEPT = "INTERCEPT"
    ACCEPT = "ACCEPT"
    REPLACE = "REPLACE"
    REJECT = "REJECT"


class _ATMT_supersocket(SuperSocket):
    """A state machine dressed as a socket: what you send goes to an ioevent,
    what the machine writes back comes out of ``recv``."""

    def __init__(self, name: str, ioevent: str, automaton: Any, proto: Any,
                 *args: Any, **kargs: Any):
        self.name = name
        self.ioevent = ioevent
        self.proto = proto
        self.spa, self.spb = ObjectPipe("spa"), ObjectPipe("spb")
        kargs["external_fd"] = {ioevent: (self.spa, self.spb)}
        kargs["is_atmt_socket"] = True
        kargs["atmt_socket"] = self.name
        self.atmt = automaton(*args, **kargs)
        self.atmt.runbg()

    def send(self, s: Any) -> int:
        return self.spa.send(s)

    def fileno(self) -> int:
        return self.spb.fileno()

    def recv(self, n: int = MTU, **kwargs: Any) -> Any:
        r = self.spb.recv(n)
        if self.proto is not None and r is not None:
            r = self.proto(r, **kwargs)
        if self.atmt.atmt_session is not None:
            r = self.atmt.atmt_session.process(r)
        return r

    def close(self) -> None:
        if not self.closed:
            self.atmt.stop()
            self.atmt.destroy()
            self.spa.close()
            self.spb.close()
            self.closed = True


class _ATMT_to_supersocket:
    def __init__(self, name: str, ioevent: str, automaton: Any):
        self.name = name
        self.ioevent = ioevent
        self.automaton = automaton

    def __call__(self, proto: Any, *args: Any, **kargs: Any) -> Any:
        return _ATMT_supersocket(self.name, self.ioevent, self.automaton,
                                 proto, *args, **kargs)


class Automaton_metaclass(type):
    """Collects the decorated methods into the tables the run loop reads.

    Every state, condition, timer and action is found once, at class creation,
    so the loop never introspects.
    """

    def __new__(cls, name: str, bases: Tuple[Any, ...], dct: Dict[str, Any]):
        cls = super().__new__(cls, name, bases, dct)
        cls.states = {}
        cls.recv_conditions = {}
        cls.conditions = {}
        cls.ioevents = {}
        cls.timeout = {}
        cls.eofs = {}
        cls.actions = {}
        cls.initial_states = []
        cls.stop_state = None
        cls.ionames = []
        cls.iosupersockets = []

        members: Dict[str, Any] = {}
        classes = [cls]
        while classes:
            # Breadth first, so an override is seen before what it overrides.
            c = classes.pop(0)
            classes += list(c.__bases__)
            for k, v in c.__dict__.items():
                members.setdefault(k, v)

        decorated = [v for v in members.values() if hasattr(v, "atmt_type")]

        for m in decorated:
            if m.atmt_type == ATMT.STATE:
                s = m.atmt_state
                cls.states[s] = m
                cls.recv_conditions[s] = []
                cls.ioevents[s] = []
                cls.conditions[s] = []
                cls.timeout[s] = _TimerList()
                if m.atmt_initial:
                    cls.initial_states.append(m)
                if m.atmt_stop:
                    if cls.stop_state is not None:
                        raise ValueError("There can only be a single stop state !")
                    cls.stop_state = m
            elif m.atmt_type in (ATMT.CONDITION, ATMT.RECV, ATMT.TIMEOUT,
                                 ATMT.IOEVENT, ATMT.EOF):
                cls.actions[m.atmt_condname] = []

        for m in decorated:
            if m.atmt_type == ATMT.CONDITION:
                cls.conditions[m.atmt_state].append(m)
            elif m.atmt_type == ATMT.RECV:
                cls.recv_conditions[m.atmt_state].append(m)
            elif m.atmt_type == ATMT.EOF:
                cls.eofs[m.atmt_state] = m
            elif m.atmt_type == ATMT.IOEVENT:
                cls.ioevents[m.atmt_state].append(m)
                cls.ionames.append(m.atmt_ioname)
                if m.atmt_as_supersocket is not None:
                    cls.iosupersockets.append(m)
            elif m.atmt_type == ATMT.TIMEOUT:
                cls.timeout[m.atmt_state].add_timer(m.atmt_timeout)
            elif m.atmt_type == ATMT.ACTION:
                for co in m.atmt_cond:
                    cls.actions[co].append(m)

        for v in itertools.chain(cls.conditions.values(),
                                 cls.recv_conditions.values(),
                                 cls.ioevents.values()):
            v.sort(key=lambda x: x.atmt_prio)
        for condname, actlst in cls.actions.items():
            actlst.sort(key=lambda x: x.atmt_cond[condname])

        for ioev in cls.iosupersockets:
            setattr(cls, ioev.atmt_as_supersocket,
                    _ATMT_to_supersocket(ioev.atmt_as_supersocket,
                                         ioev.atmt_ioname, cls))

        try:
            import inspect
            cls.__signature__ = inspect.signature(cls.parse_args)
        except (ImportError, AttributeError, ValueError):
            pass

        return cls

    def _reachable_names(cls, func: Any) -> set:
        """Every name a function mentions, following calls to the class's own
        helpers one level at a time.

        Each name is expanded once. scapy's version has no such guard and loops
        forever on a method whose body names itself — which ``self.count1 += 1``
        in a method called ``count1`` does, and which is the shape its own
        graph test uses.
        """
        seen: set = set()
        todo = list(func.__code__.co_names + func.__code__.co_consts)
        while todo:
            n = todo.pop()
            if not isinstance(n, str) or n in seen:
                continue
            seen.add(n)
            helper = cls.__dict__.get(n) if n not in cls.states else None
            if callable(helper) and hasattr(helper, "__code__"):
                todo.extend(helper.__code__.co_names)
                todo.extend(helper.__code__.co_consts)
        return seen

    def build_graph(cls) -> str:
        """The state machine as graphviz DOT source.

        Edges are read out of each function's code object: a state named
        anywhere in a transition's body is an edge from it.
        """
        s = 'digraph "%s" {\n' % cls.__name__

        se = ""  # initial nodes first, which renders better
        for st in cls.states.values():
            if st.atmt_initial:
                se = ('\t"%s" [ style=filled, fillcolor=blue, shape=box, root=true];\n' % st.atmt_state) + se  # noqa: E501
            elif st.atmt_final:
                se += '\t"%s" [ style=filled, fillcolor=green, shape=octagon ];\n' % st.atmt_state  # noqa: E501
            elif st.atmt_error:
                se += '\t"%s" [ style=filled, fillcolor=red, shape=octagon ];\n' % st.atmt_state  # noqa: E501
            elif st.atmt_stop:
                se += '\t"%s" [ style=filled, fillcolor=orange, shape=box, root=true ];\n' % st.atmt_state  # noqa: E501
        s += se

        for st in cls.states.values():
            for n in cls._reachable_names(st.atmt_origfunc):
                if n in cls.states:
                    s += '\t"%s" -> "%s" [ color=green ];\n' % (st.atmt_state, n)

        for c, sty, k, v in (
            [("purple", "solid", k, v) for k, v in cls.conditions.items()] +
            [("red", "solid", k, v) for k, v in cls.recv_conditions.items()] +
            [("orange", "solid", k, v) for k, v in cls.ioevents.items()] +
            [("black", "dashed", k, [v]) for k, v in cls.eofs.items()]
        ):
            for f in v:
                for n in cls._reachable_names(f):
                    if n in cls.states:
                        line = f.atmt_condname
                        for x in cls.actions[f.atmt_condname]:
                            line += "\\l>[%s]" % x.__name__
                        s += '\t"%s" -> "%s" [label="%s", color=%s, style=%s];\n' % (  # noqa: E501
                            k, n, line, c, sty)
        for k, timers in cls.timeout.items():
            for timer in timers:
                for n in (timer._func.__code__.co_names +
                          timer._func.__code__.co_consts):
                    if n in cls.states:
                        line = "%s/%.1fs" % (timer._func.atmt_condname,
                                             timer.get())
                        for x in cls.actions[timer._func.atmt_condname]:
                            line += "\\l>[%s]" % x.__name__
                        s += '\t"%s" -> "%s" [label="%s",color=blue];\n' % (
                            k, n, line)
        s += "}\n"
        return s

    def graph(cls, target: Any = None, type: str = "svg",
              prog: str = "dot") -> Optional[str]:
        """The DOT source, or a rendering of it where ``target=`` says where.

        graphviz is not a dependency, so with no target this hands back the
        source rather than shelling out — the same call `conversations()` makes.
        """
        from .report import _render_graph

        dot = cls.build_graph()
        if target is None:
            return dot
        _render_graph(dot, target, type, prog)
        return None


_RUNNING: "weakref.WeakSet[Automaton]" = weakref.WeakSet()


def _stop_running_automata() -> None:
    """A control thread still running states while the interpreter finalises
    can reach a live socket's capture thread, and a Rust thread calling into
    Python after finalisation segfaults."""
    for a in list(_RUNNING):
        try:
            a.forcestop()
        except BaseException:
            pass


atexit.register(_stop_running_automata)


class Automaton(metaclass=Automaton_metaclass):
    """A protocol as a state machine.

    States are methods marked ``@ATMT.state``; a transition is a method marked
    ``@ATMT.condition``, ``@ATMT.receive_condition``, ``@ATMT.timeout``,
    ``@ATMT.timer``, ``@ATMT.ioevent`` or ``@ATMT.eof`` that raises the state it
    moves to; ``@ATMT.action`` runs on the way across.

    ``run()`` drives it to a final state and returns what that state returned.
    ``recvsock=`` and ``ll=`` say where packets come from and go — pass an
    `OfflineSocket` and the run needs no interface and no privileges.
    """

    states: Dict[str, Any] = {}
    state: Any = None
    recv_conditions: Dict[str, List[Any]] = {}
    conditions: Dict[str, List[Any]] = {}
    eofs: Dict[str, Any] = {}
    ioevents: Dict[str, List[Any]] = {}
    timeout: Dict[str, _TimerList] = {}
    actions: Dict[str, List[Any]] = {}
    initial_states: List[Any] = []
    stop_state: Any = None
    ionames: List[str] = []
    iosupersockets: List[Any] = []

    pkt_cls: Any = None
    socketcls: Any = StreamSocket

    def __init__(self, *args: Any, **kargs: Any):
        from .capture import conf

        external_fd = kargs.pop("external_fd", {})
        if "sock" in kargs:
            self.sock = kargs["sock"]
        else:
            self.sock = None
            self.send_sock_class = kargs.pop("ll", conf.L3socket)
            self.recv_sock_class = kargs.pop("recvsock", conf.L2listen)
        self.listen_sock: Any = None
        self.send_sock: Any = None
        self.is_atmt_socket = kargs.pop("is_atmt_socket", False)
        self.atmt_socket = kargs.pop("atmt_socket", None)
        self.started = threading.Lock()
        self.threadid: Optional[int] = None
        self.breakpointed = None
        self.breakpoints: set = set()
        self.interception_points: set = set()
        self.intercepted_packet: Any = None
        self.debug_level = 0
        self.init_args = args
        self.init_kargs = kargs
        self.io = type.__new__(type, "IOnamespace", (), {})
        self.oi = type.__new__(type, "IOnamespace", (), {})
        self.cmdin = ObjectPipe("cmdin")
        self.cmdout = ObjectPipe("cmdout")
        self.ioin: Dict[str, Any] = {}
        self.ioout: Dict[str, Any] = {}
        self.packets: list = []
        self.final_state_output: Any = None
        self.atmt_session = kargs.pop("session", None)
        for n in self.__class__.ionames:
            extfd = external_fd.get(n)
            if not isinstance(extfd, tuple):
                extfd = (extfd, extfd)
            ioin, ioout = extfd
            ioin = ObjectPipe("ioin") if ioin is None \
                else self._IO_fdwrapper(ioin, None)
            ioout = ObjectPipe("ioout") if ioout is None \
                else self._IO_fdwrapper(None, ioout)
            self.ioin[n] = ioin
            self.ioout[n] = ioout
            ioin.ioname = n
            ioout.ioname = n
            setattr(self.io, n, self._IO_mixer(ioout, ioin))
            setattr(self.oi, n, self._IO_mixer(ioin, ioout))

        for stname in self.states:
            setattr(self, stname, _instance_state(getattr(self, stname)))

        self.start()

    def parse_args(self, debug: int = 0, store: int = 0, session: Any = None,
                   **kargs: Any) -> None:
        self.debug_level = debug
        if debug:
            log.setLevel(logging.DEBUG)
        if session:
            self.atmt_session = session
        self.socket_kargs = kargs
        self.store_packets = store

    @classmethod
    def spawn(cls, port: int, iface: Any = None, local_ip: Optional[str] = None,
              bg: bool = False, **kwargs: Any) -> Optional[socket.socket]:
        """Serve the machine over TCP: one automaton per accepted client.

        In background mode the returned server socket is the caller's to shut
        down; nothing else closes it.
        """
        from .capture import conf, get_if_addr

        ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if local_ip is None:
            local_ip = get_if_addr(iface or conf.iface)
        try:
            ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except OSError:
            pass
        ssock.bind((local_ip, port))
        ssock.listen(5)
        clients: list = []
        if kwargs.get("verb", True):
            print("Server %s started listening on %s"
                  % (cls.__name__, (local_ip, port)))

        def _run() -> None:
            try:
                while True:
                    atmt_server = None
                    clientsocket, address = ssock.accept()
                    if kwargs.get("verb", True):
                        print("Connection received from %r" % (address,))
                    try:
                        if cls.socketcls is not None:
                            sock = cls.socketcls(clientsocket, cls.pkt_cls)
                        else:
                            sock = clientsocket
                        atmt_server = cls(sock=sock, iface=iface, **kwargs)
                    except OSError:
                        if atmt_server is not None:
                            atmt_server.destroy()
                        if kwargs.get("verb", True):
                            print("X Connection aborted.")
                        if kwargs.get("debug", 0) > 0:
                            traceback.print_exc()
                        continue
                    clients.append((atmt_server, clientsocket))
                    atmt_server.runbg()
                    for atmt, clientsocket in clients[:]:
                        if not atmt.isrunning():
                            atmt.destroy()
                            clients.remove((atmt, clientsocket))
            except KeyboardInterrupt:
                print("X Exiting.")
                ssock.shutdown(socket.SHUT_RDWR)
            except OSError:
                print("X Server closed.")
                if kwargs.get("debug", 0) > 0:
                    traceback.print_exc()
            finally:
                for atmt, clientsocket in clients:
                    try:
                        atmt.forcestop(wait=False)
                        atmt.destroy()
                    except Exception:
                        pass
                    try:
                        clientsocket.shutdown(socket.SHUT_RDWR)
                        clientsocket.close()
                    except Exception:
                        pass
                ssock.close()

        if bg:
            threading.Thread(target=_run, daemon=True).start()
            return ssock
        _run()
        return None

    def master_filter(self, pkt: Any) -> bool:
        return True

    def my_send(self, pkt: Any, **kwargs: Any) -> None:
        if not self.send_sock:
            raise ValueError("send_sock is None !")
        self.send_sock.send(pkt, **kwargs)

    def update_sock(self, sock: Any) -> None:
        """Swap the socket under a running machine, which is what an eof
        condition does to reconnect."""
        self.sock = sock
        if self.listen_sock is not None:
            self.listen_sock = self.sock
        if self.send_sock:
            self.send_sock = self.sock

    def timer_by_name(self, name: str) -> Optional[Timer]:
        for _, timers in self.timeout.items():
            for timer in timers:
                if timer._func.atmt_condname == name:
                    return timer
        return None

    class _IO_fdwrapper:
        def __init__(self, rd: Any, wr: Any):
            self.rd = rd
            self.wr = wr
            if isinstance(self.rd, socket.socket):
                self.__selectable_force_select__ = True

        def fileno(self) -> int:
            if isinstance(self.rd, int):
                return self.rd
            if self.rd:
                return self.rd.fileno()
            return 0

        def read(self, n: int = 65535) -> Any:
            import os as _os
            if isinstance(self.rd, int):
                return _os.read(self.rd, n)
            if self.rd:
                return self.rd.recv(n)
            return None

        def write(self, msg: Any) -> int:
            import os as _os
            if isinstance(self.wr, int):
                return _os.write(self.wr, msg)
            if self.wr:
                return self.wr.send(msg)
            return 0

        def recv(self, n: int = 65535) -> Any:
            return self.read(n)

        def send(self, msg: Any) -> int:
            return self.write(msg)

    class _IO_mixer:
        def __init__(self, rd: Any, wr: Any):
            self.rd = rd
            self.wr = wr

        def fileno(self) -> Any:
            if isinstance(self.rd, ObjectPipe):
                return self.rd.fileno()
            return self.rd

        def recv(self, n: Optional[int] = None) -> Any:
            return self.rd.recv(n)

        def read(self, n: Optional[int] = None) -> Any:
            return self.recv(n)

        def send(self, msg: Any) -> int:
            return self.wr.send(msg)

        def write(self, msg: Any) -> int:
            return self.send(msg)

    class AutomatonException(Exception):
        def __init__(self, msg: str, state: Any = None, result: Any = None):
            Exception.__init__(self, msg)
            self.state = state
            self.result = result

    class AutomatonError(AutomatonException):
        pass

    class ErrorState(AutomatonException):
        pass

    class Stuck(AutomatonException):
        pass

    class AutomatonStopped(AutomatonException):
        pass

    class Breakpoint(AutomatonStopped):
        pass

    class Singlestep(AutomatonStopped):
        pass

    class InterceptionPoint(AutomatonStopped):
        def __init__(self, msg: str, state: Any = None, result: Any = None,
                     packet: Any = None):
            Automaton.AutomatonStopped.__init__(self, msg, state=state,
                                                result=result)
            self.packet = packet

    class CommandMessage(AutomatonException):
        pass

    def debug(self, lvl: int, msg: str) -> None:
        if self.debug_level >= lvl:
            log.debug(msg)

    def isrunning(self) -> bool:
        return self.started.locked()

    def send(self, pkt: Any, **kwargs: Any) -> None:
        if self.state.state in self.interception_points:
            self.debug(3, "INTERCEPT: packet intercepted: %s" % _brief(pkt))
            self.intercepted_packet = pkt
            self.cmdout.send(Message(type=_ATMT_Command.INTERCEPT,
                                     state=self.state, pkt=pkt))
            cmd = self.cmdin.recv()
            if not cmd:
                self.debug(3, "CANCELLED")
                return
            self.intercepted_packet = None
            if cmd.type == _ATMT_Command.REJECT:
                self.debug(3, "INTERCEPT: packet rejected")
                return
            elif cmd.type == _ATMT_Command.REPLACE:
                pkt = cmd.pkt
                self.debug(3, "INTERCEPT: packet replaced by: %s" % _brief(pkt))
            elif cmd.type == _ATMT_Command.ACCEPT:
                self.debug(3, "INTERCEPT: packet accepted")
            else:
                raise self.AutomatonError(
                    "INTERCEPT: unknown verdict: %r" % cmd.type)
        self.my_send(pkt, **kwargs)
        self.debug(3, "SENT : %s" % _brief(pkt))

        if self.store_packets:
            self.packets.append(pkt.copy() if hasattr(pkt, "copy") else pkt)

    def __iter__(self) -> "Automaton":
        return self

    def __del__(self) -> None:
        try:
            self.destroy()
        except Exception:
            pass

    def _run_condition(self, cond: Any, *args: Any, **kargs: Any) -> None:
        try:
            self.debug(5, "Trying %s [%s]" % (cond.atmt_type, cond.atmt_condname))
            cond(self, *args, **kargs)
        except ATMT.NewStateRequested as state_req:
            self.debug(2, "%s [%s] taken to state [%s]"
                       % (cond.atmt_type, cond.atmt_condname, state_req.state))
            if cond.atmt_type == ATMT.RECV and self.store_packets:
                self.packets.append(args[0])
            for action in self.actions[cond.atmt_condname]:
                self.debug(2, "   + Running action [%s]" % action.__name__)
                action(self, *state_req.action_args, **state_req.action_kargs)
            raise
        except Exception as e:
            self.debug(2, "%s [%s] raised exception [%s]"
                       % (cond.atmt_type, cond.atmt_condname, e))
            raise
        else:
            self.debug(2, "%s [%s] not taken"
                       % (cond.atmt_type, cond.atmt_condname))

    def _do_start(self, *args: Any, **kargs: Any) -> None:
        ready = threading.Event()
        _t = threading.Thread(target=self._do_control, args=(ready,) + args,
                              kwargs=kargs, name="wiry.automaton control",
                              daemon=True)
        _t.start()
        ready.wait()

    def _do_control(self, ready: threading.Event, *args: Any,
                    **kargs: Any) -> None:
        with self.started:
            _RUNNING.add(self)
            self.threadid = threading.current_thread().ident or 0

            a = args + self.init_args[len(args):]
            k = self.init_kargs.copy()
            k.update(kargs)
            self.parse_args(*a, **k)

            self.state = self.initial_states[0](self)
            self.send_sock = self.sock or self.send_sock_class(**self.socket_kargs)
            if self.recv_conditions:
                # A receiving socket is only worth opening if some state listens.
                self.listen_sock = self.sock or \
                    self.recv_sock_class(**self.socket_kargs)
            self.packets = []

            singlestep = True
            iterator = self._do_iter()
            self.debug(3, "Starting control thread [tid=%i]" % self.threadid)
            ready.set()
            try:
                while True:
                    c = self.cmdin.recv()
                    if c is None:
                        return None
                    self.debug(5, "Received command %s" % c.type)
                    if c.type == _ATMT_Command.RUN:
                        singlestep = False
                    elif c.type == _ATMT_Command.NEXT:
                        singlestep = True
                    elif c.type == _ATMT_Command.FREEZE:
                        continue
                    elif c.type == _ATMT_Command.STOP:
                        if self.stop_state:
                            self.state = self.stop_state()
                            iterator = self._do_iter()
                        else:
                            break
                    elif c.type == _ATMT_Command.FORCESTOP:
                        break
                    while True:
                        state = next(iterator)
                        if isinstance(state, self.CommandMessage):
                            break
                        elif isinstance(state, self.Breakpoint):
                            self.cmdout.send(Message(
                                type=_ATMT_Command.BREAKPOINT, state=state))
                            break
                        if singlestep:
                            self.cmdout.send(Message(
                                type=_ATMT_Command.SINGLESTEP, state=state))
                            break
            except (StopIteration, RuntimeError):
                self.cmdout.send(Message(type=_ATMT_Command.END,
                                         result=self.final_state_output))
            except Exception as e:
                exc_info = sys.exc_info()
                self.debug(3, "Transferring exception from tid=%i:\n%s"
                           % (self.threadid,
                              "".join(traceback.format_exception(*exc_info))))
                self.cmdout.send(Message(type=_ATMT_Command.EXCEPTION,
                                         exception=e, exc_info=exc_info))
            self.debug(3, "Stopping control thread (tid=%i)" % self.threadid)
            self.threadid = None
            if self.listen_sock:
                self.listen_sock.close()
            if self.send_sock:
                self.send_sock.close()

    def _do_iter(self) -> Iterator[Any]:
        while True:
            try:
                self.debug(1, "## state=[%s]" % self.state.state)

                if self.state.state in self.breakpoints and \
                        self.state.state != self.breakpointed:
                    self.breakpointed = self.state.state
                    yield self.Breakpoint(
                        "breakpoint triggered on state %s" % self.state.state,
                        state=self.state.state)
                self.breakpointed = None
                state_output = self.state.run()
                if self.state.error:
                    raise self.ErrorState(
                        "Reached %s: [%r]" % (self.state.state, state_output),
                        result=state_output, state=self.state.state)
                if self.state.final:
                    self.final_state_output = state_output
                    return

                if state_output is None:
                    state_output = ()
                elif not isinstance(state_output, list):
                    state_output = state_output,

                timers = self.timeout[self.state.state]
                # A pending command outranks an immediate condition.
                if not select_objects([self.cmdin], 0):
                    for cond in self.conditions[self.state.state]:
                        self._run_condition(cond, *state_output)

                    if (len(self.recv_conditions[self.state.state]) == 0 and
                        len(self.ioevents[self.state.state]) == 0 and
                            timers.count() == 0):
                        raise self.Stuck("stuck in [%s]" % self.state.state,
                                         state=self.state.state,
                                         result=state_output)

                timers.reset()
                time_previous = time.time()

                fds: List[Any] = [self.cmdin]
                select_func = select_objects
                if self.listen_sock and self.recv_conditions[self.state.state]:
                    fds.append(self.listen_sock)
                    select_func = self.listen_sock.select
                for ioev in self.ioevents[self.state.state]:
                    fds.append(self.ioin[ioev.atmt_ioname])
                while True:
                    time_current = time.time()
                    timers.decrement(time_current - time_previous)
                    time_previous = time_current
                    for timer in timers.expired():
                        self._run_condition(timer._func, *state_output)
                    remain = timers.until_next()

                    r = select_func(fds, remain)
                    for fd in r:
                        if fd == self.cmdin:
                            yield self.CommandMessage("Received command message")
                        elif fd == self.listen_sock:
                            try:
                                pkt = self.listen_sock.recv()
                            except EOFError:
                                self.listen_sock.close()
                                # False, not None, so update_sock still resets it
                                self.listen_sock = False
                                fds.remove(fd)
                                if self.state.state in self.eofs:
                                    eof = self.eofs[self.state.state]
                                    self.debug(2, "Condition EOF [%s] taken"
                                               % eof.__name__)
                                    raise eof(self)
                                raise EOFError("Socket ended abruptly.")
                            if self.atmt_session is not None:
                                pkt = self.atmt_session.process(pkt)
                            if pkt is not None:
                                if self.master_filter(pkt):
                                    self.debug(3, "RECVD: %s" % _brief(pkt))
                                    for rcvcond in \
                                            self.recv_conditions[self.state.state]:
                                        self._run_condition(rcvcond, pkt,
                                                            *state_output)
                                else:
                                    self.debug(4, "FILTR: %s" % _brief(pkt))
                        else:
                            self.debug(3, "IOEVENT on %s" % fd.ioname)
                            for ioevt in self.ioevents[self.state.state]:
                                if ioevt.atmt_ioname == fd.ioname:
                                    self._run_condition(ioevt, fd, *state_output)

            except ATMT.NewStateRequested as state_req:
                self.debug(2, "switching from [%s] to [%s]"
                           % (self.state.state, state_req.state))
                self.state = state_req
                yield state_req

    def __repr__(self) -> str:
        return "<Automaton %s [%s]>" % (
            self.__class__.__name__,
            ["HALTED", "RUNNING"][self.isrunning()])

    def add_interception_points(self, *ipts: Any) -> None:
        for ipt in ipts:
            self.interception_points.add(getattr(ipt, "atmt_state", ipt))

    def remove_interception_points(self, *ipts: Any) -> None:
        for ipt in ipts:
            self.interception_points.discard(getattr(ipt, "atmt_state", ipt))

    def add_breakpoints(self, *bps: Any) -> None:
        for bp in bps:
            self.breakpoints.add(getattr(bp, "atmt_state", bp))

    def remove_breakpoints(self, *bps: Any) -> None:
        for bp in bps:
            self.breakpoints.discard(getattr(bp, "atmt_state", bp))

    def start(self, *args: Any, **kargs: Any) -> None:
        if self.isrunning():
            raise ValueError("Already started")
        self._do_start(*args, **kargs)

    def run(self, resume: Optional[Message] = None, wait: bool = True) -> Any:
        """Let the machine run. Returns the final state's value when it ends."""
        if resume is None:
            resume = Message(type=_ATMT_Command.RUN)
        self.cmdin.send(resume)
        if wait:
            try:
                c = self.cmdout.recv()
                if c is None:
                    return None
            except KeyboardInterrupt:
                self.cmdin.send(Message(type=_ATMT_Command.FREEZE))
                return None
            if c.type == _ATMT_Command.END:
                return c.result
            elif c.type == _ATMT_Command.INTERCEPT:
                raise self.InterceptionPoint("packet intercepted",
                                             state=c.state.state, packet=c.pkt)
            elif c.type == _ATMT_Command.SINGLESTEP:
                raise self.Singlestep("singlestep state=[%s]" % c.state.state,
                                      state=c.state.state)
            elif c.type == _ATMT_Command.BREAKPOINT:
                raise self.Breakpoint(
                    "breakpoint triggered on state [%s]" % c.state.state,
                    state=c.state.state)
            elif c.type == _ATMT_Command.EXCEPTION:
                value = c.exc_info[0]() if c.exc_info[1] is None else c.exc_info[1]
                if value.__traceback__ is not c.exc_info[2]:
                    raise value.with_traceback(c.exc_info[2])
                raise value
        return None

    def runbg(self, resume: Optional[Message] = None,
              wait: bool = False) -> None:
        self.run(resume, wait)

    def __next__(self) -> Any:
        return self.run(resume=Message(type=_ATMT_Command.NEXT))

    def _flush_inout(self) -> None:
        for cmd in (self.cmdin, self.cmdout):
            cmd.clear()

    def destroy(self) -> None:
        """Close every descriptor a stopped machine still holds."""
        if not hasattr(self, "started"):
            return  # never started
        if self.isrunning():
            raise ValueError("Can't close running Automaton ! Call stop() beforehand")
        self.cmdin.close()
        self.cmdout.close()
        self._flush_inout()
        for i in itertools.chain(self.ioin.values(), self.ioout.values()):
            if isinstance(i, ObjectPipe):
                i.close()

    def stop(self, wait: bool = True) -> None:
        """Ask the machine to stop, through its stop state if it has one."""
        try:
            self.cmdin.send(Message(type=_ATMT_Command.STOP))
        except (OSError, ValueError):
            pass
        if wait:
            with self.started:
                self._flush_inout()

    def forcestop(self, wait: bool = True) -> None:
        """Stop without running a stop state."""
        try:
            self.cmdin.send(Message(type=_ATMT_Command.FORCESTOP))
        except (OSError, ValueError):
            pass
        if wait:
            with self.started:
                self._flush_inout()

    def restart(self, *args: Any, **kargs: Any) -> None:
        self.stop()
        self.start(*args, **kargs)

    def accept_packet(self, pkt: Any = None, wait: bool = False) -> Any:
        rsm = Message()
        if pkt is None:
            rsm.type = _ATMT_Command.ACCEPT
        else:
            rsm.type = _ATMT_Command.REPLACE
            rsm.pkt = pkt
        return self.run(resume=rsm, wait=wait)

    def reject_packet(self, wait: bool = False) -> Any:
        return self.run(resume=Message(type=_ATMT_Command.REJECT), wait=wait)


def _brief(pkt: Any) -> str:
    """A packet for a debug line. Anything at all may be sent through an
    automaton, so this never assumes a Packet."""
    summary = getattr(pkt, "summary", None)
    if summary is None:
        return repr(pkt)
    try:
        return summary()
    except Exception:
        return repr(pkt)
