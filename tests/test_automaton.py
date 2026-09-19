"""``Automaton``: states, transitions, timers and the sockets that feed them.

Every test here runs with no interface, no root and no live feature. That is
the point: a state machine is pure logic, and an `OfflineSocket` puts canned
packets in front of it and records what it sends, so the machine, its
transitions and its replies are all checkable from a capture.
"""

import os
import socket
import threading
import time

import pytest

from wiry import (
    ATMT,
    ICMP,
    IP,
    Automaton,
    Ether,
    ObjectPipe,
    OfflineSocket,
    Raw,
    StreamSocket,
    TCP,
    select_objects,
)


def nosock():
    """``ll=`` and ``recvsock=`` for a machine that needs neither."""
    return {"ll": lambda **_: None, "recvsock": lambda **_: None}


# --- the shape of a machine -------------------------------------------------


class Counter(Automaton):
    @ATMT.state(initial=1)
    def BEGIN(self):
        self.seen = ""

    @ATMT.condition(BEGIN)
    def grow(self):
        raise self.MIDDLE("a")

    @ATMT.action(grow)
    def note(self):
        self.seen += "g"

    @ATMT.state()
    def MIDDLE(self, s):
        return s

    @ATMT.condition(MIDDLE)
    def done(self, s):
        if len(s) > 3:
            raise self.END(s)
        raise self.MIDDLE(s + "a")

    @ATMT.state(final=1)
    def END(self, s):
        return self.seen + s


def test_a_machine_runs_to_its_final_state_and_returns_its_value():
    a = Counter(**nosock())
    assert a.run() == "gaaaa"


def test_an_action_runs_on_the_transition_it_is_attached_to():
    a = Counter(**nosock())
    a.run()
    assert a.seen == "g"


def test_a_machine_with_nothing_left_to_wait_for_says_it_is_stuck():
    class Nowhere(Automaton):
        @ATMT.state(initial=1)
        def BEGIN(self):
            pass

    with pytest.raises(Automaton.Stuck):
        Nowhere(**nosock()).run()


def test_an_error_state_raises_and_carries_what_it_produced():
    class Bad(Automaton):
        @ATMT.state(initial=1)
        def BEGIN(self):
            raise self.OOPS()

        @ATMT.state(error=1)
        def OOPS(self):
            return "why"

    with pytest.raises(Automaton.ErrorState) as exc:
        Bad(**nosock()).run()
    assert exc.value.result == "why"


def test_a_condition_with_the_lower_priority_number_is_tried_first():
    class Order(Automaton):
        @ATMT.state(initial=1)
        def BEGIN(self):
            self.order = ""

        @ATMT.condition(BEGIN, prio=1)
        def late(self):
            self.order += "l"
            raise self.END()

        @ATMT.condition(BEGIN, prio=-1)
        def early(self):
            self.order += "e"

        @ATMT.state(final=1)
        def END(self):
            return self.order

    assert Order(**nosock()).run() == "el"


def test_a_subclass_can_override_a_state_and_a_condition():
    class Base(Automaton):
        @ATMT.state(initial=1)
        def BEGIN(self):
            raise self.MAIN("x")

        @ATMT.state()
        def MAIN(self, s):
            return s

        @ATMT.condition(MAIN)
        def go(self, s):
            raise self.END(s)

        @ATMT.state(final=1)
        def END(self, s):
            return s

    class Child(Base):
        @ATMT.condition(Base.MAIN)
        def go(self, s):
            raise self.END(s + "y")

    assert Base(**nosock()).run() == "x"
    assert Child(**nosock()).run() == "xy"


# --- packets in, packets out ------------------------------------------------


def ping(ident):
    return Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(id=ident)


class Echo(Automaton):
    """Answers every ICMP echo it is shown, then stops on the third."""

    @ATMT.state(initial=1)
    def WAIT(self):
        pass

    @ATMT.receive_condition(WAIT)
    def got(self, pkt):
        self.answered = getattr(self, "answered", 0) + 1
        self.send(Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / ICMP(type=0))
        if self.answered >= 3:
            raise self.END()
        raise self.WAIT()

    @ATMT.eof(WAIT)
    def ran_out(self):
        raise self.END()

    @ATMT.state(final=1)
    def END(self):
        return self.answered


def test_a_machine_is_driven_from_a_capture_and_its_replies_are_recorded():
    sock = OfflineSocket([ping(i) for i in range(5)])
    a = Echo(ll=lambda **_: sock, recvsock=lambda **_: sock)
    assert a.run() == 3
    assert len(sock.sent) == 3
    assert all("ICMP" in p.layers() for p in sock.sent)


def test_an_exhausted_source_takes_the_eof_condition():
    sock = OfflineSocket([ping(0)])
    a = Echo(ll=lambda **_: sock, recvsock=lambda **_: sock)
    assert a.run() == 1


def test_a_source_that_runs_out_with_no_eof_condition_ends_the_run():
    class NoEof(Automaton):
        @ATMT.state(initial=1)
        def WAIT(self):
            pass

        @ATMT.receive_condition(WAIT)
        def got(self, pkt):
            raise self.WAIT()

        @ATMT.state(final=1)
        def END(self):
            pass

    sock = OfflineSocket([ping(0)])
    with pytest.raises(EOFError):
        NoEof(ll=lambda **_: sock, recvsock=lambda **_: sock).run()


def test_master_filter_rejects_a_packet_before_any_condition_sees_it():
    class Picky(Echo):
        def master_filter(self, pkt):
            return pkt["ICMP"].id == 2

    pkts = [ping(i) for i in range(5)]
    sock = OfflineSocket(pkts)
    a = Picky(ll=lambda **_: sock, recvsock=lambda **_: sock)
    assert a.run() == 1  # only id=2 got through, then the source ran out


def test_store_keeps_the_packets_a_run_received_and_sent():
    sock = OfflineSocket([ping(i) for i in range(3)])
    a = Echo(ll=lambda **_: sock, recvsock=lambda **_: sock, store=1)
    a.run()
    assert len(a.packets) == 6  # three received, three sent


# --- time -------------------------------------------------------------------


def test_a_timeout_fires_once_and_a_timer_reloads():
    class Ticks(Automaton):
        @ATMT.state(initial=1)
        def BEGIN(self):
            self.once = 0
            self.many = 0

        @ATMT.timeout(BEGIN, 0.05)
        def one(self):
            self.once += 1

        @ATMT.timer(BEGIN, 0.05)
        def lots(self):
            self.many += 1

        @ATMT.timeout(BEGIN, 0.45)
        def stop(self):
            raise self.END()

        @ATMT.state(final=1)
        def END(self):
            pass

    a = Ticks(**nosock())
    a.run()
    assert a.once == 1
    assert a.many >= 4


def test_a_timer_can_be_found_and_reset_before_the_run():
    class Ticks(Automaton):
        @ATMT.state(initial=1)
        def BEGIN(self):
            self.n = 0

        @ATMT.timer(BEGIN, 0.05)
        def tick(self):
            self.n += 1

        @ATMT.timeout(BEGIN, 0.3)
        def stop(self):
            raise self.END()

        @ATMT.state(final=1)
        def END(self):
            pass

    a = Ticks(**nosock())
    assert a.timer_by_name("nothing") is None
    assert a.timer_by_name("tick").get() == 0.05
    a.timer_by_name("tick").set(0.2)
    a.run()
    assert a.n <= 2


# --- io events --------------------------------------------------------------


class Talker(Automaton):
    @ATMT.state(initial=1)
    def BEGIN(self):
        self.said = ""

    @ATMT.ioevent(BEGIN, name="chat")
    def heard(self, fd):
        self.said += fd.recv()
        self.oi.chat.send(self.said.upper())
        raise self.END()

    @ATMT.state(final=1)
    def END(self):
        return self.said


def test_an_io_event_carries_objects_both_ways():
    a = Talker(**nosock())
    a.run(wait=False)
    a.io.chat.send("hello")
    assert a.io.chat.recv() == "HELLO"
    assert a.run() == "hello"


def test_an_external_descriptor_can_drive_an_io_event():
    class Reader(Automaton):
        @ATMT.state(initial=1)
        def BEGIN(self):
            self.got = b""

        @ATMT.ioevent(BEGIN, name="ext")
        def read(self, fd):
            self.got += fd.read(2)
            raise self.END()

        @ATMT.state(final=1)
        def END(self):
            return self.got

    r, w = os.pipe()
    try:
        a = Reader(external_fd={"ext": r}, **nosock())
        a.run(wait=False)
        os.write(w, b"hi")
        assert a.run() == b"hi"
    finally:
        os.close(r)
        os.close(w)


# --- control ----------------------------------------------------------------


def test_an_interception_point_hands_the_packet_over_before_it_is_sent():
    class Sender(Automaton):
        def my_send(self, pkt, **kwargs):
            self.io.loop.send(pkt)

        @ATMT.state(initial=1)
        def BEGIN(self):
            self.got = b""
            self.send(Raw(b"ABC"))

        @ATMT.ioevent(BEGIN, name="loop")
        def back(self, fd):
            self.got = bytes(fd.recv())
            raise self.END()

        @ATMT.state(final=1)
        def END(self):
            return self.got

    a = Sender(**nosock())
    assert a.run() == b"ABC"

    a.restart()
    a.BEGIN.intercepts()
    while True:
        try:
            out = a.run()
        except Automaton.InterceptionPoint as p:
            a.accept_packet(Raw(bytes(p.packet).lower()), wait=False)
        else:
            break
    assert out == b"abc"


def test_a_breakpoint_stops_the_run_at_a_state():
    a = Counter(**nosock())
    a.MIDDLE.breaks()
    with pytest.raises(Automaton.Breakpoint) as exc:
        a.run()
    assert exc.value.state == "MIDDLE"
    a.MIDDLE.unbreaks()
    assert a.run() == "gaaaa"


def test_next_single_steps_one_transition_at_a_time():
    a = Counter(**nosock())
    with pytest.raises(Automaton.Singlestep):
        next(a)
    a.forcestop()


def test_a_stop_state_runs_on_stop_and_forcestop_skips_it():
    class Polite(Automaton):
        @ATMT.state(initial=1)
        def BEGIN(self):
            self.closed = False

        @ATMT.timeout(BEGIN, 5)
        def never(self):
            raise self.END()

        @ATMT.state(stop=1)
        def CLOSING(self):
            self.closed = True
            raise self.END()

        @ATMT.state(final=1)
        def END(self):
            pass

    a = Polite(**nosock())
    a.run(wait=False)
    a.stop()
    assert a.closed is True

    b = Polite(**nosock())
    b.run(wait=False)
    b.forcestop()
    assert b.closed is False


def test_a_machine_says_whether_it_is_running_and_cleans_up_after_itself():
    a = Counter(**nosock())
    assert a.isrunning() is True
    assert "RUNNING" in repr(a)
    a.run()
    assert a.isrunning() is False
    a.destroy()


def test_only_one_stop_state_is_allowed():
    with pytest.raises(ValueError, match="single stop state"):
        class Two(Automaton):
            @ATMT.state(initial=1)
            def BEGIN(self):
                pass

            @ATMT.state(stop=1)
            def A(self):
                pass

            @ATMT.state(stop=1)
            def B(self):
                pass


# --- the graph --------------------------------------------------------------


def test_the_graph_names_the_states_and_the_edges_between_them():
    dot = Counter.build_graph()
    assert dot.startswith('digraph "Counter"')
    assert '"MIDDLE" -> "END"' in dot
    assert Counter.graph() == dot


def test_the_graph_terminates_on_a_method_that_names_itself():
    """scapy's build_graph loops forever here: it re-expands an indirection
    without remembering which names it has already followed, and a method
    called ``tick`` whose body says ``self.tick`` names itself."""

    class SelfNaming(Automaton):
        @ATMT.state(initial=1)
        def BEGIN(self):
            self.tick = 0

        @ATMT.timer(BEGIN, 0.1)
        def tick(self):
            self.tick += 1

        @ATMT.timeout(BEGIN, 1)
        def goto_end(self):
            raise self.END()

        @ATMT.state(final=1)
        def END(self):
            pass

    dot = SelfNaming.build_graph()
    assert '"BEGIN" -> "END"' in dot


def test_the_graph_follows_an_indirection_through_a_helper():
    class Indirect(Automaton):
        @ATMT.state(initial=1)
        def BEGIN(self):
            pass

        @ATMT.condition(BEGIN)
        def cnd(self):
            self.helper()

        def helper(self):
            raise self.END()

        @ATMT.state(final=1)
        def END(self):
            pass

    assert '"BEGIN" -> "END"' in Indirect.build_graph()


# --- the sockets ------------------------------------------------------------


def test_an_offline_socket_reads_a_capture_and_then_reports_the_end(tmp_path):
    from wiry import wrpcap

    path = tmp_path / "c.pcap"
    wrpcap(str(path), [ping(1), ping(2)])
    sock = OfflineSocket(str(path))
    assert sock.recv()["ICMP"].id == 1
    assert sock.recv()["ICMP"].id == 2
    with pytest.raises(EOFError):
        sock.recv()


def test_an_offline_socket_is_always_ready_so_a_wait_never_blocks_on_it():
    sock = OfflineSocket([ping(0)])
    assert sock.fileno() < 0
    assert select_objects([sock], None) == [sock]


def test_an_object_pipe_carries_objects_and_is_selectable():
    pipe = ObjectPipe("t")
    assert pipe.empty()
    assert select_objects([pipe], 0) == []
    obj = object()
    pipe.send(obj)
    assert select_objects([pipe], 0) == [pipe]
    assert pipe.recv() is obj
    pipe.close()
    with pytest.raises(EOFError):
        pipe.recv()


def test_a_stream_socket_reads_packets_off_a_byte_stream():
    a, b = socket.socketpair()
    try:
        s = StreamSocket(a, Raw)
        b.send(b"hello")
        assert bytes(s.recv()) == b"hello"
        s.send(Raw(b"back"))
        assert b.recv(16) == b"back"
        b.close()
        with pytest.raises(EOFError):
            s.recv()
    finally:
        a.close()
        b.close()


def test_a_socket_that_cannot_send_says_so():
    from wiry import SuperSocket

    with pytest.raises(NotImplementedError):
        SuperSocket().send(b"x")


# --- threads ----------------------------------------------------------------


def test_a_running_machine_is_registered_so_nothing_outlives_the_interpreter():
    from wiry.automaton import _RUNNING, _stop_running_automata

    a = Counter(**nosock())
    assert a in _RUNNING
    _stop_running_automata()
    assert a.isrunning() is False


def test_a_finished_machine_leaves_no_thread_behind():
    before = threading.active_count()
    for _ in range(5):
        Counter(**nosock()).run()
    for _ in range(50):
        if threading.active_count() <= before:
            break
        time.sleep(0.02)
    assert threading.active_count() <= before


def test_a_socket_that_will_not_open_is_raised_rather_than_hung_on():
    """scapy sets its ready event only after the sockets are open, so a socket
    that raises leaves the caller waiting on a thread that has already died."""
    class Refuses(Counter):
        pass

    def boom(**_):
        raise OSError("no such interface")

    with pytest.raises(OSError, match="no such interface"):
        Refuses(ll=boom, recvsock=boom)


def test_a_machine_cannot_be_destroyed_while_it_runs():
    a = Counter(**nosock())
    with pytest.raises(ValueError, match="running"):
        a.destroy()
    a.forcestop()
    a.destroy()


def test_a_tcp_layer_machine_can_be_fed_a_socketpair():
    """The shape ``spawn()`` builds for each client, without the listen."""

    class Upper(Automaton):
        @ATMT.state(initial=1)
        def WAIT(self):
            pass

        @ATMT.receive_condition(WAIT)
        def got(self, pkt):
            self.send(Raw(bytes(pkt).upper()))
            raise self.END()

        @ATMT.state(final=1)
        def END(self):
            return True

    a, b = socket.socketpair()
    try:
        sock = StreamSocket(a, Raw)
        m = Upper(sock=sock)
        b.send(b"ping")
        assert m.run() is True
        assert b.recv(16) == b"PING"
    finally:
        a.close()
        b.close()


def test_a_packet_carrying_layers_reaches_a_receive_condition_intact():
    seen = []

    class Look(Automaton):
        @ATMT.state(initial=1)
        def WAIT(self):
            pass

        @ATMT.receive_condition(WAIT)
        def got(self, pkt):
            seen.append(pkt.layers())
            raise self.END()

        @ATMT.state(final=1)
        def END(self):
            pass

    pkt = Ether() / IP() / TCP(dport=80)
    sock = OfflineSocket([pkt])
    Look(ll=lambda **_: sock, recvsock=lambda **_: sock).run()
    assert seen == [["Ether", "IP", "TCP"]]
