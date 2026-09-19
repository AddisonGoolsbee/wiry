"""traceroute, arping, the sr loops and address lookup, without a network.

Each of these is one exchange plus arithmetic. Everything but the exchange is
tested here from canned packets: the probes a sweep builds, the trace those
probes and their replies make, the hosts a CIDR expands to, the report a loop
round prints. What is left needs an interface, and lives in ``dev/live/``.
"""

import threading

import pytest

import wiry as P
from wiry import ARP, ICMP, IP, TCP, Ether, tools as T

live = pytest.mark.skipif(
    not P.capture_available(), reason="this host cannot load libpcap"
)

NO_SUCH_IF = "wiry-no-such-if0"


def hop_error(who, probe, kind=11):
    """The ICMP error a router sends back, quoting the probe (RFC 792)."""
    return IP(src=who, dst=probe[IP].src) / ICMP(type=kind) / bytes(probe)


def canned_trace(target="10.0.0.9", hops=3, reached=True):
    probes = T._probes([target], 1, hops, 80, None, None)
    pairs = [(p, hop_error(f"192.0.2.{i + 1}", p))
             for i, p in enumerate(probes[:-1])]
    if reached:
        last = probes[-1]
        pairs.append((last, IP(src=target, dst=last[IP].src)
                      / TCP(sport=80, dport=20, flags="SA")))
    return pairs


# --------------------------------------------------------------------------
# traceroute


def test_a_sweep_is_one_probe_per_ttl_carrying_that_ttl():
    probes = T._probes(["10.0.0.9"], 1, 4, 80, None, None)
    assert [bytes(p)[8] for p in probes] == [1, 2, 3, 4]


def test_every_probe_of_a_sweep_is_distinguishable_to_the_matcher():
    # answers.rs pairs an ICMP error with the probe whose IP id the quote
    # carries, and the TTL is not part of a reply key. Identical ids would put
    # every hop's reply on the first probe and make the trace one row long.
    probes = T._probes(["10.0.0.9"], 1, 30, 80, None, None)
    ids = [bytes(p)[4:6] for p in probes]
    assert len(set(ids)) == len(ids)


def test_a_sweep_over_two_targets_covers_both():
    probes = T._probes(["10.0.0.9", "10.0.0.10"], 5, 7, 80, None, None)
    assert len(probes) == 6
    assert {p[IP].dst for p in probes} == {"10.0.0.9", "10.0.0.10"}
    assert [p[IP].ttl for p in probes] == [5, 6, 7, 5, 6, 7]


def test_a_sweep_outside_the_range_a_ttl_has_is_refused():
    for lo, hi in ((0, 30), (1, 256), (10, 5), (-1, 4)):
        with pytest.raises(ValueError):
            T._probes(["10.0.0.9"], lo, hi, 80, None, None)


def test_the_default_probe_is_a_syn_and_l4_replaces_it():
    probe = T._probes(["10.0.0.9"], 1, 1, 443, 1234, None)[0]
    assert probe[TCP].dport == 443
    assert probe[TCP].sport == 1234
    assert probe[TCP].flags == "S"

    from wiry import UDP

    custom = T._probes(["10.0.0.9"], 1, 2, 80, None, UDP(dport=33434))
    assert all("UDP" in p.layers() for p in custom)
    assert custom[0][IP].ttl == 1 and custom[1][IP].ttl == 2


def test_the_trace_filter_names_every_error_that_quotes_a_datagram():
    expr = T._trace_filter("tcp")
    for kind in (3, 4, 5, 11, 12):
        assert f"icmp[0] = {kind}" in expr
    assert expr.endswith("or tcp")


def test_a_trace_groups_its_hops_by_target_and_ttl():
    result = T.TracerouteResult(canned_trace())
    trace = result.get_trace()
    assert set(trace) == {"10.0.0.9"}
    assert trace["10.0.0.9"] == {
        1: ("192.0.2.1", False),
        2: ("192.0.2.2", False),
        3: ("10.0.0.9", True),
    }
    assert len(result) == 3
    assert result[0] is result.res[0]
    assert len(list(result)) == 3


def test_two_targets_traced_at_once_stay_apart():
    pairs = canned_trace("10.0.0.9") + canned_trace("10.0.0.10")
    trace = T.TracerouteResult(pairs).get_trace()
    assert set(trace) == {"10.0.0.9", "10.0.0.10"}
    assert trace["10.0.0.10"][3] == ("10.0.0.10", True)


def test_a_hop_nobody_answered_shows_as_a_gap_not_a_renumbering():
    pairs = canned_trace(hops=4)
    del pairs[1]
    text = T.TracerouteResult(pairs).show_str()
    lines = [ln.split() for ln in text.strip().splitlines()[1:]]
    assert [ln[0] for ln in lines] == ["1", "2", "3", "4"]
    assert lines[1] == ["2", "*"]
    assert "time-exceeded" in text
    assert "<- target" in text


def test_an_empty_trace_shows_nothing_rather_than_failing():
    empty = T.TracerouteResult([])
    assert empty.show_str() == ""
    assert empty.get_trace() == {}
    assert empty.summary() == ""
    assert "0 hops" in repr(empty)


def test_a_reply_with_no_ip_layer_is_shown_rather_than_dropped():
    probe = T._probes(["10.0.0.9"], 1, 1, 80, None, None)[0]
    text = T.TracerouteResult([(probe, Ether() / ARP())]).show_str()
    assert "?" in text


def paired(sent, received, **kw):
    """`sr`'s own pairing, with the wire replaced by a list of frames.

    The same `Exchange` and the same `answers()` the live path uses, so a sweep
    can be checked against real replies with no interface and no privileges.
    """
    return P._wiry.pair_replies([bytes(p) for p in sent],
                                [bytes(p) for p in received], **kw)


def test_the_real_matcher_pairs_every_hop_of_a_real_sweep():
    # The whole of traceroute that is not a socket: the probes it builds, the
    # errors routers send back, and the engine's own pairing.
    probes = T._probes(["10.0.0.9"], 1, 6, 80, None, None)
    replies = [hop_error(f"192.0.2.{i + 1}", p) for i, p in enumerate(probes)]
    pairs, unanswered = paired(probes, replies)
    assert pairs == [(i, i) for i in range(6)]
    assert unanswered == []

    result = T.TracerouteResult([(probes[i], replies[j]) for i, j in pairs])
    assert result.get_trace()["10.0.0.9"] == {
        i + 1: (f"192.0.2.{i + 1}", False) for i in range(6)
    }


def test_replies_arriving_out_of_order_still_land_on_their_own_probe():
    probes = T._probes(["10.0.0.9"], 1, 4, 80, None, None)
    order = [2, 0, 3, 1]
    replies = [hop_error(f"192.0.2.{i + 1}", probes[i]) for i in order]
    pairs, unanswered = paired(probes, replies)
    assert sorted(pairs) == [(0, 1), (1, 3), (2, 0), (3, 2)]
    assert unanswered == []


def test_a_silent_hop_is_reported_unanswered_rather_than_guessed_at():
    probes = T._probes(["10.0.0.9"], 1, 4, 80, None, None)
    replies = [hop_error("192.0.2.1", probes[0]),
               hop_error("192.0.2.4", probes[3])]
    pairs, unanswered = paired(probes, replies)
    assert pairs == [(0, 0), (3, 1)]
    assert unanswered == [1, 2]


def test_an_error_quoting_a_probe_to_another_target_is_not_our_hop():
    ours = T._probes(["10.0.0.9"], 1, 2, 80, None, None)
    theirs = T._probes(["10.0.0.10"], 1, 2, 80, None, None)
    pairs, unanswered = paired(ours, [hop_error("192.0.2.1", theirs[0])])
    assert pairs == []
    assert unanswered == [0, 1]


def test_an_arp_sweeps_replies_land_on_the_address_each_asked_about():
    hosts = T._hosts("10.0.0.0/29")
    probes = [Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=h) for h in hosts]
    replies = [
        Ether() / ARP(op=2, psrc=hosts[2], hwsrc="aa:bb:cc:dd:ee:03"),
        Ether() / ARP(op=2, psrc=hosts[0], hwsrc="aa:bb:cc:dd:ee:01"),
    ]
    pairs, unanswered = paired(probes, replies, link="Ether")
    assert sorted(pairs) == [(0, 1), (2, 0)]
    assert unanswered == [1, 3, 4, 5]
    text = T.arping_str([(probes[i], replies[j]) for i, j in pairs])
    assert f"aa:bb:cc:dd:ee:03  {hosts[2]}" in text


@live
def test_traceroute_reaches_the_backend_and_refuses_nothing_first():
    with pytest.raises(OSError):
        P.traceroute("10.99.0.2", maxttl=2, iface=NO_SUCH_IF, timeout=0.1,
                     verbose=0)


# --------------------------------------------------------------------------
# arping


def test_a_cidr_expands_to_its_hosts_and_a_bare_address_to_itself():
    assert T._hosts("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]
    assert T._hosts("10.0.0.5") == ["10.0.0.5"]
    assert T._hosts("10.0.0.5/32") == ["10.0.0.5"]
    assert T._hosts(["10.0.0.1", "10.0.0.2"]) == ["10.0.0.1", "10.0.0.2"]


def test_a_sweep_wider_than_the_ceiling_is_refused_by_name():
    with pytest.raises(ValueError) as exc:
        T._hosts("10.0.0.0/8")
    assert str(T.MAX_SWEEP) in str(exc.value)


def test_arping_asks_about_ipv4_only():
    with pytest.raises(ValueError):
        T._hosts("2001:db8::/120")


def test_an_arp_sweep_reports_who_answered():
    answered = [
        (Ether() / ARP(pdst="10.0.0.1"),
         Ether() / ARP(op=2, hwsrc="aa:bb:cc:dd:ee:01", psrc="10.0.0.1")),
        (Ether() / ARP(pdst="10.0.0.2"),
         Ether() / ARP(op=2, hwsrc="aa:bb:cc:dd:ee:02", psrc="10.0.0.2")),
    ]
    text = T.arping_str(answered)
    assert "aa:bb:cc:dd:ee:01  10.0.0.1" in text
    assert text.count("\n") == 2
    assert T.arping_str([]) == ""


@live
def test_arping_reaches_the_backend():
    with pytest.raises(OSError):
        P.arping("10.99.0.0/30", iface=NO_SUCH_IF, timeout=0.1, verbose=0)


# --------------------------------------------------------------------------
# the send-receive loops


def fake_exchange(rounds):
    """An exchange that hands back canned rounds and counts its calls."""
    calls = []

    def exchange():
        calls.append(len(calls))
        return rounds[min(len(calls) - 1, len(rounds) - 1)]

    return exchange, calls


def test_a_loop_runs_the_round_count_it_was_given_and_accumulates():
    snd = IP(dst="10.0.0.1") / TCP()
    rcv = IP(src="10.0.0.1") / TCP(flags="SA")
    exchange, calls = fake_exchange([([(snd, rcv)], [])])
    answered, unanswered = T._loop(exchange, 3, 0, None, None, 0, True)
    assert len(calls) == 3
    assert len(answered) == 3 and unanswered == []


def test_a_loop_that_does_not_store_still_runs_and_reports():
    snd = IP(dst="10.0.0.1") / TCP()
    exchange, calls = fake_exchange([([], [snd])])
    answered, unanswered = T._loop(exchange, 2, 0, None, None, 0, False)
    assert len(calls) == 2
    assert answered == [] and unanswered == []


def test_an_interrupted_loop_returns_what_it_already_collected():
    snd = IP(dst="10.0.0.1") / TCP()
    rcv = IP(src="10.0.0.1") / TCP(flags="SA")
    calls = []

    def exchange():
        calls.append(1)
        if len(calls) == 3:
            raise KeyboardInterrupt
        return [(snd, rcv)], []

    answered, unanswered = T._loop(exchange, None, 0, None, None, 0, True)
    assert len(answered) == 2


def test_an_unbounded_loop_ends_on_an_interrupt_rather_than_hanging():
    # A deadline the caller checks after the call cannot catch a hang, so the
    # loop runs on a worker and the assertion is about the worker finishing.
    snd = IP(dst="10.0.0.1") / TCP()
    done = threading.Event()

    def exchange():
        raise KeyboardInterrupt

    def run():
        T._loop(exchange, None, 60, None, None, 0, True)
        done.set()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    assert done.wait(5), "an unbounded loop did not end when interrupted"


def test_a_round_reports_answers_and_failures():
    snd = IP(dst="10.0.0.1") / TCP()
    rcv = IP(src="10.0.0.1") / TCP(flags="SA")
    text = T._round_str([(snd, rcv)], [snd], None, None)
    assert text.splitlines()[0].startswith("RECV ")
    assert text.splitlines()[1].startswith("fail ")

    custom = T._round_str([(snd, rcv)], [snd],
                          lambda s, r: f"got {r[TCP].flags}",
                          lambda s: None)
    assert custom == "RECV got SA\n"
    assert T._round_str([], [], None, None) == ""


def test_a_pause_between_rounds_is_bounded_by_what_was_asked_for():
    import time

    start = time.monotonic()
    T._nap(0.05)
    assert 0.04 <= time.monotonic() - start < 2
    T._nap(0)
    T._nap(-1)


@live
@pytest.mark.parametrize("fn", ["srloop", "srploop"])
def test_the_loops_reach_the_backend(fn):
    pkt = IP(dst="10.99.0.2") / TCP() if fn == "srloop" \
        else Ether() / IP(dst="10.99.0.2") / TCP()
    with pytest.raises(OSError):
        getattr(P, fn)(pkt, count=1, iface=NO_SUCH_IF, timeout=0.1, verbose=0)


# --------------------------------------------------------------------------
# address lookup


def test_a_multicast_address_maps_to_its_mac_without_asking_anyone():
    # RFC 1112 §6.4: the low 23 bits of the group, under 01:00:5e.
    assert T._mapped_mac("224.0.0.1") == "01:00:5e:00:00:01"
    assert T._mapped_mac("224.0.0.251") == "01:00:5e:00:00:fb"
    assert T._mapped_mac("239.255.255.250") == "01:00:5e:7f:ff:fa"
    # The 23-bit window is why these two groups share one MAC.
    assert T._mapped_mac("225.128.0.1") == T._mapped_mac("224.0.0.1")


def test_the_broadcast_address_maps_to_the_broadcast_mac():
    assert T._mapped_mac("255.255.255.255") == "ff:ff:ff:ff:ff:ff"


def test_an_ordinary_address_has_to_be_asked_about():
    for addr in ("10.0.0.1", "192.168.1.255", "2001:db8::1", "not an address"):
        assert T._mapped_mac(addr) is None


def test_getmacbyip_answers_the_computed_cases_with_no_backend_at_all():
    assert P.getmacbyip("224.0.0.1") == "01:00:5e:00:00:01"
    assert P.getmacbyip("255.255.255.255") == "ff:ff:ff:ff:ff:ff"


@live
def test_getmacbyip_asks_for_anything_else():
    with pytest.raises(OSError):
        P.getmacbyip("10.99.0.2", iface=NO_SUCH_IF, timeout=0.1)


def test_an_address_needs_no_resolver_and_a_name_is_not_a_field():
    assert T._resolve("10.0.0.1") == "10.0.0.1"
    assert T._resolve("2001:db8::1") == "2001:db8::1"
    assert T._targets("10.0.0.1") == ["10.0.0.1"]
    assert T._targets(["10.0.0.1", "10.0.0.2"]) == ["10.0.0.1", "10.0.0.2"]
