"""The live surface, as far as it goes without root.

Everything that needs a real interface lives in ``dev/live/``. What is left
here is the plumbing: the keywords the live driver takes, the refusals it makes
before touching a device, and the errors it raises when it cannot open one.
"""

import pytest

import wiry as P
from wiry import capture as C

live = pytest.mark.skipif(
    not P.capture_available(), reason="this host cannot load libpcap"
)

NO_SUCH_IF = "wiry-no-such-if0"


def test_live_args_mirror_the_sniff_keywords():
    a = C._live_args(iface="eth0", count=3, store=0, timeout=2,
                     where=("IP", "ttl", 64))
    assert a["iface"] == "eth0"
    assert a["count"] == 3
    assert a["store"] is False
    assert a["timeout"] == 2.0
    assert a["conds"] == [("IP", "ttl", "==", 64)]
    assert a["wrap"] is C._wrap


def test_live_args_reject_a_keyword_sniff_does_not_take():
    with pytest.raises(TypeError):
        C._live_args(iface="eth0", session=object())


def test_live_args_refuse_an_offline_source():
    with pytest.raises(ValueError):
        C._live_args(iface="eth0", offline="somewhere.pcap")


def test_an_explicit_interface_wins_over_conf():
    assert C._iface_name("eth7") == "eth7"


@live
def test_sniffing_an_unknown_interface_raises_oserror():
    with pytest.raises(OSError):
        P.sniff(iface=NO_SUCH_IF, timeout=0.1)


@live
def test_a_malformed_bpf_filter_is_refused_before_any_capture():
    with pytest.raises((ValueError, OSError)):
        P.sniff(iface=NO_SUCH_IF, filter="tcp port", timeout=0.1)


def test_a_sniffer_is_weak_referenceable_so_the_atexit_hook_holds_nothing():
    import weakref

    s = P.AsyncSniffer(offline=None, iface="eth0")
    ref = weakref.ref(s)
    assert ref() is s
    del s
    assert ref() is None


def test_stopping_every_running_sniffer_survives_a_broken_one():
    class Broken:
        def stop(self):
            raise RuntimeError("no")

    b = Broken()
    C._RUNNING.add(b)
    try:
        C._stop_running_sniffers()
    finally:
        C._RUNNING.discard(b)


@live
def test_a_failed_start_leaves_the_sniffer_idle_and_restartable():
    s = P.AsyncSniffer(iface=NO_SUCH_IF, timeout=0.1)
    with pytest.raises(OSError):
        s.start()
    assert not s.running
    assert s.results is None
    with pytest.raises(OSError):
        s.start()


def test_an_unset_ether_src_is_filled_only_at_send_time():
    from wiry import Ether, IP

    pkt = Ether() / IP()
    filled = C._with_src(pkt, "aa:bb:cc:dd:ee:ff")
    assert bytes(filled)[6:12] == b"\xaa\xbb\xcc\xdd\xee\xff"
    # The build path stays reproducible, and the caller's packet untouched.
    assert bytes(pkt)[6:12] == b"\x00" * 6
    assert bytes(Ether())[6:12] == b"\x00" * 6


def test_an_explicit_ether_src_is_never_overwritten():
    from wiry import Ether, IP

    pkt = Ether(src="02:00:00:00:00:09") / IP()
    assert bytes(C._with_src(pkt, "aa:bb:cc:dd:ee:ff"))[6:12] == bytes.fromhex(
        "020000000009"
    )


def test_no_interface_address_is_an_ordinary_outcome():
    from wiry import Ether, IP

    pkt = Ether() / IP()
    assert C._with_src(pkt, None) is pkt
    assert C._with_src(b"\x00" * 14, "aa:bb:cc:dd:ee:ff") == b"\x00" * 14


def test_an_arp_request_is_filled_in_at_send_time_too():
    # E9: without this an arping asks on behalf of 00:00:00:00:00:00 and
    # 0.0.0.0, which is the one function where it actually breaks.
    from wiry import ARP, Ether

    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="10.0.0.9")
    filled = C._with_src(pkt, "aa:bb:cc:dd:ee:ff", "10.0.0.5")
    assert filled[ARP].hwsrc == "aa:bb:cc:dd:ee:ff"
    assert filled[ARP].psrc == "10.0.0.5"
    assert filled[Ether].src == "aa:bb:cc:dd:ee:ff"
    # Construction stays reproducible and the caller's packet untouched.
    assert pkt[ARP].hwsrc == "00:00:00:00:00:00"
    assert pkt[ARP].psrc == "0.0.0.0"
    assert bytes(Ether() / ARP()) == bytes(Ether() / ARP())


def test_an_arp_request_that_says_who_it_is_is_left_alone():
    from wiry import ARP, Ether

    pkt = Ether() / ARP(hwsrc="02:00:00:00:00:09", psrc="10.0.0.7",
                        pdst="10.0.0.9")
    filled = C._with_src(pkt, "aa:bb:cc:dd:ee:ff", "10.0.0.5")
    assert filled[ARP].hwsrc == "02:00:00:00:00:09"
    assert filled[ARP].psrc == "10.0.0.7"


def test_an_unknown_interface_address_leaves_the_arp_field_alone():
    from wiry import ARP, Ether

    pkt = Ether() / ARP(pdst="10.0.0.9")
    assert C._with_src(pkt, None, None) is pkt
    assert C._with_src(pkt, "aa:bb:cc:dd:ee:ff", None)[ARP].psrc == "0.0.0.0"


def test_the_interface_address_is_unknown_off_linux_and_never_a_path():
    import sys

    assert P._wiry.interface_mac("../../etc/passwd") is None
    assert P._wiry.interface_mac("wiry-no-such-if0") is None
    if sys.platform != "linux":
        assert P._wiry.interface_mac("lo") is None


@live
def test_send_refuses_ipv6_and_names_sendp():
    from wiry import IPv6, UDP

    with pytest.raises(NotImplementedError) as exc:
        P.send(IPv6() / UDP())
    assert "sendp" in str(exc.value)


@live
def test_send_refuses_the_arguments_it_does_not_implement():
    from wiry import Ether, IP

    with pytest.raises(NotImplementedError):
        P.sendp(Ether() / IP(), socket=object(), iface=NO_SUCH_IF)
    with pytest.raises(NotImplementedError):
        P.sendp(Ether() / IP(), realtime=True, iface=NO_SUCH_IF)


@live
def test_sendp_on_an_unknown_interface_raises_oserror():
    from wiry import Ether, IP

    with pytest.raises(OSError):
        P.sendp(Ether() / IP(), iface=NO_SUCH_IF, verbose=0)


@live
def test_a_negative_retry_is_refused_rather_than_guessed_at():
    from wiry import Ether, ARP

    with pytest.raises(NotImplementedError) as exc:
        P.srp(Ether() / ARP(pdst="10.0.0.1"), iface=NO_SUCH_IF, retry=-1,
              timeout=0.1, verbose=0)
    assert "retry" in str(exc.value)


@live
def test_sr_refuses_ipv6_and_names_sendp():
    from wiry import IPv6, UDP

    with pytest.raises(NotImplementedError) as exc:
        P.sr(IPv6() / UDP(), iface=NO_SUCH_IF, timeout=0.1, verbose=0)
    assert "sendp" in str(exc.value)


@live
@pytest.mark.parametrize("fn", ["sr", "sr1", "srp", "srp1"])
def test_every_exchange_reaches_the_backend(fn):
    from wiry import Ether, IP, ICMP

    pkt = IP(dst="10.99.0.2") / ICMP() if fn.startswith("sr") and "p" not in fn \
        else Ether() / IP(dst="10.99.0.2") / ICMP()
    with pytest.raises(OSError):
        getattr(P, fn)(pkt, iface=NO_SUCH_IF, timeout=0.1, verbose=0)


def test_only_a_packet_or_bytes_can_be_sent():
    from wiry import Ether, IP

    assert C._octets("AB") == b"AB"
    assert C._octets(b"AB") == b"AB"
    assert C._octets(bytearray(b"AB")) == b"AB"
    assert C._octets(memoryview(b"AB")) == b"AB"
    assert C._octets(Ether() / IP()) == bytes(Ether() / IP())
    # bytes(3) is three zero octets, so sendp([1, 2, 3]) used to put three
    # all-zero frames on the wire instead of complaining.
    for junk in (1, None, 3.5, object()):
        with pytest.raises(TypeError):
            C._octets(junk)


def test_an_ipv6_datagram_is_refused_however_it_is_spelt():
    from wiry import IP, IPv6, TCP

    six = bytes(IPv6() / TCP())
    for pkts in ([IPv6() / TCP()], [six], [bytearray(six)]):
        frames = [C._octets(p) for p in pkts]
        with pytest.raises(NotImplementedError) as exc:
            C._refuse_ipv6(pkts, frames, "send")
        assert "sendp" in str(exc.value)
    four = [IP() / TCP()]
    C._refuse_ipv6(four, [C._octets(p) for p in four], "send")
    C._refuse_ipv6([b""], [b""], "send")


def test_a_pause_between_packets_must_be_finite():
    assert C._pause(0) == 0.0
    assert C._pause(0.25) == 0.25
    for bad in (float("inf"), float("-inf"), float("nan")):
        with pytest.raises(ValueError) as exc:
            C._pause(bad)
        assert "inter" in str(exc.value)


def test_a_timeout_no_float_can_represent_does_not_panic_the_backend():
    # LiveSniffer builds its whole state before it touches a device, so this
    # is reachable in a build with no live feature at all.
    for t in (float("inf"), float("-inf"), float("nan"), 1e300, -5.0):
        s = P._wiry.LiveSniffer(timeout=t)
        assert s.running() is False
        assert s.results() is None


@live
def test_send_refuses_a_buffer_that_is_not_an_ipv4_datagram():
    from wiry import Ether, IP, TCP

    # An Ethernet frame's destination MAC read as an IP header used to send a
    # datagram to 0.40.0.1; anything at all of 20 octets was accepted.
    for buf in (bytes(Ether() / IP() / TCP()), b"this is not a packet at all!!",
                bytes(20), b"\xff" * 40):
        with pytest.raises(ValueError):
            P.send(buf, verbose=0)


@live
def test_send_refuses_raw_ipv6_bytes_and_names_sendp():
    from wiry import IPv6, TCP

    with pytest.raises(NotImplementedError) as exc:
        P.send(bytes(IPv6() / TCP()), verbose=0)
    assert "sendp" in str(exc.value)


@live
def test_a_retry_or_multi_round_needs_a_timeout():
    from wiry import IP, ICMP

    for kw in ({"retry": 1}, {"multi": True}):
        with pytest.raises(ValueError) as exc:
            P.sr(IP(dst="10.99.0.2") / ICMP(), iface=NO_SUCH_IF, verbose=0, **kw)
        assert "timeout" in str(exc.value)


@live
def test_an_infinite_inter_is_refused_rather_than_slept_on():
    from wiry import Ether, IP

    with pytest.raises(ValueError) as exc:
        P.sendp(Ether() / IP(), iface=NO_SUCH_IF, inter=float("inf"), verbose=0)
    assert "inter" in str(exc.value)
