"""The live surface, as far as it goes without root.

Everything that needs a real interface lives in ``dev/live/``. What is left
here is the plumbing: the keywords the live driver takes, the refusals it makes
before touching a device, and the errors it raises when it cannot open one.
"""

import pytest

import packetry as P
from packetry import capture as C

live = pytest.mark.skipif(
    not P.capture_available(), reason="built without the live feature"
)

NO_SUCH_IF = "packetry-no-such-if0"


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
    from packetry import Ether, IP

    pkt = Ether() / IP()
    filled = C._with_src(pkt, "aa:bb:cc:dd:ee:ff")
    assert bytes(filled)[6:12] == b"\xaa\xbb\xcc\xdd\xee\xff"
    # The build path stays reproducible, and the caller's packet untouched.
    assert bytes(pkt)[6:12] == b"\x00" * 6
    assert bytes(Ether())[6:12] == b"\x00" * 6


def test_an_explicit_ether_src_is_never_overwritten():
    from packetry import Ether, IP

    pkt = Ether(src="02:00:00:00:00:09") / IP()
    assert bytes(C._with_src(pkt, "aa:bb:cc:dd:ee:ff"))[6:12] == bytes.fromhex(
        "020000000009"
    )


def test_no_interface_address_is_an_ordinary_outcome():
    from packetry import Ether, IP

    pkt = Ether() / IP()
    assert C._with_src(pkt, None) is pkt
    assert C._with_src(b"\x00" * 14, "aa:bb:cc:dd:ee:ff") == b"\x00" * 14


def test_the_interface_address_is_unknown_off_linux_and_never_a_path():
    import sys

    assert P._packetry.interface_mac("../../etc/passwd") is None
    assert P._packetry.interface_mac("packetry-no-such-if0") is None
    if sys.platform != "linux":
        assert P._packetry.interface_mac("lo") is None


@live
def test_send_refuses_ipv6_and_names_sendp():
    from packetry import IPv6, UDP

    with pytest.raises(NotImplementedError) as exc:
        P.send(IPv6() / UDP())
    assert "sendp" in str(exc.value)


@live
def test_send_refuses_the_arguments_it_does_not_implement():
    from packetry import Ether, IP

    with pytest.raises(NotImplementedError):
        P.sendp(Ether() / IP(), socket=object(), iface=NO_SUCH_IF)
    with pytest.raises(NotImplementedError):
        P.sendp(Ether() / IP(), realtime=True, iface=NO_SUCH_IF)


@live
def test_sendp_on_an_unknown_interface_raises_oserror():
    from packetry import Ether, IP

    with pytest.raises(OSError):
        P.sendp(Ether() / IP(), iface=NO_SUCH_IF, verbose=0)


@live
def test_a_negative_retry_is_refused_rather_than_guessed_at():
    from packetry import Ether, ARP

    with pytest.raises(NotImplementedError) as exc:
        P.srp(Ether() / ARP(pdst="10.0.0.1"), iface=NO_SUCH_IF, retry=-1,
              timeout=0.1, verbose=0)
    assert "retry" in str(exc.value)


@live
def test_sr_refuses_ipv6_and_names_sendp():
    from packetry import IPv6, UDP

    with pytest.raises(NotImplementedError) as exc:
        P.sr(IPv6() / UDP(), iface=NO_SUCH_IF, timeout=0.1, verbose=0)
    assert "sendp" in str(exc.value)


@live
@pytest.mark.parametrize("fn", ["sr", "sr1", "srp", "srp1"])
def test_every_exchange_reaches_the_backend(fn):
    from packetry import Ether, IP, ICMP

    pkt = IP(dst="10.99.0.2") / ICMP() if fn.startswith("sr") and "p" not in fn \
        else Ether() / IP(dst="10.99.0.2") / ICMP()
    with pytest.raises(OSError):
        getattr(P, fn)(pkt, iface=NO_SUCH_IF, timeout=0.1, verbose=0)
