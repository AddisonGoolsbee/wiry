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
