"""``conf``: what each knob does, and what happens when one cannot be moved.

The rule the whole object is built on is that nothing here is inert. A knob
that silently absorbed a setting would be worse than a missing one, so a value
wiry cannot honour raises by name, and a name wiry does not have raises too.
"""

import time

import pytest

import wiry as P
from wiry import capture as C

live = pytest.mark.skipif(
    not P.capture_available(), reason="this host cannot load libpcap"
)
absent = pytest.mark.skipif(
    P.capture_available(), reason="this host can load libpcap"
)


@pytest.fixture(autouse=True)
def restore():
    conf = P.conf
    saved = (conf.verb, conf.promisc, conf.sniff_promisc, conf.checkIPaddr,
             conf.debug_dissector, conf.recv_poll_rate, conf._iface,
             conf._l3socket, conf._l2socket, conf._l2listen, conf._loopback)
    yield
    (conf.verb, conf.promisc, conf.sniff_promisc, conf.checkIPaddr,
     conf.debug_dissector, conf.recv_poll_rate, conf._iface,
     conf._l3socket, conf._l2socket, conf._l2listen, conf._loopback) = saved


def test_the_knobs_scripts_read_are_all_present_and_are_booleans():
    assert P.conf.promisc is True
    assert P.conf.sniff_promisc is True
    assert P.conf.checkIPaddr is True
    assert P.conf.debug_dissector is False
    assert isinstance(P.conf.verb, int)
    assert P.conf.recv_poll_rate > 0


def test_a_knob_conf_does_not_have_is_refused_rather_than_absorbed():
    for name in ("checkIPsrc", "manufdb", "color_theme", "nonsense"):
        with pytest.raises(AttributeError):
            setattr(P.conf, name, True)


def test_sniff_takes_its_promiscuity_from_conf_unless_told_otherwise():
    P.conf.sniff_promisc = False
    assert C._live_args(iface="eth0")["promisc"] is False
    assert C._live_args(iface="eth0", promisc=True)["promisc"] is True
    P.conf.sniff_promisc = True
    assert C._live_args(iface="eth0")["promisc"] is True
    assert C._live_args(iface="eth0", promisc=False)["promisc"] is False


def test_use_pcap_reports_the_build_and_refuses_to_be_changed():
    assert P.conf.use_pcap is P.capture_available()
    P.conf.use_pcap = P.capture_available()
    with pytest.raises(NotImplementedError) as exc:
        P.conf.use_pcap = not P.capture_available()
    assert "libpcap" in str(exc.value)


@pytest.mark.parametrize("name,default", [
    ("l3socket", "L3Socket"), ("l2socket", "L2Socket"),
    ("l2listen", "L2ListenSocket"), ("L3socket", "L3Socket"),
    ("L2socket", "L2Socket"), ("L2listen", "L2ListenSocket"),
])
def test_a_socket_knob_names_a_real_class_and_takes_a_replacement(name, default):
    assert getattr(P.conf, name).__name__ == default
    sentinel = object()
    setattr(P.conf, name, sentinel)
    assert getattr(P.conf, name) is sentinel
    # None is "back to wiry's own", which is what a save-and-restore wants.
    setattr(P.conf, name, None)
    assert getattr(P.conf, name).__name__ == default


def test_loopback_name_is_this_hosts_and_is_what_a_route_falls_back_to():
    from wiry import Route

    assert P.conf.loopback_name in ("lo", "lo0")
    P.conf.loopback_name = "lo42"
    assert Route(autoload=False).route("8.8.8.8")[0] == "lo42"
    P.conf.loopback_name = None
    assert P.conf.loopback_name in ("lo", "lo0")


def test_recv_poll_rate_is_the_wait_a_select_takes_when_given_none():
    from wiry import ObjectPipe, SuperSocket

    pipe = ObjectPipe("t")
    try:
        P.conf.recv_poll_rate = 0.3
        started = time.monotonic()
        assert SuperSocket.select([pipe]) == []
        assert time.monotonic() - started >= 0.25
    finally:
        pipe.close()


def test_conf_says_what_it_holds():
    text = repr(P.conf)
    assert "verb=" in text and "checkIPaddr=" in text


def test_the_routing_tables_are_read_without_the_live_feature():
    # Reading /proc or netstat needs neither libpcap nor a privilege, which is
    # what lets a build with no capture backend still answer a route.
    assert isinstance(P.conf.route.routes, list)
    assert isinstance(P.conf.route6.routes, list)
    iface, src, gw = P.conf.route.route("127.0.0.1")
    assert iface == P.conf.loopback_name
    assert src == "127.0.0.1"
    assert gw == "0.0.0.0"


def test_the_route_tables_cannot_be_swapped_wholesale():
    with pytest.raises(AttributeError):
        P.conf.route = None
    with pytest.raises(AttributeError):
        P.conf.route6 = None


@live
def test_the_interface_hardware_address_is_readable_or_refused_by_name():
    for info in P.interfaces():
        try:
            mac = P.get_if_hwaddr(info["name"])
        except ValueError as exc:
            assert info["name"] in str(exc)
            continue
        assert len(mac.split(":")) == 6


@absent
def test_the_interface_hardware_address_needs_the_live_feature():
    with pytest.raises(P.CaptureUnavailable):
        P.get_if_hwaddr("eth0")
