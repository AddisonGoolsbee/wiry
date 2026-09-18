"""``conf``: what each knob does, and what happens when one cannot be moved.

The rule the whole object is built on is that nothing here is inert. A knob
that silently absorbed a setting would be worse than a missing one, so a value
wiry cannot honour raises by name, and a name wiry does not have raises too.
"""

import pytest

import wiry as P
from wiry import capture as C

live = pytest.mark.skipif(
    not P.capture_available(), reason="built without the live feature"
)
absent = pytest.mark.skipif(
    P.capture_available(), reason="this build has the live feature"
)


@pytest.fixture(autouse=True)
def restore():
    conf = P.conf
    saved = (conf.verb, conf.promisc, conf.sniff_promisc, conf.checkIPaddr,
             conf._iface)
    yield
    (conf.verb, conf.promisc, conf.sniff_promisc, conf.checkIPaddr,
     conf._iface) = saved


def test_the_knobs_scripts_read_are_all_present_and_are_booleans():
    assert P.conf.promisc is True
    assert P.conf.sniff_promisc is True
    assert P.conf.checkIPaddr is True
    assert isinstance(P.conf.verb, int)


def test_a_knob_conf_does_not_have_is_refused_rather_than_absorbed():
    for name in ("checkIPsrc", "route6", "manufdb", "nonsense"):
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


@pytest.mark.parametrize("name", ["l3socket", "l2socket", "L3socket",
                                  "L2socket"])
def test_a_socket_knob_reads_none_and_refuses_anything_else(name):
    # scapy's save-and-restore idiom has to keep working, and it does: the
    # value that comes back out is the only one that goes back in.
    saved = getattr(P.conf, name)
    assert saved is None
    setattr(P.conf, name, saved)
    with pytest.raises(NotImplementedError) as exc:
        setattr(P.conf, name, object)
    assert "socket" in str(exc.value)


def test_conf_says_what_it_holds():
    text = repr(P.conf)
    assert "verb=" in text and "checkIPaddr=" in text


@live
def test_the_route_view_answers_an_interface_and_a_source_address():
    iface, out, gateway = P.conf.route.route("10.0.0.1")
    assert iface == P.conf.iface
    assert out == P.get_if_addr(iface)
    assert gateway == "0.0.0.0"


@live
def test_a_loopback_destination_routes_to_a_loopback_interface():
    loopbacks = [i["name"] for i in P.interfaces() if i["loopback"]]
    iface, _, _ = P.conf.route.route("127.0.0.1")
    assert iface in loopbacks or not loopbacks


@live
def test_the_route_table_is_interface_addresses_and_says_so():
    routes = P.conf.route.routes
    names = {i["name"] for i in P.interfaces()}
    for net, mask, gateway, iface, out, metric in routes:
        assert mask == "255.255.255.255"
        assert gateway == "0.0.0.0"
        assert iface in names
        assert net == out
    assert "no kernel table" in repr(P.conf.route)
    # A read-only view: the list handed out is a copy, and the attribute
    # itself cannot be replaced with a table wiry would then be believed for.
    routes.append(("bogus",))
    assert len(P.conf.route.routes) == len(routes) - 1
    with pytest.raises(AttributeError):
        P.conf.route.routes = []
    with pytest.raises(AttributeError):
        P.conf.route = None
    P.conf.route.resync()


@absent
def test_the_route_view_needs_the_live_feature_to_say_anything():
    with pytest.raises(P.CaptureUnavailable):
        P.conf.route.routes
    with pytest.raises(P.CaptureUnavailable):
        P.conf.route.route("10.0.0.1")


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
