"""The half of live capture that needs no privileges.

libpcap is loaded at run time rather than linked at build time, so everything
below is about what that loader hands back: which library it found, the
interface table, and the BPF compiler. None of it opens a device, so all of it
runs in ordinary CI on every platform that has libpcap at all.

What is left over — a frame actually crossing a wire — is in ``dev/live/``,
because it needs root.
"""

import ipaddress
import threading

import pytest

import wiry as P
from helpers import ETHER_IP_TCP

live = pytest.mark.skipif(
    not P.capture_available(), reason="this host cannot load libpcap"
)

NO_SUCH_IF = "wiry-no-such-if0"


def _within(seconds, fn, *args, **kw):
    """A timing assertion after the call it measures cannot catch a hang."""
    out = []
    err = []

    def go():
        try:
            out.append(fn(*args, **kw))
        except BaseException as e:  # noqa: BLE001 - re-raised on the caller's thread
            err.append(e)

    t = threading.Thread(target=go, daemon=True)
    t.start()
    t.join(seconds)
    assert not t.is_alive(), f"did not finish in {seconds}s"
    if err:
        raise err[0]
    return out[0]


# --- what was loaded ---------------------------------------------------------


def test_the_backend_report_never_raises_and_answers_the_same_question():
    b = P.capture_backend()
    assert set(b) == {"available", "library", "version", "reason"}
    assert b["available"] is P.capture_available()
    assert (b["reason"] is None) is b["available"]


@live
def test_a_loaded_backend_names_the_library_and_its_version():
    b = P.capture_backend()
    assert b["library"], "available with nothing loaded"
    assert "pcap" in b["library"].lower()
    # pcap_lib_version has been in libpcap since 0.9; Npcap answers it too.
    assert "pcap" in b["version"].lower()


def test_an_unloadable_backend_says_what_to_install():
    b = P.capture_backend()
    if b["available"]:
        pytest.skip("this host can load libpcap")
    assert b["library"] is None and b["version"] is None
    assert "live capture" in b["reason"]


# --- the interface table -----------------------------------------------------


@live
def test_every_interface_has_a_name_and_they_are_distinct():
    ifs = P.interfaces()
    assert ifs, "libpcap reported no interfaces at all"
    names = [i["name"] for i in ifs]
    assert all(names)
    assert len(set(names)) == len(names)
    assert names == P.get_if_list()


@live
def test_one_interface_is_the_loopback():
    assert any(i["loopback"] for i in P.interfaces())


@live
def test_every_address_libpcap_reports_parses_as_one():
    for i in P.interfaces():
        for a in i["addresses"]:
            # A scope suffix is libpcap's, not ours, and is not part of the
            # address; ipaddress refuses it.
            ipaddress.ip_address(a.split("%")[0])


@live
def test_the_loopback_carries_its_own_address():
    lo = [i for i in P.interfaces() if i["loopback"]]
    assert any("127.0.0.1" in i["addresses"] or "::1" in i["addresses"] for i in lo)


@live
def test_the_default_interface_is_one_of_the_listed_ones():
    assert P.get_working_if() in P.get_if_list()


@live
def test_an_interface_address_is_the_one_the_table_lists():
    name = P.get_working_if()
    listed = [
        a for i in P.interfaces() if i["name"] == name
        for a in i["addresses"] if ":" not in a
    ]
    got = P.get_if_addr(name)
    assert got == (listed[0] if listed else "0.0.0.0")


@live
def test_an_unknown_interface_has_no_address_rather_than_an_error():
    assert P.get_if_addr(NO_SUCH_IF) == "0.0.0.0"


@live
def test_the_route_view_names_an_interface_that_exists():
    iface, src, gw = P.conf.route.route("10.0.0.1")
    assert iface in P.get_if_list()
    assert gw == "0.0.0.0"
    ipaddress.ip_address(src)


@live
def test_a_loopback_destination_routes_to_a_loopback_interface():
    iface, _, _ = P.conf.route.route("127.0.0.1")
    assert any(i["name"] == iface and i["loopback"] for i in P.interfaces())


# --- the BPF compiler --------------------------------------------------------
#
# The filter is libpcap's own bytecode, so compiling one proves the loader
# reached the half of libpcap that has nothing to do with a device. Running it
# over known bytes proves the program came back intact.


@live
def test_a_filter_selects_exactly_the_packets_it_names(tmp_path):
    path = tmp_path / "mixed.pcap"
    P.wrpcap(str(path), [
        P.Ether() / P.IP() / P.TCP(dport=80),
        P.Ether() / P.IP() / P.TCP(dport=443),
        P.Ether() / P.IP() / P.UDP(dport=53),
        P.Ether() / P.ARP(),
    ])
    assert len(P.sniff(offline=str(path))) == 4
    assert len(P.sniff(offline=str(path), filter="tcp port 80")) == 1
    assert len(P.sniff(offline=str(path), filter="tcp")) == 2
    assert len(P.sniff(offline=str(path), filter="udp")) == 1
    assert len(P.sniff(offline=str(path), filter="arp")) == 1
    assert len(P.sniff(offline=str(path), filter="icmp")) == 0


@live
def test_a_filter_and_a_where_clause_narrow_together(tmp_path):
    path = tmp_path / "ttl.pcap"
    P.wrpcap(str(path), [
        P.Ether() / P.IP(ttl=64) / P.TCP(dport=80),
        P.Ether() / P.IP(ttl=1) / P.TCP(dport=80),
    ])
    got = P.sniff(offline=str(path), filter="tcp port 80", where=("IP", "ttl", 1))
    assert len(got) == 1
    assert got[0][P.IP].ttl == 1


@live
def test_a_filter_survives_the_bytes_it_is_run_over(tmp_path):
    """The compiled program outlives the call that made it, and libpcap's
    userland interpreter must not read past a truncated frame."""
    path = tmp_path / "short.pcap"
    P.wrpcap(str(path), [P.Ether(ETHER_IP_TCP[:20]), P.Ether(ETHER_IP_TCP)])
    assert len(P.sniff(offline=str(path), filter="tcp port 80")) == 1


@live
@pytest.mark.parametrize("expr", ["tcp port", "nonsense gibberish", "port 99999999"])
def test_a_malformed_filter_is_refused_with_libpcaps_own_message(tmp_path, expr):
    path = tmp_path / "one.pcap"
    P.wrpcap(str(path), [P.Ether() / P.IP() / P.TCP()])
    with pytest.raises(ValueError) as exc:
        P.sniff(offline=str(path), filter=expr)
    assert str(exc.value)


@live
def test_a_filter_is_compiled_for_the_link_type_it_will_run_on(tmp_path):
    """DLT_NULL is not Ethernet: the same expression is a different program,
    and one compiled for the wrong link type reads the wrong offsets. macOS
    lo0 is the case this exists for."""
    null = tmp_path / "null.pcap"
    P.wrpcap(str(null), [P.Loopback() / P.IP() / P.TCP(dport=80)], linktype=0)
    assert len(P.sniff(offline=str(null), filter="tcp port 80")) == 1
    assert len(P.sniff(offline=str(null), filter="tcp port 81")) == 0


# --- refusals, without opening anything --------------------------------------


@live
def test_an_unknown_interface_fails_rather_than_blocking():
    with pytest.raises(OSError):
        _within(10.0, P.sniff, iface=NO_SUCH_IF, timeout=0.1)


@live
def test_a_malformed_filter_is_refused_before_a_device_is_opened():
    with pytest.raises((ValueError, OSError)):
        _within(10.0, P.sniff, iface=NO_SUCH_IF, filter="tcp port", timeout=0.1)


@live
def test_an_interface_name_holding_a_nul_is_refused():
    with pytest.raises((ValueError, OSError)):
        _within(10.0, P.sniff, iface="lo\x000", timeout=0.1)
