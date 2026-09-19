"""The routing tables: the arithmetic, and what the host's own table says.

The decision `route()` makes is arithmetic over a table, so almost all of this
runs against a table written out by hand. What the host contributes is checked
separately and only for shape, because a machine's routes are not a fixture.
"""

import pytest

from wiry import Route, Route6, read_routes, read_routes6
from wiry.route import (
    IPV6_ADDR_GLOBAL,
    IPV6_ADDR_LINKLOCAL,
    IPV6_ADDR_LOOPBACK,
    IPV6_ADDR_MULTICAST,
    atol,
    get_source_addr_from_candidate_set,
    in6_getifaddr,
    in6_getscope,
    itom,
    loopback_name,
    ltoa,
)


@pytest.fixture
def table():
    """A table nothing reads from the host: default via a gateway, one
    directly connected /24, and loopback."""
    r = Route(autoload=False)
    r.routes = [
        (atol("0.0.0.0"), itom(0), "192.0.2.1", "eth0", "192.0.2.15", 100),
        (atol("192.0.2.0"), itom(24), "0.0.0.0", "eth0", "192.0.2.15", 0),
        (atol("10.1.0.0"), itom(16), "0.0.0.0", "eth1", "10.1.0.7", 0),
        (atol("127.0.0.0"), itom(8), "0.0.0.0", "lo", "127.0.0.1", 0),
    ]
    return r


def test_an_address_converts_both_ways():
    assert atol("1.2.3.4") == 0x01020304
    assert ltoa(0x01020304) == "1.2.3.4"
    assert itom(24) == 0xFFFFFF00
    assert itom(0) == 0
    assert itom(32) == 0xFFFFFFFF
    with pytest.raises(ValueError):
        atol("not an address")


def test_the_longest_matching_prefix_wins(table):
    assert table.route("192.0.2.9") == ("eth0", "192.0.2.15", "0.0.0.0")
    assert table.route("10.1.2.3") == ("eth1", "10.1.0.7", "0.0.0.0")
    assert table.route("8.8.8.8") == ("eth0", "192.0.2.15", "192.0.2.1")


def test_the_metric_breaks_a_tie_between_equal_prefixes(table):
    table.routes.append(
        (atol("10.1.0.0"), itom(16), "0.0.0.0", "eth2", "10.1.0.8", 500))
    table.invalidate_cache()
    assert table.route("10.1.2.3")[0] == "eth1"


def test_one_of_our_own_addresses_routes_over_loopback(table):
    assert table.route("192.0.2.15") == (loopback_name(), "192.0.2.15",
                                         "0.0.0.0")


def test_a_destination_nothing_matches_is_a_visible_non_answer():
    empty = Route(autoload=False)
    assert empty.route("8.8.8.8") == (loopback_name(), "0.0.0.0", "0.0.0.0")


def test_dev_narrows_the_search_to_one_interface(table):
    assert table.route("10.1.2.3", dev="eth1") == ("eth1", "10.1.0.7",
                                                   "0.0.0.0")
    # Narrowed to an interface with no matching route, the answer is the
    # visible non-answer rather than the default route on another interface.
    assert table.route("8.8.8.8", dev="eth1") == ("eth1", "0.0.0.0",
                                                  "0.0.0.0")


def test_a_destination_written_as_a_set_routes_as_one_of_its_members(table):
    assert table.route("192.0.2.*") == table.route("192.0.2.0")
    assert table.route("10.1.2.1-5") == table.route("10.1.2.1")
    assert table.route("192.0.2.0/24") == table.route("192.0.2.0")


def test_a_route_can_be_added_and_taken_away_again(table):
    table.add(net="203.0.113.0/24", gw="192.0.2.254")
    assert table.route("203.0.113.9") == ("eth0", "192.0.2.15", "192.0.2.254")
    table.delete(net="203.0.113.0/24", gw="192.0.2.254")
    assert table.route("203.0.113.9")[2] == "192.0.2.1"
    with pytest.raises(ValueError, match="No matching route"):
        table.delete(net="203.0.113.0/24", gw="192.0.2.254")


def test_a_host_route_can_be_pinned_to_an_interface(table):
    table.add(host="198.51.100.1", dev="eth1")
    assert table.route("198.51.100.1")[0] == "eth1"
    with pytest.raises(ValueError, match="host="):
        table.add(gw="192.0.2.1")


def test_adding_a_route_drops_the_cache(table):
    assert table.route("203.0.113.9")[2] == "192.0.2.1"
    table.add(net="203.0.113.0/24", gw="192.0.2.254")
    assert table.route("203.0.113.9")[2] == "192.0.2.254"


def test_an_interface_can_be_added_changed_and_removed(table):
    table.ifadd("eth9", "198.51.100.5/24")
    assert table.route("198.51.100.9") == ("eth9", "198.51.100.5", "0.0.0.0")
    table.ifchange("eth9", "198.51.100.6/24")
    assert table.route("198.51.100.9")[1] == "198.51.100.6"
    table.ifdel("eth9")
    assert table.route("198.51.100.9")[0] == "eth0"


def test_broadcast_addresses_come_from_the_connected_routes(table):
    assert table.get_if_bcast("eth0") == ["192.0.2.255"]
    assert table.get_if_bcast("eth1") == ["10.1.255.255"]
    assert table.get_if_bcast("nothing") == []


def test_the_table_renders_as_a_table(table):
    text = repr(table)
    assert "Network" in text and "192.0.2.0" in text and "eth0" in text


def test_resync_reads_the_host_and_drops_what_was_added(table):
    table.add(net="203.0.113.0/24", gw="192.0.2.254")
    table.resync()
    assert not any(r[2] == "192.0.2.254" for r in table.routes)


# --- IPv6 -------------------------------------------------------------------


def test_an_ipv6_address_is_classified_by_scope():
    assert in6_getscope("::1") == IPV6_ADDR_LOOPBACK
    assert in6_getscope("fe80::1") == IPV6_ADDR_LINKLOCAL
    assert in6_getscope("ff02::1") == IPV6_ADDR_MULTICAST
    assert in6_getscope("2001:db8::1") == IPV6_ADDR_GLOBAL
    assert in6_getscope("nonsense") == -1


@pytest.fixture
def table6():
    r = Route6(autoload=False)
    r.routes = [
        ("::", 0, "fe80::1", "eth0", ["2001:db8:1::5"], 100),
        ("2001:db8:1::", 64, "::", "eth0", ["2001:db8:1::5"], 0),
        ("2001:db8:2::", 64, "::", "eth1", ["2001:db8:2::9"], 0),
        ("fe80::", 64, "::", "eth0", ["fe80::5"], 0),
    ]
    return r


def test_an_ipv6_route_takes_the_longest_prefix(table6):
    assert table6.route("2001:db8:2::1") == ("eth1", "2001:db8:2::9", "::")
    assert table6.route("2001:db8:9::1") == ("eth0", "2001:db8:1::5",
                                             "fe80::1")


def test_a_link_local_destination_uses_a_link_local_source(table6):
    assert table6.route("fe80::abc") == ("eth0", "fe80::5", "::")


def test_loopback_answers_even_with_no_route_for_it():
    assert Route6(autoload=False).route("::1") == (loopback_name(), "::1", "::")


def test_an_ipv6_route_can_be_added_and_taken_away(table6):
    table6.add(dst="2001:db8:3::/64", gw="fe80::2")
    assert table6.route("2001:db8:3::1")[2] == "fe80::2"
    table6.delete("2001:db8:3::/64")
    assert table6.route("2001:db8:3::1")[2] == "fe80::1"
    with pytest.raises(ValueError, match="No matching route"):
        table6.delete("2001:db8:3::/64")


def test_an_ipv6_interface_address_becomes_a_prefix_route(table6):
    table6.ifadd("eth7", "2001:db8:7::9/64")
    assert table6.route("2001:db8:7::1") == ("eth7", "2001:db8:7::9", "::")
    assert "eth7" in table6.ipv6_ifaces
    table6.ifdel("eth7")
    assert "eth7" not in table6.ipv6_ifaces


def test_a_source_is_chosen_by_scope_then_by_longest_common_prefix():
    cset = ["fe80::9", "2001:db8:1::5", "2001:db8:9::5"]
    assert get_source_addr_from_candidate_set("2001:db8:9::1", cset) == \
        "2001:db8:9::5"
    assert get_source_addr_from_candidate_set("fe80::1", cset) == "fe80::9"
    assert get_source_addr_from_candidate_set("2001:db8::1", []) is None


def test_a_bad_ipv6_destination_is_refused_rather_than_guessed(table6):
    with pytest.raises(ValueError, match="IPv6"):
        table6.route("192.0.2.1")


def test_the_ipv6_table_renders_as_a_table(table6):
    assert "Destination" in repr(table6) and "eth1" in repr(table6)


def test_flush_empties_the_ipv6_table(table6):
    table6.flush()
    assert table6.routes == [] and table6.ipv6_ifaces == set()


# --- what this host says ----------------------------------------------------


def test_the_host_table_has_the_shape_every_reader_expects():
    for net, mask, gw, iface, addr, metric in read_routes():
        assert 0 <= net <= 0xFFFFFFFF
        assert 0 <= mask <= 0xFFFFFFFF
        assert ltoa(atol(gw)) == gw
        assert isinstance(iface, str) and iface
        assert ltoa(atol(addr)) == addr
        assert isinstance(metric, int)


def test_the_host_ipv6_table_has_the_shape_every_reader_expects():
    for prefix, plen, nh, iface, cset, metric in read_routes6():
        assert in6_getscope(prefix) != -1
        assert 0 <= plen <= 128
        assert in6_getscope(nh) != -1
        assert isinstance(iface, str) and iface
        assert cset and all(in6_getscope(a) != -1 for a in cset)
        assert isinstance(metric, int)


def test_the_host_reports_its_own_addresses():
    for addr, scope, dev in in6_getifaddr():
        assert in6_getscope(addr) == scope
        assert isinstance(dev, str)
