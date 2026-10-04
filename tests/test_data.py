"""The constants and name databases in `wiry.data`."""

import os
import subprocess
import sys
import warnings

import pytest

import wiry
from wiry import data as D


def test_link_types_match_the_tcpdump_registry():
    assert (D.DLT_NULL, D.DLT_EN10MB, D.DLT_IEEE802_11) == (0, 1, 105)
    assert (D.DLT_LINUX_SLL, D.DLT_IEEE802_11_RADIO, D.DLT_LINUX_SLL2) == (113, 127, 276)
    assert D.ARPHRD_TO_DLT[D.ARPHRD_ETHER] == D.DLT_EN10MB
    assert D.ARPHRD_TO_DLT[D.ARPHRD_IEEE80211_RADIOTAP] == D.DLT_IEEE802_11_RADIO
    assert D.ETHER_BROADCAST == b"\xff" * 6 and D.ETHER_ANY == b"\x00" * 6
    assert (D.ETH_P_IP, D.ETH_P_ARP, D.ETH_P_IPV6) == (0x0800, 0x0806, 0x86DD)


def test_fixname():
    assert D.fixname("ndl-ahp-svc") == "ndl_ahp_svc"
    assert D.fixname(b"802.1Q") == "n_802_1Q"
    assert D.fixname("") == ""


def test_dadict_reaches_keys_through_values():
    a = D.DADict("test")
    a[0] = "test_value1"
    a["scapy"] = "test_value2"
    assert a.test_value1 == 0
    assert a.test_value2 == "scapy"
    assert a[0] == "test_value1"
    assert sorted(map(str, a.keys())) == ["0", "scapy"]
    assert "<test - 2 elements>" == repr(a)
    with pytest.raises(AttributeError):
        a.nothing_here


def test_dadict_truth_is_emptiness():
    one = D.DADict("one")
    assert not one
    one[1] = "x"
    assert one


def test_ether_types_old_spelling_warns():
    et = D.load_ethertypes(None)
    assert et.IPv4 == 0x0800 and et.ARP == 0x0806 and et.IPv6 == 0x86DD
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        et["BAOBAB"] = 0xFFFF
        assert et.BAOBAB == 0xFFFF
        assert issubclass(w[-1].category, DeprecationWarning)


def test_load_services_expands_ranges(tmp_path):
    path = tmp_path / "services"
    path.write_text(
        "itu-bicc-stc\t3097/sctp\n"
        "cvsup\t\t5999/udp\t\t\t# CVSup\n"
        "x11\t\t6000-6063/tcp\t\t\t# X Window System\n"
        "x11\t\t6000-6063/udp\n"
        "ndl-ahp-svc\t6064/tcp\n"
        "garbage line\n"
        "bad\tnotaport/tcp\n"
    )
    tcp, udp, sctp = D.load_services(str(path))
    assert tcp[6002] == "x11" and udp[6063] == "x11"
    assert tcp.ndl_ahp_svc == 6064
    assert udp.cvsup == 5999
    assert sctp[3097] == "itu_bicc_stc" and sctp.itu_bicc_stc == 3097
    assert D.load_services(str(tmp_path / "missing")) [0].keys() == []


def test_load_protocols(tmp_path):
    path = tmp_path / "protocols"
    path.write_text("# comment\nip 0 IP\ntcp 6 TCP\nudp\t17\tUDP # trailing\n")
    protos = D.load_protocols(str(path))
    assert protos[6] == "tcp" and protos.udp == 17


def test_manuf_bundled_copy():
    db = D.load_manuf(None)
    assert len(db) > 10000
    short, long_ = db.lookup("00:00:0c:12:34:56")
    assert "Cisco" in short and "Cisco" in long_
    assert db.lookup("fe:ff:ff:00:00:01") == ("fe:ff:ff:00:00:01",) * 2
    assert db._resolve_MAC("00:00:0c:12:34:56").endswith(":12:34:56")
    assert "00:00:0C" in db.reverse_lookup("cisco")


def test_databases_are_published_and_lazy():
    code = (
        "import wiry, wiry.data as d;"
        "assert 'MANUFDB' in dir(wiry) and 'ETHER_TYPES' in wiry.__all__;"
        "assert not any(n in vars(d) for n in ('MANUFDB', 'ETHER_TYPES', "
        "'IP_PROTOS', 'TCP_SERVICES'))"
    )
    subprocess.run([sys.executable, "-c", code], check=True)
    assert wiry.ETHER_TYPES.IPv4 == 0x0800
    assert wiry.MANUFDB is D.MANUFDB
    assert wiry.TCP_SERVICES is D.TCP_SERVICES


@pytest.mark.skipif(not os.path.exists("/etc/protocols"), reason="no /etc/protocols")
def test_ip_protos_from_the_host():
    assert D.IP_PROTOS[6] == "tcp" and D.IP_PROTOS.udp == 17


def test_knowledge_base():
    kb = D.KnowledgeBase("somewhere")
    assert kb.get_base() == ""
    kb.reload("elsewhere")
    assert kb.filename == "elsewhere"
