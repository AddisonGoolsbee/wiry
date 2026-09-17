"""The capture surface with no live backend.

Every name must import and every entry point must explain itself. A build with
the feature on skips only the assertions that are about its absence.
"""

import pytest

import packetry as P

NAMES = [
    "sniff", "AsyncSniffer", "send", "sendp", "sr", "sr1", "srp", "srp1",
    "get_if_list", "get_if_addr", "get_working_if", "interfaces", "conf",
    "capture_available", "CaptureUnavailable",
]

absent = pytest.mark.skipif(
    P.capture_available(), reason="this build has the live feature"
)


@pytest.mark.parametrize("name", NAMES)
def test_every_name_exists(name):
    assert getattr(P, name) is not None
    assert name in P.__all__


def test_importing_the_module_directly_works():
    from packetry import capture

    assert capture.sniff is P.sniff


def test_capture_available_returns_a_bool_and_never_raises():
    assert isinstance(P.capture_available(), bool)


def test_capture_unavailable_is_an_oserror():
    assert issubclass(P.CaptureUnavailable, OSError)


def test_conf_holds_verb_without_touching_the_backend():
    assert isinstance(P.conf.verb, int)
    P.conf.iface = "eth0"
    assert P.conf.iface == "eth0"
    P.conf.iface = None


@absent
def test_capture_is_reported_absent():
    assert P.capture_available() is False


@absent
def test_sniffing_an_interface_names_the_build_command():
    with pytest.raises(P.CaptureUnavailable) as exc:
        P.sniff(iface="lo0")
    msg = str(exc.value)
    assert "maturin develop" in msg
    assert "live" in msg


@absent
def test_sniffing_with_no_source_at_all_raises():
    with pytest.raises(P.CaptureUnavailable):
        P.sniff()


@absent
def test_a_bpf_filter_offline_explains_the_feature(tmp_path):
    from packetry import Ether, IP, TCP

    path = tmp_path / "one.pcap"
    P.wrpcap(str(path), [Ether() / IP() / TCP()])
    with pytest.raises(P.CaptureUnavailable) as exc:
        P.sniff(offline=str(path), filter="tcp")
    assert "live" in str(exc.value)


@absent
@pytest.mark.parametrize("name", ["send", "sendp", "sr", "sr1", "srp", "srp1"])
def test_the_send_helpers_raise(name):
    with pytest.raises(P.CaptureUnavailable):
        getattr(P, name)(None)


@absent
def test_the_interface_helpers_raise():
    with pytest.raises(P.CaptureUnavailable):
        P.get_if_list()
    with pytest.raises(P.CaptureUnavailable):
        P.get_working_if()
    with pytest.raises(P.CaptureUnavailable):
        P.interfaces()


@absent
def test_conf_iface_raises_only_when_read():
    P.conf.iface = None
    with pytest.raises(P.CaptureUnavailable):
        P.conf.iface


@absent
def test_offline_sniffing_still_works(tmp_path):
    from packetry import Ether, IP, TCP, UDP

    path = tmp_path / "mixed.pcap"
    P.wrpcap(
        str(path),
        [Ether() / IP() / TCP(), Ether() / IP() / UDP(), Ether() / IP() / TCP()],
    )
    seen = []
    got = P.sniff(offline=str(path), prn=seen.append,
                  lfilter=lambda p: "TCP" in p.layers())
    assert len(got) == 2
    assert len(seen) == 2
