"""The wrappers around tcpdump, tshark, Wireshark and a hex editor.

None of those programs is a dependency, so everything except one optional
round trip through a real tcpdump runs against a stand-in for Popen.
"""

import io
import logging
import shutil
import subprocess
import sys

import pytest

import wiry as P
from wiry import ICMP, IP, TCP, UDP, Ether
from wiry import external as X


class FakeProc:
    """What tcpdump() touches of a Popen, recording how it was started."""

    calls: list = []

    def __init__(self, argv, stdin=None, stdout=None, stderr=None):
        FakeProc.calls.append((argv, stdin, stdout, stderr))
        self.stdin = io.BytesIO()
        self.stdin.close = lambda: None
        self.stdout = io.BytesIO(b"decoded\n")
        self.waited = False

    def wait(self):
        self.waited = True

    def terminate(self):
        pass


@pytest.fixture
def popen(monkeypatch):
    FakeProc.calls = []
    monkeypatch.setattr(subprocess, "Popen", FakeProc)
    return FakeProc


def test_prog_path_names_every_program_and_can_be_repointed():
    prog = X.ProgPath()
    for name in ("tcpdump", "tshark", "wireshark", "tcpreplay", "hexedit",
                 "dot", "display", "pdfreader", "psreader", "svgreader",
                 "ifconfig"):
        assert getattr(prog, name)
    prog.tcpdump = "/opt/bin/tcpdump"
    assert prog.tcpdump == "/opt/bin/tcpdump"
    assert P.conf.prog is P.conf.prog


@pytest.mark.parametrize("kw", [
    {"prog": 17607067425}, {"args": ["-n", 3]}, {"flt": 80},
])
def test_non_string_arguments_are_refused(kw):
    with pytest.raises(ValueError):
        P.tcpdump([IP()], **kw)


def test_a_missing_program_is_named(monkeypatch):
    monkeypatch.setattr(P.conf.prog, "tcpdump", "/nonexistent/tcpdump")
    with pytest.raises(FileNotFoundError, match="is it installed"):
        P.tcpdump([IP()], use_tempfile=False)


def test_packets_are_piped_in_with_the_link_type_named(popen):
    pkt = Ether() / IP() / ICMP()
    P.tcpdump([pkt], linktype="DLT_EN10MB", use_tempfile=False)
    argv, stdin, stdout, stderr = popen.calls[0]
    assert argv == [P.conf.prog.tcpdump, "-y", "EN10MB", "-U", "-r", "-"]
    assert (stdin, stdout, stderr) == (subprocess.PIPE, None, None)


def test_an_integer_link_type_is_named_as_libpcap_names_it(popen):
    P.tcpdump([IP()], linktype=228, use_tempfile=False)
    assert popen.calls[0][0][1:3] == ["-y", "IPV4"]
    with pytest.raises(ValueError, match="linktype"):
        P.tcpdump([IP()], linktype=9999, use_tempfile=False)


def test_the_capture_written_to_stdin_holds_the_packet(monkeypatch):
    sink = io.BytesIO()
    sink.close = lambda: None

    class Proc(FakeProc):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self.stdin = sink

    monkeypatch.setattr(subprocess, "Popen", Proc)
    pkt = Ether() / IP() / ICMP()
    P.tcpdump([pkt], use_tempfile=False)
    assert bytes(pkt) in sink.getvalue()
    assert sink.getvalue()[:4] == b"\xd4\xc3\xb2\xa1"


def test_a_path_is_read_with_dash_r(popen):
    P.tcpdump("/tmp/x.pcap", args=["-nn"], flt="tcp")
    assert popen.calls[0][0] == [P.conf.prog.tcpdump, "-r", "/tmp/x.pcap",
                                 "-nn", "tcp"]


def test_tempfile_mode_writes_a_capture_and_registers_it(popen, monkeypatch):
    registry = []
    monkeypatch.setattr(X, "_conf", lambda: _ConfWith(registry))
    P.tcpdump([IP()], use_tempfile=True, prog="tshark")
    argv = popen.calls[0][0]
    assert argv[:2] == ["tshark", "-r"] and argv[2] in registry


class _ConfWith:
    def __init__(self, registry):
        self.temp_files = registry
        self.prog = P.conf.prog


def test_dump_getfd_and_getproc(popen):
    assert P.tcpdump([IP()], dump=True, use_tempfile=False) == b"decoded\n"
    assert P.tcpdump([IP()], getfd=True, use_tempfile=False).read() == b"decoded\n"
    assert isinstance(P.tcpdump([IP()], getproc=True, use_tempfile=False), FakeProc)


def test_wireshark_and_tdecode_choose_their_programs(popen):
    P.wireshark([IP()])
    P.tdecode([IP()], dump=True)
    assert popen.calls[0][0][0] == P.conf.prog.wireshark
    assert popen.calls[0][0][1:3] == ["-ki", "-"]
    assert popen.calls[1][0][0] == P.conf.prog.tshark
    assert popen.calls[1][0][-1] == "-V"


def test_context_manager_logs_or_raises(caplog):
    with caplog.at_level(logging.ERROR, logger="wiry.runtime"):
        with X.ContextManagerSubprocess("nothere"):
            raise FileNotFoundError(2, "no such file")
    assert "Could not execute nothere, is it installed?" in caplog.text
    with pytest.raises(FileNotFoundError, match="nothere"):
        with X.ContextManagerSubprocess("nothere", suppress=False):
            raise FileNotFoundError(2, "no such file")


@pytest.mark.skipif(sys.platform == "win32", reason="needs a POSIX `true`")
def test_hexedit_reads_back_what_the_editor_left(monkeypatch):
    monkeypatch.setattr(P.conf.prog, "hexedit", shutil.which("true"))
    pkts = [Ether() / IP() / UDP(), Ether() / IP() / TCP()]
    got = P.hexedit(pkts)
    assert [bytes(p) for p in got] == [bytes(p) for p in pkts]


@pytest.mark.skipif(shutil.which("tcpdump") is None, reason="no tcpdump here")
def test_a_real_tcpdump_decodes_what_wiry_wrote():
    out = P.tcpdump([Ether() / IP() / ICMP()], dump=True, args=["-nn"])
    assert b"127.0.0.1 > 127.0.0.1: ICMP" in out
