"""`wiry.utils`, `compat`, `error`, `config` and `arch`: the helpers scapy
scripts call by name. Expectations are worked from the RFCs and the formats
themselves."""

import os
import socket

import pytest

import wiry
from wiry import ICMP, IP, Ether, Raw
from wiry import utils as U


def test_checksum_is_rfc_1071s():
    # RFC 1071 §3's worked example: 00 01 f2 03 f4 f5 f6 f7 sums to ddf2.
    data = bytes.fromhex("0001f203f4f5f6f7")
    assert U.checksum(data) == (~0xDDF2) & 0xFFFF
    assert U.checksum(bytes(IP())[:10] + b"\0\0" + bytes(IP())[12:]) == IP(bytes(IP())).chksum


def test_checksum_pads_an_odd_length():
    assert U.checksum(b"\x01") == U.checksum(b"\x01\x00")


def test_fletcher16_checkbytes_zero_the_sum():
    # RFC 905 Annex B: with the check octets in place the sum is zero.
    buf = b"\x28\x07\x00\x00\x13"
    check = U.fletcher16_checkbytes(buf, 2)
    assert U.fletcher16_checksum(buf[:2] + check + buf[4:]) == 0


def test_mac_and_ipv4_conversions_round_trip():
    assert U.mac2str("00:01:02:aa:bb:cc") == b"\x00\x01\x02\xaa\xbb\xcc"
    assert U.str2mac(b"\x00\x01\x02\xaa\xbb\xcc") == "00:01:02:aa:bb:cc"
    assert U.valid_mac("00:01:02:aa:bb:cc") and not U.valid_mac("00:01")
    assert U.atol("10.0.0.1") == 0x0A000001
    assert U.ltoa(0x0A000001) == "10.0.0.1"
    assert U.itom(24) == 0xFFFFFF00
    assert U.in4_cidr2mask(20) == b"\xff\xff\xf0\x00"
    with pytest.raises(wiry.Scapy_Exception):
        U.in4_cidr2mask(33)


def test_ipv4_multicast_classes_follow_rfc_5771():
    assert U.in4_ismaddr("224.0.0.1") and not U.in4_ismaddr("10.0.0.1")
    assert U.in4_ismlladdr("224.0.0.251")
    assert U.in4_ismlsaddr("239.1.2.3")
    assert U.in4_ismgladdr("233.1.1.1") and not U.in4_ismgladdr("239.1.1.1")
    assert U.in4_isaddrllallnodes("224.0.0.1")
    # RFC 1112 §6.4: the low 23 bits under 01:00:5e.
    assert U.in4_getnsmac(socket.inet_aton("225.128.0.1")) == "01:00:5e:00:00:01"


def test_address_validators():
    assert U.valid_ip("1.2.3.4") and not U.valid_ip("1.2.3.256")
    assert U.valid_net("10.0.0.0/8") and not U.valid_net("10.0.0.0/33")
    assert U.valid_ip6("2001:db8::1") and not U.valid_ip6("2001:db8:::1")
    assert U.valid_net6("2001:db8::/32") and not U.valid_net6("2001:db8::/129")


def test_string_operations():
    assert U.strxor(b"\x0f\xf0", b"\xff\xff") == b"\xf0\x0f"
    assert U.strand(b"AC", b"BC") == b"@C"
    assert U.stror(b"\x01\x02", b"\x10\x20") == b"\x11\x22"
    assert U.strrot(b"abcd", 1) == b"dabc"
    assert U.strrot(b"abcd", 1, right=False) == b"bcda"
    assert len(U.randstring(7)) == 7
    assert 0 not in U.zerofree_randstring(64)


def test_the_hexdump_family_prints_scapys_format():
    pkt = Ether(src="00:01:02:03:04:05")
    assert U.hexstr(b"A\x00\xffB") == "41 00 FF 42  A..B"
    assert U.linehexdump(pkt, dump=True) == (
        "FF FF FF FF FF FF 00 01 02 03 04 05 90 00  .............."
    )
    assert U.linehexdump(b"AB", onlyhex=1, dump=True) == "41 42"
    assert U.chexdump(b"\x00\xff", dump=True) == "0x00, 0xff"
    assert U.repr_hex(b"wiry") == "77697279"
    assert U.sane(b"A\x00\xffB") == "A..B"
    assert U.lhex([28, (7,)]) == "[0x1c, (0x7)]"


def test_hexdump_of_more_than_one_row():
    text = U.hexdump(bytes(range(18)), dump=True)
    lines = text.split("\n")
    assert lines[0] == "0000  " + " ".join("%02X" % i for i in range(16)) + "  " + "." * 16
    assert lines[1] == "0010  10 11" + " " * 44 + ".."


def test_import_hexcap_reads_what_hexdump_writes():
    pkt = Ether() / IP() / ICMP()
    assert U.import_hexcap(U.hexdump(pkt, dump=True)) == bytes(pkt)


def test_import_hexcap_reads_stdin_until_a_blank_line(monkeypatch):
    lines = iter(["0000  41 42 43", "", "0000  44"])
    monkeypatch.setattr(U, "input", lambda: next(lines), raising=False)
    assert U.import_hexcap() == b"ABC"


def test_tables_are_scapys():
    rows = [("a", "1", "x"), ("b", "1", "y"), ("a", "2", "z")]
    text = U.make_table(rows, lambda c, r, v: (c, r, v), dump=True)
    assert text == "  a b \n1 x y \n2 z - \n"


def test_pretty_list_lays_out_columns(monkeypatch):
    monkeypatch.setattr(U, "get_terminal_width", lambda: 0)
    out = U.pretty_list([("b", "22"), ("a", "1")], [("Name", "Num")])
    assert out.splitlines() == ["Name  Num", "a     1  ", "b     22 "]


def test_human_size():
    assert U.human_size(0) == "0B"
    assert U.human_size(512) == "512B"
    assert U.human_size(2048) == "2.0K"


def test_tex_escape_and_labels():
    assert U.tex_escape("$#_") == "\\$\\#\\_"
    gen = U.incremental_label()
    assert [next(gen), next(gen)] == ["tag00000", "tag00001"]
    assert U.binrepr(5) == "101"
    assert U.long_converter("0a 0b\n0c") == 0x0A0B0C


def test_temp_files_are_removed_unless_kept():
    from wiry.config import conf, scapy_delete_temp_files

    gone = U.get_temp_file(autoext=".pcap")
    kept = U.get_temp_file(keep=True)
    folder = U.get_temp_dir()
    assert gone.endswith(".pcap") and os.path.exists(gone)
    scapy_delete_temp_files()
    assert not os.path.exists(gone) and not os.path.exists(folder)
    assert os.path.exists(kept) and conf.temp_files == []
    os.unlink(kept)


def test_capture_output_collects_what_is_printed():
    with U.ContextManagerCaptureOutput() as out:
        print("hello")
    assert out.get_output() == "hello\n"


def test_edecimal_compares_and_adds_with_floats():
    t = U.EDecimal("1.5")
    assert t == 1.5 and t + 1 == 2.5 and isinstance(t * 2, U.EDecimal)


def test_enum_metaclass_maps_both_ways():
    class Kind(metaclass=U.Enum_metaclass):
        A = 1
        B = 2

    assert Kind[1] == "A" and 2 in Kind and int(Kind.B) == 2


def test_do_graph_returns_the_source_without_a_target():
    assert U.do_graph("digraph {}") == "digraph {}"


def test_restart_refuses_outside_the_console():
    with pytest.raises(OSError):
        U.restart()


def test_inet_ntop_collapses_the_longest_zero_run():
    from wiry.compat import _inet6_ntop, _inet6_pton

    # RFC 5952 §4.2.3: the longest run, the first of two equal ones.
    raw = bytes.fromhex("0000000033334444000000000000" + "8888")
    assert _inet6_ntop(raw) == "0:0:3333:4444::8888"
    assert wiry.inet_ntop(socket.AF_INET6, raw) == "0:0:3333:4444::8888"
    assert _inet6_pton("::1") == b"\0" * 15 + b"\1"
    with pytest.raises(ValueError):
        _inet6_ntop(b"\0" * 15)


def test_compat_conversions():
    assert wiry.bytes_hex("AB") == b"4142"
    assert wiry.hex_bytes("4142") == b"AB"
    assert wiry.plain_str(b"x\xff") == "x\\xff"
    assert wiry.chb(65) == b"A" and wiry.orb(b"A"[0]) == 65


def test_platform_constants_agree_with_sys():
    import sys

    assert wiry.DARWIN == sys.platform.startswith("darwin")
    assert wiry.IS_64BITS == (sys.maxsize > 2 ** 32)


def test_warning_is_rate_limited_per_call_site(caplog):
    from wiry.error import warning

    with caplog.at_level("WARNING", logger="wiry.runtime"):
        for _ in range(5):
            warning("same place")
    assert [r.getMessage() for r in caplog.records] == [
        "same place", "same place", "more same place"]


def test_read_nameservers_reads_resolv_conf(tmp_path, monkeypatch):
    import builtins

    from wiry.arch import read_nameservers

    conf_file = tmp_path / "resolv.conf"
    conf_file.write_text("# comment\nnameserver 192.0.2.53\nnameserver 2001:db8::53\n")
    real_open = builtins.open
    monkeypatch.setattr(builtins, "open", lambda p, *a, **k: real_open(
        conf_file if p == "/etc/resolv.conf" else p, *a, **k))
    assert read_nameservers() == ["192.0.2.53", "2001:db8::53"]


def test_get_if_raw_addr_of_an_unknown_interface_is_zero():
    from wiry.arch import get_if_raw_addr

    if not wiry.capture_available():
        pytest.skip("needs libpcap to list interfaces")
    assert get_if_raw_addr("no-such-interface0") == b"\0\0\0\0"


def test_utils_forwards_the_capture_file_names():
    assert U.RawPcapReader is wiry.RawPcapReader
    assert U.rdpcap is wiry.rdpcap
    assert U.tcpdump is wiry.tcpdump
    with pytest.raises(AttributeError):
        U.no_such_name


def test_cliutil_registers_commands_and_their_flags():
    class Shell(U.CLIUtil):
        @U.CLIUtil.addcommand()
        def greet(self, who, *, loud=False):
            return who.upper() if loud else who

    assert set(Shell.commands) == {"greet"}
    shell = Shell(cli=False)
    args, kwargs, _ = shell._parseallargs(Shell.commands["greet"], "greet", ["--loud", "x"])
    assert args == ["x"] and kwargs == {"loud": True}
    assert Shell.commands["greet"](shell, *args, **kwargs) == "X"


def test_periodic_sender_stops():
    from wiry import OfflineSocket

    sock = OfflineSocket()
    thread = U.PeriodicSenderThread(sock, Raw(b"x"), interval=0.01)
    thread.start()
    import time

    time.sleep(0.05)
    thread.stop()
    assert not thread.is_alive() and len(sock.sent) >= 1


def test_hexdump_prints_by_default(capsys):
    U.hexdump(b"AB")
    assert capsys.readouterr().out == "0000  41 42" + " " * 44 + "AB\n"
