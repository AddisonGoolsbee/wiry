"""The console, and the completion that makes it usable.

Completion is checked through `rlcompleter`, the thing the plain console
actually installs, rather than through `__dir__` alone: `conf` was invisible to
`dir(wiry)` for exactly as long as nobody looked at the real path.
"""

import os
import pickle
import rlcompleter
import subprocess
import sys

import pytest

import wiry
from wiry import IP, TCP, Ether, Raw
from wiry import console


@pytest.fixture
def pkt():
    return Ether() / IP(ttl=33) / TCP(dport=80)


# --- the namespace --------------------------------------------------------

def test_the_namespace_holds_every_exported_name():
    ns = console.namespace()
    missing = [n for n in wiry.__all__ if n not in ns]
    assert missing == []
    assert ns["wiry"] is wiry


def test_a_lazily_exported_name_is_in_the_namespace_as_a_value():
    # PEP 562 names never enter the module globals; a namespace built from
    # globals() alone would silently omit conf, sniff and the rest.
    ns = console.namespace()
    assert ns["conf"] is wiry.conf
    assert callable(ns["sniff"]) and callable(ns["ls"])


def test_extra_names_win_over_the_preloaded_ones():
    ns = console.namespace({"IP": 7, "mine": 3})
    assert ns["IP"] == 7 and ns["mine"] == 3


# --- completion -----------------------------------------------------------

def _complete(ns, text):
    comp = rlcompleter.Completer(namespace=ns)
    out = []
    for i in range(200):
        got = comp.complete(text, i)
        if got is None:
            break
        out.append(got)
    return out


def test_a_field_completes_on_a_packet(pkt):
    assert _complete({"p": pkt}, "p.ttl") == ["p.ttl"]
    assert "p.dport" in _complete({"p": pkt}, "p.dpo")


def test_every_layer_in_the_chain_contributes_its_fields(pkt):
    names = dir(pkt)
    assert "ttl" in names and "dport" in names and "src" in names


def test_a_field_completes_on_a_layer_class():
    assert _complete({"IP": IP}, "IP.tt") == ["IP.ttl"]
    assert "dataofs" in dir(TCP)


def test_a_field_completes_on_one_layer_of_a_packet(pkt):
    view = pkt[IP]
    assert _complete({"v": view}, "v.tt") == ["v.ttl"]


def test_a_layer_class_answers_with_its_field_declaration():
    assert IP.ttl.name == "ttl"
    assert IP.ttl.kind == "uint" and IP.ttl.bits == 8
    assert TCP.flags.flags == ("F", "S", "R", "P", "A", "U", "E", "C", "N")
    with pytest.raises(AttributeError):
        IP.nosuch


def test_the_keyword_arguments_of_a_layer_name_themselves():
    import inspect

    params = inspect.signature(IP).parameters
    assert "ttl" in params and "dst" in params
    assert params["ttl"].kind is inspect.Parameter.KEYWORD_ONLY


# --- session --------------------------------------------------------------

def test_a_session_round_trips_the_names_you_made(tmp_path, pkt):
    path = str(tmp_path / "s.wiry")
    session = {"p": pkt, "n": 7, "_hidden": 1, console._PRELOADED: {"IP"},
               "IP": IP}
    console.save_session(path, session=session)
    back: dict = {}
    console.load_session(path, session=back)
    assert back["n"] == 7
    assert bytes(back["p"]) == bytes(pkt)
    # The preloaded API and private names come from the import, not the file.
    assert "IP" not in back and "_hidden" not in back


def test_a_session_names_what_it_could_not_save(tmp_path, pkt):
    path = str(tmp_path / "s.wiry")
    with pytest.warns(UserWarning, match="fh"):
        console.save_session(path, session={"fh": open(os.devnull), "ok": 1})
    back: dict = {}
    console.load_session(path, session=back)
    assert back == {"ok": 1}


@pytest.mark.parametrize("build", [
    lambda: Ether() / IP(ttl=9) / TCP(dport=443),
    lambda: IP(bytes(IP(ttl=9) / TCP(dport=443))),
    lambda: Raw(b"\x00abc"),
])
def test_a_packet_pickles_to_the_same_octets(build):
    pkt = build()
    back = pickle.loads(pickle.dumps(pkt))
    assert bytes(back) == bytes(pkt)
    assert back.layers() == pkt.layers()


def test_pickling_keeps_a_template_a_template():
    tmpl = IP(ttl=(1, 4))
    back = pickle.loads(pickle.dumps(tmpl))
    assert [p.ttl for p in back] == [1, 2, 3, 4]


def test_pickling_carries_the_capture_metadata(pkt):
    pkt.time, pkt.wirelen, pkt.sniffed_on = 1.5, 99, "en0"
    back = pickle.loads(pickle.dumps(pkt))
    assert (back.time, back.wirelen, back.sniffed_on) == (1.5, 99, "en0")


# --- startup, options, banner ---------------------------------------------

def test_the_banner_says_what_this_build_is():
    text = console.banner(mini=True)
    assert wiry.__version__ in text
    assert str(len(wiry.known_layers())) in text


def test_a_startup_file_lands_in_the_namespace(tmp_path):
    rc = tmp_path / "startup.py"
    rc.write_text("greeting = 'hi'\n")
    ns = {}
    console._read_startup(str(rc), ns)
    assert ns["greeting"] == "hi"


def test_a_startup_file_that_is_not_there_is_not_an_error(tmp_path):
    console._read_startup(str(tmp_path / "absent.py"), {})


def test_a_broken_startup_file_refuses_to_start(tmp_path):
    rc = tmp_path / "startup.py"
    rc.write_text("raise ValueError('bad rc')\n")
    with pytest.raises(ValueError, match="bad rc"):
        console._read_startup(str(rc), {})


def test_help_prints_the_usage_and_stops():
    with pytest.raises(SystemExit) as exc:
        console.interact(argv=["-h"])
    assert exc.value.code == 0


def test_an_unknown_option_is_refused():
    with pytest.raises(SystemExit) as exc:
        console.interact(argv=["--nonsense"])
    assert exc.value.code == 1


# --- end to end -----------------------------------------------------------

def _run_console(script, extra=()):
    env = dict(os.environ, NO_COLOR="1", PYTHONPATH=os.pathsep.join(sys.path))
    return subprocess.run(
        [sys.executable, "-m", "wiry", "-C", *extra],
        input=script, capture_output=True, text=True, timeout=120, env=env,
    )


def _banner_of(out):
    """The plain interpreter writes its banner to stderr and IPython to
    stdout, and which one runs depends on what is installed."""
    return out.stdout + out.stderr


def test_the_console_starts_and_runs_a_packet_through():
    out = _run_console(
        'p = Ether()/IP(dst="10.0.0.2")/TCP(dport=80)\n'
        'print(p.summary())\n'
        'print(len(raw(p)))\n'
    )
    assert "Welcome to wiry" in _banner_of(out)
    assert "Ether / IP / TCP" in out.stdout
    assert "54" in out.stdout


def test_the_console_can_be_started_without_a_banner():
    out = _run_console("print('ran')\n", extra=["-H"])
    assert "Welcome to wiry" not in _banner_of(out)
    assert "ran" in out.stdout


def test_ls_and_lsc_work_at_the_prompt():
    out = _run_console("ls(IP)\nlsc('rdpcap')\n")
    assert "ttl" in out.stdout
    assert "rdpcap" in out.stdout


def _ipython_completer(ns):
    IPython = pytest.importorskip("IPython", reason="IPython is optional")
    from IPython.terminal.interactiveshell import TerminalInteractiveShell

    shell = TerminalInteractiveShell.instance(user_ns=ns)
    comp = shell.Completer
    comp.use_jedi = False
    comp.evaluation = "unsafe"
    assert IPython.version_info[0] >= 8
    return comp


def test_ipython_completes_a_field_through_a_layer_subscript(pkt):
    """`pkt[TCP].<tab>` is the idiom, and it needs the two completer settings
    the console sets. Asserted against IPython itself, not against what the
    settings are called."""
    ns = console.namespace({"p": pkt})
    comp = _ipython_completer(ns)
    from IPython.core.completer import provisionalcompleter

    with provisionalcompleter():
        def done(text):
            return [c.text for c in comp.completions(text, len(text))]

        assert ".window" in done("p[TCP].wi")
        assert ".dport" in done("p.dpo")
        assert "ttl=" in done("IP(tt")
        assert ".ttl" in done("IP.tt")


def test_the_history_file_is_typed_the_way_this_ipython_wants_it():
    import pathlib

    pytest.importorskip("IPython", reason="IPython is optional")
    from IPython.core.history import HistoryAccessor

    value = console._hist_file("/tmp/h")
    HistoryAccessor(hist_file=value)
    assert isinstance(value, (str, pathlib.Path))
