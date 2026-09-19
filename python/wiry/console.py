"""The `wiry` console: a prompt with the API already loaded.

Shaped after scapy's `interact()`, which it derives from. Two differences are
deliberate. IPython is used when it is importable and `code.InteractiveConsole`
otherwise, and **neither is an install-time dependency** — the import is lazy,
the way `columnar` treats polars. And the plain console keeps its history,
which scapy's turns off; `conf.histfile` says where.

Crossing the FFI boundary per packet is the point here. A prompt is one packet
at a time by nature, so the rule that governs bulk paths does not govern this
one — but nothing in this module is reachable from a bulk path.
"""

from __future__ import annotations

import atexit
import getopt
import os
import pathlib
import sys
from typing import Any, Optional

import wiry

__all__ = ["interact", "main", "save_session", "load_session", "banner"]

LOGO = r"""
          _
 __      ___ _ __ _   _
 \ \ /\ / / | '__| | | |
  \ V  V /| | |  | |_| |
   \_/\_/ |_|_|   \__, |
                  |___/
"""

USAGE = """\
Usage: wiry [-c startup_file] [-C] [-H] [-h]
  -c FILE  read FILE at startup instead of the default
  -C       do not read a startup file
  -H       no banner
  -h       this message
"""


def _config_dir() -> Optional[pathlib.Path]:
    """The XDG config directory, or None where it cannot be made — a read-only
    home is a reason to start without history, not to refuse to start."""
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    try:
        path = pathlib.Path(base) / "wiry"
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        return path
    except OSError:
        return None


def default_histfile() -> str:
    folder = _config_dir()
    return str(folder / "history") if folder else ""


def default_startup() -> str:
    folder = _config_dir()
    return str(folder / "startup.py") if folder else ""


def _colour() -> bool:
    return (sys.stdout.isatty() and not os.environ.get("NO_COLOR")
            and os.environ.get("TERM") != "dumb")


def banner(mini: Optional[bool] = None) -> str:
    """The startup banner: the wordmark, the version, and where to start."""
    lines = [
        f"Welcome to wiry {wiry.__version__}",
        "",
        f"{len(wiry.known_layers())} layers, "
        f"{'with' if wiry.capture_available() else 'without'} live capture",
        "",
        "ls() lists the layers, ls(IP) what one holds, lsc() the commands.",
    ]
    if mini is None:
        mini = (_terminal_width() or 80) <= 60
    if mini:
        return "\n".join(lines)
    art = LOGO.strip("\n").split("\n")
    width = max(len(a) for a in art) + 2
    rows = []
    for i in range(max(len(art), len(lines))):
        left = art[i] if i < len(art) else ""
        right = lines[i] if i < len(lines) else ""
        rows.append((left.ljust(width) + right).rstrip())
    text = "\n".join(rows)
    return f"\033[1;36m{text}\033[0m" if _colour() else text


def _terminal_width() -> int:
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 0


def namespace(extra: Optional[dict] = None) -> dict:
    """Everything `wiry` exports, plus `wiry` itself.

    Resolving each name here is what forces the lazily exported ones into
    being; a name that only `wiry.__getattr__` can produce would otherwise be
    absent from the prompt.
    """
    ns: dict = {"wiry": wiry, "__name__": "__wiry_console__", "__doc__": None}
    for name in wiry.__all__:
        try:
            ns[name] = getattr(wiry, name)
        except (AttributeError, ImportError):
            continue
    ns["save_session"] = save_session
    ns["load_session"] = load_session
    if extra:
        ns.update(extra)
    return ns


_PRELOADED = "_wiry_preloaded"


def save_session(path: Optional[str] = None, session: Optional[dict] = None
                 ) -> str:
    """Write the names you made at the prompt to a file.

    Only the picklable ones: a file handle or a live sniffer has no meaning in
    the next process, so it is left out and named in a warning rather than
    failing the save. The preloaded API is never written — it comes back from
    the import.
    """
    import gzip
    import pickle
    import warnings

    ns = session if session is not None else _caller_session()
    path = path or wiry.conf.session or "wiry.session"
    preloaded = set(ns.get(_PRELOADED) or ())
    keep, dropped = {}, []
    for name, value in ns.items():
        if name.startswith("_") or name in preloaded or name == "wiry":
            continue
        try:
            pickle.dumps(value)
        except Exception:
            dropped.append(name)
            continue
        keep[name] = value
    with gzip.open(path, "wb") as fh:
        pickle.dump(keep, fh)
    if dropped:
        warnings.warn(f"not saved, because they do not pickle: "
                      f"{', '.join(sorted(dropped))}", stacklevel=2)
    return path


def load_session(path: Optional[str] = None, session: Optional[dict] = None
                 ) -> dict:
    """Read a saved session back into the prompt's namespace."""
    import gzip
    import pickle

    ns = session if session is not None else _caller_session()
    path = path or wiry.conf.session or "wiry.session"
    with gzip.open(path, "rb") as fh:
        loaded = pickle.load(fh)
    ns.update(loaded)
    return loaded


def _caller_session() -> dict:
    """The namespace the call came from, so `save_session()` with no argument
    means the prompt the user is typing at."""
    frame = sys._getframe(2)
    return frame.f_globals if frame.f_locals is frame.f_globals else frame.f_locals


def _read_startup(path: str, ns: dict) -> None:
    """Run the user's startup file into the console namespace. An error in it
    is raised, not swallowed: a startup file that half-ran silently is worse
    than one that refuses to start."""
    try:
        source = pathlib.Path(path).read_text()
    except OSError:
        return
    exec(compile(source, path, "exec"), ns, ns)


def _plain_history(path: str) -> None:
    """readline history for the plain console. scapy disables this; there is no
    reason to."""
    if not path:
        return
    try:
        import readline
        import rlcompleter  # noqa: F401
    except ImportError:
        return
    try:
        readline.read_history_file(path)
    except OSError:
        pass
    readline.set_history_length(10000)
    atexit.register(_write_history, path)


def _write_history(path: str) -> None:
    try:
        import readline
        readline.write_history_file(path)
    except (ImportError, OSError):
        pass


def _plain(ns: dict, text: str) -> None:
    import code

    try:
        import readline
        import rlcompleter

        readline.set_completer(rlcompleter.Completer(namespace=ns).complete)
        # libedit is what macOS ships as readline; its bind syntax differs.
        if "libedit" in getattr(readline, "__doc__", "") or "":
            readline.parse_and_bind("bind ^I rl_complete")
        else:
            readline.parse_and_bind("tab: complete")
    except ImportError:
        pass
    code.InteractiveConsole(locals=ns).interact(banner=text, exitmsg="")


def _ipython(ns: dict, text: str, histfile: str) -> bool:
    """True when IPython ran. False means it is not installed, or refused."""
    try:
        from IPython import embed
    except ImportError:
        return False
    kw: dict = {"user_ns": ns, "colors": "neutral"}
    try:
        from traitlets.config.loader import Config

        cfg = Config()
        cfg.InteractiveShellEmbed.confirm_exit = False
        cfg.InteractiveShell.banner1 = text + "\n"
        cfg.TerminalInteractiveShell.term_title_format = f"wiry {wiry.__version__}"
        if histfile:
            cfg.HistoryAccessor.hist_file = histfile
        kw = {"config": cfg, "user_ns": ns}
    except ImportError:
        kw["banner1"] = text + "\n"
    try:
        embed(**kw)
    except (AttributeError, TypeError):
        return False
    return True


def interact(mydict: Optional[dict] = None, argv: Optional[list] = None,
             mybanner: Optional[str] = None, quiet: bool = False) -> None:
    """Drop into a console with the wiry API loaded.

    IPython when it is importable, `code.InteractiveConsole` otherwise.
    """
    conf = wiry.conf
    startup: Optional[str] = conf.startup_file or default_startup()
    header = True
    try:
        opts, rest = getopt.getopt(list(argv if argv is not None else sys.argv[1:]),
                                   "hHCc:")
    except getopt.GetoptError as exc:
        sys.stderr.write(f"{exc}\n{USAGE}")
        raise SystemExit(1)
    for opt, value in opts:
        if opt == "-h":
            sys.stdout.write(USAGE)
            raise SystemExit(0)
        if opt == "-H":
            header = False
        elif opt == "-C":
            startup = None
        elif opt == "-c":
            startup = value
    if rest:
        sys.stderr.write(f"unexpected arguments: {' '.join(rest)}\n{USAGE}")
        raise SystemExit(1)

    ns = namespace(mydict)
    ns[_PRELOADED] = frozenset(ns)
    if startup:
        _read_startup(startup, ns)

    text = "" if not header or quiet else (mybanner if mybanner is not None
                                           else banner())
    conf.interactive = True
    if _colour():
        sys.ps1 = "\033[1;36m>>> \033[0m"
    histfile = conf.histfile or default_histfile()
    # IPython keeps its own history; readline's would double every line.
    if not _ipython(ns, text, histfile):
        _plain_history(histfile)
        _plain(ns, text)
    conf.interactive = False


def main() -> int:
    interact()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
