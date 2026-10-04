# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from scapy: scapy/utils.py (tcpdump, wireshark, tdecode, hexedit,
#   ContextManagerSubprocess) and scapy/config.py (ProgPath)
#   scapy 2.7.0, upstream commit 7d69454
#   Copyright (C) Philippe Biondi <phil@secdev.org>
#   Copyright (C) the scapy contributors
#
# Changed by the wiry authors:
#   2026-10-03 — cut to the wrappers around external programs, resolved the
#                programs with shutil.which, and named the program and the
#                remedy whenever one is missing.

"""The wrappers around programs wiry does not ship: tcpdump, tshark,
Wireshark, tcpreplay and a hex editor.

None of them is a dependency. Each is looked up in ``conf.prog`` when it is
called, and a missing one is reported by name with the way to fix it.
"""

from __future__ import annotations

import os
import sys
from typing import Any, List, Optional

from .error import log_runtime

__all__ = [
    "ProgPath", "ContextManagerSubprocess", "tcpdump", "wireshark", "tdecode",
    "hexedit",
]

DARWIN = sys.platform == "darwin"
OPENBSD = sys.platform.startswith("openbsd")


# libpcap's `pcap_datalink_val_to_name`, for the link types `-y` is asked for.
DLT_NAMES = {
    0: "NULL", 1: "EN10MB", 9: "PPP", 101: "RAW", 105: "IEEE802_11",
    108: "LOOP", 113: "LINUX_SLL", 127: "IEEE802_11_RADIO", 147: "USER0",
    228: "IPV4", 229: "IPV6", 276: "LINUX_SLL2",
}


def _which(name: str) -> str:
    import shutil
    return shutil.which(name) or name


class ProgPath:
    """Where each external program is. Assign a path to point at another."""

    _default = "<System default>"

    def __init__(self) -> None:
        self.universal_open = _which("open" if DARWIN else "xdg-open")
        self.pdfreader = self.universal_open
        self.psreader = self.universal_open
        self.svgreader = self.universal_open
        self.dot = _which("dot")
        self.display = _which("display")
        self.tcpdump = _which("tcpdump")
        self.tcpreplay = _which("tcpreplay")
        self.hexedit = _which("hexer")
        self.tshark = _which("tshark")
        self.wireshark = _which("wireshark")
        self.ifconfig = _which("ifconfig")
        self.extcap_folders: List[str] = [
            os.path.join(os.path.expanduser("~"), ".config", "wireshark",
                         "extcap"),
            "/usr/lib/x86_64-linux-gnu/wireshark/extcap",
        ]

    def __repr__(self) -> str:
        return "\n".join(f"{k:<16} = {v!r}" for k, v in vars(self).items())


class ContextManagerSubprocess:
    """Turn a program that cannot be run into one clear message.

    ``suppress=True`` logs it on ``scapy.runtime`` and swallows the error, as
    scapy does for the tools it runs in the background; otherwise it is raised
    again, carrying the message, as the same exception type.
    """

    def __init__(self, prog: str, suppress: bool = True):
        self.prog = prog
        self.suppress = suppress

    def __enter__(self) -> None:
        pass

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> Any:
        if exc_value is None or exc_type is None:
            return None
        if isinstance(exc_value, EnvironmentError):
            msg = (f"Could not execute {self.prog}, is it installed? Install "
                   "it, or point conf.prog at it")
        else:
            msg = f"{self.prog}: execution failed ({exc_type.__name__})"
        if not self.suppress:
            raise exc_type(msg)
        log_runtime.error(msg, exc_info=True)
        return True


def _conf() -> Any:
    from .capture import conf
    return conf


def _temp_file(suffix: str = ".pcap") -> str:
    """A temporary path, in ``conf.temp_files`` where that register exists so
    it is removed at exit."""
    import tempfile
    fd, path = tempfile.mkstemp(suffix=suffix, prefix="wiry")
    os.close(fd)
    register = getattr(_conf(), "temp_files", None)
    if register is not None:
        register.append(path)
    return path


def _write_capture(target: Any, pktlist: Any, linktype: Optional[int]) -> None:
    from . import wrpcap
    if linktype is None:
        wrpcap(target, pktlist)
    else:
        wrpcap(target, pktlist, linktype=linktype)


def _linktype(linktype: Any) -> tuple:
    """(value, libpcap name) for a DLT given either way."""
    if isinstance(linktype, int):
        name = DLT_NAMES.get(linktype)
        if name is None:
            raise ValueError(
                "Unknown linktype. Try passing its datalink name instead")
        return linktype, name
    name = str(linktype)
    if name.startswith("DLT_"):
        name = name[4:]
    for value, known in DLT_NAMES.items():
        if known == name:
            return value, name
    log_runtime.warning("Unknown linktype: %s. Using EN10MB", name)
    return 1, name


def _copy(read: Any, write: Any) -> None:
    for chunk in iter(lambda: read(1 << 20), b""):
        write(chunk)


def tcpdump(pktlist: Any = None, dump: bool = False, getfd: bool = False,
            args: Optional[List[str]] = None, flt: Optional[str] = None,
            prog: Any = None, getproc: bool = False, quiet: bool = False,
            use_tempfile: Any = None, read_stdin_opts: Any = None,
            linktype: Any = None, wait: bool = True,
            _suppress: bool = False) -> Any:
    """Run tcpdump, or tshark or Wireshark through ``prog``, over packets.

    ``pktlist`` is a packet, a list of them, a capture path, a binary file
    object, or ``None`` to have the program capture by itself. ``dump``
    returns its output, ``getfd`` its stdout and ``getproc`` the process;
    otherwise ``wait`` says whether to wait for it. Apple's tcpdump cannot
    read stdin, so there a temporary file is used unless ``use_tempfile``
    says otherwise.
    """
    import subprocess
    conf = _conf()
    getfd = getfd or getproc
    if prog is None:
        if not conf.prog.tcpdump:
            raise OSError("tcpdump is not available: set conf.prog.tcpdump")
        prog = [conf.prog.tcpdump]
    elif isinstance(prog, str):
        prog = [prog]
    else:
        raise ValueError("prog must be a string")

    value = None
    if linktype is not None:
        value, name = _linktype(linktype)
        prog += ["-y", name]

    args = [] if args is None else list(args)
    if not all(isinstance(a, str) for a in args):
        raise ValueError("args must be a list of strings")
    if flt is not None:
        if not isinstance(flt, str):
            raise ValueError("flt must be a string")
        args.append(flt)

    stdout = subprocess.PIPE if dump or getfd else None
    stderr = subprocess.DEVNULL if quiet else None

    if use_tempfile is None:
        use_tempfile = DARWIN and prog[0] == conf.prog.tcpdump
    if read_stdin_opts is None:
        if prog[0] == conf.prog.wireshark:
            read_stdin_opts = ["-ki", "-"]
        elif prog[0] == conf.prog.tcpdump and not OPENBSD:
            read_stdin_opts = ["-U", "-r", "-"]
        else:
            read_stdin_opts = ["-r", "-"]
    else:
        read_stdin_opts = list(read_stdin_opts)

    def run(argv: list, **kw: Any) -> Any:
        with ContextManagerSubprocess(prog[0], suppress=_suppress):
            return subprocess.Popen(argv, stdout=stdout, stderr=stderr, **kw)
        return None

    if pktlist is None:
        proc = run(prog + args)
    elif isinstance(pktlist, (str, os.PathLike)):
        proc = run(prog + ["-r", os.fspath(pktlist)] + args)
    elif use_tempfile:
        tmp = _temp_file()
        read = getattr(pktlist, "read", None)
        if read is not None:
            with open(tmp, "wb") as fh:
                _copy(read, fh.write)
        else:
            _write_capture(tmp, pktlist, value)
        proc = run(prog + ["-r", tmp] + args)
    else:
        try:
            pktlist.fileno()
            proc = run(prog + read_stdin_opts + args, stdin=pktlist)
        except (AttributeError, ValueError, OSError):
            proc = run(prog + read_stdin_opts + args, stdin=subprocess.PIPE)
            if proc is None:
                return None
            read = getattr(pktlist, "read", None)
            if read is not None:
                _copy(read, proc.stdin.write)
                proc.stdin.close()
            else:
                _write_capture(proc.stdin, pktlist, value)
    if proc is None:
        return None
    if dump:
        data = b"".join(iter(lambda: proc.stdout.read(1 << 20), b""))
        proc.terminate()
        return data
    if getproc:
        return proc
    if getfd:
        return proc.stdout
    if wait:
        proc.wait()
    return None


def wireshark(pktlist: Any, wait: bool = False, **kwargs: Any) -> Any:
    """Open packets in Wireshark, in the background unless ``wait``."""
    return tcpdump(pktlist, prog=_conf().prog.wireshark, wait=wait, **kwargs)


def tdecode(pktlist: Any, args: Optional[List[str]] = None,
            **kwargs: Any) -> Any:
    """Decode packets with tshark, ``-V`` unless ``args`` says otherwise."""
    if args is None:
        args = ["-V"]
    return tcpdump(pktlist, prog=_conf().prog.tshark, args=args, **kwargs)


def hexedit(pktlist: Any) -> Any:
    """Edit packets in a hex editor, and read back what was saved."""
    import subprocess
    from . import rdpcap

    conf = _conf()
    path = _temp_file()
    _write_capture(path, pktlist, None)
    with ContextManagerSubprocess(conf.prog.hexedit):
        subprocess.call([conf.prog.hexedit, path])
    try:
        return rdpcap(path)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
