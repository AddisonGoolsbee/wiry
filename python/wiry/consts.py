# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from scapy: scapy/consts.py
#   scapy 2.7.0
#   Copyright (C) Philippe Biondi <phil@secdev.org>
#   Copyright (C) the scapy contributors
#
# Changed by the wiry authors:
#   2026-10-03 — taken as is, but for WINDOWS_XP, read from the running
#                Windows version rather than the platform module, which costs
#                more to import than everything else here.

"""What host this is, as scapy scripts test for it."""

import sys as _sys
from sys import byteorder as _byteorder
from sys import maxsize as _maxsize
from sys import platform as _platform

__all__ = [
    "LINUX", "OPENBSD", "FREEBSD", "NETBSD", "DARWIN", "SOLARIS", "WINDOWS",
    "WINDOWS_XP", "BSD", "IS_64BITS", "BIG_ENDIAN",
]

LINUX = _platform.startswith("linux")
OPENBSD = _platform.startswith("openbsd")
FREEBSD = "freebsd" in _platform
NETBSD = _platform.startswith("netbsd")
DARWIN = _platform.startswith("darwin")
SOLARIS = _platform.startswith("sunos")
WINDOWS = _platform.startswith("win32")
WINDOWS_XP = WINDOWS and _sys.getwindowsversion()[:2] == (5, 1)
BSD = DARWIN or FREEBSD or OPENBSD or NETBSD
IS_64BITS = _maxsize > 2**32
BIG_ENDIAN = _byteorder == "big"
