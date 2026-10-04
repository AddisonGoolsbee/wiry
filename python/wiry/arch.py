# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from scapy: scapy/arch/__init__.py, scapy/arch/common.py and
#   scapy/arch/linux/__init__.py
#   scapy 2.7.0
#   Copyright (C) Philippe Biondi <phil@secdev.org>
#   Copyright (C) the scapy contributors
#
# Changed by the wiry authors:
#   2026-10-03 — the user-facing interface helpers, over wiry's interface
#                list and routing module.

"""Per-interface address helpers."""

from __future__ import annotations

import re
import socket
from typing import Any, List, Optional

from .consts import LINUX

__all__ = [
    "get_if_addr6", "get_if_raw_addr", "get_if_raw_addr6", "read_nameservers",
    "SIOCGIFHWADDR",
]

#: Linux's ioctl for an interface's hardware address; 0 elsewhere, as scapy.
SIOCGIFHWADDR = 0x8927 if LINUX else 0


def get_if_addr6(iff: Any) -> Optional[str]:
    """The interface's global unicast IPv6 address (its loopback address on
    the loopback interface), or None."""
    from .capture import conf
    from .route import in6_getifaddr
    from .utils6 import IPV6_ADDR_GLOBAL, IPV6_ADDR_LOOPBACK

    iff = str(iff)
    scope = IPV6_ADDR_LOOPBACK if iff == conf.loopback_name else IPV6_ADDR_GLOBAL
    return next((x[0] for x in in6_getifaddr() if x[2] == iff and x[1] == scope), None)


def get_if_raw_addr(iff: Any) -> bytes:
    """``get_if_addr`` as four octets; all zeros where there is none."""
    from .capture import get_if_addr

    return socket.inet_pton(socket.AF_INET, get_if_addr(iff))


def get_if_raw_addr6(iff: Any) -> Optional[bytes]:
    ip6 = get_if_addr6(iff)
    return None if ip6 is None else socket.inet_pton(socket.AF_INET6, ip6)


def read_nameservers() -> List[str]:
    """The nameservers ``/etc/resolv.conf`` names."""
    from .error import warning

    try:
        with open("/etc/resolv.conf") as fd:
            return re.findall(r"nameserver\s+([^\s]+)", fd.read())
    except FileNotFoundError:
        warning("Could not retrieve the OS's nameserver !")
        return []
