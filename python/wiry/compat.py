# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from scapy: scapy/compat.py and scapy/pton_ntop.py
#   scapy 2.7.0
#   Copyright (C) Philippe Biondi <phil@secdev.org>
#   Copyright (C) the scapy contributors
#
# Changed by the wiry authors:
#   2026-10-03 — kept the byte/str conversions and the address converters;
#                dropped the typing shims for Pythons wiry does not support.

"""Byte and address conversions scapy scripts call by name."""

from __future__ import annotations

import binascii
import re
import socket
import struct
from typing import Any

__all__ = [
    "bytes_encode", "plain_str", "chb", "orb", "bytes_hex", "hex_bytes",
    "int_bytes", "bytes_int", "base64_bytes", "bytes_base64", "inet_pton",
    "inet_ntop",
]


def bytes_encode(x: Any) -> bytes:
    if isinstance(x, str):
        return x.encode()
    return bytes(x)


def plain_str(x: Any) -> str:
    if isinstance(x, bytes):
        return x.decode(errors="backslashreplace")
    return str(x)


def chb(x: int) -> bytes:
    return struct.pack("!B", x)


def orb(x: Any) -> int:
    return x if isinstance(x, int) else ord(x)


def bytes_hex(x: Any) -> bytes:
    return binascii.b2a_hex(bytes_encode(x))


def hex_bytes(x: Any) -> bytes:
    return binascii.a2b_hex(bytes_encode(x))


def int_bytes(x: int, size: int) -> bytes:
    return x.to_bytes(size, byteorder="big")


def bytes_int(x: bytes) -> int:
    return int.from_bytes(x, "big")


def base64_bytes(x: Any) -> bytes:
    import base64
    return base64.decodebytes(bytes_encode(x))


def bytes_base64(x: Any) -> bytes:
    import base64
    return base64.encodebytes(bytes_encode(x)).replace(b"\n", b"")


_IP6_ZEROS = re.compile("(?::|^)(0(?::0)+)(?::|$)")


def _inet6_pton(addr: str) -> bytes:
    """RFC 4291 §2.2 text to octets, for a host whose socket module lacks
    ``inet_pton``."""
    joker_pos = None
    result = b""
    addr = plain_str(addr)
    if addr == "::":
        return b"\x00" * 16
    if addr.startswith("::"):
        addr = addr[1:]
    if addr.endswith("::"):
        addr = addr[:-1]
    parts = addr.split(":")
    nparts = len(parts)
    for i, part in enumerate(parts):
        if not part:
            if joker_pos is None:
                joker_pos = len(result)
            else:
                raise socket.error("Illegal syntax for IP address")
        elif i + 1 == nparts and "." in part:
            if part.count(".") != 3:
                raise socket.error("Illegal syntax for IP address")
            try:
                result += socket.inet_aton(part)
            except socket.error:
                raise socket.error("Illegal syntax for IP address")
        else:
            try:
                result += hex_bytes(part.rjust(4, "0"))
            except (binascii.Error, TypeError):
                raise socket.error("Illegal syntax for IP address")
    if joker_pos is not None:
        if len(result) == 16:
            raise socket.error("Illegal syntax for IP address")
        result = (result[:joker_pos] + b"\x00" * (16 - len(result))
                  + result[joker_pos:])
    if len(result) != 16:
        raise socket.error("Illegal syntax for IP address")
    return result


def _inet6_ntop(addr: bytes) -> str:
    """RFC 5952 §4.2.3: the longest run of zero groups collapses, the first
    one on a tie."""
    if len(addr) != 16:
        raise ValueError("invalid length of packed IP address string")
    address = ":".join(
        plain_str(bytes_hex(addr[idx:idx + 2])).lstrip("0") or "0"
        for idx in range(0, 16, 2)
    )
    try:
        match = max(_IP6_ZEROS.finditer(address),
                    key=lambda m: m.end(1) - m.start(1))
        return "{}::{}".format(address[:match.start()], address[match.end():])
    except ValueError:
        return address


_INET_PTON = {socket.AF_INET: socket.inet_aton, socket.AF_INET6: _inet6_pton}
_INET_NTOP = {socket.AF_INET: socket.inet_ntoa, socket.AF_INET6: _inet6_ntop}


def inet_pton(af: int, addr: Any) -> bytes:
    addr = plain_str(addr)
    try:
        return socket.inet_pton(af, addr)
    except AttributeError:
        try:
            return _INET_PTON[af](addr)
        except KeyError:
            raise socket.error("Address family not supported by protocol")


def inet_ntop(af: int, addr: Any) -> str:
    addr = bytes_encode(addr)
    try:
        return socket.inet_ntop(af, addr)
    except AttributeError:
        try:
            return _INET_NTOP[af](addr)
        except KeyError:
            raise ValueError("unknown address family %d" % af)
