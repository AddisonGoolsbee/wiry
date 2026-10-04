# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from scapy: scapy/asn1packet.py
#   scapy master, upstream commit e2e35c0
#   Copyright (C) Philippe Biondi <phil@secdev.org>
#
# Changed by the wiry authors:
#   2026-10-03 — transcribed onto wiry's Python layer model; dissection runs
#     inside one element budget.
"""A packet whose layout is an ASN.1 type, held as one `ASN1_root` field."""

from typing import Any

from ._pylayer import PyPacket, PyPacketMeta
from .asn1.ber import ber_budget


class ASN1Packet_metaclass(PyPacketMeta):
    def __new__(cls, name, bases, dct):
        if dct.get("ASN1_root") is not None:
            dct["fields_desc"] = dct["ASN1_root"].get_fields_list()
        return super().__new__(cls, name, bases, dct)


class ASN1_Packet(PyPacket, metaclass=ASN1Packet_metaclass):
    ASN1_root: Any = None
    ASN1_codec: Any = None

    def self_build(self) -> bytes:
        if self.raw_packet_cache is not None:
            return self.raw_packet_cache
        return self.ASN1_root.build(self)

    def do_dissect(self, x: bytes) -> bytes:
        with ber_budget():
            return self.ASN1_root.dissect(self, x)
