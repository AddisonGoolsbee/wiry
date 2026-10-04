# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from scapy: scapy/layers/dns.py
#   scapy master, upstream commit e2e35c0
#   Copyright (C) Philippe Biondi <phil@secdev.org>
#
# Changed by the wiry authors:
#   2026-10-04 — transcribed onto wiry's Python layer model; the UDP and TCP
#     bindings are the Rust DNS layer's, which keeps a capture's DNS visible to
#     the bulk paths. The answering machines stay in wiry.answering. The EDNS0
#     Owner thresholds, Client Subnet ADDRESS length and TSIG length defaults
#     follow their specifications where 2.7.0 does not; master agrees.
"""DNS (RFC 1035), mDNS (RFC 6762) and DNS-SD (RFC 6763) messages.

The Rust DNS layer finds the message on UDP and TCP port 53 and on 5353, and
is what `columns()` and `filter()` read; `pkt[DNS]` is this module's object
tree, decoded on first access. Names are compressed only by `dns_compress()`,
as in scapy: building a message writes every name in full.
"""

import itertools
import operator
import socket
import struct
import time
import warnings

from .. import IP, TCP, UDP, IPv6, RandShort, bind_bottom_up
from .. import _PY_WIRE
from .._pyfields import (
    BitEnumField, BitField, ByteEnumField, ByteField, ConditionalField, Field,
    FieldLenField, FieldListField, FlagsField, IP6Field, IPField, IntField,
    MACField, MultipleTypeField, PacketListField,
    Scapy_Exception, ShortEnumField, ShortField, StrField, StrLenField,
    UTCTimeField, XStrFixedLenField, XStrLenField, bytes_encode, chb, conf,
    log_runtime, plain_str, warning,
)
from .._pylayer import PyPacket as Packet, PyRaw as Raw
from ..plist import SndRcvList
from socket import inet_ntop, inet_pton

__all__ = [
    "dnstypes", "dnsqtypes", "dnsclasses", "dnssecalgotypes",
    "dnssecdigesttypes", "dnssecnsec3algotypes", "dns_get_str", "dns_encode",
    "DNSgetstr", "dns_compress", "DNSCompressedPacket", "DNSStrField",
    "DNSTextField", "edns0types", "EDNS0TLV", "DNSRROPT", "EDNS0OWN",
    "EDNS0DAU", "EDNS0DHU", "EDNS0N3U", "ClientSubnetv4", "ClientSubnetv6",
    "EDNS0ClientSubnet", "EDNS0COOKIE", "EDNS0PADDING",
    "extended_dns_error_codes", "EDNS0ExtendedDNSError", "EDNS0OPT_DISPATCHER",
    "bitmap2RRlist", "RRlist2bitmap", "RRlistField", "DNSRRHINFO", "DNSRRMX",
    "DNSRRSOA", "DNSRRRSIG", "DNSRRNSEC", "DNSRRDNSKEY", "DNSRRDS", "DNSRRDLV",
    "DNSRRNSEC3", "DNSRRNSEC3PARAM", "svc_param_keys", "SvcParam",
    "DNSRRSVCB", "DNSRRHTTPS", "DNSRRSRV", "tsig_algo_sizes",
    "TimeSignedField", "DNSRRTSIG", "DNSRRNAPTR", "DNSRR_DISPATCHER", "DNSRR",
    "DNSQR", "DNS", "DNSTCP", "dns_resolve", "dyndns_add", "dyndns_del",
    "DNSSDResult", "dnssd", "DNS_am", "mDNS_am",
]


# IANA "Resource Record (RR) TYPEs".
dnstypes = {
    0: "RESERVED",
    1: "A", 2: "NS", 3: "MD", 4: "MF", 5: "CNAME", 6: "SOA", 7: "MB", 8: "MG",
    9: "MR", 10: "NULL", 11: "WKS", 12: "PTR", 13: "HINFO", 14: "MINFO",
    15: "MX", 16: "TXT", 17: "RP", 18: "AFSDB", 19: "X25", 20: "ISDN",
    21: "RT", 22: "NSAP", 23: "NSAP-PTR", 24: "SIG", 25: "KEY", 26: "PX",
    27: "GPOS", 28: "AAAA", 29: "LOC", 30: "NXT", 31: "EID", 32: "NIMLOC",
    33: "SRV", 34: "ATMA", 35: "NAPTR", 36: "KX", 37: "CERT", 38: "A6",
    39: "DNAME", 40: "SINK", 41: "OPT", 42: "APL", 43: "DS", 44: "SSHFP",
    45: "IPSECKEY", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 49: "DHCID",
    50: "NSEC3", 51: "NSEC3PARAM", 52: "TLSA", 53: "SMIMEA", 55: "HIP",
    56: "NINFO", 57: "RKEY", 58: "TALINK", 59: "CDS", 60: "CDNSKEY",
    61: "OPENPGPKEY", 62: "CSYNC", 63: "ZONEMD", 64: "SVCB", 65: "HTTPS",
    99: "SPF", 100: "UINFO", 101: "UID", 102: "GID", 103: "UNSPEC", 104: "NID",
    105: "L32", 106: "L64", 107: "LP", 108: "EUI48", 109: "EUI64", 249: "TKEY",
    250: "TSIG", 256: "URI", 257: "CAA", 258: "AVC", 259: "DOA",
    260: "AMTRELAY", 32768: "TA", 32769: "DLV", 65535: "RESERVED"
}


dnsqtypes = {251: "IXFR", 252: "AXFR", 253: "MAILB", 254: "MAILA", 255: "ALL"}
dnsqtypes.update(dnstypes)
dnsclasses = {1: 'IN', 2: 'CS', 3: 'CH', 4: 'HS', 255: 'ANY'}


# IANA "DNS Security Algorithm Numbers", 12/2023.
dnssecalgotypes = {0: "Reserved", 1: "RSA/MD5", 2: "Diffie-Hellman", 3: "DSA/SHA-1",
                   4: "Reserved", 5: "RSA/SHA-1", 6: "DSA-NSEC3-SHA1",
                   7: "RSASHA1-NSEC3-SHA1", 8: "RSA/SHA-256", 9: "Reserved",
                   10: "RSA/SHA-512", 11: "Reserved", 12: "GOST R 34.10-2001",
                   13: "ECDSA Curve P-256 with SHA-256", 14: "ECDSA Curve P-384 with SHA-384",
                   15: "Ed25519", 16: "Ed448",
                   252: "Reserved for Indirect Keys", 253: "Private algorithms - domain name",
                   254: "Private algorithms - OID", 255: "Reserved"}

# IANA "Delegation Signer (DS) Resource Record (RR) Type Digest Algorithms".
dnssecdigesttypes = {0: "Reserved", 1: "SHA-1", 2: "SHA-256", 3: "GOST R 34.11-94", 4: "SHA-384"}

# IANA "DNSSEC NSEC3 Hash Algorithms".
dnssecnsec3algotypes = {0: "Reserved", 1: "SHA-1"}


def dns_get_str(s, full=None, _ignore_compression=False):
    """Decode the name at the start of `s`, following compression pointers
    into `full`. Returns ``(name, remaining)``, where remaining starts after
    the first pointer if the name was compressed.

    A pointer loop or more than 20 jumps ends the name where it got to rather
    than raising, as does a name running off the end of the data.
    """
    max_length = len(s)
    name = b""
    after_pointer = None
    processed_pointers = []
    bytes_left = None
    _fullpacket = False
    pointer = 0
    while True:
        if abs(pointer) >= max_length:
            log_runtime.info(
                "DNS RR prematured end (ofs=%i, len=%i)", pointer, len(s)
            )
            break
        cur = s[pointer]
        pointer += 1
        if cur & 0xc0:
            if after_pointer is None:
                after_pointer = pointer + 1
            if _ignore_compression:
                pointer += 1
                continue
            if pointer >= max_length:
                log_runtime.info(
                    "DNS incomplete jump token at (ofs=%i)", pointer
                )
                break
            if not full:
                raise Scapy_Exception("DNS message can't be compressed " +
                                      "at this point!")
            pointer = ((cur & ~0xc0) << 8) + s[pointer]
            if pointer in processed_pointers:
                warning("DNS decompression loop detected")
                break
            if len(processed_pointers) >= 20:
                warning("More than 20 jumps in a single DNS decompression ! "
                        "Dropping (evil packet)")
                break
            if not _fullpacket:
                bytes_left = s[after_pointer:]
                s = full
                max_length = len(s)
                _fullpacket = True
            processed_pointers.append(pointer)
            continue
        elif cur > 0:
            name += _escape(s[pointer:pointer + cur]) + b"."
            pointer += cur
        else:
            break
    if after_pointer is not None:
        pointer = after_pointer
    if bytes_left is None:
        bytes_left = s[pointer:]
    return name or b".", bytes_left


def _escape(label):
    """RFC 1035 §5.1 and RFC 4343 §2.1: a dot or backslash inside a label is
    escaped, or the name would read back as different labels. scapy joins
    labels unescaped, so a name holding one splits on rebuild."""
    return label.replace(b"\\", b"\\\\").replace(b".", b"\\.")


def _dots(x):
    """The offsets of the dots in `x` that separate labels."""
    out = []
    i = 0
    while i < len(x):
        c = x[i]
        if c == 0x5c:
            i += 2
            continue
        if c == 0x2e:
            out.append(i)
        i += 1
    return out


def _unescape(text):
    """A label's octets from its presentation form: ``\\X`` is X and
    ``\\DDD`` the octet DDD (RFC 1035 §5.1)."""
    if b"\\" not in text:
        return text
    out = bytearray()
    i = 0
    while i < len(text):
        c = text[i]
        if c == 0x5c and i + 1 < len(text):
            ddd = text[i + 1:i + 4]
            if len(ddd) == 3 and ddd.isdigit() and int(ddd) < 256:
                out.append(int(ddd))
                i += 4
                continue
            out.append(text[i + 1])
            i += 2
            continue
        out.append(c)
        i += 1
    return bytes(out)


def _split_labels(x):
    """`x` split at its separating dots, each label unescaped; a trailing dot
    leaves an empty last label, as `bytes.split` does."""
    cuts = [-1] + _dots(x) + [len(x)]
    return [_unescape(x[a + 1:b]) for a, b in zip(cuts, cuts[1:])]


def _is_ptr(x):
    """Whether `x` already looks encoded: it ends in the root label or in a
    compression pointer."""
    return (
        (x and x[-1] == 0) or
        (len(x) >= 2 and (x[-2] & 0xc0) == 0xc0)
    )


def dns_encode(x, check_built=False):
    """`x` as RFC 1035 §3.1 labels. A label over 63 octets is truncated, and
    with `check_built` a value that is already encoded is returned as it is.
    """
    if not x or x == b".":
        return b"\x00"

    if check_built and _is_ptr(x):
        return x

    x = b"".join(chb(len(y)) + y for y in (k[:63] for k in _split_labels(x)))
    if x[-1:] != b"\x00":
        x += b"\x00"
    return x


def DNSgetstr(*args, **kwargs):
    """Deprecated spelling of `dns_get_str`."""
    warnings.warn(
        "DNSgetstr is deprecated. Use dns_get_str instead.",
        DeprecationWarning
    )
    return dns_get_str(*args, **kwargs)[:-1]


def dns_compress(pkt):
    """`pkt` with every name compressed against its first occurrence, per
    RFC 1035 §4.1.4. The compressed names are written into the fields as
    encoded labels ending in a pointer, so the result reads back as such
    until it is dissected again.
    """
    if DNS not in pkt:
        raise Scapy_Exception("Can only compress DNS layers")
    pkt = pkt.copy()
    dns_pkt = pkt.getlayer(DNS)
    dns_pkt.clear_cache()
    build_pkt = bytes(dns_pkt)

    def field_gen(dns_pkt):
        for lay in [dns_pkt.qd, dns_pkt.an, dns_pkt.ns, dns_pkt.ar]:
            if not lay:
                continue
            for current in lay:
                for field in current.fields_desc:
                    if isinstance(field, DNSStrField) or \
                        (isinstance(field, MultipleTypeField) and
                         current.type in [2, 3, 4, 5, 12, 15, 39, 47]):
                        dat = current.getfieldval(field.name)
                        yield current, field.name, dat

    def possible_shortens(dat):
        if dat == b".":
            return
        yield dat
        dots = _dots(dat)
        for x in range(1, len(dots)):
            yield dat[dots[x - 1] + 1:]
    data = {}
    for current, name, dat in field_gen(dns_pkt):
        for part in possible_shortens(dat):
            encoded = dns_encode(part, check_built=True)
            if part not in data:
                index = build_pkt.index(encoded)
                fb_index = ((index >> 8) | 0xc0)
                sb_index = index - (256 * (fb_index - 0xc0))
                pointer = chb(fb_index) + chb(sb_index)
                data[part] = [(current, name, pointer, index + 1)]
            else:
                # Blank the occurrence just claimed, so a later suffix search
                # cannot point into a name that is about to be replaced.
                data[part].append((current, name))
                _in = data[part][0][3]
                build_pkt = build_pkt[:_in] + build_pkt[_in:].replace(
                    encoded,
                    b"\0\0",
                    1
                )
                break
    for ck in data:
        replacements = data[ck]
        replace_pointer = replacements.pop(0)[2]
        for rep in replacements:
            val = rep[0].getfieldval(rep[1])
            assert val.endswith(ck)
            kept_string = dns_encode(val[:-len(ck)], check_built=True)[:-1]
            new_val = kept_string + replace_pointer
            rep[0].setfieldval(rep[1], new_val)
            try:
                del rep[0].rdlen
            except AttributeError:
                pass
    # A wiry packet carries its DNS layer as the object just edited, so the
    # copy already holds the compressed message.
    if isinstance(pkt, DNS):
        return dns_pkt
    return pkt


class DNSCompressedPacket(Packet):
    """A layer whose names may point into the message `get_full()` returns."""

    def get_full(self):
        raise NotImplementedError


class DNSStrField(StrLenField):
    """A domain name, decompressed on dissection against the enclosing
    `DNSCompressedPacket`. With `length_from` it reads that many octets first.
    """

    def any2i(self, pkt, x):
        if x and isinstance(x, list):
            return [self.h2i(pkt, y) for y in x]
        return super(DNSStrField, self).any2i(pkt, x)

    def h2i(self, pkt, x):
        # The enclosing message's octets carry pointers to this name's old
        # position; they are stale once it changes.
        if (
            pkt and
            isinstance(pkt.parent, DNSCompressedPacket) and
            pkt.parent.raw_packet_cache
        ):
            pkt.parent.clear_cache()
        if not x:
            return b"."
        x = bytes_encode(x)
        if x[-1:] != b"." and not _is_ptr(x):
            return x + b"."
        return x

    def i2m(self, pkt, x):
        return dns_encode(x, check_built=True)

    def i2len(self, pkt, x):
        return len(self.i2m(pkt, x))

    def get_full(self, pkt):
        while pkt and not isinstance(pkt, DNSCompressedPacket):
            pkt = pkt.parent or pkt.underlayer
        if not pkt:
            return None
        return pkt.get_full()

    def getfield(self, pkt, s):
        remain = b""
        if self.length_from:
            remain, s = super(DNSStrField, self).getfield(pkt, s)
        decoded, left = dns_get_str(s, full=self.get_full(pkt))
        return left + remain, decoded


class DNSTextField(StrLenField):
    """RFC 1035 §3.3.14: one or more <character-string>s. A string of 255
    octets or more is split across as many as it takes."""

    islist = 1

    def i2h(self, pkt, x):
        if not x:
            return []
        return x

    def m2i(self, pkt, s):
        ret_s = list()
        tmp_s = s
        while tmp_s:
            tmp_len = tmp_s[0] + 1
            if tmp_len > len(tmp_s):
                log_runtime.info(
                    "DNS RR TXT prematured end of character-string "
                    "(size=%i, remaining bytes=%i)", tmp_len, len(tmp_s)
                )
            ret_s.append(tmp_s[1:tmp_len])
            tmp_s = tmp_s[tmp_len:]
        return ret_s

    def any2i(self, pkt, x):
        if isinstance(x, (str, bytes)):
            return [x]
        return x

    def i2len(self, pkt, x):
        return len(self.i2m(pkt, x))

    def i2m(self, pkt, s):
        ret_s = b""
        for text in s:
            if not text:
                ret_s += b"\x00"
                continue
            text = bytes_encode(text)
            while len(text) >= 255:
                ret_s += b"\xff" + text[:255]
                text = text[255:]
            if len(text):
                ret_s += struct.pack("!B", len(text)) + text
        return ret_s


# RFC 6891 (EDNS(0)) and the IANA "DNS EDNS0 Option Codes (OPT)" registry.

edns0types = {0: "Reserved", 1: "LLQ", 2: "UL", 3: "NSID", 4: "Owner",
              5: "DAU", 6: "DHU", 7: "N3U", 8: "edns-client-subnet", 10: "COOKIE",
              12: "Padding", 15: "Extended DNS Error"}


class _EDNS0Dummy(Packet):
    name = "Dummy class that implements extract_padding()"

    def extract_padding(self, p):
        return "", p


class EDNS0TLV(_EDNS0Dummy):
    name = "DNS EDNS0 TLV"
    fields_desc = [ShortEnumField("optcode", 0, edns0types),
                   FieldLenField("optlen", None, "optdata", fmt="H"),
                   StrLenField("optdata", "",
                               length_from=lambda pkt: pkt.optlen)]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return EDNS0TLV
        if len(_pkt) < 2:
            return Raw
        edns0type = struct.unpack("!H", _pkt[:2])[0]
        return EDNS0OPT_DISPATCHER.get(edns0type, EDNS0TLV)


class DNSRROPT(Packet):
    name = "DNS OPT Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 41, dnstypes),
                   ShortEnumField("rclass", 4096, dnsclasses),
                   ByteField("extrcode", 0),
                   ByteField("version", 0),
                   # RFC 3225: the top bit is DO, "DNSSEC OK".
                   BitEnumField("z", 32768, 16, {32768: "D0"}),
                   FieldLenField("rdlen", None, length_of="rdata", fmt="H"),
                   PacketListField("rdata", [], EDNS0TLV,
                                   length_from=lambda pkt: pkt.rdlen)]


# draft-cheshire-edns0-owner-option-01: the option data is version, sequence
# and the primary MAC (8 octets), then optionally the wakeup MAC (14) and a
# password (18 or 20). scapy 2.7.0 read those thresholds as 18 and 22, as if
# OPTION-LENGTH counted the option's own four-octet header.

class EDNS0OWN(_EDNS0Dummy):
    name = "EDNS0 Owner (OWN)"
    fields_desc = [ShortEnumField("optcode", 4, edns0types),
                   FieldLenField("optlen", None, count_of="primary_mac", fmt="H"),
                   ByteField("v", 0),
                   ByteField("s", 0),
                   MACField("primary_mac", "00:00:00:00:00:00"),
                   ConditionalField(
                       MACField("wakeup_mac", "00:00:00:00:00:00"),
                       lambda pkt: (pkt.optlen or 0) >= 14),
                   ConditionalField(
                       StrLenField("password", "",
                                   length_from=lambda pkt: pkt.optlen - 14),
                       lambda pkt: (pkt.optlen or 0) >= 18)]

    def post_build(self, pkt, pay):
        pkt += pay
        if self.optlen is None:
            pkt = pkt[:2] + struct.pack("!H", len(pkt) - 4) + pkt[4:]
        return pkt


# RFC 6975: algorithm understanding signals.

class EDNS0DAU(_EDNS0Dummy):
    name = "DNSSEC Algorithm Understood (DAU)"
    fields_desc = [ShortEnumField("optcode", 5, edns0types),
                   FieldLenField("optlen", None, count_of="alg_code", fmt="H"),
                   FieldListField("alg_code", None,
                                  ByteEnumField("", 0, dnssecalgotypes),
                                  count_from=lambda pkt:pkt.optlen)]


class EDNS0DHU(_EDNS0Dummy):
    name = "DS Hash Understood (DHU)"
    fields_desc = [ShortEnumField("optcode", 6, edns0types),
                   FieldLenField("optlen", None, count_of="alg_code", fmt="H"),
                   FieldListField("alg_code", None,
                                  ByteEnumField("", 0, dnssecdigesttypes),
                                  count_from=lambda pkt:pkt.optlen)]


class EDNS0N3U(_EDNS0Dummy):
    name = "NSEC3 Hash Understood (N3U)"
    fields_desc = [ShortEnumField("optcode", 7, edns0types),
                   FieldLenField("optlen", None, count_of="alg_code", fmt="H"),
                   FieldListField("alg_code", None,
                                  ByteEnumField("", 0, dnssecnsec3algotypes),
                                  count_from=lambda pkt:pkt.optlen)]


# RFC 7871: Client Subnet.

class ClientSubnetv4(StrLenField):
    """RFC 7871 §6 ADDRESS: as many octets as SOURCE PREFIX-LENGTH needs,
    rounded up, with the host bits of the last one zero. scapy 2.7.0 rounded
    down, dropping a partial last octet."""

    af_familly = socket.AF_INET
    af_length = 32
    af_default = b"\xc0"  # 192.0.0.0

    def getfield(self, pkt, s):
        sz = operator.floordiv(self.length_from(pkt) + 7, 8)
        sz = min(sz, operator.floordiv(self.af_length, 8))
        return s[sz:], self.m2i(pkt, s[:sz])

    def m2i(self, pkt, x):
        padding = self.af_length - self.length_from(pkt)
        if padding:
            x += b"\x00" * operator.floordiv(padding, 8)
        x = x[: operator.floordiv(self.af_length, 8)]
        return inet_ntop(self.af_familly, x)

    def _pack_subnet(self, subnet, plen=None):
        packed_subnet = inet_pton(self.af_familly, plain_str(subnet))
        if plen is not None:
            num_bytes = operator.floordiv(plen + 7, 8)
            result = bytearray(packed_subnet[:num_bytes])
            rem = plen % 8
            if rem and result:
                result[-1] &= (0xff << (8 - rem)) & 0xff
            return bytes(result)
        # Without a prefix length, the octets up to the last non-zero one.
        for i in list(range(operator.floordiv(self.af_length, 8)))[::-1]:
            if packed_subnet[i] != 0:
                i += 1
                break
        return packed_subnet[:i]

    def i2m(self, pkt, x):
        if x is None:
            return self.af_default
        plen = getattr(pkt, 'source_plen', None)
        try:
            return self._pack_subnet(x, plen)
        except (OSError, socket.error):
            pkt.family = 2
            return ClientSubnetv6("", "")._pack_subnet(x, plen)

    def i2len(self, pkt, x):
        if x is None:
            return 1
        plen = getattr(pkt, 'source_plen', None)
        try:
            return len(self._pack_subnet(x, plen))
        except (OSError, socket.error):
            pkt.family = 2
            return len(ClientSubnetv6("", "")._pack_subnet(x, plen))


class ClientSubnetv6(ClientSubnetv4):
    af_familly = socket.AF_INET6
    af_length = 128
    af_default = b"\x20"  # 2000::


class EDNS0ClientSubnet(_EDNS0Dummy):
    name = "DNS EDNS0 Client Subnet"
    fields_desc = [ShortEnumField("optcode", 8, edns0types),
                   FieldLenField("optlen", None, "address", fmt="H",
                                 adjust=lambda pkt, x: x + 4),
                   ShortField("family", 1),
                   FieldLenField("source_plen", None,
                                 length_of="address",
                                 fmt="B",
                                 adjust=lambda pkt, x: x * 8),
                   ByteField("scope_plen", 0),
                   MultipleTypeField(
                       [(ClientSubnetv4("address", "192.168.0.0",
                         length_from=lambda p: p.source_plen),
                         lambda pkt: pkt.family == 1),
                        (ClientSubnetv6("address", "2001:db8::",
                         length_from=lambda p: p.source_plen),
                         lambda pkt: pkt.family == 2)],
                       ClientSubnetv4("address", "192.168.0.0",
                                      length_from=lambda p: p.source_plen))]


class EDNS0COOKIE(_EDNS0Dummy):
    name = "DNS EDNS0 COOKIE"
    fields_desc = [ShortEnumField("optcode", 10, edns0types),
                   FieldLenField("optlen", None, length_of="server_cookie", fmt="!H",
                                 adjust=lambda pkt, x: x + 8),
                   XStrFixedLenField("client_cookie", b"\x00" * 8, length=8),
                   XStrLenField("server_cookie", "",
                                length_from=lambda pkt: max(0, pkt.optlen - 8))]


# RFC 7830.
class EDNS0PADDING(_EDNS0Dummy):
    name = "DNS EDNS0 Padding"
    fields_desc = [ShortEnumField("optcode", 12, edns0types),
                   FieldLenField("optlen", None, length_of="padding", fmt="!H"),
                   StrLenField("padding", "",
                               length_from=lambda pkt: pkt.optlen)]


# IANA "Extended DNS Error Codes".
extended_dns_error_codes = {
    0: "Other",
    1: "Unsupported DNSKEY Algorithm",
    2: "Unsupported DS Digest Type",
    3: "Stale Answer",
    4: "Forged Answer",
    5: "DNSSEC Indeterminate",
    6: "DNSSEC Bogus",
    7: "Signature Expired",
    8: "Signature Not Yet Valid",
    9: "DNSKEY Missing",
    10: "RRSIGs Missing",
    11: "No Zone Key Bit Set",
    12: "NSEC Missing",
    13: "Cached Error",
    14: "Not Ready",
    15: "Blocked",
    16: "Censored",
    17: "Filtered",
    18: "Prohibited",
    19: "Stale NXDOMAIN Answer",
    20: "Not Authoritative",
    21: "Not Supported",
    22: "No Reachable Authority",
    23: "Network Error",
    24: "Invalid Data",
    25: "Signature Expired before Valid",
    26: "Too Early",
    27: "Unsupported NSEC3 Iterations Value",
    28: "Unable to conform to policy",
    29: "Synthesized",
}


# RFC 8914.
class EDNS0ExtendedDNSError(_EDNS0Dummy):
    name = "DNS EDNS0 Extended DNS Error"
    fields_desc = [ShortEnumField("optcode", 15, edns0types),
                   FieldLenField("optlen", None, length_of="extra_text", fmt="!H",
                                 adjust=lambda pkt, x: x + 2),
                   ShortEnumField("info_code", 0, extended_dns_error_codes),
                   StrLenField("extra_text", "",
                               length_from=lambda pkt: pkt.optlen - 2)]


EDNS0OPT_DISPATCHER = {
    4: EDNS0OWN,
    5: EDNS0DAU,
    6: EDNS0DHU,
    7: EDNS0N3U,
    8: EDNS0ClientSubnet,
    10: EDNS0COOKIE,
    12: EDNS0PADDING,
    15: EDNS0ExtendedDNSError,
}


def bitmap2RRlist(bitmap):
    """RFC 4034 §4.1.2 Type Bit Maps as a list of type numbers, or `None` if
    a window is malformed."""
    RRlist = []

    while bitmap:

        if len(bitmap) < 2:
            log_runtime.info("bitmap too short (%i)", len(bitmap))
            return

        window_block = bitmap[0]
        offset = 256 * window_block
        bitmap_len = bitmap[1]

        if bitmap_len <= 0 or bitmap_len > 32:
            log_runtime.info("bitmap length is no valid (%i)", bitmap_len)
            return

        tmp_bitmap = bitmap[2:2 + bitmap_len]

        for b in range(len(tmp_bitmap)):
            v = 128
            for i in range(8):
                if tmp_bitmap[b] & v:
                    RRlist += [offset + b * 8 + i]
                v = v >> 1

        bitmap = bitmap[2 + bitmap_len:]

    return RRlist


def RRlist2bitmap(lst):
    """A list of type numbers as RFC 4034 §4.1.2 Type Bit Maps."""
    import math

    bitmap = b""
    lst = [abs(x) for x in sorted(set(lst)) if x <= 65535]

    max_window_blocks = int(math.ceil(lst[-1] / 256.))
    min_window_blocks = int(math.floor(lst[0] / 256.))
    if min_window_blocks == max_window_blocks:
        max_window_blocks += 1

    for wb in range(min_window_blocks, max_window_blocks + 1):
        rrlist = sorted(x for x in lst if 256 * wb <= x < 256 * (wb + 1))
        if not rrlist:
            continue

        if rrlist[-1] == 0:
            bytes_count = 1
        else:
            max = rrlist[-1] - 256 * wb
            bytes_count = int(math.ceil(max // 8)) + 1
        if bytes_count > 32:
            bytes_count = 32

        bitmap += struct.pack("BB", wb, bytes_count)

        bitmap += b"".join(
            struct.pack(
                b"B",
                sum(2 ** (7 - (x - 256 * wb) + (tmp * 8)) for x in rrlist
                    if 256 * wb + 8 * tmp <= x < 256 * wb + 8 * tmp + 8),
            ) for tmp in range(bytes_count)
        )

    return bitmap


class RRlistField(StrField):
    """Type Bit Maps, held encoded; a list of types is encoded on assignment
    and printed by name."""

    islist = 1

    def h2i(self, pkt, x):
        if x and isinstance(x, list):
            return RRlist2bitmap(x)
        return x

    def i2repr(self, pkt, x):
        if not x:
            return "[]"
        x = self.i2h(pkt, x)
        rrlist = bitmap2RRlist(x)
        return [dnstypes.get(rr, rr) for rr in rrlist] if rrlist else repr(x)


class _DNSRRdummy(Packet):
    name = "Dummy class that implements post_build() for Resource Records"

    def post_build(self, pkt, pay):
        if self.rdlen is not None:
            return pkt + pay

        lrrname = len(self.fields_desc[0].i2m("", self.getfieldval("rrname")))
        tmp_len = len(pkt) - lrrname - 10
        tmp_pkt = pkt[:lrrname + 8]
        pkt = struct.pack("!H", tmp_len) + pkt[lrrname + 8 + 2:]

        return tmp_pkt + pkt + pay

    def default_payload_class(self, payload):
        return conf.padding_layer


# The top bit of the class is mDNS's cache-flush bit (RFC 6762 §10.2) on every
# record type mDNS carries.

class DNSRRHINFO(_DNSRRdummy):
    name = "DNS HINFO Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 13, dnstypes),
                   BitField("cacheflush", 0, 1),
                   BitEnumField("rclass", 1, 15, dnsclasses),
                   IntField("ttl", 0),
                   ShortField("rdlen", None),
                   FieldLenField("cpulen", None, fmt="!B", length_of="cpu"),
                   StrLenField("cpu", "", length_from=lambda x: x.cpulen),
                   FieldLenField("oslen", None, fmt="!B", length_of="os"),
                   StrLenField("os", "", length_from=lambda x: x.oslen)]


class DNSRRMX(_DNSRRdummy):
    name = "DNS MX Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 15, dnstypes),
                   BitField("cacheflush", 0, 1),
                   BitEnumField("rclass", 1, 15, dnsclasses),
                   IntField("ttl", 0),
                   ShortField("rdlen", None),
                   ShortField("preference", 0),
                   DNSStrField("exchange", ""),
                   ]


class DNSRRSOA(_DNSRRdummy):
    name = "DNS SOA Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 6, dnstypes),
                   ShortEnumField("rclass", 1, dnsclasses),
                   IntField("ttl", 0),
                   ShortField("rdlen", None),
                   DNSStrField("mname", ""),
                   DNSStrField("rname", ""),
                   IntField("serial", 0),
                   IntField("refresh", 0),
                   IntField("retry", 0),
                   IntField("expire", 0),
                   IntField("minimum", 0)
                   ]


class DNSRRRSIG(_DNSRRdummy):
    name = "DNS RRSIG Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 46, dnstypes),
                   BitField("cacheflush", 0, 1),
                   BitEnumField("rclass", 1, 15, dnsclasses),
                   IntField("ttl", 0),
                   ShortField("rdlen", None),
                   ShortEnumField("typecovered", 1, dnstypes),
                   ByteEnumField("algorithm", 5, dnssecalgotypes),
                   ByteField("labels", 0),
                   IntField("originalttl", 0),
                   UTCTimeField("expiration", 0),
                   UTCTimeField("inception", 0),
                   ShortField("keytag", 0),
                   DNSStrField("signersname", ""),
                   StrField("signature", "")
                   ]


class DNSRRNSEC(_DNSRRdummy):
    name = "DNS NSEC Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 47, dnstypes),
                   BitField("cacheflush", 0, 1),
                   BitEnumField("rclass", 1, 15, dnsclasses),
                   IntField("ttl", 0),
                   ShortField("rdlen", None),
                   DNSStrField("nextname", ""),
                   RRlistField("typebitmaps", [])
                   ]


class DNSRRDNSKEY(_DNSRRdummy):
    name = "DNS DNSKEY Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 48, dnstypes),
                   BitField("cacheflush", 0, 1),
                   BitEnumField("rclass", 1, 15, dnsclasses),
                   IntField("ttl", 0),
                   ShortField("rdlen", None),
                   # RFC 4034 §2.1.1: S is the Secure Entry Point, Z the Zone
                   # Key, bit 7 and bit 15.
                   FlagsField("flags", 256, 16, "S???????Z???????"),
                   ByteField("protocol", 3),
                   ByteEnumField("algorithm", 5, dnssecalgotypes),
                   StrField("publickey", "")
                   ]


class DNSRRDS(_DNSRRdummy):
    name = "DNS DS Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 43, dnstypes),
                   BitField("cacheflush", 0, 1),
                   BitEnumField("rclass", 1, 15, dnsclasses),
                   IntField("ttl", 0),
                   ShortField("rdlen", None),
                   ShortField("keytag", 0),
                   ByteEnumField("algorithm", 5, dnssecalgotypes),
                   ByteEnumField("digesttype", 5, dnssecdigesttypes),
                   StrField("digest", "")
                   ]


# RFC 4431.
class DNSRRDLV(DNSRRDS):
    name = "DNS DLV Resource Record"

    def __init__(self, *args, **kargs):
        DNSRRDS.__init__(self, *args, **kargs)
        if not kargs.get('type', 0):
            self.type = 32769


# RFC 5155.

class DNSRRNSEC3(_DNSRRdummy):
    name = "DNS NSEC3 Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 50, dnstypes),
                   BitField("cacheflush", 0, 1),
                   BitEnumField("rclass", 1, 15, dnsclasses),
                   IntField("ttl", 0),
                   ShortField("rdlen", None),
                   ByteField("hashalg", 0),
                   BitEnumField("flags", 0, 8, {1: "Opt-Out"}),
                   ShortField("iterations", 0),
                   FieldLenField("saltlength", 0, fmt="!B", length_of="salt"),
                   StrLenField("salt", "", length_from=lambda x: x.saltlength),
                   FieldLenField("hashlength", 0, fmt="!B", length_of="nexthashedownername"),
                   StrLenField("nexthashedownername", "", length_from=lambda x: x.hashlength),
                   RRlistField("typebitmaps", [])
                   ]


class DNSRRNSEC3PARAM(_DNSRRdummy):
    name = "DNS NSEC3PARAM Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 51, dnstypes),
                   BitField("cacheflush", 0, 1),
                   BitEnumField("rclass", 1, 15, dnsclasses),
                   IntField("ttl", 0),
                   ShortField("rdlen", None),
                   ByteField("hashalg", 0),
                   ByteField("flags", 0),
                   ShortField("iterations", 0),
                   FieldLenField("saltlength", 0, fmt="!B", length_of="salt"),
                   StrLenField("salt", "", length_from=lambda pkt: pkt.saltlength)
                   ]


# RFC 9460 and the IANA "DNS SVCB" registry.

svc_param_keys = {
    0: "mandatory",
    1: "alpn",
    2: "no-default-alpn",
    3: "port",
    4: "ipv4hint",
    5: "ech",
    6: "ipv6hint",
    7: "dohpath",
    8: "ohttp",
}


class SvcParam(Packet):
    name = "SvcParam"
    fields_desc = [ShortEnumField("key", 0, svc_param_keys),
                   FieldLenField("len", None, length_of="value", fmt="H"),
                   MultipleTypeField(
                       [
                           (FieldListField("value", [],
                                           ShortEnumField("", 0, svc_param_keys),
                                           length_from=lambda pkt: pkt.len),
                               lambda pkt: pkt.key == 0),
                           (DNSTextField("value", [],
                                         length_from=lambda pkt: pkt.len),
                               lambda pkt: pkt.key in (1, 2)),
                           (ShortField("value", 0),
                               lambda pkt: pkt.key == 3),
                           (FieldListField("value", [],
                                           IPField("", "0.0.0.0"),
                                           length_from=lambda pkt: pkt.len),
                               lambda pkt: pkt.key == 4),
                           (FieldListField("value", [],
                                           IP6Field("", "::"),
                                           length_from=lambda pkt: pkt.len),
                               lambda pkt: pkt.key == 6),
                       ],
                       StrLenField("value", "",
                                   length_from=lambda pkt:pkt.len))]

    def extract_padding(self, p):
        return "", p


class DNSRRSVCB(_DNSRRdummy):
    name = "DNS SVCB Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 64, dnstypes),
                   BitField("cacheflush", 0, 1),
                   BitEnumField("rclass", 1, 15, dnsclasses),
                   IntField("ttl", 0),
                   ShortField("rdlen", None),
                   ShortField("svc_priority", 0),
                   DNSStrField("target_name", ""),
                   PacketListField("svc_params", [], SvcParam)]


class DNSRRHTTPS(_DNSRRdummy):
    name = "DNS HTTPS Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 65, dnstypes)
                   ] + DNSRRSVCB.fields_desc[2:]


# RFC 2782.

class DNSRRSRV(_DNSRRdummy):
    name = "DNS SRV Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 33, dnstypes),
                   BitField("cacheflush", 0, 1),
                   BitEnumField("rclass", 1, 15, dnsclasses),
                   IntField("ttl", 0),
                   ShortField("rdlen", None),
                   ShortField("priority", 0),
                   ShortField("weight", 0),
                   ShortField("port", 0),
                   DNSStrField("target", ""), ]


# RFC 8945 (TSIG, formerly RFC 2845).
tsig_algo_sizes = {"HMAC-MD5.SIG-ALG.REG.INT": 16,
                   "hmac-sha1": 20}


class TimeSignedField(Field):
    """RFC 8945 §4.2 Time Signed: seconds since the epoch in 48 bits."""

    def __init__(self, name, default):
        Field.__init__(self, name, default, fmt="6s")

    def _convert_seconds(self, packed_seconds):
        seconds = struct.unpack("!H", packed_seconds[:2])[0]
        seconds += struct.unpack("!I", packed_seconds[2:])[0]
        return seconds

    def i2m(self, pkt, seconds):
        if seconds is None:
            seconds = 0

        tmp_short = (seconds >> 32) & 0xFFFF
        tmp_int = seconds & 0xFFFFFFFF

        return struct.pack("!HI", tmp_short, tmp_int)

    def m2i(self, pkt, packed_seconds):
        if packed_seconds is None:
            return None

        return self._convert_seconds(packed_seconds)

    def i2repr(self, pkt, packed_seconds):
        time_struct = time.gmtime(packed_seconds)
        return time.strftime("%a %b %d %H:%M:%S %Y", time_struct)


class DNSRRTSIG(_DNSRRdummy):
    name = "DNS TSIG Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 250, dnstypes),
                   ShortEnumField("rclass", 1, dnsclasses),
                   IntField("ttl", 0),
                   ShortField("rdlen", None),
                   DNSStrField("algo_name", "hmac-sha1"),
                   TimeSignedField("time_signed", 0),
                   ShortField("fudge", 0),
                   FieldLenField("mac_len", None, fmt="!H", length_of="mac_data"),
                   StrLenField("mac_data", "", length_from=lambda pkt: pkt.mac_len),
                   ShortField("original_id", 0),
                   ShortField("error", 0),
                   FieldLenField("other_len", None, fmt="!H", length_of="other_data"),
                   StrLenField("other_data", "", length_from=lambda pkt: pkt.other_len)
                   ]


# RFC 3403.
class DNSRRNAPTR(_DNSRRdummy):
    name = "DNS NAPTR Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 35, dnstypes),
                   BitField("cacheflush", 0, 1),
                   BitEnumField("rclass", 1, 15, dnsclasses),
                   IntField("ttl", 0),
                   ShortField("rdlen", None),
                   ShortField("order", 0),
                   ShortField("preference", 0),
                   FieldLenField("flags_len", None, fmt="!B", length_of="flags"),
                   StrLenField("flags", "", length_from=lambda pkt: pkt.flags_len),
                   FieldLenField("services_len", None, fmt="!B", length_of="services"),
                   StrLenField("services", "",
                               length_from=lambda pkt: pkt.services_len),
                   FieldLenField("regexp_len", None, fmt="!B", length_of="regexp"),
                   StrLenField("regexp", "", length_from=lambda pkt: pkt.regexp_len),
                   DNSStrField("replacement", ""),
                   ]


DNSRR_DISPATCHER = {
    6: DNSRRSOA,
    13: DNSRRHINFO,
    15: DNSRRMX,
    33: DNSRRSRV,
    35: DNSRRNAPTR,
    41: DNSRROPT,
    43: DNSRRDS,
    46: DNSRRRSIG,
    47: DNSRRNSEC,
    48: DNSRRDNSKEY,
    50: DNSRRNSEC3,
    51: DNSRRNSEC3PARAM,
    64: DNSRRSVCB,
    65: DNSRRHTTPS,
    250: DNSRRTSIG,
    32769: DNSRRDLV,
}


class DNSRR(Packet):
    name = "DNS Resource Record"
    show_indent = 0
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 1, dnstypes),
                   BitField("cacheflush", 0, 1),
                   BitEnumField("rclass", 1, 15, dnsclasses),
                   IntField("ttl", 0),
                   FieldLenField("rdlen", None, length_of="rdata", fmt="H"),
                   MultipleTypeField(
                       [
                           (IPField("rdata", "0.0.0.0"),
                               lambda pkt: pkt.type == 1),
                           (IP6Field("rdata", "::"),
                               lambda pkt: pkt.type == 28),
                           # NS, MD, MF, CNAME, PTR, DNAME
                           (DNSStrField("rdata", "",
                                        length_from=lambda pkt: pkt.rdlen),
                               lambda pkt: pkt.type in [2, 3, 4, 5, 12, 39]),
                           (DNSTextField("rdata", [""],
                                         length_from=lambda pkt: pkt.rdlen),
                               lambda pkt: pkt.type == 16),
                       ],
                       StrLenField("rdata", "",
                                   length_from=lambda pkt:pkt.rdlen)
    )]

    def default_payload_class(self, payload):
        return conf.padding_layer


def _DNSRR(s, **kwargs):
    """The record at the start of `s` as its type's class, followed by the
    rest of `s` as Padding for the list to carry on from."""
    if s:
        _, remain = dns_get_str(s, _ignore_compression=True)
        cls = DNSRR_DISPATCHER.get(
            struct.unpack("!H", remain[:2])[0],
            DNSRR,
        )
        rrlen = (
            len(s) - len(remain) +
            10 +
            struct.unpack("!H", remain[8:10])[0]
        )
        pkt = cls(s[:rrlen], **kwargs) / conf.padding_layer(s[rrlen:])
        # A compressed RDATA rebuilds to another length.
        del pkt.fields["rdlen"]
        return pkt
    return None


class DNSQR(Packet):
    name = "DNS Question Record"
    show_indent = 0
    fields_desc = [DNSStrField("qname", "www.example.com"),
                   ShortEnumField("qtype", 1, dnsqtypes),
                   BitField("unicastresponse", 0, 1),
                   BitEnumField("qclass", 1, 15, dnsclasses)]

    def default_payload_class(self, payload):
        return conf.padding_layer


class _DNSPacketListField(PacketListField):
    """A record section, still answering scapy's pre-list spelling: ``None``
    for an empty section and ``pkt.an.rdata`` for the first record, each with
    a DeprecationWarning."""

    def any2i(self, pkt, x):
        if x is None:
            warnings.warn(
                ("The DNS fields 'qd', 'an', 'ns' and 'ar' are now "
                 "PacketListField(s) ! "
                 "Setting a null default should be [] instead of None"),
                DeprecationWarning
            )
            x = []
        return super(_DNSPacketListField, self).any2i(pkt, x)

    def i2h(self, pkt, x):
        class _list(list):
            def __getattr__(self, attr):
                try:
                    ret = getattr(self[0], attr)
                    warnings.warn(
                        ("The DNS fields 'qd', 'an', 'ns' and 'ar' are now "
                         "PacketListField(s) ! "
                         "To access the first element, use pkt.an[0] instead of "
                         "pkt.an"),
                        DeprecationWarning
                    )
                    return ret
                except AttributeError:
                    raise
        return _list(x)


class DNS(DNSCompressedPacket):
    name = "DNS"
    FORCE_TCP = False
    fields_desc = [
        # RFC 1035 §4.2.2.
        ConditionalField(ShortField("length", None),
                         lambda p: p.FORCE_TCP or isinstance(p.underlayer, TCP)),
        ShortField("id", 0),
        BitField("qr", 0, 1),
        BitEnumField("opcode", 0, 4, {0: "QUERY", 1: "IQUERY", 2: "STATUS"}),
        BitField("aa", 0, 1),
        BitField("tc", 0, 1),
        BitField("rd", 1, 1),
        BitField("ra", 0, 1),
        BitField("z", 0, 1),
        # RFC 4035 §3.2.
        BitField("ad", 0, 1),
        BitField("cd", 0, 1),
        BitEnumField("rcode", 0, 4, {0: "ok", 1: "format-error",
                                     2: "server-failure", 3: "name-error",
                                     4: "not-implemented", 5: "refused"}),
        FieldLenField("qdcount", None, count_of="qd"),
        FieldLenField("ancount", None, count_of="an"),
        FieldLenField("nscount", None, count_of="ns"),
        FieldLenField("arcount", None, count_of="ar"),
        _DNSPacketListField("qd", [DNSQR()], DNSQR, count_from=lambda pkt: pkt.qdcount),
        _DNSPacketListField("an", [], _DNSRR, count_from=lambda pkt: pkt.ancount),
        _DNSPacketListField("ns", [], _DNSRR, count_from=lambda pkt: pkt.nscount),
        _DNSPacketListField("ar", [], _DNSRR, count_from=lambda pkt: pkt.arcount),
    ]

    def get_full(self):
        if isinstance(self.underlayer, TCP) or self.FORCE_TCP:
            return self.original[2:]
        else:
            return self.original

    def answers(self, other):
        return (isinstance(other, DNS) and
                self.id == other.id and
                self.qr == 1 and
                other.qr == 0)

    def mysummary(self):
        name = ""
        if self.qr:
            type = "Ans"
            if self.an and isinstance(self.an[0], DNSRR):
                name = ' %s' % self.an[0].rdata
            elif self.rcode != 0:
                name = self.sprintf(' %rcode%')
        else:
            type = "Qry"
            if self.qd and isinstance(self.qd[0], DNSQR):
                name = ' %s' % self.qd[0].qname
        return "%sDNS %s%s" % (
            "m"
            if isinstance(self.underlayer, UDP) and self.underlayer.dport == 5353
            else "",
            type,
            name,
        )

    def post_build(self, pkt, pay):
        if (
            (isinstance(self.underlayer, TCP) or self.FORCE_TCP) and
            self.length is None
        ):
            pkt = struct.pack("!H", len(pkt) - 2) + pkt[2:]
        return pkt + pay

    def compress(self):
        """This message with its names compressed; see `dns_compress()`."""
        return dns_compress(self)

    def pre_dissect(self, s):
        """Refuse a stream message whose prefix is missing or claims more than
        is there, or less than a header and a question."""
        if isinstance(self.underlayer, TCP):
            if len(s) >= 2:
                dns_len = struct.unpack("!H", s[:2])[0]
            else:
                message = "Malformed DNS message: too small!"
                log_runtime.info(message)
                raise Scapy_Exception(message)

            if dns_len < 14 or len(s) < dns_len:
                message = "Malformed DNS message: invalid length!"
                log_runtime.info(message)
                raise Scapy_Exception(message)

        return s


class DNSTCP(DNS):
    """A DNS message that always carries the RFC 1035 §4.2.2 length prefix."""

    FORCE_TCP = True
    match_subclass = True


# A payload too short for the Rust layer is still offered to the model, which
# is what refuses it, and raises under conf.debug_dissector as scapy does.
for _lower, _ports in ((UDP, (53, 5353)), (TCP, (53,))):
    for _port in _ports:
        bind_bottom_up(_lower, DNS, sport=_port)
        bind_bottom_up(_lower, DNS, dport=_port)


def _wire(stack, i, obj):
    """The Rust DNS layer's header fields, the rest of the message, and what
    follows it. Under TCP the Rust layer writes the RFC 1035 §4.2.2 prefix
    itself, keeping a value only if one was given."""
    msg = bytes(obj)
    pay = bytes(obj.payload)
    if pay and msg.endswith(pay):
        msg = msg[:-len(pay)]
    ints = []
    if obj.FORCE_TCP or isinstance(obj.underlayer, TCP):
        msg = msg[2:]
        length = obj.fields.get("length")
        if length is not None and i and stack[i - 1][0] == "TCP":
            ints.append((i, "length", int(length)))
    h = msg[:12].ljust(12, b"\0")
    ints += [
        (i, "id", (h[0] << 8) | h[1]),
        (i, "qr", h[2] >> 7),
        (i, "opcode", (h[2] >> 3) & 0xf),
        (i, "aa", (h[2] >> 2) & 1),
        (i, "tc", (h[2] >> 1) & 1),
        (i, "rd", h[2] & 1),
        (i, "ra", h[3] >> 7),
        (i, "z", (h[3] >> 6) & 1),
        (i, "ad", (h[3] >> 5) & 1),
        (i, "cd", (h[3] >> 4) & 1),
        (i, "rcode", h[3] & 0xf),
        (i, "qdcount", (h[4] << 8) | h[5]),
        (i, "ancount", (h[6] << 8) | h[7]),
        (i, "nscount", (h[8] << 8) | h[9]),
        (i, "arcount", (h[10] << 8) | h[11]),
    ]
    return ints, msg[12:], pay


_PY_WIRE["DNS"] = _wire


def _cache():
    from ..capture import conf as _conf
    return _conf.netcache.dns_cache


def dns_resolve(qname, qtype="A", raw=False, tcp=False, verbose=1, timeout=3, **kwargs):
    """Resolve `qname` through each of `conf.nameservers` in turn, caching
    the answer for 300 seconds.

    :param raw: return the whole response rather than the matching records
    :param tcp: ask over TCP from the start; a truncated UDP answer is retried
        over TCP regardless
    :param timeout: seconds per server
    :raise TimeoutError: if no server answered
    """
    from ..capture import conf as _conf
    from ..supersocket import StreamSocket

    qtype = DNSQR.qtype.any2i_one(None, qtype)
    qname = DNSQR.qname.any2i(None, qname)
    cache_ident = b";".join(
        [qname, struct.pack("!H", qtype)] +
        ([b"raw"] if raw else [])
    )
    result = _cache().get(cache_ident)
    if result:
        return result

    kwargs.setdefault("timeout", timeout)
    kwargs.setdefault("verbose", 0)
    res = None
    for nameserver in _conf.nameservers:
        sock = None
        try:
            if tcp:
                cls = DNSTCP
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            else:
                cls = DNS
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(kwargs["timeout"])
            sock.connect((nameserver, 53))
            sock = StreamSocket(sock, cls)
            res = sock.sr1(
                cls(qd=[DNSQR(qname=qname, qtype=qtype)], id=RandShort()),
                **kwargs,
            )
        except IOError as ex:
            if verbose:
                log_runtime.warning(str(ex))
            continue
        finally:
            if sock is not None:
                sock.close()
        if res:
            if res[DNS].tc == 1:
                if not tcp:
                    return dns_resolve(
                        qname=qname,
                        qtype=qtype,
                        raw=raw,
                        tcp=True,
                        **kwargs,
                    )
                elif verbose:
                    log_runtime.info("DNS answer is truncated !")

            if res[DNS].rcode == 2:
                res = None
                if verbose:
                    log_runtime.info(
                        "DNS: %s answered with failure for %s" % (
                            nameserver,
                            qname,
                        )
                    )
            else:
                break
    if res is not None:
        if raw:
            result = res
        else:
            result = [
                x
                for x in itertools.chain(res.an, res.ns, res.ar)
                if getattr(x, "type", None) == qtype
            ]
        if result:
            _cache()[cache_ident] = result
        return result
    else:
        raise TimeoutError


def _sr1(*args, **kw):
    from .. import sr1
    return sr1(*args, **kw)


def dyndns_add(nameserver, name, rdata, type="A", ttl=10):
    """Ask `nameserver` to add an `rdata` record for `name` (RFC 2136).
    Returns the response's rcode, 0 for success, or -1 with no response."""
    zone = name[name.find(".") + 1:]
    r = _sr1(IP(dst=nameserver) / UDP() / DNS(opcode=5,
                                              qd=[DNSQR(qname=zone, qtype="SOA")],
                                              ns=[DNSRR(rrname=name, type="A",
                                                        ttl=ttl, rdata=rdata)]),
             verbose=0, timeout=5)
    if r and r.haslayer(DNS):
        return r.getlayer(DNS).rcode
    else:
        return -1


def dyndns_del(nameserver, name, type="ALL", ttl=10):
    """Ask `nameserver` to delete `name`'s records of `type` (RFC 2136).
    Returns the response's rcode, 0 for success, or -1 with no response."""
    zone = name[name.find(".") + 1:]
    r = _sr1(IP(dst=nameserver) / UDP() / DNS(opcode=5,
                                              qd=[DNSQR(qname=zone, qtype="SOA")],
                                              ns=[DNSRR(rrname=name, type=type,
                                                        rclass="ANY", ttl=0, rdata="")]),
             verbose=0, timeout=5)
    if r and r.haslayer(DNS):
        return r.getlayer(DNS).rcode
    else:
        return -1


def __getattr__(name):
    if name in ("DNS_am", "mDNS_am"):
        from .. import answering
        return getattr(answering, name)
    raise AttributeError(name)


class DNSSDResult(SndRcvList):
    def __init__(self, res=None, name="DNS-SD", stats=None):
        SndRcvList.__init__(self, res, name, stats)

    def show(self, types=['PTR', 'SRV'], alltypes=False):
        """Print the services discovered, one row per responder.

        :param types: the record types to list
        :param alltypes: list every type
        """
        from .. import Ether
        from ..capture import conf as _conf
        from ..utils import pretty_list

        if alltypes:
            types = None
        data = list()

        resolve_mac = (
            self.res and isinstance(self.res[0][1].underlayer, Ether) and
            _conf.manufdb
        )

        header = ("IP", "Service")
        if resolve_mac:
            header = ("Mac",) + header

        for _, r in self.res:
            attrs = []
            for attr in itertools.chain(r[DNS].an, r[DNS].ar):
                if types and dnstypes.get(attr.type) not in types:
                    continue
                if isinstance(attr, DNSRRNSEC):
                    attrs.append(attr.sprintf("%type%=%nextname%"))
                elif isinstance(attr, DNSRRSRV):
                    attrs.append(attr.sprintf("%type%=(%target%,%port%)"))
                else:
                    attrs.append(attr.sprintf("%type%=%rdata%"))
            ans = (r.src, attrs)
            if resolve_mac:
                mac = _conf.manufdb._resolve_MAC(r.underlayer.src)
                data.append((mac,) + ans)
            else:
                data.append(ans)

        print(
            pretty_list(
                data,
                [header],
            )
        )


def dnssd(service="_services._dns-sd._udp.local",
          af=socket.AF_INET,
          qtype="PTR",
          iface=None,
          verbose=2,
          timeout=3):
    """Browse for `service` with a DNS-SD (RFC 6763) query over mDNS.

    :param af: socket.AF_INET or socket.AF_INET6
    :param qtype: PTR, SRV or TXT
    """
    from .. import sr
    from .._pyfields import ScopedIP

    if af == socket.AF_INET:
        pkt = IP(dst=ScopedIP("224.0.0.251", iface), ttl=255)
    elif af == socket.AF_INET6:
        pkt = IPv6(dst=ScopedIP("ff02::fb", iface))
    else:
        return
    pkt /= UDP(sport=5353, dport=5353)
    pkt /= DNS(rd=0, qd=[DNSQR(qname=service, qtype=qtype)])
    ans, _ = sr(pkt, multi=True, timeout=timeout, verbose=verbose)
    return DNSSDResult(ans.res)

