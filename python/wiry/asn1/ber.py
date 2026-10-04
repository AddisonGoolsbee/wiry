# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from scapy: scapy/asn1/ber.py
#   scapy master, upstream commit e2e35c0
#   Copyright (C) Philippe Biondi <phil@secdev.org>
#   Acknowledgment: Maxence Tury <maxence.tury@ssi.gouv.fr>
#   Acknowledgment: Ralph Broenink
#
# Changed by the wiry authors:
#   2026-10-03 — transcribed; bounded the element count of one decode, the
#     nesting of packets as well as of values, and the octets a SEQUENCE OF
#     or an OID copies, all of which were attacker-controlled.
"""Basic Encoding Rules, ITU-T X.690 §8, which DER (§10) narrows.

Every bound on a decode is named here. Each is raised as `BER_Exception`,
which, unlike a decoding error, an OPTIONAL or CHOICE field does not read as
"absent, try the next one".
"""

import socket
import threading
from contextlib import contextmanager

from ..capture import conf
from .asn1 import (
    ASN1Tag,
    ASN1_BADTAG,
    ASN1_BadTag_Decoding_Error,
    ASN1_Class,
    ASN1_Class_UNIVERSAL,
    ASN1_Codecs,
    ASN1_DECODING_ERROR,
    ASN1_Decoding_Error,
    ASN1_Encoding_Error,
    ASN1_Error,
    ASN1_Object,
    _ASN1_ERROR,
    binrepr,
    bytes_encode,
    chb,
    warning,
)

from typing import (
    Any,
    AnyStr,
    Dict,
    Generic,
    Iterator,
    List,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
)

# Nesting of constructed values within one generic decode, and of ASN.1
# packets within one another; scapy bounds only the first.
MAX_BER_DEPTH = 32

# Identifier octets read in one top-level decode. Each costs a Python object
# or more, so this is what bounds the memory a crafted message can claim:
# two octets of input otherwise buy several hundred of heap.
MAX_BER_ELEMENTS = 1 << 18

_state = threading.local()


@contextmanager
def ber_budget() -> Iterator[None]:
    """Charge every decode inside to one budget, opened by the outermost."""
    outer = getattr(_state, "left", None) is not None
    if not outer:
        _state.left = MAX_BER_ELEMENTS
        _state.nesting = 0
    _state.nesting += 1
    try:
        if _state.nesting > MAX_BER_DEPTH:
            raise BER_Exception("Reached maximum ASN.1 packet nesting")
        yield
    finally:
        _state.nesting -= 1
        if not outer:
            _state.left = None


def _charge() -> None:
    left = getattr(_state, "left", None)
    if left is not None:
        if left <= 0:
            raise BER_Exception(
                "BER: more than %d elements in one decode" % MAX_BER_ELEMENTS)
        _state.left = left - 1


def _inet_aton(s: str) -> bytes:
    return socket.inet_aton(s)


def _inet_ntoa(b: bytes) -> str:
    if len(b) != 4:
        raise ValueError("an IPv4 address is four octets")
    return socket.inet_ntoa(b)


class Elements:
    """The elements of a constructed value's contents, each sliced once.

    scapy walks them as `while s: o, s = dec(s)`, re-copying what remains
    after every element, which is quadratic in the element count. This hands
    each decoder exactly its own TLV instead. Should a decoder leave octets
    undecoded, `leftover()` puts them back in front of the rest and the walk
    continues scapy's way from there, so the result is the same either way.
    """

    __slots__ = ("s", "ends", "i", "pos", "slow", "last")

    def __init__(self, s: bytes) -> None:
        self.s = s
        self.ends = _tlv_ends(s)
        self.i = 0
        self.pos = 0
        self.slow: Optional[bytes] = None
        self.last = 0

    def __iter__(self) -> "Elements":
        return self

    def __next__(self) -> bytes:
        if self.slow is not None:
            if not self.slow:
                raise StopIteration
            chunk, self.slow = self.slow, b""
        elif self.i < len(self.ends):
            end = self.ends[self.i]
            self.i += 1
            chunk, self.pos = self.s[self.pos:end], end
        elif self.pos < len(self.s):
            chunk, self.pos, self.slow = self.s[self.pos:], len(self.s), b""
        else:
            raise StopIteration
        self.last = len(chunk)
        return chunk

    def rest(self) -> bytes:
        """What follows the element last handed out."""
        return self.slow if self.slow is not None else self.s[self.pos:]

    def leftover(self, remain: bytes) -> None:
        if remain:
            # scapy loops forever on an element that consumes nothing.
            if len(remain) >= self.last:
                raise BER_Decoding_Error("element consumed no octets",
                                         remaining=remain)
            self.slow = remain + self.rest()
            self.pos, self.i = len(self.s), len(self.ends)


def _tlv_ends(s: bytes) -> List[int]:
    """Where each TLV of `s` ends, up to the first whose header does not
    parse or overruns `s`; the rest is left to the decoder to refuse."""
    ends: List[int] = []
    i, n = 0, len(s)
    while i < n:
        j = i + 1
        if s[i] & 0x1F == 0x1F:
            while j < n and s[j] & 0x80:
                j += 1
            j += 1
        if j >= n:
            break
        first = s[j]
        j += 1
        if first & 0x80:
            k = first & 0x7F
            if j + k > n:
                break
            ln = int.from_bytes(s[j:j + k], "big")
            j += k
        else:
            ln = first
        if j + ln > n:
            break
        i = j + ln
        ends.append(i)
    return ends


class BER_Exception(Exception):
    pass


class BER_Encoding_Error(ASN1_Encoding_Error):
    def __init__(self,
                 msg,
                 encoded=None,
                 remaining=b""
                 ):
        Exception.__init__(self, msg)
        self.remaining = remaining
        self.encoded = encoded

    def __str__(self):
        s = Exception.__str__(self)
        if isinstance(self.encoded, ASN1_Object):
            s += "\n### Already encoded ###\n%s" % self.encoded.strshow()
        else:
            s += "\n### Already encoded ###\n%r" % self.encoded
        s += "\n### Remaining ###\n%r" % self.remaining
        return s


class BER_Decoding_Error(ASN1_Decoding_Error):
    def __init__(self,
                 msg,
                 decoded=None,
                 remaining=b""
                 ):
        Exception.__init__(self, msg)
        self.remaining = remaining
        self.decoded = decoded

    def __str__(self):
        s = Exception.__str__(self)
        if isinstance(self.decoded, ASN1_Object):
            s += "\n### Already decoded ###\n%s" % self.decoded.strshow()
        else:
            s += "\n### Already decoded ###\n%r" % self.decoded
        s += "\n### Remaining ###\n%r" % self.remaining
        return s


class BER_BadTag_Decoding_Error(BER_Decoding_Error,
                                ASN1_BadTag_Decoding_Error):
    pass


def BER_len_enc(ll, size=0):
    if size is None:
        size = conf.ASN1_default_long_size
    if ll <= 127 and size == 0:
        return chb(ll)
    s = b""
    while ll or size > 0:
        s = chb(ll & 0xff) + s
        ll >>= 8
        size -= 1
    if len(s) > 127:
        raise BER_Exception(
            "BER_len_enc: Length too long (%i) to be encoded [%r]" %
            (len(s), s)
        )
    return chb(len(s) | 0x80) + s


def BER_len_dec(s):
    tmp_len = s[0]
    if not tmp_len & 0x80:
        return tmp_len, s[1:]
    tmp_len &= 0x7f
    if len(s) <= tmp_len:
        raise BER_Decoding_Error(
            "BER_len_dec: Got %i bytes while expecting %i" %
            (len(s) - 1, tmp_len),
            remaining=s
        )
    ll = 0
    for c in s[1:tmp_len + 1]:
        ll <<= 8
        ll |= c
    return ll, s[tmp_len + 1:]


def BER_num_enc(ll, size=1):
    x = []
    while ll or size > 0:
        x.insert(0, ll & 0x7f)
        if len(x) > 1:
            x[0] |= 0x80
        ll >>= 7
        size -= 1
    return b"".join(chb(k) for k in x)


def BER_num_dec(s, cls_id=0, max_pow=32):
    if len(s) == 0:
        raise BER_Decoding_Error("BER_num_dec: got empty string", remaining=s)
    x = cls_id
    for i, c in enumerate(s):
        x <<= 7
        x |= c & 0x7f
        if not c & 0x80:
            break
        if i > max_pow:
            raise BER_Decoding_Error("BER_num_dec: maximum value reached (2^32-1)",
                                     remaining=s)
    if c & 0x80:
        raise BER_Decoding_Error("BER_num_dec: unfinished number description",
                                 remaining=s)
    return x, s[i + 1:]


def BER_id_dec(s):
    """The tag with its class and constructed bits still on it, so 0x81 stays
    0x81. A high tag number keeps the top three bits of its first octet as a
    leading base-128 digit: 0xff 0x22 is (0xff >> 5) * 128 + 0x22."""
    _charge()
    x = s[0]
    if x & 0x1f != 0x1f:
        return x, s[1:]
    return BER_num_dec(s[1:], cls_id=x >> 5)


def BER_id_enc(n):
    if n < 256:
        return chb(n)
    s = BER_num_enc(n)
    return chb((s[0] & 0x07) << 5 | 0x1f) + s[1:]


def BER_tagging_dec(s,
                    hidden_tag=None,
                    implicit_tag=None,
                    explicit_tag=None,
                    safe=False,
                    _fname="",
                    ):
    """Strip an implicit or explicit tag, putting back the `hidden_tag` an
    implicit one replaced. Returns the tag actually seen where it differs
    from the one asked for, which only `safe` tolerates."""
    real_tag = None
    if len(s) > 0:
        err_msg = (
            "BER_tagging_dec: observed tag 0x%.02x does not "
            "match expected tag 0x%.02x (%s)"
        )
        if implicit_tag is not None:
            ber_id, s = BER_id_dec(s)
            if ber_id != implicit_tag:
                if not safe and ber_id != implicit_tag:
                    raise BER_Decoding_Error(err_msg % (
                        ber_id, implicit_tag, _fname),
                        remaining=s)
                else:
                    real_tag = ber_id
            s = chb(int(hidden_tag)) + s
        elif explicit_tag is not None:
            ber_id, s = BER_id_dec(s)
            if ber_id != explicit_tag:
                if not safe:
                    raise BER_Decoding_Error(
                        err_msg % (ber_id, explicit_tag, _fname),
                        remaining=s)
                else:
                    real_tag = ber_id
            l, s = BER_len_dec(s)
    return real_tag, s


def BER_tagging_enc(s, implicit_tag=None, explicit_tag=None):
    if len(s) > 0:
        if implicit_tag is not None:
            s = BER_id_enc(implicit_tag) + s[1:]
        elif explicit_tag is not None:
            s = BER_id_enc(explicit_tag) + BER_len_enc(
                len(s), size=conf.ASN1_default_long_size,
            ) + s
    return s

#    [ BER classes ]    #


class BERcodec_metaclass(type):
    def __new__(cls,
                name,
                bases,
                dct
                ):
        c = cast('Type[BERcodec_Object[Any]]',
                 super(BERcodec_metaclass, cls).__new__(cls, name, bases, dct))
        try:
            c.tag.register(c.codec, c)
        except Exception:
            warning("Error registering %r for %r" % (c.tag, c.codec))
        return c


_K = TypeVar('_K')


class BERcodec_Object(Generic[_K], metaclass=BERcodec_metaclass):
    codec = ASN1_Codecs.BER
    tag = ASN1_Class_UNIVERSAL.ANY

    @classmethod
    def asn1_object(cls, val):
        return cls.tag.asn1_object(val)

    @classmethod
    def check_string(cls, s):
        if not s:
            raise BER_Decoding_Error(
                "%s: Got empty object while expecting tag %r" %
                (cls.__name__, cls.tag), remaining=s
            )

    @classmethod
    def check_type(cls, s):
        cls.check_string(s)
        tag, remainder = BER_id_dec(s)
        if not isinstance(tag, int) or cls.tag != tag:
            raise BER_BadTag_Decoding_Error(
                "%s: Got tag [%i/%#x] while expecting %r" %
                (cls.__name__, tag, tag, cls.tag), remaining=s
            )
        return remainder

    @classmethod
    def check_type_get_len(cls, s):
        s2 = cls.check_type(s)
        if not s2:
            raise BER_Decoding_Error("%s: No bytes while expecting a length" %
                                     cls.__name__, remaining=s)
        return BER_len_dec(s2)

    @classmethod
    def check_type_check_len(cls, s):
        l, s3 = cls.check_type_get_len(s)
        if len(s3) < l:
            raise BER_Decoding_Error("%s: Got %i bytes while expecting %i" %
                                     (cls.__name__, len(s3), l), remaining=s)
        return l, s3[:l], s3[l:]

    @classmethod
    def do_dec(cls,
               s,
               context=None,
               safe=False,
               _depth=0,
               ):
        if context is not None:
            _context = context
        else:
            _context = cls.tag.context
        cls.check_string(s)
        p, remainder = BER_id_dec(s)
        if p not in _context:
            t = s
            if len(t) > 18:
                t = t[:15] + b"..."
            raise BER_Decoding_Error("Unknown prefix [%02x] for [%r]" %
                                     (p, t), remaining=s)
        tag = _context[p]
        codec = cast('Type[BERcodec_Object[_K]]',
                     tag.get_codec(ASN1_Codecs.BER))
        if codec == BERcodec_Object:
            # X.690 §8.1.3 lengths are not base-128 numbers, which is how
            # scapy reads this one; a long-form length came out wrong.
            if not remainder:
                raise BER_Decoding_Error("BER_num_dec: got empty string",
                                         remaining=remainder)
            l, s = BER_len_dec(remainder)
            return ASN1_BADTAG(s[:l]), s[l:]
        return codec.dec(s, _context, safe, _depth=_depth)

    @classmethod
    def dec(cls,
            s,
            context=None,
            safe=False,
            _depth=0,
            **_kwargs
            ):
        if _depth > MAX_BER_DEPTH:
            raise BER_Exception("Reached maximum BER recursion limit")
        if _depth == 0:
            with ber_budget():
                return cls._dec(s, context, safe, _depth)
        return cls._dec(s, context, safe, _depth)

    @classmethod
    def _dec(cls, s, context, safe, _depth):
        if not safe:
            return cls.do_dec(s, context, safe, _depth=_depth)
        try:
            return cls.do_dec(s, context, safe, _depth=_depth)
        except BER_BadTag_Decoding_Error as e:
            o, remain = BERcodec_Object.dec(
                e.remaining,
                context=context,
                safe=safe,
                _depth=_depth + 1,
            )
            return ASN1_BADTAG(o), remain
        except BER_Decoding_Error as e:
            return ASN1_DECODING_ERROR(s, exc=e), b""
        except ASN1_Error as e:
            return ASN1_DECODING_ERROR(s, exc=e), b""

    @classmethod
    def safedec(cls,
                s,
                context=None,
                _depth=0,
                **_kwargs
                ):
        return cls.dec(s, context, safe=True, _depth=_depth)

    @classmethod
    def enc(cls, s, size_len=0, **_kwargs):
        if isinstance(s, (str, bytes)):
            return BERcodec_STRING.enc(s, size_len=size_len)
        else:
            try:
                return BERcodec_INTEGER.enc(int(s), size_len=size_len)
            except TypeError:
                raise TypeError("Trying to encode an invalid value !")


ASN1_Codecs.BER.register_stem(BERcodec_Object)
ASN1_Codecs.BER.register_tagging(BER_tagging_enc, BER_tagging_dec)


##########################
#    BERcodec objects    #
##########################

class BERcodec_INTEGER(BERcodec_Object[int]):
    tag = ASN1_Class_UNIVERSAL.INTEGER

    @classmethod
    def enc(cls, i, size_len=0, **_kwargs):
        ls = []
        while True:
            ls.append(i & 0xff)
            if -127 <= i < 0:
                break
            if 128 <= i <= 255:
                ls.append(0)
            i >>= 8
            if not i:
                break
        s = [chb(int(c)) for c in ls]
        s.append(BER_len_enc(len(s), size=size_len))
        s.append(chb(int(cls.tag)))
        s.reverse()
        return b"".join(s)

    @classmethod
    def do_dec(cls,
               s,
               context=None,
               safe=False,
               _depth=0,
               ):
        l, s, t = cls.check_type_check_len(s)
        return cls.asn1_object(int.from_bytes(s, "big", signed=True)), t


class BERcodec_BOOLEAN(BERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.BOOLEAN


class BERcodec_BIT_STRING(BERcodec_Object[str]):
    tag = ASN1_Class_UNIVERSAL.BIT_STRING

    @classmethod
    def do_dec(cls,
               s,
               context=None,
               safe=False,
               _depth=0,
               ):
        # The count of unused bits is not kept: `val` simply has that many fewer.
        l, s, t = cls.check_type_check_len(s)
        if len(s) > 0:
            unused_bits = s[0]
            if safe and unused_bits > 7:
                raise BER_Decoding_Error(
                    "BERcodec_BIT_STRING: too many unused_bits advertised",
                    remaining=s
                )
            fs = "".join(binrepr(x).zfill(8) for x in s[1:])
            if unused_bits > 0:
                fs = fs[:-unused_bits]
            return cls.tag.asn1_object(fs), t
        else:
            raise BER_Decoding_Error(
                "BERcodec_BIT_STRING found no content "
                "(not even unused_bits byte)",
                remaining=s
            )

    @classmethod
    def enc(cls, _s, size_len=0, **_kwargs):
        # X.690 §11.2.1 (DER): the unused bits are zero.
        s = bytes_encode(_s)
        if len(s) % 8 == 0:
            unused_bits = 0
        else:
            unused_bits = 8 - len(s) % 8
            s += b"0" * unused_bits
        s = b"".join(chb(int(b"".join(chb(y) for y in x), 2))
                     for x in zip(*[iter(s)] * 8))
        s = chb(unused_bits) + s
        return chb(int(cls.tag)) + BER_len_enc(len(s), size=size_len) + s


class BERcodec_STRING(BERcodec_Object[str]):
    tag = ASN1_Class_UNIVERSAL.STRING

    @classmethod
    def enc(cls, _s, size_len=0, **_kwargs):
        s = bytes_encode(_s)
        return chb(int(cls.tag)) + BER_len_enc(len(s), size=size_len) + s

    @classmethod
    def do_dec(cls,
               s,
               context=None,
               safe=False,
               _depth=0,
               ):
        l, s, t = cls.check_type_check_len(s)
        return cls.tag.asn1_object(s), t


class BERcodec_NULL(BERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.NULL

    @classmethod
    def enc(cls, i, size_len=0, **_kwargs):
        if i == 0:
            return chb(int(cls.tag)) + b"\0"
        else:
            return super(cls, cls).enc(i, size_len=size_len)


class BERcodec_OID(BERcodec_Object[bytes]):
    tag = ASN1_Class_UNIVERSAL.OID

    @classmethod
    def enc(cls, _oid, size_len=0, **_kwargs):
        oid = bytes_encode(_oid)
        if oid:
            lst = [int(x) for x in oid.strip(b".").split(b".")]
        else:
            lst = list()
        if len(lst) >= 2:
            lst[1] += 40 * lst[0]
            del lst[0]
        s = b"".join(BER_num_enc(k) for k in lst)
        return chb(int(cls.tag)) + BER_len_enc(len(s), size=size_len) + s

    @classmethod
    def do_dec(cls,
               s,
               context=None,
               safe=False,
               _depth=0,
               ):
        l, s, t = cls.check_type_check_len(s)
        lst = []
        x = i = 0
        for i, c in enumerate(s):
            x = x << 7 | c & 0x7f
            if not c & 0x80:
                lst.append(x)
                x = 0
            elif x >> 7 * 33:
                raise BER_Decoding_Error(
                    "BER_num_dec: maximum value reached (2^32-1)", remaining=s)
        if s and s[-1] & 0x80:
            raise BER_Decoding_Error(
                "BER_num_dec: unfinished number description", remaining=s)
        if lst:
            # X.690 §8.19.4: the first subidentifier is 40X + Y, and only X
            # = 2 may have Y >= 40. scapy splits it by 40 alone, so 2.999
            # decoded as 26.39.
            first = lst[0]
            lst[0:1] = [2, first - 80] if first >= 80 else divmod(first, 40)
        return (
            cls.asn1_object(b".".join(str(k).encode('ascii') for k in lst)),
            t,
        )


class BERcodec_ENUMERATED(BERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.ENUMERATED


class BERcodec_UTF8_STRING(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.UTF8_STRING


class BERcodec_NUMERIC_STRING(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.NUMERIC_STRING


class BERcodec_PRINTABLE_STRING(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.PRINTABLE_STRING


class BERcodec_T61_STRING(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.T61_STRING


class BERcodec_VIDEOTEX_STRING(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.VIDEOTEX_STRING


class BERcodec_IA5_STRING(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.IA5_STRING


class BERcodec_GENERAL_STRING(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.GENERAL_STRING


class BERcodec_UTC_TIME(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.UTC_TIME


class BERcodec_GENERALIZED_TIME(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.GENERALIZED_TIME


class BERcodec_ISO646_STRING(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.ISO646_STRING


class BERcodec_UNIVERSAL_STRING(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.UNIVERSAL_STRING


class BERcodec_BMP_STRING(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.BMP_STRING


class BERcodec_SEQUENCE(BERcodec_Object[Union[bytes, List[BERcodec_Object[Any]]]]):
    tag = ASN1_Class_UNIVERSAL.SEQUENCE

    @classmethod
    def enc(cls, _ll, size_len=None, **_kwargs):
        if isinstance(_ll, bytes):
            ll = _ll
        else:
            ll = b"".join(x.enc(cls.codec) for x in _ll)
        # None reads conf.ASN1_default_long_size; 0 is the shortest form.
        if size_len is None:
            size_len = conf.ASN1_default_long_size
        return chb(int(cls.tag)) + BER_len_enc(len(ll), size=size_len) + ll

    @classmethod
    def do_dec(cls,
               s,
               context=None,
               safe=False,
               _depth=0,
               ):
        if context is None:
            context = cls.tag.context
        if _depth > MAX_BER_DEPTH:
            raise BER_Exception("Reached maximum BER recursion limit")
        ll, st = cls.check_type_get_len(s)
        s, t = st[:ll], st[ll:]
        obj = []
        elts = Elements(s)
        for elt in elts:
            try:
                o, remain = BERcodec_Object.dec(
                    elt,
                    context=context,
                    safe=safe,
                    _depth=_depth + 1,
                )
            except BER_Decoding_Error as err:
                err.remaining += elts.rest() + t
                if err.decoded is not None:
                    obj.append(err.decoded)
                err.decoded = obj
                raise
            obj.append(o)
            elts.leftover(remain)
        if len(st) < ll:
            raise BER_Decoding_Error("Not enough bytes to decode sequence",
                                     decoded=obj)
        return cls.asn1_object(obj), t


class BERcodec_SET(BERcodec_SEQUENCE):
    tag = ASN1_Class_UNIVERSAL.SET


class BERcodec_IPADDRESS(BERcodec_STRING):
    tag = ASN1_Class_UNIVERSAL.IPADDRESS

    @classmethod
    def enc(cls, ipaddr_ascii, size_len=0, **_kwargs):
        try:
            s = _inet_aton(ipaddr_ascii)
        except Exception:
            raise BER_Encoding_Error("IPv4 address could not be encoded")
        return chb(int(cls.tag)) + BER_len_enc(len(s), size=size_len) + s

    @classmethod
    def do_dec(cls,
               s,
               context=None,
               safe=False,
               _depth=0,
               ):
        l, s, t = cls.check_type_check_len(s)
        try:
            ipaddr_ascii = _inet_ntoa(s)
        except Exception:
            raise BER_Decoding_Error("IP address could not be decoded",
                                     remaining=s)
        return cls.asn1_object(ipaddr_ascii), t


class BERcodec_COUNTER32(BERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.COUNTER32


class BERcodec_COUNTER64(BERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.COUNTER64


class BERcodec_GAUGE32(BERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.GAUGE32


class BERcodec_TIME_TICKS(BERcodec_INTEGER):
    tag = ASN1_Class_UNIVERSAL.TIME_TICKS
