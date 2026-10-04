# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from scapy: scapy/asn1/asn1.py; Enum_metaclass and EnumElement from
#   scapy/utils.py; GeneralizedTime, IntAutoTime and RandOID from scapy/volatile.py
#   scapy master, upstream commit e2e35c0
#   Copyright (C) Philippe Biondi <phil@secdev.org>
#   Acknowledgment: Maxence Tury <maxence.tury@ssi.gouv.fr>
#
# Changed by the wiry authors:
#   2026-10-03 — transcribed; the volatile values draw in Python, and the
#     Python 2 timezone fallback is gone.
"""ASN.1 classes, tags and value objects (ITU-T X.680)."""

import random
import time

from datetime import datetime, timedelta, timezone

from ..capture import conf
from ..volatile import VolatileValue, RandIP

from typing import (
    Any,
    AnyStr,
    Dict,
    Generic,
    List,
    Optional,
    Tuple,
    Type,
    Union,
    cast,
    TYPE_CHECKING,
)
from typing import (
    TypeVar,
)

if TYPE_CHECKING:
    from .ber import BERcodec_Object


class Scapy_Exception(Exception):
    pass


def warning(msg: str) -> None:
    import logging
    logging.getLogger("wiry").warning(msg)


def plain_str(x: Any) -> str:
    if isinstance(x, bytes):
        return x.decode(errors="backslashreplace")
    return str(x)


def bytes_encode(x: Any) -> bytes:
    if isinstance(x, bytes):
        return x
    if isinstance(x, (bytearray, memoryview)):
        return bytes(x)
    if isinstance(x, str):
        return x.encode()
    return bytes(x)


def chb(x: int) -> bytes:
    return bytes([x])


def binrepr(val: int) -> str:
    return bin(val)[2:]


class EnumElement:
    def __init__(self, key, value):
        self._key = key
        self._value = value

    def __repr__(self):
        return "<%s %s[%r]>" % (self.__dict__.get("_name", self.__class__.__name__), self._key, self._value)

    def __getattr__(self, attr):
        return getattr(self._value, attr)

    def __str__(self):
        return self._key

    def __bytes__(self):
        return bytes_encode(self.__str__())

    def __hash__(self):
        return self._value

    def __int__(self):
        return int(self._value)

    def __eq__(self, other):
        return self._value == int(other)


class Enum_metaclass(type):
    element_class = EnumElement

    def __new__(cls, name, bases, dct):
        rdict = {}
        for k, v in dct.items():
            if isinstance(v, int):
                v = cls.element_class(k, v)
                dct[k] = v
                rdict[v] = k
        dct["__rdict__"] = rdict
        return super(Enum_metaclass, cls).__new__(cls, name, bases, dct)

    def __getitem__(self, attr):
        return self.__rdict__[attr]

    def __contains__(self, val):
        return val in self.__rdict__


class _PyVolatile(VolatileValue):
    """A volatile value drawn in Python rather than from a Rust spec."""

    __slots__ = ()

    def __init__(self) -> None:
        super().__init__(("python",))

    def _draw(self) -> Any:
        return self._fix()

    def __repr__(self) -> str:
        return "<%s>" % type(self).__name__


class IntAutoTime(_PyVolatile):
    __slots__ = ("diff",)

    def __init__(self, base: Optional[float] = None, diff: Optional[float] = None):
        super().__init__()
        self.diff = diff if diff is not None else (
            0 if base is None else time.time() - base)

    def _fix(self) -> int:
        return int(time.time() - self.diff)


class GeneralizedTime(_PyVolatile):
    __slots__ = ("diff",)

    def __init__(self, diff: float = 0):
        super().__init__()
        self.diff = diff

    def _fix(self) -> str:
        return time.strftime("%Y%m%d%H%M%SZ", time.gmtime(time.time() + self.diff))


class RandOID(_PyVolatile):
    """Arcs and depth drawn from exponential distributions, as scapy's are."""

    __slots__ = ()

    def _fix(self) -> str:
        depth = int(random.expovariate(0.1))
        return ".".join(str(int(random.expovariate(0.01))) for _ in range(1 + depth))


class RandASN1Object(_PyVolatile):
    __slots__ = ("objlist", "chars")

    def __init__(self, objlist=None):
        super().__init__()
        if objlist:
            self.objlist = objlist
        else:
            self.objlist = [
                x._asn1_obj
                for x in ASN1_Class_UNIVERSAL.__rdict__.values()
                if hasattr(x, "_asn1_obj")
            ]
        self.chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

    def _fix(self, n=0):
        o = random.choice(self.objlist)
        if issubclass(o, ASN1_INTEGER):
            return o(int(random.gauss(0, 1000)))
        elif issubclass(o, ASN1_IPADDRESS):
            return o(str(RandIP()))
        elif issubclass(o, ASN1_GENERALIZED_TIME) or issubclass(o, ASN1_UTC_TIME):
            return o(GeneralizedTime()._fix())
        elif issubclass(o, ASN1_STRING):
            z1 = int(random.expovariate(0.05) + 1)
            return o("".join(random.choice(self.chars) for _ in range(z1)).encode())
        elif issubclass(o, ASN1_SEQUENCE) and (n < 10):
            z2 = int(random.expovariate(0.08) + 1)
            return o([self.__class__(objlist=self.objlist)._fix(n + 1)
                      for _ in range(z2)])
        return ASN1_INTEGER(int(random.gauss(0, 1000)))


##############
#    ASN1    #
##############

class ASN1_Error(Scapy_Exception):
    pass


class ASN1_Encoding_Error(ASN1_Error):
    pass


class ASN1_Decoding_Error(ASN1_Error):
    pass


class ASN1_BadTag_Decoding_Error(ASN1_Decoding_Error):
    pass


class ASN1Codec(EnumElement):
    def register_stem(cls, stem):
        cls._stem = stem

    def register_tagging(cls, enc, dec):
        # Codec-level implicit/explicit tagging (BER/OER) or identity (UPER/PER).
        cls._tagging_enc = enc
        cls._tagging_dec = dec

    def tagging_enc(cls, s, **kwargs):
        return cls._tagging_enc(s, **kwargs)

    def tagging_dec(cls, s, **kwargs):
        return cls._tagging_dec(s, **kwargs)

    def dec(cls, s, context=None, _depth=0):
        return cls._stem.dec(s, context=context, _depth=_depth)

    def safedec(cls, s, context=None, _depth=0):
        return cls._stem.safedec(s, context=context, _depth=_depth)

    def get_stem(cls):
        return cls._stem


class ASN1_Codecs_metaclass(Enum_metaclass):
    element_class = ASN1Codec


class ASN1_Codecs(metaclass=ASN1_Codecs_metaclass):
    BER = cast(ASN1Codec, 1)
    DER = cast(ASN1Codec, 2)
    PER = cast(ASN1Codec, 3)
    CER = cast(ASN1Codec, 4)
    LWER = cast(ASN1Codec, 5)
    BACnet = cast(ASN1Codec, 6)
    OER = cast(ASN1Codec, 7)
    SER = cast(ASN1Codec, 8)
    XER = cast(ASN1Codec, 9)


class ASN1Tag(EnumElement):
    def __init__(self,
                 key,
                 value,
                 context=None,
                 codec=None
                 ):
        EnumElement.__init__(self, key, value)
        # populated by the metaclass
        self.context = context
        if codec is None:
            codec = {}
        self._codec = codec

    def clone(self):  # not a real deep copy. self.codec is shared
        return self.__class__(self._key, self._value, self.context, self._codec)

    def register_asn1_object(self, asn1obj):
        self._asn1_obj = asn1obj

    def asn1_object(self, val):
        if hasattr(self, "_asn1_obj"):
            return self._asn1_obj(val)
        raise ASN1_Error("%r does not have any assigned ASN1 object" % self)

    def register(self, codecnum, codec):
        self._codec[codecnum] = codec

    def get_codec(self, codec):
        try:
            c = self._codec[codec]
        except KeyError:
            raise ASN1_Error("Codec %r not found for tag %r" % (codec, self))
        return c


class ASN1_Class_metaclass(Enum_metaclass):
    element_class = ASN1Tag

    # XXX factorise a bit with Enum_metaclass.__new__()
    def __new__(cls,
                name,
                bases,
                dct
                ):
        for b in bases:
            for k, v in b.__dict__.items():
                if k not in dct and isinstance(v, ASN1Tag):
                    dct[k] = v.clone()

        rdict = {}
        for k, v in dct.items():
            if isinstance(v, int):
                v = ASN1Tag(k, v)
                dct[k] = v
                rdict[v] = v
            elif isinstance(v, ASN1Tag):
                rdict[v] = v
        dct["__rdict__"] = rdict

        ncls = cast('Type[ASN1_Class]',
                    type.__new__(cls, name, bases, dct))
        for v in ncls.__dict__.values():
            if isinstance(v, ASN1Tag):
                # overwrite ASN1Tag contexts, even cloned ones
                v.context = ncls
        return ncls


class ASN1_Class(metaclass=ASN1_Class_metaclass):
    pass


class ASN1_Class_UNIVERSAL(ASN1_Class):
    name = "UNIVERSAL"
    # Those casts are made so that MyPy understands what the
    # metaclass does in the background.
    ERROR = cast(ASN1Tag, -3)
    RAW = cast(ASN1Tag, -2)
    NONE = cast(ASN1Tag, -1)
    ANY = cast(ASN1Tag, 0)
    BOOLEAN = cast(ASN1Tag, 1)
    INTEGER = cast(ASN1Tag, 2)
    BIT_STRING = cast(ASN1Tag, 3)
    STRING = cast(ASN1Tag, 4)
    NULL = cast(ASN1Tag, 5)
    OID = cast(ASN1Tag, 6)
    OBJECT_DESCRIPTOR = cast(ASN1Tag, 7)
    EXTERNAL = cast(ASN1Tag, 8)
    REAL = cast(ASN1Tag, 9)
    ENUMERATED = cast(ASN1Tag, 10)
    EMBEDDED_PDF = cast(ASN1Tag, 11)
    UTF8_STRING = cast(ASN1Tag, 12)
    RELATIVE_OID = cast(ASN1Tag, 13)
    SEQUENCE = cast(ASN1Tag, 16 | 0x20)     # constructed encoding
    SET = cast(ASN1Tag, 17 | 0x20)          # constructed encoding
    NUMERIC_STRING = cast(ASN1Tag, 18)
    PRINTABLE_STRING = cast(ASN1Tag, 19)
    T61_STRING = cast(ASN1Tag, 20)          # aka TELETEX_STRING
    VIDEOTEX_STRING = cast(ASN1Tag, 21)
    IA5_STRING = cast(ASN1Tag, 22)
    UTC_TIME = cast(ASN1Tag, 23)
    GENERALIZED_TIME = cast(ASN1Tag, 24)
    GRAPHIC_STRING = cast(ASN1Tag, 25)
    ISO646_STRING = cast(ASN1Tag, 26)       # aka VISIBLE_STRING
    GENERAL_STRING = cast(ASN1Tag, 27)
    UNIVERSAL_STRING = cast(ASN1Tag, 28)
    CHAR_STRING = cast(ASN1Tag, 29)
    BMP_STRING = cast(ASN1Tag, 30)
    IPADDRESS = cast(ASN1Tag, 0 | 0x40)     # application-specific encoding
    COUNTER32 = cast(ASN1Tag, 1 | 0x40)     # application-specific encoding
    COUNTER64 = cast(ASN1Tag, 6 | 0x40)     # application-specific encoding
    GAUGE32 = cast(ASN1Tag, 2 | 0x40)       # application-specific encoding
    TIME_TICKS = cast(ASN1Tag, 3 | 0x40)    # application-specific encoding


class ASN1_Object_metaclass(type):
    def __new__(cls,
                name,
                bases,
                dct
                ):
        c = cast(
            'Type[ASN1_Object[Any]]',
            super(ASN1_Object_metaclass, cls).__new__(cls, name, bases, dct)
        )
        try:
            c.tag.register_asn1_object(c)
        except Exception:
            warning("Error registering %r" % c.tag)
        return c


_K = TypeVar('_K')


class ASN1_Object(Generic[_K], metaclass=ASN1_Object_metaclass):
    tag = ASN1_Class_UNIVERSAL.ANY

    def __init__(self, val):
        self.val = val

    def enc(self, codec):
        return self.tag.get_codec(codec).enc(self.val)

    def __repr__(self):
        return "<%s[%r]>" % (self.__dict__.get("name", self.__class__.__name__), self.val)

    def __str__(self):
        return plain_str(self.enc(conf.ASN1_default_codec))

    def __bytes__(self):
        return self.enc(conf.ASN1_default_codec)

    def strshow(self, lvl=0):
        return ("  " * lvl) + repr(self) + "\n"

    def show(self, lvl=0):
        print(self.strshow(lvl))

    def __eq__(self, other):
        return bool(self.val == other)

    def __lt__(self, other):
        return bool(self.val < other)

    def __le__(self, other):
        return bool(self.val <= other)

    def __gt__(self, other):
        return bool(self.val > other)

    def __ge__(self, other):
        return bool(self.val >= other)

    def __ne__(self, other):
        return bool(self.val != other)

    def command(self, json=False):
        if json:
            if isinstance(self.val, bytes):
                val = self.val.decode("utf-8", errors="backslashreplace")
            else:
                val = repr(self.val)
            return {"type": self.__class__.__name__, "value": val}
        else:
            return "%s(%s)" % (self.__class__.__name__, repr(self.val))


#######################
#     ASN1 objects    #
#######################

# on the whole, we order the classes by ASN1_Class_UNIVERSAL tag value

class _ASN1_ERROR(ASN1_Object[Union[bytes, ASN1_Object[Any]]]):
    pass


class ASN1_DECODING_ERROR(_ASN1_ERROR):
    tag = ASN1_Class_UNIVERSAL.ERROR

    def __init__(self, val, exc=None):
        ASN1_Object.__init__(self, val)
        self.exc = exc

    def __repr__(self):
        return "<%s[%r]{{%r}}>" % (
            self.__dict__.get("name", self.__class__.__name__),
            self.val,
            self.exc and self.exc.args[0] or ""
        )

    def enc(self, codec):
        if isinstance(self.val, ASN1_Object):
            return self.val.enc(codec)
        return self.val


class ASN1_force(_ASN1_ERROR):
    tag = ASN1_Class_UNIVERSAL.RAW

    def enc(self, codec):
        if isinstance(self.val, ASN1_Object):
            return self.val.enc(codec)
        return self.val


class ASN1_BADTAG(ASN1_force):
    pass


class ASN1_INTEGER(ASN1_Object[int]):
    tag = ASN1_Class_UNIVERSAL.INTEGER

    def __repr__(self):
        h = hex(self.val)
        if h[-1] == "L":
            h = h[:-1]
        # cut at 22 because with leading '0x', x509 serials should be < 23
        if len(h) > 22:
            h = h[:12] + "..." + h[-10:]
        r = repr(self.val)
        if len(r) > 20:
            r = r[:10] + "..." + r[-10:]
        return h + " <%s[%s]>" % (self.__dict__.get("name", self.__class__.__name__), r)


class ASN1_BOOLEAN(ASN1_INTEGER):
    tag = ASN1_Class_UNIVERSAL.BOOLEAN
    # BER: 0 means False, anything else means True

    def __repr__(self):
        return '%s %s' % (not (self.val == 0), ASN1_Object.__repr__(self))


class ASN1_BIT_STRING(ASN1_Object[str]):
    """
     ASN1_BIT_STRING values are bit strings like "011101".
     A zero-bit padded readable string is provided nonetheless,
     which is stored in val_readable
    """
    tag = ASN1_Class_UNIVERSAL.BIT_STRING

    def __init__(self, val, readable=False):
        if not readable:
            self.val = cast(str, val)
        else:
            self.val_readable = cast(bytes, val)

    def __setattr__(self, name, value):
        if name == "val_readable":
            if isinstance(value, bytes):
                val = "".join(binrepr(x).zfill(8) for x in value)
            else:
                warning("Invalid val: should be bytes")
                val = "<invalid val_readable>"
            object.__setattr__(self, "val", val)
            object.__setattr__(self, name, bytes_encode(value))
            object.__setattr__(self, "unused_bits", 0)
        elif name == "val":
            value = plain_str(value)
            if isinstance(value, str):
                if any(c for c in value if c not in ["0", "1"]):
                    warning("Invalid operation: 'val' is not a valid bit string.")
                    return
                else:
                    if len(value) % 8 == 0:
                        unused_bits = 0
                    else:
                        unused_bits = 8 - (len(value) % 8)
                    padded_value = value + ("0" * unused_bits)
                    bytes_arr = zip(*[iter(padded_value)] * 8)
                    val_readable = b"".join(chb(int("".join(x), 2)) for x in bytes_arr)
            else:
                warning("Invalid val: should be str")
                val_readable = b"<invalid val>"
                unused_bits = 0
            object.__setattr__(self, "val_readable", val_readable)
            object.__setattr__(self, name, value)
            object.__setattr__(self, "unused_bits", unused_bits)
        elif name == "unused_bits":
            warning("Invalid operation: unused_bits rewriting "
                    "is not supported.")
        else:
            object.__setattr__(self, name, value)

    def set(self, i, val):
        """
        Sets bit 'i' to value 'val' (starting from 0)
        """
        val = str(val)
        assert val in ['0', '1']
        if len(self.val) < i:
            self.val += "0" * (i - len(self.val))
        self.val = self.val[:i] + val + self.val[i + 1:]

    def __repr__(self):
        s = self.val_readable
        if len(s) > 16:
            s = s[:10] + b"..." + s[-10:]
        v = self.val
        if len(v) > 20:
            v = v[:10] + "..." + v[-10:]
        return "<%s[%s]=%r (%d unused bit%s)>" % (
            self.__dict__.get("name", self.__class__.__name__),
            v,
            s,
            self.unused_bits,
            "s" if self.unused_bits > 1 else ""
        )


class ASN1_STRING(ASN1_Object[bytes]):
    tag = ASN1_Class_UNIVERSAL.STRING


class ASN1_NULL(ASN1_Object[None]):
    tag = ASN1_Class_UNIVERSAL.NULL

    def __repr__(self):
        return ASN1_Object.__repr__(self)


class ASN1_OID(ASN1_Object[str]):
    tag = ASN1_Class_UNIVERSAL.OID

    def __init__(self, val):
        val = plain_str(val)
        val = conf.mib._oid(val)
        ASN1_Object.__init__(self, val)
        self.oidname = conf.mib._oidname(val)

    def __repr__(self):
        return "<%s[%r]>" % (self.__dict__.get("name", self.__class__.__name__), self.oidname)


class ASN1_ENUMERATED(ASN1_INTEGER):
    tag = ASN1_Class_UNIVERSAL.ENUMERATED


class ASN1_UTF8_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.UTF8_STRING


class ASN1_NUMERIC_STRING(ASN1_Object[str]):
    tag = ASN1_Class_UNIVERSAL.NUMERIC_STRING


class ASN1_PRINTABLE_STRING(ASN1_Object[str]):
    tag = ASN1_Class_UNIVERSAL.PRINTABLE_STRING


class ASN1_T61_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.T61_STRING


class ASN1_VIDEOTEX_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.VIDEOTEX_STRING


class ASN1_IA5_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.IA5_STRING


class ASN1_GENERAL_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.GENERAL_STRING


class ASN1_GENERALIZED_TIME(ASN1_Object[str]):
    """
    Improved version of ASN1_GENERALIZED_TIME, properly handling time zones and
    all string representation formats defined by ASN.1. These are:

    1. Local time only:                        YYYYMMDDHH[MM[SS[.fff]]]
    2. Universal time (UTC time) only:         YYYYMMDDHH[MM[SS[.fff]]]Z
    3. Difference between local and UTC times: YYYYMMDDHH[MM[SS[.fff]]]+-HHMM

    It also handles ASN1_UTC_TIME, which allows:

    1. Universal time (UTC time) only:         YYMMDDHHMM[SS[.fff]]Z
    2. Difference between local and UTC times: YYMMDDHHMM[SS[.fff]]+-HHMM

    Note the differences: Year is only two digits, minutes are not optional and
    there is no milliseconds.
    """
    tag = ASN1_Class_UNIVERSAL.GENERALIZED_TIME
    pretty_time = None

    def __init__(self, val):
        if isinstance(val, datetime):
            self.__setattr__("datetime", val)
        else:
            super(ASN1_GENERALIZED_TIME, self).__init__(val)

    def __setattr__(self, name, value):
        if isinstance(value, bytes):
            value = plain_str(value)

        if name == "val":
            formats = {
                10: "%Y%m%d%H",
                12: "%Y%m%d%H%M",
                14: "%Y%m%d%H%M%S"
            }
            dt = None
            try:
                if value[-1] == "Z":
                    str, ofs = value[:-1], value[-1:]
                elif value[-5] in ("+", "-"):
                    str, ofs = value[:-5], value[-5:]
                elif isinstance(self, ASN1_UTC_TIME):
                    raise ValueError()
                else:
                    str, ofs = value, ""

                if isinstance(self, ASN1_UTC_TIME) and len(str) >= 10:
                    fmt = "%y" + formats[len(str) + 2][2:]
                elif str[-4] == ".":
                    fmt = formats[len(str) - 4] + ".%f"
                else:
                    fmt = formats[len(str)]

                dt = datetime.strptime(str, fmt)
                if ofs == 'Z':
                    dt = dt.replace(tzinfo=timezone.utc)
                elif ofs:
                    sign = -1 if ofs[0] == "-" else 1
                    ofs = datetime.strptime(ofs[1:], "%H%M")
                    delta = timedelta(hours=ofs.hour * sign,
                                      minutes=ofs.minute * sign)
                    dt = dt.replace(tzinfo=timezone(delta))
            except Exception:
                dt = None

            pretty_time = None
            if dt is None:
                _nam = self.tag._asn1_obj.__name__[5:]
                _nam = _nam.lower().replace("_", " ")
                pretty_time = "%s [invalid %s]" % (value, _nam)
            else:
                pretty_time = dt.strftime("%Y-%m-%d %H:%M:%S")
                if dt.microsecond:
                    pretty_time += dt.strftime(".%f")[:4]
                if dt.tzinfo == timezone.utc:
                    pretty_time += dt.strftime(" UTC")
                elif dt.tzinfo is not None:
                    if dt.tzinfo.utcoffset(dt) is not None:
                        pretty_time += dt.strftime(" %z")

            ASN1_STRING.__setattr__(self, "pretty_time", pretty_time)
            ASN1_STRING.__setattr__(self, "datetime", dt)
            ASN1_STRING.__setattr__(self, name, value)
        elif name == "pretty_time":
            print("Invalid operation: pretty_time rewriting is not supported.")
        elif name == "datetime":
            ASN1_STRING.__setattr__(self, name, value)
            if isinstance(value, datetime):
                yfmt = "%y" if isinstance(self, ASN1_UTC_TIME) else "%Y"
                if value.microsecond:
                    str = value.strftime(yfmt + "%m%d%H%M%S.%f")[:-3]
                else:
                    str = value.strftime(yfmt + "%m%d%H%M%S")

                if value.tzinfo == timezone.utc:
                    str = str + "Z"
                else:
                    str = str + value.strftime("%z")  # empty if naive

                ASN1_STRING.__setattr__(self, "val", str)
            else:
                ASN1_STRING.__setattr__(self, "val", None)
        else:
            ASN1_STRING.__setattr__(self, name, value)

    def __repr__(self):
        return "%s %s" % (
            self.pretty_time,
            super(ASN1_GENERALIZED_TIME, self).__repr__()
        )


class ASN1_UTC_TIME(ASN1_GENERALIZED_TIME):
    tag = ASN1_Class_UNIVERSAL.UTC_TIME


class ASN1_ISO646_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.ISO646_STRING


class ASN1_UNIVERSAL_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.UNIVERSAL_STRING


class ASN1_BMP_STRING(ASN1_STRING):
    tag = ASN1_Class_UNIVERSAL.BMP_STRING

    def __setattr__(self, name, value):
        if name == "val":
            if isinstance(value, str):
                value = value.encode("utf-16be")
            object.__setattr__(self, name, value)
        else:
            object.__setattr__(self, name, value)

    def __repr__(self):
        return "<%s[%r]>" % (
            self.__dict__.get("name", self.__class__.__name__),
            self.val.decode("utf-16be"),
        )


class ASN1_SEQUENCE(ASN1_Object[List[Any]]):
    tag = ASN1_Class_UNIVERSAL.SEQUENCE

    def strshow(self, lvl=0):
        s = ("  " * lvl) + ("# %s:" % self.__class__.__name__) + "\n"
        for o in self.val:
            s += o.strshow(lvl=lvl + 1)
        return s


class ASN1_SET(ASN1_SEQUENCE):
    tag = ASN1_Class_UNIVERSAL.SET


class ASN1_IPADDRESS(ASN1_Object[str]):
    tag = ASN1_Class_UNIVERSAL.IPADDRESS


class ASN1_COUNTER32(ASN1_INTEGER):
    tag = ASN1_Class_UNIVERSAL.COUNTER32


class ASN1_COUNTER64(ASN1_INTEGER):
    tag = ASN1_Class_UNIVERSAL.COUNTER64


class ASN1_GAUGE32(ASN1_INTEGER):
    tag = ASN1_Class_UNIVERSAL.GAUGE32


class ASN1_TIME_TICKS(ASN1_INTEGER):
    tag = ASN1_Class_UNIVERSAL.TIME_TICKS


conf.ASN1_default_codec = ASN1_Codecs.BER
