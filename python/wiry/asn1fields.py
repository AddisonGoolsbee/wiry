# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from scapy: scapy/asn1fields.py
#   scapy master, upstream commit e2e35c0
#   Copyright (C) Philippe Biondi <phil@secdev.org>
#   Acknowledgment: Maxence Tury <maxence.tury@ssi.gouv.fr>
#
# Changed by the wiry authors:
#   2026-10-03 — transcribed; a SEQUENCE OF slices each element once instead
#     of re-copying the remainder after every one.
"""ASN.1 fields: how an `ASN1_Packet` maps its values to BER and back."""

import copy

from functools import reduce

from .asn1.asn1 import (
    ASN1_BIT_STRING,
    ASN1_BOOLEAN,
    ASN1_Class,
    ASN1_Class_UNIVERSAL,
    ASN1_Decoding_Error,
    ASN1_Error,
    ASN1_INTEGER,
    ASN1_NULL,
    ASN1_OID,
    ASN1_Object,
    ASN1_STRING,
    GeneralizedTime,
    PyRandChoice as RandChoice,
    PyRandNum as RandNum,
    PyRandString as RandString,
    RandOID,
)
from .asn1.ber import (
    BER_Decoding_Error,
    BER_id_dec,
    Elements,
)
from ._pylayer import PyPacket, PyRaw, fuzz as _fuzz

from typing import (
    Any,
    AnyStr,
    Callable,
    Dict,
    Generic,
    List,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from .asn1packet import ASN1_Packet


class ASN1F_badsequence(Exception):
    pass


class ASN1F_element(object):
    pass


##########################
#    Basic ASN1 Field    #
##########################

_I = TypeVar('_I')
_A = TypeVar('_A')


class ASN1F_field(ASN1F_element, Generic[_I, _A]):
    holds_packets = 0
    islist = 0
    ASN1_tag = ASN1_Class_UNIVERSAL.ANY
    context = ASN1_Class_UNIVERSAL

    def __init__(self,
                 name,
                 default,
                 context=None,
                 implicit_tag=None,
                 explicit_tag=None,
                 flexible_tag=False,
                 size_len=None,
                 ):
        if context is not None:
            self.context = context
        self.name = name
        if default is None:
            self.default = default
        elif isinstance(default, ASN1_NULL):
            self.default = default
        else:
            self.default = self.ASN1_tag.asn1_object(default)
        self.size_len = size_len
        self.flexible_tag = flexible_tag
        if (implicit_tag is not None) and (explicit_tag is not None):
            err_msg = "field cannot be both implicitly and explicitly tagged"
            raise ASN1_Error(err_msg)
        self.implicit_tag = implicit_tag and int(implicit_tag)
        self.explicit_tag = explicit_tag and int(explicit_tag)
        # The tag a CHOICE dispatches on.
        self.network_tag = int(implicit_tag or explicit_tag or self.ASN1_tag)
        self.owners = []

    def register_owner(self, cls):
        self.owners.append(cls)

    def _apply_diff_tag(self, diff_tag):
        # Only a flexible_tag field sees a tag other than its own.
        if diff_tag is not None:
            if self.implicit_tag is not None:
                self.implicit_tag = diff_tag
            elif self.explicit_tag is not None:
                self.explicit_tag = diff_tag

    def _tagging_dec(self, pkt, s, **kwargs):
        return pkt.ASN1_codec.tagging_dec(s, **kwargs)

    def _tagging_enc(self, pkt, s, **kwargs):
        return pkt.ASN1_codec.tagging_enc(s, **kwargs)

    def _apply_tagging_dec(self, s, pkt, hidden_tag=None, **kwargs):
        if hidden_tag is None:
            hidden_tag = self.ASN1_tag
        diff_tag, s = self._tagging_dec(
            pkt, s,
            hidden_tag=hidden_tag,
            implicit_tag=self.implicit_tag,
            explicit_tag=self.explicit_tag,
            safe=self.flexible_tag,
            **kwargs,
        )
        self._apply_diff_tag(diff_tag)
        return s

    def _codec_kwargs(self, pkt):
        # A codec with per-field constraints (OER, UPER) overrides this.
        return {"size_len": self.size_len}

    def _use_object_enc(self, pkt, item):
        # A fixed length size has to go through the codec, which takes it.
        return self.size_len is None

    def _encode_item(self, pkt, item):
        """Encode a field value with codec kwargs, without field tagging."""
        if item is None:
            return b""
        if isinstance(item, ASN1_Object):
            if (self.ASN1_tag == ASN1_Class_UNIVERSAL.ANY or
                    item.tag == ASN1_Class_UNIVERSAL.RAW or
                    item.tag == ASN1_Class_UNIVERSAL.ERROR):
                return item.enc(pkt.ASN1_codec)
            if self.ASN1_tag != item.tag:
                raise ASN1_Error(
                    "Encoding Error: got %r instead of an %r for field [%s]" %
                    (item, self.ASN1_tag, self.name)
                )
            if self._use_object_enc(pkt, item):
                return item.enc(pkt.ASN1_codec)
            item = item.val
        elif hasattr(item, "self_build"):
            # A packet value still gets this field's own tag and length.
            item = item.self_build()
        codec = self.ASN1_tag.get_codec(pkt.ASN1_codec)
        return codec.enc(item, **self._codec_kwargs(pkt))

    def i2repr(self, pkt, x):
        return repr(x)

    def i2h(self, pkt, x):
        return x

    def m2i(self, pkt, s):
        """With `flexible_tag`, a value under the wrong tag decodes anyway,
        wrapped in ASN1_BADTAG. That swallows the error ASN1F_optional needs to
        see a field is absent, so an optional field is never flexible, and
        neither is any other by default."""
        s = self._apply_tagging_dec(s, pkt, _fname=self.name)
        codec = self.ASN1_tag.get_codec(pkt.ASN1_codec)
        dec = codec.safedec if self.flexible_tag else codec.dec
        return dec(s, context=self.context, **self._codec_kwargs(pkt))

    def i2m(self, pkt, x):
        if x is None:
            return b""
        s = self._encode_item(pkt, x)
        return self._tagging_enc(
            pkt, s,
            implicit_tag=self.implicit_tag,
            explicit_tag=self.explicit_tag,
        )

    def any2i(self, pkt, x):
        return cast(_I, x)

    def extract_packet(self,
                       cls,
                       s,
                       _underlayer=None
                       ):
        try:
            c = cls(s, _underlayer=_underlayer)
        except ASN1F_badsequence:
            c = PyRaw(s, _underlayer=_underlayer)
        cpad = c.getlayer(PyRaw)
        s = b""
        if cpad is not None:
            s = cpad.load
            if cpad.underlayer:
                del cpad.underlayer.payload
        return c, s

    def build(self, pkt):
        return self.i2m(pkt, getattr(pkt, self.name))

    def dissect(self, pkt, s):
        v, s = self.m2i(pkt, s)
        self.set_val(pkt, v)
        return s

    def do_copy(self, x):
        if isinstance(x, list):
            x = x[:]
            for i in range(len(x)):
                if isinstance(x[i], PyPacket):
                    x[i] = x[i].copy()
            return x
        if hasattr(x, "copy"):
            return x.copy()
        return x

    def set_val(self, pkt, val):
        setattr(pkt, self.name, val)

    def is_empty(self, pkt):
        return getattr(pkt, self.name) is None

    def get_fields_list(self):
        return [self]

    def __str__(self):
        return repr(self)

    def randval(self):
        return RandNum(0, 2**32 - 1)

    def copy(self):
        return copy.copy(self)


############################
#    Simple ASN1 Fields    #
############################

class ASN1F_BOOLEAN(ASN1F_field[bool, ASN1_BOOLEAN]):
    ASN1_tag = ASN1_Class_UNIVERSAL.BOOLEAN

    def randval(self):
        return RandChoice(True, False)


class ASN1F_INTEGER(ASN1F_field[int, ASN1_INTEGER]):
    ASN1_tag = ASN1_Class_UNIVERSAL.INTEGER

    def randval(self):
        return RandNum(-2**64, 2**64 - 1)


class ASN1F_enum_INTEGER(ASN1F_INTEGER):
    def __init__(self,
                 name,
                 default,
                 enum,
                 context=None,
                 implicit_tag=None,
                 explicit_tag=None,
                 ):
        super(ASN1F_enum_INTEGER, self).__init__(
            name, default, context=context,
            implicit_tag=implicit_tag,
            explicit_tag=explicit_tag
        )
        i2s = self.i2s = {}
        s2i = self.s2i = {}
        if isinstance(enum, list):
            keys = range(len(enum))
        else:
            keys = list(enum)
        if any(isinstance(x, str) for x in keys):
            i2s, s2i = s2i, i2s
        for k in keys:
            i2s[k] = enum[k]
            s2i[enum[k]] = k

    def i2m(self,
            pkt,
            s,
            ):
        if not isinstance(s, str):
            vs = s
        else:
            vs = self.s2i[s]
        return super(ASN1F_enum_INTEGER, self).i2m(pkt, vs)

    def i2repr(self,
               pkt,
               x,
               ):
        if x is not None and isinstance(x, ASN1_INTEGER):
            r = self.i2s.get(x.val)
            if r:
                return "'%s' %s" % (r, repr(x))
        return repr(x)


class ASN1F_BIT_STRING(ASN1F_field[str, ASN1_BIT_STRING]):
    ASN1_tag = ASN1_Class_UNIVERSAL.BIT_STRING

    def __init__(self,
                 name,
                 default,
                 default_readable=True,
                 context=None,
                 implicit_tag=None,
                 explicit_tag=None,
                 ):
        super(ASN1F_BIT_STRING, self).__init__(
            name, None, context=context,
            implicit_tag=implicit_tag,
            explicit_tag=explicit_tag
        )
        if isinstance(default, (bytes, str)):
            self.default = ASN1_BIT_STRING(default,
                                           readable=default_readable)
        else:
            self.default = default

    def randval(self):
        return RandString(RandNum(0, 1000))


class ASN1F_STRING(ASN1F_field[str, ASN1_STRING]):
    ASN1_tag = ASN1_Class_UNIVERSAL.STRING

    def randval(self):
        return RandString(RandNum(0, 1000))


class ASN1F_NULL(ASN1F_INTEGER):
    ASN1_tag = ASN1_Class_UNIVERSAL.NULL


class ASN1F_OID(ASN1F_field[str, ASN1_OID]):
    ASN1_tag = ASN1_Class_UNIVERSAL.OID

    def randval(self):
        return RandOID()


class ASN1F_ENUMERATED(ASN1F_enum_INTEGER):
    ASN1_tag = ASN1_Class_UNIVERSAL.ENUMERATED


class ASN1F_UTF8_STRING(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.UTF8_STRING


class ASN1F_NUMERIC_STRING(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.NUMERIC_STRING


class ASN1F_PRINTABLE_STRING(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.PRINTABLE_STRING


class ASN1F_T61_STRING(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.T61_STRING


class ASN1F_VIDEOTEX_STRING(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.VIDEOTEX_STRING


class ASN1F_IA5_STRING(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.IA5_STRING


class ASN1F_GENERAL_STRING(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.GENERAL_STRING


class ASN1F_UTC_TIME(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.UTC_TIME

    def randval(self):
        return GeneralizedTime()


class ASN1F_GENERALIZED_TIME(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.GENERALIZED_TIME

    def randval(self):
        return GeneralizedTime()


class ASN1F_ISO646_STRING(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.ISO646_STRING


class ASN1F_UNIVERSAL_STRING(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.UNIVERSAL_STRING


class ASN1F_BMP_STRING(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.BMP_STRING


class ASN1F_SEQUENCE(ASN1F_field[List[Any], List[Any]]):
    # explicit_tag=0 with flexible_tag=True takes a SEQUENCE under any outer
    # tag, an unknown private high tag included (x509's ASN1P_PRIVSEQ).
    ASN1_tag = ASN1_Class_UNIVERSAL.SEQUENCE
    holds_packets = 1

    def __init__(self, *seq, **kwargs):
        name = "dummy_seq_name"
        default = [field.default for field in seq]
        super(ASN1F_SEQUENCE, self).__init__(
            name, default, **kwargs
        )
        self.seq = seq
        self.islist = len(seq) > 1

    def __repr__(self):
        return "<%s%r>" % (self.__class__.__name__, self.seq)

    def is_empty(self, pkt):
        return all(f.is_empty(pkt) for f in self.seq)

    def get_fields_list(self):
        return reduce(lambda x, y: x + y.get_fields_list(),
                      self.seq, [])

    def m2i(self, pkt, s):
        """Dissect each member into `pkt` itself. The value returned is an
        empty list; only the remainder means anything."""
        s = self._apply_tagging_dec(s, pkt, _fname=pkt.name)
        codec = self.ASN1_tag.get_codec(pkt.ASN1_codec)
        i, s, remain = codec.check_type_check_len(s)
        if len(s) == 0:
            for obj in self.seq:
                obj.set_val(pkt, None)
        else:
            for obj in self.seq:
                try:
                    s = obj.dissect(pkt, s)
                except ASN1F_badsequence:
                    break
            if len(s) > 0:
                raise BER_Decoding_Error(
                    "unexpected remainder in %s" % pkt.name,
                    remaining=s,
                )
        return [], remain

    def dissect(self, pkt, s):
        _, x = self.m2i(pkt, s)
        return x

    def build(self, pkt):
        s = reduce(lambda x, y: x + y.build(pkt),
                   self.seq, b"")
        return super(ASN1F_SEQUENCE, self).i2m(pkt, s)


class ASN1F_SET(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_UNIVERSAL.SET


_SEQ_T = Union[
    'ASN1_Packet',
    Type[ASN1F_field[Any, Any]],
    'ASN1F_PACKET',
    ASN1F_field[Any, Any],
]


class ASN1F_SEQUENCE_OF(ASN1F_field[List[_SEQ_T],
                                    List[ASN1_Object[Any]]]):
    """`cls` is an ASN1_Packet class (or a callable making one) or an
    ASN1F_field, class or instance."""
    ASN1_tag = ASN1_Class_UNIVERSAL.SEQUENCE
    islist = 1

    def __init__(self,
                 name,
                 default,
                 cls,
                 context=None,
                 implicit_tag=None,
                 explicit_tag=None,
                 ):
        if isinstance(cls, type) and issubclass(cls, ASN1F_field) or \
                isinstance(cls, ASN1F_field):
            if isinstance(cls, type):
                self.fld = cls(name, b"")
            else:
                self.fld = cls
            self._extract_packet = lambda s, pkt: self.fld.m2i(pkt, s)
            self.holds_packets = 0
        elif hasattr(cls, "ASN1_root") or callable(cls):
            self.cls = cast("Type[ASN1_Packet]", cls)
            self._extract_packet = lambda s, pkt: self.extract_packet(
                self.cls, s, _underlayer=pkt)
            self.holds_packets = 1
        else:
            raise ValueError("cls should be an ASN1_Packet or ASN1_field")
        super(ASN1F_SEQUENCE_OF, self).__init__(
            name, None, context=context,
            implicit_tag=implicit_tag, explicit_tag=explicit_tag
        )
        self.default = default

    def is_empty(self,
                 pkt,
                 ):
        return ASN1F_field.is_empty(self, pkt)

    def m2i(self,
            pkt,
            s,
            ):
        s = self._apply_tagging_dec(s, pkt)
        codec = self.ASN1_tag.get_codec(pkt.ASN1_codec)
        i, s, remain = codec.check_type_check_len(s)
        lst = []
        elts = Elements(s)
        for elt in elts:
            c, left = self._extract_packet(elt, pkt)
            if c:
                lst.append(c)
            elts.leftover(left)
        return lst, remain

    def build(self, pkt):
        val = getattr(pkt, self.name)
        if isinstance(val, ASN1_Object) and \
                val.tag == ASN1_Class_UNIVERSAL.RAW:
            s = cast(Union[List[_SEQ_T], bytes], val)
        elif val is None:
            s = b""
        elif self.holds_packets:
            s = b"".join(bytes(i) for i in val)
        else:
            # Through the element field's i2m, so its own tags are written.
            s = b"".join(self.fld.i2m(pkt, i) for i in val)
        return self.i2m(pkt, s)

    def i2repr(self, pkt, x):
        if self.holds_packets:
            return super(ASN1F_SEQUENCE_OF, self).i2repr(pkt, x)
        elif x is None:
            return "[]"
        else:
            return "[%s]" % ", ".join(
                self.fld.i2repr(pkt, x) for x in x
            )

    def randval(self):
        if self.holds_packets:
            return _fuzz(self.cls())
        else:
            return self.fld.randval()

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, self.name)


class ASN1F_SET_OF(ASN1F_SEQUENCE_OF):
    ASN1_tag = ASN1_Class_UNIVERSAL.SET


class ASN1F_IPADDRESS(ASN1F_STRING):
    ASN1_tag = ASN1_Class_UNIVERSAL.IPADDRESS


class ASN1F_TIME_TICKS(ASN1F_INTEGER):
    ASN1_tag = ASN1_Class_UNIVERSAL.TIME_TICKS


#############################
#    Complex ASN1 Fields    #
#############################

class ASN1F_optional(ASN1F_element):
    """An OPTIONAL member: absent when its field fails to decode here."""
    def __init__(self, field):
        field.flexible_tag = False
        self._field = field

    def __getattr__(self, attr):
        return getattr(self._field, attr)

    def m2i(self, pkt, s):
        try:
            return self._field.m2i(pkt, s)
        except (ASN1_Error, ASN1F_badsequence, ASN1_Decoding_Error):
            # ASN1_Error is what a CHOICE with no matching tag raises.
            return None, s

    def dissect(self, pkt, s):
        try:
            return self._field.dissect(pkt, s)
        except (ASN1_Error, ASN1F_badsequence, ASN1_Decoding_Error):
            self._field.set_val(pkt, None)
            return s

    def build(self, pkt):
        if self._field.is_empty(pkt):
            return b""
        return self._field.build(pkt)

    def any2i(self, pkt, x):
        return self._field.any2i(pkt, x)

    def i2repr(self, pkt, x):
        return self._field.i2repr(pkt, x)


class ASN1F_omit(ASN1F_field[None, None]):
    """A field with no encoding at all, unlike ASN1F_NULL, which has one."""
    def m2i(self, pkt, s):
        return None, s

    def i2m(self, pkt, x):
        return b""


_CHOICE_T = Union['ASN1_Packet', Type[ASN1F_field[Any, Any]], 'ASN1F_PACKET']


class ASN1F_CHOICE(ASN1F_field[_CHOICE_T, ASN1_Object[Any]]):
    """Alternatives are ASN1_Packet classes, ASN1F_field classes, or
    ASN1F_PACKET instances; no other field instance."""
    holds_packets = 1
    ASN1_tag = ASN1_Class_UNIVERSAL.ANY

    def __init__(self, name, default, *args, **kwargs):
        if "implicit_tag" in kwargs:
            err_msg = "ASN1F_CHOICE has been called with an implicit_tag"
            raise ASN1_Error(err_msg)
        self.implicit_tag = None
        for kwarg in ["context", "explicit_tag"]:
            setattr(self, kwarg, kwargs.get(kwarg))
        super(ASN1F_CHOICE, self).__init__(
            name, None, context=self.context,
            explicit_tag=self.explicit_tag
        )
        self.default = default
        self.current_choice = None
        self.choices = {}
        self.pktchoices = {}
        for p in args:
            if hasattr(p, "ASN1_root"):
                p = cast('ASN1_Packet', p)
                if hasattr(p.ASN1_root, "choices"):
                    root = cast(ASN1F_CHOICE, p.ASN1_root)
                    for k, v in root.choices.items():
                        # A CHOICE of CHOICEs flattens into one.
                        self.choices[k] = v
                else:
                    self.choices[p.ASN1_root.network_tag] = p
            elif hasattr(p, "ASN1_tag"):
                if isinstance(p, type):
                    self.choices[int(p.ASN1_tag)] = p
                else:
                    self.choices[p.network_tag] = p
                    self.pktchoices[hash(p.cls)] = (p.implicit_tag, p.explicit_tag)
            else:
                raise ASN1_Error("ASN1F_CHOICE: no tag found for one field")

    def m2i(self, pkt, s):
        """Pick the alternative by the tag ahead, then decode it."""
        if len(s) == 0:
            raise ASN1_Error("ASN1F_CHOICE: got empty string")
        s = self._apply_tagging_dec(s, pkt)
        tag, _ = BER_id_dec(s)
        if tag in self.choices:
            choice = self.choices[tag]
        else:
            if self.flexible_tag:
                choice = ASN1F_field
            else:
                raise ASN1_Error(
                    "ASN1F_CHOICE: unexpected field in '%s' "
                    "(tag %s not in possible tags %s)" % (
                        self.name, tag, list(self.choices.keys())
                    )
                )
        if hasattr(choice, "ASN1_root"):
            return self.extract_packet(choice, s, _underlayer=pkt)
        elif isinstance(choice, type):
            return choice(self.name, b"").m2i(pkt, s)
        else:
            return choice.m2i(pkt, s)

    def i2m(self, pkt, x):
        if x is None:
            s = b""
        else:
            # The packet's codec, where bytes(x) would take the default one.
            if isinstance(x, ASN1_Object):
                s = x.enc(pkt.ASN1_codec)
            else:
                s = bytes(x)
            if hash(type(x)) in self.pktchoices:
                imp, exp = self.pktchoices[hash(type(x))]
                s = self._tagging_enc(
                    pkt, s,
                    implicit_tag=imp,
                    explicit_tag=exp,
                )
        return self._tagging_enc(pkt, s, explicit_tag=self.explicit_tag)

    def randval(self):
        randchoices = []
        for p in self.choices.values():
            if hasattr(p, "ASN1_root"):
                randchoices.append(_fuzz(p()))
            elif hasattr(p, "ASN1_tag"):
                if isinstance(p, type):
                    randchoices.append(p("dummy", None).randval())
                else:
                    randchoices.append(p.randval())
        return RandChoice(*randchoices)


class ASN1F_PACKET(ASN1F_field['ASN1_Packet', Optional['ASN1_Packet']]):
    holds_packets = 1

    def __init__(self,
                 name,
                 default,
                 cls,
                 context=None,
                 implicit_tag=None,
                 explicit_tag=None,
                 next_cls_cb=None,
                 ):
        self.cls = cls
        self.next_cls_cb = next_cls_cb
        super(ASN1F_PACKET, self).__init__(
            name, None, context=context,
            implicit_tag=implicit_tag, explicit_tag=explicit_tag
        )
        if implicit_tag is None and explicit_tag is None and cls is not None:
            if cls.ASN1_root.ASN1_tag == ASN1_Class_UNIVERSAL.SEQUENCE:
                self.network_tag = 16 | 0x20
        self.default = default

    def m2i(self, pkt, s):
        if self.next_cls_cb:
            cls = self.next_cls_cb(pkt) or self.cls
        else:
            cls = self.cls
        if not hasattr(cls, "ASN1_root"):
            # A packet that is not ASN.1 brings its own framing.
            return self.extract_packet(cls, s, _underlayer=pkt)
        s = self._apply_tagging_dec(
            s, pkt,
            hidden_tag=cls.ASN1_root.ASN1_tag,
            _fname=self.name,
        )
        if not s:
            return None, s
        return self.extract_packet(cls, s, _underlayer=pkt)

    def i2m(self,
            pkt,
            x
            ):
        if x is None:
            s = b""
        elif isinstance(x, bytes):
            s = x
        elif isinstance(x, ASN1_Object):
            if x.val:
                s = bytes(x.val)
            else:
                s = b""
        else:
            s = bytes(x)
            if not hasattr(x, "ASN1_root"):
                # A packet that is not ASN.1 brings its own framing.
                return s
        return self._tagging_enc(
            pkt, s,
            implicit_tag=self.implicit_tag,
            explicit_tag=self.explicit_tag,
        )

    def any2i(self,
              pkt,
              x
              ):
        if hasattr(x, "add_underlayer"):
            x.add_underlayer(pkt)
        return super(ASN1F_PACKET, self).any2i(pkt, x)

    def randval(self):
        return _fuzz(self.cls())


class ASN1F_BIT_STRING_ENCAPS(ASN1F_BIT_STRING):
    """A packet carried inside a BIT STRING, whose unused-bits octet an
    explicit OCTET STRING tag could not express."""
    ASN1_tag = ASN1_Class_UNIVERSAL.BIT_STRING

    def __init__(self,
                 name,
                 default,
                 cls,
                 context=None,
                 implicit_tag=None,
                 explicit_tag=None,
                 ):
        self.cls = cls
        super(ASN1F_BIT_STRING_ENCAPS, self).__init__(
            name,
            default and bytes(default),
            context=context,
            implicit_tag=implicit_tag,
            explicit_tag=explicit_tag
        )

    def m2i(self, pkt, s):
        bit_string, remain = super(ASN1F_BIT_STRING_ENCAPS, self).m2i(pkt, s)
        if len(bit_string.val) % 8 != 0:
            raise BER_Decoding_Error("wrong bit string", remaining=s)
        if bit_string.val_readable:
            p, s = self.extract_packet(self.cls, bit_string.val_readable,
                                       _underlayer=pkt)
        else:
            return None, bit_string.val_readable
        if len(s) > 0:
            raise BER_Decoding_Error(
                "unexpected remainder in %s" % pkt.name,
                remaining=s,
            )
        return p, remain

    def i2m(self, pkt, x):
        if not isinstance(x, ASN1_BIT_STRING):
            x = ASN1_BIT_STRING(
                b"" if x is None else bytes(x),
                readable=True,
            )
        return super(ASN1F_BIT_STRING_ENCAPS, self).i2m(pkt, x)


class ASN1F_FLAGS(ASN1F_BIT_STRING):
    def __init__(self,
                 name,
                 default,
                 mapping,
                 context=None,
                 implicit_tag=None,
                 explicit_tag=None,
                 ):
        self.mapping = mapping
        super(ASN1F_FLAGS, self).__init__(
            name, default,
            default_readable=False,
            context=context,
            implicit_tag=implicit_tag,
            explicit_tag=explicit_tag
        )

    def any2i(self, pkt, x):
        if isinstance(x, str):
            if any(y not in ["0", "1"] for y in x):
                # Flag names joined with "+" become the bit string.
                value = ["0"] * len(self.mapping)
                for i in x.split("+"):
                    value[self.mapping.index(i)] = "1"
                x = "".join(value)
            x = ASN1_BIT_STRING(x)
        return super(ASN1F_FLAGS, self).any2i(pkt, x)

    def get_flags(self, pkt):
        fbytes = getattr(pkt, self.name).val
        return [self.mapping[i] for i, positional in enumerate(fbytes)
                if positional == '1' and i < len(self.mapping)]

    def i2repr(self, pkt, x):
        if x is not None:
            pretty_s = ", ".join(self.get_flags(pkt))
            return pretty_s + " " + repr(x)
        return repr(x)


class ASN1F_STRING_PacketField(ASN1F_STRING):
    """An OCTET STRING whose value may be a packet."""
    holds_packets = 1

    def i2m(self, pkt, val):
        if hasattr(val, "ASN1_root"):
            val = ASN1_STRING(bytes(val))
        return super(ASN1F_STRING_PacketField, self).i2m(pkt, val)

    def any2i(self, pkt, x):
        if hasattr(x, "add_underlayer"):
            x.add_underlayer(pkt)
        return super(ASN1F_STRING_PacketField, self).any2i(pkt, x)


class ASN1F_STRING_ENCAPS(ASN1F_STRING_PacketField):
    """An OCTET STRING whose content is one packet of class `cls`."""

    def __init__(self,
                 name,
                 default,
                 cls,
                 context=None,
                 implicit_tag=None,
                 explicit_tag=None,
                 ):
        self.cls = cls
        super(ASN1F_STRING_ENCAPS, self).__init__(
            name,
            default and bytes(default),
            context=context,
            implicit_tag=implicit_tag,
            explicit_tag=explicit_tag
        )

    def m2i(self, pkt, s):
        val = super(ASN1F_STRING_ENCAPS, self).m2i(pkt, s)
        return self.cls(val[0].val, _underlayer=pkt), val[1]
