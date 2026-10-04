# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from scapy: scapy/layers/ldap.py
#   scapy master, upstream commit e2e35c0
#   Copyright (C) Gabriel Potter <gabriel[]potter[]fr>
#
# Changed by the wiry authors:
#   2026-10-03 — transcribed the protocol (RFC 4511 messages, filters,
#     controls, CLDAP and the SASL buffer) onto wiry's ASN.1 model. The
#     client, the answering machine and the DC locator are not here, and SASL
#     credentials stay octets, as wiry has no GSSAPI layer.
"""LDAP (RFC 4511, RFC 1777) and CLDAP (RFC 1798).

To mimic Microsoft Windows LDAP packets, set `conf.ASN1_default_long_size = 4`.
"""

import struct
import uuid

from .. import bind_bottom_up, bind_layers
from .._pyfields import FieldLenField, StrLenField
from .._pylayer import PyPacket, PyRaw
from ..asn1.asn1 import (
    ASN1_BOOLEAN,
    ASN1_Class,
    ASN1_Codecs,
    ASN1_ENUMERATED,
    ASN1_INTEGER,
    ASN1_STRING,
)
from ..asn1.ber import (
    BER_Decoding_Error,
    BER_id_dec,
    BER_len_dec,
    BERcodec_STRING,
)
from ..asn1fields import (
    ASN1F_badsequence,
    ASN1F_BOOLEAN,
    ASN1F_CHOICE,
    ASN1F_ENUMERATED,
    ASN1F_FLAGS,
    ASN1F_INTEGER,
    ASN1F_NULL,
    ASN1F_optional,
    ASN1F_PACKET,
    ASN1F_SEQUENCE_OF,
    ASN1F_SEQUENCE,
    ASN1F_SET_OF,
    ASN1F_STRING_PacketField,
    ASN1F_STRING,
)
from ..asn1packet import ASN1_Packet
from .. import UDP


# Elements of protocol
# https://datatracker.ietf.org/doc/html/rfc1777#section-4

LDAPString = ASN1F_STRING
LDAPOID = ASN1F_STRING
LDAPDN = LDAPString
RelativeLDAPDN = LDAPString
AttributeType = LDAPString
AttributeValue = ASN1F_STRING
URI = LDAPString


class AttributeValueAssertion(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        AttributeType("attributeType", "organizationName"),
        AttributeValue("attributeValue", ""),
    )


class LDAPReferral(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = LDAPString("uri", "")


LDAPResult = (
    ASN1F_ENUMERATED(
        "resultCode",
        0,
        {
            0: "success",
            1: "operationsError",
            2: "protocolError",
            3: "timeLimitExceeded",
            4: "sizeLimitExceeded",
            5: "compareFalse",
            6: "compareTrue",
            7: "authMethodNotSupported",
            8: "strongAuthRequired",
            10: "referral",
            11: "adminLimitExceeded",
            14: "saslBindInProgress",
            16: "noSuchAttribute",
            17: "undefinedAttributeType",
            18: "inappropriateMatching",
            19: "constraintViolation",
            20: "attributeOrValueExists",
            21: "invalidAttributeSyntax",
            32: "noSuchObject",
            33: "aliasProblem",
            34: "invalidDNSyntax",
            35: "isLeaf",
            36: "aliasDereferencingProblem",
            48: "inappropriateAuthentication",
            49: "invalidCredentials",
            50: "insufficientAccessRights",
            51: "busy",
            52: "unavailable",
            53: "unwillingToPerform",
            54: "loopDetect",
            64: "namingViolation",
            65: "objectClassViolation",
            66: "notAllowedOnNonLeaf",
            67: "notAllowedOnRDN",
            68: "entryAlreadyExists",
            69: "objectClassModsProhibited",
            70: "resultsTooLarge",  # CLDAP
            80: "other",
        },
    ),
    LDAPDN("matchedDN", ""),
    LDAPString("diagnosticMessage", ""),
    # LDAP v3 only
    ASN1F_optional(ASN1F_SEQUENCE_OF("referral", [], LDAPReferral, implicit_tag=0xA3)),
)


# ldap APPLICATION


class ASN1_Class_LDAP(ASN1_Class):
    name = "LDAP"
    # APPLICATION + CONSTRUCTED = 0x40 | 0x20
    BindRequest = 0x60
    BindResponse = 0x61
    UnbindRequest = 0x42  # not constructed
    SearchRequest = 0x63
    SearchResultEntry = 0x64
    SearchResultDone = 0x65
    ModifyRequest = 0x66
    ModifyResponse = 0x67
    AddRequest = 0x68
    AddResponse = 0x69
    DelRequest = 0x4A  # not constructed
    DelResponse = 0x6B
    ModifyDNRequest = 0x6C
    ModifyDNResponse = 0x6D
    CompareRequest = 0x6E
    CompareResponse = 0x7F
    AbandonRequest = 0x50  # application + primitive
    SearchResultReference = 0x73
    ExtendedRequest = 0x77
    ExtendedResponse = 0x78


# Bind operation
# https://datatracker.ietf.org/doc/html/rfc4511#section-4.2


class ASN1_Class_LDAP_Authentication(ASN1_Class):
    name = "LDAP Authentication"
    # CONTEXT-SPECIFIC = 0x80
    simple = 0x80
    krbv42LDAP = 0x81
    krbv42DSA = 0x82
    sasl = 0xA3  # CONTEXT-SPECIFIC | CONSTRUCTED
    # [MS-ADTS] sect 5.1.1.1
    sicilyPackageDiscovery = 0x89
    sicilyNegotiate = 0x8A
    sicilyResponse = 0x8B


# simple
class LDAP_Authentication_simple(ASN1_STRING):
    tag = ASN1_Class_LDAP_Authentication.simple


class BERcodec_LDAP_Authentication_simple(BERcodec_STRING):
    tag = ASN1_Class_LDAP_Authentication.simple


class ASN1F_LDAP_Authentication_simple(ASN1F_STRING):
    ASN1_tag = ASN1_Class_LDAP_Authentication.simple


# krbv42LDAP
class LDAP_Authentication_krbv42LDAP(ASN1_STRING):
    tag = ASN1_Class_LDAP_Authentication.krbv42LDAP


class BERcodec_LDAP_Authentication_krbv42LDAP(BERcodec_STRING):
    tag = ASN1_Class_LDAP_Authentication.krbv42LDAP


class ASN1F_LDAP_Authentication_krbv42LDAP(ASN1F_STRING):
    ASN1_tag = ASN1_Class_LDAP_Authentication.krbv42LDAP


# krbv42DSA
class LDAP_Authentication_krbv42DSA(ASN1_STRING):
    tag = ASN1_Class_LDAP_Authentication.krbv42DSA


class BERcodec_LDAP_Authentication_krbv42DSA(BERcodec_STRING):
    tag = ASN1_Class_LDAP_Authentication.krbv42DSA


class ASN1F_LDAP_Authentication_krbv42DSA(ASN1F_STRING):
    ASN1_tag = ASN1_Class_LDAP_Authentication.krbv42DSA


# sicilyPackageDiscovery
class LDAP_Authentication_sicilyPackageDiscovery(ASN1_STRING):
    tag = ASN1_Class_LDAP_Authentication.sicilyPackageDiscovery


class BERcodec_LDAP_Authentication_sicilyPackageDiscovery(BERcodec_STRING):
    tag = ASN1_Class_LDAP_Authentication.sicilyPackageDiscovery


class ASN1F_LDAP_Authentication_sicilyPackageDiscovery(ASN1F_STRING):
    ASN1_tag = ASN1_Class_LDAP_Authentication.sicilyPackageDiscovery


# sicilyNegotiate
class LDAP_Authentication_sicilyNegotiate(ASN1_STRING):
    tag = ASN1_Class_LDAP_Authentication.sicilyNegotiate


class BERcodec_LDAP_Authentication_sicilyNegotiate(BERcodec_STRING):
    tag = ASN1_Class_LDAP_Authentication.sicilyNegotiate


class ASN1F_LDAP_Authentication_sicilyNegotiate(ASN1F_STRING):
    ASN1_tag = ASN1_Class_LDAP_Authentication.sicilyNegotiate


# sicilyResponse
class LDAP_Authentication_sicilyResponse(ASN1_STRING):
    tag = ASN1_Class_LDAP_Authentication.sicilyResponse


class BERcodec_LDAP_Authentication_sicilyResponse(BERcodec_STRING):
    tag = ASN1_Class_LDAP_Authentication.sicilyResponse


class ASN1F_LDAP_Authentication_sicilyResponse(ASN1F_STRING):
    ASN1_tag = ASN1_Class_LDAP_Authentication.sicilyResponse


_SASL_MECHANISMS: dict = {}


class _SaslCredentialsField(ASN1F_STRING_PacketField):
    def m2i(self, pkt, s):
        val = super(_SaslCredentialsField, self).m2i(pkt, s)
        if not val[0].val:
            return val
        if pkt.mechanism.val in _SASL_MECHANISMS:
            return (
                _SASL_MECHANISMS[pkt.mechanism.val](val[0].val, _underlayer=pkt),
                val[1],
            )
        return val


class LDAP_Authentication_SaslCredentials(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        LDAPString("mechanism", ""),
        ASN1F_optional(
            _SaslCredentialsField("credentials", ""),
        ),
        implicit_tag=ASN1_Class_LDAP_Authentication.sasl,
    )


class LDAP_BindRequest(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("version", 3),
        LDAPDN("bind_name", ""),
        ASN1F_CHOICE(
            "authentication",
            None,
            ASN1F_LDAP_Authentication_simple,
            ASN1F_LDAP_Authentication_krbv42LDAP,
            ASN1F_LDAP_Authentication_krbv42DSA,
            LDAP_Authentication_SaslCredentials,
        ),
        implicit_tag=ASN1_Class_LDAP.BindRequest,
    )


class LDAP_BindResponse(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        *(
            LDAPResult
            + (
                ASN1F_optional(
                    # For GSSAPI, the response is wrapped in
                    # LDAP_Authentication_SaslCredentials
                    ASN1F_STRING("serverSaslCredsWrap", "", implicit_tag=0xA7),
                ),
                ASN1F_optional(
                    ASN1F_STRING("serverSaslCreds", "", implicit_tag=0x87),
                ),
            )
        ),
        implicit_tag=ASN1_Class_LDAP.BindResponse,
    )

    @property
    def serverCreds(self):
        """
        serverCreds field in SicilyBindResponse
        """
        return self.matchedDN.val

    @serverCreds.setter
    def serverCreds(self, val):
        """
        serverCreds field in SicilyBindResponse
        """
        self.matchedDN = ASN1_STRING(val)

    @property
    def serverSaslCredsData(self):
        """
        Get serverSaslCreds or serverSaslCredsWrap depending on what's available
        """
        if self.serverSaslCredsWrap and self.serverSaslCredsWrap.val:
            wrap = LDAP_Authentication_SaslCredentials(self.serverSaslCredsWrap.val)
            val = wrap.credentials
            if isinstance(val, ASN1_STRING):
                return val.val
            return bytes(val)
        elif self.serverSaslCreds and self.serverSaslCreds.val:
            return self.serverSaslCreds.val
        else:
            return None


# Unbind operation
# https://datatracker.ietf.org/doc/html/rfc4511#section-4.3


class LDAP_UnbindRequest(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_NULL("info", 0),
        implicit_tag=ASN1_Class_LDAP.UnbindRequest,
    )


# Search operation
# https://datatracker.ietf.org/doc/html/rfc4511#section-4.5


class LDAP_SubstringFilterInitial(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = LDAPString("val", "")


class LDAP_SubstringFilterAny(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = LDAPString("val", "")


class LDAP_SubstringFilterFinal(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = LDAPString("val", "")


class LDAP_SubstringFilterStr(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_CHOICE(
        "str",
        ASN1_STRING(""),
        ASN1F_PACKET(
            "initial",
            LDAP_SubstringFilterInitial(),
            LDAP_SubstringFilterInitial,
            implicit_tag=0x80,
        ),
        ASN1F_PACKET(
            "any", LDAP_SubstringFilterAny(), LDAP_SubstringFilterAny, implicit_tag=0x81
        ),
        ASN1F_PACKET(
            "final",
            LDAP_SubstringFilterFinal(),
            LDAP_SubstringFilterFinal,
            implicit_tag=0x82,
        ),
    )


class LDAP_SubstringFilter(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        AttributeType("type", ""),
        ASN1F_SEQUENCE_OF("filters", [], LDAP_SubstringFilterStr),
    )


_LDAP_Filter = lambda *args, **kwargs: LDAP_Filter(*args, **kwargs)


class LDAP_FilterAnd(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SET_OF("vals", [], _LDAP_Filter)


class LDAP_FilterOr(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SET_OF("vals", [], _LDAP_Filter)


class LDAP_FilterNot(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_PACKET("val", None, None, next_cls_cb=lambda *args, **kwargs: LDAP_Filter)
    )


class LDAP_FilterPresent(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = AttributeType("present", "objectClass")


class LDAP_FilterEqual(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = AttributeValueAssertion.ASN1_root


class LDAP_FilterGreaterOrEqual(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = AttributeValueAssertion.ASN1_root


class LDAP_FilterLessOrEqual(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = AttributeValueAssertion.ASN1_root


class LDAP_FilterApproxMatch(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = AttributeValueAssertion.ASN1_root


class LDAP_FilterExtensibleMatch(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_optional(
            LDAPString("matchingRule", "", implicit_tag=0x81),
        ),
        ASN1F_optional(
            LDAPString("type", "", implicit_tag=0x81),
        ),
        AttributeValue("matchValue", "", implicit_tag=0x82),
        ASN1F_BOOLEAN("dnAttributes", False, implicit_tag=0x84),
    )


class ASN1_Class_LDAP_Filter(ASN1_Class):
    name = "LDAP Filter"
    # CONTEXT-SPECIFIC + CONSTRUCTED = 0x80 | 0x20
    And = 0xA0
    Or = 0xA1
    Not = 0xA2
    EqualityMatch = 0xA3
    Substrings = 0xA4
    GreaterOrEqual = 0xA5
    LessOrEqual = 0xA6
    Present = 0x87  # not constructed
    ApproxMatch = 0xA8
    ExtensibleMatch = 0xA9


class LDAP_Filter(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_CHOICE(
        "filter",
        LDAP_FilterPresent(),
        ASN1F_PACKET(
            "and_", None, LDAP_FilterAnd, implicit_tag=ASN1_Class_LDAP_Filter.And
        ),
        ASN1F_PACKET(
            "or_", None, LDAP_FilterOr, implicit_tag=ASN1_Class_LDAP_Filter.Or
        ),
        ASN1F_PACKET(
            "not_", None, LDAP_FilterNot, implicit_tag=ASN1_Class_LDAP_Filter.Not
        ),
        ASN1F_PACKET(
            "equalityMatch",
            None,
            LDAP_FilterEqual,
            implicit_tag=ASN1_Class_LDAP_Filter.EqualityMatch,
        ),
        ASN1F_PACKET(
            "substrings",
            None,
            LDAP_SubstringFilter,
            implicit_tag=ASN1_Class_LDAP_Filter.Substrings,
        ),
        ASN1F_PACKET(
            "greaterOrEqual",
            None,
            LDAP_FilterGreaterOrEqual,
            implicit_tag=ASN1_Class_LDAP_Filter.GreaterOrEqual,
        ),
        ASN1F_PACKET(
            "lessOrEqual",
            None,
            LDAP_FilterLessOrEqual,
            implicit_tag=ASN1_Class_LDAP_Filter.LessOrEqual,
        ),
        ASN1F_PACKET(
            "present",
            None,
            LDAP_FilterPresent,
            implicit_tag=ASN1_Class_LDAP_Filter.Present,
        ),
        ASN1F_PACKET(
            "approxMatch",
            None,
            LDAP_FilterApproxMatch,
            implicit_tag=ASN1_Class_LDAP_Filter.ApproxMatch,
        ),
        ASN1F_PACKET(
            "extensibleMatch",
            None,
            LDAP_FilterExtensibleMatch,
            implicit_tag=ASN1_Class_LDAP_Filter.ExtensibleMatch,
        ),
    )

    @staticmethod
    def from_rfc2254_string(filter: str):
        """
        Convert a RFC-2254 filter to LDAP_Filter
        """
        # Note: this code is very dumb to be readable.
        _lerr = "Invalid LDAP filter string: "
        if filter.lstrip()[0] != "(":
            filter = "(%s)" % filter

        # 1. Cheap lexer.
        tokens = []
        cur = tokens
        backtrack = []
        filterlen = len(filter)
        i = 0
        while i < filterlen:
            c = filter[i]
            i += 1
            if c in [" ", "\t", "\n"]:
                # skip spaces
                continue
            elif c == "(":
                # enclosure
                cur.append([])
                backtrack.append(cur)
                cur = cur[-1]
            elif c == ")":
                # end of enclosure
                if not backtrack:
                    raise ValueError(_lerr + "parenthesis unmatched.")
                cur = backtrack.pop(-1)
            elif c in "&|!":
                # and / or / not
                cur.append(c)
            elif c in "=":
                # filtertype
                if cur[-1] in "~><:":
                    cur[-1] += c
                    continue
                cur.append(c)
            elif c in "~><":
                # comparisons
                cur.append(c)
            elif c == ":":
                # extensible
                cur.append(c)
            elif c == "*":
                # substring
                cur.append(c)
            else:
                # value
                v = ""
                for x in filter[i - 1 :]:
                    if x in "():!|&~<>=*":
                        break
                    v += x
                if not v:
                    raise ValueError(_lerr + "critical failure (impossible).")
                i += len(v) - 1
                cur.append(v)

        # Check that parenthesis were closed
        if backtrack:
            raise ValueError(_lerr + "parenthesis unmatched.")

        # LDAP filters must have an empty enclosure ()
        tokens = tokens[0]

        # 2. Cheap grammar parser.
        # Doing it recursively is trivial.
        def _getfld(x):
            if not x:
                raise ValueError(_lerr + "empty enclosure.")
            elif len(x) == 1 and isinstance(x[0], list):
                # useless enclosure
                return _getfld(x[0])
            elif x[0] in "&|":
                # multinary operator
                if len(x) < 3:
                    raise ValueError(_lerr + "bad use of multinary operator.")
                return (LDAP_FilterAnd if x[0] == "&" else LDAP_FilterOr)(
                    vals=[LDAP_Filter(filter=_getfld(y)) for y in x[1:]]
                )
            elif x[0] == "!":
                # unary operator
                if len(x) != 2:
                    raise ValueError(_lerr + "bad use of unary operator.")
                return LDAP_FilterNot(
                    val=LDAP_Filter(filter=_getfld(x[1])),
                )
            elif "=" in x and "*" in x:
                # substring
                if len(x) < 3 or x[1] != "=":
                    raise ValueError(_lerr + "bad use of substring.")
                return LDAP_SubstringFilter(
                    type=ASN1_STRING(x[0].strip()),
                    filters=[
                        LDAP_SubstringFilterStr(
                            str=(
                                LDAP_SubstringFilterFinal
                                if i == (len(x) - 3)
                                else (
                                    LDAP_SubstringFilterInitial
                                    if i == 0
                                    else LDAP_SubstringFilterAny
                                )
                            )(val=ASN1_STRING(y))
                        )
                        for i, y in enumerate(x[2:])
                        if y != "*"
                    ],
                )
            elif ":=" in x:
                # extensible
                raise NotImplementedError("Extensible not implemented.")
            elif any(y in ["<=", ">=", "~=", "="] for y in x):
                # simple
                if len(x) != 3 or "=" not in x[1]:
                    raise ValueError(_lerr + "bad use of comparison.")
                if x[2] == "*":
                    return LDAP_FilterPresent(present=ASN1_STRING(x[0]))
                return (
                    LDAP_FilterLessOrEqual
                    if "<=" in x
                    else (
                        LDAP_FilterGreaterOrEqual
                        if ">=" in x
                        else LDAP_FilterApproxMatch if "~=" in x else LDAP_FilterEqual
                    )
                )(
                    attributeType=ASN1_STRING(x[0].strip()),
                    attributeValue=ASN1_STRING(x[2]),
                )
            else:
                raise ValueError(_lerr + "invalid filter.")

        return LDAP_Filter(filter=_getfld(tokens))


class LDAP_SearchRequestAttribute(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = AttributeType("type", "")


class LDAP_SearchRequest(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        LDAPDN("baseObject", ""),
        ASN1F_ENUMERATED(
            "scope", 0, {0: "baseObject", 1: "singleLevel", 2: "wholeSubtree"}
        ),
        ASN1F_ENUMERATED(
            "derefAliases",
            0,
            {
                0: "neverDerefAliases",
                1: "derefInSearching",
                2: "derefFindingBaseObj",
                3: "derefAlways",
            },
        ),
        ASN1F_INTEGER("sizeLimit", 0),
        ASN1F_INTEGER("timeLimit", 0),
        ASN1F_BOOLEAN("attrsOnly", False),
        ASN1F_PACKET("filter", LDAP_Filter(), LDAP_Filter),
        ASN1F_SEQUENCE_OF("attributes", [], LDAP_SearchRequestAttribute),
        implicit_tag=ASN1_Class_LDAP.SearchRequest,
    )


class LDAP_AttributeValue(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = AttributeValue("value", "")


class LDAP_PartialAttribute(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        AttributeType("type", ""),
        ASN1F_SET_OF("values", [], LDAP_AttributeValue),
    )


class LDAP_SearchResponseEntry(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        LDAPDN("objectName", ""),
        ASN1F_SEQUENCE_OF(
            "attributes",
            LDAP_PartialAttribute(),
            LDAP_PartialAttribute,
        ),
        implicit_tag=ASN1_Class_LDAP.SearchResultEntry,
    )


class LDAP_SearchResponseResultDone(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        *LDAPResult,
        implicit_tag=ASN1_Class_LDAP.SearchResultDone,
    )


class LDAP_SearchResponseReference(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE_OF(
        "uris",
        [],
        URI,
        implicit_tag=ASN1_Class_LDAP.SearchResultReference,
    )


# Modify Operation
# https://datatracker.ietf.org/doc/html/rfc4511#section-4.6


class LDAP_ModifyRequestChange(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_ENUMERATED(
            "operation",
            0,
            {
                0: "add",
                1: "delete",
                2: "replace",
            },
        ),
        ASN1F_PACKET("modification", LDAP_PartialAttribute(), LDAP_PartialAttribute),
    )


class LDAP_ModifyRequest(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        LDAPDN("object", ""),
        ASN1F_SEQUENCE_OF("changes", [], LDAP_ModifyRequestChange),
        implicit_tag=ASN1_Class_LDAP.ModifyRequest,
    )


class LDAP_ModifyResponse(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        *LDAPResult,
        implicit_tag=ASN1_Class_LDAP.ModifyResponse,
    )


# Add Operation
# https://datatracker.ietf.org/doc/html/rfc4511#section-4.7


class LDAP_Attribute(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = LDAP_PartialAttribute.ASN1_root


class LDAP_AddRequest(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        LDAPDN("entry", ""),
        ASN1F_SEQUENCE_OF(
            "attributes",
            LDAP_Attribute(),
            LDAP_Attribute,
        ),
        implicit_tag=ASN1_Class_LDAP.AddRequest,
    )


class LDAP_AddResponse(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        *LDAPResult,
        implicit_tag=ASN1_Class_LDAP.AddResponse,
    )


# Delete Operation
# https://datatracker.ietf.org/doc/html/rfc4511#section-4.8


class LDAP_DelRequest(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = LDAPDN(
        "entry",
        "",
        implicit_tag=ASN1_Class_LDAP.DelRequest,
    )


class LDAP_DelResponse(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        *LDAPResult,
        implicit_tag=ASN1_Class_LDAP.DelResponse,
    )


# Modify DN Operation
# https://datatracker.ietf.org/doc/html/rfc4511#section-4.9


class LDAP_ModifyDNRequest(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        LDAPDN("entry", ""),
        LDAPDN("newrdn", ""),
        ASN1F_BOOLEAN("deleteoldrdn", ASN1_BOOLEAN(False)),
        ASN1F_optional(LDAPDN("newSuperior", None, implicit_tag=0xA0)),
        implicit_tag=ASN1_Class_LDAP.ModifyDNRequest,
    )


class LDAP_ModifyDNResponse(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        *LDAPResult,
        implicit_tag=ASN1_Class_LDAP.ModifyDNResponse,
    )


# Abandon Operation
# https://datatracker.ietf.org/doc/html/rfc4511#section-4.11


class LDAP_AbandonRequest(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("messageID", 0),
        implicit_tag=ASN1_Class_LDAP.AbandonRequest,
    )


# LDAP v3

# RFC 4511 sect 4.12 - Extended Operation


class LDAP_ExtendedResponse(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        *(
            LDAPResult
            + (
                ASN1F_optional(LDAPOID("responseName", None, implicit_tag=0x8A)),
                ASN1F_optional(ASN1F_STRING("responseValue", None, implicit_tag=0x8B)),
            )
        ),
        implicit_tag=ASN1_Class_LDAP.ExtendedResponse,
    )

    def do_dissect(self, x):
        # Note: Windows builds this packet with a buggy sequence size, that does not
        # include the optional fields. Do another pass of dissection on the optionals.
        s = super(LDAP_ExtendedResponse, self).do_dissect(x)
        if not s:
            return s
        for obj in self.ASN1_root.seq[-2:]:  # only on the 2 optional fields
            try:
                s = obj.dissect(self, s)
            except ASN1F_badsequence:
                break
        return s


# RFC 4511 sect 4.1.11

_LDAP_CONTROLS = {}


class _ControlValue_Field(ASN1F_STRING_PacketField):
    def m2i(self, pkt, s):
        val = super(_ControlValue_Field, self).m2i(pkt, s)
        if not val[0].val:
            return val
        controlType = pkt.controlType.val.decode()
        if controlType in _LDAP_CONTROLS:
            return (
                _LDAP_CONTROLS[controlType](val[0].val, _underlayer=pkt),
                val[1],
            )
        return val


class LDAP_Control(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        LDAPOID("controlType", ""),
        ASN1F_optional(
            ASN1F_BOOLEAN("criticality", False),
        ),
        ASN1F_optional(_ControlValue_Field("controlValue", "")),
    )


# RFC 2696 - LDAP Control Extension for Simple Paged Results Manipulation


class LDAP_realSearchControlValue(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("size", 0),
        ASN1F_STRING("cookie", ""),
    )


_LDAP_CONTROLS["1.2.840.113556.1.4.319"] = LDAP_realSearchControlValue


# [MS-ADTS]


class LDAP_serverSDFlagsControl(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_FLAGS(
            "flags",
            None,
            [
                "OWNER",
                "GROUP",
                "DACL",
                "SACL",
            ],
        )
    )


_LDAP_CONTROLS["1.2.840.113556.1.4.801"] = LDAP_serverSDFlagsControl


# LDAP main class


class LDAP(ASN1_Packet):
    # Names the Rust layer too, so `pl.filter(LDAP)` and `columns()` take it.
    name = "LDAP"
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_INTEGER("messageID", 0),
        ASN1F_CHOICE(
            "protocolOp",
            LDAP_SearchRequest(),
            LDAP_BindRequest,
            LDAP_BindResponse,
            LDAP_SearchRequest,
            LDAP_SearchResponseEntry,
            LDAP_SearchResponseResultDone,
            LDAP_AbandonRequest,
            LDAP_SearchResponseReference,
            LDAP_ModifyRequest,
            LDAP_ModifyResponse,
            LDAP_AddRequest,
            LDAP_AddResponse,
            LDAP_DelRequest,
            LDAP_DelResponse,
            LDAP_ModifyDNRequest,
            LDAP_ModifyDNResponse,
            LDAP_UnbindRequest,
            LDAP_ExtendedResponse,
        ),
        # LDAP v3 only
        ASN1F_optional(
            ASN1F_SEQUENCE_OF("Controls", None, LDAP_Control, implicit_tag=0xA0)
        ),
    )

    show_indent = 0

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 4:
            # Heuristic to detect SASL_Buffer
            if _pkt[0] != 0x30:
                if struct.unpack("!I", _pkt[:4])[0] + 4 == len(_pkt):
                    return LDAP_SASL_Buffer
                return PyRaw
        return cls

    @classmethod
    def tcp_reassemble(cls, data, metadata, *args, **kwargs):
        if len(data) < 4:
            return None
        # For LDAP, we would prefer to have the entire LDAP response
        # (multiple LDAP concatenated) in one go, to stay consistent with
        # what you get when using SASL.
        remaining = data
        while remaining:
            try:
                length, x = BER_len_dec(BER_id_dec(remaining)[1])
            except (BER_Decoding_Error, IndexError):
                return None
            if length and len(x) >= length:
                remaining = x[length:]
                if not remaining:
                    pkt = cls(data)
                    # Packet can be a whole response yet still miss some content.
                    if (
                        LDAP_SearchResponseEntry in pkt
                        and LDAP_SearchResponseResultDone not in pkt
                    ):
                        return None
                    return pkt
            else:
                if length:
                    metadata["tcp_min_len"] = len(data) - len(x) + length
                return None
        return None

    def hashret(self):
        return b"ldap"

    @property
    def unsolicited(self):
        # RFC4511 sect 4.4. - Unsolicited Notification
        return self.messageID == 0 and isinstance(
            self.protocolOp, LDAP_ExtendedResponse
        )

    def answers(self, other):
        if self.unsolicited:
            return True
        return isinstance(other, LDAP) and other.messageID == self.messageID

    def mysummary(self):
        if not self.protocolOp or not self.messageID:
            return ""
        return (
            "%s(%s)"
            % (
                self.protocolOp.__class__.__name__.replace("_", " "),
                self.messageID.val,
            ),
            [LDAP],
        )


bind_layers(LDAP, LDAP)

# TCP 389 and 3268 are the Rust LDAP layer's, which keeps an LDAP capture
# visible to the bulk paths; `pkt[LDAP]` decodes that layer's octets here.

# CLDAP - rfc1798


class CLDAP(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        LDAP.ASN1_root.seq[0],  # messageID
        ASN1F_optional(
            LDAPDN("user", ""),
        ),
        LDAP.ASN1_root.seq[1],  # protocolOp
    )

    def answers(self, other):
        return isinstance(other, CLDAP) and other.messageID == self.messageID


bind_layers(CLDAP, CLDAP)

bind_bottom_up(UDP, CLDAP, dport=389)
bind_bottom_up(UDP, CLDAP, sport=389)
bind_layers(UDP, CLDAP, sport=389, dport=389)

# [MS-ADTS] sect 3.1.1.2.3.3

LDAP_PROPERTY_SET = {
    uuid.UUID(
        "C7407360-20BF-11D0-A768-00AA006E0529"
    ): "Domain Password & Lockout Policies",
    uuid.UUID("59BA2F42-79A2-11D0-9020-00C04FC2D3CF"): "General Information",
    uuid.UUID("4C164200-20C0-11D0-A768-00AA006E0529"): "Account Restrictions",
    uuid.UUID("5F202010-79A5-11D0-9020-00C04FC2D4CF"): "Logon Information",
    uuid.UUID("BC0AC240-79A9-11D0-9020-00C04FC2D4CF"): "Group Membership",
    uuid.UUID("E45795B2-9455-11D1-AEBD-0000F80367C1"): "Phone and Mail Options",
    uuid.UUID("77B5B886-944A-11D1-AEBD-0000F80367C1"): "Personal Information",
    uuid.UUID("E45795B3-9455-11D1-AEBD-0000F80367C1"): "Web Information",
    uuid.UUID("E48D0154-BCF8-11D1-8702-00C04FB96050"): "Public Information",
    uuid.UUID("037088F8-0AE1-11D2-B422-00A0C968F939"): "Remote Access Information",
    uuid.UUID("B8119FD0-04F6-4762-AB7A-4986C76B3F9A"): "Other Domain Parameters",
    uuid.UUID("72E39547-7B18-11D1-ADEF-00C04FD8D5CD"): "DNS Host Name Attributes",
    uuid.UUID("FFA6F046-CA4B-4FEB-B40D-04DFEE722543"): "MS-TS-GatewayAccess",
    uuid.UUID("91E647DE-D96F-4B70-9557-D63FF4F3CCD8"): "Private Information",
    uuid.UUID("5805BC62-BDC9-4428-A5E2-856A0F4C185E"): "Terminal Server License Server",
}

# [MS-ADTS] sect 5.1.3.2.1

LDAP_CONTROL_ACCESS_RIGHTS = {
    uuid.UUID("ee914b82-0a98-11d1-adbb-00c04fd8d5cd"): "Abandon-Replication",
    uuid.UUID("440820ad-65b4-11d1-a3da-0000f875ae0d"): "Add-GUID",
    uuid.UUID("1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd"): "Allocate-Rids",
    uuid.UUID("68b1d179-0d15-4d4f-ab71-46152e79a7bc"): "Allowed-To-Authenticate",
    uuid.UUID("edacfd8f-ffb3-11d1-b41d-00a0c968f939"): "Apply-Group-Policy",
    uuid.UUID("0e10c968-78fb-11d2-90d4-00c04f79dc55"): "Certificate-Enrollment",
    uuid.UUID("a05b8cc2-17bc-4802-a710-e7c15ab866a2"): "Certificate-AutoEnrollment",
    uuid.UUID("014bf69c-7b3b-11d1-85f6-08002be74fab"): "Change-Domain-Master",
    uuid.UUID("cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd"): "Change-Infrastructure-Master",
    uuid.UUID("bae50096-4752-11d1-9052-00c04fc2d4cf"): "Change-PDC",
    uuid.UUID("d58d5f36-0a98-11d1-adbb-00c04fd8d5cd"): "Change-Rid-Master",
    uuid.UUID("e12b56b6-0a95-11d1-adbb-00c04fd8d5cd"): "Change-Schema-Master",
    uuid.UUID("e2a36dc9-ae17-47c3-b58b-be34c55ba633"): "Create-Inbound-Forest-Trust",
    uuid.UUID("fec364e0-0a98-11d1-adbb-00c04fd8d5cd"): "Do-Garbage-Collection",
    uuid.UUID("ab721a52-1e2f-11d0-9819-00aa0040529b"): "Domain-Administer-Server",
    uuid.UUID("69ae6200-7f46-11d2-b9ad-00c04f79f805"): "DS-Check-Stale-Phantoms",
    uuid.UUID("2f16c4a5-b98e-432c-952a-cb388ba33f2e"): "DS-Execute-Intentions-Script",
    uuid.UUID("9923a32a-3607-11d2-b9be-0000f87a36b2"): "DS-Install-Replica",
    uuid.UUID("4ecc03fe-ffc0-4947-b630-eb672a8a9dbc"): "DS-Query-Self-Quota",
    uuid.UUID("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"): "DS-Replication-Get-Changes",
    uuid.UUID("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"): "DS-Replication-Get-Changes-All",
    uuid.UUID(
        "89e95b76-444d-4c62-991a-0facbeda640c"
    ): "DS-Replication-Get-Changes-In-Filtered-Set",
    uuid.UUID("1131f6ac-9c07-11d1-f79f-00c04fc2dcd2"): "DS-Replication-Manage-Topology",
    uuid.UUID(
        "f98340fb-7c5b-4cdb-a00b-2ebdfa115a96"
    ): "DS-Replication-Monitor-Topology",
    uuid.UUID("1131f6ab-9c07-11d1-f79f-00c04fc2dcd2"): "DS-Replication-Synchronize",
    uuid.UUID(
        "05c74c5e-4deb-43b4-bd9f-86664c2a7fd5"
    ): "Enable-Per-User-Reversibly-Encrypted-Password",
    uuid.UUID("b7b1b3de-ab09-4242-9e30-9980e5d322f7"): "Generate-RSoP-Logging",
    uuid.UUID("b7b1b3dd-ab09-4242-9e30-9980e5d322f7"): "Generate-RSoP-Planning",
    uuid.UUID("7c0e2a7c-a419-48e4-a995-10180aad54dd"): "Manage-Optional-Features",
    uuid.UUID("ba33815a-4f93-4c76-87f3-57574bff8109"): "Migrate-SID-History",
    uuid.UUID("b4e60130-df3f-11d1-9c86-006008764d0e"): "msmq-Open-Connector",
    uuid.UUID("06bd3201-df3e-11d1-9c86-006008764d0e"): "msmq-Peek",
    uuid.UUID("4b6e08c3-df3c-11d1-9c86-006008764d0e"): "msmq-Peek-computer-Journal",
    uuid.UUID("4b6e08c1-df3c-11d1-9c86-006008764d0e"): "msmq-Peek-Dead-Letter",
    uuid.UUID("06bd3200-df3e-11d1-9c86-006008764d0e"): "msmq-Receive",
    uuid.UUID("4b6e08c2-df3c-11d1-9c86-006008764d0e"): "msmq-Receive-computer-Journal",
    uuid.UUID("4b6e08c0-df3c-11d1-9c86-006008764d0e"): "msmq-Receive-Dead-Letter",
    uuid.UUID("06bd3203-df3e-11d1-9c86-006008764d0e"): "msmq-Receive-journal",
    uuid.UUID("06bd3202-df3e-11d1-9c86-006008764d0e"): "msmq-Send",
    uuid.UUID("a1990816-4298-11d1-ade2-00c04fd8d5cd"): "Open-Address-Book",
    uuid.UUID(
        "1131f6ae-9c07-11d1-f79f-00c04fc2dcd2"
    ): "Read-Only-Replication-Secret-Synchronization",
    uuid.UUID("45ec5156-db7e-47bb-b53f-dbeb2d03c40f"): "Reanimate-Tombstones",
    uuid.UUID("0bc1554e-0a99-11d1-adbb-00c04fd8d5cd"): "Recalculate-Hierarchy",
    uuid.UUID(
        "62dd28a8-7f46-11d2-b9ad-00c04f79f805"
    ): "Recalculate-Security-Inheritance",
    uuid.UUID("ab721a56-1e2f-11d0-9819-00aa0040529b"): "Receive-As",
    uuid.UUID("9432c620-033c-4db7-8b58-14ef6d0bf477"): "Refresh-Group-Cache",
    uuid.UUID("1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8"): "Reload-SSL-Certificate",
    uuid.UUID("7726b9d5-a4b4-4288-a6b2-dce952e80a7f"): "Run-Protect_Admin_Groups-Task",
    uuid.UUID("91d67418-0135-4acc-8d79-c08e857cfbec"): "SAM-Enumerate-Entire-Domain",
    uuid.UUID("ab721a54-1e2f-11d0-9819-00aa0040529b"): "Send-As",
    uuid.UUID("ab721a55-1e2f-11d0-9819-00aa0040529b"): "Send-To",
    uuid.UUID("ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501"): "Unexpire-Password",
    uuid.UUID(
        "280f369c-67c7-438e-ae98-1d46f3c6f541"
    ): "Update-Password-Not-Required-Bit",
    uuid.UUID("be2bb760-7f46-11d2-b9ad-00c04f79f805"): "Update-Schema-Cache",
    uuid.UUID("ab721a53-1e2f-11d0-9819-00aa0040529b"): "User-Change-Password",
    uuid.UUID("00299570-246d-11d0-a768-00aa006e0529"): "User-Force-Change-Password",
    uuid.UUID("3e0f7e18-2c7a-4c10-ba82-4d926db99a3e"): "DS-Clone-Domain-Controller",
    uuid.UUID("084c93a2-620d-4879-a836-f0ae47de0e89"): "DS-Read-Partition-Secrets",
    uuid.UUID("94825a8d-b171-4116-8146-1e34d8f54401"): "DS-Write-Partition-Secrets",
    uuid.UUID("4125c71f-7fac-4ff0-bcb7-f09a41325286"): "DS-Set-Owner",
    uuid.UUID("88a9933e-e5c8-4f2a-9dd7-2527416b8092"): "DS-Bypass-Quota",
    uuid.UUID("9b026da6-0d3c-465c-8bee-5199d7165cba"): "DS-Validated-Write-Computer",
}

# [MS-ADTS] sect 5.1.3.2 and
# https://learn.microsoft.com/en-us/windows/win32/secauthz/directory-services-access-rights

LDAP_DS_ACCESS_RIGHTS = {
    0x00000001: "CREATE_CHILD",
    0x00000002: "DELETE_CHILD",
    0x00000004: "LIST_CONTENTS",
    0x00000008: "WRITE_PROPERTY_EXTENDED",
    0x00000010: "READ_PROP",
    0x00000020: "WRITE_PROP",
    0x00000040: "DELETE_TREE",
    0x00000080: "LIST_OBJECT",
    0x00000100: "CONTROL_ACCESS",
    0x00010000: "DELETE",
    0x00020000: "READ_CONTROL",
    0x00040000: "WRITE_DAC",
    0x00080000: "WRITE_OWNER",
    0x00100000: "SYNCHRONIZE",
    0x01000000: "ACCESS_SYSTEM_SECURITY",
    0x80000000: "GENERIC_READ",
    0x40000000: "GENERIC_WRITE",
    0x20000000: "GENERIC_EXECUTE",
    0x10000000: "GENERIC_ALL",
}


class LDAP_SASL_Buffer(PyPacket):
    """RFC 4422 §3.7: a security layer's buffer behind a four-octet length.
    scapy unwraps it as GSSAPI; it stays octets here."""

    fields_desc = [
        FieldLenField("BufferLength", None, fmt="!I", length_of="Buffer"),
        StrLenField("Buffer", b"", length_from=lambda pkt: pkt.BufferLength),
    ]

    def hashret(self):
        return b"ldap"

    def answers(self, other):
        return isinstance(other, LDAP_SASL_Buffer)

    @classmethod
    def tcp_reassemble(cls, data, *args, **kwargs):
        if len(data) < 4:
            return None
        if data[0] == 0x30:
            # A plain LDAP message, which is how a server reports an error.
            try:
                xlen, x = BER_len_dec(BER_id_dec(data)[1])
            except (BER_Decoding_Error, IndexError):
                return None
            if xlen and xlen == len(x):
                return LDAP(data)
        length = struct.unpack("!I", data[:4])[0] + 4
        if len(data) >= length:
            return cls(data)
