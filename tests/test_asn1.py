"""The ASN.1 model, its bounds, and the two halves of SNMP agreeing."""

import threading

import pytest

import wiry
from wiry import (
    ASN1_COUNTER32, ASN1_COUNTER64, ASN1_GAUGE32, ASN1_INTEGER, ASN1_IPADDRESS,
    ASN1_NULL, ASN1_OID, ASN1_STRING, ASN1_TIME_TICKS, BER_Decoding_Error,
    BER_Exception, BERcodec_OID, BERcodec_SEQUENCE, Ether, IP, SNMP, SNMPbulk,
    SNMPget, SNMPresponse, SNMPtrapv1, SNMPtrapv2, SNMPvarbind, UDP, rdpcap,
    wrpcap,
)
from wiry.asn1 import ber


def within(seconds, fn):
    """Run `fn` on a worker with a deadline: an assertion after the call
    cannot catch a hang."""
    out = {}

    def run():
        try:
            out["value"] = fn()
        except BaseException as exc:  # noqa: BLE001
            out["error"] = exc

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(seconds)
    assert not t.is_alive(), f"still running after {seconds}s"
    if "error" in out:
        raise out["error"]
    return out.get("value")


def messages():
    vb = SNMPvarbind
    yield SNMP(community="public", PDU=SNMPget(id=1, varbindlist=[
        vb(oid="1.3.6.1.2.1.1.1.0")]))
    yield SNMP(version="v2c", PDU=SNMPresponse(id=2, error=5, error_index=1,
                                              varbindlist=[
        vb(oid="1.3.6.1.2.1.1.5.0", value=ASN1_STRING(b"\xffbinary")),
        vb(oid="1.3.6.1.2.1.2.2.1.10.1", value=ASN1_COUNTER32(4000000000)),
        vb(oid="1.3.6.1.2.1.31.1.1.1.6.1", value=ASN1_COUNTER64(2**64 - 1)),
        vb(oid="1.3.6.1.2.1.1.3.0", value=ASN1_TIME_TICKS(12345)),
        vb(oid="1.3.6.1.2.1.2.2.1.5.1", value=ASN1_GAUGE32(7)),
        vb(oid="1.3.6.1.2.1.4.20.1.1", value=ASN1_IPADDRESS("192.0.2.1")),
        vb(oid="1.3.6.1.2.1.1.2.0", value=ASN1_OID("1.3.6.1.4.1.8072.3.2.10")),
        vb(oid="1.3.6.1.4.1.1.1", value=ASN1_INTEGER(-129)),
        vb(oid="1.3.6.1.4.1.1.2", value=None, noSuchObject=ASN1_NULL(0)),
        vb(oid="1.3.6.1.4.1.1.3", value=None, noSuchInstance=ASN1_NULL(0)),
        vb(oid="1.3.6.1.4.1.1.4", value=None, endOfMibView=ASN1_NULL(0)),
    ]))
    yield SNMP(version="v2c", PDU=SNMPbulk(id=3, non_repeaters=1,
                                          max_repetitions=10, varbindlist=[
        vb(oid="1.3.6.1.2.1.1")]))
    yield SNMP(version="v1", PDU=SNMPtrapv1(
        enterprise="1.3.6.1.4.1.9", agent_addr="10.1.2.3", generic_trap=3,
        specific_trap=0, time_stamp=99, varbindlist=[
            vb(oid="1.3.6.1.2.1.2.2.1.1.1", value=ASN1_INTEGER(1))]))
    yield SNMP(version="v2c", PDU=SNMPtrapv2(id=9, varbindlist=[]))


EXCEPTIONS = ("noSuchObject", "noSuchInstance", "endOfMibView")


def as_items(snmp):
    """`pkt[SNMP]` flattened the way the Rust layer flattens the message."""
    pdu = snmp.PDU
    out = [("version", snmp.version.val), ("community", snmp.community.val),
           ("PDU", type(pdu).__name__)]
    for f in pdu.fields_desc:
        if f.name != "varbindlist":
            v = getattr(pdu, f.name)
            out.append((f.name, v.val))
    binds = []
    for b in pdu.varbindlist:
        if b.value is None:
            value = next(n for n in EXCEPTIONS if getattr(b, n) is not None)
        else:
            value = None if isinstance(b.value, ASN1_NULL) else b.value.val
        binds.append((b.oid.val, value))
    out.append(("varbindlist", binds))
    return out


def test_the_bulk_path_and_the_object_tree_agree(tmp_path):
    frames = [Ether() / IP() / UDP(sport=50000, dport=161) / m for m in messages()]
    path = tmp_path / "snmp.pcap"
    wrpcap(str(path), frames)
    pl = rdpcap(str(path))
    bulk = pl.columns([("SNMP", "vars")])["SNMP.vars"]
    assert len(bulk) == len(frames)
    for i, items in enumerate(bulk):
        assert items == as_items(pl[i][SNMP]), i


def test_a_layer_reads_the_same_whichever_way_it_was_reached():
    msg = next(messages())
    built = IP() / UDP() / msg
    assert built.sport == built.dport == 161
    dissected = IP(bytes(built))
    assert SNMP in dissected and SNMPvarbind in dissected
    assert dissected[SNMP].community.val == b"public"
    assert dissected["SNMP"].PDU.id.val == 1
    assert dissected.community.val == b"public"


def test_a_change_through_the_object_tree_reaches_the_octets():
    pkt = IP(bytes(IP() / UDP() / next(messages())))
    pkt[SNMP].community = b"private"
    again = IP(bytes(pkt))
    assert again[SNMP].community.val == b"private"
    assert again[UDP].len == len(bytes(again[SNMP])) + 8


def test_reading_a_non_canonical_message_never_rewrites_it():
    # A four-octet length where one would do: legal BER, not what the
    # encoder writes back.
    canonical = bytes(next(messages()))
    loose = b"\x30\x84" + len(canonical[2:]).to_bytes(4, "big") + canonical[2:]
    frame = bytes(IP() / UDP(sport=1, dport=161) / loose)
    pkt = IP(frame)
    assert pkt[SNMP].community.val == b"public"
    assert bytes(pkt) == frame


def test_stacking_above_a_python_layer_makes_it_that_layers_payload():
    pkt = IP() / UDP() / SNMP() / b"trailer"
    assert pkt[SNMP].payload.load == b"trailer"
    assert bytes(pkt).endswith(b"trailer")


def test_a_malformed_message_stays_the_rust_layer():
    frame = bytes(IP() / UDP(sport=1, dport=161) / b"\x30\x03\x02\x05\x00")
    pkt = IP(frame)
    assert pkt.layers()[-1] == "SNMP"
    assert SNMP not in pkt
    assert bytes(pkt) == frame


def test_an_oid_decodes_as_x690_says_where_scapy_does_not():
    """X.690 §8.19.5's own example. scapy splits the first subidentifier by
    40 and reads 2.999.3 back as 26.39.3."""
    obj, _ = BERcodec_OID.do_dec(bytes([0x06, 0x03, 0x88, 0x37, 0x03]))
    assert obj.val == "2.999.3"
    assert BERcodec_OID.enc("2.999.3") == bytes([0x06, 0x03, 0x88, 0x37, 0x03])


def test_value_nesting_is_bounded_without_recursing_out():
    data = b"\x05\x00"
    for _ in range(ber.MAX_BER_DEPTH + 8):
        data = BERcodec_SEQUENCE.enc(data)
    with pytest.raises(BER_Exception):
        BERcodec_SEQUENCE.dec(data)


def test_packet_nesting_is_bounded_without_recursing_out():
    from wiry.asn1fields import ASN1F_CHOICE, ASN1F_INTEGER, ASN1F_PACKET
    from wiry.asn1packet import ASN1_Packet
    from wiry.asn1.asn1 import ASN1_Codecs

    # A type that contains itself, as an LDAP Filter does.
    class Node(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.BER
        ASN1_root = ASN1F_CHOICE("n", None, ASN1F_INTEGER)

    Node.ASN1_root = ASN1F_CHOICE(
        "n", None, ASN1F_INTEGER,
        ASN1F_PACKET("n", None, Node, explicit_tag=0xA0))
    data = b"\x02\x01\x00"
    for _ in range(ber.MAX_BER_DEPTH * 4):
        data = b"\xa0" + bytes([len(data)]) + data if len(data) < 128 else \
            b"\xa0\x82" + len(data).to_bytes(2, "big") + data
    with pytest.raises(BER_Exception):
        within(10, lambda: Node(data))


def test_an_element_bomb_stops_at_the_budget():
    n = ber.MAX_BER_ELEMENTS + 10
    body = b"\x05\x00" * n
    data = b"\x30\x84" + len(body).to_bytes(4, "big") + body
    with pytest.raises(BER_Exception):
        within(60, lambda: BERcodec_SEQUENCE.dec(data))


def test_a_long_sequence_of_decodes_in_linear_time():
    """scapy hands each element everything after it and gets the rest back
    as a copy, which for these 20,000 bindings is 1.6 GB of copying."""
    vbs = b"".join(
        b"\x30\x06\x06\x01\x2b\x02\x01\x01" for _ in range(20_000))
    pdu = b"\x02\x01\x00\x02\x01\x00\x02\x01\x00" + b"\x30\x83" + \
        len(vbs).to_bytes(3, "big") + vbs
    body = b"\x02\x01\x01\x04\x01p" + b"\xa2\x83" + len(pdu).to_bytes(3, "big") + pdu
    msg = b"\x30\x83" + len(body).to_bytes(3, "big") + body
    snmp = within(30, lambda: SNMP(msg))
    assert len(snmp.PDU.varbindlist) == 20_000
    assert bytes(snmp) == msg


def test_truncations_raise_scapys_errors_and_nothing_else():
    msg = bytes(next(messages()))
    for n in range(len(msg)):
        try:
            SNMP(msg[:n])
        except (BER_Decoding_Error, wiry.ASN1_Error, BER_Exception):
            pass


def test_every_exported_python_layer_name_resolves():
    from wiry._pynames import EXPORTS

    for names in EXPORTS.values():
        for n in names:
            assert getattr(wiry, n) is not None, n
            assert n in dir(wiry), n
