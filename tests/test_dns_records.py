"""DNS record classes: building, compression, and agreement with the bulk path.

Expected octets are hand-built from RFC 1035 (§4.1 messages, §4.1.4
compression, §4.2.2 TCP framing), RFC 2782 (SRV), RFC 6891 (OPT) and
RFC 4034 (DNSSEC).
"""

import struct

import pytest

import wiry
from wiry import (
    DNS, DNSQR, DNSRR, DNSRRMX, DNSRROPT, DNSRRSOA, DNSRRSRV, EDNS0TLV, IP,
    TCP, UDP, Ether, Raw, dns_compress, rdpcap, wrpcap,
)


def name(*labels):
    return b"".join(bytes([len(x)]) + x.encode() for x in labels) + b"\x00"


def test_the_tutorial_query_builds_rfc_1035_octets():
    pkt = IP(dst="8.8.8.8") / UDP() / DNS(rd=1, qd=DNSQR(qname="example.com"))
    msg = bytes(pkt)[28:]
    assert msg == (
        b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        + name("example", "com") + b"\x00\x01\x00\x01"
    )
    assert bytes(pkt)[20:22] == struct.pack("!H", 53)


def test_a_bare_dns_asks_scapys_sample_question():
    assert bytes(DNS()) == (
        b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        + name("www", "example", "com") + b"\x00\x01\x00\x01"
    )
    assert bytes(DNS(qd=[])) == b"\x00\x00\x01\x00" + b"\x00" * 8


def test_records_encode_with_their_lengths_and_counts():
    dns = DNS(qr=1, qd=[], an=[
        DNSRR(rrname="a.example", rdata="192.0.2.1", ttl=60),
        DNSRRMX(rrname="example", preference=10, exchange="mx.example"),
        DNSRRSRV(rrname="_x._tcp.example", priority=1, weight=2, port=443,
                 target="host.example"),
    ])
    raw = bytes(dns)
    assert struct.unpack("!HHHH", raw[4:12]) == (0, 3, 0, 0)
    a = name("a", "example") + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([192, 0, 2, 1])
    mx_rdata = struct.pack("!H", 10) + name("mx", "example")
    mx = name("example") + struct.pack("!HHIH", 15, 1, 0, len(mx_rdata)) + mx_rdata
    srv_rdata = struct.pack("!HHH", 1, 2, 443) + name("host", "example")
    srv = (name("_x", "_tcp", "example")
           + struct.pack("!HHIH", 33, 1, 0, len(srv_rdata)) + srv_rdata)
    assert raw[12:] == a + mx + srv


def test_compression_points_at_the_first_occurrence():
    dns = DNS(qd=DNSQR(qname="www.example.com"),
              an=DNSRR(rrname="www.example.com", rdata="192.0.2.1"),
              ns=DNSRR(rrname="example.com", type="NS", rdata="ns.example.com"))
    z = bytes(dns_compress(dns))
    assert z.count(b"\x07example\x03com\x00") == 1
    question = 12 + len(name("www", "example", "com")) + 4
    # The answer's owner is the whole question name, at offset 12; the
    # authority's owner is its suffix, four octets further in.
    assert z[question:question + 2] == b"\xc0\x0c"
    assert b"\xc0\x10\x00\x02" in z
    assert z.endswith(b"\x02ns\xc0\x10")
    back = DNS(z)
    assert back.an[0].rrname == b"www.example.com."
    assert back.ns[0].rrname == b"example.com."
    assert back.ns[0].rdata == b"ns.example.com."


def test_a_compressed_dissected_message_rebuilds_unchanged():
    msg = (
        b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
        + name("example", "com") + b"\x00\x01\x00\x01"
        + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + bytes([192, 0, 2, 7])
    )
    pkt = Ether(bytes(Ether() / IP() / UDP(sport=53, dport=4000) / Raw(load=msg)))
    assert pkt[DNS].an[0].rrname == b"example.com."
    assert bytes(pkt).endswith(msg)
    pkt[DNS].an[0].ttl = 1
    out = bytes(pkt)
    assert out.endswith(name("example", "com") + struct.pack("!HHIH", 1, 1, 1, 4)
                        + bytes([192, 0, 2, 7]))
    assert Ether(out)[UDP].len == len(out) - 34


def test_over_tcp_the_prefix_counts_the_message_alone():
    pkt = IP() / TCP() / DNS(qd=[]) / Raw(load=b"next")
    raw = bytes(pkt)
    assert raw[40:42] == struct.pack("!H", 12)
    assert raw.endswith(b"next")
    back = IP(raw)
    assert back.layers() == ["IP", "TCP", "DNS", "Raw"]
    assert back[DNS].length == 12


def test_edns0_options_build_inside_the_opt_record():
    dns = DNS(qd=[], ar=[DNSRROPT(rdata=[EDNS0TLV(optcode=10, optdata=b"\x01" * 8)])])
    raw = bytes(dns)
    assert raw[12:] == (
        b"\x00" + struct.pack("!HHIH", 41, 4096, 0x8000, 12)
        + struct.pack("!HH", 10, 8) + b"\x01" * 8
    )


def test_a_generated_field_yields_one_packet_per_value_innermost_first():
    pkt = IP(ttl=[1, 2]) / UDP() / DNS(id=[7, 8])
    got = [(p[IP].ttl, p[DNS].id) for p in pkt]
    assert got == [(1, 7), (1, 8), (2, 7), (2, 8)]
    assert [p[DNS].id for p in wiry.expand(pkt)] == [7, 8, 7, 8]


def test_a_message_the_model_refuses_is_still_the_rust_layer():
    # RFC 1035 §4.1.1: the header claims two questions and carries one.
    msg = b"\xab\xcd\x01\x00\x00\x02\x00\x00\x00\x00\x00\x00" + name("a") + b"\x00\x01"
    pkt = IP(bytes(IP() / UDP(sport=4000, dport=53) / Raw(load=msg)))
    assert DNS in pkt
    assert pkt[DNS].id == 0xABCD


def _messages():
    zone = name("example", "com")
    soa = (name("ns", "example", "com") + name("host", "example", "com")
           + struct.pack("!IIIII", 1, 2, 3, 4, 5))
    rrs = [
        (1, bytes([192, 0, 2, 1])),
        (28, bytes(15) + b"\x01"),
        (2, b"\x02ns\xc0\x0c"),
        (5, name("alias", "example", "net")),
        (12, b"\x03ptr\xc0\x0c"),
        (16, b"\x05hello\x00"),
        (6, soa),
        (99, b"\xde\xad"),
    ]
    out = []
    for rtype, rdata in rrs:
        msg = (b"\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
               + zone + b"\x00\x01\x00\x01"
               + b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, 3600, len(rdata)) + rdata)
        out.append(Ether() / IP() / UDP(sport=53, dport=4000) / Raw(load=msg))
    return out


def _norm(rr):
    if isinstance(rr.rdata, list):
        return [t.decode() for t in rr.rdata]
    if isinstance(rr.rdata, bytes) and rr.type in (2, 5, 12):
        return rr.rdata.decode()
    return rr.rdata


def test_the_bulk_parse_and_the_record_objects_agree(tmp_path):
    path = str(tmp_path / "dns.pcap")
    wrpcap(path, _messages())
    pl = rdpcap(path)
    ids = pl.columns([("DNS", "id"), ("DNS", "ancount")])
    for i, pkt in enumerate(pl):
        dns = pkt[DNS]
        assert (ids["DNS.id"][i], ids["DNS.ancount"][i]) == (dns.id, dns.ancount)
        bulk = pkt._materialize().dns_records(pkt.layers().index("DNS"))
        assert bulk["qd"][0]["qname"] == dns.qd[0].qname.decode()
        b, rr = bulk["an"][0], dns.an[0]
        assert (b["rrname"], b["rtype"], b["ttl"]) == (rr.rrname.decode(), rr.type, rr.ttl)
        if isinstance(rr, DNSRRSOA):
            assert b["rdata"]["mname"] == rr.mname.decode()
            assert b["rdata"]["minimum"] == rr.minimum
        else:
            assert b["rdata"] == _norm(rr)


def test_dns_resolve_answers_from_its_cache_without_asking():
    key = b"cached.example.;\x00\x1c"
    wiry.conf.netcache.dns_cache[key] = ["hit"]
    try:
        assert wiry.dns_resolve("cached.example", qtype="AAAA") == ["hit"]
    finally:
        del wiry.conf.netcache.dns_cache[key]


@pytest.mark.parametrize("cls", [DNSRR, DNSRRMX, DNSRRSRV, DNSRRSOA, DNSRROPT])
def test_a_record_round_trips_through_its_own_octets(cls):
    rr = cls(rrname="x.example")
    assert bytes(cls(bytes(rr))) == bytes(rr)
