"""The concrete answering machines, driven offline through replies_to().

Requests are hand-built from the RFCs. A reply is round-tripped through its
link layer before it is read, so a field filled at send time (E9) or a length
computed at build time is read as it goes on the wire, not as it was assigned.
"""

import ipaddress

import pytest

import wiry
from wiry import ARP, BOOTP, DHCP, DNS, DNSQR, ICMP, IP, NBNS, UDP, Ether, Raw
from wiry.answering import _nb_encode


def wire(pkt):
    return Ether(bytes(pkt))


def reply(am, req):
    out = am.replies_to([wire(req)])
    return wire(out[0]) if out else None


def dns_query(qname, qtype=1, **l):
    pkt = Ether(src=l.get("esrc", "aa:aa:aa:aa:aa:aa"),
                dst=l.get("edst", "bb:bb:bb:bb:bb:bb"))
    pkt = pkt / IP(src=l.get("src", "127.0.0.1"), dst=l.get("dst", "127.0.0.2"),
                   ttl=l.get("ttl", 64))
    pkt = pkt / UDP(sport=l.get("sport", 1234), dport=l.get("dport", 53))
    return pkt / DNS(qd=[DNSQR(qname=qname, qtype=qtype)])


# ------------------------------------------------------------------- ARP


def test_arp_am_answers_for_address():
    am = wiry.ARP_am(IP_addr="10.28.7.1", ARP_addr="00:01:02:03:04:05")
    am.optsend = {"iface": "x"}
    r = reply(am, Ether() / ARP(pdst="10.28.7.1"))
    assert r[ARP].op == 2
    assert r[ARP].psrc == "10.28.7.1"
    assert r[ARP].hwsrc == "00:01:02:03:04:05"


def test_arp_am_ignores_wrong_address_and_non_request():
    am = wiry.ARP_am(IP_addr="10.28.7.1")
    am.optsend = {"iface": "x"}
    assert not am.is_request(Ether() / ARP(op=1, pdst="10.0.0.9"))
    assert not am.is_request(Ether() / ARP(op=2, pdst="10.28.7.1"))


def test_arp_am_published_as_farpd():
    assert callable(wiry.farpd)


# ------------------------------------------------------------------ ICMP


def test_icmpecho_am_swaps_addresses_and_echoes():
    req = Ether(src="aa:aa:aa:aa:aa:aa", dst="ff:ff:ff:ff:ff:ff") \
        / IP(src="1.1.1.1", dst="2.2.2.2") / ICMP(seq=12, id=7) / Raw(load=b"ping")
    r = reply(wiry.ICMPEcho_am(), req)
    assert r[ICMP].type == 0
    assert r[ICMP].seq == 12 and r[ICMP].id == 7
    assert r[IP].src == "2.2.2.2" and r[IP].dst == "1.1.1.1"
    assert r[Ether].dst == "aa:aa:aa:aa:aa:aa"
    # Arrived broadcast, so the source is left for the interface to fill (E9).
    assert r[Ether].src == "00:00:00:00:00:00"
    assert bytes(r[Raw].load).endswith(b"ping")


def test_icmpecho_am_ignores_reply():
    assert not wiry.ICMPEcho_am().is_request(
        Ether() / IP() / ICMP(type=0))


# ------------------------------------------------------------ BOOTP/DHCP


def bootp_request(mac="02:00:00:00:00:01"):
    return Ether(src=mac) / IP() / UDP(sport=68, dport=67) / BOOTP(op=1)


def test_bootp_am_assigns_from_pool():
    am = wiry.BOOTP_am(verbose=False)
    r = reply(am, bootp_request())
    assert r[BOOTP].op == 2
    assert r[BOOTP].yiaddr == "192.168.1.128"
    assert r[BOOTP].giaddr == "192.168.1.1"


def test_bootp_am_one_lease_per_mac():
    am = wiry.BOOTP_am(pool=["192.168.1.128", "192.168.1.129"], verbose=False)
    first = am.make_reply(wire(bootp_request("02:00:00:00:00:01")))
    again = am.make_reply(wire(bootp_request("02:00:00:00:00:01")))
    assert first[BOOTP].yiaddr == again[BOOTP].yiaddr


def test_bootp_am_pool_exhausted_returns_none():
    am = wiry.BOOTP_am(pool=["192.168.1.128", "192.168.1.129"], verbose=False)
    for i in range(2):
        assert am.make_reply(wire(bootp_request("02:00:00:00:00:0%d" % i))) is not None
    assert am.make_reply(wire(bootp_request("02:00:00:00:00:02"))) is None


def test_dhcp_am_carries_options():
    am = wiry.DHCP_am(domain="localnet")
    req = Ether() / IP() / UDP(sport=68, dport=67) / BOOTP(op=1) \
        / DHCP(options=[("message-type", "request")])
    r = reply(am, req)
    opts = dict((o[0], o[1]) for o in r[DHCP].options if isinstance(o, tuple))
    assert opts["message-type"] == 5  # a request is answered with an ack
    assert "domain" in opts and "server_id" in opts
    assert opts["lease_time"] == 1800


def test_dhcp_am_discover_gets_offer():
    am = wiry.DHCP_am()
    req = Ether() / IP() / UDP(sport=68, dport=67) / BOOTP(op=1) \
        / DHCP(options=[("message-type", "discover")])
    r = reply(am, req)
    mt = next(o[1] for o in r[DHCP].options if o[0] == "message-type")
    assert mt == 2  # offer


# -------------------------------------------------------------- DNS kin


def test_dns_am_answers_a_query():
    am = wiry.DNS_am(joker="192.168.1.1")
    r = reply(am, dns_query(b"www.secdev.org."))
    assert r[DNS].ancount == 1
    assert r[DNS].an[0].rdata == "192.168.1.1"
    assert r[DNS].qd[0].qname == b"www.secdev.org."
    assert r[IP].src == "127.0.0.2" and r[IP].dst == "127.0.0.1"
    # The answer's owner name points back at the question (RFC 1035 §4.1.4).
    assert bytes(r[DNS]).count(b"\x03www\x06secdev\x03org\x00") == 1


def test_dns_am_match_table():
    am = wiry.DNS_am(match={"google.com": ("127.0.0.1", "::1")})
    r4 = reply(am, dns_query(b"google.com.", 1))
    assert r4[DNS].an[0].rdata == "127.0.0.1"
    r6 = reply(am, dns_query(b"google.com.", 28))
    assert r6[DNS].an[0].rdata == "::1"


def test_dns_am_srv():
    am = wiry.DNS_am(srvmatch={"_ldap._tcp.scapy.fr": (389, "dc.scapy.fr")})
    r = reply(am, dns_query(b"_ldap._tcp.scapy.fr.", 33))
    an = r[DNS].an[0]
    assert an.type == 33
    assert an.port == 389
    assert an.target == b"dc.scapy.fr."


def test_dns_am_ptr_arpa():
    am = wiry.DNS_am(jokerarpa="scapy")
    r = reply(am, dns_query(b"1.0.16.172.in-addr.arpa.", 12))
    assert r[DNS].an[0].rdata == b"scapy."
    assert r[DNS].an[0].rrname == b"1.0.16.172.in-addr.arpa."


def test_dns_am_no_answer_is_silent():
    am = wiry.DNS_am(joker=False)
    assert am.replies_to([wire(dns_query(b"nope.example.", 1))]) == []


def test_dns_am_unknown_names_not_cached():
    am = wiry.DNS_am(joker=False)
    for i, qt in enumerate((1, 28)):
        am.make_reply(wire(dns_query(("u-%d.example." % i).encode(), qt)))
    assert not am.match


def test_dns_am_malformed_requests_return_none():
    assert wiry.DNS_am().make_reply(Ether()) is None
    assert wiry.DNS_am().make_reply(Ether() / IP()) is None
    assert wiry.DNS_am().make_reply(Ether() / IP() / UDP()) is None


def test_dns_am_relay_answers_from_the_resolver_cache():
    from wiry.layers.dns import DNSRR

    resolved = DNS(qr=1, an=[DNSRR(rrname="relayed.example.", rdata="10.9.8.7")])
    wiry.conf.netcache.dns_cache[b"relayed.example.;\x00\x01;raw"] = resolved
    try:
        am = wiry.DNS_am(relay=True, joker=False)
        r = reply(am, dns_query(b"relayed.example.", 1))
    finally:
        del wiry.conf.netcache.dns_cache[b"relayed.example.;\x00\x01;raw"]
    assert r[DNS].an[0].rdata == "10.9.8.7"


def test_llmnr_am_scopes_to_link_multicast():
    am = wiry.LLMNR_am(ttl=60, match={"TEST": "192.168.1.1"})
    good = dns_query(b"TEST.", 1, src="192.168.0.1", dst="224.0.0.252",
                     ttl=1, sport=51938, dport=5355,
                     edst="01:00:5e:00:00:fc", esrc="aa:aa:aa:aa:aa:aa")
    r = reply(am, good)
    assert r[UDP].sport == 5355 and r[UDP].dport == 51938
    assert r[DNS].ancount == 1 and r[DNS].qdcount == 1
    assert r[DNS].an[0].rdata == "192.168.1.1"
    assert r[DNS].an[0].ttl == 60
    # LLMNR is not compressed (RFC 4795 §2.1.1).
    assert b"\x04TEST\x00\x00\x01" in bytes(r[DNS])
    assert r[Ether].dst == "aa:aa:aa:aa:aa:aa"
    # A routed query (ttl != 1) or a unicast one is not answered (RFC 4795).
    routed = dns_query(b"TEST.", 1, dst="224.0.0.252", ttl=42, dport=5355)
    assert not am.is_request(wire(routed))


def test_mdns_am_answers_without_question():
    am = wiry.mDNS_am(joker="192.168.1.1")
    q = dns_query(b"TEST.local.", 1, src="192.168.0.1", dst="224.0.0.251",
                  ttl=1, sport=5353, dport=5353, edst="01:00:5e:00:00:fb")
    r = reply(am, q)
    assert r[IP].dst == "224.0.0.251" and r[IP].ttl == 255
    assert r[UDP].sport == 5353 and r[UDP].dport == 5353
    assert r[DNS].ancount == 1 and r[DNS].qdcount == 0
    assert r[DNS].an[0].rrname == b"TEST.local."
    assert r[DNS].an[0].ttl == 10
    assert r[DNS].an[0].cacheflush == 1


def test_mdns_am_negative_answer_lists_the_types_held():
    # RFC 6762 §6.1: the NSEC bit map names the types that exist, so an ALL
    # query for a name with only an A record draws A plus an NSEC saying A.
    from wiry.layers.dns import bitmap2RRlist

    am = wiry.mDNS_am(match={"TEST.local": "192.168.1.1"})
    q = dns_query(b"TEST.local.", 255, dst="224.0.0.251", ttl=1, dport=5353)
    r = reply(am, q)
    nsec = [x for x in r[DNS].an if x.type == 47]
    assert len(nsec) == 1
    assert bitmap2RRlist(nsec[0].typebitmaps) == [1]


def test_mdns_am_nsec_only_is_discarded():
    # An AAAA query for a name with only an A record draws a lone NSEC, which
    # RFC 6762 §6.1 says to withhold.
    am = wiry.mDNS_am(match={"TEST.local": "192.168.1.1"})
    q = dns_query(b"TEST.local.", 28, dst="224.0.0.251", ttl=1, dport=5353)
    assert am.replies_to([wire(q)]) == []


# ------------------------------------------------------------------ NBNS


def nbns_query(name=b"test"):
    body = _nb_encode(name) + b"\x00\x20\x00\x01"
    return Ether(src="aa:aa:aa:aa:aa:aa", dst="ff:ff:ff:ff:ff:ff") \
        / IP(src="1.2.3.4") / UDP(sport=137, dport=137) \
        / NBNS(NAME_TRN_ID=0x1234, FLAGS=0x0110, QDCOUNT=1) / Raw(load=body)


def nbns_reply_fields(r):
    body = r._materialize().payload(r.layers().index("NBNS"))
    length = body[0]
    enc = body[1:1 + length]
    name = bytes(((enc[2 * i] - 0x41) << 4) | (enc[2 * i + 1] - 0x41)
                 for i in range(len(enc) // 2)).rstrip(b" \x00")
    addr = str(ipaddress.IPv4Address(body[-4:]))
    return name, addr


def test_nbns_am_answers_query():
    am = wiry.NBNS_am(ip="9.8.7.6")
    r = reply(am, nbns_query(b"test"))
    assert r[NBNS].NAME_TRN_ID == 0x1234
    assert r[NBNS].FLAGS == 0x8500 and r[NBNS].ANCOUNT == 1
    assert r[Ether].dst == "aa:aa:aa:aa:aa:aa"
    name, addr = nbns_reply_fields(r)
    assert name == b"test" and addr == "9.8.7.6"


def test_nbns_am_server_name_filter():
    am = wiry.NBNS_am(server_name="other", ip="9.8.7.6")
    assert not am.is_request(wire(nbns_query(b"test")))
    assert am.is_request(wire(nbns_query(b"other")))


def test_nbns_am_non_ascii_name():
    am = wiry.NBNS_am(server_name=b"\x85", ip="9.8.7.6")
    r = reply(am, nbns_query(b"\x85"))
    name, _ = nbns_reply_fields(r)
    assert name == b"\x85"
