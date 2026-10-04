resp = (
    IP(src="8.8.8.8", dst="10.0.0.3")
    / UDP(sport=53, dport=33333)
    / DNS(id=99, qr=1, aa=0, rd=1, ra=1,
          qd=DNSQR(qname="example.com", qtype="A"),
          an=DNSRR(rrname="example.com", type="A", ttl=300, rdata="93.184.216.34")
          / DNSRR(rrname="example.com", type="A", ttl=300, rdata="93.184.216.35"))
)
resp.show()
wire = bytes(resp)
print(wire.hex())

back = IP(wire)
dns = back[DNS]
print(dns.id, dns.qr, dns.ancount, dns.qdcount)
print(dns.qd.qname, dns.qd.qtype)
for i in range(dns.ancount):
    rr = dns.an[i]
    print(rr.rrname, rr.type, rr.ttl, rr.rdata)
print(back.summary())
