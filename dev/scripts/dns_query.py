query = (
    IP(src="192.168.1.10", dst="8.8.8.8")
    / UDP(sport=40000, dport=53)
    / DNS(id=4242, rd=1, qd=DNSQR(qname="www.example.com", qtype="A"))
)

query.show()
print(repr(query))
print(bytes(query).hex())

wire = bytes(query)
again = IP(wire)
print(repr(again))
print(again[DNS].qd.qname)
print(again[DNS].id, again[DNS].qdcount, again[DNS].rd)
print(bytes(again) == wire)

pkts = rdpcap(PCAP)
answers = [p for p in pkts if p.haslayer(DNS) and p[DNS].qr == 1]
for p in answers:
    p[DNS].show()
    print(p[DNS].an.rrname, p[DNS].an.rdata)
