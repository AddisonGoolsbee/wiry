pkts = rdpcap(PCAP)
for p in pkts:
    print(p.sprintf("%.time% {IP:%IP.src% -> %IP.dst%}{ARP:ARP %ARP.psrc% asks for %ARP.pdst%}"))
    print(p.sprintf("{TCP:%TCP.sport% > %TCP.dport% %TCP.flags%}{UDP:udp %UDP.sport% > %UDP.dport%}"))

p = pkts[0]
print(p.sprintf("%Ether.src% %IP.ttl% %TCP.flags%"))
print(p.sprintf("%IP.proto% %r,IP.proto% %TCP.window%"))
print(p.sprintf("%-15s,IP.src%|%5s,TCP.dport%|"))
