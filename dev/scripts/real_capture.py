from collections import Counter

pkts = rdpcap(REAL_PCAP)
print(len(pkts))
print(repr(pkts))

chains = Counter("/".join(l.__name__ if isinstance(l, type) else str(l)
                          for l in p.layers()) for p in pkts)
for chain, n in sorted(chains.items()):
    print(n, chain)

for p in pkts[:40]:
    print(p.summary())

ports = Counter()
for p in pkts:
    if TCP in p:
        ports[p[TCP].dport] += 1
print(sorted(ports.items())[:20])

names = [p[DNSQR].qname for p in pkts if p.haslayer(DNSQR)]
print(names[:20])
pkts[0].show()
