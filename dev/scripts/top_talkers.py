from collections import Counter

pkts = rdpcap(PCAP)
talkers = Counter()
protos = Counter()
for p in pkts:
    if IP in p:
        talkers[(p[IP].src, p[IP].dst)] += 1
        protos[p[IP].proto] += 1
    elif IPv6 in p:
        talkers[(p[IPv6].src, p[IPv6].dst)] += 1
    else:
        protos[p.lastlayer().name] += 1

for (src, dst), n in sorted(talkers.items()):
    print("%-15s -> %-15s %d" % (src, dst, n))
print(sorted(protos.items(), key=str))
print("bytes:", sum(len(p) for p in pkts))
print("tcp:", len([p for p in pkts if TCP in p]), "udp:", len([p for p in pkts if UDP in p]))
print("first:", pkts[0].time, "last:", pkts[-1].time, "span:", pkts[-1].time - pkts[0].time)
