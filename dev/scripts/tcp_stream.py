pkts = rdpcap(PCAP)

flows = {}
for p in pkts:
    if not p.haslayer(TCP):
        continue
    key = (p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport)
    flows.setdefault(key, []).append(p)

for key in sorted(flows, key=str):
    print(key, len(flows[key]))

chosen = sorted(flows, key=str)[0]
stream = b""
for p in sorted(flows[chosen], key=lambda q: q[TCP].seq):
    if p.haslayer(Raw):
        stream += bytes(p[Raw].load)
print("reassembled:", repr(stream))

for p in pkts:
    if p.haslayer(TCP):
        print(p[TCP].flags, p[TCP].seq, p[TCP].ack, p[TCP].window,
              p[TCP].dataofs)
