pkts = rdpcap(PCAP)
print("packets:", len(pkts))

for p in pkts:
    print(p.summary())

print()
pkts[0].show()

first = pkts[0]
lengths = [len(bytes(p)) for p in pkts]
print("total bytes:", sum(lengths))
print("lengths:", lengths)
