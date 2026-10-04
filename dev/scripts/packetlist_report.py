pkts = rdpcap(PCAP)

print(repr(pkts))
pkts.nsummary()
print(len(pkts))

tcp = pkts.filter(lambda p: p.haslayer(TCP))
print(repr(tcp))
print(len(tcp))

sessions = pkts.sessions()
for key in sorted(sessions):
    print(key, len(sessions[key]))

sliced = pkts[2:5]
print(repr(sliced))
for p in sliced:
    print(" ", p.summary())

print(pkts[0].sprintf("%IP.src% %IP.dst% %IP.proto%"))
print([p.sprintf("%IP.src%") for p in pkts if p.haslayer(IP)])
