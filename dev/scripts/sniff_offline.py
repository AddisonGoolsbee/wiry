seen = []


def note(p):
    seen.append(p.summary())
    print("saw:", p.summary())


capture = sniff(offline=PCAP, prn=note)
print("count:", len(capture))
print("noted:", len(seen))

tcp_only = sniff(offline=PCAP, filter="tcp", count=3)
print("tcp:", len(tcp_only))
for p in tcp_only:
    print(" ", p.summary())

picked = sniff(offline=PCAP, lfilter=lambda p: p.haslayer(UDP))
print("udp:", len(picked))
for p in picked:
    print(" ", p.summary())
