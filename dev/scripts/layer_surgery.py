pkt = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1, dport=2) / Raw(load=b"payload")

ip = pkt[IP].copy()
print(repr(ip))
print(repr(pkt.payload))
print(repr(pkt[TCP].payload))

stripped = pkt.copy()
stripped[TCP].remove_payload()
print(repr(stripped))
print(len(stripped), len(pkt))

print(pkt.getlayer(TCP).dport, pkt.getlayer(2).name, pkt.getlayer(Raw).load)
print(pkt.haslayer(UDP), UDP in pkt, TCP in pkt)
print(pkt.firstlayer().name, pkt.lastlayer().name)

other = Ether(bytes(pkt))
print(bytes(other) == bytes(pkt))
print(other[IP].src, other[TCP].sport, other[Raw].load)

swapped = IP(src=pkt[IP].dst, dst=pkt[IP].src) / TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags="R")
print(repr(swapped))
print(swapped.summary())
