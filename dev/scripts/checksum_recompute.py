pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=2)
print(pkt[IP].chksum, pkt[TCP].chksum)

wire = bytes(pkt)
back = IP(wire)
print(hex(back[IP].chksum), hex(back[TCP].chksum))
print(back[IP].len, back[IP].ihl, back[TCP].dataofs)

del back[IP].chksum
del back[TCP].chksum
print(back[IP].chksum, back[TCP].chksum)
print(bytes(back) == wire)

udp = IP(src="1.2.3.4", dst="5.6.7.8") / UDP(sport=9, dport=10) / Raw(load=b"abc")
built = bytes(udp)
print(built.hex())
print(hex(IP(built)[UDP].chksum), IP(built)[UDP].len)

icmp = IP(src="1.1.1.1", dst="2.2.2.2") / ICMP(id=7, seq=3) / Raw(load=b"ping")
print(bytes(icmp).hex())
print(hex(IP(bytes(icmp))[ICMP].chksum))
