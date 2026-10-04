pkts = rdpcap(PCAP)

for p in pkts:
    names = [layer.__name__ if isinstance(layer, type) else str(layer)
             for layer in p.layers()]
    print(" / ".join(names))
    print("  Ether:", p.haslayer(Ether), " IP:", p.haslayer(IP),
          " TCP:", p.haslayer(TCP), " UDP:", p.haslayer(UDP))
    if p.haslayer(IP):
        ip = p.getlayer(IP)
        print("  ip", ip.src, ip.dst, ip.ttl, ip.proto, ip.len, ip.id)
    print("  name:", p.name, " lastlayer:", p.lastlayer().name)
    print("  sprintf:", p.sprintf("%Ether.src% -> %Ether.dst%"))

deep = Ether() / Dot1Q(vlan=10) / IP(src="1.1.1.1", dst="2.2.2.2") / UDP() / Raw(load=b"x")
print(repr(deep))
print([layer.__name__ if isinstance(layer, type) else str(layer)
       for layer in deep.layers()])
print(deep[Dot1Q].vlan, deep[UDP].sport)
