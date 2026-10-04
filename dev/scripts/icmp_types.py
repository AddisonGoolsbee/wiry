for t, c in [(0, 0), (3, 1), (3, 3), (5, 1), (8, 0), (11, 0), (13, 0)]:
    p = IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=t, code=c)
    print(p.summary())
    print(p[ICMP].type, p[ICMP].code, repr(p[ICMP]))

unreach = IP(bytes(IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=3, code=3)
                   / IP(src="10.0.0.2", dst="10.0.0.1") / UDP(sport=5000, dport=53)))
unreach.show()
print([layer.__name__ if isinstance(layer, type) else str(layer) for layer in unreach.layers()])
