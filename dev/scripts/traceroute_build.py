probes = []
for ttl in range(1, 9):
    probes.append(IP(src="192.168.1.10", dst="93.184.216.34", ttl=ttl, id=ttl)
                  / UDP(sport=33434 + ttl, dport=33434 + ttl))

for p in probes:
    print(p.summary(), len(bytes(p)), bytes(p).hex())

probes[0].show()

exceeded = (
    IP(src="10.0.0.1", dst="192.168.1.10")
    / ICMP(type=11, code=0)
    / IPerror(src="192.168.1.10", dst="93.184.216.34", ttl=1, id=1)
    / UDPerror(sport=33435, dport=33435)
)
print(repr(exceeded))
exceeded.show()
print(exceeded.answers(probes[0]))
