pkt = Ether(dst="00:11:22:33:44:55", src="66:77:88:99:aa:bb") / IP(
    src="10.0.0.1", dst="10.0.0.2"
) / TCP(sport=1234, dport=80, flags="S")

before = bytes(pkt)
print(repr(pkt))
print(before.hex())

pkt[IP].dst = "192.168.9.9"
pkt[IP].ttl = 12
pkt[TCP].dport = 8080
pkt[TCP].flags = "SA"

after = bytes(pkt)
print(repr(pkt))
print(after.hex())
print(len(before), len(after), before == after)

pkt.show()

dissected = Ether(after)
print(dissected[IP].dst, dissected[IP].ttl, dissected[TCP].dport)
print(dissected[TCP].flags, str(dissected[TCP].flags))
print(hex(dissected[IP].chksum), hex(dissected[TCP].chksum))
