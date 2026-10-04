pkt = (
    Ether(dst="00:11:22:33:44:55", src="66:77:88:99:aa:bb")
    / IP(src="192.168.1.10", dst="93.184.216.34", ttl=57)
    / TCP(sport=51000, dport=443, flags="S", seq=12345, window=64240)
)

print(repr(pkt))
print(pkt.summary())
pkt.show()
print()
pkt.show2()
print()
hexdump(pkt)
print(bytes(pkt).hex())
print(len(pkt))

payload = pkt / Raw(load=b"hello world")
print(repr(payload))
print(bytes(payload).hex())
