requests = []
for host in range(1, 9):
    target = "192.168.1.%d" % host
    req = Ether(dst="ff:ff:ff:ff:ff:ff", src="aa:bb:cc:dd:ee:ff") / ARP(
        op=1, hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.1.100", pdst=target
    )
    requests.append(req)

for req in requests:
    print(req.summary())
print(len(requests), "requests")

requests[0].show()
print(bytes(requests[0]).hex())

reply = Ether(dst="aa:bb:cc:dd:ee:ff", src="11:22:33:44:55:66") / ARP(
    op=2, hwsrc="11:22:33:44:55:66", psrc="192.168.1.5",
    hwdst="aa:bb:cc:dd:ee:ff", pdst="192.168.1.100",
)
print(repr(reply))
print(reply[ARP].psrc, reply[ARP].hwsrc, reply[ARP].op)
print(reply.answers(requests[4]))
