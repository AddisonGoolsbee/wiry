echo = IPv6(src="2001:db8::1", dst="2001:db8::2") / ICMPv6EchoRequest(id=1, seq=7, data=b"ping")
print(echo.summary())
echo.show()
print(bytes(echo).hex())

back = IPv6(bytes(echo))
print(repr(back))
print(back[IPv6].nh, back[IPv6].plen, back[IPv6].hlim)
print(hex(back[ICMPv6EchoRequest].cksum))

ns = (
    Ether(src="aa:bb:cc:dd:ee:ff", dst="33:33:ff:00:00:02")
    / IPv6(src="fe80::1", dst="ff02::1:ff00:2")
    / ICMPv6ND_NS(tgt="fe80::2")
    / ICMPv6NDOptSrcLLAddr(lladdr="aa:bb:cc:dd:ee:ff")
)
ns.show2()
print(Ether(bytes(ns)).summary())

reply = IPv6(src="2001:db8::2", dst="2001:db8::1") / ICMPv6EchoReply(id=1, seq=7, data=b"ping")
print(reply.answers(echo))
