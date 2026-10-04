discover = (
    Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff")
    / IP(src="0.0.0.0", dst="255.255.255.255")
    / UDP(sport=68, dport=67)
    / BOOTP(chaddr=b"\xaa\xbb\xcc\xdd\xee\xff", xid=0x12345678)
    / DHCP(options=[("message-type", "discover"), "end"])
)

discover.show()
print(repr(discover))
wire = bytes(discover)
print(wire.hex())

back = Ether(wire)
print(repr(back))
print(back[BOOTP].xid, back[BOOTP].chaddr)
print(back[DHCP].options)
print(bytes(back) == wire)

offer = (
    Ether(src="11:22:33:44:55:66", dst="aa:bb:cc:dd:ee:ff")
    / IP(src="192.168.1.1", dst="192.168.1.50")
    / UDP(sport=67, dport=68)
    / BOOTP(op=2, yiaddr="192.168.1.50", siaddr="192.168.1.1",
            chaddr=b"\xaa\xbb\xcc\xdd\xee\xff", xid=0x12345678)
    / DHCP(options=[("message-type", "offer"), ("server_id", "192.168.1.1"),
                    ("lease_time", 86400), ("subnet_mask", "255.255.255.0"),
                    "end"])
)
offer.show()
print(bytes(offer).hex())
print(Ether(bytes(offer))[DHCP].options)
