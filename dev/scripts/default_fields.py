print(repr(IP()))
print(repr(TCP()))
print(repr(UDP()))
print(repr(ICMP()))
print(repr(IP() / TCP()))
print(repr(IP() / TCP() / "GET / HTTP/1.0\r\n\r\n"))
print(repr(IP(proto=55) / TCP()))

a = IP(ttl=10)
print(repr(a))
a.dst = "192.168.1.1"
print(repr(a))
del a.ttl
print(repr(a))
print(a.ttl)

print(repr(IP().default_fields if hasattr(IP(), "default_fields") else None))
print(IP().version, IP().ihl, IP().proto, IP().flags)
print(TCP().dataofs, TCP().flags, TCP().window, TCP().seq)

c = IP(bytes(IP(dst="10.9.8.7") / TCP(dport=443)))
print(repr(c))
c.hide_defaults()
print(repr(c))
