pkts = rdpcap(PCAP)

hosts = []
for p in pkts:
    if not p.haslayer(Raw):
        continue
    body = bytes(p[Raw].load)
    if not body.startswith(b"GET") and not body.startswith(b"POST"):
        continue
    for line in body.split(b"\r\n"):
        if line.lower().startswith(b"host:"):
            hosts.append(line.split(b":", 1)[1].strip().decode())

print("hosts:", hosts)

for p in pkts:
    if p.haslayer(Raw):
        print(p[IP].src, "->", p[IP].dst, repr(p[Raw].load))

crafted = (
    IP(src="10.1.1.1", dst="10.1.1.2")
    / TCP(sport=40000, dport=80, flags="PA", seq=1, ack=1)
    / Raw(load=b"POST /submit HTTP/1.1\r\nHost: api.example.org\r\n\r\nx=1")
)
crafted.show()
print(bytes(crafted).hex())
print(repr(crafted[Raw].load))
