pkts = rdpcap(PCAP)
out = WORKDIR + "/roundtrip.pcap"

wrpcap(out, pkts)
again = rdpcap(out)

print(len(pkts), len(again))
identical = [bytes(a) == bytes(b) for a, b in zip(pkts, again)]
print("identical:", identical)
print("all identical:", all(identical))

for a, b in zip(pkts, again):
    print(a.summary(), "|", b.summary())

digest = b"".join(bytes(p) for p in again)
print(len(digest), digest[:32].hex())
