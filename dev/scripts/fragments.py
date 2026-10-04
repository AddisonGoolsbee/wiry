big = IP(src="10.0.0.1", dst="10.0.0.2", id=4242) / UDP(sport=1000, dport=2000) / Raw(load=b"A" * 3000)
frags = fragment(big, fragsize=1000)
print(len(frags))
for f in frags:
    print(f.summary(), f[IP].flags, f[IP].frag, len(f))

whole = defragment(frags)
print(len(whole))
print(whole[0].summary())
print(bytes(whole[0]) == bytes(IP(bytes(big))))
print(whole[0][IP].len, len(whole[0][Raw].load))
