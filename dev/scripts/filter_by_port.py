pkts = rdpcap(PCAP)

tcp_ports = {}
udp_ports = {}
for p in pkts:
    if p.haslayer(TCP):
        port = p[TCP].dport
        tcp_ports[port] = tcp_ports.get(port, 0) + 1
    elif p.haslayer(UDP):
        port = p[UDP].dport
        udp_ports[port] = udp_ports.get(port, 0) + 1

print("tcp destination ports")
for port in sorted(tcp_ports):
    print("  %5d  %d" % (port, tcp_ports[port]))
print("udp destination ports")
for port in sorted(udp_ports):
    print("  %5d  %d" % (port, udp_ports[port]))

web = [p for p in pkts if p.haslayer(TCP) and p[TCP].dport == 80]
print("port 80 packets:", len(web))
for p in web:
    print(" ", p[IP].src, "->", p[IP].dst, p[TCP].flags)
