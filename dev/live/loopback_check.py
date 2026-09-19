"""macOS loopback capture. Needs /dev/bpf* readable (ChmodBPF).

lo0 is DLT_NULL rather than Ethernet, which is the case ProtoId::Null exists
for and the one a Linux-only test would never reach.
"""

import sys
import time

import wiry as P
from wiry import IP, Raw, UDP


def main():
    if not P.capture_available():
        sys.exit(P.capture_backend()["reason"])
    print("backend:", P.capture_backend()["version"])

    s = P.AsyncSniffer(iface="lo0", filter="udp port 4445", count=1, timeout=5)
    s.start()
    time.sleep(0.3)

    import socket
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sk.sendto(b"wiry-lo-probe", ("127.0.0.1", 4445))
    sk.close()

    s.join()
    got = s.results
    if len(got) != 1:
        sys.exit(f"expected 1 frame, got {len(got)}")

    pkt = got[0]
    print("layers:", pkt.layers())
    if pkt.layers()[0] != "Loopback":
        sys.exit(f"lo0 should dissect as Loopback (DLT_NULL), got {pkt.layers()[0]}")
    if IP not in pkt or UDP not in pkt:
        sys.exit("the null header should be followed by IP/UDP")
    if pkt[Raw].load != b"wiry-lo-probe":
        sys.exit("payload did not survive")
    print("loopback capture works, and the DLT_NULL header dissected")


if __name__ == "__main__":
    main()
