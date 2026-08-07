from scapy.all import IP, TCP, wrpcap

pakety = []

for i in range(120):
    pkt = IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=10000 + i, dport=80, flags="S")
    pakety.append(pkt)

for i in range(2):
    pkt = IP(src="10.0.0.1", dst="192.168.1.100") / TCP(sport=80, dport=10000 + i, flags="R")
    pakety.append(pkt)

wrpcap("synflood.cap", pakety)
print("done")
