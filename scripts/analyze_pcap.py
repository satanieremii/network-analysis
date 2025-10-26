#!/usr/bin/env python3
from collections import defaultdict
import sys
try:
    from scapy.all import rdpcap, ARP, IP, TCP
except Exception:
    print("Install scapy: pip3 install scapy")
    raise

if len(sys.argv) < 2:
    print("Usage: python3 analyze_pcap.py <pcap>")
    sys.exit(1)

cap = sys.argv[1]
pkts = rdpcap(cap)

ip_to_macs = defaultdict(set)
ip_pktcount = defaultdict(int)
syn_count = defaultdict(int)

for p in pkts:
    if p.haslayer(ARP):
        arp = p.getlayer(ARP)
        ip_to_macs[arp.psrc].add(arp.hwsrc)
    if p.haslayer(IP):
        ip_pktcount[p[IP].src] += 1
        if p.haslayer(TCP):
            t = p[TCP]
            if t.flags & 0x02:
                syn_count[p[IP].src] += 1

print("\\nARP: IP -> MACs (entries with >1 MAC shown)")
for ip, macs in ip_to_macs.items():
    if len(macs) > 1:
        print(f"{ip} -> {macs}")

print("\\nTop talkers by packet count:")
for ip, c in sorted(ip_pktcount.items(), key=lambda x: x[1], reverse=True)[:20]:
    print(f"{ip}: {c} packets, SYNs: {syn_count.get(ip,0)}")

if len(ip_pktcount) >= 2:
    top = sorted(ip_pktcount.values(), reverse=True)
    if top[0] > 3 * (top[1] if len(top) > 1 else 1):
        print("\\nPossible anomaly: one host sends much more packets than others")
