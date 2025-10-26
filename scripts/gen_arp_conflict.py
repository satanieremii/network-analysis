from scapy.all import Ether, ARP, wrpcap
import os
outdir = "/captures"
os.makedirs(outdir, exist_ok=True)
out = os.path.join(outdir, "arp_conflict.pcap")
ip = "172.18.0.5"
pkts = []
macs = ["00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"]
for mac in macs:
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac)/ARP(op=2, psrc=ip, hwsrc=mac, pdst=ip, hwdst="ff:ff:ff:ff:ff:ff")
    pkts.append(pkt)
wrpcap(out, pkts)
print("Saved", out)
