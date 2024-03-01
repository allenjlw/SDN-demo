import sys
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.all import sendp, send

if __name__ == '__main__':
    srcMac = sys.argv[1]
    dstMac = sys.argv[2]
    srcIP = sys.argv[3]
    dstIP = sys.argv[4]
    proto = sys.argv[5]
    intf = sys.argv[6]
    pkt = Ether(type=0x0800, src=srcMac, dst=dstMac)/IP(dst=dstIP, src=srcIP, proto=int(proto))/"Payload"
    sendp(pkt, iface=intf)