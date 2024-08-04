#! /usr/bin/python

import socket
import sys

from struct import *



def ip():
    if len(sys.argv) > 4:
        src = sys.argv[1]
        dst = sys.argv[2]
        proto = int(sys.argv[3])
        x   = int(sys.argv[4])

        sendsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sendsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sendsock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # ip header fielss
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tos_len = 0 # Kernal will fill the correct total length
        ip_id = 54321  # ID of this packet
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = proto
        ip_check = 0 # Kernal will fill the correct checksum
        ip_saddr = socket.inet_aton ( src ) # spoof the source ip if u want to
        ip_daddr = socket.inet_aton ( dst )

        ip_ihl_ver = (ip_ver << 4) + ip_ihl

        # packing the ip header
        # the ! in the pack format string means network order
        ip_header = pack("!BBHHHBBH4s4s" , ip_ihl_ver, ip_tos, ip_tos_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
        packet = ip_header
       
       # Request Sending
    for i in range(x):
        sendsock.sendto(packet, (dst , 0))




if __name__ == "__main__":
    ip()

