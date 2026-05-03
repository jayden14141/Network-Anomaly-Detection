# code by Jayden

# Example use of the library pypcap 
# (Capturing the packet in a network and printing its source and destination MAC address)

# Prerequisites - install pypcap in terminal by typing:
# pip install pypcap / pip3 install pypcap
# (Dependency => libpcap-dev) if not installed, apt-get install libpcap-dev first

# Imports pcap library
import pcap
import socket
import re

# Initialises the sniffer object
sniffer = pcap.pcap(name=None, promisc=True, immediate=True, timeout_ms=50)

# ts for timestamp
# pkt for packet
for ts, pkt in sniffer:
    print('Dst MAC :', end='', flust=True)
    # Prints Packet data from 0 to 5 bytes
    print(':'.join('%02X' % i for i in pkt[0:6]))
    print('Src Mac :', end='', flush=True)
    # Prints Packet data from 6 to 11 bytes
    print(':'.join('%02X' % i for i in pkt[6:12]))
    print()