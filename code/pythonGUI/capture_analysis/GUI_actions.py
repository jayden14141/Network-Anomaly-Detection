import binascii

from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP
from scapy.all import *
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
import pandas as pd

from pythonGUI.capture_analysis import Packet_Capture, plotting

# import Packet_Capture
from scapy.all import *


# object with commands accessible from the user interface
class GUIActions:
    def __init__(self):
        self.captured_packets = None
        self.running = True
        self.sniffer = Packet_Capture.Sniffer()

        self.protocols = {1: "ICMP",
                          2: "IGMP",
                          6: "TCP",
                          17: "UDP",
                          58: "ICMPv6"}

    # calls method to start sniffer
    def start_sniffer(self, status, window):
        self.sniffer.run_sniffer(status, window)

    # returns sniffed packets from sniffer
    def get_sniffed_packets(self):
        return self.sniffer.sniffed_packets

    # Method to filter collected packets,
    def filter_packets(self, protocol):
        filtered_packets = []
        sniffed_packets = self.get_sniffed_packets()
        self.sniffer.set_protocol(protocol)
        # if no filter specified returns all packets
        if protocol == "":
            return sniffed_packets
        else:
            # checks if each packet has that protocol and appends to list if so
            for packet in sniffed_packets:
                if packet.haslayer(protocol):
                    filtered_packets.append(packet)
            return filtered_packets

    # Methods to read and write pcap files
    def read_pcap(self, file, window):
        self.sniffer.sniff_read(file, window)

    def write_pcap(self, filename):
        # writes each packet captured to a pcap file
        for packet in self.sniffer.sniffed_packets:
            wrpcap(filename, packet, append=True)

    # returns protocol depending on protocol number
    def get_protocol(self, protocol, packet):
        if protocol in self.protocols.keys():
            protocol_name = self.protocols[protocol]
            # packets can have UDP and DNS layers
            if protocol_name == "UDP" and packet.haslayer(DNS):
                return "UDP/DNS"
            else:
                return protocol_name
        else:
            return protocol
