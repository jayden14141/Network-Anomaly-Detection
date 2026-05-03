import matplotlib.pyplot as plt
import pandas as pd
import networkx as nx
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6

from scapy.layers.l2 import ARP, Ether
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from scapy.packet import Raw


class DataframeCreate:
    def __init__(self, data):
        self.protocols = {1: "ICMP",
                          2: "IGMP",
                          6: "TCP",
                          17: "UDP",
                          58: "ICMPv6"}
        self.data_frame = self.create_data(data)


    def create_data(self, packets):
        data = {"Number": [], "Time": [], "SourceMac": [], "DestMac": [], "IP_Version": [], "SourceIP": [], "DestIP": [], "Protocol": [], "TCP_Flags" : [], "op" : [], "hwsrc" : [], "ICMP_Type": [], "DNS_Type": [], "raw": []}
        packet_number = 1
        for packet in packets:
            data["Number"].append(packet_number)
            if packet.haslayer(IP):
                version = IP
            elif packet.haslayer(IPv6):
                version = IPv6
            else:
                version = ARP

            data["Time"].append(packet.time)
            if packet.haslayer(Ether):
                data["SourceMac"].append(packet.getlayer(Ether).src)
                data["DestMac"].append(packet.getlayer(Ether).dst)
            else:
                data["SourceMac"].append(None)
                data["DestMac"].append(None)
            if version == IP or version == IPv6:
                data["SourceIP"].append(packet.getlayer(version).src)
                data["DestIP"].append(packet.getlayer(version).dst)
                if version == IP:
                    data["IP_Version"].append("IPv4")
                    data["Protocol"].append(str(self.get_protocol(packet.getlayer(IP).proto, packet)))
                elif version == IPv6:
                    data["IP_Version"].append("IPv6")
                    data["Protocol"].append(str(self.get_protocol(packet.getlayer(IPv6).nh, packet)))
                data["op"].append(None)
                data["hwsrc"].append(None)
            elif version == ARP:
                data["SourceIP"].append(packet.getlayer(ARP).psrc)
                data["DestIP"].append(packet.getlayer(ARP).pdst)
                data["Protocol"].append("ARP")
                data["op"].append(packet.getlayer(ARP).op)
                data["hwsrc"].append(packet.getlayer(ARP).hwsrc)
                data["IP_Version"].append(None)

            if packet.haslayer(TCP):
                data["TCP_Flags"].append(packet[TCP].flags)
                if packet.haslayer(Raw):
                    data["raw"].append(packet[Raw].load)
                else:
                    data["raw"].append(None)
            else:
                data["TCP_Flags"].append(None)
                data["raw"].append(None)

            if packet.haslayer(ICMP):
                data["ICMP_Type"].append(packet[ICMP].type)
            else:
                data["ICMP_Type"].append(None)

            if packet.haslayer(DNS):
                data["DNS_Type"].append(packet[DNS].qr)
            else:
                data["DNS_Type"].append(None)



            packet_number +=1

        df = pd.DataFrame(data=data)
        return df

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
