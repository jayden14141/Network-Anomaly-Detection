import matplotlib.pyplot as plt
import pandas as pd
import networkx as nx
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas

from pythonGUI.capture_analysis import dataframe_create


class Plotting:
    def __init__(self, data):
        dataframe_creator = dataframe_create.DataframeCreate(data)
        self.data_frame = dataframe_creator.data_frame

    # Plots protocol frequency
    def plot_protocol(self):
        fig = plt.figure()
        df_p = self.data_frame['Protocol'].value_counts().rename_axis("Protocols")
        df_p = df_p.plot(kind="barh")
        df_p.bar_label(df_p.containers[-1], label_type='edge')
        df_p.set_title("Protocol Frequency")
        df_p.set_xlabel("Frequency")
        canvas = FigureCanvas(fig)
        return canvas

    # Plots network address map for ipv4 addresses
    def ipv4_network_graph(self):
        fig = plt.figure()

        ipv4_addresses = self.data_frame[self.data_frame["IP_Version"] == "IPv4"]
        # uses connections between source ip and destination ip to form edges
        network = nx.from_pandas_edgelist(ipv4_addresses, source='SourceIP', target='DestIP')
        nx.draw_circular(network, with_labels=True)

        canvas = FigureCanvas(fig)
        return canvas

    # Plots network address map for ipv6 addresses
    def ipv6_network_graph(self):
        fig = plt.figure()

        ipv4_addresses = self.data_frame[self.data_frame["IP_Version"] == "IPv6"]
        network = nx.from_pandas_edgelist(ipv4_addresses, source='SourceIP', target='DestIP')
        nx.draw_circular(network, with_labels=True)

        canvas = FigureCanvas(fig)
        return canvas

    # Plots mac address map
    def mac_network_graph(self):
        fig = plt.figure()
        network = nx.from_pandas_edgelist(self.data_frame, source="SourceMac", target="DestMac")
        nx.draw_circular(network, with_labels=True)
        canvas = FigureCanvas(fig)
        return canvas

    # plots frequency of source addresses
    def plot_source(self):
        fig = plt.figure()
        df_p = self.data_frame['SourceIP'].value_counts()
        df_p = df_p.plot(kind="barh")
        df_p.set_title("IP Source Frequency")
        df_p.set_xlabel("Frequency")
        canvas = FigureCanvas(fig)
        return canvas

    # plots of destination addresses
    def plot_dest(self):
        fig = plt.figure()
        df_p = self.data_frame['DestIP'].value_counts()
        df_p = df_p.plot(kind="barh")
        df_p.set_title("IP Destination Frequency")
        df_p.set_xlabel("Frequency")
        canvas = FigureCanvas(fig)
        return canvas

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
