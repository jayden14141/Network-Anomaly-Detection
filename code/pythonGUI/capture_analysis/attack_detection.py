import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import networkx as nx
import scapy
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from pythonGUI.capture_analysis import dataframe_create


# small object used to create embedded graphs onto GUI
class ImbeddedCanvas(FigureCanvas):
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        fig = Figure(figsize=(width, height), dpi=dpi)
        self.axes = fig.add_subplot(111)
        super(ImbeddedCanvas, self).__init__(fig)


class AttackDetection:
    def __init__(self, data, flagged_IPs):

        self.arp_suspicious_addresses = None
        self.icmp_suspicious = None
        self.dns_response_suspicious = None
        self.dns_request_suspicious = None
        self.dos_suspicious_addresses = None
        self.http_suspicious = None
        self.tcp_suspicious_addresses = None
        self.tcp_scanning_suspicious = None

        self.quarantined_packets = None
        dataframe_creator = dataframe_create.DataframeCreate(data)
        self.dataframe = dataframe_creator.data_frame

        self.blocked_addresses = []
        self.suspicious_addresses = flagged_IPs
        self.attacked_addresses = []
        self.packets = data

    def update_flagged_ips(self, ips):
        for ip in ips:
            if ip not in self.suspicious_addresses:
                self.suspicious_addresses.append(ip)

    def tcp_syn_flood_detect(self):
        # creates canvas
        canvas = ImbeddedCanvas(self)

        # initialises suspicious address lists
        self.tcp_suspicious_addresses = []
        self.attacked_addresses = []

        # filters non-TCP packets out of dataframe
        tcp_packets = pd.DataFrame(self.dataframe[self.dataframe['Protocol'] == 'TCP'])

        # Returns None is no tcp packets are present
        if tcp_packets.empty:
            return None

        # dataframe with SYN packets
        tcp_syn_packets = pd.DataFrame(
            tcp_packets[tcp_packets["TCP_Flags"].apply(lambda x: True if str(x).find('S') != -1 else False)])

        # dataframe with syn-ack packets
        tcp_syn_ack_packets = pd.DataFrame(
            tcp_packets[tcp_packets["TCP_Flags"].apply(lambda x: True if str(x).find('SA') != -1 else False)])

        if tcp_syn_packets.empty or tcp_syn_ack_packets.empty:
            return None

        # addresses of syn and syn-ack packets
        syn_sources_addresses = pd.Series(tcp_syn_packets['SourceIP'])
        syn_ack_source_addresses = pd.Series(tcp_syn_ack_packets['SourceIP'])

        syn_dest_addresses = pd.Series(tcp_syn_packets['DestIP'])
        syn_ack_dest_addresses = pd.Series(tcp_syn_ack_packets['DestIP'])

        # concatenation of frequency of addresses
        syn_addresses = pd.concat([syn_sources_addresses.value_counts(), syn_dest_addresses.value_counts(),
                                   syn_ack_source_addresses.value_counts(), syn_ack_dest_addresses.value_counts()],
                                  axis=1).reset_index()
        syn_addresses.columns = ['Address', 'SendsSYN', 'ReceivesSYN', 'SendsSYN-ACK', 'ReceivesSYN-ACK']
        syn_addresses = syn_addresses.replace(np.nan, 0)

        # plots graph with these values
        tcpsyn_graph = syn_addresses.plot(ax=canvas.axes, x="Address",
                                          y=["SendsSYN", "ReceivesSYN", "SendsSYN-ACK", "ReceivesSYN-ACK"], kind="barh")
        tcpsyn_graph.set(title="TCP SYN Flood", xlabel="Packets")

        for index, row in syn_addresses.iterrows():
            address = row['Address']
            # add to attacked addresses if receives more SYN packets then sends SYN-ACK packets back
            if row['ReceivesSYN'] > 1.5 * row['SendsSYN-ACK']:
                self.attacked_addresses.append(address)
            # add to suspicious addresses if sends more SYN packets then receives SYN-ACK packets back
            if row['SendsSYN'] > 1.5 * row['ReceivesSYN-ACK']:
                if address not in self.suspicious_addresses:
                    self.suspicious_addresses.append(address)
                if address not in self.tcp_suspicious_addresses:
                    self.tcp_suspicious_addresses.append(address)

        return canvas

    def tcp_connect_scanning_detect(self, threshold):
        canvas = ImbeddedCanvas()
        self.tcp_scanning_suspicious = []
        # Sets interval time
        interval = 5

        tcp_packets = pd.DataFrame(self.dataframe[self.dataframe['Protocol'] == 'TCP'])
        if tcp_packets.empty:
            return None

        tcp_syn_packets = pd.DataFrame(
            tcp_packets[tcp_packets["TCP_Flags"].apply(lambda x: True if str(x).find('S') != -1 else False)])

        tcp_syn_ack_packets = pd.DataFrame(
            tcp_packets[tcp_packets["TCP_Flags"].apply(lambda x: True if str(x).find('SA') != -1 else False)])

        if tcp_syn_packets.empty or tcp_syn_ack_packets.empty:
            return None

        syn_sources_addresses = pd.Series(tcp_syn_packets['SourceIP'])
        syn_ack_dest_addresses = pd.Series(tcp_syn_ack_packets['DestIP'])

        syn_addresses = pd.concat([syn_sources_addresses.value_counts(), syn_ack_dest_addresses.value_counts()],
                                  axis=1).reset_index()
        syn_addresses.columns = ['Address', 'SendsSYN', 'ReceivesSYN-ACK']
        syn_addresses = syn_addresses.replace(np.nan, 0)
        syn_rate = {'Address': [],
                    'SYN_rate': []}
        src_addr = tcp_syn_packets['SourceIP'].unique()
        for add in src_addr:
            packet_ip = self.dataframe[self.dataframe['SourceIP'] == add]
            time_diff = 0
            if len(packet_ip) > 1:
                time_diff = packet_ip['Time'].iloc[-1] - packet_ip['Time'].iloc[0]

            # Added time_diff condition to mitigate the rate soaring
            # if the time difference is too short
            if time_diff <= 1 or len(packet_ip) == 1:
                rate = len(packet_ip)
                syn_rate['Address'].append(add)
                syn_rate['SYN_rate'].append(int(rate))
            else:
                rate = len(packet_ip) / time_diff
                syn_rate['Address'].append(add)
                syn_rate['SYN_rate'].append(int(rate))

        syn_rate_df = pd.DataFrame.from_dict(syn_rate)
        if syn_rate_df.empty:
            return None
        tcp_con_graph = syn_rate_df.plot(ax=canvas.axes, x="Address", kind='barh', legend=False)
        tcp_con_graph.axvline(threshold, color='r', linestyle='--')
        tcp_con_graph.set(xlabel="SYN sending rate (packets/sec)")

        tcp_connection_count = {}
        tcp_connection_time = {}

        # The detection requires two steps to be suspicious:
        # 1. If the address sends SYN flags without receiving SYN-ACK packets
        # 2. If the same address sends more SYN packets than the threshold within the time interval
        for index, row in syn_addresses.iterrows():
            if row['SendsSYN'] > 0 and row['ReceivesSYN-ACK'] == 0:
                src_ip = row['Address']
                # DataFrame of packets that has src_ip as the Source IP
                tcp_ip = pd.DataFrame(tcp_packets[tcp_packets["SourceIP"]
                                      .apply(lambda x: True if str(x).find(src_ip) != -1 else False)])
                # Initialising the SYN packet count
                tcp_connection_count[src_ip] = 0
                for i, r in tcp_ip.iterrows():

                    # Initialising with time of the first occurrence of the src_ip
                    if src_ip not in tcp_connection_time.keys():
                        tcp_connection_time[src_ip] = r['Time']

                    # If the number of SYN packet excels the threshold,
                    # Check whether the time elapsed if less than interval.
                    # If so, the packet is classified as suspicious
                    if tcp_connection_count[src_ip] >= threshold:
                        if r['Time'] - tcp_connection_time[src_ip] <= interval:
                            if src_ip not in self.tcp_scanning_suspicious:
                                self.tcp_scanning_suspicious.append(src_ip)
                            if src_ip not in self.suspicious_addresses:
                                self.suspicious_addresses.append(src_ip)
                        # If not, reset the time period by the latest occurrence
                        else:
                            tcp_connection_count[src_ip] = 0
                            tcp_connection_time[src_ip] = r['Time']
                    tcp_connection_count[src_ip] += 1

        return canvas

    def arp_poison_detect(self):
        self.arp_suspicious_addresses = []
        canvas = ImbeddedCanvas()

        # dataframe with only ARP packets
        arp_packets = pd.DataFrame(self.dataframe[self.dataframe['Protocol'] == 'ARP'])

        # Returns empty canvas if no arp packets are present since no analysis can be performed
        if arp_packets.empty:
            return None

        arp_packets.reset_index()
        ip_mac = {}
        suspicious_addresses = []

        # iterates through each ARP packet
        for index, arp_packet in arp_packets.iterrows():
            # stores each source ip and mac address
            source_IP = arp_packet['SourceIP']
            source_mac = arp_packet['hwsrc']
            # if source mac not already in dictionary an entry is created
            if source_mac not in ip_mac:
                ip_mac[source_mac] = [source_IP]
            else:
                # if ip address is not associated with mac address add to its list
                if source_IP not in ip_mac[source_mac]:
                    ip_mac.setdefault(source_mac, []).append(source_IP)

        # initialises mac address frequency dictionary to be made into dataframe
        mac_freq_table = {"MAC_addresses": [],
                          "Frequency": []}

        mac_addr_list = []
        mac_addr_freq_list = []

        for mac_addr in ip_mac:
            mac_addr_list.append(mac_addr)
            # add number of ip addresses associated with that mac address
            mac_addr_freq_list.append(len(ip_mac[mac_addr]))
            # if that mac address is associated with more than one ip address than it is marked as suspicious
            if len(ip_mac[mac_addr]) > 1:
                suspicious_addresses.extend(ip_mac[mac_addr])

        # add lists to dictionary, an address at a time
        for index, mac_addr in enumerate(mac_addr_list):
            mac_freq_table["MAC_addresses"].append(mac_addr)
            mac_freq_table["Frequency"].append(mac_addr_freq_list[index])

        table_dataframe = pd.DataFrame.from_dict(mac_freq_table)
        arp_graph = table_dataframe.plot(ax=canvas.axes, kind='barh', x='MAC_addresses', legend=False)
        arp_graph.set(xlabel="Frequency", title="ARP Poison")
        arp_graph.locator_params(axis="x", integer=True, tight=True)
        # threshold here is 1 since any address having more than one ip address is suspicious
        arp_graph.axvline(1, color='r', linestyle='--')
        # removes any repeated addresses
        self.arp_suspicious_addresses = list(dict.fromkeys(suspicious_addresses))

        # adds suspicious addresses to main suspicious address list
        for address in self.arp_suspicious_addresses:
            if address not in self.suspicious_addresses:
                self.suspicious_addresses.append(address)

        return canvas

    # Simple detection to see if pps are above a threshold
    def threshold_dos_detect(self, threshold):
        self.dos_suspicious_addresses = []
        canvas = ImbeddedCanvas()

        sources_addresses = self.dataframe['SourceIP'].unique()

        pps_table = {'Address': [],
                     'PPS': []}

        # calculates packets per second sent for each address
        for address in sources_addresses:
            packets_ip = self.dataframe[self.dataframe['SourceIP'] == address]

            if len(packets_ip) < 2:
                continue

            # calculates average packets per second
            difference = packets_ip['Time'].iloc[-1] - packets_ip['Time'].iloc[0]

            if difference == 0:
                continue

            packet_per_sec = len(packets_ip) / difference

            pps_table['Address'].append(address)
            pps_table['PPS'].append(int(packet_per_sec))

        pps_dataframe = pd.DataFrame.from_dict(pps_table)

        dos_graph = pps_dataframe.plot(ax=canvas.axes, x="Address", kind='barh', legend=False)
        dos_graph.set(title="DOS Detection", xlabel="Packets Per Second")
        dos_graph.axvline(threshold, color='r', linestyle='--')

        # marks addresses as suspicious if above 3 standard deviations from the mean
        for index, address in pps_dataframe.iterrows():
            if address["PPS"] > threshold:
                if address["Address"] not in self.dos_suspicious_addresses:
                    self.dos_suspicious_addresses.append(address["Address"])
                if address["Address"] not in self.suspicious_addresses:
                    self.suspicious_addresses.append(address["Address"])

        return canvas

    def icmp_flood_detect(self, threshold):
        self.icmp_suspicious = []
        canvas = ImbeddedCanvas()

        # dataframe with only ICMP Echo packets
        icmp_packets = self.dataframe[(self.dataframe['Protocol'] == 'ICMP') & (self.dataframe['ICMP_Type'] == 8)]

        if icmp_packets.empty:
            return None

        # removes any duplicated addresses
        icmp_addresses = icmp_packets['SourceIP'].unique()

        pps_table = self.calc_pps(icmp_addresses, icmp_packets, self.icmp_suspicious, threshold)

        # creates dataframe from dictionary
        pps_dataframe = pd.DataFrame.from_dict(pps_table)

        # creates graph from dataframe
        pps_graph = pps_dataframe.plot(ax=canvas.axes, kind='barh', x="Address", legend=False)
        pps_graph.set(title="ICMP Flood Detection", xlabel="Packets Per Second")

        pps_graph.locator_params(axis="x", integer=True, tight=True)

        pps_graph.axvline(threshold, color='r', linestyle='--')

        return canvas

    def http_attack(self, threshold):
        self.http_suspicious = []
        canvas = ImbeddedCanvas()

        tcp_packets = pd.DataFrame(
            self.dataframe[(self.dataframe['Protocol'] == 'TCP') & (self.dataframe["IP_Version"] == "IPv4")])

        # Returns None if no tcp packets
        if tcp_packets.empty:
            return None

        # Loop to establish if a tcp handshake has been established
        synlist = []
        source_ips = []
        for index, packet in tcp_packets.iterrows():
            # adds addresses to dictionary if syn packet is found
            if packet["TCP_Flags"] == "S":
                synlist.append({"SourceIP": packet["SourceIP"],
                                "DestIP": packet["DestIP"],
                                "Stage": "syn"})
            # if syn-ack is found, checks if packet addresses link up
            if packet["TCP_Flags"] == "SA":
                for syn_packet in synlist:
                    if syn_packet["SourceIP"] == packet["DestIP"] and syn_packet["DestIP"] == packet["SourceIP"]:
                        syn_packet["Stage"] = "synack"
            # if ack is found, check if syn_ack was previously found and adds addresses and sets tcp_connection to true
            if packet["TCP_Flags"] == "A":
                for syn_packet in synlist:
                    if syn_packet["SourceIP"] == packet["SourceIP"] and syn_packet["DestIP"] == packet["DestIP"] and \
                            syn_packet["Stage"] == "synack":
                        syn_packet["Stage"] = "connected"
                        if syn_packet["SourceIP"] not in source_ips:
                            source_ips.append(syn_packet["SourceIP"])

        # if no tcp connection was established return None
        if not source_ips:
            return None

        request_packets = []
        # for each address in which a tcp connection was established, check if packets sent are GET or POST requests
        for sourceIP in source_ips:
            tcp_requests = tcp_packets[(tcp_packets["SourceIP"] == sourceIP) & tcp_packets["raw"].notna()]
            for index, packet in tcp_requests.iterrows():
                request = packet["raw"]

                request_utf = ""
                request_latin = ""
                try:
                    request_utf = request.decode("utf-8")
                except:
                    request_latin = request.decode("latin-1")

                if ("GET" in request_utf or "POST" in request_utf) or (
                        "GET" in request_latin or "POST" in request_latin):
                    request_packets.append(packet["Number"])

        # dataframe of request packets
        requests = tcp_packets[tcp_packets["Number"].isin(request_packets)]

        if requests.empty:
            return None

        # calculates packets per second for http request packets
        pps_table = self.calc_pps(source_ips, requests, self.http_suspicious, threshold)

        # creates dataframe from dictionary
        pps_dataframe = pd.DataFrame.from_dict(pps_table)

        # creates graph from dataframe
        pps_graph = pps_dataframe.plot(ax=canvas.axes, kind='barh', x="Address", legend=False)
        pps_graph.set(title="HTTP Request Flood Detection", xlabel="Packets Per Second")
        pps_graph.locator_params(axis="x", integer=True, tight=True)
        pps_graph.axvline(threshold, color='r', linestyle='--')

        return canvas

    def dns_request_response_detect(self, threshold):
        canvas = ImbeddedCanvas()
        canvas2 = ImbeddedCanvas()
        self.dns_request_suspicious = []
        self.dns_response_suspicious = []

        # Filters to DNS protocols only
        dns_packets = pd.DataFrame(self.dataframe[self.dataframe['Protocol'] == 'UDP/DNS'])

        # Returns empty canvas if no packets are present
        if dns_packets.empty:
            return [None, None]

        # Requests have a qr flag of 0 and responses have a qr flag of 1
        dns_requests = pd.DataFrame(dns_packets[dns_packets['DNS_Type'] == 0])
        dns_responses = pd.DataFrame(dns_packets[dns_packets['DNS_Type'] == 1])

        # Obtains unique addresses
        dns_request_addresses = dns_requests['SourceIP'].unique()
        dns_response_addresses = dns_responses['SourceIP'].unique()

        # Calculates packets per second for dns requests
        pps_table = self.calc_pps(dns_request_addresses, dns_requests, self.dns_request_suspicious, threshold)

        # creates dataframe from dictionary
        pps_dataframe = pd.DataFrame.from_dict(pps_table)

        # creates graph from dataframe
        pps_graph = pps_dataframe.plot(ax=canvas.axes, kind='barh', x="Address", legend=False)
        pps_graph.set(title="DNS Request Flood Detection", xlabel="Packets Per Second")
        pps_graph.locator_params(axis="x", integer=True, tight=True)
        pps_graph.axvline(threshold, color='r', linestyle='--')

        # Calculates packets per second for dns_responses
        pps_table = self.calc_pps(dns_response_addresses, dns_responses, self.dns_response_suspicious, threshold)

        # creates dataframe from dictionary
        pps2_dataframe = pd.DataFrame.from_dict(pps_table)

        # creates graph from dataframe
        pps2_graph = pps2_dataframe.plot(ax=canvas2.axes, kind='barh', x="Address", legend=False)
        pps2_graph.set(title="DNS Response Flood Detection", xlabel="Packets Per Second")
        pps2_graph.locator_params(axis="x", integer=True, tight=True)
        pps2_graph.axvline(threshold, color='r', linestyle='--')

        # Returns both graphs
        return [canvas, canvas2]

    def calc_pps(self, suspicious_addresses, packets, attack_sus_list, threshold):
        # dictionary of the addresses and their packets per second
        pps_table = {'Address': [],
                     'PPS': []}

        # For each address:
        #    - calculate mean and standard deviation
        #    - remove any outliers using these
        #    - calculate the packets per second sent by each address
        #    - adds to suspicious addresses if above the threshold
        for address in suspicious_addresses:
            packets_ip = packets[packets['SourceIP'] == address]

            # calculates mean and standard deviation
            mean = packets_ip['Time'].mean()
            std = packets_ip['Time'].std()

            # removes any outliers (timestamps that are 3 standard deviations away from the mean)
            packets_no_outliers = packets_ip[packets_ip['Time'] <= mean + (3 * std)]

            # calculates average packets per second
            difference = packets_no_outliers['Time'].iloc[-1] - packets_no_outliers['Time'].iloc[0]
            packet_per_sec = len(packets_no_outliers) / difference

            pps_table['Address'].append(address)
            pps_table['PPS'].append(int(packet_per_sec))

            # adds to suspicious addresses if above threshold
            if packet_per_sec > threshold:
                if address not in self.suspicious_addresses:
                    self.suspicious_addresses.append(address)
                if address not in attack_sus_list:
                    attack_sus_list.append(address)

            return pps_table

    # Runs all established attack detections
    def run_all_detection(self, threshold):
        if threshold is None:
            self.tcp_syn_flood_detect()
            self.tcp_connect_scanning_detect(100)
            self.threshold_dos_detect(200)
            self.arp_poison_detect()
            self.icmp_flood_detect(100)
            self.http_attack(5)
            self.dns_request_response_detect(20)
        else:
            self.tcp_syn_flood_detect()
            self.tcp_connect_scanning_detect(threshold)
            self.threshold_dos_detect(threshold)
            self.arp_poison_detect()
            self.icmp_flood_detect(threshold)
            self.http_attack(threshold)
            self.dns_request_response_detect(threshold)
