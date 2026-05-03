# Code by Owen
import socket
import struct
from datetime import datetime

# Gets IP address of current device
HOST = socket.gethostbyname(socket.gethostname())


# Object for storing the components of a IPv4 header
class IPv4:
    def __init__(self, packet):
        self.udp = None
        self.tcp = None
        self.icmp = None
        self.time = datetime.now()
        self.ip_header_raw = packet[:20]

        # unpacks header: ! = big-endian, B = 1 byte -> integer, H = 2 bytes -> integer, 4s = 4 bytes
        ip_header = struct.unpack("!B B H H H B B H 4s 4s", self.ip_header_raw)

        version = ip_header[0]
        self.service_type = ip_header[1]
        self.length = ip_header[2]
        self.identification = ip_header[3]
        self.flags_offset = ip_header[4]
        self.ttl = ip_header[5]
        self.protocol = ip_header[6]
        self.checksum = ip_header[7]
        src = ip_header[8]
        dest = ip_header[9]

        # first 4 bits is the ipv4 version and second is header length so splits accordingly
        self.version = version >> 4
        self.ip_header_length = (version & 0xF) * 4

        self.source_addr = self.ip_format(src)
        self.destination_addr = self.ip_format(dest)

        self.handle_protocol(packet)

    # Method to handle packet depending on its protocol.
    def handle_protocol(self, packet):
        # IP headers have variable, so we need to find out the length first
        data = packet[self.ip_header_length:]

        if self.protocol == 1:
            self.icmp = self.ICMP(data)

        elif self.protocol == 6:
            self.tcp = self.TCP(data)

        elif self.protocol == 17:
            self.udp = self.UDP(data)

    # Method to format the IP address into regular format
    def ip_format(self, addr):
        return '.'.join(map(str, addr))

    # Inner classes to create sub-classes of IPv4 object depending on the protocol used
    # Object for storing the components of an ICMP header
    class ICMP:
        def __init__(self, packet):
            self.ICMP_header_raw = packet[:4]
            icmp_header = struct.unpack("!BBH", packet[:4])

            self.type = icmp_header[0]
            self.code = icmp_header[1]
            self.checksum = icmp_header[2]

    # Stores the components of a TCP header
    class TCP:
        def __init__(self, packet):
            self.TCP_header_raw = packet[:20]

            # L = 4 bytes -> integer
            tcp_header = struct.unpack("!H H L L H H H H", self.TCP_header_raw)

            self.source_port = tcp_header[0]
            self.destination_port = tcp_header[1]
            self.sequence = tcp_header[2]
            self.acknowledgement = tcp_header[3]
            self.offset_reserved_flags = tcp_header[4]
            self.window = tcp_header[5]
            self.checksum = tcp_header[6]
            self.urgent = tcp_header[7]

    # Creation of a UDP object
    class UDP:
        def __init__(self, packet):
            self.udp_header_raw = packet[:8]
            udp_header = struct.unpack('! H H 2x H', self.udp_header_raw)
            self.source_port = udp_header[0]
            self.destination_port = udp_header[1]
            self.size = udp_header[2]


# Sniffer object that initialises the socket and receives packets
class Sniffer:
    def __init__(self):
        # create a socket, AF_INET = IPv4, SOCK_RAW = RAW socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        # binds to a certain port
        self.socket.bind((HOST, 0))

        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # Enables promiscuous mode to scan entire network
        self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        self.icmp_packets = []
        self.tcp_packets = []
        self.udp_packets = []

        self.sniffed_packets = {}

    # Method to continuously receive the specified amount of packets
    def sniff(self, amount):
        for i in range(0, amount):
            packet = self.socket.recvfrom(65536)
            self.handle_packet(packet[0])

    # Breaks down IPv4 header and adds packet to dictionary of all sniffed packets.
    def handle_packet(self, packet):
        ipv4 = IPv4(packet)

        if ipv4.protocol == 1:
            self.icmp_packets.append(ipv4)

        elif ipv4.protocol == 6:
            self.tcp_packets.append(ipv4)

        elif ipv4.protocol == 17:
            self.udp_packets.append(ipv4)

        self.sniffed_packets["icmp"] = self.icmp_packets
        self.sniffed_packets["tcp"] = self.tcp_packets
        self.sniffed_packets["udp"] = self.udp_packets


if __name__ == '__main__':
    sniffer = Sniffer()
    # This amount will be specified by the user.
    packet_amount = 10
    sniffer.sniff(packet_amount)

    # Disables promiscuous mode
    sniffer.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
