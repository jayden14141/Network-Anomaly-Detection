# Code by Owen
import socket
import struct
import binascii

# Gets IP address of current device
HOST = socket.gethostbyname(socket.gethostname())


# Class for creation of object for storage of ethernet frame data
class Ethernet:
    def __init__(self, packet):
        self.header_raw = packet[:14]
        ethernet_frame = struct.unpack("!6s6sH", packet[:14])

        destination_address = ethernet_frame[0]
        source_address = ethernet_frame[1]
        self.protocol = ethernet_frame[2]

        self.destination_mac = self.format_mac_address(destination_address)
        self.source_mac = self.format_mac_address(source_address)

    # Method to format MAC addresses
    def format_mac_address(self, address):
        return binascii.hexlify(address, ":").upper().decode("utf-8")


# Object for storing the components of a IPv4 header
class IPv4:
    def __init__(self, packet):
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

    # Method to format the IP address into regular format
    def ip_format(self, addr):
        return '.'.join(map(str, addr))


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


# Breaks down IPv4 header and handles packet depending on its protocol
def handle_packet(packet):
    ethernet = Ethernet(packet)
    packet = packet[14:]
    ipv4 = IPv4(packet)

    # IP headers have variable, so we need to find out the length first
    data = packet[ipv4.ip_header_length:]
    print("protocol = ", ipv4.protocol)

    if ipv4.protocol == 1:
        print("\nICMP Packet")
        icmp = ICMP(data)

    elif ipv4.protocol == 6:
        print("\nTCP Packet")
        tcp = TCP(data)

    elif ipv4.protocol == 17:
        print("\nUDP Packet")
        udp = UDP(data)


class Sniffer:
    def __init__(self):
        # creates a socket
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    # Method to continuously receive the specified amount of packets
    def sniffer(self, amount):
        for i in range(0, amount):
            packet = self.socket.recvfrom(65536)
            handle_packet(packet[0])


if __name__ == '__main__':
    sniffer = Sniffer()
    # This amount will be specified by the user.
    packet_amount = 100
    sniffer.sniffer(packet_amount)
