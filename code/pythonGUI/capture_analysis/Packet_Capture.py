from scapy.all import *


# Sniffer object with related methods.
class Sniffer:
    def __init__(self):
        self.timeout = None
        self.sniffer = None
        self.amount = 0
        self.protocol = ""
        self.filter = ""
        self.continuous_sniff = False
        self.running = True
        self.ptc = ""

        self.sniffed_packets = []

    # Method ran when packet capture is initiated by user.
    def run_sniffer(self, start, window):
        if start:
            self.running = True
            return self.sniffing(window)
        else:
            self.running = False

    # Method to reset the stored packets
    def reset(self):
        self.sniffed_packets = []

    # Method to change the amount of packets to capture.
    def set_sniff_amount(self, amount):
        # if no amount specified, captures continuously
        if amount == '':
            self.set_continuous_sniff(True)
        else:
            self.set_continuous_sniff(False)
            self.amount = int(amount)

    # Sets filter to be used at the start of capturing
    def set_filter(self, protocol):
        if protocol == "IPv6":
            self.filter = 'ip6'
        else:
            self.filter = str(protocol.lower())

    # Switches continuous sniffing on and off
    def set_continuous_sniff(self, status):
        self.continuous_sniff = status

    # sets timeout in seconds for sniffer
    def set_sniff_timeout(self, time):
        self.timeout = time

    # called by sniffer each packet to see if it should continue sniffing
    def stop_sniffing(self, packet):
        if self.running:
            return False
        else:
            return True

    # Method to start asynchronous sniffing
    def sniffing(self, window):
        # if no packet amount is specified
        if self.continuous_sniff:
            # scapy sniffer to capture packets
            # prn = sends every captured packet to be handled by this function
            # stop_filter = calls method to check if the user has stopped the capture
            sniff(prn=self.packet_display(window), filter=self.filter, store=False, stop_filter=self.stop_sniffing,
                  timeout=self.timeout)
        else:
            # same as above by only captures a set amount of packets
            sniff(count=self.amount, filter=self.filter, prn=self.packet_display(window), store=False,
                  stop_filter=self.stop_sniffing, timeout=self.timeout)

    def packet_filter(self, packet):
        if self.filter == "":
            return True
        else:
            if packet.haslayer(self.filter):
                return True
            else:
                return False

    def set_protocol(self, protocol):
        self.ptc = protocol

    # alternate sniffing method for reading pcap file packets
    def sniff_read(self, read_packets, window):
        sniff(count=self.amount, prn=self.packet_display(window), store=False, offline=read_packets,
              lfilter=self.packet_filter)

    # called for every captured packet
    def packet_display(self, window):
        # inner function to allow arguments to be passed into sniffer function
        def send_packet(packet):
            # adds new packet to captured packets list
            self.sniffed_packets.append(packet)
            # calls display packet method on each packet using window object
            if window is not None:
                if self.ptc == "" or packet.haslayer(self.ptc):
                    window.display_packet(packet)

        return send_packet
