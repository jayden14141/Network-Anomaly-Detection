# code by Owen

from scapy.all import *

def packet_summary(packet):
    # displays the destination of each packet
    print(packet.dst)

def main():
    # sniff() captures incoming traffic, listens infinitely unless limited with count.
    capture = sniff(count=10)
    # summary() shows a summary of the collect traffic
    capture.summary()

    # sniffing can be filtered to certain protocols
    capture2 = sniff(filter="tcp", count=10)

    # specifying network interface, this example only works on Linux, on windows use ipconfig /all to find interfaces
    capture3 = sniff(iface="eth0", count=10)

    # passing a function with prn executes that function for each packet found
    sniff(prn=packet_summary, count=10)

    # can write to a pcap file, to store packets
    packets = sniff(count=10)
    wrpcap("sniffed_packets.pcap", packets)

    # reading from pcap file
    pcap_file = rdpcap("sniffed_packets.pcap")
    for packet in pcap_file:
        print(packet)


main()


