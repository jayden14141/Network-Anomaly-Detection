from scapy.all import *
import unittest

from pythonGUI.capture_analysis import GUI_actions

# unit testing for packet capturing
class PacketCaptureTesting(unittest.TestCase):
    def setUp(self):
        self.actions = GUI_actions.GUIActions()
        self.filter_options = ["IGMP", "ICMP", "TCP", "UDP", "IPv6", "ARP"]

    # tests the methods of the sniffer object
    def test_sniffer_methods(self):
        # tests that the set sniff amount method works
        self.actions.sniffer.set_sniff_amount(40)
        self.assertEqual(40, self.actions.sniffer.amount)
        self.actions.start_sniffer(True, None)
        self.assertEqual(40, len(self.actions.get_sniffed_packets()))
        self.actions.sniffer.reset()
        self.actions.sniffer.set_sniff_amount(20)
        self.assertEqual(20, self.actions.sniffer.amount)
        self.actions.start_sniffer(True, None)
        self.assertEqual(20, len(self.actions.get_sniffed_packets()))
        self.actions.sniffer.reset()

        # checks that sniffer.reset removes captured packets
        self.assertEqual([], self.actions.get_sniffed_packets())
        self.actions.start_sniffer(True, None)
        self.assertNotEqual([], self.actions.get_sniffed_packets())
        self.actions.sniffer.reset()
        self.assertEqual([], self.actions.get_sniffed_packets())

    # tests setting the filter before running sniffer
    def test_sniffer_filter(self):
        self.actions.sniffer.set_sniff_amount(10)
        # sets timeout in case a specific protocol cannot be captured
        self.actions.sniffer.set_sniff_timeout(10)
        # applying filter with every type of protocol considered so far
        for option in self.filter_options:
            self.actions.sniffer.reset()
            self.actions.sniffer.set_filter(option)
            self.actions.start_sniffer(True, None)
            sniffed_packets = self.actions.get_sniffed_packets()
            for packet in sniffed_packets:
                if option != "IGMP" or option != "ICMP":
                    self.assertEqual(packet.haslayer(option), True)
                else:
                    pass
        self.actions.sniffer.set_sniff_timeout(None)

    # tests filtering on captured packets
    def test_filter_captured(self):
        self.actions.sniffer.reset()
        self.actions.sniffer.set_sniff_amount(100)
        self.actions.start_sniffer(True, None)
        sniffed_packets = self.actions.get_sniffed_packets()

        # no filter applied
        filtered_packets = self.actions.filter_packets("")
        self.assertEqual(sniffed_packets, filtered_packets)

        # applying filter with every type of protocol considered so far
        for option in self.filter_options:
            filtered_packets = self.actions.filter_packets(option)
            for packet in filtered_packets:
                self.assertEqual(packet.haslayer(option), True)

    # tests writing and reading of pcap files
    def test_read_write_pcap(self):
        # removes test pcap file if it exists already
        self.actions.sniffer.set_filter("")
        if os.path.exists('test_pcap.pcap'):
            os.remove('test_pcap.pcap')
        self.actions.sniffer.set_sniff_amount(10)
        self.actions.start_sniffer(True, None)
        sniffed_packets = self.actions.get_sniffed_packets()
        self.actions.write_pcap("test_pcap.pcap")
        self.actions.sniffer.reset()
        self.actions.read_pcap("test_pcap.pcap", None)
        read_packets = self.actions.get_sniffed_packets()

        self.assertEqual(sniffed_packets, read_packets)


if __name__ == '__main__':
    unittest.main()
