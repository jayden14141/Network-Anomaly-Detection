import os
import sys
import unittest

import matplotlib

matplotlib.use('Agg')
from scapy.sendrecv import sniff

from pythonGUI.capture_analysis import attack_detection, GUI_actions, dataframe_create


class MyTestCase(unittest.TestCase):
    def setUp(self):
        self.actions = GUI_actions.GUIActions()

    def test_tcp_flood(self):
        # pcap file of a TCP Syn Flood attack with 2 addresses
        self.actions.read_pcap("test_pcaps/SYN.pcap", None)
        read_packets = self.actions.get_sniffed_packets()
        attack_detect = attack_detection.AttackDetection(read_packets, [])

        known_sus = "10.128.0.2"
        known_vic = "10.0.0.2"

        attack_detect.tcp_syn_flood_detect()
        suspicious_addresses = attack_detect.tcp_suspicious_addresses
        attacked_addresses = attack_detect.attacked_addresses

        # Tests whether any suspicious addresses were detected
        self.assertTrue(suspicious_addresses)
        self.assertTrue(attacked_addresses)

        # Tests whether the known suspicious and victim addresses appeared in the correct lists
        self.assertTrue(known_sus in suspicious_addresses)
        self.assertTrue(known_vic in attacked_addresses)
        self.assertTrue(known_sus not in attacked_addresses)
        self.assertTrue(known_vic not in suspicious_addresses)

    def test_tcp_scan_detect(self):
        self.actions.read_pcap("test_pcaps/SYN.pcap", None)
        read_packets = self.actions.get_sniffed_packets()
        attack_detect = attack_detection.AttackDetection(read_packets, [])

        known_sus = "10.128.0.2"

        attack_detect.tcp_connect_scanning_detect(100)
        suspicious_addresses = attack_detect.tcp_scanning_suspicious

        # Tests whether any suspicious addresses were detected
        self.assertTrue(suspicious_addresses)

        # Tests whether the known suspicious and victim addresses appeared in the correct lists
        self.assertTrue(known_sus in suspicious_addresses)

        attack_detect.tcp_connect_scanning_detect(10000)
        suspicious_addresses_wthreshold = attack_detect.tcp_scanning_suspicious
        self.assertTrue(known_sus not in suspicious_addresses_wthreshold)

    def test_arp_poison(self):
        # pcap file of an ARP poison attack with 2 addresses
        self.actions.read_pcap("test_pcaps/arp-poisoning.pcap", None)
        read_packets = self.actions.get_sniffed_packets()
        attack_detect = attack_detection.AttackDetection(read_packets, [])

        known_sus = ['192.168.1.1', '192.168.1.254']

        attack_detect.arp_poison_detect()
        suspicious_addresses = attack_detect.arp_suspicious_addresses

        self.assertCountEqual(suspicious_addresses, known_sus)

    def test_icmp_flood(self):
        # pcap file of an imcp flood attack
        self.actions.read_pcap("test_pcaps/icmp-ping.pcap", None)
        read_packets = self.actions.get_sniffed_packets()
        attack_detect = attack_detection.AttackDetection(read_packets, [])

        known_sus = '10.0.0.2'

        attack_detect.icmp_flood_detect(100)
        suspicious_addresses = attack_detect.icmp_suspicious

        self.assertTrue(known_sus in suspicious_addresses)

        attack_detect.icmp_flood_detect(10000)
        suspicious_addresses_wthreshold = attack_detect.icmp_suspicious
        self.assertTrue(known_sus not in suspicious_addresses_wthreshold)

    def test_http_flood(self):
        self.actions.read_pcap("test_pcaps/http-flood.pcap", None)
        read_packets = self.actions.get_sniffed_packets()
        attack_detect = attack_detection.AttackDetection(read_packets, [])

        known_sus = "10.0.0.2"

        attack_detect.http_attack(5)
        suspicious_addresses = attack_detect.http_suspicious

        self.assertTrue(known_sus in suspicious_addresses)

        attack_detect.http_attack(500)
        suspicious_addresses_wthreshold = attack_detect.http_suspicious
        self.assertTrue(known_sus not in suspicious_addresses_wthreshold)

    def test_dns(self):
        self.actions.read_pcap("test_pcaps/dns.pcap", None)
        read_packets = self.actions.get_sniffed_packets()
        attack_detect = attack_detection.AttackDetection(read_packets, [])

        known_request_sus = "207.86.6.174"
        known_response_sus = "205.94.14.222"

        attack_detect.dns_request_response_detect(20)
        request_sus_addresses = attack_detect.dns_request_suspicious
        response_sus_addresses = attack_detect.dns_response_suspicious

        self.assertTrue(known_request_sus in request_sus_addresses)
        self.assertTrue(known_response_sus in response_sus_addresses)

        attack_detect.dns_request_response_detect(2000)

        request_sus_addresses_wthreshold = attack_detect.dns_request_suspicious
        response_sus_addresses_wthreshold = attack_detect.dns_response_suspicious
        self.assertTrue(known_request_sus not in request_sus_addresses_wthreshold)
        self.assertTrue(known_response_sus not in response_sus_addresses_wthreshold)

    def test_run_all(self):
        self.actions.read_pcap("test_pcaps/icmp-ping.pcap", None)
        read_packets = self.actions.get_sniffed_packets()
        attack_detect = attack_detection.AttackDetection(read_packets, [])

        attack_lists = {"TCP Scanning": attack_detect.tcp_scanning_suspicious,
                        "TCP": attack_detect.tcp_suspicious_addresses,
                        "HTTP": attack_detect.http_suspicious,
                        "ARP": attack_detect.arp_suspicious_addresses,
                        "DNSreq": attack_detect.dns_request_suspicious,
                        "DNS": attack_detect.dns_response_suspicious}

        known_sus = "10.0.0.2"
        attack_detect.run_all_detection(500)

        # Checks that the address is not in all the lists it shouldn't be
        for attack_sus in attack_lists:
            self.assertTrue(known_sus not in attack_sus)

        self.assertTrue(known_sus in attack_detect.dos_suspicious_addresses)
        self.assertTrue(known_sus in attack_detect.icmp_suspicious)

        # Run with high threshold so should not be any list
        attack_detect.run_all_detection(5000)

        for attack_sus in attack_lists:
            self.assertTrue(known_sus not in attack_sus)

        self.assertTrue(known_sus not in attack_detect.dos_suspicious_addresses)
        self.assertTrue(known_sus not in attack_detect.icmp_suspicious)


if __name__ == '__main__':
    unittest.main()
