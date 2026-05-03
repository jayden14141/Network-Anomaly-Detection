import unittest
import IPv4_Capture_Windows
import struct


class TestCapture(unittest.TestCase):

    #create a packet and ipv4 with each protocol
    def setUp(self):
        self.icmpPacket = struct.pack("!B B H H H B B H 4s 4s", 0, 0, 20, 0, 0, 0, 1, 0, b'\0\0\0\0', b'\0\0\0\0')
        self.testICMP = IPv4_Capture_Windows.IPv4(self.icmpPacket)
        self.tcpPacket = struct.pack("!B B H H H B B H 4s 4s", 0, 0, 20, 0, 0, 0, 6, 0, b'\0\0\0\0', b'\0\0\0\0')
        self.testTCP = IPv4_Capture_Windows.IPv4(self.tcpPacket)
        self.udpPacket = struct.pack("!B B H H H B B H 4s 4s", 0, 0, 20, 0, 0, 0, 17, 0, b'\0\0\0\0', b'\0\0\0\0')
        self.testUDP = IPv4_Capture_Windows.IPv4(self.udpPacket)

    #test that the protocol triggers the correct attribute to update
    def test_handle_protocol(self):
        self.assertNotEqual(self.testICMP.icmp, None)
        self.assertEqual(self.testICMP.tcp, None)
        self.assertEqual(self.testICMP.udp, None)

        self.assertEqual(self.testTCP.icmp, None)
        self.assertNotEqual(self.testTCP.tcp, None)
        self.assertEqual(self.testTCP.udp, None)

        self.assertEqual(self.testUDP.icmp, None)
        self.assertEqual(self.testUDP.tcp, None)
        self.assertNotEqual(self.testUDP.udp, None)

    #test that addresses format correctly
    def test_ip_format(self):
        self.assertEqual(self.testUDP.source_addr, '0.0.0.0')
        self.assertEqual(self.testUDP.destination_addr, '0.0.0.0')

    #test that sniffer handles packets based on their protocol
"""
    def test_handle_packet(self):
        sniffer = IPv4_Capture_Windows.Sniffer()
        self.assertEqual(sniffer.icmp_packets, [])
        self.assertEqual(sniffer.tcp_packets, [])
        self.assertEqual(sniffer.udp_packets, [])

        sniffer.handle_packet(self.icmpPacket)
        self.assertEqual(sniffer.icmp_packets, [self.testICMP])

        sniffer.handle_packet(self.tcpPacket)
        self.assertEqual(sniffer.tcp_packets, [self.testTCP])

        sniffer.handle_packet(self.udpPacket)
        self.assertEqual(sniffer.udp_packets, [self.testUDP])
"""

if __name__ == '__main__':
    unittest.main()
