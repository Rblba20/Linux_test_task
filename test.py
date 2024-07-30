import unittest
# from scapy.all import Ether, IP
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from main import read_pcap, find_matching_intervals, display_intervals

class TestPCAPMatching(unittest.TestCase):
    def create_test_packets(self):
        packet1 = Ether()/IP(dst="10.0.0.1")
        packet2 = Ether()/IP(dst="10.0.0.2")
        packet3 = Ether()/IP(dst="10.0.0.3")
        return [packet1, packet2, packet3]

    def test_find_matching_intervals(self):
        packets1 = self.create_test_packets()
        packets2 = self.create_test_packets()
        packets2.append(Ether()/IP(dst="10.0.0.4"))

        intervals = find_matching_intervals(packets1, packets2, 2)
        self.assertEqual(len(intervals), 1)
        self.assertEqual(intervals[0], (0, 0, 3))

    def test_no_matching_intervals(self):
        packets1 = self.create_test_packets()
        packets2 = [Ether()/IP(dst="10.0.0.4"), Ether()/IP(dst="10.0.0.5")]

        intervals = find_matching_intervals(packets1, packets2, 1)
        self.assertEqual(len(intervals), 0)

if __name__ == "__main__":
    unittest.main()
