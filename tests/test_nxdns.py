import unittest
import base64
import struct
import sys
import os

# Add parent directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from dnslib import DNSRecord, DNSQuestion, QTYPE, RCODE
from nxdns import process_dns_query, TCPRequestHandler

class TestNXDNS(unittest.TestCase):

    def test_process_dns_query_returns_nxdomain_with_aa(self):
        query = DNSRecord.question("example.com", "A")
        raw_data = query.pack()

        response_data = process_dns_query(raw_data, "UDP", "127.0.0.1", 5353)
        self.assertIsNotNone(response_data)

        response = DNSRecord.parse(response_data)
        self.assertEqual(response.header.id, query.header.id)
        self.assertEqual(response.header.rcode, RCODE.NXDOMAIN)
        self.assertEqual(response.header.aa, 1)
        self.assertEqual(response.header.qr, 1)
        self.assertEqual(len(response.rr), 0)
        self.assertEqual(str(response.q.qname), "example.com.")

    def test_process_dns_query_ignores_qr_response_packet(self):
        response_packet = DNSRecord.question("example.com", "A").reply()
        response_packet.header.qr = 1
        raw_data = response_packet.pack()

        result = process_dns_query(raw_data, "UDP", "127.0.0.1", 5353)
        self.assertIsNone(result)

    def test_process_dns_query_invalid_packet_raises_value_error(self):
        with self.assertRaises(ValueError):
            process_dns_query(b"invalid_non_dns_payload", "UDP", "127.0.0.1", 5353)

    def test_doh_base64url_padding_logic(self):
        query = DNSRecord.question("test.org", "AAAA").pack()
        encoded = base64.urlsafe_b64encode(query).decode('ascii').rstrip('=')

        padding = '=' * (-len(encoded) % 4)
        padded = encoded + padding
        decoded = base64.urlsafe_b64decode(padded)

        self.assertEqual(decoded, query)

    def test_tcp_max_packet_limit(self):
        self.assertEqual(TCPRequestHandler.MAX_DNS_PACKET, 4096)

    def test_process_dns_query_sanitizes_qname(self):
        # Even with weird characters, query parsing and NXDOMAIN generation must succeed
        query = DNSRecord.question("clean-domain.local", "TXT")
        raw_data = query.pack()
        response_data = process_dns_query(raw_data, "UDP", "127.0.0.1", 5353)
        self.assertIsNotNone(response_data)
        response = DNSRecord.parse(response_data)
        self.assertEqual(response.header.rcode, RCODE.NXDOMAIN)

if __name__ == '__main__':
    unittest.main()
