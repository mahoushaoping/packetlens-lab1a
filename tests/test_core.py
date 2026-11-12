import os
from pathlib import Path
import random
import struct
import tempfile
import unittest
from sniffer.decoder import decode, dns_name
from sniffer.filtering import compile_filter
from sniffer.pcap import read_pcap, write_pcap, Pcap
from sniffer.streams import reassemble
from tools.make_sample import sample_packets, tcp, udp, ip4, ip6, checksum


class DecoderTests(unittest.TestCase):
    def setUp(self):
        self.packets = sample_packets()

    def test_protocol_coverage(self):
        protocols = set().union(*(p.protocols for p in self.packets))
        self.assertTrue({"arp", "ipv4", "ipv6", "tcp", "udp", "icmp", "icmpv6", "http", "dns", "tls"} <= protocols)
        self.assertFalse([p.warnings for p in self.packets if p.warnings])

    def test_http_detected_by_content(self):
        p = decode(1, 0, tcp(b"GET / HTTP/1.1\r\n\r\n", dport=8765))
        self.assertEqual(p.protocol, "HTTP")
        self.assertEqual(decode(1, 0, tcp(b"not http", dport=80)).protocol, "TCP")

    def test_dns_response(self):
        p = self.packets[2]
        fields = p.layers[-1][1]
        self.assertTrue(fields["response"])
        self.assertIn("198.51.100.20", fields["answers"][0])

    def test_dns_loop_rejected(self):
        with self.assertRaisesRegex(ValueError, "循环"):
            dns_name(b"\xc0\x00", 0)

    def test_all_truncation_boundaries(self):
        for p in self.packets:
            for length in range(len(p.raw)):
                value = decode(1, 0, p.raw[:length], len(p.raw))
                self.assertTrue(value.warnings)

    def test_random_input_never_crashes(self):
        rng = random.Random(42)
        for link in [0, 1, 12, 101, 108, 113, 276, 999]:
            for _ in range(250):
                data = rng.randbytes(rng.randrange(0, 512))
                decode(1, 0, data, linktype=link)

    def test_loopback_and_vlan(self):
        p = self.packets[6]
        self.assertEqual(decode(1, 0, struct.pack("<I", 2) + p.raw[14:], linktype=0).protocol, "HTTP")
        self.assertEqual(decode(1, 0, struct.pack(">I", 2) + p.raw[14:], linktype=0).protocol, "HTTP")
        vlan = p.raw[:12] + b"\x81\0\0\x64" + p.raw[12:]
        q = decode(1, 0, vlan)
        self.assertIn("vlan", q.protocols)
        self.assertEqual(q.protocol, "HTTP")

    def test_fragments_not_misparsed(self):
        p = decode(1, 0, ip4(b"\0"*32, 6, frag=1))
        self.assertTrue(p.fragmented)
        self.assertNotIn("tcp", p.protocols)
        p = decode(1, 0, ip6(b"\x06\0\0\x09" + b"\0"*28, 44))
        self.assertTrue(p.fragmented)
        self.assertNotIn("tcp", p.protocols)

    def test_ipv6_extension(self):
        packet = self.packets[13]
        raw = ip6(b"\x11\0" + b"\0"*6 + packet.raw[54:], 0)
        p = decode(1, 0, raw)
        self.assertEqual(p.protocol, "DNS")

    def test_invalid_udp_length(self):
        p = decode(1, 0, ip4(struct.pack("!HHHH", 1, 2, 7, 0), 17))
        self.assertTrue(p.warnings)

    def test_sample_checksums(self):
        for p in self.packets:
            if "ipv4" in p.protocols:
                self.assertEqual(checksum(p.raw[14:34]), 0)


class FilterTests(unittest.TestCase):
    def test_boolean_precedence(self):
        packets = sample_packets()
        pred = compile_filter("http or dns and ipv6")
        self.assertEqual([p.number for p in packets if pred(p)], [7, 9, 10, 14])
        pred = compile_filter("tcp and (port 80 or port 443) and not http")
        self.assertEqual(sum(pred(p) for p in packets), 7)

    def test_fields(self):
        p = sample_packets()[6]
        self.assertTrue(compile_filter("host 192.0.2.10 and src 192.0.2.10 and dst 198.51.100.20 and contains get")(p))
        self.assertFalse(compile_filter("port 0")(sample_packets()[0]))

    def test_invalid_expressions(self):
        for value in ["tcp udp", "tcp and", "(tcp", "tcp)", "port 99999", "host invalid", "__import__('os')", "and tcp", "not "*200]:
            with self.assertRaises(ValueError, msg=value):
                compile_filter(value)


class StreamTests(unittest.TestCase):
    def test_out_of_order_retransmission(self):
        packets = sample_packets()
        result = reassemble(packets, packets[6].flow_key)
        server = next(item for item in result if item[0].startswith("198."))
        self.assertEqual(server[2:], (35, 0))
        self.assertTrue(server[1].startswith(b"HTTP/1.1 200 OK"))
        self.assertEqual(server[1].count(b"Hello, PacketLens!"), 1)

    def test_wrap_gap_and_overlap(self):
        packets = [decode(1, 0, tcp(b"abcd", seq=0xFFFFFFFE)), decode(2, 1, tcp(b"cdef", seq=0)), decode(3, 2, tcp(b"z", seq=8))]
        direction = reassemble(packets, packets[0].flow_key)[0]
        self.assertEqual(direction[1], b"abcdef\n[" + "缺失 4 字节".encode() + b"]\nz")
        self.assertEqual(direction[2:], (2, 4))

    def test_syn_initial_gap(self):
        packets = [decode(1, 0, tcp(seq=100, flags=2)), decode(2, 1, tcp(b"X", seq=110))]
        self.assertEqual(reassemble(packets, packets[0].flow_key)[0][3], 9)


class PcapTests(unittest.TestCase):
    def test_roundtrip(self):
        packets = sample_packets()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/"test.pcap"
            write_pcap(path, packets)
            data = list(read_pcap(path))
            self.assertEqual([d[1] for d in data], [p.raw for p in packets])
            self.assertEqual([d[2] for d in data], [p.wirelen for p in packets])
            self.assertAlmostEqual(data[3][0], packets[3].timestamp, places=5)

    def test_big_endian_nanoseconds(self):
        data = struct.pack(">IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1) + struct.pack(">IIII", 1, 500000000, 1, 1) + b"a"
        with tempfile.NamedTemporaryFile() as f:
            f.write(data); f.flush()
            self.assertEqual(list(read_pcap(f.name))[0], (1.5, b"a", 1, 1))

    def test_bad_files(self):
        head = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        for data in [b"", b"\x0a\x0d\x0d\x0a"+b"\0"*20, head+b"x", head+struct.pack("<IIII",0,0,9999999,9999999), head+struct.pack("<IIII",0,0,5,5)+b"x"]:
            with tempfile.NamedTemporaryFile() as f:
                f.write(data); f.flush()
                with self.assertRaises(ValueError):
                    list(read_pcap(f.name))

    def test_real_libpcap_bpf(self):
        try:
            api = Pcap()
        except OSError as exc:
            self.skipTest(str(exc))
        packets = sample_packets()
        match = api.matches(packets, "tcp port 80")
        self.assertEqual(sum(match), 9)
        match = api.matches(packets, "ip6 and udp port 53")
        self.assertEqual(sum(match), 1)
        with self.assertRaises(ValueError):
            api.matches(packets, "tcp and ???")


if __name__ == "__main__":
    unittest.main()
