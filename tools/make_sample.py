"""生成完全合成、校验和有效的教学报文；不发送到网络。"""
from pathlib import Path
import ipaddress
import struct
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sniffer.decoder import decode
from sniffer.pcap import write_pcap


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def ethernet(data, typ=0x800):
    return bytes.fromhex("020000000002020000000001") + struct.pack("!H", typ) + data


def ip4(data, proto, src="192.0.2.10", dst="198.51.100.20", frag=0):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, len(data)+20, 1, frag, 64, proto, 0,
                         ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed)
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return ethernet(header + data)


def ip6(data, proto, src="2001:db8::10", dst="2001:db8::20"):
    return ethernet(struct.pack("!IHBB16s16s", 6 << 28, len(data), proto, 64,
                    ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed) + data, 0x86DD)


def tcp(payload=b"", seq=1001, ack=5001, flags=0x18, src="192.0.2.10", dst="198.51.100.20", sport=49152, dport=80):
    segment = struct.pack("!HHIIHHHH", sport, dport, seq, ack, (5 << 12) | flags, 65535, 0, 0) + payload
    pseudo = ipaddress.ip_address(src).packed + ipaddress.ip_address(dst).packed + struct.pack("!BBH", 0, 6, len(segment))
    segment = segment[:16] + struct.pack("!H", checksum(pseudo + segment)) + segment[18:]
    return ip4(segment, 6, src, dst)


def udp(payload, sport=53000, dport=53, ipv6=False):
    segment = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    if ipv6:
        pseudo = ipaddress.ip_address("2001:db8::10").packed + ipaddress.ip_address("2001:db8::20").packed + struct.pack("!I3xB", len(segment), 17)
    else:
        pseudo = ipaddress.ip_address("192.0.2.10").packed + ipaddress.ip_address("198.51.100.20").packed + struct.pack("!BBH", 0, 17, len(segment))
    segment = segment[:6] + struct.pack("!H", checksum(pseudo + segment) or 65535) + segment[8:]
    return ip6(segment, 17) if ipv6 else ip4(segment, 17)


def sample_packets():
    req = b"GET /lab1a HTTP/1.1\r\nHost: example.test\r\nUser-Agent: PacketLens-demo\r\n\r\n"
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 18\r\n\r\nHello, PacketLens!\n"
    reverse = dict(src="198.51.100.20", dst="192.0.2.10", sport=80, dport=49152)
    arp = struct.pack("!HHBBH", 1, 0x800, 6, 4, 1) + bytes.fromhex("020000000001") + ipaddress.ip_address("192.0.2.10").packed + b"\0"*6 + ipaddress.ip_address("192.0.2.1").packed
    question = b"\x07example\x04test\0" + struct.pack("!HH", 1, 1)
    query = struct.pack("!6H", 0x1234, 0x0100, 1, 0, 0, 0) + question
    response = struct.pack("!6H", 0x1234, 0x8180, 1, 1, 0, 0) + question + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + ipaddress.ip_address("198.51.100.20").packed
    icmp = b"\x08\x00\0\0\x00\x01\x00\x01PacketLens"
    icmp = icmp[:2] + struct.pack("!H", checksum(icmp)) + icmp[4:]
    icmp6 = b"\x80\0\0\0\0\x01\0\x01PacketLens"
    pseudo6 = ipaddress.ip_address("2001:db8::10").packed + ipaddress.ip_address("2001:db8::20").packed + struct.pack("!I3xB", len(icmp6), 58)
    icmp6 = icmp6[:2] + struct.pack("!H", checksum(pseudo6 + icmp6)) + icmp6[4:]
    frames = [
        ethernet(arp, 0x806), udp(query), udp(response, 53, 53000),
        tcp(seq=1000, ack=0, flags=2), tcp(seq=5000, ack=1001, flags=0x12, **reverse),
        tcp(flags=0x10), tcp(req),
        tcp(resp[35:], seq=5036, ack=1001+len(req), **reverse),
        tcp(resp[:35], seq=5001, ack=1001+len(req), **reverse),
        tcp(resp[:35], seq=5001, ack=1001+len(req), **reverse),
        tcp(seq=1001+len(req), ack=5001+len(resp), flags=0x11),
        tcp(seq=5001+len(resp), ack=1002+len(req), flags=0x11, **reverse),
        ip4(icmp, 1), udp(query, ipv6=True), ip6(icmp6, 58),
        tcp(b"\x17\x03\x03\x00\x08DEMOONLY", sport=49153, dport=443),
        udp(b"PacketLens local demo", sport=9000, dport=9001),
    ]
    return [decode(i+1, 1794441600+i*0.025, frame) for i, frame in enumerate(frames)]


if __name__ == "__main__":
    path = Path(__file__).resolve().parents[1] / "samples" / "demo.pcap"
    packets = sample_packets()
    write_pcap(path, packets)
    print(f"Generated {len(packets)} synthetic packets: {path}")
