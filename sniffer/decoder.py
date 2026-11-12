"""显式按网络字节序解析协议；不依赖 Scapy/Wireshark。"""
from dataclasses import dataclass, field
import ipaddress
import struct


@dataclass
class Packet:
    number: int
    timestamp: float
    raw: bytes
    wirelen: int
    linktype: int = 1
    src: str = ""
    dst: str = ""
    sport: int = 0
    dport: int = 0
    protocol: str = "Unknown"
    info: str = ""
    protocols: set = field(default_factory=set)
    layers: list = field(default_factory=list)
    payload: bytes = b""
    seq: int = 0
    flags: int = 0
    fragmented: bool = False
    warnings: list = field(default_factory=list)

    def layer(self, name, **values):
        self.protocols.add(name.lower())
        self.protocol = name
        self.layers.append((name, values))

    @property
    def flow_key(self):
        if "tcp" not in self.protocols:
            return None
        return tuple(sorted(((self.src, self.sport), (self.dst, self.dport))))


def require(data, size):
    if len(data) < size:
        raise ValueError(f"报文截断：需要 {size} 字节，实际 {len(data)} 字节")


def mac(data):
    return ":".join(f"{v:02x}" for v in data)


def dns_name(data, start):
    parts, seen, pos, end = [], set(), start, None
    for _ in range(128):
        if pos in seen:
            raise ValueError("DNS 压缩指针循环")
        seen.add(pos)
        require(data, pos + 1)
        length = data[pos]
        if length & 0xC0 == 0xC0:
            require(data, pos + 2)
            end = end if end is not None else pos + 2
            pos = ((length & 63) << 8) | data[pos + 1]
        elif length == 0:
            return ".".join(parts), end if end is not None else pos + 1
        elif length > 63:
            raise ValueError("DNS 标签长度非法")
        else:
            require(data, pos + 1 + length)
            parts.append(data[pos + 1:pos + 1 + length].decode("ascii", "replace"))
            pos += 1 + length
    raise ValueError("DNS 名称过深")


def application(p):
    data = p.payload
    first = data.split(b"\r\n", 1)[0]
    methods = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ")
    if "tcp" in p.protocols and (data.startswith(b"HTTP/1.") or (data.startswith(methods) and b" HTTP/1." in first)):
        head = data.split(b"\r\n\r\n", 1)[0][:8192].decode("utf-8", "replace")
        p.layer("HTTP", start_line=first.decode("utf-8", "replace"), headers=head,
                note="按载荷识别 HTTP/1.x；跨包头部请使用 TCP 流追踪")
        p.info = first.decode("utf-8", "replace")[:200]
    elif "tcp" in p.protocols and len(data) >= 5 and data[0] in (20, 21, 22, 23) and data[1] == 3 and data[2] <= 4:
        length = int.from_bytes(data[3:5], "big")
        p.layer("TLS", content_type=data[0], record_version=f"0x{data[1:3].hex()}",
                record_length=length, note="仅记录头识别，不解密；记录版本不等于协商版本")
        p.info = f"TLS record type={data[0]} length={length}"
    elif 53 in (p.sport, p.dport) and ("udp" in p.protocols or "tcp" in p.protocols):
        if "tcp" in p.protocols:
            require(data, 2)
            size = int.from_bytes(data[:2], "big")
            require(data, size + 2)
            data = data[2:2 + size]
        require(data, 12)
        ident, flags, qd, an, ns, ar = struct.unpack("!6H", data[:12])
        questions, pos = [], 12
        if qd > 64:
            raise ValueError("DNS 问题数超过分析上限 64")
        for _ in range(qd):
            name, pos = dns_name(data, pos)
            require(data, pos + 4)
            qtype, qclass = struct.unpack_from("!HH", data, pos)
            questions.append(f"{name} type={qtype} class={qclass}")
            pos += 4
        answers = []
        if an > 128:
            raise ValueError("DNS 应答数超过分析上限 128")
        for _ in range(an):
            name, pos = dns_name(data, pos)
            require(data, pos + 10)
            typ, cls, ttl, size = struct.unpack_from("!HHIH", data, pos)
            pos += 10
            require(data, pos + size)
            value = data[pos:pos + size].hex()
            if (typ, size) in ((1, 4), (28, 16)):
                value = str(ipaddress.ip_address(data[pos:pos + size]))
            elif typ in (5, 2, 12):
                value, _ = dns_name(data, pos)
            answers.append(f"{name} type={typ} ttl={ttl} {value}")
            pos += size
        p.layer("DNS", transaction_id=f"0x{ident:04x}", response=bool(flags & 0x8000),
                rcode=flags & 15, questions=questions, answers=answers, authority_count=ns, additional_count=ar)
        p.info = f"DNS {'response' if flags & 0x8000 else 'query'} " + "; ".join(questions)


def transport(p, data, proto):
    if proto == 6:
        require(data, 20)
        p.sport, p.dport, p.seq, ack, bits, window, checksum, urgent = struct.unpack("!HHIIHHHH", data[:20])
        size, p.flags = (bits >> 12) * 4, bits & 0x1FF
        if size < 20:
            raise ValueError("TCP 头长度小于 20")
        require(data, size)
        flags = ",".join(name for bit, name in [(1,"FIN"),(2,"SYN"),(4,"RST"),(8,"PSH"),(16,"ACK"),(32,"URG"),(64,"ECE"),(128,"CWR")] if p.flags & bit)
        p.payload = data[size:]
        p.layer("TCP", source_port=p.sport, destination_port=p.dport, sequence=p.seq,
                acknowledgment=ack, flags=flags, header_length=size, window=window,
                checksum=f"0x{checksum:04x} (未验证)", urgent_pointer=urgent, payload_length=len(p.payload))
        p.info = f"{p.sport} → {p.dport} [{flags}] Seq={p.seq} Ack={ack} Len={len(p.payload)}"
    elif proto == 17:
        require(data, 8)
        p.sport, p.dport, size, checksum = struct.unpack("!HHHH", data[:8])
        if size < 8:
            raise ValueError("UDP 长度小于 8")
        require(data, size)
        p.payload = data[8:size]
        p.layer("UDP", source_port=p.sport, destination_port=p.dport, length=size, checksum=f"0x{checksum:04x} (未验证)")
        p.info = f"{p.sport} → {p.dport} Len={size}"
    elif proto in (1, 58):
        require(data, 4)
        p.payload = data[4:]
        name = "ICMP" if proto == 1 else "ICMPv6"
        p.layer(name, type=data[0], code=data[1], checksum=data[2:4].hex())
        p.info = f"{name} Type={data[0]} Code={data[1]}"
        return
    else:
        p.payload = data
        p.info = f"IP protocol / next header = {proto}"
        return
    if p.payload:
        application(p)


def decode(number, timestamp, data, wirelen=None, linktype=1):
    p = Packet(number, timestamp, data, wirelen if wirelen is not None else len(data), linktype)
    p.layers.append(("Frame", dict(number=number, captured=len(data), on_wire=p.wirelen, linktype=linktype)))
    if len(data) < p.wirelen:
        p.warnings.append("抓包截断：captured length < original length")
    try:
        if linktype == 1:
            require(data, 14)
            typ = int.from_bytes(data[12:14], "big")
            p.src, p.dst = mac(data[6:12]), mac(data[:6])
            p.layer("Ethernet", source=p.src, destination=p.dst, ethertype=f"0x{typ:04x}")
            data = data[14:]
            for _ in range(4):
                if typ not in (0x8100, 0x88A8):
                    break
                require(data, 4)
                tci, typ = struct.unpack("!HH", data[:4])
                p.layer("VLAN", vlan_id=tci & 4095, priority=tci >> 13)
                data = data[4:]
        elif linktype in (0, 108):
            require(data, 4)
            family = int.from_bytes(data[:4], "big" if linktype == 108 else "little")
            if family not in (2, 10, 24, 28, 30):
                family = int.from_bytes(data[:4], "big")
            typ = 0x800 if family == 2 else 0x86DD if family in (10, 24, 28, 30) else 0
            p.layer("Loopback", family=family)
            data = data[4:]
        elif linktype in (12, 101, 228, 229):
            require(data, 1)
            typ = 0x800 if data[0] >> 4 == 4 else 0x86DD
        elif linktype in (113, 276):
            size = 16 if linktype == 113 else 20
            require(data, size)
            typ = int.from_bytes(data[14:16] if size == 16 else data[:2], "big")
            p.layer("Linux cooked", version=1 if size == 16 else 2)
            data = data[size:]
        else:
            p.info = f"未支持链路类型 {linktype}，保留原始数据"
            return p
        if typ == 0x806:
            require(data, 8)
            hw, pr, hl, pl, op = struct.unpack("!HHBBH", data[:8])
            require(data, 8 + 2 * (hl + pl))
            if (hw, pr, hl, pl) == (1, 0x800, 6, 4):
                p.src, p.dst = str(ipaddress.ip_address(data[14:18])), str(ipaddress.ip_address(data[24:28]))
                p.layer("ARP", operation=op, sender_mac=mac(data[8:14]), sender_ip=p.src,
                        target_mac=mac(data[18:24]), target_ip=p.dst)
                p.info = f"ARP {'request' if op == 1 else 'reply'} {p.src} → {p.dst}"
            else:
                p.layer("ARP", hardware=hw, protocol=pr, operation=op)
        elif typ == 0x800:
            require(data, 20)
            size, total = (data[0] & 15) * 4, int.from_bytes(data[2:4], "big")
            if data[0] >> 4 != 4 or size < 20 or total < size:
                raise ValueError("IPv4 版本或长度非法")
            require(data, size)
            if len(data) < total:
                p.warnings.append("IPv4 数据不足 total length")
            frag, proto = int.from_bytes(data[6:8], "big"), data[9]
            p.src, p.dst = str(ipaddress.ip_address(data[12:16])), str(ipaddress.ip_address(data[16:20]))
            p.layer("IPv4", source=p.src, destination=p.dst, header_length=size, total_length=total,
                    identification=int.from_bytes(data[4:6], "big"), ttl=data[8], protocol=proto,
                    fragment_offset=(frag & 8191) * 8, more_fragments=bool(frag & 0x2000))
            if frag & 0x3FFF:
                p.fragmented = True
                p.info = "IPv4 分片：未重组，保留 IP 层"
            else:
                transport(p, data[size:total], proto)
        elif typ == 0x86DD:
            require(data, 40)
            if data[0] >> 4 != 6:
                raise ValueError("IPv6 版本非法")
            size, proto = int.from_bytes(data[4:6], "big"), data[6]
            p.src, p.dst = str(ipaddress.ip_address(data[8:24])), str(ipaddress.ip_address(data[24:40]))
            p.layer("IPv6", source=p.src, destination=p.dst, payload_length=size, next_header=proto, hop_limit=data[7])
            if len(data) < 40 + size:
                p.warnings.append("IPv6 数据不足 payload length")
            data = data[40:40 + size]
            for _ in range(16):
                if proto not in (0, 43, 44, 51, 60):
                    break
                require(data, 8)
                old = proto
                if old == 44:
                    frag = int.from_bytes(data[2:4], "big")
                    p.fragmented = bool(frag & 0xFFF9)
                    length = 8
                else:
                    length = (data[1] + 2) * 4 if old == 51 else (data[1] + 1) * 8
                require(data, length)
                p.layers.append(("IPv6 extension", dict(type=old, length=length)))
                proto, data = data[0], data[length:]
                if p.fragmented:
                    break
            else:
                raise ValueError("IPv6 扩展头数量超过 16")
            if p.fragmented:
                p.info = "IPv6 分片：未重组，保留 IP 层"
            else:
                transport(p, data, proto)
        else:
            p.info = f"EtherType 0x{typ:04x}"
    except (ValueError, struct.error, IndexError) as exc:
        p.warnings.append(str(exc))
        p.info = (p.info + " | " if p.info else "") + "解析不完整：" + str(exc)
    return p


def hexdump(data):
    return "\n".join(f"{i:06x}  " + " ".join(f"{v:02x}" for v in data[i:i+16]).ljust(47)
                     + "  " + "".join(chr(v) if 32 <= v < 127 else "." for v in data[i:i+16])
                     for i in range(0, len(data), 16))
