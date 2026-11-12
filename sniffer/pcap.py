"""libpcap/Npcap 的最小 ctypes 绑定，以及独立的 classic PCAP 文件读写。"""
import ctypes as C
import ctypes.util
import os
import struct

MAX_FRAME = 262144


class Timeval(C.Structure):
    _fields_ = [("sec", C.c_long), ("usec", C.c_long)]


class Header(C.Structure):
    _fields_ = [("ts", Timeval), ("caplen", C.c_uint32), ("len", C.c_uint32)]


class Device(C.Structure):
    pass


Device._fields_ = [("next", C.POINTER(Device)), ("name", C.c_char_p),
                  ("description", C.c_char_p), ("addresses", C.c_void_p), ("flags", C.c_uint)]


class Bpf(C.Structure):
    _fields_ = [("length", C.c_uint), ("instructions", C.c_void_p)]


class Stats(C.Structure):
    _fields_ = [("received", C.c_uint), ("dropped", C.c_uint), ("interface_dropped", C.c_uint)]


class Pcap:
    def __init__(self):
        self.dll_dir = None
        if os.name == "nt":
            folder = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap")
            if hasattr(os, "add_dll_directory"):
                self.dll_dir = os.add_dll_directory(folder)
            path = os.path.join(folder, "wpcap.dll")
        else:
            path = ctypes.util.find_library("pcap")
        if not path:
            raise OSError("找不到 libpcap；Windows 请安装 Npcap，Linux 请安装 libpcap")
        self.lib = C.CDLL(path)
        signatures = {
            "pcap_findalldevs": ([C.POINTER(C.POINTER(Device)), C.c_char_p], C.c_int),
            "pcap_freealldevs": ([C.POINTER(Device)], None),
            "pcap_open_live": ([C.c_char_p, C.c_int, C.c_int, C.c_int, C.c_char_p], C.c_void_p),
            "pcap_open_dead": ([C.c_int, C.c_int], C.c_void_p),
            "pcap_close": ([C.c_void_p], None),
            "pcap_geterr": ([C.c_void_p], C.c_char_p),
            "pcap_datalink": ([C.c_void_p], C.c_int),
            "pcap_setnonblock": ([C.c_void_p, C.c_int, C.c_char_p], C.c_int),
            "pcap_compile": ([C.c_void_p, C.POINTER(Bpf), C.c_char_p, C.c_int, C.c_uint32], C.c_int),
            "pcap_setfilter": ([C.c_void_p, C.POINTER(Bpf)], C.c_int),
            "pcap_freecode": ([C.POINTER(Bpf)], None),
            "pcap_offline_filter": ([C.POINTER(Bpf), C.POINTER(Header), C.c_void_p], C.c_uint),
            "pcap_next_ex": ([C.c_void_p, C.POINTER(C.POINTER(Header)), C.POINTER(C.POINTER(C.c_ubyte))], C.c_int),
            "pcap_stats": ([C.c_void_p, C.POINTER(Stats)], C.c_int),
        }
        for name, (args, result) in signatures.items():
            fn = getattr(self.lib, name)
            fn.argtypes, fn.restype = args, result

    def devices(self):
        first, err = C.POINTER(Device)(), C.create_string_buffer(256)
        if self.lib.pcap_findalldevs(C.byref(first), err) != 0:
            raise OSError(err.value.decode(errors="replace"))
        result, node = [], first
        try:
            while node:
                d = node.contents
                result.append((d.name.decode(errors="replace"), (d.description or b"").decode(errors="replace")))
                node = d.next
        finally:
            self.lib.pcap_freealldevs(first)
        return result

    def error(self, handle):
        return (self.lib.pcap_geterr(handle) or b"libpcap error").decode(errors="replace")

    def compile(self, handle, expression):
        prog = Bpf()
        if self.lib.pcap_compile(handle, C.byref(prog), expression.encode(), 1, 0xFFFFFFFF):
            raise ValueError("BPF 过滤器错误：" + self.error(handle))
        return prog

    def open(self, name, expression="", promiscuous=False):
        err = C.create_string_buffer(256)
        handle = self.lib.pcap_open_live(name.encode(), 65535, int(promiscuous), 100, err)
        if not handle:
            raise OSError(err.value.decode(errors="replace") + "；请检查网卡和抓包权限")
        try:
            if expression.strip():
                prog = self.compile(handle, expression)
                try:
                    if self.lib.pcap_setfilter(handle, C.byref(prog)):
                        raise ValueError(self.error(handle))
                finally:
                    self.lib.pcap_freecode(C.byref(prog))
            if self.lib.pcap_setnonblock(handle, 1, err):
                raise OSError(err.value.decode(errors="replace"))
            return handle, self.lib.pcap_datalink(handle)
        except Exception:
            self.lib.pcap_close(handle)
            raise

    def next(self, handle):
        header, data = C.POINTER(Header)(), C.POINTER(C.c_ubyte)()
        result = self.lib.pcap_next_ex(handle, C.byref(header), C.byref(data))
        if result == 0:
            return None
        if result < 0:
            raise OSError(self.error(handle))
        h = header.contents
        if h.caplen > MAX_FRAME:
            raise ValueError("抓包帧超过安全上限")
        return h.ts.sec + h.ts.usec / 1e6, C.string_at(data, h.caplen), h.len

    def stats(self, handle):
        # Windows pcap_stat 可有额外成员；提供足够大的缓冲区。
        buf = C.create_string_buffer(256)
        if self.lib.pcap_stats(handle, C.cast(buf, C.POINTER(Stats))):
            return None
        value = C.cast(buf, C.POINTER(Stats)).contents
        return {name: getattr(value, name) for name, _ in Stats._fields_}

    def matches(self, packets, expression, linktype=1):
        """离线验证实际 BPF 编译与执行，无需抓包权限。"""
        handle = self.lib.pcap_open_dead(linktype, 65535)
        if not handle:
            raise OSError("pcap_open_dead failed")
        try:
            prog = self.compile(handle, expression)
            try:
                result = []
                for p in packets:
                    header = Header(Timeval(0, 0), len(p.raw), p.wirelen)
                    data = C.create_string_buffer(p.raw)
                    result.append(bool(self.lib.pcap_offline_filter(C.byref(prog), C.byref(header), data)))
                return result
            finally:
                self.lib.pcap_freecode(C.byref(prog))
        finally:
            self.lib.pcap_close(handle)


def read_pcap(path):
    with open(path, "rb") as f:
        header = f.read(24)
        if len(header) != 24:
            raise ValueError("PCAP 文件头截断")
        formats = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
                   b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9)}
        if header[:4] not in formats:
            raise ValueError("仅支持 classic PCAP；PCAPNG 请先用 Wireshark 转存为 PCAP")
        endian, scale = formats[header[:4]]
        major, minor, _, _, snaplen, network = struct.unpack(endian + "HHIIII", header[4:])
        linktype = network & 0xFFFF
        if (major, minor) != (2, 4) or not 0 < snaplen <= MAX_FRAME:
            raise ValueError("PCAP 版本或 snaplen 不支持")
        while True:
            record = f.read(16)
            if not record:
                break
            if len(record) != 16:
                raise ValueError("PCAP 记录头截断")
            sec, sub, caplen, wirelen = struct.unpack(endian + "IIII", record)
            if caplen > snaplen or caplen > wirelen or sub >= scale:
                raise ValueError("PCAP 记录长度或时间戳非法")
            data = f.read(caplen)
            if len(data) != caplen:
                raise ValueError("PCAP 数据截断")
            yield sec + sub / scale, data, wirelen, linktype


def write_pcap(path, packets, linktype=1):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, MAX_FRAME, linktype))
        for p in packets:
            if p.linktype != linktype:
                raise ValueError("单个 classic PCAP 不能混用链路类型")
            sec = int(p.timestamp)
            micros = min(999999, round((p.timestamp - sec) * 1e6))
            f.write(struct.pack("<IIII", sec, micros, len(p.raw), p.wirelen))
            f.write(p.raw)
