"""PacketLens 原生 Tk 桌面界面。主线程更新控件；后台只负责抓包。"""
from collections import Counter
from pathlib import Path
import queue
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from .capture import Capture
from .decoder import decode, hexdump
from .filtering import compile_filter
from .pcap import Pcap, read_pcap, write_pcap
from .streams import reassemble

ROOT = Path(__file__).resolve().parent.parent
MAX_PACKETS = 10000
MAX_BYTES = 32 * 1024 * 1024


class App:
    def __init__(self, root):
        self.root, self.packets = root, []
        self.bytes = 0
        self.capture = Capture()
        self.predicate = compile_filter("")
        self.visible = []
        self.active = False
        self.importing = False
        self.closing = False
        self.reader = None
        self.root.title("PacketLens · 实验 1A 网络嗅探器")
        self.root.geometry("1280x840")
        self.root.minsize(1000, 680)
        self.root.configure(bg="#f3f6fa")
        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure("TFrame", background="#f3f6fa")
        style.configure("TLabel", background="#f3f6fa", foreground="#25324a", font=("Helvetica", 12))
        style.configure("TButton", padding=(10, 7), font=("Helvetica", 11), background="#e7eef7", borderwidth=0)
        style.map("TButton", background=[("active", "#ccddf5")])
        style.configure("Treeview", rowheight=28, font=("Helvetica", 11), background="white", fieldbackground="white")
        style.configure("Treeview.Heading", font=("Helvetica", 11, "bold"), padding=(5, 7), background="#e7eef7")
        style.map("Treeview", background=[("selected", "#d6e6fc")], foreground=[("selected", "#14345a")])
        top = tk.Frame(root, bg="#12253e", padx=22, pady=16)
        top.pack(fill="x")
        tk.Label(top, text="PacketLens", font=("Helvetica", 25, "bold"), fg="white", bg="#12253e").pack(side="left")
        tk.Label(top, text="NETWORK OBSERVATORY  /  实验 1A", font=("Helvetica", 11), fg="#a7bedb", bg="#12253e").pack(side="left", padx=20)
        self.badge = tk.Label(top, text="● 就绪", bg="#12253e", fg="#86dfca", font=("Helvetica", 12))
        self.badge.pack(side="right")
        controls = ttk.Frame(root, padding=(16, 10))
        controls.pack(fill="x")
        ttk.Label(controls, text="接口").grid(row=0, column=0, padx=4)
        self.device = tk.StringVar()
        self.devices = ttk.Combobox(controls, textvariable=self.device, width=20, state="readonly")
        self.devices.grid(row=0, column=1, padx=4)
        ttk.Button(controls, text="刷新", command=self.refresh).grid(row=0, column=2, padx=4)
        self.start_button = ttk.Button(controls, text="▶ 开始抓包", command=self.start)
        self.start_button.grid(row=0, column=3, padx=4)
        self.stop_button = ttk.Button(controls, text="■ 停止", command=self.stop, state="disabled")
        self.stop_button.grid(row=0, column=4, padx=4)
        self.open_button = ttk.Button(controls, text="打开 PCAP", command=self.open_file)
        self.open_button.grid(row=0, column=5, padx=4)
        ttk.Button(controls, text="导出可见包", command=self.save).grid(row=0, column=6, padx=4)
        self.sample_button = ttk.Button(controls, text="演示样本", command=lambda: self.load_file(ROOT / "samples" / "demo.pcap"))
        self.sample_button.grid(row=0, column=7, padx=4)
        ttk.Button(controls, text="使用帮助", command=self.help).grid(row=0, column=8, padx=4)
        options = ttk.Frame(root, padding=(20, 0, 20, 8))
        options.pack(fill="x")
        ttk.Label(options, text="抓包过滤 BPF").pack(side="left")
        self.bpf = tk.StringVar(value="")
        ttk.Entry(options, textvariable=self.bpf, width=32).pack(side="left", padx=8)
        ttk.Label(options, text="时限 / 秒").pack(side="left", padx=(12, 4))
        self.duration = tk.StringVar(value="60")
        ttk.Spinbox(options, from_=1, to=3600, width=5, textvariable=self.duration).pack(side="left")
        ttk.Label(options, text="包数上限").pack(side="left", padx=(12, 4))
        self.limit = tk.StringVar(value="10000")
        ttk.Spinbox(options, from_=1, to=10000, width=7, textvariable=self.limit).pack(side="left")
        self.promiscuous = tk.BooleanVar(value=False)
        ttk.Checkbutton(options, text="混杂模式", variable=self.promiscuous).pack(side="left", padx=12)
        filters = ttk.Frame(root, padding=(20, 0, 20, 10))
        filters.pack(fill="x")
        ttk.Label(filters, text="显示过滤").pack(side="left")
        self.filter_text = tk.StringVar()
        entry = ttk.Entry(filters, textvariable=self.filter_text)
        entry.pack(side="left", fill="x", expand=True, padx=8)
        entry.bind("<Return>", lambda e: self.apply_filter())
        ttk.Button(filters, text="应用", command=self.apply_filter).pack(side="left")
        for name in ("全部", "HTTP", "DNS", "TCP", "UDP", "IPv6", "ICMP"):
            ttk.Button(filters, text=name, width=5, command=lambda n=name: self.quick(n)).pack(side="left", padx=2)
        self.summary = tk.StringVar(value="0 packets  /  0 bytes")
        ttk.Label(root, textvariable=self.summary, padding=(22, 5)).pack(fill="x")
        panes = ttk.Panedwindow(root, orient="vertical")
        panes.pack(fill="both", expand=True, padx=16, pady=(4, 8))
        packet_frame = ttk.Frame(panes)
        columns = ("no", "time", "src", "dst", "proto", "length", "info")
        self.table = ttk.Treeview(packet_frame, columns=columns, show="headings", selectmode="browse")
        for key, title, width in zip(columns, ["No.", "时间 / s", "源地址", "目的地址", "协议", "字节", "摘要"], [50,90,175,175,75,55,450]):
            self.table.heading(key, text=title)
            self.table.column(key, width=width, minwidth=40, stretch=key == "info")
        scrollbar = ttk.Scrollbar(packet_frame, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.table.pack(fill="both", expand=True)
        for proto, color in {"HTTP":"#e9f6f0", "DNS":"#eef1ff", "TCP":"#f0f6fc", "UDP":"#f0f8ff", "ICMP":"#fff6e5", "ICMPv6":"#fff6e5", "ARP":"#f8edf4", "TLS":"#f2edfc"}.items():
            self.table.tag_configure(proto, background=color)
        self.table.bind("<<TreeviewSelect>>", self.select)
        self.table.bind("<Double-1>", lambda e: self.follow())
        panes.add(packet_frame, weight=3)
        lower = ttk.Panedwindow(panes, orient="horizontal")
        details_frame = ttk.Frame(lower)
        ttk.Label(details_frame, text="协议层次与字段", padding=8, font=("Helvetica", 12, "bold")).pack(anchor="w")
        self.details = ttk.Treeview(details_frame, show="tree")
        scroll = ttk.Scrollbar(details_frame, orient="vertical", command=self.details.yview)
        self.details.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.details.pack(fill="both", expand=True)
        lower.add(details_frame, weight=1)
        hex_frame = ttk.Frame(lower)
        head = ttk.Frame(hex_frame)
        head.pack(fill="x")
        ttk.Label(head, text="原始字节 · HEX / ASCII", padding=8, font=("Helvetica", 12, "bold")).pack(side="left")
        ttk.Button(head, text="追踪 TCP 流", command=self.follow).pack(side="right", padx=8)
        self.hex = self.text_widget(hex_frame)
        lower.add(hex_frame, weight=2)
        panes.add(lower, weight=2)
        root.after(100, lambda: panes.sashpos(0, max(220, int(root.winfo_height() * .36)) ))
        root.after(100, lambda: lower.sashpos(0, 440))
        self.status = tk.StringVar(value="可加载演示样本；实时抓包前选择接口。仅在授权网络使用。")
        ttk.Label(root, textvariable=self.status, padding=(20, 8), wraplength=1200).pack(fill="x")
        self.refresh()
        menu = tk.Menu(root)
        files = tk.Menu(menu, tearoff=False)
        files.add_command(label="打开 PCAP", command=self.open_file, accelerator="Command+O")
        files.add_command(label="导出演示结果", command=self.save, accelerator="Command+E")
        files.add_command(label="加载演示样本", command=lambda: self.load_file(ROOT / "samples/demo.pcap"))
        files.add_separator()
        files.add_command(label="退出", command=self.close)
        menu.add_cascade(label="文件", menu=files)
        filters_menu = tk.Menu(menu, tearoff=False)
        for number, name in enumerate(("全部", "HTTP", "DNS", "IPv6"), 1):
            filters_menu.add_command(label=name, command=lambda n=name: self.quick(n), accelerator=f"Command+{number}")
            root.bind(f"<Command-Key-{number}>", lambda e, n=name: self.quick(n))
        menu.add_cascade(label="过滤", menu=filters_menu)
        menu.add_command(label="追踪 TCP 流", command=self.follow)
        root.configure(menu=menu)
        root.bind("<Command-o>", lambda e: self.open_file())
        root.bind("<Command-e>", lambda e: self.save())
        root.bind("<Command-f>", lambda e: self.follow())
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.after(80, self.poll)

    @staticmethod
    def text_widget(parent):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        text = tk.Text(frame, wrap="none", bg="#fbfcfe", fg="#21334d", font=("Menlo", 11), relief="flat", padx=10, pady=8)
        y = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        x = ttk.Scrollbar(frame, orient="horizontal", command=text.xview)
        text.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        y.pack(side="right", fill="y")
        x.pack(side="bottom", fill="x")
        text.pack(fill="both", expand=True)
        text.configure(state="disabled")
        return text

    @staticmethod
    def set_text(widget, value):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.configure(state="disabled")

    def refresh(self):
        try:
            devices = Pcap().devices()
            self.devices["values"] = [name for name, _ in devices]
            if not self.device.get() and devices:
                self.device.set("lo0" if "lo0" in self.devices["values"] else devices[0][0])
        except Exception as exc:
            self.status.set(f"网卡枚举不可用：{exc}；仍可离线分析 PCAP。")

    def set_busy(self, busy):
        for button in (self.start_button, self.open_button, self.sample_button):
            button.configure(state="disabled" if busy else "normal")
        self.stop_button.configure(state="normal" if busy else "disabled")

    def reset(self):
        self.packets.clear()
        self.visible.clear()
        self.bytes = 0
        self.table.delete(*self.table.get_children())
        self.details.delete(*self.details.get_children())
        self.set_text(self.hex, "")
        self.update_summary()

    def confirm_replace(self):
        return not self.packets or messagebox.askyesno("开始新会话", "当前会话将被清空。需要保存时请先取消并导出。是否继续？")

    def start(self):
        if self.active or self.importing:
            return
        try:
            seconds, limit = int(self.duration.get()), int(self.limit.get())
            if not self.device.get():
                raise ValueError("请选择网卡")
            if not 1 <= seconds <= 3600 or not 1 <= limit <= MAX_PACKETS:
                raise ValueError("时限为 1..3600 秒；包数为 1..10000")
            if not self.confirm_replace():
                return
            self.capture.start(self.device.get(), self.bpf.get(), seconds, limit, self.promiscuous.get())
            self.reset()
            self.active = True
            self.set_busy(True)
            self.badge.configure(text="● 正在抓包", fg="#86dfca")
            self.status.set(f"接口 {self.device.get()} | BPF: {self.bpf.get() or '无'} | 自动停止 {seconds}s / {limit} 包")
        except Exception as exc:
            messagebox.showerror("无法开始", str(exc))

    def stop(self):
        if self.importing:
            self.finish_import("已停止导入，保留已读包")
        self.capture.stop()

    def append(self, record):
        timestamp, raw, wirelen, linktype = record
        if len(self.packets) >= MAX_PACKETS or self.bytes + len(raw) > MAX_BYTES:
            self.status.set("已达到内存上限（10000 包 / 32 MiB 原始字节），保留已收数据")
            return False
        p = decode(len(self.packets) + 1, timestamp, raw, wirelen, linktype)
        self.packets.append(p)
        self.bytes += len(raw)
        if self.predicate(p):
            self.insert(p)
        return True

    def insert(self, p):
        self.visible.append(p)
        self.table.insert("", "end", iid=str(p.number), values=(p.number, f"{p.timestamp-self.packets[0].timestamp:.6f}",
                          p.src, p.dst, p.protocol, p.wirelen, p.info), tags=(p.protocol,))

    def poll(self):
        changed = False
        for _ in range(200):
            try:
                record = self.capture.events.get_nowait()
            except queue.Empty:
                break
            if not self.append(record):
                self.capture.stop()
            changed = True
        if changed:
            self.update_summary()
        if self.active and not self.capture.running and self.capture.events.empty():
            self.active = False
            self.set_busy(False)
            self.badge.configure(text="● 已停止")
            self.status.set(f"{self.capture.reason} | 队列丢包 {self.capture.dropped} | libpcap 统计 {self.capture.stats or '不可用'}" + (" | " + self.capture.error if self.capture.error else ""))
            if self.capture.error and not self.closing:
                messagebox.showerror("抓包失败", self.capture.error)
        if self.closing and not self.capture.running:
            self.root.destroy()
            return
        self.root.after(80, self.poll)

    def update_summary(self):
        counts = Counter(p.protocol for p in self.visible)
        warning_count = sum(bool(p.warnings) for p in self.packets)
        protocols = "   ".join(f"{name} {count}" for name, count in counts.most_common(8))
        self.summary.set(f"显示 {len(self.visible)} / {len(self.packets)} 包   ·   {self.bytes:,} bytes   ·   异常 {warning_count}   |   {protocols}")

    def quick(self, name):
        self.filter_text.set("" if name == "全部" else name.lower())
        self.apply_filter()

    def apply_filter(self):
        try:
            predicate = compile_filter(self.filter_text.get())
        except ValueError as exc:
            self.status.set(f"过滤器错误（保留原过滤结果）：{exc}")
            return False
        self.predicate = predicate
        self.table.delete(*self.table.get_children())
        self.visible.clear()
        self.details.delete(*self.details.get_children())
        self.set_text(self.hex, "")
        for p in self.packets:
            if predicate(p):
                self.insert(p)
        if self.visible:
            self.table.selection_set(str(self.visible[0].number))
            self.table.focus(str(self.visible[0].number))
            self.select()
        self.update_summary()
        self.status.set("显示过滤：" + (self.filter_text.get() or "全部") + "；抓包 BPF 只在开始时生效")
        return True

    def select(self, event=None):
        ids = self.table.selection()
        if not ids:
            return
        p = self.packets[int(ids[0]) - 1]
        self.details.delete(*self.details.get_children())
        for name, fields in p.layers:
            node = self.details.insert("", "end", text=name, open=name == p.protocol)
            for key, value in fields.items():
                self.details.insert(node, "end", text=f"{key}: {value}")
        for warning in p.warnings:
            self.details.insert("", "end", text="⚠ " + warning)
        self.set_text(self.hex, hexdump(p.raw))

    def follow(self):
        ids = self.table.selection()
        if not ids:
            messagebox.showinfo("追踪 TCP 流", "请先选择一个 TCP / HTTP / TLS 包")
            return
        p = self.packets[int(ids[0]) - 1]
        if p.flow_key is None:
            messagebox.showinfo("追踪 TCP 流", "所选包不是 TCP")
            return
        window = tk.Toplevel(self.root)
        window.title("TCP 流 · 双向重组")
        window.geometry("1000x650")
        window.configure(bg="#f3f6fa")
        ttk.Label(window, text="按序列号重组 · 重复字节去除 · 缺口显式标注 · 不解密 TLS", padding=12).pack(anchor="w")
        ttk.Label(window, text="按端点聚合；同一四元组多次连接可能合并。重叠数据按序列位置优先、同位置首见优先。", padding=(12,0,12,8)).pack(anchor="w")
        notebook = ttk.Notebook(window)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)
        self.last_stream_window = window
        for title, data, duplicates, gaps in reassemble(self.packets, p.flow_key):
            frame = ttk.Frame(notebook)
            notebook.add(frame, text=title)
            ttk.Label(frame, text=f"去重字节 {duplicates}  |  缺失字节 {gaps}  |  UTF-8 替换显示", padding=8).pack(anchor="w")
            text = self.text_widget(frame)
            self.set_text(text, data.decode("utf-8", "replace") or "（此方向没有应用层载荷）")

    def open_file(self):
        path = filedialog.askopenfilename(filetypes=[("PCAP", "*.pcap"), ("所有文件", "*")])
        if path:
            self.load_file(path)

    def load_file(self, path):
        if self.active or self.importing or not self.confirm_replace():
            return
        self.reset()
        self.importing = True
        self.set_busy(True)
        self.reader = read_pcap(path)
        self.badge.configure(text="● 离线分析")
        self.status.set(f"导入 {Path(path).name}")
        self.root.after(1, self.import_chunk)

    def import_chunk(self):
        if not self.importing:
            return
        try:
            for _ in range(200):
                if not self.append(next(self.reader)):
                    self.finish_import("导入达到内存上限，保留已读包")
                    return
        except StopIteration:
            self.finish_import("PCAP 导入完成")
            return
        except (OSError, ValueError) as exc:
            self.finish_import(f"导入失败：{exc}；保留已读包")
            return
        self.update_summary()
        self.root.after(1, self.import_chunk)

    def finish_import(self, status):
        self.importing = False
        if self.reader:
            self.reader.close()
            self.reader = None
        self.set_busy(False)
        self.update_summary()
        self.status.set(status)
        if self.visible:
            self.table.selection_set(str(self.visible[0].number))

    def save(self):
        if not self.visible:
            messagebox.showinfo("导出", "没有可导出的包")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP", "*.pcap")])
        if path:
            try:
                write_pcap(path, self.visible, self.visible[0].linktype)
                self.status.set(f"已导出 {len(self.visible)} 个可见包：{path}")
            except (OSError, ValueError) as exc:
                messagebox.showerror("导出失败", str(exc))

    def help(self):
        messagebox.showinfo("PacketLens 使用帮助", "1. 离线体验：点击演示样本，无需抓包权限。\n2. macOS 本机测试选 lo0，BPF 填 tcp port 8765。\n3. 开始抓包，再运行 python3 tools/local_traffic.py。\n4. 选择一行查看协议和字节；双击或按钮追踪 TCP 流。\n\n显示过滤例子：\nhttp or dns\ntcp and (port 80 or port 8765)\nipv6 and not udp\nhost 127.0.0.1\nsrc 192.0.2.10 and contains get\n\nBPF 由 libpcap 编译；显示过滤为本程序语法，不是完整 Wireshark 语法。\n默认 60 秒 / 10000 包；32 MiB 原始数据上限。\nHTTPS 仅识别 TLS 记录；不解密内容。")

    def close(self):
        self.closing = True
        if self.importing:
            self.finish_import("正在退出")
        self.capture.stop()
        self.status.set("正在等待抓包线程释放句柄…")


def main():
    root = tk.Tk()
    app = App(root)
    import sys
    if "--demo" in sys.argv:
        root.after(200, lambda: app.load_file(ROOT / "samples" / "demo.pcap"))
    root.mainloop()
