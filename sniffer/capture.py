"""抓包句柄只归 worker 所有；UI 经有界队列获取事件。"""
import queue
import threading
import time
from .pcap import Pcap


class Capture:
    def __init__(self):
        self.events = queue.Queue(maxsize=2048)
        self.stop_event = threading.Event()
        self.thread = None
        self.dropped = 0
        self.error = ""
        self.stats = None
        self.reason = ""

    @property
    def running(self):
        return self.thread is not None and self.thread.is_alive()

    def start(self, device, expression="", seconds=60, count=10000, promiscuous=False):
        if self.running:
            raise RuntimeError("抓包已在运行")
        if not 1 <= seconds <= 3600 or not 1 <= count <= 50000:
            raise ValueError("时间范围 1..3600 秒，包数范围 1..50000")
        self.stop_event.clear()
        self.dropped, self.error, self.stats, self.reason = 0, "", None, ""

        def worker():
            api, handle = None, None
            try:
                api = Pcap()
                handle, linktype = api.open(device, expression, promiscuous)
                end, received = time.monotonic() + seconds, 0
                while not self.stop_event.is_set() and time.monotonic() < end and received < count:
                    value = api.next(handle)
                    if value is None:
                        self.stop_event.wait(0.01)
                        continue
                    received += 1
                    try:
                        self.events.put_nowait((*value, linktype))
                    except queue.Full:
                        self.dropped += 1
                self.reason = "用户停止" if self.stop_event.is_set() else "包数上限" if received >= count else "时间上限"
            except Exception as exc:
                self.error, self.reason = str(exc), "抓包失败"
            finally:
                if handle:
                    self.stats = api.stats(handle)
                    api.lib.pcap_close(handle)

        self.thread = threading.Thread(target=worker, name="pcap-capture", daemon=False)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
