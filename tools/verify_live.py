"""有界的真实 lo0 抓包验收；仅捕获本机 HTTP 实验端口。"""
from pathlib import Path
import json
import platform
import queue
import sys
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sniffer.capture import Capture
from sniffer.decoder import decode
from sniffer.pcap import write_pcap
from tools.local_traffic import generate


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("test-output")
    out.mkdir(parents=True, exist_ok=True)
    cap = Capture()
    interface = "lo0" if platform.system() == "Darwin" else "lo"
    cap.start(interface, "tcp port 8765 and host 127.0.0.1", seconds=4, count=200)
    time.sleep(0.5)
    if cap.running:
        try:
            print(generate(), end="")
        except Exception:
            cap.stop()
            cap.thread.join(5)
            raise
    cap.thread.join(6)
    if cap.running:
        cap.stop(); cap.thread.join(2)
        raise RuntimeError("抓包未按时停止")
    packets = []
    while True:
        try:
            timestamp, raw, wirelen, link = cap.events.get_nowait()
        except queue.Empty:
            break
        packets.append(decode(len(packets)+1, timestamp, raw, wirelen, link))
    passed = any(p.protocol == "HTTP" and p.info.startswith("GET /lab1a") for p in packets) and any(p.protocol == "HTTP" and p.info.startswith("HTTP/1.") for p in packets)
    result = dict(passed=passed, interface=interface, filter="tcp port 8765 and host 127.0.0.1", packets=len(packets),
                  http_packets=sum(p.protocol=="HTTP" for p in packets), error=cap.error, stats=cap.stats,
                  queue_dropped=cap.dropped, platform=platform.platform())
    (out / "live-result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2))
    if packets:
        write_pcap(out / "live-loopback.pcap", packets, packets[0].linktype)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
