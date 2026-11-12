"""实际 Tk 窗口集成测试；需桌面会话。--show 在验收后保留窗口。"""
from pathlib import Path
import sys
import time
import tempfile
import tkinter as tk
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sniffer.gui import App, ROOT
from sniffer.pcap import read_pcap


def pump(root, predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("GUI action timed out")
        root.update()
        time.sleep(0.01)
    root.update()


def main():
    root = tk.Tk()
    app = App(root)
    app.load_file(ROOT / "samples/demo.pcap")
    pump(root, lambda: not app.importing)
    assert len(app.packets) == 17
    app.quick("HTTP")
    assert len(app.visible) == 3
    app.filter_text.set("tcp and (")
    assert app.apply_filter() is False and len(app.visible) == 3
    app.quick("全部")
    app.table.selection_set("7")
    app.select()
    assert "47 45 54" in app.hex.get("1.0", "end")
    app.follow()
    root.update()
    assert app.last_stream_window.winfo_exists()
    app.last_stream_window.destroy()
    with tempfile.TemporaryDirectory() as tmp:
        path = str(Path(tmp) / "export.pcap")
        app.quick("DNS")
        with patch("sniffer.gui.filedialog.asksaveasfilename", return_value=path):
            app.save()
        assert len(list(read_pcap(path))) == 3
    with patch("sniffer.gui.messagebox.askyesno", return_value=False):
        app.load_file(ROOT / "samples/demo.pcap")
    assert not app.importing and len(app.packets) == 17
    app.quick("全部")
    app.table.selection_set("7")
    app.select()
    print("PASS: GUI import, HTTP filter, invalid filter preservation, packet details, TCP stream window, filtered export, replace cancellation", flush=True)
    if "--show" in sys.argv:
        root.mainloop()
    else:
        app.close()
        pump(root, lambda: not app.capture.running)
        root.destroy()


if __name__ == "__main__":
    main()
