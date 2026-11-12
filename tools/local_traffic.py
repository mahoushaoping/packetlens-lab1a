"""仅向 127.0.0.1:8765 发送 HTTP，用于本机真实抓包验收。"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import urllib.request


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        data = b"PacketLens live loopback capture OK\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        pass


def generate():
    server = HTTPServer(("127.0.0.1", 8765), Handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        # 不继承系统代理，确保实验流量只经过 loopback。
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open("http://127.0.0.1:8765/lab1a", timeout=5) as reply:
            return reply.read().decode()
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == "__main__":
    print(generate(), end="")
