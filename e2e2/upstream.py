import http.server
import socket
import ssl
import struct
import threading


IP = "172.30.0.10"
RECORDS = {"protected.example.test.": IP, "ordinary.example.test.": IP}


def dns():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, 5353))
    while True:
        query, peer = sock.recvfrom(4096)
        pos, labels = 12, []
        while query[pos]:
            size = query[pos]
            pos += 1
            labels.append(query[pos:pos + size].decode())
            pos += size
        pos += 1
        question_end = pos + 4
        name = ".".join(labels) + "."
        answer = b""
        if name in RECORDS:
            answer = b"\xc0\x0c\x00\x01\x00\x01" + struct.pack("!IH", 30, 4) + socket.inet_aton(RECORDS[name])
        header = query[:2] + struct.pack("!HHHHH", 0x8180, 1, bool(answer), 0, 0)
        sock.sendto(header + query[12:question_end] + answer, peer)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"upstream-ok\n")

    do_HEAD = do_GET

    def log_message(self, *_):
        pass


threading.Thread(target=dns, daemon=True).start()
server = http.server.ThreadingHTTPServer((IP, 80), Handler)
tls = http.server.ThreadingHTTPServer((IP, 443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("/cert/cert.pem", "/cert/key.pem")
tls.socket = context.wrap_socket(tls.socket, server_side=True)
threading.Thread(target=server.serve_forever, daemon=True).start()
tls.serve_forever()
