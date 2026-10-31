"""HTTPS transport: the web UI, GET /challenge and POST /rpc.

TLS is here only because browsers require a secure context for WebCrypto and
Web Bluetooth. Security comes from the envelopes, which are checked by Rpc.
"""

import http.server
import logging
import ssl
import sys
from pathlib import Path

from . import protocol

log = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent / "static"
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/qrcode.js": ("qrcode.js", "text/javascript; charset=utf-8"),
}
CSP = "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'"


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive: fewer TLS handshakes
    server_version = "gpio-server"
    sys_version = ""
    timeout = 10

    def setup(self):
        # Handshake here, in the worker thread, so a slow client can't stall accept().
        self.request.settimeout(self.timeout)
        self.request.do_handshake()
        super().setup()

    def do_GET(self):
        if self.path == "/challenge":
            self._send(200, "application/octet-stream", self.server.rpc.challenges.issue())
        elif self.path in STATIC:
            filename, content_type = STATIC[self.path]
            self._send(200, content_type, (STATIC_DIR / filename).read_bytes())
        else:
            self._send(404, "text/plain", b"not found\n")

    def do_POST(self):
        if self.path != "/rpc":
            return self._send(404, "text/plain", b"not found\n")
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self._send(411, "text/plain", b"length required\n")
        if not 0 < length <= protocol.MAX_ENVELOPE:
            self.close_connection = True  # the body was not read
            return self._send(413, "text/plain", b"too large\n")
        reply = self.server.rpc.handle(self.rfile.read(length))
        if reply is None:
            self._send(403, "text/plain", b"denied\n")
        else:
            self._send(200, "application/octet-stream", reply)

    def _send(self, status: int, content_type: str, body: bytes):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", CSP)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        log.debug("%s %s", self.client_address[0], format % args)


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, rpc, cert_file: str, key_file: str):
        super().__init__(address, Handler)
        self.rpc = rpc
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        self.socket = context.wrap_socket(
            self.socket, server_side=True, do_handshake_on_connect=False
        )

    def handle_error(self, request, client_address):
        error = sys.exc_info()[1]
        if isinstance(error, (ssl.SSLError, ConnectionError, TimeoutError)):
            # Browsers abort the handshake until the self-signed certificate is accepted.
            log.debug("connection from %s failed: %s", client_address[0], error)
        else:
            log.exception("error handling request from %s", client_address[0])
