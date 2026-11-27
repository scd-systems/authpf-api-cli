#!/usr/bin/env python3
"""Mock of an authpf-api server for tests/e2e.sh.

The answers are as hostile as the vuln-0003 report was: escape sequences in an anchor name
and in an error body, an anchor entry that is null, an oversized response that is never
finished under any path beginning with /huge, and an answer that is late under /slow.
Nothing else, so the server needs no scenario switching: the test picks its branch by the
command and the config it uses.

Usage: mock_server.py PORT   (prints the listening port, 0 picks a free one)
"""
import json
import os
import ssl
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

OK_INFO = {"api_version": "1.2", "server_version": "1.0"}

# A raw 0x1b is refused inside a JSON string, so the escape sequences travel as \u001b and
# the client's JSON decoder is the one that hands them back as real escape characters.
ANCHORS = (r'{"anchors":{"anchor\u001b]0;PWNED-TITLE\u0007":null,'
           r'"bob":{"username":"bob","user_ip":"10.0.0.7","user_id":2,"timeout":"8h"},'
           # U+009B is the CSI introducer on its own and arrives as two UTF-8 bytes, so a
           # filter that only knows the ASCII control range would let it through.
           r'"carol":{"username":"carol\u009b[2J","user_ip":"10.0.0.8","user_id":3,"timeout":"8h"}}}')

# A plain text error body, echoed verbatim by the client: OSC title change, CSI erase and a
# carriage return that tries to pass off the next text as output of the tool itself.
DENIED = b"denied\x1b]0;root@core-gw\x07Access denied\r  Username: root"

# One megabyte past the 8 MB the client is allowed to buffer.
HUGE_BYTES = 9 << 20

# Long enough that a client which ignores its own timeout is still waiting when the test
# looks, short enough that a broken client cannot hold the suite for a minute.
SLOW_SECONDS = 20


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _split(self):
        # A test picks the flavour of this server with a path prefix, so one server can be
        # hostile (default), endless (/huge) or obliging (/allow) at the same time.
        for prefix in ("/huge", "/allow", "/slow"):
            if self.path.startswith(prefix):
                return prefix, self.path[len(prefix):] or "/"
        return "", self.path

    def _send(self, status, body):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _huge(self):
        chunk = b"a" * (64 << 10)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        try:
            for _ in range(HUGE_BYTES // len(chunk) + 1):
                self.wfile.write(chunk)
                self.wfile.flush()
        except Exception:
            return  # the client hung up, which is exactly what the test wants to see
        time.sleep(30)  # the body never ends: a client that waits for one waits here

    def do_GET(self):
        flavour, route = self._split()
        if flavour == "/huge":
            return self._huge()
        if route == "/info":
            if flavour == "/slow":
                time.sleep(SLOW_SECONDS)
                try:
                    self._send(200, json.dumps(OK_INFO))
                except Exception:
                    pass  # the client hung up, which is the point of this endpoint
                return
            return self._send(200, json.dumps(OK_INFO))
        if route == "/login":
            return self._send(200, '{"ok": true}')
        if route.startswith("/api/v1/authpf"):
            return self._send(200, ANCHORS)
        self._send(404, '{"error": "not found"}')

    def do_POST(self):
        flavour, route = self._split()
        if flavour == "/huge":
            return self._huge()
        if route.startswith("/api/v1/authpf"):
            if flavour == "/allow":
                # Only with a bearer token, so the flow proves that what auth login saved
                # is what authpf activate then sends.
                if not self.headers.get("Authorization", "").startswith("Bearer "):
                    return self._send(401, '{"error": "unauthorized"}')
                return self._send(200, '{"message": "anchor activated"}')
            return self._send(403, DENIED)
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if b"definitely-not-this-password" in body:
            # The password tests/e2e_remote.sh sends on purpose, answered like a real server
            # would, so the case is checkable without a live host.
            return self._send(401, '{"error": "invalid credentials"}')
        if flavour == "/allow":
            # Not a JWT: a token the client reads no expiry from counts as valid, which is
            # what the server itself claimed about a token it just issued.
            return self._send(200, '{"token": "issuedbytheserver0123456789"}')
        self._send(200, '{"ok": true}')

    def do_DELETE(self):
        flavour, route = self._split()
        if route.startswith("/api/v1/authpf"):
            if flavour == "/allow":
                if not self.headers.get("Authorization", "").startswith("Bearer "):
                    return self._send(401, '{"error": "unauthorized"}')
                return self._send(200, '{"message": "anchor deactivated"}')
            return self._send(403, DENIED)
        self._send(404, '{"error": "not found"}')


def main():
    server = ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler)
    server.daemon_threads = True
    # MOCK_TLS names a pem holding certificate and key. Judging a server certificate needs
    # a server speaking TLS with a self signed certificate.
    pem = os.environ.get("MOCK_TLS", "")
    if pem:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(pem)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print(server.server_address[1], flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
