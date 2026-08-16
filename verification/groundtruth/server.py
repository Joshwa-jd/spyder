"""Serves the ground-truth site on localhost.

Deterministic by construction: no timestamps, no randomness, no per-request
state. Two runs against this server differ only if the *client* is nondeterministic,
which is what makes it usable as a determinism harness.
"""
from __future__ import annotations

import contextlib
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .site import _SITEMAP, BARE_PATHS, GLOBAL_HEADERS, PAGES, REDIRECTS


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # BaseHTTP otherwise announces "BaseHTTP/x Python/y" on any response it
    # generates itself. That is a technology signal the site never declared, so
    # a fingerprint run that tripped one would be measuring the harness.
    server_version = ""
    sys_version = ""

    def log_message(self, *args: object) -> None:  # silence stderr spam
        pass

    def _drain(self) -> None:
        """Read and discard the request body.

        Mandatory on a keep-alive connection: whatever is left unread stays in
        the socket buffer and is parsed as the *next* request line. A probe
        POSTing ``q=marker`` made the following GET come back as
        ``501 Unsupported method ('q=markerGET')``, which silently turned every
        later measurement on that connection into garbage.
        """
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            while True:
                size_line = self.rfile.readline(65536).split(b";", 1)[0].strip()
                if not size_line:
                    break
                try:
                    size = int(size_line, 16)
                except ValueError:
                    break
                if size == 0:
                    self.rfile.readline(65536)  # trailing CRLF after last chunk
                    break
                self.rfile.read(size)
                self.rfile.readline(65536)  # CRLF after each chunk
            return
        length = self.headers.get("Content-Length")
        if length:
            try:
                self.rfile.read(int(length))
            except ValueError:
                pass

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        """Answer with the site's own error page rather than BaseHTTP's.

        Routed through :meth:`_send` so unsupported methods carry the site's
        headers and a correct Content-Length, keeping the connection usable.
        """
        self._drain()
        self._send(code, {"Content-Type": "text/html"}, b"<html><body>Error</body></html>")

    def _send(
        self, status: int, headers: dict[str, str], body: bytes, *, bare: bool = False
    ) -> None:
        """Write a response.

        ``bare`` suppresses :data:`GLOBAL_HEADERS`, so a page declared free of
        technology evidence really is free of it on the wire. Without this the
        site could not express Unknown and no false-positive rate would be
        measurable.
        """
        # send_response_only, NOT send_response: the latter appends BaseHTTP's
        # own "Server: BaseHTTP/x Python/y" and a "Date". The former would make
        # every bare page fingerprint as Python (defeating the point of
        # BARE_PATHS) and give pages like /fp/nginx two Server headers; the
        # latter is a clock value, which is exactly what a determinism harness
        # must not emit.
        self.send_response_only(status)
        merged = dict(headers) if bare else {**GLOBAL_HEADERS, **headers}
        for k, v in merged.items():
            # A folded Set-Cookie ("a=1; Path=/, b=2; Path=/") is two cookies on
            # the wire, which is the shape a client must cope with.
            if k.lower() == "set-cookie" and ", " in v:
                for cookie in v.split(", "):
                    self.send_header(k, cookie)
                continue
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        self._drain()
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        host = self.headers.get("Host", "127.0.0.1")

        if path in REDIRECTS:
            self._send(301, {"Location": REDIRECTS[path], "Content-Type": "text/html"}, b"")
            return
        if path == "/sitemap.xml":
            body = _SITEMAP.format(host=host).encode()
            self._send(200, {"Content-Type": "application/xml"}, body)
            return
        if path in PAGES:
            status, headers, text = PAGES[path]
            self._send(status, headers, text.encode(), bare=path in BARE_PATHS)
            return
        self._send(404, {"Content-Type": "text/html"}, b"<html><body>Not Found</body></html>")

    def do_POST(self) -> None:  # noqa: N802
        self._drain()
        self._send(200, {"Content-Type": "text/html"}, b"<html><body>ok</body></html>")

    def do_HEAD(self) -> None:  # noqa: N802
        """Headers only, so a probe that HEADs a URL sees the same technology
        signals a GET would give. Content-Length is the 0 bytes actually
        written rather than the GET body's length — self-consistency is what
        keeps the connection reusable."""
        self._drain()
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        status, headers, _ = PAGES.get(path, (404, {"Content-Type": "text/html"}, ""))
        self._send(status, headers, b"", bare=path in BARE_PATHS)


@contextlib.contextmanager
def ground_truth_server(port: int = 0) -> Iterator[str]:
    """Run the site for the duration of the block; yields its base URL."""
    srv = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    srv.daemon_threads = True
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    import sys

    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    with ground_truth_server(port) as base:
        print(f"ground-truth site on {base}  (Ctrl+C to stop)")
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            print("\nstopped")
