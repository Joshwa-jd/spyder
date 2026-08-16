"""The ground-truth server is measuring equipment; it needs its own calibration.

Every precision/recall number SPYDER publishes is read off this server. A fault
here does not fail loudly — it silently changes the answer the oracle gives, so
the oracle gets tested like any other component.
"""
from __future__ import annotations

import socket
from urllib.parse import urlparse

from verification.groundtruth.server import ground_truth_server


def _converse(base: str, *requests: bytes) -> bytes:
    """Send raw requests down one keep-alive connection; return everything read."""
    u = urlparse(base)
    s = socket.create_connection((u.hostname, u.port), timeout=5)
    try:
        s.sendall(b"".join(requests))
        s.settimeout(2)
        out = b""
        while True:
            try:
                chunk = s.recv(4096)
            except TimeoutError:
                break
            if not chunk:
                break
            out += chunk
        return out
    finally:
        s.close()


def _status_lines(raw: bytes) -> list[bytes]:
    # Responses are concatenated on a keep-alive connection, and a status line
    # can therefore be glued to the previous body — split on the marker itself.
    return [b"HTTP/1.1" + p.split(b"\r\n", 1)[0] for p in raw.split(b"HTTP/1.1")[1:]]


_GET = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"


def test_two_gets_on_one_connection_both_answered():
    with ground_truth_server() as base:
        raw = _converse(base, _GET, _GET)
    assert len(_status_lines(raw)) == 2


def test_post_body_is_drained_so_the_next_request_is_not_desynced():
    """Regression for R7-002.

    An undrained request body stays in the socket buffer and is parsed as the
    *next* request line, so the following GET returned
    ``501 Unsupported method ('q=markerGET')``. Any verification run that
    probed a body parameter then read a response was reading garbage.
    """
    body = b"q=marker"
    post = (
        b"POST / HTTP/1.1\r\nHost: x\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: %d\r\n\r\n%s" % (len(body), body)
    )
    with ground_truth_server() as base:
        raw = _converse(base, post, _GET)

    statuses = _status_lines(raw)
    assert len(statuses) == 2, f"expected 2 responses, got {statuses}"
    assert b"501" not in raw, f"connection desynced: {statuses}"
    assert statuses[1].startswith(b"HTTP/1.1 200"), statuses[1]


def test_unsupported_method_does_not_leak_the_python_server_banner():
    """A 501 from BaseHTTP advertises 'Server: BaseHTTP/x Python/y'.

    That is a technology signal the site never declared, so a fingerprint run
    that trips it would measure the harness rather than the site.
    """
    with ground_truth_server() as base:
        raw = _converse(base, b"TRACE / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert b"BaseHTTP" not in raw, "harness leaked its own server banner"


def test_chunked_body_is_drained():
    chunked = (
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"8\r\nq=marker\r\n0\r\n\r\n"
    )
    with ground_truth_server() as base:
        raw = _converse(base, chunked, _GET)
    assert b"501" not in raw, "chunked body desynced the connection"
    assert len(_status_lines(raw)) == 2
