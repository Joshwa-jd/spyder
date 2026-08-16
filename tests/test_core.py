"""Core unit tests for SPYDER."""
from __future__ import annotations

from spyder.analysis.diff import diff, normalize, similarity
from spyder.analysis.fingerprint import fingerprint
from spyder.core.models import Endpoint, Parameter, ParamLocation, Severity
from spyder.http.client import Transaction
from spyder.utils.scope import RateLimiter, ScopeGuard


def _txn(body: str = "", status: int = 200, headers: dict | None = None, ms: float = 10.0) -> Transaction:
    return Transaction(
        id="t", method="GET", url="http://x/", request_headers={}, request_body=None,
        status=status, response_headers=headers or {}, body=body, elapsed_ms=ms,
    )


def test_scope_denies_out_of_scope():
    g = ScopeGuard(["example.com"])
    assert g.in_scope("http://example.com/a")
    assert g.in_scope("http://api.example.com/a")  # subdomain
    assert not g.in_scope("http://evil.com/a")


def test_scope_no_subdomains():
    g = ScopeGuard(["example.com"], include_subdomains=False)
    assert not g.in_scope("http://api.example.com/")


def test_similarity_identical_and_different():
    assert similarity("<p>hello world</p>", "<p>hello world</p>") == 1.0
    assert similarity("hello world foo bar", "completely other text here") < 0.6


def test_normalize_strips_tags():
    assert normalize("<div>  a   b </div>") == "a b"


def test_diff_flags_status_and_length():
    base = _txn("hello", 200, ms=10)
    other = _txn("hello" + "x" * 500, 500, ms=10)
    d = diff(base, other)
    assert d.status_changed
    assert d.length_delta == 500
    assert any("status" in n for n in d.notable)


def test_fingerprint_detects_server_and_dbms():
    txn = _txn("...You have an error in your SQL syntax; MySQL server...",
               headers={"Server": "nginx/1.24.0"})
    fp = fingerprint(txn)
    assert "mysql" in fp.dbms_hints
    # The engine reports the technology, not the header role that carried it.
    assert fp.technologies == {"Nginx": "1.24.0"}
    (nginx,) = fp.entities
    assert nginx.name == "Nginx"
    assert nginx.version == "1.24.0"
    assert nginx.evidence[0].detail == "Server: nginx/1.24.0"


def test_endpoint_fingerprint_stable():
    e1 = Endpoint(url="http://x/a", params=[Parameter(name="id", location=ParamLocation.QUERY)])
    e2 = Endpoint(url="http://x/a#frag", params=[Parameter(name="id", location=ParamLocation.QUERY)])
    assert e1.fingerprint() == e2.fingerprint()  # fragment stripped


def test_severity_rank_ordering():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.INFO.rank


async def test_rate_limiter_allows_burst():
    rl = RateLimiter(rate_per_sec=100, burst=5)
    for _ in range(5):
        await rl.acquire()  # should not raise or hang
