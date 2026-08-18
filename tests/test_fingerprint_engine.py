"""Regression tests for the evidence-driven fingerprint engine (Round 5).

Each test here pins a defect that was reproduced before it was fixed:

  FP-1  every detection was automatically CONFIRMED, because the authoritative
        label set covered every label the engine could emit
  FP-2  spoofed passive headers reached CONFIRMED, so an attacker chose the
        scanner's confidence
  FP-3  header *roles* were reported ("server -> nginx/1.24.0") instead of
        technology entities ("Nginx 1.24.0, evidenced by the Server header")
  FP-4  cookies, meta generators, framework markup, and asset paths were not
        read at all
  FP-5  the ground-truth server applied identifying headers to every response,
        so Unknown — and therefore any false-positive rate — was unmeasurable

Precision is asserted as strictly as recall: pages that merely *discuss* a
technology must fingerprint as Unknown.
"""
from __future__ import annotations

import hashlib
import json
import urllib.request

import pytest

from spyder.analysis.fingerprint import EvidenceSource, Technology, fingerprint
from spyder.http.client import Transaction
from spyder.validation.confidence import ConfidenceLevel
from spyder.validation.fingerprint import validate_technologies
from verification.groundtruth.server import ground_truth_server
from verification.groundtruth.site import (
    BARE_PATHS,
    GLOBAL_HEADERS,
    TRUTH_CORROBORATED,
    TRUTH_FINGERPRINT,
    TRUTH_NO_TECH,
    TRUTH_VERSIONS,
)

_HTML = {"Content-Type": "text/html; charset=utf-8"}


def _txn(headers: dict[str, str] | None = None, body: str = "") -> Transaction:
    return Transaction(
        id="t", method="GET", url="http://x/", request_headers={}, request_body=None,
        status=200, response_headers=headers or {}, body=body, final_url="http://x/",
    )


def _names(fp) -> set[str]:
    return {t.name for t in fp.entities}


# ---------------------------------------------------------------------------
# FP-1 / FP-2 — confidence must not be a rubber stamp
# ---------------------------------------------------------------------------


def test_single_passive_header_is_never_confirmed():
    """FP-1: a lone header is strong evidence, but nothing has verified it."""
    fp = fingerprint(_txn({"Server": "nginx/1.24.0"}))
    (tech,) = validate_technologies(fp.entities)
    assert tech.name == "Nginx"
    assert tech.level is ConfidenceLevel.HIGH
    assert not tech.verified


def test_spoofed_headers_do_not_reach_confirmed():
    """FP-2: an attacker who picks the headers must not pick our confidence."""
    spoofed = {
        "Server": "nginx/1.24.0",
        "X-Powered-By": "PHP/8.2.15",
        "X-AspNet-Version": "4.0.30319",
        "X-Generator": "Drupal 10",
    }
    scored = validate_technologies(fingerprint(_txn(spoofed)).entities)
    assert scored, "expected detections from these headers"
    assert not any(t.verified for t in scored)
    assert all(t.level is not ConfidenceLevel.CONFIRMED for t in scored)
    # All evidence came from one source kind, so nothing corroborates anything.
    assert all(t.sources == (EvidenceSource.HEADER,) for t in scored)


def test_confirmation_requires_two_independent_sources():
    """A header plus a cookie are two things that would have to be wrong."""
    fp = fingerprint(_txn({
        "X-Powered-By": "PHP/8.2.15",
        "Set-Cookie": "PHPSESSID=abc123; Path=/",
    }))
    (php,) = validate_technologies(fp.entities)
    assert php.name == "PHP"
    assert set(php.sources) == {EvidenceSource.HEADER, EvidenceSource.COOKIE}
    assert php.verified
    assert php.score > 80


def test_weak_sources_agreeing_do_not_reach_confirmed():
    """Two weak signals agree — enough to raise the score, not to confirm."""
    fp = fingerprint(_txn(
        {**_HTML, "Set-Cookie": "csrftoken=t; Path=/"},
        '<form><input type="hidden" name="csrfmiddlewaretoken" value="x"></form>',
    ))
    (django,) = validate_technologies(fp.entities)
    assert django.name == "Django"
    assert len(django.sources) == 2
    assert not django.verified
    assert django.level is ConfidenceLevel.MEDIUM


def test_no_authoritative_label_shortcut_exists():
    """FP-1 root cause: promotion must depend on evidence, not on a name list.

    The old engine promoted anything whose label appeared in a hardcoded set
    that happened to contain every label it could emit. Confirmation is now a
    function of how many independent sources agree.
    """
    import spyder.validation.fingerprint as vf

    assert not hasattr(vf, "_AUTHORITATIVE_LABELS")
    assert vf._CONFIRM_MIN_SOURCES >= 2


# ---------------------------------------------------------------------------
# FP-3 — technology entities, not header roles
# ---------------------------------------------------------------------------


def test_reports_technology_entities_not_header_roles():
    fp = fingerprint(_txn({"Server": "nginx/1.24.0", "X-Powered-By": "Express"}))
    assert _names(fp) == {"Nginx", "Express"}
    assert not {"server", "framework"} & _names(fp)
    nginx = next(t for t in fp.entities if t.name == "Nginx")
    assert nginx.version == "1.24.0"
    assert nginx.category == "web server"
    (ev,) = nginx.evidence
    assert ev.source is EvidenceSource.HEADER
    assert ev.detail == "Server: nginx/1.24.0"


def test_every_entity_carries_name_evidence_source_and_confidence():
    """The design contract: no claim without attributable evidence."""
    fp = fingerprint(_txn(
        {**_HTML, "Server": "nginx/1.24.0", "Set-Cookie": "PHPSESSID=a; Path=/"},
        '<meta name="generator" content="WordPress 6.5.2">'
        '<link href="/wp-content/themes/x/style.css">',
    ))
    for tech in validate_technologies(fp.entities):
        assert tech.name
        assert tech.category
        assert tech.evidence, f"{tech.name} claimed with no evidence"
        assert 0 <= tech.score <= 100
        for ev in tech.evidence:
            assert ev.detail and ev.kind
            assert isinstance(ev.source, EvidenceSource)


def test_entity_with_no_evidence_is_suppressed_not_reported():
    (tech,) = validate_technologies([Technology(name="Ghost", category="cms")])
    assert tech.level is ConfidenceLevel.NOISE
    assert tech.score == 0


# ---------------------------------------------------------------------------
# FP-4 — the evidence sources that were previously absent
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("headers", "body", "expected"), [
    # cookies
    ({"Set-Cookie": "PHPSESSID=abc; Path=/"}, "", "PHP"),
    ({"Set-Cookie": "connect.sid=s%3Aabc; Path=/"}, "", "Express"),
    ({"Set-Cookie": "JSESSIONID=0A1B; Path=/"}, "", "Java"),
    ({"Set-Cookie": "laravel_session=eyJ; Path=/"}, "", "Laravel"),
    ({"Set-Cookie": "__cf_bm=xyz; Path=/"}, "", "Cloudflare"),
    # meta generator
    ({}, '<meta name="generator" content="Drupal 10">', "Drupal"),
    ({}, '<meta name="generator" content="WordPress 6.5.2">', "WordPress"),
    ({}, '<meta content="Hugo 0.120.0" name="generator">', "Hugo"),
    # framework markup / JS globals
    ({}, '<app-root ng-version="17.1.0"></app-root>', "Angular"),
    ({}, '<div id="root" data-reactroot=""></div>', "React"),
    ({}, '<script id="__NEXT_DATA__" type="application/json">{}</script>', "Next.js"),
    ({}, "<script>window.__NUXT__={};</script>", "Nuxt.js"),
    # body / asset signatures
    ({}, '<input type="hidden" name="csrfmiddlewaretoken" value="x">', "Django"),
    ({}, '<link href="/wp-content/themes/x/style.css">', "WordPress"),
    ({}, '<script src="/js/jquery-3.7.1.min.js"></script>', "jQuery"),
    ({}, '<script src="/_next/static/chunks/main.js"></script>', "Next.js"),
])
def test_evidence_source_is_read(headers, body, expected):
    fp = fingerprint(_txn({**_HTML, **headers}, body))
    assert expected in _names(fp)


def test_folded_set_cookie_yields_every_cookie():
    """httpx folds repeated Set-Cookie headers into one comma-joined value."""
    fp = fingerprint(_txn({"Set-Cookie": "__cf_bm=xyz; Path=/, PHPSESSID=abc; Path=/"}))
    assert _names(fp) == {"Cloudflare", "PHP"}


def test_cookie_expiry_comma_is_not_mistaken_for_a_cookie():
    fp = fingerprint(_txn(
        {"Set-Cookie": "PHPSESSID=abc; Expires=Wed, 21 Oct 2025 07:28:00 GMT; Path=/"}
    ))
    assert _names(fp) == {"PHP"}


def test_versions_are_extracted():
    cases = [
        ({"Server": "nginx/1.24.0"}, "", "Nginx", "1.24.0"),
        ({"Server": "Apache/2.4.58 (Ubuntu)"}, "", "Apache", "2.4.58"),
        ({"X-Powered-By": "PHP/8.2.15"}, "", "PHP", "8.2.15"),
        ({}, '<meta name="generator" content="WordPress 6.5.2">', "WordPress", "6.5.2"),
        ({}, '<app-root ng-version="17.1.0"></app-root>', "Angular", "17.1.0"),
        ({}, '<script src="/js/jquery-3.7.1.min.js"></script>', "jQuery", "3.7.1"),
    ]
    for headers, body, name, version in cases:
        fp = fingerprint(_txn({**_HTML, **headers}, body))
        tech = next(t for t in fp.entities if t.name == name)
        assert tech.version == version, f"{name}: expected {version}, got {tech.version}"


# ---------------------------------------------------------------------------
# Precision — Unknown is a real answer
# ---------------------------------------------------------------------------


def test_empty_response_is_unknown():
    fp = fingerprint(_txn({**_HTML}, "<html><body>nothing here</body></html>"))
    assert fp.unknown
    assert fp.technologies == {}


def test_prose_naming_technologies_is_not_a_detection():
    """The core precision rule: discussing a technology is not running it."""
    fp = fingerprint(_txn(
        _HTML,
        "<html><body><p>We migrated from WordPress to Drupal, and we run nginx "
        "with an Express middleware and a jQuery plugin.</p></body></html>",
    ))
    assert fp.unknown, f"guessed {_names(fp)} from prose"


def test_technology_names_inside_unrelated_paths_are_not_detections():
    fp = fingerprint(_txn(
        _HTML,
        '<a href="/articles/wordpress-vs-drupal-2026">x</a>'
        '<img src="/img/react-conference-banner.png">'
        '<script src="/js/not-jquery-really.js"></script>',
    ))
    assert fp.unknown, f"guessed {_names(fp)} from unrelated path names"


def test_non_html_bodies_are_not_scanned_for_markup():
    """A JSON document mentioning products must not fingerprint as them."""
    fp = fingerprint(_txn(
        {"Content-Type": "application/json"},
        '{"topic":"nginx tuning","tags":["php","express","laravel"]}',
    ))
    assert fp.unknown


def test_server_header_must_match_structurally():
    """'my-nginx-notes' is not nginx."""
    fp = fingerprint(_txn({"Server": "acme-proxy (nginx-compatible)"}))
    assert fp.unknown


# ---------------------------------------------------------------------------
# FP-5 — the verification environment can express Unknown
# ---------------------------------------------------------------------------


def test_ground_truth_serves_pages_with_no_identifying_headers():
    identifying = ("server", "x-powered-by", "set-cookie")
    with ground_truth_server() as base:
        for path in sorted(TRUTH_NO_TECH):
            with urllib.request.urlopen(base + path) as resp:
                headers = {k.lower() for k, _ in resp.getheaders()}
            leaked = headers & set(identifying)
            assert not leaked, f"{path} leaked {leaked}; Unknown is unmeasurable"


def test_ground_truth_no_tech_pages_are_declared_bare():
    assert TRUTH_NO_TECH <= BARE_PATHS


def test_ground_truth_normal_pages_still_carry_the_stack():
    """The repair must not have stripped evidence from the rest of the site."""
    with ground_truth_server() as base:
        with urllib.request.urlopen(base + "/about") as resp:
            assert resp.getheader("Server") == GLOBAL_HEADERS["Server"]
            assert resp.getheader("X-Powered-By") == GLOBAL_HEADERS["X-Powered-By"]


def test_ground_truth_emits_no_clock_derived_headers():
    """A Date header would make the determinism harness lie."""
    with ground_truth_server() as base:
        with urllib.request.urlopen(base + "/fp/bare") as resp:
            assert resp.getheader("Date") is None


# ---------------------------------------------------------------------------
# End-to-end accuracy against the manifest
# ---------------------------------------------------------------------------


def _fetch(base: str, path: str) -> Transaction:
    with urllib.request.urlopen(base + path) as resp:
        body = resp.read().decode()
        headers: dict[str, str] = {}
        for k, v in resp.getheaders():
            key = k.lower()
            # Mirror httpx's folding of repeated headers.
            headers[key] = f"{headers[key]}, {v}" if key in headers else v
    return Transaction(
        id=path, method="GET", url=base + path, request_headers={}, request_body=None,
        status=200, response_headers=headers, body=body, final_url=base + path,
    )


def test_perfect_precision_and_recall_against_ground_truth():
    with ground_truth_server() as base:
        observed = {p: _names(fingerprint(_fetch(base, p))) for p in TRUTH_FINGERPRINT}

    false_positives: list[str] = []
    false_negatives: list[str] = []
    for path, truth in TRUTH_FINGERPRINT.items():
        got = observed[path]
        false_positives += [f"{path}: {t}" for t in sorted(got - truth)]
        false_negatives += [f"{path}: {t}" for t in sorted(truth - got)]
    assert not false_positives, f"false positives: {false_positives}"
    assert not false_negatives, f"false negatives: {false_negatives}"


def test_only_corroborated_technologies_are_confirmed_end_to_end():
    with ground_truth_server() as base:
        for path in sorted(TRUTH_FINGERPRINT):
            scored = validate_technologies(fingerprint(_fetch(base, path)).entities)
            confirmed = {t.name for t in scored if t.verified}
            assert confirmed == TRUTH_CORROBORATED.get(path, set()), (
                f"{path}: confirmed {sorted(confirmed)}"
            )
            for tech in scored:
                if tech.verified:
                    assert len(tech.sources) >= 2


def test_versions_match_ground_truth_end_to_end():
    with ground_truth_server() as base:
        for path, expected in TRUTH_VERSIONS.items():
            fp = fingerprint(_fetch(base, path))
            got = {t.name: t.version for t in fp.entities if t.version}
            for name, version in expected.items():
                assert got.get(name) == version, f"{path} {name}: got {got.get(name)}"


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def _digest(fp) -> str:
    payload = [t.to_dict() for t in fp.entities]
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def test_fingerprint_is_deterministic_over_100_runs():
    """Same bytes in, byte-identical assessment out — 100 times."""
    txn = _txn(
        {**_HTML, "Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.2.15",
         "Set-Cookie": "PHPSESSID=abc; Path=/, __cf_bm=z; Path=/", "cf-ray": "abc-LHR"},
        '<meta name="generator" content="WordPress 6.5.2">'
        '<link href="/wp-content/themes/x/style.css">'
        '<script src="/js/jquery-3.7.1.min.js"></script>',
    )
    digests = {_digest(fingerprint(txn)) for _ in range(100)}
    assert len(digests) == 1, f"{len(digests)} distinct results across 100 runs"

    scores = {
        tuple((t.name, t.score, t.level.value) for t in validate_technologies(
            fingerprint(txn).entities))
        for _ in range(100)
    }
    assert len(scores) == 1


def test_entity_order_is_stable_and_evidence_led():
    fp = fingerprint(_txn(
        {**_HTML, "Server": "nginx/1.24.0", "Set-Cookie": "JSESSIONID=a; Path=/"},
        '<script src="/js/jquery-3.7.1.min.js"></script>',
    ))
    assert [t.name for t in fp.entities] == ["Nginx", "jQuery", "Java"]


def test_technology_round_trips_through_serialization():
    """Entities are persisted to the workspace and rescored later."""
    fp = fingerprint(_txn(
        {**_HTML, "X-Powered-By": "PHP/8.2.15", "Set-Cookie": "PHPSESSID=a; Path=/"}
    ))
    restored = [Technology.from_dict(json.loads(json.dumps(t.to_dict()))) for t in fp.entities]
    assert [t.to_dict() for t in restored] == [t.to_dict() for t in fp.entities]
    assert validate_technologies(restored)[0].verified
