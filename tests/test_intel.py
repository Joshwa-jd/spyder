"""Tests for recon intelligence: classification, scoring, analytics, surface."""
from __future__ import annotations

from spyder.analysis.intel import (
    EndpointClass,
    analyze_parameters,
    attack_surface,
    classify_all,
    classify_endpoint,
    high_interest,
    summarize_technologies,
)
from spyder.core.models import (
    Endpoint,
    Finding,
    HTTPMethod,
    Parameter,
    ParamLocation,
    Severity,
)


def _ep(url, method=HTTPMethod.GET, params=None):
    return Endpoint(url=url, method=method, params=params or [])


def test_classify_admin_and_auth():
    intel = classify_endpoint(_ep("http://x/admin/login"))
    assert EndpointClass.ADMIN in intel.classes
    assert EndpointClass.AUTH in intel.classes
    assert intel.high_interest


def test_classify_graphql_and_api():
    intel = classify_endpoint(_ep("http://x/api/graphql"))
    assert EndpointClass.GRAPHQL in intel.classes
    assert EndpointClass.API in intel.classes


def test_classify_upload():
    intel = classify_endpoint(_ep("http://x/upload", method=HTTPMethod.POST))
    assert EndpointClass.UPLOAD in intel.classes
    assert "method:POST" in intel.tags


def test_static_assets_score_low():
    intel = classify_endpoint(_ep("http://x/assets/app.css"))
    assert intel.classes == [EndpointClass.STATIC]
    assert intel.score == 0  # clamped from negative


def test_interesting_params_and_reflection_raise_score():
    plain = classify_endpoint(_ep("http://x/page"))
    rich = classify_endpoint(
        _ep("http://x/page", params=[
            Parameter(name="redirect", location=ParamLocation.QUERY, reflected=True),
            Parameter(name="id", location=ParamLocation.QUERY),
        ])
    )
    assert rich.score > plain.score
    assert "reflected" in rich.tags
    assert "param:redirect" in rich.tags


def test_classify_all_sorted_descending():
    eps = [_ep("http://x/style.css"), _ep("http://x/admin"), _ep("http://x/about")]
    intels = classify_all(eps)
    scores = [i.score for i in intels]
    assert scores == sorted(scores, reverse=True)


def test_high_interest_filter():
    eps = [_ep("http://x/admin/login"), _ep("http://x/favicon.ico")]
    intels = classify_all(eps)
    hi = high_interest(intels)
    assert all(i.score >= 40 for i in hi)
    assert len(hi) == 1


def test_parameter_analytics():
    eps = [
        _ep("http://x/a", params=[
            Parameter(name="id", location=ParamLocation.QUERY, reflected=True),
            Parameter(name="q", location=ParamLocation.QUERY),
        ]),
        _ep("http://x/b", params=[Parameter(name="id", location=ParamLocation.BODY)]),
    ]
    pa = analyze_parameters(eps)
    assert pa.total == 3
    assert pa.unique_names == 2  # id, q
    assert pa.reflected == 1
    assert pa.by_location["query"] == 2
    assert ("id", 2) in pa.interesting


def test_attack_surface_metrics():
    eps = [
        _ep("http://x/admin", method=HTTPMethod.POST,
            params=[Parameter(name="id", location=ParamLocation.QUERY)]),
        _ep("http://x/style.css"),
    ]
    surf = attack_surface(eps)
    assert surf.total_endpoints == 2
    assert surf.with_params == 1
    assert surf.write_endpoints == 1
    assert surf.by_method["POST"] == 1
    assert surf.high_interest >= 1


def test_summarize_technologies():
    findings = [
        Finding(
            title="Passive fingerprint",
            severity=Severity.INFO,
            evidence={
                "technologies": {"server": "nginx", "framework": "express"},
                "waf_hints": ["cloudflare"],
                "dbms_hints": ["mysql"],
            },
        ),
    ]
    tech = summarize_technologies(findings)
    assert tech.technologies["server"] == "nginx"
    assert "cloudflare" in tech.waf
    assert "mysql" in tech.dbms
    assert not tech.empty
