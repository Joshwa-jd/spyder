"""Score SPYDER's fingerprint engine against a known-answer site and peer tools.

Every page under ``/fp/`` has a hand-verified answer in
:data:`verification.groundtruth.site.TRUTH_FINGERPRINT`, including pages whose
answer is *nothing*. That makes precision measurable, not just recall: a decoy
page that discusses WordPress without running it will expose any engine that
substring-matches product names.

Reference tools are scored on the same pages against the same manifest, so the
numbers are absolute rather than "SPYDER vs WhatWeb". A reference tool that
fails to run is reported as a failure — never as a tool that found nothing.

Usage:  python -m verification.comparison.fingerprint_compare
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from spyder.analysis.fingerprint import fingerprint  # noqa: E402
from spyder.http.client import Transaction  # noqa: E402
from spyder.validation.fingerprint import validate_technologies  # noqa: E402
from verification.groundtruth.server import ground_truth_server  # noqa: E402
from verification.groundtruth.site import (  # noqa: E402
    TRUTH_CORROBORATED,
    TRUTH_FINGERPRINT,
    TRUTH_VERSIONS,
)

TIMEOUT = 120

#: Reference tools name technologies their own way; map their vocabulary onto
#: the manifest's so the comparison is about detection, not spelling.
_ALIASES = {
    "nginx": "Nginx",
    "apache": "Apache",
    "httpd": "Apache",
    "php": "PHP",
    "express": "Express",
    "expressjs": "Express",
    "asp.net": "ASP.NET",
    "aspnet": "ASP.NET",
    "microsoft-iis": "IIS",
    "iis": "IIS",
    "java": "Java",
    "jsp": "Java",
    "laravel": "Laravel",
    "cloudflare": "Cloudflare",
    "drupal": "Drupal",
    "wordpress": "WordPress",
    "react": "React",
    "reactjs": "React",
    "angular": "Angular",
    "angularjs": "Angular",
    "next.js": "Next.js",
    "nextjs": "Next.js",
    "jquery": "jQuery",
    "django": "Django",
}

#: Technology names in the manifest. A reference tool reporting something
#: outside this vocabulary (e.g. "HTTPServer", "Script", "Country") is reporting
#: a different kind of thing, not a false positive about *these* technologies.
_VOCAB = {t for techs in TRUTH_FINGERPRINT.values() for t in techs}


def _normalize(names: set[str]) -> set[str]:
    out = set()
    for raw in names:
        key = raw.strip().lower()
        mapped = _ALIASES.get(key)
        if mapped:
            out.add(mapped)
    return out


@dataclass
class Score:
    tool: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    unknown_correct: int = 0
    unknown_total: int = 0
    false_positives: list[str] = field(default_factory=list)
    false_negatives: list[str] = field(default_factory=list)

    @property
    def precision(self) -> float:
        return 100.0 * self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 100.0

    @property
    def recall(self) -> float:
        return 100.0 * self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 100.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def score_tool(tool: str, observed: dict[str, set[str]]) -> Score:
    """Compare per-path detections against the manifest."""
    s = Score(tool=tool)
    for path in sorted(TRUTH_FINGERPRINT):
        truth = TRUTH_FINGERPRINT[path]
        got = _normalize(observed.get(path, set()))
        # Only judge a tool on the vocabulary the manifest defines.
        got &= _VOCAB
        s.tp += len(got & truth)
        for extra in sorted(got - truth):
            s.fp += 1
            s.false_positives.append(f"{path}: {extra}")
        for missed in sorted(truth - got):
            s.fn += 1
            s.false_negatives.append(f"{path}: {missed}")
        if not truth:
            s.unknown_total += 1
            s.unknown_correct += not got
    return s


# --- SPYDER ------------------------------------------------------------------


def _fetch(base: str, path: str) -> Transaction:
    """Fetch one page with SPYDER's own transaction shape."""
    import httpx

    resp = httpx.get(base + path, timeout=10)
    return Transaction(
        id=path, method="GET", url=base + path, request_headers={}, request_body=None,
        status=resp.status_code, response_headers=dict(resp.headers),
        body=resp.text, final_url=str(resp.url),
    )


def run_spyder(base: str) -> tuple[dict[str, set[str]], dict[str, dict], dict[str, set[str]]]:
    """Returns (detections, versions, confirmed) per path."""
    detections: dict[str, set[str]] = {}
    versions: dict[str, dict] = {}
    confirmed: dict[str, set[str]] = {}
    for path in sorted(TRUTH_FINGERPRINT):
        fp = fingerprint(_fetch(base, path))
        detections[path] = {t.name for t in fp.entities}
        versions[path] = {t.name: t.version for t in fp.entities if t.version}
        confirmed[path] = {t.name for t in validate_technologies(fp.entities) if t.verified}
    return detections, versions, confirmed


# --- reference tools ---------------------------------------------------------


def _run(cmd: list[str]) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"{cmd[0]} exceeded {TIMEOUT}s — result would be misleading") from None
    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(f"{cmd[0]} exited {proc.returncode}: {proc.stderr[:300]}")
    return proc.stdout


def run_whatweb(base: str) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for path in sorted(TRUTH_FINGERPRINT):
        raw = _run(["whatweb", "--log-json=-", "--no-errors", "-a", "1", base + path])
        names: set[str] = set()
        for line in raw.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError:
                continue
            names |= set(doc.get("plugins", {}))
        out[path] = names
    return out


def run_httpx(base: str) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    targets = "\n".join(base + p for p in sorted(TRUTH_FINGERPRINT))
    proc = subprocess.run(
        ["httpx", "-silent", "-json", "-td", "-nc"],
        input=targets, capture_output=True, text=True, timeout=TIMEOUT,
    )
    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(f"httpx exited {proc.returncode}: {proc.stderr[:300]}")
    for line in proc.stdout.splitlines():
        try:
            doc = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = doc.get("url", "")
        path = url[len(base):] or "/"
        out[path] = set(doc.get("tech", []) or [])
    for p in TRUTH_FINGERPRINT:
        out.setdefault(p, set())
    return out


def main() -> int:
    failures: list[str] = []
    with ground_truth_server() as base:
        detections, versions, confirmed = run_spyder(base)
        scores = [score_tool("SPYDER", detections)]
        for name, fn in (("whatweb", run_whatweb), ("httpx", run_httpx)):
            if not shutil.which(name):
                print(f"[skip] {name} not installed")
                continue
            try:
                scores.append(score_tool(name, fn(base)))
            except (RuntimeError, subprocess.TimeoutExpired) as exc:
                # An unusable reference tool is a verification failure, not a
                # tool that legitimately detected nothing.
                failures.append(f"{name}: {exc}")
                print(f"[FAIL] {name}: {exc}")

    truth_claims = sum(len(v) for v in TRUTH_FINGERPRINT.values())
    unknown_pages = sum(1 for v in TRUTH_FINGERPRINT.values() if not v)
    print(f"\nGround truth: {len(TRUTH_FINGERPRINT)} pages, {truth_claims} technology claims, "
          f"{unknown_pages} pages that must yield Unknown\n")

    hdr = (f"{'tool':10} {'precision':>10} {'recall':>8} {'F1':>6} "
           f"{'TP':>4} {'FP':>4} {'FN':>4} {'unknown-correct':>16}")
    print(hdr)
    print("-" * len(hdr))
    for s in scores:
        print(f"{s.tool:10} {s.precision:9.1f}% {s.recall:7.1f}% {s.f1:5.1f} "
              f"{s.tp:>4} {s.fp:>4} {s.fn:>4} "
              f"{f'{s.unknown_correct}/{s.unknown_total}':>16}")

    for s in scores:
        if s.false_positives:
            print(f"\n{s.tool} FALSE POSITIVES ({len(s.false_positives)}):")
            for f in s.false_positives:
                print(f"    {f}")
        if s.false_negatives:
            print(f"\n{s.tool} FALSE NEGATIVES ({len(s.false_negatives)}):")
            for f in s.false_negatives:
                print(f"    {f}")

    print("\nVersion extraction (SPYDER):")
    v_ok = v_total = 0
    for path, expected in sorted(TRUTH_VERSIONS.items()):
        got = versions.get(path, {})
        for tech, want in sorted(expected.items()):
            v_total += 1
            have = got.get(tech)
            v_ok += have == want
            mark = "ok " if have == want else "MISS"
            print(f"  [{mark}] {path:18} {tech:12} expected {want!r} got {have!r}")
    print(f"  versions: {v_ok}/{v_total}")

    print("\nCONFIRMED promotion (only corroborated claims may be confirmed):")
    c_ok = True
    for path in sorted(TRUTH_FINGERPRINT):
        expected = TRUTH_CORROBORATED.get(path, set())
        got = confirmed.get(path, set())
        if got != expected:
            c_ok = False
            print(f"  [MISMATCH] {path:18} expected {sorted(expected)} got {sorted(got)}")
    if c_ok:
        print("  ok — every CONFIRMED technology is backed by >=2 independent sources")

    if failures:
        print(f"\nVERIFICATION FAILURE: {len(failures)} reference tool(s) unusable")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
