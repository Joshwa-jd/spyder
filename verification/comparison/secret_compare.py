"""Score SPYDER's secret detectors against a known-answer corpus and TruffleHog.

The corpus in :mod:`verification.groundtruth.secrets` pairs live-looking (but
non-functional) credentials with decoys whose correct answer is *nothing*, so
this measures precision and recall together. A scanner that flags every
high-entropy string scores perfect recall and is still useless.

TruffleHog is scored on the same corpus. The installed build is the v2 Python
tool, which only reads git history, so the corpus is materialised into a
throwaway repository first. A reference tool that cannot run is reported as a
failure — never as a tool that legitimately found nothing.

Usage:  python -m verification.comparison.secret_compare
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from spyder.analysis.jsintel import extract_secrets  # noqa: E402
from verification.groundtruth.secrets import (  # noqa: E402
    CORPUS,
    DECOY,
    REQUIRED_KINDS,
    TRUTH,
)

TIMEOUT = 180

#: TruffleHog v2 names its rules its own way; map them onto the manifest's
#: vocabulary so the comparison is about detection, not spelling.
_ALIASES = {
    "aws api key": "aws_access_key_id",
    "amazon aws access key id": "aws_access_key_id",
    "aws access key id": "aws_access_key_id",
    "aws secret key": "aws_secret_access_key",
    "amazon aws secret access key": "aws_secret_access_key",
    "slack token": "slack_token",
    "slack webhook": "slack_webhook",
    "github": "github_token",
    "github token": "github_token",
    "stripe api key": "stripe_key",
    "stripe restricted api key": "stripe_key",
    "twilio api key": "twilio_api_key",
    "json web token": "jwt",
    "generic secret": "generic_secret",
    "password in url": "generic_secret",
    "rsa private key": "private_key",
    "ssh (dsa) private key": "private_key",
    "ssh (ec) private key": "private_key",
    "ssh (openssh) private key": "private_key",
    "pgp private key block": "private_key",
    "google api key": "google_api_key",
    "google (gcp) service-account": "google_api_key",
}

#: Kinds the manifest actually talks about. A tool reporting something outside
#: this vocabulary is reporting a different kind of thing, not a false positive
#: about *these* credentials.
_VOCAB = {k for kinds in TRUTH.values() for k in kinds}


def _normalize(names: set[str]) -> set[str]:
    out = set()
    for raw in names:
        mapped = _ALIASES.get(raw.strip().lower())
        if mapped:
            out.add(mapped)
    return out


@dataclass
class Score:
    tool: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    decoys_silent: int = 0
    decoys_total: int = 0
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


def score_tool(tool: str, observed: dict[str, set[str]], *, normalize: bool = False) -> Score:
    s = Score(tool=tool)
    for name in sorted(TRUTH):
        truth = TRUTH[name]
        got = _normalize(observed.get(name, set())) if normalize else observed.get(name, set())
        got &= _VOCAB
        s.tp += len(got & truth)
        for extra in sorted(got - truth):
            s.fp += 1
            s.false_positives.append(f"{name}: {extra}")
        for missed in sorted(truth - got):
            s.fn += 1
            s.false_negatives.append(f"{name}: {missed}")
        if name in DECOY:
            s.decoys_total += 1
            s.decoys_silent += not got
    return s


# --- SPYDER ------------------------------------------------------------------


def run_spyder() -> dict[str, set[str]]:
    return {
        name: {s.kind for s in extract_secrets(body, source=name)}
        for name, body in CORPUS.items()
    }


# --- TruffleHog --------------------------------------------------------------


def _materialise(root: Path) -> None:
    """Write the corpus into a throwaway git repo (TruffleHog v2 reads history)."""
    for name, body in CORPUS.items():
        (root / name).write_text(body)
    env = {"GIT_AUTHOR_NAME": "gt", "GIT_AUTHOR_EMAIL": "gt@example.invalid",
           "GIT_COMMITTER_NAME": "gt", "GIT_COMMITTER_EMAIL": "gt@example.invalid"}
    for cmd in (["git", "init", "-q", "-b", "main"], ["git", "add", "-A"],
                ["git", "commit", "-q", "-m", "corpus"]):
        subprocess.run(cmd, cwd=root, check=True, capture_output=True, env={"PATH": "/usr/bin:/bin", **env})


def run_trufflehog() -> dict[str, set[str]]:
    out: dict[str, set[str]] = {name: set() for name in CORPUS}
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _materialise(root)
        proc = subprocess.run(
            ["trufflehog", "--json", "--regex", "--entropy=False", f"file://{root}"],
            capture_output=True, text=True, timeout=TIMEOUT,
        )
        if proc.returncode != 0 and not proc.stdout.strip():
            raise RuntimeError(f"trufflehog exited {proc.returncode}: {proc.stderr[:300]}")
        for line in proc.stdout.splitlines():
            try:
                doc = json.loads(line)
            except json.JSONDecodeError:
                continue
            path = doc.get("path", "")
            reason = doc.get("reason", "")
            if path in out and reason:
                out[path].add(reason)
    return out


def main() -> int:
    failures: list[str] = []
    detections = run_spyder()
    scores = [score_tool("SPYDER", detections)]

    if shutil.which("trufflehog"):
        try:
            scores.append(score_tool("trufflehog", run_trufflehog(), normalize=True))
        except (RuntimeError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:
            failures.append(f"trufflehog: {exc}")
            print(f"[FAIL] trufflehog: {exc}")
    else:
        print("[skip] trufflehog not installed")
    if not shutil.which("gitleaks"):
        print("[skip] gitleaks not installed")

    claims = sum(len(v) for v in TRUTH.values())
    print(f"\nCorpus: {len(CORPUS)} documents, {claims} credential claims, "
          f"{len(DECOY)} decoys that must yield nothing\n")

    hdr = (f"{'tool':12} {'precision':>10} {'recall':>8} {'F1':>6} "
           f"{'TP':>4} {'FP':>4} {'FN':>4} {'decoys-silent':>14}")
    print(hdr)
    print("-" * len(hdr))
    for s in scores:
        print(f"{s.tool:12} {s.precision:9.1f}% {s.recall:7.1f}% {s.f1:5.1f} "
              f"{s.tp:>4} {s.fp:>4} {s.fn:>4} "
              f"{f'{s.decoys_silent}/{s.decoys_total}':>14}")

    for s in scores:
        if s.false_positives:
            print(f"\n{s.tool} FALSE POSITIVES ({len(s.false_positives)}):")
            for f in s.false_positives:
                print(f"    {f}")
        if s.false_negatives:
            print(f"\n{s.tool} FALSE NEGATIVES ({len(s.false_negatives)}):")
            for f in s.false_negatives:
                print(f"    {f}")

    print("\nRequired detector coverage (Round 6):")
    detected_kinds = {k for kinds in detections.values() for k in kinds}
    missing = sorted(REQUIRED_KINDS - detected_kinds)
    for kind in sorted(REQUIRED_KINDS):
        print(f"  [{'ok ' if kind in detected_kinds else 'MISS'}] {kind}")
    if missing:
        print(f"  MISSING: {', '.join(missing)}")

    if failures:
        print(f"\nVERIFICATION FAILURE: {len(failures)} reference tool(s) unusable")
        return 2
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
