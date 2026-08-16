"""Recon-pipeline connectors — orchestrate the analyst's installed recon tooling.

Each connector shells out to an established, user-installed recon tool (subfinder,
amass, assetfinder, httpx, katana, gau, waybackurls, ffuf), streams its discoveries
live onto the event bus, normalizes/deduplicates output into a unified shape, and
returns a summary Finding whose evidence carries the discovered inventory.

Scope posture (recon only):
  * passive/discovery flags by default — amass runs ``-passive``; ffuf is
    content-discovery only and refuses to run without an explicit wordlist.
  * no exploitation, no auth attacks, no payload generation.
  * SPYDER ships no tool logic; it builds command lines and captures output.
"""
from __future__ import annotations

import shutil
from typing import Any
from urllib.parse import urlparse

from ..core.events import EventType
from ..core.models import Finding, Severity
from .base import ConnectorError, ExternalToolConnector


def _host(target: str) -> str:
    """Return the bare hostname for a URL or pass through a bare domain."""
    if "://" in target:
        return urlparse(target).netloc.split("@")[-1].split(":")[0]
    return target.split("/")[0].split(":")[0]


def _norm_subdomain(line: str) -> str | None:
    s = line.strip().lower()
    if "://" in s:
        s = urlparse(s).netloc
    s = s.split()[0] if s.split() else s
    s = s.strip(".")
    return s if ("." in s and " " not in s and "/" not in s) else None


_ILLEGAL_HOST_CHARS = frozenset(" '\"\\<>{}|^`()[]")


def _norm_url(line: str) -> str | None:
    """Extract a real URL from a tool output line, or None.

    Recon tools emit the URL as the first whitespace-delimited token (httpx may
    append ``[status] [title] [tech]`` columns). We take that first token and
    require it to resolve to a genuine host — a dotted domain, an IP literal, or
    ``localhost`` — so that arbitrary noise/error text a tool prints to stdout is
    never fabricated into a "discovered URL".
    """
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    token = s.split()[0]
    if "://" not in token:
        token = "http://" + token
    if not token.startswith(("http://", "https://")):
        return None
    host = (urlparse(token).hostname or "").strip()
    if not host or any(c in _ILLEGAL_HOST_CHARS for c in host):
        return None
    # Require a plausible host: dotted domain, IPv4/IPv6 literal, or localhost.
    if "." not in host and ":" not in host and host != "localhost":
        return None
    return token


def _is_python_httpx_shim(path: str) -> bool:
    """True when ``path`` is the Python ``httpx`` library's console script.

    SPYDER depends on the ``httpx`` HTTP library, whose package installs an
    ``httpx`` console script. In a venv that script shadows ProjectDiscovery's
    ``httpx`` recon binary on PATH. ProjectDiscovery httpx is a native
    executable (ELF / PE / Mach-O); the Python shim is a small text script with
    a ``python`` shebang — that is the reliable, cross-platform discriminator.
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(256)
    except OSError:
        return False
    if head[:4] == b"\x7fELF" or head[:2] in (b"MZ", b"\xcf\xfa"):
        return False  # native binary → the real recon tool
    first_line = head.split(b"\n", 1)[0]
    return first_line.startswith(b"#!") and b"python" in first_line


class ReconToolConnector(ExternalToolConnector):
    """Shared behaviour for recon connectors that emit a normalized inventory."""

    # "subdomains" or "urls" — the evidence key this tool populates.
    result_kind: str = "urls"

    def _summary(self, target: str, items: list[str], tool_meta: dict | None = None) -> list[Finding]:
        kind = self.result_kind
        finding = self._finding(
            title=f"{self.name}: {len(items)} {kind} discovered",
            severity=Severity.INFO,
            endpoint=target,
            description=f"Recon tool '{self.name}' discovered {len(items)} {kind}.",
            evidence={kind: sorted(items), "count": len(items), **(tool_meta or {})},
        )
        self._emit(
            EventType.RECON_TOOL,
            f"{self.name}: {len(items)} {kind}",
            tool=self.name, kind=kind, count=len(items),
        )
        return [finding]


# ---------------------------------------------------------------------------
# Subdomain enumeration
# ---------------------------------------------------------------------------


class SubfinderConnector(ReconToolConnector):
    name = "subfinder"
    version = "1.0.0"
    binary = "subfinder"
    result_kind = "subdomains"

    async def run(self, target: str, options: dict[str, Any]) -> list[Finding]:
        host = _host(target)
        found: set[str] = set()

        def on_line(line: str) -> None:
            sub = _norm_subdomain(line)
            if sub and sub not in found:
                found.add(sub)
                self._emit(EventType.SUBDOMAIN, sub, tool=self.name, host=sub)

        args = ["-silent", "-d", host]
        if sources := options.get("sources"):
            args += ["-sources", sources]
        await self._stream(args, on_line, timeout=options.get("timeout", 600.0))
        return self._summary(target, list(found))


class AmassConnector(ReconToolConnector):
    name = "amass"
    version = "1.0.0"
    binary = "amass"
    result_kind = "subdomains"

    async def run(self, target: str, options: dict[str, Any]) -> list[Finding]:
        host = _host(target)
        found: set[str] = set()

        def on_line(line: str) -> None:
            sub = _norm_subdomain(line)
            if sub and host.split(".")[-2:] == sub.split(".")[-2:] and sub not in found:
                found.add(sub)
                self._emit(EventType.SUBDOMAIN, sub, tool=self.name, host=sub)

        # Passive-only by default to remain a recon (non-intrusive) operation.
        args = ["enum", "-passive", "-d", host]
        await self._stream(args, on_line, timeout=options.get("timeout", 900.0))
        return self._summary(target, list(found))


class AssetfinderConnector(ReconToolConnector):
    name = "assetfinder"
    version = "1.0.0"
    binary = "assetfinder"
    result_kind = "subdomains"

    async def run(self, target: str, options: dict[str, Any]) -> list[Finding]:
        host = _host(target)
        found: set[str] = set()

        def on_line(line: str) -> None:
            sub = _norm_subdomain(line)
            if sub and sub not in found:
                found.add(sub)
                self._emit(EventType.SUBDOMAIN, sub, tool=self.name, host=sub)

        await self._stream(["--subs-only", host], on_line, timeout=options.get("timeout", 300.0))
        return self._summary(target, list(found))


# ---------------------------------------------------------------------------
# URL discovery / probing
# ---------------------------------------------------------------------------


class HttpxConnector(ReconToolConnector):
    name = "httpx"
    version = "1.0.0"
    binary = "httpx"
    result_kind = "urls"

    _SHIM_HINT = (
        "the 'httpx' on PATH is the Python HTTP library's CLI, not ProjectDiscovery "
        "httpx. Install ProjectDiscovery httpx and make sure it precedes the Python "
        "shim on PATH — https://github.com/projectdiscovery/httpx"
    )

    def available(self) -> bool:
        path = shutil.which(self.binary)
        if not path:
            return False
        return not _is_python_httpx_shim(path)

    def _require_binary(self) -> None:
        path = shutil.which(self.binary)
        if path and _is_python_httpx_shim(path):
            raise ConnectorError(self._SHIM_HINT)
        super()._require_binary()

    async def run(self, target: str, options: dict[str, Any]) -> list[Finding]:
        found: set[str] = set()

        def on_line(line: str) -> None:
            url = _norm_url(line)
            if url and url not in found:
                found.add(url)
                self._emit(EventType.RECON_TOOL, url, tool=self.name, kind="urls")

        args = ["-silent", "-u", target]
        if options.get("status_code"):
            args += ["-status-code"]
        if options.get("title"):
            args += ["-title"]
        if options.get("tech_detect"):
            args += ["-tech-detect"]
        await self._stream(args, on_line, timeout=options.get("timeout", 300.0))
        return self._summary(target, list(found))


class KatanaConnector(ReconToolConnector):
    name = "katana"
    version = "1.0.0"
    binary = "katana"
    result_kind = "urls"

    async def run(self, target: str, options: dict[str, Any]) -> list[Finding]:
        found: set[str] = set()

        def on_line(line: str) -> None:
            url = _norm_url(line)
            if url and url not in found:
                found.add(url)
                self._emit(EventType.RECON_TOOL, url, tool=self.name, kind="urls")

        args = ["-silent", "-u", target]
        if depth := options.get("depth"):
            args += ["-d", str(depth)]
        if options.get("js_crawl"):
            args += ["-jc"]
        await self._stream(args, on_line, timeout=options.get("timeout", 600.0))
        return self._summary(target, list(found))


class GauConnector(ReconToolConnector):
    name = "gau"
    version = "1.0.0"
    binary = "gau"
    result_kind = "urls"

    async def run(self, target: str, options: dict[str, Any]) -> list[Finding]:
        host = _host(target)
        found: set[str] = set()

        def on_line(line: str) -> None:
            url = _norm_url(line)
            if url and url not in found:
                found.add(url)

        args = [host]
        if options.get("subs"):
            args += ["--subs"]
        await self._stream(args, on_line, timeout=options.get("timeout", 600.0))
        return self._summary(target, list(found))


class WaybackurlsConnector(ReconToolConnector):
    name = "waybackurls"
    version = "1.0.0"
    binary = "waybackurls"
    result_kind = "urls"

    async def run(self, target: str, options: dict[str, Any]) -> list[Finding]:
        host = _host(target)
        found: set[str] = set()

        def on_line(line: str) -> None:
            url = _norm_url(line)
            if url and url not in found:
                found.add(url)

        # waybackurls reads the target domain from stdin.
        await self._stream(
            [], on_line, timeout=options.get("timeout", 600.0), input_data=host + "\n"
        )
        return self._summary(target, list(found))


class FfufConnector(ReconToolConnector):
    """Content discovery only — requires a wordlist; performs no exploitation."""

    name = "ffuf"
    version = "1.0.0"
    binary = "ffuf"
    result_kind = "urls"

    async def run(self, target: str, options: dict[str, Any]) -> list[Finding]:
        wordlist = options.get("wordlist")
        if not wordlist:
            raise ConnectorError(
                "ffuf requires a 'wordlist' option (content discovery only). "
                "Pass wordlist=/path/to/list.txt"
            )
        fuzz_url = target if "FUZZ" in target else target.rstrip("/") + "/FUZZ"
        found: set[str] = set()

        def on_line(line: str) -> None:
            payload = line.strip()
            if not payload:
                return
            url = fuzz_url.replace("FUZZ", payload)
            if url not in found:
                found.add(url)
                self._emit(EventType.RECON_TOOL, url, tool=self.name, kind="urls")

        match_codes = str(options.get("match_codes", "200,204,301,302,307,401,403"))
        args = ["-u", fuzz_url, "-w", str(wordlist), "-mc", match_codes, "-s"]
        await self._stream(args, on_line, timeout=options.get("timeout", 900.0))
        return self._summary(target, list(found), {"wordlist": str(wordlist), "match_codes": match_codes})


RECON_CONNECTORS = (
    SubfinderConnector,
    AmassConnector,
    AssetfinderConnector,
    HttpxConnector,
    KatanaConnector,
    GauConnector,
    WaybackurlsConnector,
    FfufConnector,
)
