"""Configuration and profile management for SPYDER.

Data directory strategy (matches professional Kali tool conventions):

    ~/.local/share/spyder/   — persistent data (DB, workspaces, reports, logs)
    ~/.config/spyder/        — config profiles (optional)
    $SPYDER_HOME             — override both of the above

This means `spyder` works correctly after `pip install` or `pipx install`
from any working directory, just like sqlmap, nuclei, and subfinder do.
"""
from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_home() -> Path:
    """
    Resolve the SPYDER data directory.

    Priority:
      1. $SPYDER_HOME environment variable (explicit override)
      2. ~/.local/share/spyder/  (XDG_DATA_HOME, standard for installed tools)

    Using XDG means:
      - `spyder` works from any directory after `pip install` / `pipx install`
      - All engagements live in a predictable, version-control-friendly location
      - Multiple users on the same machine don't collide
    """
    env = os.environ.get("SPYDER_HOME")
    if env:
        return Path(env).expanduser().resolve()

    xdg_data = os.environ.get("XDG_DATA_HOME")
    if xdg_data:
        return Path(xdg_data) / "spyder"

    return Path.home() / ".local" / "share" / "spyder"


def _default_user_agent() -> str:
    """Identify SPYDER honestly, at the real version.

    Deliberately NOT a spoofed browser string: SPYDER is a recon tool for
    authorized engagements, and a target's operators should be able to attribute
    the traffic. The version is read from the package so it cannot go stale.
    """
    from .. import __version__

    return f"Mozilla/5.0 (X11; Linux x86_64) SPYDER/{__version__} (+authorized-testing)"


class HTTPConfig(BaseModel):
    timeout: float = 20.0
    max_connections: int = 50
    max_retries: int = 2
    http2: bool = True
    verify_tls: bool = True
    follow_redirects: bool = True
    proxy: str | None = None          # set to "http://127.0.0.1:8080" for Burp
    user_agents: list[str] = Field(default_factory=lambda: [_default_user_agent()])
    default_headers: dict[str, str] = Field(default_factory=dict)


class CrawlConfig(BaseModel):
    max_depth: int = 3
    max_pages: int = 500
    concurrency: int = 10
    respect_robots: bool = True
    parse_sitemap: bool = True
    extract_js_endpoints: bool = True
    rate_limit_per_sec: float = 10.0


class RateLimitConfig(BaseModel):
    requests_per_second: float = 10.0
    burst: int = 20


class SpyderConfig(BaseSettings):
    """Root configuration. Loadable from env vars (SPYDER_*) or a YAML profile."""

    model_config = SettingsConfigDict(env_prefix="SPYDER_", env_nested_delimiter="__")

    home: Path = Field(default_factory=_default_home)
    profile_name: str = "default"
    passive_mode: bool = False
    http: HTTPConfig = Field(default_factory=HTTPConfig)
    crawl: CrawlConfig = Field(default_factory=CrawlConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    plugin_dirs: list[Path] = Field(default_factory=list)

    # ── Derived settings ───────────────────────────────────────────────────
    @property
    def effective_rate_limit(self) -> float:
        """Requests per second actually applied to the target.

        Two settings name this rate: ``rate_limit.requests_per_second`` and
        ``crawl.rate_limit_per_sec``. Only the former was ever read, so an
        operator who throttled a scan under the ``crawl:`` section — the obvious
        place to look, and where both shipped profiles also set it — was
        silently ignored and their scan ran at the default rate. For a tool
        aimed at authorized targets, a rate limit that does nothing is a way to
        hit a target harder than its owner agreed to.

        Whichever limit is lower wins, so neither setting can be exceeded. The
        crawl figure only participates when it was set explicitly: leaving it at
        its default must not cap an operator who deliberately raised the client
        rate. Both shipped profiles set the two to the same value, so their
        behaviour is unchanged.
        """
        rate = self.rate_limit.requests_per_second
        if "rate_limit_per_sec" in self.crawl.model_fields_set:
            return min(rate, self.crawl.rate_limit_per_sec)
        return rate

    # ── Derived paths ──────────────────────────────────────────────────────
    @property
    def db_path(self) -> Path:
        return self.home / "db" / "spyder.sqlite"

    @property
    def workspaces_dir(self) -> Path:
        return self.home / "workspaces"

    @property
    def reports_dir(self) -> Path:
        return self.home / "reports"

    @property
    def logs_dir(self) -> Path:
        return self.home / "logs"

    @property
    def configs_dir(self) -> Path:
        return self.home / "configs"

    @property
    def default_plugin_dir(self) -> Path:
        return self.home / "plugins"

    def ensure_dirs(self) -> None:
        """Create the runtime directory tree on first use."""
        for p in (
            self.home,
            self.db_path.parent,
            self.workspaces_dir,
            self.reports_dir,
            self.logs_dir,
            self.configs_dir,
            self.default_plugin_dir,
        ):
            p.mkdir(parents=True, exist_ok=True)

    # ── Profile I/O ────────────────────────────────────────────────────────
    @classmethod
    def from_profile(cls, path: str | Path) -> SpyderConfig:
        p = Path(path)
        # Clean, operator-facing errors instead of a raw OSError/YAML traceback:
        # a mistyped --profile path is user input, not a crash.
        if not p.is_file():
            raise FileNotFoundError(f"profile not found: {path}")
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ValueError(f"invalid YAML in profile {path}: {exc}") from exc
        return cls(**data)

    def save_profile(self, path: str | Path) -> None:
        Path(path).write_text(
            yaml.safe_dump(self.model_dump(mode="json"), sort_keys=False), encoding="utf-8"
        )


def load_config(profile: str | Path | None = None) -> SpyderConfig:
    """Load configuration from a YAML profile or from environment variables."""
    cfg = SpyderConfig.from_profile(profile) if profile else SpyderConfig()
    if profile:
        cfg.profile_name = Path(profile).stem
    if cfg.default_plugin_dir not in cfg.plugin_dirs:
        cfg.plugin_dirs.append(cfg.default_plugin_dir)
    cfg.ensure_dirs()
    return cfg
