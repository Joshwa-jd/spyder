"""Structured logging for SPYDER, backed by Rich."""
from __future__ import annotations

import logging
from pathlib import Path

from rich.logging import RichHandler

_CONFIGURED = False


def setup_logging(level: str = "INFO", log_dir: Path | None = None, debug: bool = False) -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    # Keep noisy third-party loggers out of the console.
    for noisy in ("httpx", "httpcore", "hpack", "h2", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    # Console handler: quiet by default so command output reads like a
    # professional CLI (sqlmap/nuclei stay silent unless something is wrong).
    # `--debug` opens the firehose. The full INFO trail always goes to the file.
    console_handler = RichHandler(rich_tracebacks=True, show_path=debug, markup=True)
    console_handler.setLevel(logging.DEBUG if debug else logging.WARNING)
    handlers: list[logging.Handler] = [console_handler]
    if log_dir:
        log_dir.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_dir / "spyder.log")
        fh.setLevel(logging.DEBUG if debug else logging.INFO)
        fh.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-7s %(name)s :: %(message)s")
        )
        handlers.append(fh)
    # Root at DEBUG so handlers decide what to surface via their own levels.
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(message)s",
        datefmt="[%X]",
        handlers=handlers,
    )
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"spyder.{name}")
