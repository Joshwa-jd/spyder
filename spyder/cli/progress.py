"""Progress / status-message surface.

The single source of the framework's status vocabulary. Every progress line is
built with one of these so wording and prefixes stay consistent everywhere:

    info(msg) → "[*] ..."   in-progress / informational
    ok(msg)   → "[+] ..."   success
    err(msg)  → "[-] ..."   failure / invalid input
    warn(msg) → "[!] ..."   warning (e.g. optional dependency missing)
"""
from __future__ import annotations

from ..ui.theme import err, info, ok, warn

__all__ = ["err", "info", "ok", "warn"]
