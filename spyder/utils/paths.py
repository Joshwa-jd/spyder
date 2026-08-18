"""Filesystem-safe name helpers.

Workspace names and report labels are operator-supplied and may, in scripted or
CI-driven use, be derived from untrusted input (e.g. a target hostname). Anything
that turns such a label into a filesystem path must first reduce it to a single
safe path segment, or a value like ``../../etc/passwd`` could steer writes outside
the intended directory (path traversal / arbitrary file write).
"""
from __future__ import annotations

import re

# Everything outside this set is collapsed to "_". Note "/" and "\" are excluded,
# so no path separators can survive; "." is allowed but leading/trailing dots are
# stripped below so ".." and dotfiles cannot escape or hide.
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def safe_slug(name: str, *, default: str = "default", max_len: int = 96) -> str:
    """Reduce an arbitrary label to a safe single path segment.

    Guarantees the result contains only ``[A-Za-z0-9._-]``, has no path
    separators, and no leading/trailing dots — so it can never reference a parent
    directory. Always returns a non-empty string (``default`` if nothing usable
    remains).
    """
    slug = _UNSAFE.sub("_", (name or "").strip())
    slug = slug.strip("._")[:max_len].strip("._")
    return slug or default
