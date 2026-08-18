"""Input-validation surface.

``parse_target`` turns raw operator input into a validated ``Target`` (raising a
clean ``ValueError`` on bad URLs rather than leaking a pydantic traceback);
``normalize_url`` promotes bare hosts to ``https://``.
"""
from __future__ import annotations

from ..core.models import normalize_url, parse_target

__all__ = ["normalize_url", "parse_target"]
