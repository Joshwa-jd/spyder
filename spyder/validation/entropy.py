"""Entropy & character-distribution heuristics for fake-secret suppression.

Pure, deterministic string analytics. These functions let the secret validator
tell a real high-entropy credential apart from a placeholder, a template literal,
or a low-entropy English word that merely matched a greedy regex.
"""
from __future__ import annotations

import math
import re
from collections import Counter

# Tokens that strongly indicate a *non*-secret: examples, placeholders, scaffolds.
_PLACEHOLDER_TOKENS: frozenset[str] = frozenset({
    "example", "examples", "test", "tests", "testing", "sample", "demo",
    "placeholder", "dummy", "changeme", "change_me", "yourkey", "your_key",
    "your-api-key", "yourapikey", "apikey", "api_key", "secret", "token",
    "xxxx", "xxxxxx", "redacted", "todo", "fixme", "foo", "bar", "baz",
    "none", "null", "undefined", "false", "true", "lorem", "ipsum",
    "abc123", "123456", "password", "passw0rd", "default", "insertkey",
    "admin", "root", "letmein", "qwerty", "welcome", "secret_key",
})

#: Trailing runs a weak value is commonly padded with. "password1234" is a
#: dictionary word wearing a counter, not a credential — but it is long enough
#: and diverse enough to fool a pure entropy test, so the word is checked once
#: the padding is removed.
_PAD_CHARS = "0123456789_-!@#$."

# Substrings that, if present, mark a value as a template/placeholder.
_PLACEHOLDER_SUBSTRINGS: tuple[str, ...] = (
    "your", "example", "placeholder", "changeme", "change-me", "change_me",
    "xxxx", "<", ">", "{{", "}}", "${", "%s", "%d", "...", "redact",
    "enter_", "insert_", "replace_", "dummy", "sample",
)

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_REPEAT_RE = re.compile(r"^(.)\1+$")  # a single repeated character


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits-per-character (0 for empty/uniform strings)."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def charset_classes(s: str) -> int:
    """How many character classes (lower/upper/digit/symbol) appear in ``s``."""
    classes = 0
    if any(c.islower() for c in s):
        classes += 1
    if any(c.isupper() for c in s):
        classes += 1
    if any(c.isdigit() for c in s):
        classes += 1
    if any(not c.isalnum() for c in s):
        classes += 1
    return classes


def is_placeholder(s: str) -> bool:
    """Whether ``s`` looks like an example/placeholder rather than a real secret."""
    if not s:
        return True
    low = s.strip().lower()
    if low in _PLACEHOLDER_TOKENS:
        return True
    if any(tok in low for tok in _PLACEHOLDER_SUBSTRINGS):
        return True
    if _REPEAT_RE.match(s):  # "aaaaaaaa", "00000000"
        return True
    # "password1234", "changeme_01" — a placeholder word plus padding.
    if low.strip(_PAD_CHARS) in _PLACEHOLDER_TOKENS:
        return True
    # A run of a single character padded to length (e.g. "Axxxxxxxxxx").
    most_common = Counter(s).most_common(1)
    if most_common and most_common[0][1] >= max(8, len(s) * 0.7):
        return True
    return False


def looks_random(s: str, *, min_entropy: float = 3.0, min_len: int = 12) -> bool:
    """Heuristic: does ``s`` resemble a genuinely random high-entropy token?

    Requires sufficient length, entropy, and character-class diversity. Pure hex
    digests are allowed a lower class bar (they are single-class by nature).
    """
    if len(s) < min_len or is_placeholder(s):
        return False
    entropy = shannon_entropy(s)
    if _HEX_RE.match(s):
        # hex digests: judge purely on length + entropy
        return len(s) >= 16 and entropy >= 3.0
    return entropy >= min_entropy and charset_classes(s) >= 2
