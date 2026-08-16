#!/usr/bin/env python3
"""Development entry point — delegates entirely to spyder.__main__.

Usage:
    python3 main.py                    # interactive REPL
    python3 main.py scan -u <url>      # one-shot CLI
    python3 main.py --help             # help

After `pip install -e .`:
    spyder                             # same as above (preferred)

This file exists only so `python3 main.py` works from the repo root
without requiring an editable install. For all other uses, prefer `spyder`.
"""
import sys
from pathlib import Path

# Ensure the package is importable from the repo root (dev convenience only).
# This has no effect when the package is installed.
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from spyder.__main__ import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
