"""pytest configuration for SPYDER test suite."""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure the project root is on sys.path so `import spyder` works
# regardless of whether the package is installed.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
