"""SPYDER — modular red-team workflow orchestration platform.

SPYDER focuses on reconnaissance, endpoint discovery, passive response analysis,
workspace management, reporting, and orchestration of external analyst tools.
It deliberately does *not* implement automated exploitation or bypass logic.
"""

# The single source of truth for SPYDER's version. pyproject.toml reads it from
# here (`[tool.setuptools.dynamic] version = {attr = "spyder.__version__"}`), so
# the packaged version, `spyder --version`, the banner, and the default
# User-Agent can never disagree.
__version__ = "1.0.0"

__all__ = ["__version__"]
