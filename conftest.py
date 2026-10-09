"""Root pytest configuration.

Guarantees that the repository root is importable as the ``satsa`` package parent
regardless of how pytest is invoked (``python -m pytest``, ``pytest`` from a
subdirectory, CI runners, etc.), replacing the former per-module
``sys.path.insert(...)`` hacks.
"""

from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
