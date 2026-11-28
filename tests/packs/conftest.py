"""Put the cyber-au plugin (``store``) on the import path for the sector pack tests."""

from __future__ import annotations

import sys
from pathlib import Path

PLUGIN = str(Path(__file__).resolve().parents[2] / "plugins" / "cyber-au")
if PLUGIN not in sys.path:
    sys.path.insert(0, PLUGIN)
