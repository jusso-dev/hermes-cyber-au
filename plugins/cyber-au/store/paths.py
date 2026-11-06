"""Where cyber-au keeps its state.

``CYBERAU_DATA_DIR`` wins. Otherwise state lives under
``$HERMES_HOME/plugin-data/cyber-au``, or ``~/.hermes/plugin-data/cyber-au``
when ``HERMES_HOME`` is unset. Nothing here creates a directory.
"""

from __future__ import annotations

import os
from pathlib import Path

_SUBDIR = Path("plugin-data") / "cyber-au"


def configured_data_dir() -> Path | None:
    """The data directory named by the environment, or ``None`` when neither variable is set."""
    override = os.environ.get("CYBERAU_DATA_DIR", "").strip()
    if override:
        return Path(override).expanduser()
    home = os.environ.get("HERMES_HOME", "").strip()
    if home:
        return Path(home).expanduser() / _SUBDIR
    return None


def data_dir() -> Path:
    """The data directory, falling back to the default Hermes home."""
    return configured_data_dir() or Path.home() / ".hermes" / _SUBDIR
