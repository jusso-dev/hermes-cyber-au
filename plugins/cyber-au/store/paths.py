"""Where cyber-au keeps its state.

``CYBERAU_DATA_DIR`` wins. Otherwise state lives under
``$HERMES_HOME/plugin-data/cyber-au``, or ``~/.hermes/plugin-data/cyber-au``
when ``HERMES_HOME`` is unset. Nothing here creates a directory.

This is the same rule as ``cyberau_common.runtime.profile_data_dir``. It is kept here,
standard library only, because the plugin package, ``update`` and ``doctor`` load before
the connector virtualenv (and PyYAML) exists. A parity test keeps the two in step.
"""

from __future__ import annotations

import os
from pathlib import Path

_SUBDIR = Path("plugin-data") / "cyber-au"


def _override() -> Path | None:
    value = os.environ.get("CYBERAU_DATA_DIR", "").strip()
    return Path(value).expanduser() if value else None


def _inside(path: Path, root: Path) -> bool:
    target = path.resolve()
    base = root.resolve()
    return target == base or base in target.parents


def foreign_data_dir(profile: Path) -> Path | None:
    """``CYBERAU_DATA_DIR`` when it is set and resolves outside ``profile``, else ``None``.

    Such a value belongs to another profile (or none), so ``profile_data_dir`` ignores it.
    """
    override = _override()
    if override is None or _inside(override, Path(profile)):
        return None
    return override


def profile_data_dir(profile: Path) -> Path:
    """The data directory for a named profile home.

    ``CYBERAU_DATA_DIR`` wins only when it resolves inside ``profile``. Otherwise it is
    ``<profile>/plugin-data/cyber-au``, whatever ``HERMES_HOME`` says, because the caller
    named the profile.
    """
    override = _override()
    if override is not None and _inside(override, Path(profile)):
        return override
    return Path(profile) / _SUBDIR


def configured_data_dir() -> Path | None:
    """The data directory named by the environment, or ``None`` when neither variable is set."""
    override = _override()
    if override is not None:
        return override
    home = os.environ.get("HERMES_HOME", "").strip()
    if home:
        return Path(home).expanduser() / _SUBDIR
    return None


def data_dir() -> Path:
    """The data directory, falling back to the default Hermes home."""
    return configured_data_dir() or Path.home() / ".hermes" / _SUBDIR
