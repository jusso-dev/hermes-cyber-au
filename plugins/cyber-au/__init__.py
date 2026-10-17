"""cyber-au native plugin.

``register(ctx)`` wires the in-process pieces: intel store tools, evidence
import, audit hooks, the untrusted-content middleware, and the cyber-au CLI
and slash commands. A piece whose implementation is not in this checkout
answers that it is not installed yet.
"""

from __future__ import annotations

import os
from pathlib import Path


def data_dir() -> Path:
    """Return the directory for cyber-au plugin state.

    ``CYBERAU_DATA_DIR`` overrides the path. Otherwise state lives under
    ``$HERMES_HOME/plugin-data/cyber-au``, or ``~/.hermes/plugin-data/cyber-au``
    when ``HERMES_HOME`` is unset. This function does not create the directory.
    """
    override = os.environ.get("CYBERAU_DATA_DIR", "").strip()
    if override:
        return Path(override).expanduser()
    home = os.environ.get("HERMES_HOME", "").strip()
    root = Path(home).expanduser() if home else Path.home() / ".hermes"
    return root / "plugin-data" / "cyber-au"


def register(ctx) -> None:
    """Register tools, hooks, middleware, and commands.

    A failure is not swallowed. Hermes then marks the plugin as failed to load, which
    is louder than a plugin with half its tools.
    """
    from .cli import register_commands
    from .hooks.audit import register_hooks
    from .middleware.untrusted import register_middleware
    from .tools.evidence import register_evidence
    from .tools.store import register_store

    register_store(ctx)
    register_evidence(ctx)
    register_hooks(ctx)
    register_middleware(ctx)
    register_commands(ctx)
