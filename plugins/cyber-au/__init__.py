"""Load the cyber-au command when Hermes imports this plugin."""

from __future__ import annotations

import sys
from pathlib import Path


def register(ctx):
    """Register `hermes cyber-au update`."""
    plugin_dir = str(Path(__file__).resolve().parent)
    if plugin_dir not in sys.path:
        sys.path.insert(0, plugin_dir)
    from cli import register as register_cli

    register_cli(ctx)
