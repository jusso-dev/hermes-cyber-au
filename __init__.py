"""Hermes loads this file. The importable package is hermes_cyber_au."""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def register(ctx):
    from hermes_cyber_au.plugin import register as register_plugin

    return register_plugin(ctx)
