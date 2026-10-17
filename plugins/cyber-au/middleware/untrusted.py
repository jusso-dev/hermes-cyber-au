"""Untrusted-content middleware. The guard is not installed yet.

Tool execution is passed through unchanged. Feed text is not wrapped and is
not inspected. Arguments are never logged.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

logger = logging.getLogger(__name__)

GUARD_NOT_INSTALLED = "The untrusted-content guard is not installed yet."


def tool_execution(**kwargs):
    """Pass the tool call through. Call ``next_call`` exactly once when present."""
    next_call = kwargs.get("next_call")
    try:
        logger.debug("%s", GUARD_NOT_INSTALLED)
    except Exception:
        logger.exception("cyber-au untrusted-content middleware failed")
    if not isinstance(next_call, Callable):
        logger.error("cyber-au untrusted-content middleware did not receive next_call")
        return None
    payload_key = "request" if "request" in kwargs else "args"
    return next_call(kwargs.get(payload_key))


def register_middleware(ctx) -> None:
    """Register the tool_execution pass-through."""
    ctx.register_middleware("tool_execution", tool_execution)
