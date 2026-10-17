"""Audit hooks. The hash-chained audit log is not installed yet.

Failures are logged and swallowed. The pre_tool_call fail-closed path from the
security epic is not installed yet, so a failure does not block the tool call.
Arguments and results are never logged.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

AUDIT_NOT_INSTALLED = "The audit log is not installed yet."


def _run(event: str) -> None:
    """Note that this audit event has no writer yet."""
    del event
    logger.debug("%s", AUDIT_NOT_INSTALLED)


def _safe(event: str) -> None:
    try:
        _run(event)
    except Exception:
        logger.exception("cyber-au audit %s failed", event)
    return None


def on_pre_tool_call(**kwargs) -> None:
    """Observe a tool call before it runs. Does not block."""
    del kwargs
    return _safe("pre_tool_call")


def on_post_tool_call(**kwargs) -> None:
    """Observe a tool call after it returns."""
    del kwargs
    return _safe("post_tool_call")


def on_session_start(**kwargs) -> None:
    """Mark a session start. No audit record is written."""
    del kwargs
    return _safe("on_session_start")


def on_session_end(**kwargs) -> None:
    """Mark a session end. No audit record is written."""
    del kwargs
    return _safe("on_session_end")


def register_hooks(ctx) -> None:
    """Register the hooks declared in plugin.yaml."""
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("post_tool_call", on_post_tool_call)
    ctx.register_hook("on_session_start", on_session_start)
    ctx.register_hook("on_session_end", on_session_end)
