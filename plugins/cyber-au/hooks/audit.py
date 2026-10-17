"""Audit hooks for the cyber-au plugin.

The plugin skeleton calls ``register`` from its own ``register(ctx)``.
The callbacks record session boundaries, tool calls, approvals, blocks,
exports and deliveries. Write tools are blocked when the log cannot be
written. Read tools continue, with a warning.
"""

from __future__ import annotations

from cyberau_common.audit import AuditHooks, AuditLog, register_cli, register_hooks

_hooks = AuditHooks(AuditLog())


def pre_tool_call(tool_name, args=None, task_id="", **kwargs):
    return _hooks.pre_tool_call(tool_name, args, task_id, **kwargs)


def post_tool_call(tool_name, args=None, result=None, task_id="", duration_ms=0, **kwargs):
    return _hooks.post_tool_call(
        tool_name, args, result, task_id, duration_ms, **kwargs
    )


def on_session_start(session_id, model="", platform="", **kwargs):
    return _hooks.on_session_start(session_id, model, platform, **kwargs)


def on_session_end(
    session_id,
    completed=False,
    interrupted=False,
    model="",
    platform="",
    **kwargs,
):
    return _hooks.on_session_end(
        session_id, completed, interrupted, model, platform, **kwargs
    )


def register(ctx):
    """Register audit hooks and the ``cyber-au audit`` command."""
    register_hooks(ctx, _hooks)
    register_cli(ctx)
