"""Audit hooks for the cyber-au plugin.

The callbacks record session boundaries, tool calls, approvals, blocks,
exports and deliveries. Write tools are blocked when the log cannot be
written. Read tools continue, with a warning.
"""

from __future__ import annotations

from cyberau_common.audit import AuditHooks, AuditLog, register_hooks


def register(ctx):
    """Register the audit hooks.

    ``cyber-au audit`` is a subcommand of the plugin's single ``cyber-au``
    command (see ``cli.setup_parser``), so it is not registered here.
    """
    register_hooks(ctx, AuditHooks(AuditLog()))
