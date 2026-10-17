"""pre_tool_call guard: disabled by default, then budget, terms and approval."""

from __future__ import annotations

import logging

from cyberau_common.secrets import lookup

from cyberau_premium.base import QuotaPolicy
from cyberau_premium.budget import BudgetLedger, BudgetSettings
from cyberau_premium.caching import clear_session_caches
from cyberau_premium.catalog import (
    TermsRejected,
    VendorSpec,
    apply_terms,
    get_vendor,
    quota_override,
    vendor_config,
    vendor_for_tool,
)

LOGGER = logging.getLogger("cyberau.premium")
_QUOTA_FIELDS = set(QuotaPolicy.model_fields)


def pre_tool_call(
    tool_name: str | None = None,
    args: dict | None = None,
    vendor: str | None = None,
    routine: bool = False,
    approved: bool = False,
    config: dict | None = None,
    ledger: BudgetLedger | None = None,
    **kwargs,
) -> dict:
    spec = _resolve(tool_name, vendor)
    if spec is None:
        return {"decision": "allow", "block": False, "message": ""}
    routine = bool(routine or kwargs.get("cron") or kwargs.get("is_routine"))
    book = ledger or BudgetLedger()
    if not _enabled(spec, config):
        return _block(book, spec.server, _off_message(spec))
    if spec.licence_env and any(lookup(name) is None for name in spec.licence_env):
        return _block(book, spec.server, f"Blocked {spec.server}: on, key missing.")
    try:
        apply_terms(spec, config)
    except TermsRejected as exc:
        return _block(book, spec.server, f"Blocked {spec.server}: {exc}.")
    settings = settings_for(spec, config)
    try:
        pages = _pages(args)
    except (TypeError, ValueError):
        return _block(book, spec.server, f"Blocked {spec.server}: pages must be a whole number.")
    if pages is not None and pages > settings.max_pages:
        return _block(
            book,
            spec.server,
            f"Blocked {spec.server}: max_pages limit is {settings.max_pages}.",
        )
    decision = book.gate(
        spec.server,
        settings,
        routine=routine,
        approved=approved,
    )
    return {
        "decision": decision.decision,
        "block": decision.decision == "block",
        "needs_approval": decision.decision == "ask",
        "message": decision.message,
    }


def on_session_end(**kwargs) -> None:
    del kwargs
    clear_session_caches()


def settings_for(spec: VendorSpec, config: dict | None) -> BudgetSettings:
    data = spec.quota.model_dump()
    override = quota_override(spec, config)
    for key, value in override.items():
        if key in _QUOTA_FIELDS:
            data[key] = value
    share = float(override.get("routine_share", spec.routine_share))
    pages = int(override.get("max_pages", spec.max_pages))
    return BudgetSettings(
        quota=QuotaPolicy.model_validate(data),
        routine_share=share,
        max_pages=pages,
    )


def _resolve(tool_name: str | None, vendor: str | None) -> VendorSpec | None:
    if vendor:
        try:
            return get_vendor(vendor)
        except KeyError:
            return None
    if not tool_name:
        return None
    return vendor_for_tool(tool_name)


def _enabled(spec: VendorSpec, config: dict | None) -> bool:
    if not config:
        return False
    servers = config.get("mcp_servers") or {}
    entry = servers.get(spec.server) or {}
    if isinstance(entry, dict) and "enabled" in entry:
        return entry["enabled"] is True
    block = vendor_config(config, spec.server)
    return block.get("enabled") is True


def _off_message(spec: VendorSpec) -> str:
    if spec.paid:
        return f"Blocked {spec.server}: off (paid, bring your own licence)."
    return f"Blocked {spec.server}: off (free feed, disabled until you enable it)."


def _pages(args: dict | None) -> int | None:
    if not isinstance(args, dict):
        return None
    for key in ("pages", "max_pages", "page_count"):
        if args.get(key) is not None:
            value = args[key]
            if isinstance(value, bool):
                raise TypeError("pages must be a whole number")
            return int(value)
    return None


def _block(ledger: BudgetLedger, vendor: str, message: str) -> dict:
    ledger.log(vendor, "block", message)
    LOGGER.warning("%s", message)
    return {"decision": "block", "block": True, "needs_approval": False, "message": message}
