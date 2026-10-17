"""Fresh render and doctor lines for premium servers."""

from __future__ import annotations

from datetime import datetime

import yaml

from cyberau_premium.budget import BudgetLedger, Usage
from cyberau_premium.catalog import VendorSpec, load_vendors
from cyberau_premium.paths import repo_root


def load_servers() -> dict:
    path = repo_root() / "mcp" / "servers.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return document.get("servers") or {}


def render_premium_servers(
    servers: dict,
    *,
    env: dict[str, str] | None = None,
    profile_home: str = "/profile",
    user_enabled: dict[str, bool] | None = None,
) -> dict:
    """Render premium MCP servers. A fresh install leaves every one disabled.

    `env` is accepted so a caller can prove that a present licence does not
    switch a server on. Values are never copied into the result.
    """
    del env
    catalogue = {spec.server for spec in load_vendors()}
    chosen = user_enabled or {}
    rendered = {}
    for name, entry in servers.items():
        if name not in catalogue and not entry.get("paid"):
            continue
        rendered[name] = {
            "command": f"{profile_home}/mcp/.venv/bin/cyberau-mcp",
            "args": list(entry.get("args") or ["serve", name]),
            "env": _render_env(entry, profile_home),
            "enabled": bool(chosen.get(name)),
            "trust": entry.get("trust", "untrusted"),
            "lazy": bool(entry.get("lazy", True)),
            "timeout": entry.get("timeout", 120),
        }
    return rendered


def vendor_state(*, enabled: bool, key_present: bool, paid: bool, needs_key: bool) -> str:
    if not enabled:
        if paid:
            return "off (paid, bring your own licence)"
        return "off (free feed, disabled until you enable it)"
    if needs_key and not key_present:
        return "on, key missing"
    return "on"


def format_premium_doctor(
    env: dict[str, str],
    enabled: dict[str, bool],
    ledger: BudgetLedger,
    *,
    now: datetime | None = None,
) -> str:
    lines = []
    for spec in load_vendors():
        key_present = _key_present(spec, env)
        state = vendor_state(
            enabled=bool(enabled.get(spec.server)),
            key_present=key_present,
            paid=spec.paid,
            needs_key=bool(spec.licence_env),
        )
        usage = ledger.usage(spec.server, now=now)
        lines.append(f"{spec.server}: {state}")
        lines.append(_usage_line(spec, usage))
    return "\n".join(lines)


def _key_present(spec: VendorSpec, env: dict[str, str]) -> bool:
    if not spec.licence_env:
        return True
    return all(str(env.get(name) or "").strip() for name in spec.licence_env)


def _usage_line(spec: VendorSpec, usage: Usage) -> str:
    quota = spec.quota
    return (
        f"  usage: day {usage.calls_today}/{_limit(quota.calls_per_day)}; "
        f"month {usage.calls_month}/{_limit(quota.calls_per_month)}; "
        f"cost {usage.cost_month:g}/{_limit(quota.monthly_budget_units)} "
        "(Australia/Sydney)"
    )


def _limit(value) -> str:
    if value is None:
        return "not set"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _render_env(entry: dict, profile_home: str) -> dict[str, str]:
    rendered = {
        "CYBERAU_DATA_DIR": f"{profile_home}/plugin-data/cyber-au",
        "CYBERAU_EGRESS_ALLOWLIST": f"{profile_home}/mcp/egress-allowlist.yaml",
    }
    for item in entry.get("env") or []:
        name, raw = str(item).split("=", 1)
        variable = raw.strip()
        if variable.startswith("${") and variable.endswith("}"):
            variable = variable[2:-1]
        rendered[name] = "${" + variable + "}"
    return rendered
