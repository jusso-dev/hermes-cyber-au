"""Markdown notes generated from the vendor catalogue."""

from __future__ import annotations

from cyberau_premium.catalog import VendorSpec
from cyberau_premium.paths import repo_root


def terms_dir():
    return repo_root() / "docs" / "premium" / "terms"


def render_vendor_terms(spec: VendorSpec) -> str:
    if spec.paid:
        standing = "Paid, bring your own licence. The server ships disabled."
    else:
        standing = (
            "Free feed. It still ships disabled because it handles victim claims."
        )
    lines = [
        f"# {spec.name}",
        "",
        f"Server `{spec.server}`. {standing}",
        "",
        "Generated from `mcp/premium/vendors.yaml`. Not legal advice.",
        "",
        "## Terms",
        "",
        "| Flag | Default |",
        "| --- | --- |",
        f"| `cache` | `{spec.terms.cache}` |",
        f"| `cache_ttl_max_s` | `{spec.terms.cache_ttl_max_s}` |",
        f"| `store` | `{spec.terms.store}` |",
        f"| `stix_export` | `{str(spec.terms.stix_export).lower()}` |",
        f"| `share_outside_profile` | `{str(spec.terms.share_outside_profile).lower()}` |",
        f"| `redistribution` | `{spec.terms.redistribution}` |",
        "",
        "## Licence environment",
        "",
        "Names only. Put values in the profile `.env`. Do not commit them.",
        "",
    ]
    if spec.licence_env:
        lines.extend(f"- `{name}` (required)" for name in spec.licence_env)
    else:
        lines.append("- No required licence variable.")
    lines.extend(f"- `{name}` (optional)" for name in spec.optional_env)
    lines.extend(
        [
            "",
            "## Quota defaults",
            "",
            f"- Calls per day: {_quota(spec.quota.calls_per_day)}",
            f"- Calls per month: {_quota(spec.quota.calls_per_month)}",
            f"- Cost units per call: {_quota(spec.quota.cost_units_per_call)}",
            f"- Monthly budget units: {_quota(spec.quota.monthly_budget_units)} (you set this)",
            f"- Approval above units: {_quota(spec.quota.approval_above_units)}",
            f"- Hard stop: {str(spec.quota.hard_stop).lower()}",
            f"- Routine share: {spec.routine_share}",
            f"- Max pages: {spec.max_pages}",
            "",
            "## Attribution",
            "",
            spec.terms.attribution,
            "",
        ]
    )
    return "\n".join(lines)


def _quota(value) -> str:
    if value is None:
        return "not set"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)
