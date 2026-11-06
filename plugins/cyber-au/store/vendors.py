"""Built-in vendor aliases shared by the watchlist and the asset inventory."""

from __future__ import annotations

# Keys and aliases are matched with each caller's own token rule.
VENDOR_ALIASES: dict[str, tuple[str, ...]] = {
    "Microsoft": ("MSFT",),
    "Fortinet": ("FortiGate", "FortiOS"),
    "Palo Alto Networks": ("PAN-OS",),
    "Cisco": (),
    "Citrix": ("NetScaler",),
    "Ivanti": ("Pulse Secure",),
    "VMware": ("Broadcom VMware",),
    "Atlassian": ("Confluence", "Jira"),
}
