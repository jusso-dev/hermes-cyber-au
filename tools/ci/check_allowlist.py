#!/usr/bin/env python3
"""Fail when the egress allowlist drifts from the connector inventory.

The inventory is the source of the host lists. This script exits non-zero
when a connector host is added, removed, or renamed on only one side, and
when ``global_deny_cidrs`` drops a network the code always refuses.
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
from pathlib import Path

import yaml
from cyberau_common.egress import FLOOR_CIDRS, normalise_host

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ALLOWLIST = ROOT / "mcp" / "egress-allowlist.yaml"

# In-library connector. It does not call the network and is not an inventory row.
_STUB = "stub"
_STUB_HOSTS = frozenset({"example.com"})
_ORG_EXPOSURE = "org-exposure"
_ORG_EXPOSURE_HOSTS = frozenset({"abr.business.gov.au"})
_LOOPBACK = frozenset({"localhost", "127.0.0.1"})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    parser.add_argument(
        "--print-hosts",
        action="store_true",
        help="Print concrete catalogue hosts, one per line, after the drift check.",
    )
    args = parser.parse_args(argv)
    problems = differences(args.allowlist, inventory_rows())
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1
    if args.print_hosts:
        for host in catalogue_hosts(args.allowlist):
            print(host)
        return 0
    print(f"egress allowlist matches the inventory ({args.allowlist})")
    return 0


def differences(allowlist_path: Path, rows: list[dict]) -> list[str]:
    if not allowlist_path.is_file():
        return [f"allowlist missing: {allowlist_path}"]
    data = yaml.safe_load(allowlist_path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        return ["allowlist must be a mapping"]
    problems: list[str] = []
    if data.get("version") != 1:
        problems.append("allowlist version must be 1")
    problems.extend(_deny_problems(data.get("global_deny_cidrs")))
    listed = data.get("connectors") or {}
    if not isinstance(listed, dict):
        problems.append("allowlist connectors must be a mapping")
        return problems

    expected: dict[str, set[str]] = {}
    for row in rows:
        key = str(row.get("key") or "")
        if not key:
            problems.append("inventory row is missing a key")
            continue
        if key in expected:
            problems.append(f"inventory key {key} is duplicated")
            continue
        expected[key] = _expected_hosts(row.get("hosts") or [], key, problems)

    for key, hosts in expected.items():
        if key not in listed:
            problems.append(f"{key} is in the inventory but not the allowlist")
            continue
        actual = _listed_hosts(listed[key], key, problems)
        if actual is None:
            continue
        missing = sorted(hosts - actual)
        extra = sorted(actual - hosts)
        if missing:
            problems.append(f"{key} allowlist is missing: {', '.join(missing)}")
        if extra:
            problems.append(f"{key} allowlist has extra hosts: {', '.join(extra)}")

    for key in sorted(set(listed) - set(expected)):
        if key == _STUB:
            actual = _listed_hosts(listed[key], key, problems)
            if actual is not None and actual != _STUB_HOSTS:
                problems.append("stub hosts must stay example.com")
            continue
        if key == _ORG_EXPOSURE:
            actual = _listed_hosts(listed[key], key, problems)
            if actual is not None and actual != _ORG_EXPOSURE_HOSTS:
                problems.append("org-exposure hosts must stay abr.business.gov.au")
            continue
        problems.append(f"{key} is in the allowlist but not the inventory")
    return problems


def catalogue_hosts(allowlist_path: Path) -> list[str]:
    data = yaml.safe_load(allowlist_path.read_text(encoding="utf-8")) or {}
    connectors = data.get("connectors") or {}
    found: set[str] = set()
    for key, spec in connectors.items():
        if key == _STUB:
            continue
        hosts = spec.get("hosts", spec) if isinstance(spec, dict) else spec
        if not isinstance(hosts, list):
            continue
        for host in hosts:
            text = normalise_host(str(host))
            if text in _LOOPBACK:
                continue
            found.add(text)
    return sorted(found)


def inventory_rows() -> list[dict]:
    tickets = ROOT / "tools" / "tickets"
    if str(tickets) not in sys.path:
        sys.path.insert(0, str(tickets))
    import inventory
    import inventory_added
    import inventory_premium

    return [*inventory.CONNECTORS, *inventory_added.ADDED, *inventory_premium.PREMIUM]


def _deny_problems(raw) -> list[str]:
    if not isinstance(raw, list):
        return ["global_deny_cidrs must be a list"]
    try:
        present = {ipaddress.ip_network(str(item), strict=False) for item in raw}
    except ValueError as exc:
        return [f"global_deny_cidrs has an invalid network: {exc}"]
    floor = {ipaddress.ip_network(item) for item in FLOOR_CIDRS}
    missing = sorted(str(network) for network in floor - present)
    if missing:
        return [f"global_deny_cidrs drops floor networks: {', '.join(missing)}"]
    return []


def _expected_hosts(raw, key: str, problems: list[str]) -> set[str]:
    if not isinstance(raw, list):
        problems.append(f"{key} inventory hosts must be a list")
        return set()
    concrete: list[str] = []
    for item in raw:
        text = str(item).strip()
        if not text:
            continue
        if _unfixed(text):
            if concrete:
                problems.append(f"{key} mixes fixed hosts with an unfixed host")
            return set()
        try:
            concrete.append(normalise_host(text))
        except Exception as exc:
            problems.append(f"{key} inventory host {text!r} is not valid: {exc}")
    return set(concrete)


def _listed_hosts(spec, key: str, problems: list[str]) -> set[str] | None:
    hosts = spec.get("hosts", spec) if isinstance(spec, dict) else spec
    if isinstance(spec, list):
        hosts = spec
    if not isinstance(hosts, list):
        problems.append(f"{key} allowlist hosts must be a list")
        return None
    found = set()
    for item in hosts:
        text = str(item).strip()
        if _unfixed(text):
            problems.append(f"{key} allowlist contains an unfixed host")
            continue
        try:
            found.add(normalise_host(text))
        except Exception as exc:
            problems.append(f"{key} allowlist host {text!r} is not valid: {exc}")
    return found


def _unfixed(text: str) -> bool:
    return any(mark in text for mark in (" ", "(", ")", "`"))


if __name__ == "__main__":
    raise SystemExit(main())
