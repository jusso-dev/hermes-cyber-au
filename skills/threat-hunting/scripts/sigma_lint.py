#!/usr/bin/env python3
"""Check a Sigma rule's shape and Kusto modifiers. No network and no conversion.

pySigma's Kusto backend produces KQL. This script does not. ``kql`` in the
result is always null. A modifier that is absent from the bundled support
list is treated as unsupported, and the hunt is not ready.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_SKIP_KEYS = {"condition", "timeframe"}
_LEVELS = {"informational", "low", "medium", "high", "critical"}
_STATUSES = {"experimental", "test", "stable", "deprecated", "unsupported"}


def support_path() -> Path:
    return Path(__file__).resolve().parents[1] / "references" / "kusto-support.yaml"


def load_support(path: Path) -> dict:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise TypeError("Kusto support file must be a mapping")
    supported = loaded.get("supported")
    if not isinstance(supported, list) or any(
        not isinstance(item, str) for item in supported
    ):
        raise ValueError("Kusto support file needs a supported list")
    for key in ("source_name", "version", "retrieved"):
        if not isinstance(loaded.get(key), str) or not loaded[key].strip():
            raise ValueError(f"Kusto support file needs {key}")
    return loaded


def lint_text(text: str, support: dict) -> dict:
    """Return a structured lint result. Never includes a KQL translation."""
    try:
        loaded = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return _fail([f"Sigma YAML could not be parsed: {exc}"])
    if not isinstance(loaded, dict):
        return _fail(["Sigma rule must be a mapping"])
    errors = _structure_errors(loaded)
    modifiers = _modifiers(loaded.get("detection"))
    allowed = set(support["supported"])
    unsupported = [item for item in modifiers if item not in allowed]
    for item in unsupported:
        errors.append(
            f"modifier {item} is not in the bundled Kusto support list, "
            "so it is treated as unsupported. No KQL was produced."
        )
    if unsupported:
        errors.append("The hunt is not ready.")
    return {
        "ok": not errors,
        "title": loaded.get("title") if isinstance(loaded.get("title"), str) else "",
        "id": loaded.get("id") if isinstance(loaded.get("id"), str) else "",
        "author": loaded.get("author") if isinstance(loaded.get("author"), str) else "",
        "modifiers": modifiers,
        "unsupported": unsupported,
        "errors": errors,
        "kql": None,
        "conversion": "not performed",
        "source_name": support["source_name"],
        "version": support["version"],
        "retrieved": support["retrieved"],
    }


def _fail(errors: list[str]) -> dict:
    return {
        "ok": False,
        "title": "",
        "id": "",
        "author": "",
        "modifiers": [],
        "unsupported": [],
        "errors": errors,
        "kql": None,
        "conversion": "not performed",
        "source_name": "",
        "version": "",
        "retrieved": "",
    }


def _structure_errors(rule: dict) -> list[str]:
    errors: list[str] = []
    title = rule.get("title")
    if not isinstance(title, str) or not title.strip():
        errors.append("title is required")
    author = rule.get("author")
    if not isinstance(author, str) or not author.strip():
        errors.append("author is required so attribution is kept")
    rule_id = rule.get("id")
    if not isinstance(rule_id, str) or not _UUID.fullmatch(rule_id):
        errors.append("id must be a UUID")
    logsource = rule.get("logsource")
    if not isinstance(logsource, dict) or not any(
        isinstance(logsource.get(key), str) and logsource.get(key).strip()
        for key in ("category", "product", "service")
    ):
        errors.append("logsource needs a category, product, or service")
    detection = rule.get("detection")
    condition = detection.get("condition") if isinstance(detection, dict) else None
    if not (
        isinstance(condition, str)
        or (
            isinstance(condition, list)
            and condition
            and all(isinstance(item, str) for item in condition)
        )
    ):
        errors.append("detection.condition is required")
    level = rule.get("level")
    if level is not None and level not in _LEVELS:
        errors.append("level is not a Sigma level")
    status = rule.get("status")
    if status is not None and status not in _STATUSES:
        errors.append("status is not a Sigma status")
    return errors


def _modifiers(detection: object) -> list[str]:
    found: list[str] = []
    for key in _field_keys(detection):
        found.extend(part for part in key.split("|")[1:] if part)
    return found


def _field_keys(node: object) -> list[str]:
    keys: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key not in _SKIP_KEYS and isinstance(key, str) and "|" in key:
                keys.append(key)
            keys.extend(_field_keys(value))
    elif isinstance(node, list):
        for item in node:
            keys.extend(_field_keys(item))
    return keys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Lint a Sigma rule for a Kusto hunt draft."
    )
    parser.add_argument("path", nargs="?", type=Path, help="Sigma YAML file")
    parser.add_argument("--support", type=Path, default=support_path())
    args = parser.parse_args(argv)
    try:
        text = (
            sys.stdin.read()
            if args.path is None
            else args.path.read_text(encoding="utf-8")
        )
        payload = lint_text(text, load_support(args.support))
    except (OSError, ValueError, TypeError, yaml.YAMLError) as exc:
        payload = _fail([f"sigma lint failed: {exc}"])
    json.dump(payload, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
