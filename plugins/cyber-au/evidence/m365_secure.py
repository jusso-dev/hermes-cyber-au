"""Read-only parser for M365-Secure JSON assessment reports.

Not an MCP server. The user runs m365-assess and passes the local report path.
The report shape is schema 1.1 from jusso-dev/M365-Secure commit
9fae976a0acfda3f55795013d7f78739c86a94a9.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path

import jsonschema
from cyberau_common.envelope import envelope, untrusted_text

SOURCE = "m365-secure"
ATTRIBUTION = (
    "M365-Secure assessment report (m365-assess), MIT licence, "
    "https://github.com/jusso-dev/M365-Secure. "
    "This parser does not call Microsoft and is not endorsed by Microsoft."
)
TOOL_NAME = "evidence_import"
ANNOTATIONS = {"readOnlyHint": True, "openWorldHint": True}

_SCHEMA_PATH = Path(__file__).resolve().parent / "schema" / "m365_secure_report.schema.json"
_SCHEMA: dict | None = None
_STATUS_LABELS = {
    "pass": "Pass",
    "fail": "Fail",
    "warning": "Warning",
    "review": "Review",
    "info": "Info",
    "unknown": "Unknown",
    "notlicensed": "Not Licensed",
}
_FREE_TEXT = (
    "category",
    "section",
    "setting",
    "description",
    "current_value",
    "expected_value",
    "remediation",
)


def evidence_import(path: str) -> dict:
    """Import an M365-Secure JSON report as assessment evidence."""
    if not isinstance(path, str) or path.strip() == "":
        return _warn("path is required")
    if "://" in path:
        return _warn("path must be a local JSON report, not a URL")
    file_path = Path(path).expanduser()
    if not file_path.is_file():
        if os.environ.get("CYBERAU_OFFLINE") == "1" and not file_path.exists():
            return _warn("unavailable: M365-Secure report file was not found")
        if file_path.exists():
            return _warn("M365-Secure report path is not a file")
        return _warn("M365-Secure report file was not found")
    try:
        text = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return _warn("M365-Secure report could not be read")
    try:
        payload = json.loads(text, parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        return _warn("M365-Secure report was not valid JSON")
    try:
        problem = schema_drift(payload)
        if problem:
            return _warn(problem)
        data = _normalise(payload)
    except RecursionError:
        return _warn("M365-Secure report is nested too deeply to import")
    return envelope(
        SOURCE,
        data,
        cache="snapshot",
        data_as_of=payload["summary"]["timestamp"],
        attribution=ATTRIBUTION,
    )


def _reject_constant(name: str):
    raise ValueError(f"{name} is not valid JSON")


def schema_drift(payload: object) -> str | None:
    """Return a warning when the report does not match schema 1.1."""
    if not isinstance(payload, dict):
        return "M365-Secure report was not a JSON object"
    errors = list(jsonschema.Draft202012Validator(_report_schema()).iter_errors(payload))
    if errors:
        required = [error for error in errors if error.validator == "required"]
        return f"M365-Secure schema drift, {_describe(required[0] if required else errors[0])}"
    return _inconsistent(payload)


def _inconsistent(payload: dict) -> str | None:
    """Catch a report that is valid JSON but whose summary disagrees with its findings."""
    findings = payload["findings"]
    summary = payload["summary"]
    statuses = Counter(_STATUS_LABELS[item["status"]] for item in findings)
    severities = Counter(item["severity"].capitalize() for item in findings)
    if (
        summary["total_checks"] != len(findings)
        or {k: v for k, v in summary["status_counts"].items() if v} != dict(statuses)
        or {k: v for k, v in summary["severity_counts"].items() if v} != dict(severities)
    ):
        return "M365-Secure report is incomplete, summary counts do not match the findings"
    return None


def _describe(error: jsonschema.ValidationError) -> str:
    """Describe a schema error from the schema's own path, never from report text."""
    rule = [str(part) for part in error.absolute_schema_path]
    where = ".".join(part for part in rule if part not in {"properties", "items", "$ref", "$defs"})
    indexes = "".join(f"[{part}]" for part in error.absolute_path if isinstance(part, int))
    if error.validator == "required":
        missing = [name for name in error.validator_value if name not in error.instance]
        return f"missing required field {missing[0]!r} in {where or 'report'}{indexes}"
    return f"{error.validator} check failed at {where}{indexes}"


def _report_schema() -> dict:
    global _SCHEMA
    if _SCHEMA is None:
        _SCHEMA = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    return _SCHEMA


def _warn(message: str) -> dict:
    return envelope(
        SOURCE,
        {"records": []},
        cache="snapshot",
        warnings=(message,),
        attribution=ATTRIBUTION,
    )


def _normalise(payload: dict) -> dict:
    summary = payload["summary"]
    tenant = summary["tenant"]
    records = [_record(item) for item in payload["findings"]]
    return {
        "schema_version": payload["schema_version"],
        "tool": {
            "name": payload["tool"]["name"],
            "version": payload["tool"]["version"],
        },
        "summary": {
            "tenant_id": tenant["tenant_id"],
            "display_name": untrusted_text(tenant["display_name"], SOURCE),
            "primary_domain": tenant["primary_domain"],
            "verified_domains": list(tenant["verified_domains"]),
            "license_skus": list(tenant["license_skus"]),
            "timestamp": summary["timestamp"],
            "duration_seconds": summary["duration_seconds"],
            "total_checks": summary["total_checks"],
            "status_counts": dict(summary["status_counts"]),
            "severity_counts": dict(summary["severity_counts"]),
            "score": summary["score"],
            "modules_run": list(summary["modules_run"]),
            "modules_failed": list(summary["modules_failed"]),
        },
        "records": records,
        "compliance": [_compliance(item) for item in payload["compliance"]],
    }


def _record(finding: dict) -> dict:
    mappings = _mappings(finding["framework_mappings"])
    record = {
        "check_id": finding["check_id"],
        "status": finding["status"],
        "severity": finding["severity"],
        "timestamp": finding["timestamp"],
        "framework_mappings": mappings,
        "essential_eight": list(mappings.get("essential_eight") or []),
        "affected_resources": [
            untrusted_text(item, SOURCE) for item in finding.get("affected_resources") or []
        ],
    }
    for name in _FREE_TEXT:
        record[name] = untrusted_text(finding[name], SOURCE)
    if "details" in finding and finding["details"] is not None:
        record["details"] = _wrap_json(finding["details"])
    return record


def _mappings(raw: dict) -> dict:
    cleaned: dict = {}
    for key, value in raw.items():
        if key == "other" and isinstance(value, dict):
            cleaned[key] = {name: list(ids) for name, ids in value.items()}
        elif isinstance(value, list):
            cleaned[key] = list(value)
    return cleaned


def _compliance(item: dict) -> dict:
    return {
        "framework_id": item["framework_id"],
        "framework_name": untrusted_text(item["framework_name"], SOURCE),
        "total_controls": item["total_controls"],
        "assessed_controls": item["assessed_controls"],
        "passing_controls": item["passing_controls"],
        "failing_controls": item["failing_controls"],
        "pass_rate": item["pass_rate"],
        "control_results": [_control(row) for row in item["control_results"]],
    }


def _control(item: dict) -> dict:
    return {
        "control_id": item["control_id"],
        "control_name": untrusted_text(item["control_name"], SOURCE),
        "section": untrusted_text(item["section"], SOURCE),
        "status": item["status"],
        "mapped_checks": list(item["mapped_checks"]),
        "check_statuses": [
            {
                "check_id": row["check_id"],
                "status": row["status"],
                "setting": untrusted_text(row["setting"], SOURCE),
            }
            for row in item["check_statuses"]
        ],
    }


def _wrap_json(value):
    if isinstance(value, str):
        return untrusted_text(value, SOURCE)
    if isinstance(value, list):
        return [_wrap_json(item) for item in value]
    if isinstance(value, dict):
        return {key: _wrap_json(item) for key, item in value.items()}
    return value
