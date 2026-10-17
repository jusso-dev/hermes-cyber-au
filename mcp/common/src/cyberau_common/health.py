"""Connector health probes and schema drift reports.

Live vendor calls are refused while pytest is running. Tests pass fixtures.
A connector with no ``schema/*.response.json`` in this checkout is not checked
and is not probed.
"""

from __future__ import annotations

import importlib
import json
import os
import re
from collections.abc import Callable
from datetime import UTC, date, datetime
from pathlib import Path

from cyberau_common.secrets import redact
from cyberau_common.server import Probe, get_connector

KEYED_CONNECTORS = frozenset({"nvd", "abusech", "otx", "greynoise", "cloudflare-radar"})
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_STATUS = re.compile(r"\bstatus\s+(\d{3})\b")
_NUMERIC = re.compile(r"[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?")
_JSON_TYPES = {
    type(None): "null",
    bool: "boolean",
    int: "integer",
    float: "number",
    str: "string",
    list: "array",
    dict: "object",
}


def run_health(name: str, *, live: bool, check_schema: bool = False) -> Probe:
    try:
        connector = get_connector(name)
    except KeyError:
        return Probe(name, False, "unknown connector")
    return connector.health(live=live, check_schema=check_schema)


def default_root() -> Path:
    return Path(__file__).resolve().parents[4]


def collect_connector_health(
    root: Path | None = None,
    *,
    live: bool,
    check_schema: bool,
    fixtures: Path | None = None,
    fetcher: Callable[[str], dict] | None = None,
    today: date | None = None,
    state_path: Path | None = None,
) -> dict:
    """Build the JSON report written by ``cyberau-mcp health --all --json``."""
    checkout = root or default_root()
    stamp = today or datetime.now(UTC).date()
    saved = _read_state(state_path)
    fetch = fetcher or fetch_live
    rows: list[dict] = []
    for key, package in _connectors(checkout):
        schemas = sorted((package / "schema").glob("*.response.json"))
        if not schemas:
            rows.append(_row(key, status="not_checked", detail="not checked"))
            continue
        try:
            fetched = _response(key, live=live, fixtures=fixtures, fetcher=fetch)
        except AssertionError:
            raise
        except Exception as exc:
            rows.append(
                _finish(
                    key,
                    status="fail",
                    detail=_short(redact(str(exc)), "probe failed"),
                    error_class=type(exc).__name__,
                    saved=saved,
                    today=stamp,
                )
            )
            continue
        rows.append(
            _assess(
                key,
                fetched,
                schemas,
                check_schema=check_schema,
                saved=saved,
                today=stamp,
            )
        )
    if state_path is not None and any(row["status"] == "ok" for row in rows):
        _write_state(state_path, saved)
    return {"checked_at": stamp.isoformat(), "connectors": rows}


def fetch_live(key: str) -> dict:
    """Probe one connector. Tests never reach the network: pytest sets the guard."""
    if os.environ.get("PYTEST_CURRENT_TEST"):
        raise RuntimeError("refusing to probe a vendor host from tests")
    return _fetch_live_unchecked(key)


def diff_response(schema: dict, payload: object) -> list[dict] | None:
    """Compare one payload with a stored response schema.

    Returns ``None`` when the payload has an empty record list, a list of
    changes otherwise. A numeric string satisfies ``number`` so decimal fields
    published as text are not treated as drift.
    """
    nodes = _subject_nodes(schema, payload)
    if nodes is None:
        return None
    changes: list[dict] = []
    for prefix, node in nodes:
        _walk(schema, node, prefix, changes)
    return changes[:30]


def _connectors(root: Path) -> list[tuple[str, Path]]:
    mcp = root / "mcp"
    found = []
    if not mcp.is_dir():
        return found
    for path in sorted(mcp.iterdir()):
        if not path.is_dir() or path.name == "common" or path.name.startswith("."):
            continue
        if (path / "pyproject.toml").is_file():
            found.append((path.name, path))
    return found


def _response(
    key: str,
    *,
    live: bool,
    fixtures: Path | None,
    fetcher: Callable[[str], dict],
) -> dict:
    if fixtures is not None:
        path = fixtures / f"{key}.json"
        if path.is_file():
            return _load_fixture(path)
    if not live:
        return {
            "ok": False,
            "status_code": None,
            "error_class": "no_fixture",
            "body": None,
            "detail": "no fixture response",
        }
    return fetcher(key)


def _load_fixture(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if (
        isinstance(data, dict)
        and "body" in data
        and ("status_code" in data or "error_class" in data or "ok" in data)
    ):
        return data
    return {
        "ok": True,
        "status_code": 200,
        "error_class": None,
        "body": data,
        "detail": "fixture",
    }


def _assess(
    key: str,
    fetched: dict,
    schemas: list[Path],
    *,
    check_schema: bool,
    saved: dict,
    today: date,
) -> dict:
    detail = _short(str(fetched.get("detail") or ""), "")
    code = fetched.get("status_code")
    if code is None:
        code = status_code_from_text(detail)
    if code is not None and not isinstance(code, int):
        code = None
    error = fetched.get("error_class")
    if error is not None and not isinstance(error, str):
        error = None
    body = fetched.get("body")
    if code is not None and code >= 400:
        return _finish(
            key,
            status="fail",
            detail=detail or f"upstream status {code}",
            status_code=code,
            error_class=error or classify_error(code, detail),
            saved=saved,
            today=today,
        )
    if error in {"timeout", "auth", "rate_limit", "http_error", "no_fixture"} and body is None:
        return _finish(
            key,
            status="fail",
            detail=detail or error,
            status_code=code,
            error_class=error,
            saved=saved,
            today=today,
        )
    if body is None:
        ok = bool(fetched.get("ok"))
        return _finish(
            key,
            status="ok" if ok else "fail",
            detail=detail or ("live ok" if ok else "no response"),
            status_code=code if code is not None else (200 if ok else None),
            error_class=None if ok else (error or "no_response"),
            saved=saved,
            today=today,
        )
    if not check_schema:
        return _finish(
            key,
            status="ok",
            detail=detail or "fixture",
            status_code=code if code is not None else 200,
            saved=saved,
            today=today,
        )
    changes: list[dict] = []
    empty = True
    for schema_path in schemas:
        try:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return _finish(
                key,
                status="fail",
                detail="schema file is not valid JSON",
                status_code=code,
                error_class="schema_drift",
                saved=saved,
                today=today,
            )
        if not isinstance(schema, dict):
            continue
        found = diff_response(schema, body)
        if found is None:
            continue
        empty = False
        for item in found:
            item["schema"] = schema_path.name
            changes.append(item)
    if changes:
        return _finish(
            key,
            status="fail",
            detail="schema drift",
            status_code=code if code is not None else 200,
            error_class="schema_drift",
            schema_diff=changes[:30],
            saved=saved,
            today=today,
        )
    return _finish(
        key,
        status="ok",
        detail="no records" if empty else "schema ok",
        status_code=code if code is not None else 200,
        saved=saved,
        today=today,
    )


def _finish(
    key: str,
    *,
    status: str,
    detail: str,
    saved: dict,
    today: date,
    status_code: int | None = None,
    error_class: str | None = None,
    schema_diff: list | None = None,
) -> dict:
    if status == "ok":
        last_good = today.isoformat()
        saved[key] = last_good
    elif status == "fail":
        last_good = _known_date(saved.get(key))
    else:
        last_good = None
    return _row(
        key,
        status=status,
        detail=detail,
        status_code=status_code,
        error_class=error_class,
        schema_diff=schema_diff,
        last_good=last_good,
    )


def _row(
    key: str,
    *,
    status: str,
    detail: str,
    status_code: int | None = None,
    error_class: str | None = None,
    schema_diff: list | None = None,
    last_good: str | None = None,
) -> dict:
    return {
        "key": key,
        "status": status,
        "status_code": status_code,
        "error_class": error_class,
        "schema_diff": schema_diff or [],
        "last_good": last_good,
        "detail": detail,
        "keyed": key in KEYED_CONNECTORS,
    }


def _fetch_live_unchecked(key: str) -> dict:
    module_name = f"cyberau_{key.replace('-', '_')}.source"
    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError:
        return {
            "ok": False,
            "status_code": None,
            "error_class": "unknown_connector",
            "body": None,
            "detail": "unknown connector",
        }
    loader = getattr(module, "health_response", None)
    if callable(loader):
        raw = loader()
        if isinstance(raw, dict):
            return raw
    probe = run_health(key, live=True, check_schema=True)
    code = status_code_from_text(probe.detail)
    if probe.ok:
        return {
            "ok": True,
            "status_code": code or 200,
            "error_class": None,
            "body": None,
            "detail": probe.detail,
        }
    return {
        "ok": False,
        "status_code": code,
        "error_class": classify_error(code, probe.detail),
        "body": None,
        "detail": probe.detail,
    }


def status_code_from_text(detail: str) -> int | None:
    match = _STATUS.search(detail)
    if not match:
        return None
    return int(match.group(1))


def classify_error(status: int | None, detail: str) -> str:
    text = detail.lower()
    denied = "unauthorised" in text or "unauthorized" in text or "forbidden" in text
    if status in {401, 403} or denied:
        return "auth"
    if status == 429:
        return "rate_limit"
    if status in {408, 504} or "timed out" in text or "timeout" in text:
        return "timeout"
    return "http_error"


def _subject_nodes(schema: dict, payload: object) -> list[tuple[str, object]] | None:
    props = set(schema.get("properties") or {})
    if isinstance(payload, dict) and (not props or props & set(payload)):
        return [("", payload)]
    if isinstance(payload, dict):
        for key, value in payload.items():
            if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
                continue
            if not value:
                return None
            return [(f"{key}.0", value[0])]
    if isinstance(payload, list):
        if not payload:
            return None
        return [("0", payload[0])]
    return [("", payload)]


def _walk(schema: dict, instance: object, prefix: str, out: list[dict]) -> None:
    if len(out) >= 30 or not isinstance(schema, dict):
        return
    expected = schema.get("type")
    if expected is not None and not _type_ok(expected, instance):
        origin = expected if isinstance(expected, str) else "/".join(str(part) for part in expected)
        out.append(
            {
                "change": "type_changed",
                "field": prefix or "$",
                "from": origin,
                "to": _json_type(instance),
            }
        )
        return
    if isinstance(instance, dict) and (expected == "object" or "properties" in schema):
        props = schema.get("properties") or {}
        required = set(schema.get("required") or [])
        for name, sub in props.items():
            field = f"{prefix}.{name}" if prefix else str(name)
            if name not in instance:
                if name in required:
                    out.append({"change": "removed", "field": field})
                continue
            if isinstance(sub, dict):
                _walk(sub, instance[name], field, out)
        for name in instance:
            if name not in props:
                field = f"{prefix}.{name}" if prefix else str(name)
                out.append({"change": "added", "field": field})
        return
    if isinstance(instance, list) and expected == "array" and isinstance(schema.get("items"), dict):
        for index, item in enumerate(instance[:5]):
            field = f"{prefix}.{index}" if prefix else str(index)
            _walk(schema["items"], item, field, out)


def _type_ok(expected: object, value: object) -> bool:
    if isinstance(expected, list):
        return any(_type_ok(item, value) for item in expected)
    if not isinstance(expected, str):
        return True
    actual = _json_type(value)
    if expected == "number" and (actual in {"number", "integer"} or _numeric_string(value)):
        return True
    if expected == "integer" and (actual == "integer" or _integer_string(value)):
        return True
    return actual == expected


def _json_type(value: object) -> str:
    if isinstance(value, bool):
        return "boolean"
    return _JSON_TYPES.get(type(value), "unknown")


def _numeric_string(value: object) -> bool:
    return isinstance(value, str) and bool(_NUMERIC.fullmatch(value.strip()))


def _integer_string(value: object) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[+-]?\d+", value.strip()))


def _short(detail: str, fallback: str) -> str:
    text = detail.strip()
    if not text or len(text) > 160 or "\n" in text:
        return fallback
    return text


def _known_date(value: object) -> str | None:
    if isinstance(value, str) and _DATE.fullmatch(value):
        return value
    return None


def _read_state(path: Path | None) -> dict:
    if path is None or not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(key): value for key, value in data.items() if _known_date(value)}


def _write_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
