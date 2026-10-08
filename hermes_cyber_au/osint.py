"""Optional indicator lookups. Off until a key is set. Read-only HTTP only."""

from __future__ import annotations

import json
import os
import re
from typing import Any
from urllib.parse import quote

from .fetch import USER_AGENT, FetchError, fetch_url

_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_HOSTS = {
    "urlhaus-api.abuse.ch",
    "threatfox-api.abuse.ch",
    "api.abuseipdb.com",
    "api.greynoise.io",
    "otx.alienvault.com",
}


def status() -> dict[str, str]:
    keys = {
        "abuseipdb": "CYBER_AU_ABUSEIPDB_KEY",
        "greynoise": "CYBER_AU_GREYNOISE_KEY",
        "otx": "CYBER_AU_OTX_KEY",
        "abusech": "CYBER_AU_ABUSECH_KEY",
    }
    return {name: "configured" if os.environ.get(env, "").strip() else "off" for name, env in keys.items()}


def lookup(indicator: str, *, transport: Any = None) -> dict[str, Any]:
    """Look up one indicator. `transport` is a test double and is not a network call."""
    indicator = (indicator or "").strip()
    if not indicator or len(indicator) > 200:
        return {"ok": False, "executed": False, "error": "indicator is missing or too long"}
    configured = {name for name, state in status().items() if state == "configured"}
    if not configured:
        return {
            "ok": False,
            "executed": False,
            "error": "OSINT lookups are off until a key is configured",
            "providers": status(),
        }
    if transport is not None:
        return {"ok": True, "executed": True, "read_only": True, "result": transport(indicator, sorted(configured))}
    results = {}
    errors = {}
    if "abuseipdb" in configured and _IPV4.match(indicator):
        results["abuseipdb"], errors["abuseipdb"] = _get(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={quote(indicator)}&maxAgeInDays=90",
            {"Key": os.environ["CYBER_AU_ABUSEIPDB_KEY"], "Accept": "application/json"},
            indicator,
        )
    if "greynoise" in configured and _IPV4.match(indicator):
        results["greynoise"], errors["greynoise"] = _get(
            f"https://api.greynoise.io/v3/community/{indicator}",
            {"key": os.environ["CYBER_AU_GREYNOISE_KEY"], "Accept": "application/json"},
            indicator,
        )
    if "otx" in configured:
        kind = "IPv4" if _IPV4.match(indicator) else "domain"
        results["otx"], errors["otx"] = _get(
            f"https://otx.alienvault.com/api/v1/indicators/{kind}/{quote(indicator, safe='')}/general",
            {"X-OTX-API-KEY": os.environ["CYBER_AU_OTX_KEY"], "Accept": "application/json"},
            indicator,
        )
    if "abusech" in configured:
        results["abusech"], errors["abusech"] = _post_abusech(indicator)
    clean = {key: value for key, value in results.items() if value is not None}
    return {
        "ok": bool(clean),
        "executed": True,
        "read_only": True,
        "providers": status(),
        "result": clean,
        "errors": {key: value for key, value in errors.items() if value},
        "instructions": "data_only",
    }


def _get(url: str, headers: dict[str, str], indicator: str) -> tuple[dict | None, str]:
    try:
        fetched = fetch_url(url, _HOSTS, timeout=20, headers=headers)
    except FetchError as exc:
        return None, exc.code
    try:
        payload = fetched.json()
    except json.JSONDecodeError:
        return None, "shape"
    if not isinstance(payload, dict):
        return None, "shape"
    payload.pop("email", None)
    return {"indicator": indicator, "status": fetched.status, "body": _trim(payload)}, ""


def _post_abusech(indicator: str) -> tuple[dict | None, str]:
    import urllib.request

    url = "https://threatfox-api.abuse.ch/api/v1/"
    body = json.dumps({"query": "search_ioc", "search_term": indicator}).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "User-Agent": USER_AGENT,
            "Auth-Key": os.environ["CYBER_AU_ABUSECH_KEY"],
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        import ssl

        with urllib.request.urlopen(request, timeout=20, context=ssl.create_default_context()) as response:
            payload = json.loads(response.read(1_000_000).decode("utf-8", errors="replace"))
    except Exception as exc:
        return None, type(exc).__name__
    if not isinstance(payload, dict):
        return None, "shape"
    return {"indicator": indicator, "query_status": payload.get("query_status"), "body": _trim(payload)}, ""


def _trim(payload: dict) -> dict:
    text = json.dumps(payload)[:2000]
    return {"preview": text, "instructions": "data_only"}
