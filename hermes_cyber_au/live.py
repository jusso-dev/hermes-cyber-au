"""Optional read-only live queries. Off until every required setting is present.

Every accepted query is appended to a local audit log. Write verbs never leave
this process. Secrets are not written to the log.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .common import data_home, sha256_text
from .querycheck import check_query

SENTINEL_ENV = (
    "CYBER_AU_SENTINEL_TENANT_ID",
    "CYBER_AU_SENTINEL_CLIENT_ID",
    "CYBER_AU_SENTINEL_CLIENT_SECRET",
    "CYBER_AU_SENTINEL_WORKSPACE_ID",
)
AWS_ENV = (
    "CYBER_AU_AWS_REGION",
)


def _configured(names: tuple[str, ...]) -> bool:
    return all(os.environ.get(name, "").strip() for name in names)


def status() -> dict[str, Any]:
    return {
        "sentinel": "configured" if _configured(SENTINEL_ENV) else "off",
        "aws": "configured" if os.environ.get("CYBER_AU_AWS_REGION", "").strip() else "off",
        "mode": "read_only",
    }


def _audit(kind: str, query: str, outcome: str, home: Path | None = None) -> None:
    root = home or data_home()
    path = root / "audit" / "queries.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    row = {
        "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "kind": kind,
        "query_sha256": sha256_text(query),
        "query": query[:4000],
        "outcome": outcome,
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def _redact(query: str) -> str:
    secret = os.environ.get("CYBER_AU_SENTINEL_CLIENT_SECRET", "")
    if secret and secret in query:
        return query.replace(secret, "[redacted]")
    return query


def sentinel_query(query: str) -> dict[str, Any]:
    """Read-only Log Analytics query. No other Azure API is called."""
    import urllib.parse
    import urllib.request

    from .fetch import USER_AGENT

    tenant = os.environ["CYBER_AU_SENTINEL_TENANT_ID"]
    workspace = os.environ["CYBER_AU_SENTINEL_WORKSPACE_ID"]
    token_url = f"https://login.microsoftonline.com/{urllib.parse.quote(tenant)}/oauth2/v2.0/token"
    form = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "client_id": os.environ["CYBER_AU_SENTINEL_CLIENT_ID"],
            "client_secret": os.environ["CYBER_AU_SENTINEL_CLIENT_SECRET"],
            "scope": "https://api.loganalytics.io/.default",
        }
    ).encode()
    # Token host is fixed. The knowledge allowlist does not apply to this operator call.
    request = urllib.request.Request(
        token_url,
        data=form,
        headers={"User-Agent": USER_AGENT, "Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    import ssl

    with urllib.request.urlopen(request, timeout=30, context=ssl.create_default_context()) as response:
        token = json.loads(response.read().decode("utf-8"))["access_token"]
    query_url = f"https://api.loganalytics.io/v1/workspaces/{urllib.parse.quote(workspace)}/query"
    body = json.dumps({"query": query}).encode()
    call = urllib.request.Request(
        query_url,
        data=body,
        headers={"User-Agent": USER_AGENT, "Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(call, timeout=60, context=ssl.create_default_context()) as response:
        payload = json.loads(response.read().decode("utf-8"))
    del token
    tables = payload.get("tables") or []
    rows = len(tables[0].get("rows") or []) if tables else 0
    return {"row_count": rows, "tables": tables[:1]}


def _boto_client(service: str):
    region = os.environ["CYBER_AU_AWS_REGION"]
    if not __import__("re").fullmatch(r"[a-z]{2}-[a-z]+-\d", region):
        raise ValueError("CYBER_AU_AWS_REGION is not a region name")
    import boto3

    profile = os.environ.get("CYBER_AU_AWS_PROFILE") or None
    session = boto3.Session(profile_name=profile, region_name=region)
    return session.client(service)


def logs_insights(query: str) -> dict[str, Any]:
    import time

    group = os.environ.get("CYBER_AU_LOG_GROUP", "")
    if not group:
        raise ValueError("CYBER_AU_LOG_GROUP is not set")
    client = _boto_client("logs")
    started = client.start_query(logGroupName=group, startTime=int(time.time()) - 86400, endTime=int(time.time()), queryString=query)
    query_id = started["queryId"]
    for _ in range(5):
        result = client.get_query_results(queryId=query_id)
        if result.get("status") in {"Complete", "Failed", "Cancelled", "Timeout"}:
            return {"query_id": query_id, "status": result.get("status"), "rows": len(result.get("results") or [])}
        time.sleep(1)
    return {"query_id": query_id, "status": "Running", "rows": 0}


def cloudtrail_lake(query: str) -> dict[str, Any]:
    import time

    client = _boto_client("cloudtrail")
    started = client.start_query(QueryStatement=query)
    query_id = started["QueryId"]
    for _ in range(5):
        result = client.get_query_results(QueryId=query_id, MaxQueryResults=20)
        status = result.get("QueryStatus")
        if status in {"FINISHED", "FAILED", "CANCELLED", "TIMED_OUT"}:
            return {"query_id": query_id, "status": status, "rows": len(result.get("QueryResultRows") or [])}
        time.sleep(1)
    return {"query_id": query_id, "status": "RUNNING", "rows": 0}


def _default_transport(kind: str, query: str) -> dict[str, Any]:
    if kind == "sentinel":
        return sentinel_query(query)
    if kind == "logs_insights":
        return logs_insights(query)
    if kind == "cloudtrail_lake":
        return cloudtrail_lake(query)
    raise ValueError(kind)


def live_query(kind: str, query: str, *, home: Path | None = None, transport: Any = None) -> dict[str, Any]:
    """Run a read-only query if configured. `transport` is a test double."""
    language = {"sentinel": "kql", "logs_insights": "logs_insights", "cloudtrail_lake": "sql"}.get(kind)
    if language is None:
        return {"ok": False, "error": "unknown live kind", "executed": False}
    safe_query = _redact(query)
    checked = check_query(language, query)
    if not checked["ready"]:
        _audit(kind, safe_query, "refused_not_ready", home)
        return {"ok": False, "executed": False, "check": checked}
    if kind == "sentinel" and not _configured(SENTINEL_ENV):
        _audit(kind, safe_query, "off", home)
        return {"ok": False, "executed": False, "error": "sentinel live queries are off until the read-only service principal is configured"}
    if kind in {"logs_insights", "cloudtrail_lake"} and not os.environ.get("CYBER_AU_AWS_REGION", "").strip():
        _audit(kind, safe_query, "off", home)
        return {"ok": False, "executed": False, "error": "aws live queries are off until CYBER_AU_AWS_REGION and a read-only role are configured"}
    runner = transport or _default_transport
    try:
        result = runner(kind, query)
    except Exception as exc:  # surface the failure, keep the last good local state
        _audit(kind, safe_query, f"error:{type(exc).__name__}", home)
        return {"ok": False, "executed": False, "error": type(exc).__name__, "check": checked}
    _audit(kind, safe_query, "executed_read", home)
    return {"ok": True, "executed": True, "read_only": True, "result": result, "check": checked}
