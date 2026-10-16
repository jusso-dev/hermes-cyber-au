"""Read-only NIST National Vulnerability Database CVE API."""

import json
import os
import re
from pathlib import Path
from typing import Annotated

from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import lookup, redact
from cyberau_common.server import Connector, ToolSpec, register_connector
from pydantic import Field

CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HISTORY_API = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"
ATTRIBUTION = (
    "This product uses data from the NVD API but is not endorsed or certified by the NVD."
)
_PACKAGE = Path(__file__).resolve().parents[2]
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_CveId = Annotated[str, Field(pattern=r"^CVE-\d{4}-\d{4,}$")]


def nvd_get_cve(cve_id: _CveId) -> dict:
    if not cve_id:
        return _envelope(None, "snapshot", warnings=("cve_id is required",))
    payload, cache = _fetch(CVE_API, {"cveId": cve_id}, ttl=24 * 3600)
    if payload is None:
        return _envelope(None, cache, warnings=("NVD CVE payload was not usable",))
    drift = schema_drift(payload)
    if drift:
        return _envelope(None, cache, warnings=(drift,))
    vulns = payload.get("vulnerabilities") or []
    if not vulns:
        return _envelope(None, cache, payload, warnings=_miss(cache))
    record = _cve(vulns[0]["cve"])
    if record["cve_id"] != cve_id:
        return _envelope(None, cache, payload, warnings=_miss("snapshot"))
    return _envelope(record, cache, payload)


def nvd_search(
    keyword: str | None = None,
    cpe_name: str | None = None,
    published_from: str | None = None,
    published_to: str | None = None,
    kev_only: bool = False,
    cvss_v3_severity: str | None = None,
    limit: int = 20,
) -> dict:
    params: dict[str, str] = {"resultsPerPage": str(min(limit, 200))}
    if keyword:
        params["keywordSearch"] = keyword
    if cpe_name:
        params["cpeName"] = cpe_name
    if published_from:
        params["pubStartDate"] = published_from + "T00:00:00.000"
    if published_to:
        params["pubEndDate"] = published_to + "T23:59:59.999"
    if kev_only:
        params["hasKev"] = "true"
    if cvss_v3_severity:
        params["cvssV3Severity"] = cvss_v3_severity
    payload, cache = _fetch(CVE_API, params, ttl=3600)
    if payload is None:
        return _envelope([], cache, warnings=("NVD search payload was not usable",))
    rows = []
    for item in payload.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        if "id" not in cve:
            return _envelope([], cache, warnings=("NVD schema drift, missing id",))
        row = _cve(cve)
        if keyword and keyword.lower() not in row["description"].lower():
            continue
        rows.append(row)
    if not rows and cache == "snapshot":
        return _envelope([], cache, payload, warnings=_miss("snapshot"))
    return _envelope(rows[:limit], cache, payload)


def nvd_cve_history(cve_id: _CveId) -> dict:
    if not _CVE.match(cve_id):
        return _envelope([], "snapshot", warnings=("cve_id is not a CVE id",))
    payload, cache = _fetch(HISTORY_API, {"cveId": cve_id}, ttl=24 * 3600)
    if payload is None:
        return _envelope([], cache, warnings=("NVD history payload was not usable",))
    changes = []
    for item in payload.get("cveChanges") or []:
        change = item.get("change") or item
        changes.append(
            {
                "cve_id": change.get("cveId") or cve_id,
                "event": change.get("eventName") or "",
                "created": change.get("created") or "",
            }
        )
    return _envelope(changes, cache, payload)


def connector() -> Connector:
    return Connector(
        key="nvd",
        server_name="nvd",
        attribution=ATTRIBUTION,
        tools=[
            ToolSpec("nvd_get_cve", "One CVE record from NVD.", nvd_get_cve),
            ToolSpec("nvd_search", "Search NVD CVEs.", nvd_search),
            ToolSpec("nvd_cve_history", "Change history for one CVE.", nvd_cve_history),
        ],
    )


def schema_drift(payload: dict) -> str | None:
    vulns = payload.get("vulnerabilities")
    if not isinstance(vulns, list):
        return "NVD payload has no vulnerabilities list"
    if not vulns:
        return None
    cve = vulns[0].get("cve") if isinstance(vulns[0], dict) else None
    if not isinstance(cve, dict) or "id" not in cve:
        return "NVD schema drift, missing id"
    return None


def _fetch(url: str, params: dict, *, ttl: int) -> tuple[dict | None, str]:
    snapshot = os.environ.get("CYBERAU_NVD_SNAPSHOT")
    if os.environ.get("CYBERAU_OFFLINE") == "1" or snapshot:
        path = Path(snapshot) if snapshot else _PACKAGE / "data" / "cve.json"
        return _load(path.read_text(encoding="utf-8")), "snapshot"
    data_dir = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-nvd"))
    allowlist = Path(os.environ.get("CYBERAU_EGRESS_ALLOWLIST", str(_allowlist())))
    key = lookup("NVD_API_KEY")
    burst = 50 if key else 5
    headers = {"apiKey": key} if key else None
    client = HttpClient(
        "nvd",
        policy=EgressPolicy(allowlist, "nvd"),
        cache=HttpCache(data_dir / "http_cache.sqlite"),
        limiter=RateLimiter(data_dir / "rate_limit.sqlite"),
        user_agent=USER_AGENT,
        rate=burst / 30,
        burst=burst,
        window="rolling",
        timeout=60,
    )
    try:
        response = client.get(url, params=params, headers=headers, ttl=ttl)
    except Exception as exc:
        message = redact(str(exc))
        if key:
            message = message.replace(key, "[REDACTED]")
        raise RuntimeError(message) from None
    finally:
        client.close()
    return _load(response.body.decode("utf-8")), response.cache


def _cve(cve: dict) -> dict:
    description = ""
    for item in cve.get("descriptions") or []:
        if item.get("lang") == "en":
            description = untrusted_text(str(item.get("value", "")), "nvd")
            break
    cvss = None
    metrics = cve.get("metrics") or {}
    for group in ("cvssMetricV40", "cvssMetricV31"):
        entries = metrics.get(group) or []
        if entries:
            data = entries[0].get("cvssData") or {}
            cvss = {
                "version": group,
                "score": data.get("baseScore"),
                "severity": data.get("baseSeverity"),
            }
            break
    cwes = []
    for weakness in cve.get("weaknesses") or []:
        for desc in weakness.get("description") or []:
            if desc.get("value"):
                cwes.append(desc["value"])
    return {
        "cve_id": cve.get("id"),
        "description": description,
        "cvss": cvss,
        "cwes": cwes,
        "references": [
            ref.get("url") for ref in cve.get("references") or [] if ref.get("url")
        ],
    }


def _miss(cache: str) -> tuple[str, ...]:
    if cache != "snapshot":
        return ()
    return ("no matching CVE in the offline snapshot or cache",)


def _envelope(
    data,
    cache: str,
    payload: dict | None = None,
    warnings: tuple[str, ...] = (),
) -> dict:
    return envelope(
        "nvd",
        data,
        urls=[CVE_API],
        cache=cache,
        data_as_of=None if payload is None else payload.get("timestamp"),
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


def _load(text: str) -> dict | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _allowlist() -> Path:
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


register_connector("nvd", connector)
