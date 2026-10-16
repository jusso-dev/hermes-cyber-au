"""Read-only NIST National Vulnerability Database CVE API."""

import json
import os
import re
from pathlib import Path
from typing import Annotated, Literal

from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import lookup, redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector
from pydantic import Field

CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HISTORY_API = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"
ATTRIBUTION = (
    "This product uses data from the NVD API but is not endorsed or certified by the NVD."
)
_PACKAGE = Path(__file__).resolve().parents[2]
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_CveId = Annotated[str, Field(pattern=r"^CVE-\d{4}-\d{4,}$")]
_TRANSPORT = None
_Date = Annotated[str, Field(pattern=r"^\d{4}-\d{2}-\d{2}$")]
_Limit = Annotated[int, Field(ge=1, le=200)]
_Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def nvd_get_cve(cve_id: _CveId) -> dict:
    if not cve_id:
        return _envelope(None, "snapshot", warnings=("cve_id is required",))
    payload, cache, warning = _fetch(CVE_API, {"cveId": cve_id}, ttl=24 * 3600)
    if warning:
        return _envelope(None, cache, warnings=(warning,))
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
    published_from: _Date | None = None,
    published_to: _Date | None = None,
    kev_only: bool = False,
    cvss_v3_severity: _Severity | None = None,
    limit: _Limit = 20,
) -> dict:
    problem = _validate_search(published_from, published_to, cvss_v3_severity, limit)
    if problem:
        return _envelope([], "snapshot", warnings=(problem,))
    params: dict[str, str] = {"resultsPerPage": str(limit)}
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
    payload, cache, warning = _fetch(CVE_API, params, ttl=3600)
    if warning:
        return _envelope([], cache, warnings=(warning,))
    if payload is None:
        return _envelope([], cache, warnings=("NVD search payload was not usable",))
    rows = []
    for item in payload.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        if "id" not in cve:
            return _envelope([], cache, warnings=("NVD schema drift, missing id",))
        if not _matches(
            cve,
            keyword=keyword,
            cpe_name=cpe_name,
            published_from=published_from,
            published_to=published_to,
            kev_only=kev_only,
            severity=cvss_v3_severity,
        ):
            continue
        rows.append(_cve(cve))
    if not rows and cache == "snapshot":
        return _envelope([], cache, payload, warnings=_miss("snapshot"))
    return _envelope(rows[:limit], cache, payload)


def nvd_cve_history(cve_id: _CveId) -> dict:
    if not _CVE.match(cve_id):
        return _envelope([], "snapshot", warnings=("cve_id is not a CVE id",))
    payload, cache, warning = _fetch(HISTORY_API, {"cveId": cve_id}, ttl=24 * 3600)
    if warning:
        return _envelope([], cache, warnings=(warning,))
    if payload is None:
        return _envelope([], cache, warnings=("NVD history payload was not usable",))
    changes = []
    for item in payload.get("cveChanges") or []:
        change = item.get("change") or item
        found = change.get("cveId")
        if found != cve_id:
            continue
        changes.append(
            {
                "cve_id": found,
                "event": change.get("eventName") or "",
                "created": change.get("created") or "",
            }
        )
    if not changes and cache == "snapshot":
        return _envelope([], cache, payload, warnings=_miss("snapshot"))
    return _envelope(changes, cache, payload)


def connector() -> Connector:
    return _NvdConnector()


class _NvdConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key="nvd",
            server_name="nvd",
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec("nvd_get_cve", "One CVE record from NVD.", nvd_get_cve),
                ToolSpec("nvd_search", "Search NVD CVEs.", nvd_search),
                ToolSpec("nvd_cve_history", "Change history for one CVE.", nvd_cve_history),
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            payload = _load(_snapshot_text())
            problem = schema_drift(payload or {})
            if problem:
                return Probe(self.key, False, problem)
            return Probe(self.key, True, "schema ok")
        if not live:
            return Probe(self.key, True, "offline ok")
        payload, _cache, warning = _fetch(
            CVE_API,
            {"cveId": "CVE-2024-3400"},
            ttl=60,
            force_live=True,
        )
        if warning:
            return Probe(self.key, False, warning)
        problem = schema_drift(payload or {})
        if problem:
            return Probe(self.key, False, problem)
        if not payload or not payload.get("vulnerabilities"):
            return Probe(self.key, False, "live probe returned no CVE")
        return Probe(self.key, True, "live ok")


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


def _fetch(
    url: str,
    params: dict,
    *,
    ttl: int,
    force_live: bool = False,
) -> tuple[dict | None, str, str]:
    snapshot = os.environ.get("CYBERAU_NVD_SNAPSHOT")
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    data_dir = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-nvd"))
    cache = HttpCache(data_dir / "http_cache.sqlite")
    cache_key = cache.key("GET", url, params, b"", "anonymous")
    if snapshot and not force_live:
        return _load(_snapshot_text()), "snapshot", ""
    cached = cache.get(cache_key)
    if cached and not force_live and (offline or cache.fresh(cached)):
        state = "hit" if cache.fresh(cached) else "stale"
        return _load(cached.body.decode("utf-8")), state, ""
    if offline:
        return _load((_PACKAGE / "data" / "cve.json").read_text(encoding="utf-8")), "snapshot", ""
    allowlist = Path(os.environ.get("CYBERAU_EGRESS_ALLOWLIST", str(_allowlist())))
    secret = lookup("NVD_API_KEY")
    burst = 50 if secret else 5
    headers = {"apiKey": secret} if secret else None
    client = HttpClient(
        "nvd",
        policy=EgressPolicy(allowlist, "nvd"),
        cache=cache,
        limiter=RateLimiter(data_dir / "rate_limit.sqlite"),
        user_agent=USER_AGENT,
        rate=burst / 30,
        burst=burst,
        window="rolling",
        timeout=60,
        transport=_TRANSPORT,
    )
    try:
        response = client.get(
            url,
            params=params,
            headers=headers,
            ttl=ttl,
            skip_cache=force_live,
        )
    except Exception as exc:
        message = redact(str(exc))
        if secret:
            message = message.replace(secret, "[REDACTED]")
        cached = cache.get(cache_key)
        if cached:
            return _load(cached.body.decode("utf-8")), "stale", ""
        return None, "snapshot", message
    finally:
        client.close()
    return _load(response.body.decode("utf-8")), response.cache, ""


def _matches(
    cve: dict,
    *,
    keyword: str | None,
    cpe_name: str | None,
    published_from: str | None,
    published_to: str | None,
    kev_only: bool,
    severity: str | None,
) -> bool:
    row = _cve(cve)
    if keyword and keyword.lower() not in row["description"].lower():
        return False
    if severity and _v3_severity(cve) != severity:
        return False
    if cpe_name and cpe_name not in json.dumps(cve.get("configurations") or []):
        return False
    published = str(cve.get("published") or "")[:10]
    if published_from and (not published or published < published_from):
        return False
    if published_to and (not published or published > published_to):
        return False
    if kev_only and not cve.get("cisaExploitAdd"):
        return False
    return True


def _v3_severity(cve: dict) -> str | None:
    entries = (cve.get("metrics") or {}).get("cvssMetricV31") or []
    if not entries:
        return None
    data = entries[0].get("cvssData") or {}
    severity = data.get("baseSeverity")
    return str(severity) if severity else None


def _validate_search(start: str | None, end: str | None, severity: str | None, limit: int) -> str:
    if start and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", start):
        return "published_from must be YYYY-MM-DD"
    if end and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", end):
        return "published_to must be YYYY-MM-DD"
    if severity and severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        return "cvss_v3_severity is not a known value"
    if not 1 <= limit <= 200:
        return "limit must be between 1 and 200"
    return ""


def _snapshot_text() -> str:
    snapshot = os.environ.get("CYBERAU_NVD_SNAPSHOT")
    path = Path(snapshot) if snapshot else _PACKAGE / "data" / "cve.json"
    return path.read_text(encoding="utf-8")


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
