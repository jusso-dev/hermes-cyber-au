"""Read-only FIRST EPSS scores."""

import json
import os
import re
from pathlib import Path
from typing import Annotated

from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressDenied, EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient, HttpError
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector
from pydantic import Field

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_CveId = Annotated[str, Field(pattern=r"^CVE-\d{4}-\d{4,}$")]
_CveList = Annotated[list[_CveId], Field(min_length=1, max_length=100)]
_Score = Annotated[float, Field(ge=0, le=1)]
_Limit = Annotated[int, Field(ge=1, le=500)]
_TRANSPORT = None

API = "https://api.first.org/data/v1/epss"
ATTRIBUTION = "FIRST EPSS. Cite the model version and the score date."
REQUIRED = ("cve", "epss", "percentile", "date")
_PACKAGE = Path(__file__).resolve().parents[2]


def epss_scores(
    cve_ids: _CveList,
    date: Annotated[str, Field(pattern=r"^\d{4}-\d{2}-\d{2}$")] | None = None,
) -> dict:
    if not cve_ids:
        return _envelope([], "snapshot", warnings=("cve_ids is required",))
    if len(cve_ids) > 100:
        return _envelope(
            [],
            "snapshot",
            warnings=("batch at most 100 CVEs; use the bulk file above that",),
        )
    problem = _validate_scores(cve_ids, date)
    if problem:
        return _envelope([], "snapshot", warnings=(problem,))
    params = {"cve": ",".join(cve_ids or [])}
    if date:
        params["date"] = date
    payload, cache, warning = _fetch(params)
    if warning:
        return _envelope([], cache, warnings=(warning,))
    if payload is None:
        return _envelope([], cache, warnings=("EPSS response was not usable",))
    rows, warnings = _rows(payload, history=False)
    rows = _select(rows, cves=set(cve_ids or []), on=date)
    if not rows and cache == "snapshot":
        warnings.append("no matching score in the offline snapshot or cache")
    _persist(rows)
    return _envelope(rows, cache, payload, warnings=tuple(warnings))


def epss_history(cve_id: _CveId) -> dict:
    if not cve_id:
        return _envelope([], "snapshot", warnings=("cve_id is required",))
    if not _CVE.match(cve_id):
        return _envelope([], "snapshot", warnings=("cve_id is not a CVE id",))
    payload, cache, warning = _fetch({"cve": cve_id, "scope": "time-series"})
    if warning:
        return _envelope([], cache, warnings=(warning,))
    if payload is None:
        return _envelope([], cache, warnings=("EPSS history was not usable",))
    rows, warnings = _rows(payload, history=True)
    rows = [row for row in rows if row["cve"] == cve_id]
    rows = sorted(rows, key=lambda row: row["date"])[-30:]
    if not rows and cache == "snapshot":
        warnings.append("no matching history in the offline snapshot or cache")
    _persist(rows)
    return _envelope(rows, cache, payload, warnings=tuple(warnings))


def epss_top(min_epss: _Score = 0.5, limit: _Limit = 50) -> dict:
    problem = _validate_top(min_epss, limit)
    if problem:
        return _envelope([], "snapshot", warnings=(problem,))
    params = {"epss-gt": str(min_epss), "order": "!epss", "limit": str(limit)}
    payload, cache, warning = _fetch(params)
    if warning:
        return _envelope([], cache, warnings=(warning,))
    if payload is None:
        return _envelope([], cache, warnings=("EPSS top list was not usable",))
    rows, warnings = _rows(payload, history=False)
    rows = _select(rows, min_epss=min_epss)
    rows = sorted(rows, key=lambda row: row["epss"], reverse=True)[:limit]
    if not rows and cache == "snapshot":
        warnings.append("no score above the threshold in the offline snapshot or cache")
    _persist(rows)
    return _envelope(rows, cache, payload, warnings=tuple(warnings))


def connector() -> Connector:
    return _EpssConnector()


class _EpssConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key="first-epss",
            server_name="epss",
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec("epss_scores", "Score and percentile for up to 100 CVEs.", epss_scores),
                ToolSpec("epss_history", "Daily scores for one CVE, last 30 points.", epss_history),
                ToolSpec("epss_top", "CVEs above a score threshold.", epss_top),
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            payload, _state = _load(_snapshot_text())
            problem = schema_drift(payload or {})
            if problem:
                return Probe(self.key, False, problem)
            return Probe(self.key, True, "schema ok")
        if not live:
            return Probe(self.key, True, "offline ok")
        try:
            payload, _cache, warning = _fetch({"cve": "CVE-2024-3400"}, force_live=True)
        except HttpError as exc:
            return Probe(self.key, False, str(exc))
        if warning:
            return Probe(self.key, False, warning)
        problem = schema_drift(payload or {})
        if problem:
            return Probe(self.key, False, problem)
        if payload is None or not payload.get("data"):
            return Probe(self.key, False, "live probe returned no scores")
        return Probe(self.key, True, "live ok")


def schema_drift(payload: dict) -> str | None:
    rows = payload.get("data")
    if not isinstance(rows, list):
        return "EPSS payload has no data list"
    if not rows:
        return None
    missing = [name for name in REQUIRED if name not in rows[0]]
    if missing:
        return "EPSS schema drift, missing " + ", ".join(missing)
    return None


def _fetch(params: dict, *, force_live: bool = False) -> tuple[dict | None, str, str]:
    snapshot = os.environ.get("CYBERAU_EPSS_SNAPSHOT")
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    data_dir = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-epss"))
    cache = HttpCache(data_dir / "http_cache.sqlite")
    key = cache.key("GET", API, params, b"", "anonymous")
    if not force_live and not snapshot:
        cached = cache.get(key)
        if cached and (offline or cache.fresh(cached)):
            payload, _state = _load(cached.body.decode("utf-8"))
            state = "hit" if cache.fresh(cached) else "stale"
            return payload, state, ""
    if offline or (snapshot and not force_live):
        payload, _state = _load(_snapshot_text())
        return payload, "snapshot", ""
    allowlist = Path(os.environ.get("CYBERAU_EGRESS_ALLOWLIST", str(_allowlist())))
    client = HttpClient(
        "first-epss",
        policy=EgressPolicy(allowlist, "first-epss"),
        cache=cache,
        limiter=RateLimiter(data_dir / "rate_limit.sqlite"),
        user_agent=USER_AGENT,
        rate=1000 / 60,
        burst=50,
        window="rolling",
        transport=_TRANSPORT,
    )
    try:
        response = client.get(API, params=params, ttl=12 * 3600)
    except (HttpError, EgressDenied, TimeoutError) as exc:
        cached = cache.get(key)
        if cached:
            payload, _state = _load(cached.body.decode("utf-8"))
            return payload, "stale", ""
        return None, "snapshot", redact(str(exc))
    finally:
        client.close()
    payload, _state = _load(response.body.decode("utf-8"))
    return payload, response.cache, ""


def _load(text: str) -> tuple[dict | None, str]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None, "snapshot"
    if not isinstance(payload, dict):
        return None, "snapshot"
    return payload, "snapshot"


def _rows(payload: dict, *, history: bool) -> tuple[list[dict], list[str]]:
    drift = schema_drift(payload)
    if drift:
        return [], [drift]
    model = str(payload.get("version", ""))
    rows = []
    seen: set[tuple[str, str]] = set()
    for item in payload["data"]:
        points = [_point(item, model)]
        if history:
            for older in item.get("time-series") or []:
                points.append(_point({**item, **older}, model))
        for row in points:
            identity = (row["cve"], row["date"])
            if identity in seen:
                continue
            seen.add(identity)
            rows.append(row)
    return rows, []


def _point(item: dict, model: str) -> dict:
    return {
        "cve": item["cve"],
        "epss": float(item["epss"]),
        "percentile": float(item["percentile"]),
        "date": item["date"],
        "model": model,
        "note": _note(item),
    }


def _select(
    rows,
    *,
    cves: set[str] | None = None,
    on: str | None = None,
    min_epss: float | None = None,
):
    chosen = []
    for row in rows:
        if cves and row["cve"] not in cves:
            continue
        if on and row["date"] != on:
            continue
        if min_epss is not None and row["epss"] <= min_epss:
            continue
        chosen.append(row)
    return chosen


def _validate_scores(cve_ids: list[str] | None, on: str | None) -> str:
    if not cve_ids:
        return "cve_ids is required"
    if len(cve_ids) > 100:
        return "batch at most 100 CVEs; use the bulk file above that"
    if any(_CVE.match(item) is None for item in cve_ids):
        return "cve_ids must be CVE identifiers"
    if on and _DATE.match(on) is None:
        return "date must be YYYY-MM-DD"
    return ""


def _validate_top(min_epss: float, limit: int) -> str:
    if not 0 <= min_epss <= 1:
        return "min_epss must be between 0 and 1"
    if not 1 <= limit <= 500:
        return "limit must be between 1 and 500"
    return ""


def _persist(rows: list[dict]) -> None:
    if not rows:
        return
    directory = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-epss"))
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "epss-observations.jsonl"
    with path.open("a", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def _snapshot_text() -> str:
    snapshot = os.environ.get("CYBERAU_EPSS_SNAPSHOT")
    path = Path(snapshot) if snapshot else _PACKAGE / "data" / "epss_batch.json"
    return path.read_text(encoding="utf-8")


def _note(item: dict) -> str:
    raw = item.get("note")
    if not raw:
        return ""
    return untrusted_text(str(raw), "first-epss")


def _envelope(
    data,
    cache: str,
    payload: dict | None = None,
    warnings: tuple[str, ...] = (),
) -> dict:
    version = "" if payload is None else str(payload.get("version", ""))
    score_date = ""
    if payload and isinstance(payload.get("data"), list) and payload["data"]:
        score_date = str(payload["data"][0].get("date", ""))
    as_of = " ".join(part for part in (version, score_date) if part)
    return envelope(
        "first-epss",
        data,
        urls=[API],
        cache=cache,
        data_as_of=as_of or None,
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


def _allowlist() -> Path:
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


def health_response() -> dict:
    """One live EPSS payload for the health workflow.

    Unit tests must not call this. They pass fixtures instead.
    """
    payload, _cache, warning = _fetch({"cve": "CVE-2024-3400"}, force_live=True)
    if warning or payload is None:
        return {
            "ok": False,
            "status_code": None,
            "error_class": None,
            "body": None,
            "detail": warning or "no response",
        }
    return {
        "ok": True,
        "status_code": 200,
        "error_class": None,
        "body": payload,
        "detail": "live ok",
    }


register_connector("first-epss", connector)
