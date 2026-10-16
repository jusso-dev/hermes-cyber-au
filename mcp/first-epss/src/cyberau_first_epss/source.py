"""Read-only FIRST EPSS scores."""

from __future__ import annotations

import json
import os
from pathlib import Path

from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient, HttpError
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector

API = "https://api.first.org/data/v1/epss"
ATTRIBUTION = "FIRST EPSS. Cite the model version and the score date."
REQUIRED = ("cve", "epss", "percentile", "date")
_PACKAGE = Path(__file__).resolve().parents[2]


def epss_scores(cve_ids: list[str] | None = None, date: str | None = None) -> dict:
    if not cve_ids:
        return _envelope([], "snapshot", warnings=("cve_ids is required",))
    if len(cve_ids) > 100:
        return _envelope(
            [],
            "snapshot",
            warnings=("batch at most 100 CVEs; use the bulk file above that",),
        )
    params = {"cve": ",".join(cve_ids)}
    if date:
        params["date"] = date
    payload, cache = _fetch(params)
    if payload is None:
        return _envelope([], cache, warnings=("EPSS response was not usable",))
    rows, warnings = _rows(payload)
    return _envelope(rows, cache, payload, warnings=tuple(warnings))


def epss_history(cve_id: str | None = None) -> dict:
    if not cve_id:
        return _envelope([], "snapshot", warnings=("cve_id is required",))
    payload, cache = _fetch({"cve": cve_id, "scope": "time-series"})
    if payload is None:
        return _envelope([], cache, warnings=("EPSS history was not usable",))
    rows, warnings = _rows(payload)
    return _envelope(rows[-30:], cache, payload, warnings=tuple(warnings))


def epss_top(min_epss: float = 0.5, limit: int = 50) -> dict:
    payload, cache = _fetch({"epss-gt": str(min_epss), "limit": str(limit)})
    if payload is None:
        return _envelope([], cache, warnings=("EPSS top list was not usable",))
    rows, warnings = _rows(payload)
    return _envelope(rows[:limit], cache, payload, warnings=tuple(warnings))


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

    def health(self, *, live: bool) -> Probe:
        if not live:
            return Probe(self.key, True, "offline ok")
        try:
            payload, _cache = _fetch({"cve": "CVE-2024-3400"}, force_live=True)
        except HttpError as exc:
            return Probe(self.key, False, str(exc))
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


def _fetch(params: dict, *, force_live: bool = False) -> tuple[dict | None, str]:
    snapshot = os.environ.get("CYBERAU_EPSS_SNAPSHOT")
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    if offline or (snapshot and not force_live):
        path = Path(snapshot) if snapshot else _PACKAGE / "data" / "epss_batch.json"
        return _load(path.read_text(encoding="utf-8"))
    data_dir = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-epss"))
    allowlist = Path(os.environ.get("CYBERAU_EGRESS_ALLOWLIST", str(_allowlist())))
    client = HttpClient(
        "first-epss",
        policy=EgressPolicy(allowlist, "first-epss"),
        cache=HttpCache(data_dir / "http_cache.sqlite"),
        limiter=RateLimiter(data_dir / "rate_limit.sqlite"),
        user_agent=USER_AGENT,
        rate=1000 / 60,
        burst=50,
        window="rolling",
    )
    try:
        response = client.get(API, params=params, ttl=12 * 3600)
    finally:
        client.close()
    payload, _state = _load(response.body.decode("utf-8"))
    return payload, response.cache


def _load(text: str) -> tuple[dict | None, str]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None, "snapshot"
    if not isinstance(payload, dict):
        return None, "snapshot"
    return payload, "snapshot"


def _rows(payload: dict) -> tuple[list[dict], list[str]]:
    drift = schema_drift(payload)
    if drift:
        return [], [drift]
    rows = []
    for item in payload["data"]:
        rows.append(
            {
                "cve": item["cve"],
                "epss": float(item["epss"]),
                "percentile": float(item["percentile"]),
                "date": item["date"],
                "model": str(payload.get("version", "")),
                "note": _note(item),
            }
        )
    return rows, []


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


register_connector("first-epss", connector)
