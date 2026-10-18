"""Read-only CISA Known Exploited Vulnerabilities catalogue."""

from __future__ import annotations

import json
import os
from datetime import date, datetime
from pathlib import Path

from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient, HttpError
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.server import Connector, ToolSpec, register_connector
from cyberau_common.snapshot import unavailable

CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
ATTRIBUTION = "CISA Known Exploited Vulnerabilities catalog. US Government work."
LABEL = "The CISA KEV catalogue"
SNAPSHOT_NOTE = (
    "served the operator-supplied KEV snapshot file (CYBERAU_KEV_SNAPSHOT), not a live fetch"
)


def kev_lookup(cve_ids: list[str] | None = None) -> dict:
    if not cve_ids:
        return _envelope([], "snapshot", warnings=("cve_ids is required",))
    catalog, cache, notes = _load_catalog()
    if catalog is None:
        return _envelope({"found": [], "missing": []}, cache, warnings=notes)
    wanted = {item.upper() for item in cve_ids}
    found = [_entry(row) for row in catalog["vulnerabilities"] if row["cveID"].upper() in wanted]
    present = {row["cve_id"] for row in found}
    missing = sorted(wanted - present)
    return _envelope({"found": found, "missing": missing}, cache, catalog, notes)


def kev_recent(days: int = 7, vendor: str | None = None, ransomware_only: bool = False) -> dict:
    catalog, cache, notes = _load_catalog()
    if catalog is None:
        return _envelope([], cache, warnings=notes)
    today = _today()
    rows = []
    for row in catalog["vulnerabilities"]:
        added = date.fromisoformat(row["dateAdded"])
        if (today - added).days > days:
            continue
        if vendor and vendor.lower() not in row["vendorProject"].lower():
            continue
        if ransomware_only and row.get("knownRansomwareCampaignUse") != "Known":
            continue
        rows.append(_entry(row))
    return _envelope(rows, cache, catalog, notes)


def kev_search(query: str | None = None, limit: int = 20) -> dict:
    if not query or len(query) < 2:
        return _envelope([], "snapshot", warnings=("query must be at least 2 characters",))
    catalog, cache, notes = _load_catalog()
    if catalog is None:
        return _envelope([], cache, warnings=notes)
    needle = query.lower()
    rows = []
    for row in catalog["vulnerabilities"]:
        fields = ("vendorProject", "product", "vulnerabilityName", "shortDescription")
        haystack = " ".join(str(row.get(field, "")) for field in fields).lower()
        if needle in haystack:
            rows.append(_entry(row))
        if len(rows) >= limit:
            break
    return _envelope(rows, cache, catalog, notes)


def connector() -> Connector:
    return Connector(
        key="cisa-kev",
        server_name="kev",
        attribution=ATTRIBUTION,
        tools=[
            ToolSpec("kev_lookup", "Check whether CVEs are in the CISA KEV catalogue.", kev_lookup),
            ToolSpec("kev_recent", "KEV entries added in the last N days.", kev_recent),
            ToolSpec("kev_search", "Search KEV by vendor, product, or keyword.", kev_search),
        ],
    )


def _catalog() -> tuple[dict | None, str]:
    """Return the catalogue and its cache state. The catalogue is None when unavailable.

    cyberau_common.refresh calls this, so keep the shape.
    """
    catalog, cache, _notes = _load_catalog()
    return catalog, cache


def _load_catalog() -> tuple[dict | None, str, tuple[str, ...]]:
    """Return the catalogue, its cache state and warnings.

    The ladder is live, then this connector's own HTTP cache, then an
    operator-supplied snapshot file. Nothing shipped in the repo is served.
    When all of them fail the catalogue is None and the warning says why.
    """
    snapshot = os.environ.get("CYBERAU_KEV_SNAPSHOT")
    if snapshot:
        return json.loads(Path(snapshot).read_text(encoding="utf-8")), "snapshot", (SNAPSHOT_NOTE,)
    offline = os.environ.get("CYBERAU_OFFLINE") == "1"
    data_dir = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-kev"))
    allowlist = Path(os.environ.get("CYBERAU_EGRESS_ALLOWLIST", str(_repo_allowlist())))
    client = HttpClient(
        "cisa-kev",
        policy=EgressPolicy(allowlist, "cisa-kev"),
        cache=HttpCache(data_dir / "http_cache.sqlite"),
        limiter=RateLimiter(data_dir / "rate_limit.sqlite"),
        user_agent=USER_AGENT,
        rate=1 / (6 * 3600),
        burst=1,
        window="rolling",
        offline=offline,
    )
    try:
        response = client.get(CATALOG_URL, ttl=6 * 3600)
        catalog = json.loads(response.body)
    except HttpError as exc:
        reason = "offline mode and no cached copy" if offline else f"the live fetch failed ({exc})"
        return None, "snapshot", (unavailable(LABEL, reason),)
    except ValueError:
        return None, "snapshot", (unavailable(LABEL, "the live response was not valid JSON"),)
    finally:
        client.close()
    if not isinstance(catalog, dict) or not isinstance(catalog.get("vulnerabilities"), list):
        return None, "snapshot", (unavailable(LABEL, "the live response had no vulnerabilities list"),)
    return catalog, response.cache, ()


def _entry(row: dict) -> dict:
    return {
        "cve_id": row["cveID"],
        "vendor": _free(row.get("vendorProject")),
        "product": _free(row.get("product")),
        "name": _free(row.get("vulnerabilityName")),
        "date_added": row.get("dateAdded"),
        "due_date": row.get("dueDate"),
        "ransomware": row.get("knownRansomwareCampaignUse"),
        "action": _free(row.get("requiredAction")),
        "description": _free(row.get("shortDescription")),
    }


def _free(value: object) -> str:
    if value is None or value == "":
        return ""
    return untrusted_text(str(value), "cisa-kev")


def _envelope(
    data,
    cache: str,
    catalog: dict | None = None,
    warnings: tuple[str, ...] = (),
) -> dict:
    return envelope(
        "cisa-kev",
        data,
        urls=[CATALOG_URL],
        cache=cache,
        data_as_of=None if catalog is None else catalog.get("catalogVersion"),
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


def _today() -> date:
    override = os.environ.get("CYBERAU_TODAY")
    if override:
        return date.fromisoformat(override)
    return datetime.now().date()


def _repo_allowlist() -> Path:
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


register_connector("cisa-kev", connector)
