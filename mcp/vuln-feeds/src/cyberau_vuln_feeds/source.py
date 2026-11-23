"""Daily public vulnerability feeds: OSV, GitHub advisories, the CVE List, Exploit-DB, Metasploit.

The ``cyberau-mcp refresh`` adapters and the two read-only tools share the ``fetch_*`` functions
here. Each returns a ``Fetched`` with rows (see ``feeds.py``), the problems that stopped part of
the feed, and whether every request was answered live. A stale cache answer is a problem, not a
result: refresh exists to get new data.
"""

import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Literal

from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressDenied, EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient, HttpError
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector
from cyberau_common.snapshot import unavailable
from pydantic import Field

from . import feeds

KEY = "vuln-feeds"
SERVER = "vuln_feeds"
LABEL = "The public vulnerability feeds"
ATTRIBUTION = (
    "Each item names its feed. Cite OSV.dev (per record licence), the GitHub Advisory Database "
    "(CC BY 4.0), the CVE Program (copyright The MITRE Corporation, CVE Terms of Use), "
    "Exploit-DB (GPL-2.0 repository, index rows only) and Metasploit (Rapid7, BSD 3-clause)."
)
OSV_BUCKET = "https://osv-vulnerabilities.storage.googleapis.com"
OSV_API = "https://api.osv.dev/v1"
GHSA_API = "https://api.github.com/advisories"
DELTA_LOG = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
EXPLOITDB_CSV = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
METASPLOIT_JSON = (
    "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/"
    "db/modules_metadata_base.json"
)
# Ecosystems that carry MAL- records in the OSV bucket.
MALWARE_ECOSYSTEMS = ("npm", "PyPI", "crates.io", "RubyGems")
FEED_NAMES = ("osv-malicious", "ghsa", "cvelist", "exploit-db", "metasploit")
SOURCES = {
    "osv-malicious": "osv-mal",
    "ghsa": "ghsa",
    "cvelist": "cvelist",
    "exploit-db": "exploit-db",
    "metasploit": "metasploit",
}
MAX_ROWS = 400
_TTL = 3600
_RANGE_CSV = 1024 * 1024
_RANGE_DELTA = 6 * 1024 * 1024
_MAX_RECORDS = 150
_GHSA_PAGE = 100
# Three pages of 100 a type: a run makes at most six unauthenticated calls of the 60 an hour.
_GHSA_PAGES = 3
_LIVE = {"miss", "hit"}
_TRANSPORT = None
_Feed = Literal["osv-malicious", "ghsa", "cvelist", "exploit-db", "metasploit"]
_Days = Annotated[int, Field(ge=1, le=14)]
_Limit = Annotated[int, Field(ge=1, le=100)]


class FeedError(Exception):
    """One upstream request failed. The message holds no secret."""


@dataclass
class Fetched:
    rows: list[dict] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    live: bool = True

    @property
    def ok(self) -> bool:
        return self.live and not self.problems


class Session:
    """One HTTP client for a run. Records whether every answer was live."""

    def __init__(self, *, private: bool = False) -> None:
        self.stale = False
        data_dir = _data_dir()
        self._scratch = None
        if private:
            # Answers about private repositories are never written to the shared cache.
            cache = HttpCache(data_dir / "unused.sqlite", persistence="none")
        else:
            cache = HttpCache(data_dir / "http_cache.sqlite")
        allowlist = Path(os.environ.get("CYBERAU_EGRESS_ALLOWLIST", str(_allowlist())))
        self.client = HttpClient(
            KEY,
            policy=EgressPolicy(allowlist, KEY),
            cache=cache,
            limiter=RateLimiter(data_dir / "rate_limit.sqlite"),
            user_agent=USER_AGENT,
            rate=5,
            burst=5,
            window="rolling",
            timeout=120,
            offline=os.environ.get("CYBERAU_OFFLINE") == "1",
            transport=_TRANSPORT,
        )
        self.client.max_bytes = 64 * 1024 * 1024

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *_exc) -> None:
        self.client.close()

    def get(self, url: str, *, ttl: int = _TTL, params=None, headers=None, label: str) -> bytes:
        try:
            response = self.client.get(url, params=params, headers=headers, ttl=ttl)
        except (HttpError, EgressDenied, TimeoutError) as exc:
            raise FeedError(f"{label} was not reachable ({redact(str(exc))})") from None
        if response.status >= 400:
            raise FeedError(f"{label} returned status {response.status}")
        if response.cache not in _LIVE:
            self.stale = True
        return response.body

    def text(self, url: str, **kwargs) -> str:
        return self.get(url, **kwargs).decode("utf-8", "replace")

    def json(self, url: str, **kwargs):
        try:
            return json.loads(self.get(url, **kwargs))
        except ValueError:
            raise FeedError(f"{kwargs['label']} did not return JSON") from None


# OSV malicious packages (MAL-)


def fetch_osv_malicious(
    since: datetime, *, session: Session | None = None, ecosystems=MALWARE_ECOSYSTEMS
) -> Fetched:
    """MAL- records modified since ``since``, from the OSV bucket index and the OSV API."""
    result = Fetched()
    with _session(session) as http:
        ids: list[str] = []
        for ecosystem in ecosystems:
            try:
                text = http.text(
                    f"{OSV_BUCKET}/{ecosystem}/modified_id.csv",
                    headers={"Range": f"bytes=0-{_RANGE_CSV - 1}"},
                    label=f"OSV {ecosystem} index",
                )
            except FeedError as exc:
                result.problems.append(str(exc))
                continue
            found, covered = feeds.osv_modified_ids(text, since)
            if not covered:
                result.problems.append(f"OSV {ecosystem} index did not reach back to the window")
            ids.extend(item for item in found if item not in ids)
        for ident in ids[:MAX_ROWS]:
            try:
                record = http.json(f"{OSV_API}/vulns/{ident}", ttl=24 * 3600, label=f"OSV {ident}")
            except FeedError as exc:
                result.problems.append(str(exc))
                continue
            item = feeds.osv_row(record) if isinstance(record, dict) else None
            if item:
                result.rows.append(item)
        result.live = not http.stale
    return result


def fetch_osv_scan(packages: list[dict], *, session: Session | None = None) -> Fetched:
    """Known vulnerabilities in the packages of the asset inventory, OSV-Scanner style.

    ``packages`` holds ``{"asset": name, "purl": package URL}``. Only the ecosystem, package
    name and version of each purl are sent to api.osv.dev.
    """
    result = Fetched()
    queries = []
    for package in packages:
        query = feeds.purl_query(package.get("purl", ""))
        if query:
            queries.append((package.get("asset") or query["package"], query))
    if not queries:
        return result
    with _session(session) as http:
        for start in range(0, len(queries), 100):
            batch = queries[start : start + 100]
            try:
                body = {"queries": [feeds.osv_query_body(q) for _, q in batch]}
                payload = _post(http, f"{OSV_API}/querybatch", body)
            except FeedError as exc:
                result.problems.append(str(exc))
                continue
            results = payload.get("results") if isinstance(payload, dict) else None
            if not isinstance(results, list):
                result.problems.append("OSV batch response has no results list")
                continue
            for (asset, _query), found in zip(batch, results, strict=False):
                for vuln in (found or {}).get("vulns") or []:
                    ident = str(vuln.get("id") or "")
                    if not ident or len(result.rows) >= MAX_ROWS:
                        continue
                    try:
                        record = http.json(
                            f"{OSV_API}/vulns/{ident}", ttl=24 * 3600, label=f"OSV {ident}"
                        )
                    except FeedError as exc:
                        result.problems.append(str(exc))
                        continue
                    item = (
                        feeds.osv_row(record, "osv-scan", asset=asset)
                        if isinstance(record, dict)
                        else None
                    )
                    if item:
                        result.rows.append(item)
        result.live = not http.stale
    return result


def _post(http: Session, url: str, body: dict):
    try:
        response = http.client.post_json(url, body, ttl=_TTL)
    except (HttpError, EgressDenied, TimeoutError) as exc:
        raise FeedError(f"OSV was not reachable ({redact(str(exc))})") from None
    if response.status >= 400:
        raise FeedError(f"OSV returned status {response.status}")
    if response.cache not in _LIVE:
        http.stale = True
    try:
        return json.loads(response.body)
    except ValueError:
        raise FeedError("OSV did not return JSON") from None


# GitHub Advisory Database (public REST, no token)


def fetch_ghsa(since: datetime, *, session: Session | None = None) -> Fetched:
    """Reviewed advisories and malware advisories published since ``since``."""
    result = Fetched()
    published = ">=" + since.astimezone(UTC).strftime("%Y-%m-%d")
    with _session(session) as http:
        for kind in ("reviewed", "malware"):
            for page in range(1, _GHSA_PAGES + 1):
                try:
                    payload = http.json(
                        GHSA_API,
                        params={
                            "type": kind,
                            "published": published,
                            "sort": "published",
                            "direction": "desc",
                            "per_page": str(_GHSA_PAGE),
                            "page": str(page),
                        },
                        headers={
                            "Accept": "application/vnd.github+json",
                            "X-GitHub-Api-Version": "2022-11-28",
                        },
                        label=f"GitHub advisories ({kind})",
                    )
                except FeedError as exc:
                    result.problems.append(str(exc))
                    break
                result.rows.extend(feeds.ghsa_rows(payload))
                if not isinstance(payload, list) or len(payload) < _GHSA_PAGE:
                    break
        result.live = not http.stale
    result.rows = _newest(result.rows, since)
    return result


def fetch_dependabot(repos: list[str], token: str) -> Fetched:
    """Open critical and high Dependabot alerts on the owner's repositories. Needs a token."""
    result = Fetched()
    with Session(private=True) as http:
        for repo in repos:
            try:
                payload = http.json(
                    f"https://api.github.com/repos/{repo}/dependabot/alerts",
                    params={"state": "open", "severity": "critical,high", "per_page": "100"},
                    headers={
                        "Accept": "application/vnd.github+json",
                        "Authorization": f"Bearer {token}",
                        "X-GitHub-Api-Version": "2022-11-28",
                    },
                    ttl=0,
                    label=f"Dependabot alerts for {repo}",
                )
            except FeedError as exc:
                result.problems.append(str(exc).replace(token, "[REDACTED]"))
                continue
            result.rows.extend(feeds.dependabot_rows(payload, repo))
        result.live = not http.stale
    return result


# CVE List (cvelistV5)


def fetch_cvelist(since: datetime, *, session: Session | None = None) -> Fetched:
    """Newly published CVE records, from cvelistV5's delta log and the raw record files."""
    result = Fetched()
    with _session(session) as http:
        try:
            text = http.text(
                DELTA_LOG,
                headers={"Range": f"bytes=0-{_RANGE_DELTA - 1}"},
                label="cvelistV5 delta log",
            )
        except FeedError as exc:
            result.problems.append(str(exc))
            result.live = False
            return result
        for entry in feeds.delta_log_new(text, since)[:_MAX_RECORDS]:
            try:
                record = http.json(entry["link"], ttl=24 * 3600, label=f"CVE record {entry['cve']}")
            except FeedError as exc:
                result.problems.append(str(exc))
                continue
            item = feeds.cve_record_row(record) if isinstance(record, dict) else None
            if item:
                result.rows.append(item)
        result.live = not http.stale
    return result


# Exploit-DB and Metasploit


def fetch_exploitdb(since: datetime, *, session: Session | None = None) -> Fetched:
    return _bulk(
        session, EXPLOITDB_CSV, "Exploit-DB", lambda text: feeds.exploitdb_rows(text, since)
    )


def fetch_metasploit(since: datetime, *, session: Session | None = None) -> Fetched:
    return _bulk(
        session, METASPLOIT_JSON, "Metasploit", lambda text: feeds.metasploit_rows(text, since)
    )


def _bulk(session, url: str, label: str, parse) -> Fetched:
    result = Fetched()
    with _session(session) as http:
        try:
            text = http.text(url, ttl=6 * 3600, label=f"{label} index")
        except FeedError as exc:
            result.problems.append(str(exc))
            result.live = False
            return result
        rows = parse(text)
        if not text.strip():
            result.problems.append(f"{label} index is empty")
        result.rows = rows[:MAX_ROWS]
        result.live = not http.stale
    return result


def fetch(feed: str, since: datetime) -> Fetched:
    if feed == "osv-malicious":
        return fetch_osv_malicious(since)
    if feed == "ghsa":
        return fetch_ghsa(since)
    if feed == "cvelist":
        return fetch_cvelist(since)
    if feed == "exploit-db":
        return fetch_exploitdb(since)
    if feed == "metasploit":
        return fetch_metasploit(since)
    raise ValueError("unknown feed")


# Tools


def vuln_feed_list() -> dict:
    """The feeds this connector reads, and the intel store source id of each."""
    data = {
        "feeds": [{"feed": name, "source": SOURCES[name]} for name in FEED_NAMES],
    }
    return _envelope(data, "snapshot", notes=("static list, no upstream call",))


def vuln_feed_recent(feed: _Feed, days: _Days = 1, limit: _Limit = 25) -> dict:
    """Items one feed published or changed in the last ``days`` days, newest first."""
    if feed not in FEED_NAMES:
        return _envelope(None, "snapshot", notes=("feed is not one of " + ", ".join(FEED_NAMES),))
    if os.environ.get("CYBERAU_OFFLINE") == "1":
        return _envelope(None, "snapshot", notes=(unavailable(LABEL, "offline mode"),))
    since = datetime.now(UTC) - timedelta(days=days)
    try:
        fetched = fetch(feed, since)
    except Exception as exc:  # a fetch fault is a warning, never a crash
        return _envelope(
            None,
            "snapshot",
            notes=(unavailable(LABEL, f"the live fetch failed ({redact(str(exc))})"),),
        )
    if not fetched.rows and fetched.problems:
        return _envelope(None, "snapshot", notes=tuple(fetched.problems))
    items = [_present(item) for item in fetched.rows[:limit]]
    cache = "miss" if fetched.live else "stale"
    return _envelope(
        {"feed": feed, "days": days, "count": len(fetched.rows), "items": items},
        cache,
        notes=tuple(fetched.problems) or (("no items in the window",) if not items else ()),
    )


def _present(item: dict) -> dict:
    return {
        "id": item["id"],
        "title": untrusted_text(item["title"], KEY),
        "url": item["url"],
        "published_at": item["published_at"],
        "summary": untrusted_text(item["summary"], KEY) if item["summary"] else None,
        "cves": item["cves"],
        "severity": item["severity"],
        "kind": item["kind"],
    }


def connector() -> Connector:
    return _VulnFeedsConnector()


class _VulnFeedsConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key=KEY,
            server_name=SERVER,
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec("vuln_feed_list", "The daily vulnerability feeds read.", vuln_feed_list),
                ToolSpec(
                    "vuln_feed_recent",
                    "New items from OSV MAL- alerts, GitHub advisories, the CVE List, Exploit-DB "
                    "or Metasploit.",
                    vuln_feed_recent,
                ),
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            return Probe(self.key, True, "no local copy to check")
        if not live:
            return Probe(self.key, True, "offline ok")
        since = datetime.now(UTC) - timedelta(days=1)
        try:
            with Session() as http:
                http.json(
                    GHSA_API,
                    params={"per_page": "1"},
                    headers={"Accept": "application/vnd.github+json"},
                    ttl=60,
                    label="GitHub advisories",
                )
                text = http.text(
                    f"{OSV_BUCKET}/npm/modified_id.csv",
                    headers={"Range": "bytes=0-4095"},
                    ttl=60,
                    label="OSV npm index",
                )
        except FeedError as exc:
            return Probe(self.key, False, str(exc))
        if not text.strip() or feeds.parse_time(text.split(",", 1)[0]) is None or since is None:
            return Probe(self.key, False, "OSV index did not parse")
        return Probe(self.key, True, "live ok")


# Helpers


def _session(session: Session | None):
    return _Borrowed(session) if session is not None else Session()


class _Borrowed:
    """Lets a caller share one Session across fetches without it being closed under them."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def __enter__(self) -> "Session":
        return self.session

    def __exit__(self, *_exc) -> None:
        return None


def _newest(rows: list[dict], since: datetime) -> list[dict]:
    cutoff = feeds.iso(since)
    seen: dict[str, dict] = {}
    for item in rows:
        if (item["published_at"] or "") >= cutoff:
            seen.setdefault(item["id"], item)
    ordered = sorted(seen.values(), key=lambda item: item["published_at"] or "", reverse=True)
    return ordered[:MAX_ROWS]


def _envelope(data, cache: str, notes: tuple[str, ...] = ()) -> dict:
    return envelope(
        KEY,
        data,
        urls=[GHSA_API],
        cache=cache,
        data_as_of=None,
        warnings=notes,
        attribution=ATTRIBUTION,
    )


def _data_dir() -> Path:
    return Path(os.environ.get("CYBERAU_DATA_DIR") or Path(tempfile.gettempdir()) / "cyberau-vuln")


def _allowlist() -> Path:
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


register_connector(KEY, connector)
