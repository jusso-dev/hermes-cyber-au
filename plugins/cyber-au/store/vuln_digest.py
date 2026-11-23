"""The daily vulnerability digest: what the public feeds added since the last briefing.

``cyberau-mcp refresh`` loads OSV, GitHub advisories, the CVE List, NVD, Exploit-DB, Metasploit,
cve.now, pwn.watch and the dependency scans into ``advisories``. This module reads back what is
new and shapes it as intel-store ``hits`` under named groups, so the morning email and the
daily briefing show it with the watch hits they already render. It makes no network call and
reads no secret.

New means ``first_seen`` at or after ``since``. Vulnerabilities from several feeds are merged
into one row per CVE and ranked by what matters most to a defender: active exploitation (CISA
KEV), a public exploit (Exploit-DB or Metasploit), EPSS, then CVSS.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from .canonical import canonical_timestamp
from .db import open_store, resolve_db_path
from .text import unwrap_untrusted

GROUP_EXPLOITS = "Public exploits"
GROUP_MALWARE = "Malicious packages"
GROUP_VULNS = "Critical and high vulnerabilities"
GROUP_INCIDENTS = "Live incidents"
GROUP_DEPENDENCIES = "Your dependencies"

EXPLOIT_SOURCES = ("exploit-db", "metasploit")
MALWARE_SOURCES = ("osv-mal",)
VULN_SOURCES = ("cvelist", "ghsa", "feed-cve-now-critical", "nvd")
INCIDENT_SOURCES = ("feed-pwn-watch",)
DEPENDENCY_SOURCES = ("osv-scan", "dependabot")
ALL_SOURCES = (
    *EXPLOIT_SOURCES,
    *MALWARE_SOURCES,
    *VULN_SOURCES,
    *INCIDENT_SOURCES,
    *DEPENDENCY_SOURCES,
)
PER_GROUP = 10

_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_SEVERITY = re.compile(r"Severity: (critical|high|medium|low)\.", re.IGNORECASE)
_TITLE_SEVERITY = re.compile(r"^\[(critical|high|medium|low)\]", re.IGNORECASE)
_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
# Which feed's wording heads a merged vulnerability. Earlier is preferred.
_TITLE_ORDER = ("cvelist", "ghsa", "feed-cve-now-critical", "nvd")


def hits(*, store: str | Path | None = None, since: str, per_group: int = PER_GROUP) -> list[dict]:
    """Digest rows in the intel-store ``hits`` shape, one ``watch`` title per group."""
    store_file = resolve_db_path(store)
    if not store_file.is_file():
        return []
    cutoff = canonical_timestamp(since)
    conn = open_store(store_file).connection()
    marks = ",".join("?" for _ in ALL_SOURCES)
    rows = conn.execute(
        "SELECT id, source_id, title, url, published_at, summary, first_seen FROM advisories"
        f" WHERE source_id IN ({marks}) AND first_seen >= ?",
        (*ALL_SOURCES, cutoff),
    ).fetchall()
    if not rows:
        return []
    items = [_item(row) for row in rows]
    exploited = _exploit_cves(conn)
    facts = _facts(conn, {cve for item in items for cve in item["cves"]})

    out: list[dict] = []
    out += _flat(items, EXPLOIT_SOURCES, GROUP_EXPLOITS, per_group, exploited, facts)
    out += _flat(items, MALWARE_SOURCES, GROUP_MALWARE, per_group, exploited, facts)
    out += _merged_vulnerabilities(items, exploited, facts, per_group)
    out += _flat(items, INCIDENT_SOURCES, GROUP_INCIDENTS, per_group, exploited, facts)
    out += _flat(items, DEPENDENCY_SOURCES, GROUP_DEPENDENCIES, per_group, exploited, facts)
    return out


def _item(row) -> dict:
    summary = row["summary"] or ""
    text = unwrap_untrusted(summary)
    text = summary if text is None else text
    title = row["title"] or ""
    severity = None
    found = _SEVERITY.search(text) or _TITLE_SEVERITY.search(title)
    if found:
        severity = found.group(1).lower()
    elif row["source_id"] == "feed-cve-now-critical":
        severity = "critical"  # the feed is cve.now's critical filter
    malware = row["source_id"] in MALWARE_SOURCES or "Malicious package." in text
    cves = sorted({match.upper() for match in _CVE.findall(f"{title} {text}")})
    return {
        "id": row["id"],
        "source": row["source_id"],
        "title": title,
        "url": row["url"],
        "published": row["published_at"],
        "seen": row["first_seen"],
        "severity": severity,
        "malware": malware,
        "cves": cves,
    }


def _exploit_cves(conn) -> set[str]:
    """CVEs that any stored Exploit-DB entry or Metasploit module names."""
    marks = ",".join("?" for _ in EXPLOIT_SOURCES)
    found: set[str] = set()
    for row in conn.execute(
        f"SELECT title, summary FROM advisories WHERE source_id IN ({marks})", EXPLOIT_SOURCES
    ):
        found.update(match.upper() for match in _CVE.findall(f"{row['title']} {row['summary']}"))
    return found


def _facts(conn, cves: set[str]) -> dict[str, dict]:
    found: dict[str, dict] = {}
    ordered = sorted(cves)
    for start in range(0, len(ordered), 500):
        chunk = ordered[start : start + 500]
        rows = conn.execute(
            "SELECT cve_id, kev_date_added, epss, cvss_v3, cvss_v4 FROM vulnerabilities"
            f" WHERE cve_id IN ({','.join('?' for _ in chunk)})",
            chunk,
        )
        for row in rows:
            found[row["cve_id"]] = dict(row)
    return found


def _flat(items, sources, group, per_group, exploited, facts) -> list[dict]:
    chosen = [item for item in items if item["source"] in sources and not item["malware"]]
    if group == GROUP_MALWARE:
        chosen = [item for item in items if item["malware"]]
    chosen.sort(key=lambda item: (_RANK.get(item["severity"] or "", 0), item["seen"]), reverse=True)
    return _rows(
        group,
        [(item, [item], _tags(item, exploited, facts)) for item in chosen],
        per_group,
    )


def _merged_vulnerabilities(items, exploited, facts, per_group) -> list[dict]:
    """One row per CVE across NVD, GHSA, the CVE List and cve.now, ranked by risk."""
    merged: dict[str, list[dict]] = {}
    for item in items:
        if item["source"] not in VULN_SOURCES or item["malware"]:
            continue
        key = item["cves"][0] if item["cves"] else item["id"]
        merged.setdefault(key, []).append(item)
    scored = []
    for key, group in merged.items():
        cves = {cve for item in group for cve in item["cves"]}
        tags = _tags(group[0], exploited, facts, cves=cves, extra=group)
        severity = max((_RANK.get(item["severity"] or "", 0) for item in group), default=0)
        known = [facts.get(cve) or {} for cve in cves]
        kev = any(fact.get("kev_date_added") for fact in known)
        exploit = bool(cves & exploited)
        epss = max((fact.get("epss") or 0 for fact in known), default=0)
        cvss = max((fact.get("cvss_v3") or fact.get("cvss_v4") or 0 for fact in known), default=0)
        # Medium and low entries only matter when something makes them urgent.
        if severity < _RANK["high"] and not (kev or exploit):
            continue
        scored.append(((kev, exploit, round(epss, 4), cvss, severity), key, group, tags))
    scored.sort(key=lambda row: (row[0], row[1]), reverse=True)
    pairs = []
    for _score, _key, group, tags in scored:
        head = sorted(
            group,
            key=lambda item: (
                _TITLE_ORDER.index(item["source"]) if item["source"] in _TITLE_ORDER else 99
            ),
        )[0]
        pairs.append((head, group, tags))
    return _rows(GROUP_VULNS, pairs, per_group)


def _tags(item, exploited, facts, *, cves=None, extra=None) -> list[str]:
    cves = set(item["cves"]) if cves is None else cves
    known = [facts.get(cve) or {} for cve in sorted(cves)]
    tags = []
    if any(fact.get("kev_date_added") for fact in known):
        tags.append("exploited, CISA KEV")
    if cves & exploited:
        tags.append("public exploit")
    epss = max((fact.get("epss") or 0 for fact in known), default=0)
    if epss:
        tags.append(f"EPSS {epss:.2f}")
    cvss = max((fact.get("cvss_v3") or fact.get("cvss_v4") or 0 for fact in known), default=0)
    if cvss:
        tags.append(f"CVSS {cvss:g}")
    severities = [i["severity"] for i in (extra or [item]) if i.get("severity")]
    if severities and not _TITLE_SEVERITY.match(item["title"]):  # pwn.watch titles say it already
        tags.append(max(severities, key=lambda level: _RANK[level]))
    return tags


def _rows(group: str, pairs: list, per_group: int) -> list[dict]:
    out = []
    for rank, (head, members, tags) in enumerate(pairs[:per_group], start=1):
        value = re.sub(r"\s+", " ", head["title"]).strip()
        if tags:
            value += f" [{'; '.join(tags)}]"
        sources = sorted({member["source"] for member in members})
        digest = hashlib.sha256(f"{group}\0{head['id']}".encode()).hexdigest()[:12]
        out.append(
            {
                "id": f"vuln-{digest}",
                "kind": "advisory digest",
                "value": value,
                "seen": max(member["seen"] for member in members),
                "published": head["published"],
                "source": "+".join(sources),
                "url": head["url"],
                "watch": group,
                "rank": rank,
            }
        )
    if len(pairs) > per_group:
        rest = len(pairs) - per_group
        newest = max(member["seen"] for _head, members, _tags in pairs for member in members)
        out.append(
            {
                "id": "vuln-" + hashlib.sha256(f"{group}\0more".encode()).hexdigest()[:12],
                "kind": "advisory digest",
                "value": f"{rest} more new {'item' if rest == 1 else 'items'} not shown",
                "seen": newest,
                "published": None,
                "source": "intel-store",
                "url": "",
                "watch": group,
                "rank": per_group + 1,
            }
        )
    return out
