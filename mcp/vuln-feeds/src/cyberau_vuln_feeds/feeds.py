"""Parsers for the daily vulnerability feeds. No network access in this module.

Every parser returns plain rows with the same keys:

``id``           stable id, unique across feeds, for example ``ghsa:GHSA-xxxx``
``source``       intel store source id (``osv-mal``, ``ghsa``, ``cvelist``, ...)
``title``        one line, starts with the upstream id
``url``          https link to the upstream page
``published_at`` ISO 8601 UTC string or ``None``
``summary``      short plain text or ``None``
``cves``         CVE ids the item names
``severity``     ``critical``, ``high``, ``medium``, ``low`` or ``None``
``kind``         ``malicious-package``, ``vulnerability``, ``public-exploit``,
                 ``dependency-finding``

Feed text is untrusted. The parsers only cut and join it. The store wraps summaries.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from datetime import UTC, datetime
from urllib.parse import unquote

CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_SEVERITIES = {"critical", "high", "medium", "low"}
_OSV_MARKER = re.compile(r"\n?---\n_-= Per source details\..*", re.DOTALL)
_PURL_ECOSYSTEMS = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "golang": "Go",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "nuget": "NuGet",
    "composer": "Packagist",
}
_RAW_CVE_PREFIX = "https://raw.githubusercontent.com/CVEProject/cvelistV5/"


def row(
    ident: str,
    source: str,
    title: str,
    url: str,
    *,
    kind: str,
    published_at: str | None = None,
    summary: str | None = None,
    cves=(),
    severity: str | None = None,
) -> dict:
    found = sorted({cve.upper() for cve in cves if cve and CVE.fullmatch(str(cve))})
    level = str(severity).lower() if severity else None
    if level not in _SEVERITIES:
        level = None
    if level:
        # The store keeps no severity column, so the briefing reads it back from this lead.
        summary = f"Severity: {level}. {summary or ''}".strip()
    return {
        "id": ident,
        "source": source,
        "title": _one_line(title, 300),
        "url": url,
        "published_at": published_at,
        "summary": _one_line(summary, 600) if summary else None,
        "cves": found,
        "severity": level,
        "kind": kind,
    }


def parse_time(value) -> datetime | None:
    """ISO 8601 with up to nanosecond digits, or a Metasploit ``2026-10-22 17:52:59 +0000``."""
    text = str(value or "").strip()
    if not text:
        return None
    text = re.sub(r"(\.\d{6})\d+", r"\1", text).replace("Z", "+00:00")
    if re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4}", text):
        text = text.replace(" ", "T", 1).replace(" ", "")
    try:
        stamp = datetime.fromisoformat(text)
    except ValueError:
        return None
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=UTC)


def iso(stamp: datetime) -> str:
    return stamp.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# OSV


def osv_modified_ids(text: str, since: datetime, prefix: str = "MAL-") -> tuple[list[str], bool]:
    """Ids with ``prefix`` modified at or after ``since`` from an OSV ``modified_id.csv``.

    The file is newest first and fetched with a byte range, so its last line may be cut.
    The flag is True when the window is fully covered, False when every line read was still
    inside the window and older entries may have been missed.
    """
    lines = text.split("\n")
    if lines and lines[-1]:
        lines = lines[:-1]  # a cut line
    ids: list[str] = []
    covered = False
    for line in lines:
        stamp, _, ident = line.strip().partition(",")
        when = parse_time(stamp)
        if when is None or not ident:
            continue
        if when < since:
            covered = True
            break
        if ident.startswith(prefix) and ident not in ids:
            ids.append(ident)
    return ids, covered


def osv_row(record: dict, source: str = "osv-mal", *, asset: str | None = None) -> dict | None:
    ident = str(record.get("id") or "")
    if not ident or record.get("withdrawn"):
        return None
    summary = str(record.get("summary") or "").strip()
    details = _OSV_MARKER.sub("", str(record.get("details") or "")).strip()
    packages = []
    for entry in record.get("affected") or []:
        package = (entry.get("package") or {}) if isinstance(entry, dict) else {}
        if package.get("name"):
            packages.append(f"{package.get('ecosystem', '')}/{package['name']}".strip("/"))
    aliases = [str(alias) for alias in record.get("aliases") or []]
    parts = []
    if packages:
        parts.append("Packages: " + ", ".join(dict.fromkeys(packages[:6])) + ".")
    if aliases:
        parts.append("Aliases: " + ", ".join(aliases[:6]) + ".")
    if details:
        parts.append(details)
    severity = None
    specific = record.get("database_specific")
    if isinstance(specific, dict):
        severity = specific.get("severity")
    title = f"{ident}: {summary or 'OSV record'}"
    if asset:
        title += f" (in {asset})"
    return row(
        f"{source}:{_asset_key(asset) + ':' if asset else ''}{ident}",
        source,
        title,
        f"https://osv.dev/vulnerability/{ident}",
        kind="malicious-package" if ident.startswith("MAL-") else "dependency-finding",
        published_at=_stamp(record.get("published")),
        summary=" ".join(parts) or None,
        cves=[*aliases, ident],
        severity=severity,
    )


def purl_query(purl: str) -> dict | None:
    """An OSV query for a package URL, or None when the type or name is unusable."""
    text = str(purl or "").strip().split("#", 1)[0].split("?", 1)[0]
    match = re.fullmatch(r"pkg:([A-Za-z]+)/(.+?)(?:@([^@/]+))?", text)
    if not match:
        return None
    ecosystem = _PURL_ECOSYSTEMS.get(match.group(1).lower())
    if ecosystem is None:
        return None
    name = unquote(match.group(2))
    if ecosystem == "Maven":
        name = name.replace("/", ":")
    query = {"ecosystem": ecosystem, "package": name}
    if match.group(3):
        query["version"] = unquote(match.group(3))
    return query


def osv_query_body(query: dict) -> dict:
    """The OSV API body for one ``purl_query`` result."""
    body = {"package": {"name": query["package"], "ecosystem": query["ecosystem"]}}
    if query.get("version"):
        body["version"] = query["version"]
    return body


# GitHub Advisory Database


def ghsa_rows(payload) -> list[dict]:
    rows = []
    for item in payload if isinstance(payload, list) else []:
        if not isinstance(item, dict) or item.get("withdrawn_at"):
            continue
        ghsa = str(item.get("ghsa_id") or "")
        if not ghsa:
            continue
        malware = item.get("type") == "malware"
        packages = []
        for vuln in item.get("vulnerabilities") or []:
            package = (vuln.get("package") or {}) if isinstance(vuln, dict) else {}
            if package.get("name"):
                packages.append(f"{package.get('ecosystem', '')}/{package['name']}".strip("/"))
        parts = ["Malicious package."] if malware else []
        if packages:
            parts.append("Packages: " + ", ".join(dict.fromkeys(packages[:6])) + ".")
        score = (
            (item.get("cvss") or {}).get("score") if isinstance(item.get("cvss"), dict) else None
        )
        if score:
            parts.append(f"CVSS {score}.")
        epss = item.get("epss")
        if isinstance(epss, dict) and epss.get("percentage") is not None:
            parts.append(f"EPSS {float(epss['percentage']):.4f}.")
        cve = item.get("cve_id")
        summary = str(item.get("summary") or "").strip()
        title = f"{ghsa}: {summary or 'GitHub advisory'}"
        if cve:
            title += f" ({cve})"
        rows.append(
            row(
                f"ghsa:{ghsa}",
                "ghsa",
                title,
                str(item.get("html_url") or f"https://github.com/advisories/{ghsa}"),
                kind="malicious-package" if malware else "vulnerability",
                published_at=_stamp(item.get("published_at")),
                summary=" ".join(parts) or None,
                cves=[cve] if cve else [],
                severity=item.get("severity"),
            )
        )
    return rows


def dependabot_rows(payload, repo: str) -> list[dict]:
    rows = []
    for alert in payload if isinstance(payload, list) else []:
        if not isinstance(alert, dict) or alert.get("state") not in (None, "open"):
            continue
        advisory = alert.get("security_advisory") or {}
        vulnerability = alert.get("security_vulnerability") or {}
        package = (vulnerability.get("package") or {}).get("name") or (
            (alert.get("dependency") or {}).get("package") or {}
        ).get("name")
        number = alert.get("number")
        if number is None or not package:
            continue
        cve = advisory.get("cve_id")
        patched = (vulnerability.get("first_patched_version") or {}).get("identifier")
        parts = [f"Package: {package}."]
        if patched:
            parts.append(f"Fixed in {patched}.")
        summary = str(advisory.get("summary") or "").strip()
        rows.append(
            row(
                f"dependabot:{repo}#{number}",
                "dependabot",
                f"{advisory.get('ghsa_id') or cve or 'Dependabot alert'}: {summary or package}"
                f" ({repo})",
                str(alert.get("html_url") or f"https://github.com/{repo}/security/dependabot"),
                kind="dependency-finding",
                published_at=_stamp(alert.get("created_at")),
                summary=" ".join(parts),
                cves=[cve] if cve else [],
                severity=advisory.get("severity") or vulnerability.get("severity"),
            )
        )
    return rows


# CVE List (cvelistV5)


def delta_log_new(text: str, since: datetime) -> list[dict]:
    """Newly published CVEs from the start of ``deltaLog.json``, newest block first.

    The file is large and fetched with a byte range, so it may end in the middle of a block.
    Blocks are read one by one and the cut block is dropped.
    """
    decoder = json.JSONDecoder()
    body = text.lstrip()
    if not body.startswith("["):
        return []
    index = 1
    found: dict[str, dict] = {}
    while True:
        while index < len(body) and body[index] in " \r\n\t,":
            index += 1
        if index >= len(body) or body[index] != "{":
            break
        try:
            block, index = decoder.raw_decode(body, index)
        except json.JSONDecodeError:
            break
        fetched = parse_time(block.get("fetchTime"))
        if fetched is None:
            continue
        if fetched < since:
            break
        for entry in block.get("new") or []:
            cve = str(entry.get("cveId") or "")
            link = str(entry.get("githubLink") or "")
            if CVE.fullmatch(cve) and link.startswith(_RAW_CVE_PREFIX):
                found.setdefault(cve.upper(), {"cve": cve.upper(), "link": link})
    return list(found.values())


def cve_record_row(record: dict) -> dict | None:
    meta = record.get("cveMetadata") if isinstance(record, dict) else None
    if not isinstance(meta, dict) or meta.get("state") != "PUBLISHED":
        return None
    cve = str(meta.get("cveId") or "")
    if not CVE.fullmatch(cve):
        return None
    cna = (record.get("containers") or {}).get("cna") or {}
    description = ""
    for item in cna.get("descriptions") or []:
        if str(item.get("lang", "")).startswith("en") and item.get("value"):
            description = str(item["value"])
            break
    title = str(cna.get("title") or "").strip() or description[:120]
    products = []
    for entry in cna.get("affected") or []:
        if isinstance(entry, dict) and entry.get("product"):
            products.append(f"{entry.get('vendor', '')} {entry['product']}".strip())
    severity = None
    for metric in cna.get("metrics") or []:
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
            data = metric.get(key) if isinstance(metric, dict) else None
            if isinstance(data, dict) and data.get("baseSeverity"):
                severity = data["baseSeverity"]
                break
        if severity:
            break
    parts = []
    if products:
        parts.append("Affects: " + ", ".join(dict.fromkeys(products[:5])) + ".")
    if description:
        parts.append(description)
    return row(
        f"cvelist:{cve}",
        "cvelist",
        f"{cve}: {title or 'new CVE record'}",
        f"https://www.cve.org/CVERecord?id={cve}",
        kind="vulnerability",
        published_at=_stamp(meta.get("datePublished")),
        summary=" ".join(parts) or None,
        cves=[cve],
        severity=severity,
    )


# Exploit-DB and Metasploit


def exploitdb_rows(text: str, since: datetime) -> list[dict]:
    """Exploits added to Exploit-DB at or after ``since`` (by ``date_added``)."""
    cutoff = since.astimezone(UTC).strftime("%Y-%m-%d")
    rows = []
    for record in csv.DictReader(io.StringIO(text)):
        added = str(record.get("date_added") or "")
        edb = str(record.get("id") or "").strip()
        if not edb.isdigit() or added < cutoff:
            continue
        codes = str(record.get("codes") or "")
        cves = CVE.findall(codes)
        parts = [
            f"Type: {record.get('type') or 'unknown'}.",
            f"Platform: {record.get('platform') or 'unknown'}.",
        ]
        if str(record.get("verified")) == "1":
            parts.append("Verified.")
        if cves:
            parts.append("Names " + ", ".join(sorted({c.upper() for c in cves})) + ".")
        rows.append(
            row(
                f"edb:{edb}",
                "exploit-db",
                f"EDB-{edb}: {record.get('description') or 'exploit'}",
                f"https://www.exploit-db.com/exploits/{edb}",
                kind="public-exploit",
                published_at=f"{added}T00:00:00Z",
                summary=" ".join(parts),
                cves=cves,
            )
        )
    rows.sort(key=lambda item: (item["published_at"] or "", item["id"]), reverse=True)
    return rows


def metasploit_rows(text: str, since: datetime) -> list[dict]:
    """Exploit modules, and modules that name a CVE, changed at or after ``since``."""
    try:
        modules = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(modules, dict):
        return []
    rows = []
    for module in modules.values():
        if not isinstance(module, dict):
            continue
        changed = parse_time(module.get("mod_time"))
        full = str(module.get("fullname") or "")
        if changed is None or changed < since or not re.fullmatch(r"[a-z0-9_/.-]{3,200}", full):
            continue
        cves = [ref for ref in module.get("references") or [] if CVE.fullmatch(str(ref))]
        if module.get("type") != "exploit" and not cves:
            continue
        disclosed = str(module.get("disclosure_date") or "")
        parts = [f"Module type: {module.get('type') or 'unknown'}."]
        if disclosed:
            parts.append(f"Disclosed {disclosed[:10]}.")
        if module.get("rank") is not None:
            parts.append(f"Rank {module['rank']}.")
        rows.append(
            row(
                f"msf:{full}",
                "metasploit",
                f"Metasploit {module.get('type') or 'module'}: {module.get('name') or full}"
                f" ({full})",
                f"https://www.rapid7.com/db/modules/{full}/",
                kind="public-exploit",
                published_at=iso(changed),
                summary=" ".join(parts),
                cves=cves,
            )
        )
    rows.sort(key=lambda item: (item["published_at"] or "", item["id"]), reverse=True)
    return rows


def _asset_key(asset: str) -> str:
    """A store-safe key for an asset name: a short slug plus a hash, so two names never collide."""
    slug = re.sub(r"[^a-z0-9]+", "-", asset.lower()).strip("-")[:40] or "asset"
    return f"{slug}-{hashlib.sha1(asset.encode(), usedforsecurity=False).hexdigest()[:6]}"


def _stamp(value) -> str | None:
    when = parse_time(value)
    return iso(when) if when else None


def _one_line(value, limit: int) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"
