"""Rank CVE findings. No network.

Patch-by dates are calculated only from Essential Eight text the caller
supplies. This module does not contact a connector and does not apply a patch.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from datetime import date, datetime, time, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from zoneinfo import ZoneInfo

SYDNEY = ZoneInfo("Australia/Sydney")
RULES_PATH = Path(__file__).resolve().parents[1] / "references" / "ranking.json"
CONNECTOR_BATCH_CAP = 100

CVE_FIND = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_INSTRUCTION = re.compile(
    r"(?i)(ignore (?:all |the |previous )*instructions|send_alert|apply_patch|\bmcp__)"
)
_NUMBER = (
    r"\d+|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|fourteen|thirty"
)
_DURATION_RE = re.compile(
    rf"\b({_NUMBER})\s+(hour|hours|day|days|week|weeks|month|months)\b",
    re.IGNORECASE,
)
_WORDS = {
    "one": 1,
    "two": 2,
    "three": 3,
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
    "eight": 8,
    "nine": 9,
    "ten": 10,
    "eleven": 11,
    "twelve": 12,
    "fourteen": 14,
    "thirty": 30,
}
_ASSET_ALIASES = {
    "internet-facing": "internet-facing",
    "internet facing": "internet-facing",
    "external": "internet-facing",
    "dmz": "internet-facing",
    "perimeter": "internet-facing",
    "workstations-office": "workstations-office",
    "workstation": "workstations-office",
    "workstations": "workstations-office",
    "office": "workstations-office",
    "office-productivity": "workstations-office",
    "other": "other",
    "internal": "other",
    "internal-only": "other",
}
_ASSET_RANK = {"internet-facing": 0, "workstations-office": 1, "other": 2}
_ASSET_SENTENCE = {
    "internet-facing": ("internet-facing", "internet facing"),
    "workstations-office": ("office productivity", "workstation"),
    "other": ("other application",),
}
_CVE_HEADERS = ("cve", "cve id", "cveid", "vulnerability id", "vulnerabilityid")
_CVSS_HEADERS = (
    "cvss",
    "cvss score",
    "cvssscore",
    "cvss base",
    "cvss v3.0 base score",
    "cvss v3 base score",
)
_CLASS_HEADERS = ("asset class", "exposure")
_NAME_HEADERS = ("name", "title", "synopsis")
_ASSET_HEADERS = {
    "nessus": ("host",),
    "qualys": ("ip", "dns"),
    "defender": ("devicename", "device name", "machinename", "machine name"),
    "trivy": ("pkgname", "package", "package name"),
    "csv": ("asset", "host"),
}
_FORMAT_LABEL = {
    "nessus": "Nessus export",
    "qualys": "Qualys export",
    "defender": "Defender export",
    "trivy": "Trivy export",
    "csv": "scanner export",
    "cyclonedx": "CycloneDX SBOM",
    "spdx": "SPDX SBOM",
}
_URL_RE = re.compile(r"\b(https?)://([^\s/]+)(\S*)", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HOST_RE = re.compile(r"(?i)^((?:[a-z0-9-]+\.)+[a-z]{2,})((?::\d+)?(?:[/?#].*)?)$")
_COLUMNS = (
    "rank",
    "cve",
    "tier",
    "rule",
    "kev",
    "epss",
    "cvss",
    "au_mentions",
    "asset",
    "patch_by",
)


def load_rules(path: Path | None = None) -> dict:
    """Load the ranking rules. Raises ValueError when the file is not usable."""
    rules_path = path or RULES_PATH
    payload = json.loads(rules_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("rules file must be a JSON object")
    if not isinstance(payload.get("version"), str) or not payload["version"].strip():
        raise ValueError("rules version must be a string")
    size = payload.get("batch_size")
    if isinstance(size, bool) or not isinstance(size, int) or size < 1:
        raise ValueError("batch_size must be an integer of at least 1")
    rules = payload.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError("rules must be a non-empty list")
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get("id"), str) or not rule["id"]:
            raise ValueError("each rule needs an id")
        tier = rule.get("tier")
        if isinstance(tier, bool) or not isinstance(tier, int) or tier < 1:
            raise ValueError(f"rule {rule['id']} tier must be an integer of at least 1")
        when = rule.get("when")
        if not isinstance(when, dict) and when not in ("kev", "au_mention", "else"):
            raise ValueError(f"rule {rule['id']} has an unknown when")
    return payload


def batch_ids(cve_ids: list[str], size: int) -> list[list[str]]:
    """Split unique CVE ids into batches. Never returns a batch longer than 100."""
    unique: list[str] = []
    seen: set[str] = set()
    for cve in cve_ids:
        token = cve.upper()
        if not CVE_FIND.fullmatch(token) or token in seen:
            continue
        seen.add(token)
        unique.append(token)
    width = max(1, min(int(size), CONNECTOR_BATCH_CAP))
    return [unique[index : index + width] for index in range(0, len(unique), width)]


def normalise_asset(value: str | None, *, default: str = "other") -> str:
    if value is None or not str(value).strip():
        return default
    key = re.sub(r"\s+", " ", str(value).strip().lower().replace("_", "-"))
    return _ASSET_ALIASES.get(key, default)


def parse_input(text: str) -> tuple[list[dict], list[str]]:
    """Parse a CVE list, scanner CSV, or SBOM. Returns findings and warnings."""
    stripped = text.strip()
    if not stripped:
        return [], ["input was empty"]
    if stripped[0] in "[{":
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            payload = None
        if payload is not None:
            return _parse_json(payload)
    first = stripped.splitlines()[0]
    if "," in first:
        return _parse_csv(text)
    found = _unique_cves(stripped)
    if not found:
        return [], ["no CVE ids found"]
    return [_finding(cve, scanner_format="cve-list") for cve in found], []


def propose_patch_by(
    quote: str,
    *,
    reference: str | None,
    asset_class: str,
    exploit_known: bool,
) -> str:
    """Return a Sydney patch-by date, or empty when the quote does not say how long.

    A month written in the quote counts as 30 days. The caller keeps the quote
    so the reader can see the source wording. No duration is stored in this function.
    """
    delta = choose_duration(quote or "", asset_class, exploit_known)
    if delta is None or not reference:
        return ""
    try:
        start_date = date.fromisoformat(reference)
    except ValueError:
        return ""
    start = datetime.combine(start_date, time.min, tzinfo=SYDNEY)
    return (start + delta).astimezone(SYDNEY).date().isoformat()


def choose_duration(quote: str, asset_class: str, exploit_known: bool) -> timedelta | None:
    """Pick one duration from quoted text. Returns None when the quote has none."""
    if not quote.strip():
        return None
    if exploit_known and re.search(r"exploit", quote, re.IGNORECASE):
        for sentence in _sentences(quote):
            if not re.search(r"exploit", sentence, re.IGNORECASE):
                continue
            found = _durations(sentence)
            if not found:
                continue
            marker = re.search(r"exploit", sentence, re.IGNORECASE)
            before = [item for item in found if marker and item[0] < marker.start()]
            return (before or found)[-1][1]
    asset = normalise_asset(asset_class)
    for sentence in _sentences(quote):
        lowered = sentence.lower()
        if not any(word in lowered for word in _ASSET_SENTENCE.get(asset, ())):
            continue
        found = _durations(sentence)
        if found:
            return found[0][1]
    found = _durations(quote)
    if found:
        return found[0][1]
    return None


def defang_observable(value: str) -> str:
    """Defang one observable for display. Tool arguments stay raw."""
    text = value.strip()
    bare = _HOST_RE.fullmatch(text)
    if bare:
        return bare.group(1).replace(".", "[.]") + bare.group(2)

    def url_sub(match: re.Match[str]) -> str:
        scheme = "hxxps" if match.group(1).lower() == "https" else "hxxp"
        host = match.group(2).replace(".", "[.]")
        return f"{scheme}://{host}{match.group(3)}"

    text = _URL_RE.sub(url_sub, text)

    def email_sub(match: re.Match[str]) -> str:
        return f"{match.group(1)}[@]{match.group(2).replace('.', '[.]')}"

    text = _EMAIL_RE.sub(email_sub, text)
    return _IPV4_RE.sub(lambda match: match.group(0).replace(".", "[.]"), text)


def rank_findings(
    findings: list[dict],
    enrichment: dict,
    *,
    rules: dict | None = None,
    default_asset: str = "other",
    maturity: int | None = None,
    today: str | None = None,
) -> list[dict]:
    """Rank findings. enrichment is keyed by CVE id and may be empty."""
    if not isinstance(enrichment, dict):
        raise ValueError("enrichment must be an object keyed by CVE id")
    loaded = rules or load_rules()
    stamp = today or datetime.now(SYDNEY).date().isoformat()
    grouped: dict[str, list[dict]] = {}
    for finding in findings:
        cve = str(finding.get("cve", "")).upper()
        if not CVE_FIND.fullmatch(cve):
            continue
        grouped.setdefault(cve, []).append(finding)
    rows = [
        _rank_one(
            cve,
            group,
            enrichment.get(cve) or {},
            loaded,
            default_asset=default_asset,
            today=stamp,
        )
        for cve, group in grouped.items()
    ]
    rows.sort(key=_sort_key)
    for index, row in enumerate(rows, start=1):
        row["rank"] = index
        row["maturity"] = maturity
    return rows


def render_csv(rows: list[dict]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: _csv_cell(_export_value(row, key)) for key in _COLUMNS})
    return buffer.getvalue()


def render_markdown(rows: list[dict], *, maturity: int | None = None, limit: int = 30) -> str:
    lines = [
        "Guidance only. This is not legal advice, an audit, or a certification. "
        "No system was changed and nobody was notified.",
        "",
    ]
    level = maturity if maturity is not None else (rows[0]["maturity"] if rows else None)
    if level is not None:
        lines.append(f"Target maturity level: {level}.")
        lines.append("")
    missing = _dedupe(item for row in rows for item in row.get("missing_sources", []))
    if missing:
        lines.append("Missing sources: " + ", ".join(missing) + ".")
        lines.append("")
    lines.extend(
        [
            "| rank | CVE | tier | rule | KEV | EPSS | CVSS | AU mentions | asset | patch-by |",
            "|---:|---|---|---|---|---|---|---|---|---|",
        ]
    )
    shown = rows[:limit]
    for row in shown:
        cells = [
            str(row["rank"]),
            row["cve"],
            _tier_text(row),
            row["rule"],
            row["kev"],
            row["epss"],
            row["cvss"],
            row["au_mentions"],
            row["asset"],
            row["patch_by"],
        ]
        lines.append("| " + " | ".join(_md_cell(cell) for cell in cells) + " |")
    lines.append("")
    if len(rows) > limit:
        lines.append(f"Showing {limit} of {len(rows)}. The CSV has every row.")
        lines.append("")
    for row in shown:
        for note in row.get("untrusted_notes", []):
            text = defang_observable(str(note.get("text") or "")).replace("Source:", "source:")
            text = text.replace("\n", " ")
            source = note.get("source") or "connector"
            lines.append(f"{source} text was treated as untrusted content: {text}")
    if any(row.get("untrusted_notes") for row in shown):
        lines.append("")
    proposals = _proposals(rows)
    lines.extend(proposals)
    if proposals:
        lines.append("")
    citations = _dedupe(_citation(source) for row in rows for source in row.get("sources", []))
    lines.extend(citations)
    if citations:
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Rank CVE findings offline. No network.")
    parser.add_argument("input_path", nargs="?")
    parser.add_argument("--enrichment", required=True)
    parser.add_argument("--rules")
    parser.add_argument("--asset-class", default="other")
    parser.add_argument("--maturity", type=int)
    parser.add_argument("--format", choices=("markdown", "csv"), default="markdown")
    parser.add_argument("--today")
    args = parser.parse_args(argv)
    if args.input_path:
        text = Path(args.input_path).read_text(encoding="utf-8")
    else:
        text = sys.stdin.read()
    findings, warnings = parse_input(text)
    enrichment = json.loads(Path(args.enrichment).read_text(encoding="utf-8"))
    rules = load_rules(Path(args.rules)) if args.rules else load_rules()
    rows = rank_findings(
        findings,
        enrichment,
        rules=rules,
        default_asset=args.asset_class,
        maturity=args.maturity,
        today=args.today,
    )
    if args.format == "csv":
        sys.stdout.write(render_csv(rows))
    else:
        sys.stdout.write(render_markdown(rows, maturity=args.maturity))
    if warnings:
        print("\n".join(warnings), file=sys.stderr)
    return 0


def _rank_one(
    cve: str,
    group: list[dict],
    extra: dict,
    rules: dict,
    *,
    default_asset: str,
    today: str,
) -> dict:
    asset_class = _asset_class(group, extra, default_asset)
    context = _context(group, extra, asset_class)
    warnings: list[str] = []
    missing = [str(item) for item in extra.get("missing_sources") or []]
    if context["kev_checked"] is False:
        warnings.append("KEV was not checked")
    if context["epss_checked"] is False:
        warnings.append("EPSS was not checked")
    if context["nvd_checked"] is False:
        warnings.append("NVD was not checked")
    if context["au_checked"] is False:
        warnings.append("Australian advisories were not checked")
    notes = _notes(group, extra)
    quote = str(extra.get("e8_quote") or "")
    if not quote.strip():
        if "Essential Eight" in missing:
            warnings.append("patch-by not set: Essential Eight connector unavailable")
        else:
            warnings.append("patch-by not set: Essential Eight text was not supplied")
        patch_by = ""
    else:
        reference = extra.get("reference_date")
        patch_by = propose_patch_by(
            quote,
            reference=reference if isinstance(reference, str) else None,
            asset_class=asset_class,
            exploit_known=context["exploit_known"],
        )
        if not patch_by:
            warnings.append("patch-by not set: the Essential Eight quote had no usable duration")
    if context["known"]:
        rule = _winning_rule(rules["rules"], context)
        status = "ranked"
        tier = rule["tier"]
        rule_id = rule["id"]
    elif context["any_checked"]:
        status = "unknown"
        tier = None
        rule_id = "no-record"
        warnings.append("no matching record")
    else:
        status = "not-enriched"
        tier = None
        rule_id = "not-enriched"
    sources = _sources(group, extra, context, today)
    names = _dedupe(
        _csv_cell(defang_observable(str(item.get("asset"))))
        for item in group
        if item.get("asset")
    )
    return {
        "rank": 0,
        "cve": cve,
        "tier": tier,
        "rule": rule_id,
        "status": status,
        "kev": _kev_text(extra.get("kev")),
        "epss": _epss_text(extra.get("epss")),
        "cvss": _cvss_text(context),
        "au_mentions": _au_text(extra.get("au")),
        "asset": _asset_text(asset_class, names),
        "patch_by": patch_by or "not set",
        "warnings": warnings,
        "missing_sources": _dedupe(missing),
        "sources": sources,
        "untrusted_notes": notes,
        "maturity": None,
        "_epss": context["epss"],
        "_cvss": context["cvss"],
    }


def _context(group: list[dict], extra: dict, asset_class: str) -> dict:
    kev = extra.get("kev") if "kev" in extra else None
    epss = extra.get("epss") if "epss" in extra else None
    nvd = extra.get("nvd") if "nvd" in extra else None
    au = extra.get("au") if "au" in extra else None
    kev_listed = bool(kev.get("listed")) if isinstance(kev, dict) else None
    epss_score = _decimal(epss.get("score")) if isinstance(epss, dict) else None
    nvd_found = bool(nvd.get("found")) if isinstance(nvd, dict) else None
    nvd_cvss = _decimal(nvd.get("cvss")) if isinstance(nvd, dict) and nvd.get("found") else None
    nvd_cvss_text = ""
    if isinstance(nvd, dict) and nvd.get("found") and nvd.get("cvss") not in (None, ""):
        nvd_cvss_text = str(nvd.get("cvss"))
    scanner_pairs = []
    for item in group:
        raw = item.get("scanner_cvss")
        if raw in (None, ""):
            continue
        number = _decimal(raw)
        if number is not None:
            scanner_pairs.append((number, str(raw)))
    scanner_cvss = max(scanner_pairs)[0] if scanner_pairs else None
    scanner_text = max(scanner_pairs)[1] if scanner_pairs else ""
    cvss = nvd_cvss if nvd_cvss is not None else scanner_cvss
    au_count = len(au) if isinstance(au, list) else 0
    known = bool(
        kev_listed
        or au_count
        or epss_score is not None
        or nvd_found
        or scanner_cvss is not None
    )
    return {
        "kev_listed": kev_listed if isinstance(kev, dict) else None,
        "kev_checked": isinstance(kev, dict),
        "epss": epss_score,
        "epss_checked": isinstance(epss, dict),
        "nvd_found": nvd_found if isinstance(nvd, dict) else None,
        "nvd_checked": isinstance(nvd, dict),
        "cvss": cvss,
        "cvss_display": nvd_cvss_text or scanner_text,
        "cvss_from_scanner": nvd_cvss is None and scanner_cvss is not None,
        "scanner_cvss": scanner_cvss,
        "au_count": au_count,
        "au_checked": isinstance(au, list),
        "asset_class": asset_class,
        "exploit_known": bool(kev_listed) or au_count > 0,
        "known": known,
        "any_checked": any(
            (
                isinstance(kev, dict),
                isinstance(epss, dict),
                isinstance(nvd, dict),
                isinstance(au, list),
            )
        ),
    }


def _winning_rule(rules: list[dict], context: dict) -> dict:
    matches = [rule for rule in rules if _matches(rule, context)]
    if not matches:
        return {"id": "unmatched", "tier": 3, "when": "else"}
    return min(enumerate(matches), key=lambda item: (item[1]["tier"], item[0]))[1]


def _matches(rule: dict, context: dict) -> bool:
    when = rule.get("when")
    if when == "else":
        return True
    if when == "kev":
        return context["kev_listed"] is True
    if when == "au_mention":
        return context["au_count"] > 0
    if not isinstance(when, dict) or not when:
        return False
    matched = False
    if "epss_gte" in when:
        matched = True
        if context["epss"] is None or context["epss"] < _decimal(when["epss_gte"]):
            return False
    if "cvss_gte" in when:
        matched = True
        if context["cvss"] is None or context["cvss"] < _decimal(when["cvss_gte"]):
            return False
    if "asset" in when:
        matched = True
        if context["asset_class"] != normalise_asset(str(when["asset"])):
            return False
    return matched


def _asset_class(group: list[dict], extra: dict, default_asset: str) -> str:
    explicit: list[str] = []
    if extra.get("asset_class"):
        explicit.append(normalise_asset(str(extra["asset_class"])))
    for finding in group:
        if finding.get("asset_class"):
            explicit.append(normalise_asset(str(finding["asset_class"])))
    if not explicit:
        return normalise_asset(default_asset)
    chosen = explicit[0]
    for item in explicit[1:]:
        if _ASSET_RANK[item] < _ASSET_RANK[chosen]:
            chosen = item
    return chosen


def _sources(group: list[dict], extra: dict, context: dict, today: str) -> list[dict]:
    sources = []
    for key in ("kev", "epss", "nvd"):
        block = extra.get(key)
        if isinstance(block, dict) and block.get("source"):
            sources.append(_source_block(block))
    if isinstance(extra.get("au"), list):
        for mention in extra["au"]:
            if isinstance(mention, dict) and mention.get("source"):
                sources.append(_source_block(mention))
        if not extra["au"] and extra.get("au_source"):
            sources.append(_source_block(extra["au_source"]))
    if context["cvss_from_scanner"]:
        label = _FORMAT_LABEL.get(str(group[0].get("scanner_format")), "scanner export")
        sources.append({"name": label, "version": "none", "retrieved": today})
    return [item for item in sources if item["retrieved"]]


def _source_block(block: dict) -> dict:
    return {
        "name": str(block.get("source")),
        "version": str(block.get("version") or "none"),
        "retrieved": sydney_day(str(block.get("retrieved_at") or "")),
    }


def _notes(group: list[dict], extra: dict) -> list[dict]:
    notes = []
    for finding in group:
        name = str(finding.get("name") or "")
        if _INSTRUCTION.search(name):
            notes.append({"source": finding.get("scanner_format") or "scanner", "text": name})
    for item in extra.get("untrusted") or []:
        if isinstance(item, str) and item.strip():
            notes.append({"source": "connector", "text": item})
        elif isinstance(item, dict) and str(item.get("text") or "").strip():
            notes.append({"source": item.get("source") or "connector", "text": str(item["text"])})
    return notes


def _proposals(rows: list[dict]) -> list[str]:
    lines = []
    tier3 = False
    for row in rows:
        if row["tier"] in {1, 2}:
            lines.append(
                f"Proposal: schedule {row['cve']} for patching at tier {row['tier']} "
                f"under rule {row['rule']}. Reversible by not applying the change."
            )
        elif row["tier"] == 3:
            tier3 = True
    if tier3:
        lines.append(
            "Proposal: schedule tier 3 findings after higher tiers. "
            "Reversible by not applying the change."
        )
    return lines


def _parse_json(payload: object) -> tuple[list[dict], list[str]]:
    if isinstance(payload, dict) and payload.get("bomFormat") == "CycloneDX":
        cves = _unique_cves_from(
            [
                item.get("id", "")
                for item in payload.get("vulnerabilities") or []
                if isinstance(item, dict)
            ]
        )
        return [_finding(cve, scanner_format="cyclonedx") for cve in cves], []
    if isinstance(payload, dict) and payload.get("spdxVersion"):
        locators = []
        for package in payload.get("packages") or []:
            if not isinstance(package, dict):
                continue
            for ref in package.get("externalRefs") or []:
                if isinstance(ref, dict):
                    locators.append(str(ref.get("referenceLocator") or ""))
        cves = _unique_cves_from(locators)
        return [_finding(cve, scanner_format="spdx") for cve in cves], []
    if isinstance(payload, list) and payload and all(isinstance(item, str) for item in payload):
        cves = _unique_cves_from(payload)
        return [_finding(cve, scanner_format="cve-list") for cve in cves], []
    trivy_rows = isinstance(payload, list) and any(
        isinstance(item, dict) and _trivy_id(item) for item in payload
    )
    if trivy_rows:
        findings = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            cve = _trivy_id(item)
            if not cve:
                continue
            findings.append(
                _finding(
                    cve,
                    asset=str(item.get("PkgName") or ""),
                    scanner_cvss=_plain_cvss(item.get("CVSS")),
                    scanner_format="trivy",
                    name=str(item.get("Title") or ""),
                )
            )
        return findings, []
    return [], ["JSON was not a known SBOM or CVE list"]


def _parse_csv(text: str) -> tuple[list[dict], list[str]]:
    reader = csv.DictReader(io.StringIO(text.lstrip("\ufeff")))
    if not reader.fieldnames:
        return [], ["header was not a known scanner export"]
    headers = [_header(name) for name in reader.fieldnames if name]
    kind = _csv_kind(headers)
    if kind is None:
        return [], ["header was not a known scanner export"]
    findings = []
    warnings = []
    for number, raw in enumerate(reader, start=2):
        mapped = {
            _header(key): (value or "").strip()
            for key, value in raw.items()
            if key is not None
        }
        cell = _first(mapped, _CVE_HEADERS)
        cves = _unique_cves(cell)
        if not cves:
            warnings.append(f"row {number} has no CVE id")
            continue
        asset = _first(mapped, _ASSET_HEADERS[kind])
        asset_class = _first(mapped, _CLASS_HEADERS)
        cvss = _first(mapped, _CVSS_HEADERS)
        name = _first(mapped, _NAME_HEADERS)
        for cve in cves:
            findings.append(
                _finding(
                    cve,
                    asset=asset,
                    asset_class=asset_class,
                    scanner_cvss=cvss,
                    scanner_format=kind,
                    name=name,
                )
            )
    if not findings and not warnings:
        warnings.append("no rows")
    return findings, warnings


def _csv_kind(headers: list[str]) -> str | None:
    header_set = set(headers)
    if "vulnerabilityid" in header_set or "vulnerability id" in header_set:
        return "trivy"
    if {"cveid", "cve id"} & header_set and {
        "devicename",
        "device name",
        "machinename",
        "machine name",
    } & header_set:
        return "defender"
    if "qid" in header_set and ({"cve", "cve id"} & header_set):
        return "qualys"
    if "plugin id" in header_set and "cve" in header_set:
        return "nessus"
    if {"cve", "cve id", "cveid"} & header_set:
        return "csv"
    return None


def _finding(
    cve: str,
    *,
    asset: str = "",
    asset_class: str = "",
    scanner_cvss: str = "",
    scanner_format: str = "",
    name: str = "",
) -> dict:
    return {
        "cve": cve.upper(),
        "asset": asset,
        "asset_class": asset_class,
        "scanner_cvss": scanner_cvss,
        "scanner_format": scanner_format,
        "name": name,
    }


def _header(name: str) -> str:
    return re.sub(r"\s+", " ", name.replace("_", " ").strip().lower())


def _first(mapped: dict, keys: tuple[str, ...]) -> str:
    for key in keys:
        if mapped.get(key):
            return mapped[key]
    return ""


def _trivy_id(item: dict) -> str:
    raw = item.get("VulnerabilityID") or item.get("vulnerabilityID") or ""
    found = _unique_cves(str(raw))
    return found[0] if found else ""


def _plain_cvss(value: object) -> str:
    if isinstance(value, str | int | float) and not isinstance(value, bool):
        return str(value)
    return ""


def _unique_cves(text: str) -> list[str]:
    return _unique_cves_from([text])


def _unique_cves_from(values: list[object]) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for value in values:
        for match in CVE_FIND.findall(str(value)):
            token = match.upper()
            if token not in seen:
                seen.add(token)
                found.append(token)
    return found


def _sentences(quote: str) -> list[str]:
    return [part.strip() for part in re.split(r"(?<=[.])\s+", quote.strip()) if part.strip()]


def _durations(text: str) -> list[tuple[int, timedelta]]:
    found = []
    for match in _DURATION_RE.finditer(text):
        found.append((match.start(), _to_delta(match.group(1), match.group(2))))
    return found


def _to_delta(number: str, unit: str) -> timedelta:
    value = int(number) if number.isdigit() else _WORDS[number.lower()]
    name = unit.lower()
    if name.startswith("hour"):
        return timedelta(hours=value)
    if name.startswith("day"):
        return timedelta(days=value)
    if name.startswith("week"):
        return timedelta(days=7 * value)
    return timedelta(days=30 * value)


def _decimal(value: object) -> Decimal | None:
    if value is None or value == "":
        return None
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None


def sydney_day(value: str) -> str:
    text = value.strip()
    if not text:
        return ""
    if "T" not in text:
        return text[:10]
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return parsed.astimezone(SYDNEY).date().isoformat()


def _kev_text(kev: object) -> str:
    if not isinstance(kev, dict):
        return "not checked"
    if not kev.get("listed"):
        return "no"
    due = str(kev.get("due_date") or "")
    return f"yes, due {due}" if due else "yes"


def _epss_text(epss: object) -> str:
    if not isinstance(epss, dict):
        return "not checked"
    score = epss.get("score")
    if score is None or score == "":
        return "none"
    text = str(score)
    percentile = epss.get("percentile")
    if percentile not in (None, ""):
        text += f" (p {percentile})"
    return text


def _cvss_text(context: dict) -> str:
    if context["cvss_display"]:
        return context["cvss_display"]
    if context["nvd_checked"]:
        return "none"
    return "not checked"


def _au_text(au: object) -> str:
    if not isinstance(au, list):
        return "not checked"
    if not au:
        return "none"
    names = []
    for item in au:
        if isinstance(item, dict):
            names.append(str(item.get("publisher") or item.get("source") or "AU"))
    return ", ".join(names) if names else "none"


def _asset_text(asset_class: str, names: list[str]) -> str:
    if not names:
        return asset_class
    shown = names[:3]
    text = ", ".join(shown)
    extra = len(names) - len(shown)
    if extra:
        text += f" and {extra} more"
    return f"{asset_class}: {text}"


def _sort_key(row: dict) -> tuple:
    tier = row["tier"] if isinstance(row["tier"], int) else 99
    epss = row["_epss"] if row["_epss"] is not None else Decimal("-1")
    cvss = row["_cvss"] if row["_cvss"] is not None else Decimal("-1")
    return (tier, -epss, -cvss, row["cve"])


def _tier_text(row: dict) -> str:
    if row["tier"] is None:
        return "unranked"
    return str(row["tier"])


def _export_value(row: dict, key: str) -> object:
    if key == "tier":
        return _tier_text(row)
    return row.get(key, "")


def _csv_cell(value: object) -> str:
    text = "" if value is None else str(value)
    if text.startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def _md_cell(value: object) -> str:
    return str(value).replace("|", "/").replace("\n", " ")


def _citation(source: dict) -> str:
    return f"Source: {source['name']}, {source['version']}, retrieved {source['retrieved']}"


def _dedupe(items) -> list:
    seen: list = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen


if __name__ == "__main__":
    raise SystemExit(main())
