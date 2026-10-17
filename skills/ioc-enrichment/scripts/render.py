"""Render an enrichment result. Pure helper: no network."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence

GUIDANCE = "This is guidance for an analyst, not legal advice or a formal assessment."
NO_STORE = "No store proposal. Nothing has been written."

_KINDS = {"ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256", "unknown"}
_VERDICTS = {"malicious", "suspicious", "benign", "unknown"}
_TLPS = {"CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"}
_HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}
_POINT_KEYS = ("malicious", "suspicious", "benign")
_CITATION_RE = re.compile(r"^[^,]+, [^,]+, retrieved \d{4}-\d{2}-\d{2}$")
_WHEN_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}Z)?$")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_COLUMNS = (
    "Indicator",
    "Type",
    "Verdict",
    "Confidence",
    "Sources",
    "First seen",
    "Last seen",
)


def citation_body(name: str, version: str, retrieved: str) -> str:
    if "," in name or "," in version:
        raise ValueError("citation name and version must not contain commas")
    if not name.strip() or not version.strip():
        raise ValueError("citation name and version are required")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", retrieved):
        raise ValueError("retrieved must be YYYY-MM-DD")
    return f"{name}, {version}, retrieved {retrieved}"


def citation_line(name: str, version: str, retrieved: str) -> str:
    return f"Source: {citation_body(name, version, retrieved)}"


def store_proposal(
    *,
    indicator: str,
    kind: str,
    verdict: str,
    confidence: int,
    sources: Sequence[str],
) -> str:
    if not sources:
        raise ValueError("a store proposal needs a source")
    label = "source" if len(sources) == 1 else "sources"
    listed = ", ".join(sources)
    return (
        f"Proposal: store an observation for {indicator}, type {kind}, "
        f"verdict {verdict}, confidence {confidence}, TLP:CLEAR, "
        f"{label} {listed}. Nothing has been written."
    )


def note_proposal(indicator: str) -> str:
    return (
        f"Proposal: store the analyst note for {indicator} at TLP:AMBER. "
        "Nothing has been written."
    )


def document(
    *,
    indicator: str,
    kind: str,
    verdict: str,
    confidence: int,
    points: Mapping[str, int],
    sources: Sequence[str],
    context_sources: Sequence[str],
    first_seen: str | None,
    last_seen: str | None,
    external_lookup: bool,
    from_store: bool,
    documentation: bool,
    refusal: str | None,
    citations: Sequence[str],
    excerpts: Sequence[tuple[str, str]] = (),
    missing_sources: Sequence[str] = (),
    proposals: Sequence[str] = (),
    tlp: str = "CLEAR",
) -> dict:
    """Build one result object. Raises if the object breaks the published shape."""
    item: dict = {
        "indicator": indicator,
        "type": kind,
        "verdict": verdict,
        "confidence": confidence,
        "points": {key: points[key] for key in _POINT_KEYS},
        "sources": list(sources),
        "context_sources": list(context_sources),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "tlp": tlp,
        "external_lookup": external_lookup,
        "from_store": from_store,
        "documentation": documentation,
        "citations": list(citations),
    }
    if refusal:
        item["refusal"] = refusal
    if excerpts:
        item["untrusted_excerpts"] = [
            {"source": source, "text": text} for source, text in excerpts
        ]
    body = {
        "indicators": [item],
        "missing_sources": sorted(missing_sources),
        "proposals": list(proposals),
    }
    problems = validate(body)
    if problems:
        raise ValueError("; ".join(problems))
    return body


def dumps(doc: Mapping) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


def markdown_table(doc: Mapping) -> str:
    header = "| " + " | ".join(_COLUMNS) + " |"
    separator = "|" + "|".join("---" for _ in _COLUMNS) + "|"
    rows = [header, separator]
    for item in doc["indicators"]:
        sources = ", ".join(item["sources"]) if item["sources"] else "none"
        cells = [
            item["indicator"],
            item["type"],
            item["verdict"],
            str(item["confidence"]),
            sources,
            item["first_seen"] or "unknown",
            item["last_seen"] or "unknown",
        ]
        rows.append("| " + " | ".join(_cell(value) for value in cells) + " |")
    return "\n".join(rows)


def validate(doc: Mapping) -> list[str]:
    """Return problems. An empty list means the object matches the published shape."""
    problems: list[str] = []
    if set(doc) != {"indicators", "missing_sources", "proposals"}:
        problems.append("result keys are indicators, missing_sources, proposals")
        return problems
    if not isinstance(doc["indicators"], list):
        return ["indicators must be a list"]
    if not isinstance(doc["missing_sources"], list) or not all(
        isinstance(item, str) and item for item in doc["missing_sources"]
    ):
        problems.append("missing_sources must be a list of strings")
    if not isinstance(doc["proposals"], list):
        problems.append("proposals must be a list")
    else:
        for proposal in doc["proposals"]:
            problems.extend(_proposal_problems(proposal))
    for item in doc["indicators"]:
        problems.extend(_indicator_problems(item))
    return problems


def _proposal_problems(proposal: object) -> list[str]:
    if not isinstance(proposal, str):
        return ["proposal must be a string"]
    problems = []
    if not proposal.startswith("Proposal: "):
        problems.append("proposal must start with 'Proposal: '")
    if "Nothing has been written." not in proposal:
        problems.append("proposal must say nothing has been written")
    if _IPV4_RE.search(proposal) or _EMAIL_RE.search(proposal):
        problems.append("proposal is not defanged")
    return problems


def _indicator_problems(item: object) -> list[str]:
    if not isinstance(item, dict):
        return ["indicator must be an object"]
    problems: list[str] = []
    required = {
        "indicator",
        "type",
        "verdict",
        "confidence",
        "points",
        "sources",
        "context_sources",
        "first_seen",
        "last_seen",
        "tlp",
        "external_lookup",
        "from_store",
        "documentation",
        "citations",
    }
    missing = required - set(item)
    if missing:
        problems.append("indicator missing " + ", ".join(sorted(missing)))
        return problems
    extra = set(item) - required - {"refusal", "untrusted_excerpts"}
    if extra:
        problems.append("indicator has unknown keys " + ", ".join(sorted(extra)))
    kind = item["type"]
    indicator = item["indicator"]
    if kind not in _KINDS or not isinstance(indicator, str) or not indicator:
        problems.append("indicator type or value is invalid")
    else:
        problems.extend(_display_problems(kind, indicator))
    if item["verdict"] not in _VERDICTS:
        problems.append("verdict is invalid")
    if type(item["confidence"]) is not int or not 0 <= item["confidence"] <= 100:
        problems.append("confidence must be an integer from 0 to 100")
    problems.extend(_points_problems(item["points"]))
    problems.extend(_string_list("sources", item["sources"]))
    problems.extend(_string_list("context_sources", item["context_sources"]))
    for label in ("first_seen", "last_seen"):
        value = item[label]
        if value is not None and (
            not isinstance(value, str) or not _WHEN_RE.fullmatch(value)
        ):
            problems.append(f"{label} must be a date or null")
    if item["tlp"] not in _TLPS:
        problems.append("tlp is invalid")
    for label in ("external_lookup", "from_store", "documentation"):
        if type(item[label]) is not bool:
            problems.append(f"{label} must be a boolean")
    if item["from_store"] and item["external_lookup"]:
        problems.append("a fresh store row does not call external connectors")
    if "refusal" in item:
        if not isinstance(item["refusal"], str) or not item["refusal"]:
            problems.append("refusal must be a string")
        elif item["external_lookup"]:
            problems.append("a refused indicator is not sent externally")
    if not isinstance(item["citations"], list) or not item["citations"]:
        problems.append("citations must be a non-empty list")
    elif any(not _valid_citation(value) for value in item["citations"]):
        problems.append("citation must be 'name, version, retrieved YYYY-MM-DD'")
    if "untrusted_excerpts" in item:
        problems.extend(_excerpt_problems(item["untrusted_excerpts"]))
    return problems


def _points_problems(points: object) -> list[str]:
    if not isinstance(points, dict) or set(points) != set(_POINT_KEYS):
        return ["points must be malicious, suspicious and benign"]
    problems = []
    for key in _POINT_KEYS:
        if type(points[key]) is not int or not 0 <= points[key] <= 100:
            problems.append(f"points.{key} must be an integer from 0 to 100")
    return problems


def _string_list(label: str, value: object) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        return [f"{label} must be a list of strings"]
    return []


def _display_problems(kind: str, indicator: str) -> list[str]:
    problems = []
    if kind == "ipv4" and _IPV4_RE.search(indicator):
        problems.append("ipv4 indicator is not defanged")
    if kind in {"domain", "url"} and "." in indicator.replace("[.]", ""):
        problems.append(f"{kind} indicator is not defanged")
    if kind == "url" and indicator.startswith(("http://", "https://")):
        problems.append("url indicator is not defanged")
    if kind == "email" and _EMAIL_RE.search(indicator):
        problems.append("email indicator is not defanged")
    if kind in _HASH_LENGTHS and not re.fullmatch(
        rf"[0-9a-f]{{{_HASH_LENGTHS[kind]}}}", indicator
    ):
        problems.append("hash indicator must be lowercase hex")
    return problems


def _excerpt_problems(value: object) -> list[str]:
    if not isinstance(value, list):
        return ["untrusted_excerpts must be a list"]
    problems = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"source", "text"}:
            problems.append("excerpt needs source and text")
            continue
        if not isinstance(item["source"], str) or not isinstance(item["text"], str):
            problems.append("excerpt source and text must be strings")
            continue
        if _IPV4_RE.search(item["text"]) or _EMAIL_RE.search(item["text"]):
            problems.append("untrusted excerpt is not defanged")
    return problems


def _valid_citation(value: object) -> bool:
    return isinstance(value, str) and _CITATION_RE.fullmatch(value) is not None


def _cell(value: str) -> str:
    return value.replace("|", "/").replace("\n", " ")
