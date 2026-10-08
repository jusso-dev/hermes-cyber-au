"""Parse an ASD ISM OSCAL catalogue into citation-tagged control chunks.

Control identifiers come only from the catalogue. Nothing here invents an ID.
"""

from __future__ import annotations

from typing import Any

from .common import parse_day, sha256_text, strip_emails

APPLICABILITY_FILES = {
    "NC": "ISM_NON_CLASSIFIED-baseline_profile.json",
    "OS": "ISM_OFFICIAL_SENSITIVE-baseline_profile.json",
    "P": "ISM_PROTECTED-baseline_profile.json",
    "S": "ISM_SECRET-baseline_profile.json",
    "TS": "ISM_TOP_SECRET-baseline_profile.json",
}


def _props(control: dict[str, Any], name: str) -> list[str]:
    values: list[str] = []
    for prop in control.get("props") or []:
        if prop.get("name") == name and prop.get("value"):
            values.append(str(prop["value"]))
    return values


def _statement(control: dict[str, Any]) -> str:
    pieces: list[str] = []

    def walk(parts: list[dict[str, Any]]) -> None:
        for part in parts:
            prose = (part.get("prose") or "").strip()
            if prose and part.get("name") in {None, "statement", "guidance", "overview"}:
                pieces.append(prose)
            nested = part.get("parts") or []
            if nested:
                walk(nested)

    walk(control.get("parts") or [])
    if not pieces:
        for part in control.get("parts") or []:
            prose = (part.get("prose") or "").strip()
            if prose:
                pieces.append(prose)
    return strip_emails("\n".join(pieces).strip())


def _profile_ids(profile_doc: dict[str, Any]) -> set[str]:
    profile = profile_doc.get("profile") or profile_doc
    found: set[str] = set()
    for imported in profile.get("imports") or []:
        for block in imported.get("include-controls") or []:
            for control_id in block.get("with-ids") or []:
                found.add(str(control_id))
    return found


def _profile_title(profile_doc: dict[str, Any]) -> str:
    profile = profile_doc.get("profile") or profile_doc
    return str((profile.get("metadata") or {}).get("title") or "")


def applicability_legend(
    controls: list[dict[str, Any]],
    profiles: dict[str, dict[str, Any]],
) -> dict[str, dict[str, str]]:
    """Bind each applicability code to the ASD profile whose membership matches it.

    The label is the profile title ASD published. If membership does not match,
    the code is left unlabelled rather than guessed.
    """
    by_code: dict[str, set[str]] = {code: set() for code in APPLICABILITY_FILES}
    for control in controls:
        for code in control["applicability"]:
            if code in by_code:
                by_code[code].add(control["control_id"])
    legend: dict[str, dict[str, str]] = {}
    for code, filename in APPLICABILITY_FILES.items():
        document = profiles.get(filename)
        if not document:
            legend[code] = {"code": code, "label": "", "verified": "profile_missing"}
            continue
        members = _profile_ids(document)
        title = _profile_title(document)
        verified = "exact" if members and members == by_code[code] else "not_exact"
        legend[code] = {
            "code": code,
            "label": title if verified == "exact" else "",
            "profile_file": filename,
            "verified": verified,
        }
    return legend


def parse_catalog(
    document: dict[str, Any],
    *,
    git_sha: str,
    mirror_url: str,
    canonical_url: str,
    profiles: dict[str, dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    catalog = document["catalog"]
    metadata = catalog.get("metadata") or {}
    version = str(metadata.get("version") or "")
    published = parse_day(str(metadata.get("published") or ""))
    if not version or not published:
        raise ValueError("ISM catalogue metadata is missing version or published date")

    chunks: list[dict[str, Any]] = []

    def walk(groups: list[dict[str, Any]], trail: list[str]) -> None:
        for group in groups:
            title = str(group.get("title") or "")
            here = trail + ([title] if title else [])
            for control in group.get("controls") or []:
                control_id = str(control.get("id") or "").strip()
                if not control_id.startswith("ism-"):
                    continue
                statement = _statement(control)
                if not statement:
                    continue
                applicability = _props(control, "applicability")
                e8 = _props(control, "essential-eight-applicability")
                text = statement
                chunks.append(
                    {
                        "chunk_id": f"asd-ism-oscal:{version}:{control_id}",
                        "source_id": "asd-ism-oscal",
                        "publisher": "Australian Signals Directorate",
                        "title": str(control.get("title") or control_id),
                        "section": " / ".join(here),
                        "control_id": control_id,
                        "text": text,
                        "applicability": applicability,
                        "essential_eight": e8,
                        "control_updated": " ".join(_props(control, "updated")),
                        "control_revision": " ".join(_props(control, "revision")),
                        "version": version,
                        "published": published,
                        "url": canonical_url,
                        "mirror_url": mirror_url,
                        "mirror_sha": git_sha,
                        "content_sha256": sha256_text(text),
                        "valid_from": published,
                        "valid_to": None,
                        "trust_tier_offered": "upstream_official",
                        "evidence_class": "prepared_not_observed",
                        "instructions": "data_only",
                        "instruction_like": False,
                    }
                )
            walk(group.get("groups") or [], here)

    walk(catalog.get("groups") or [], [])
    if not chunks:
        raise ValueError("ISM catalogue produced no controls")
    legend = applicability_legend(chunks, profiles or {})
    header = {
        "source_id": "asd-ism-oscal",
        "version": version,
        "published": published,
        "git_sha": git_sha,
        "control_count": len(chunks),
        "applicability_legend": legend,
        "canonical_url": canonical_url,
    }
    return chunks, header
