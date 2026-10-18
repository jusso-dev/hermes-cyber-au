"""Read-only Essential Eight and ASD Essentials connector.

Essential Eight maturity levels and ASD Essentials priority phases are different
scales. A phase number is never returned as a maturity score.
"""

import hashlib
import json
import os
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Annotated, Literal

from cyberau_common import GOV_AU_USER_AGENT as USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector
from pydantic import Field

_Strategy = Literal[
    "patch_applications",
    "patch_operating_systems",
    "multi_factor_authentication",
    "restrict_admin_privileges",
    "application_control",
    "restrict_office_macros",
    "user_application_hardening",
    "regular_backups",
]
_Chapter = Literal["enterprise-it", "cloud", "ot"]
_Level = Annotated[int, Field(ge=1, le=3)]
_Domain = Annotated[str, Field(min_length=2)]

ATTRIBUTION = (
    "Essential Eight and ASD Essentials material is published by the Australian "
    "Signals Directorate. Essential Eight maturity levels are not ASD Essentials "
    "priority phases. Priority phases only sequence work. They are not a maturity, "
    "compliance or assurance rating. This connector is not endorsed by ASD."
)
ISM_RELEASE = "v2026.09.4"
RAW_ROOT = "https://raw.githubusercontent.com/AustralianCyberSecurityCentre/ism-oscal"
CHAPTERS = {
    "enterprise-it": "https://www.cyber.gov.au/publication/essentials-for-enterprise-it",
    "cloud": "https://www.cyber.gov.au/publication/essentials-for-cloud",
    "ot": "https://www.cyber.gov.au/publication/essentials-for-ot",
}
TRANSITION_URL = "https://www.cyber.gov.au/publication/transitioning-from-the-essential-eight"
LAUNCH_URL = "https://www.asd.gov.au/news/2026-10-15-asd-essentials-evolving-our-approach-cyber-security-resilience"
_PACKAGE = Path(__file__).resolve().parents[2]
_TRANSPORT = None
_SLEEP = __import__("time").sleep
_PHASE = re.compile(r"^Priority phase (\d+)\s*:\s*(.+)$", re.IGNORECASE)
# Escapes keep the source free of literal dashes and ticks for the style check.
_PRINCIPLE = re.compile(r"^([A-Z]{2,5}-\d+)\s*(?:[-\u2013\u2014]\s*)?(.+)$")
_PUBLISHED = re.compile(r"Published\s+(\d{1,2}\s+[A-Za-z]+\s+\d{4})")
_TICK_MARKS = ("\u2714", "\u2713")
_TICKS = {*_TICK_MARKS, "yes", "y"}
_SECTION_STRATEGY = {
    "application control": "application_control",
    "multi-factor authentication": "multi_factor_authentication",
    "privileged access to systems": "restrict_admin_privileges",
    "separate privileged operating environments": "restrict_admin_privileges",
    "administrative infrastructure": "restrict_admin_privileges",
    "protecting credentials": "restrict_admin_privileges",
    "suspension of access to systems": "restrict_admin_privileges",
    (
        "setting credentials for built-in administrator accounts, break glass accounts, "
        "local administrator accounts and service accounts"
    ): "restrict_admin_privileges",
    "web browsers": "user_application_hardening",
    "portable document format applications": "user_application_hardening",
    "command shell": "user_application_hardening",
    "powershell": "user_application_hardening",
    "performing and retaining backups": "regular_backups",
    "backup access": "regular_backups",
    "backup modification and deletion": "regular_backups",
    "testing restoration of backups": "regular_backups",
    "operating system releases and versions": "patch_operating_systems",
}
_PATCH_SECTIONS = {
    "mitigating known vulnerabilities",
    "vulnerability scanning",
    "cessation of support",
}
_STRATEGY_LABELS = {
    "application_control": "Application control",
    "patch_applications": "Patch applications",
    "patch_operating_systems": "Patch operating systems",
    "multi_factor_authentication": "Multi-factor authentication",
    "restrict_admin_privileges": "Restrict administrative privileges",
    "restrict_office_macros": "Restrict Microsoft Office macros",
    "user_application_hardening": "User application hardening",
    "regular_backups": "Regular backups",
}
_STRATEGY_ALIASES = {label.lower(): key for key, label in _STRATEGY_LABELS.items()}
_STRATEGY_ALIASES.update({key: key for key in _STRATEGY_LABELS})
_STRATEGY_ALIASES["restrict admin privileges"] = "restrict_admin_privileges"
_STRATEGY_ALIASES["restrict office macros"] = "restrict_office_macros"
_STRATEGY_ALIASES["multi factor authentication"] = "multi_factor_authentication"


def e8_requirements(strategy: _Strategy, maturity_level: _Level) -> dict:
    """Essential Eight requirements for one mitigation strategy at one maturity level."""
    chosen = _strategy_key(strategy)
    level, level_problem = _level(maturity_level)
    if chosen is None or level_problem:
        return _envelope(
            None,
            "snapshot",
            warnings=(level_problem or "strategy is not an Essential Eight mitigation strategy",),
        )
    maturity, cache, warning = _maturity()
    if maturity is None:
        return _envelope(
            None,
            cache,
            warnings=(warning or "Essential Eight snapshot was not usable",),
        )
    rows = []
    for control in maturity.get("controls") or []:
        if control.get("strategy") != chosen:
            continue
        if level not in (control.get("maturity_levels") or []):
            continue
        rows.append(
            {
                "control_id": control["control_id"],
                "strategy": chosen,
                "maturity_level": level,
                "maturity_levels": list(control["maturity_levels"]),
                "section": _quote(control.get("section") or ""),
                "statement": _quote(control.get("statement") or ""),
                "updated": control.get("updated") or "",
            }
        )
    warnings = [warning] if warning else []
    if not rows:
        warnings.append(f"no {_STRATEGY_LABELS[chosen]} controls apply at maturity level {level}")
    cross = _cross_cutting(maturity, level)
    if cross:
        warnings.append(
            "Event logging and incident reporting controls in this catalogue "
            "are not part of one mitigation strategy. They are listed in cross_cutting."
        )
    urls = list(maturity.get("source_urls") or [])
    return _envelope(
        {
            "strategy": chosen,
            "strategy_label": _STRATEGY_LABELS[chosen],
            "maturity_level": level,
            "scale": "essential_eight_maturity_level",
            "not_an_essentials_priority_phase": True,
            "ism_release": maturity.get("ism_release") or ISM_RELEASE,
            "controls": rows,
            "cross_cutting": cross,
        },
        cache,
        urls,
        maturity.get("retrieved_on"),
        tuple(item for item in warnings if item),
    )


def essentials_chapter(chapter: _Chapter, domain: _Domain | None = None) -> dict:
    """Domains, principles, actions and priority phases for one ASD Essentials chapter."""
    if chapter not in CHAPTERS:
        return _envelope(None, "snapshot", warnings=("chapter must be enterprise-it, cloud or ot",))
    essentials, cache, warning = _essentials()
    if essentials is None:
        return _envelope(None, cache, warnings=(warning or "Essentials snapshot was not usable",))
    page = (essentials.get("chapters") or {}).get(chapter)
    if not isinstance(page, dict):
        return _envelope(
            None,
            cache,
            [CHAPTERS[chapter]],
            warnings=(f"{chapter} is not in the snapshot",),
        )
    selected = domain.strip() if isinstance(domain, str) else ""
    actions = []
    known = [item.get("name") or "" for item in page.get("domains") or []]
    matched = _matching_domains(selected, known) if selected else []
    if selected and not matched:
        names = ", ".join(name for name in known if name) or "none"
        return _envelope(
            _chapter_body(chapter, page, actions=[], domain=selected),
            cache,
            [page.get("url") or CHAPTERS[chapter]],
            essentials.get("retrieved_on"),
            (f"no domain named {selected!r}. Chapters name: {names}",),
        )
    for action in page.get("actions") or []:
        if selected and not _action_in_domain(action, matched):
            continue
        actions.append(_public_action(action))
    warnings = [warning] if warning else []
    if selected and not actions:
        warnings.append(f"no actions in {chapter} apply to {selected}")
    return _envelope(
        _chapter_body(chapter, page, actions=actions, domain=selected or None),
        cache,
        [page.get("url") or CHAPTERS[chapter]],
        essentials.get("retrieved_on"),
        tuple(item for item in warnings if item),
    )


def essentials_transition(strategy: str) -> dict:
    """How one Essential Eight strategy maps into Essentials, quoted from ASD only."""
    if not isinstance(strategy, str) or not strategy.strip():
        return _envelope(None, "snapshot", warnings=("strategy is required",))
    chosen = _strategy_key(strategy)
    essentials, cache, warning = _essentials()
    if essentials is None:
        return _envelope(None, cache, warnings=(warning or "Essentials snapshot was not usable",))
    transition = essentials.get("transition") or {}
    if chosen is None:
        return _envelope(
            None,
            cache,
            [transition.get("url") or TRANSITION_URL],
            warnings=(
                "strategy was not found in ASD's transition guidance. "
                "Use an Essential Eight mitigation strategy name.",
            ),
        )
    block = (transition.get("strategies") or {}).get(chosen)
    if not isinstance(block, dict):
        return _envelope(
            None,
            cache,
            [transition.get("url") or TRANSITION_URL],
            warnings=(f"ASD's transition guidance has no mapping for {_STRATEGY_LABELS[chosen]}",),
        )
    mappings = []
    for row in block.get("mappings") or []:
        mappings.append(
            {
                "principle": _quote(row.get("principle") or ""),
                "action": _quote(row.get("action") or ""),
                "domain_coverage": _quote(row.get("domain_coverage") or ""),
                "existing_contribution": _quote(row.get("existing_contribution") or ""),
            }
        )
    return _envelope(
        {
            "strategy": chosen,
            "strategy_label": block.get("label") or _STRATEGY_LABELS[chosen],
            "principles": [_quote(item) for item in block.get("principles") or []],
            "mappings": mappings,
            "quoted_from": transition.get("url") or TRANSITION_URL,
            "priority_phases_are_not_maturity_levels": True,
        },
        cache,
        [transition.get("url") or TRANSITION_URL],
        essentials.get("retrieved_on"),
        (warning,) if warning else (),
    )


def connector() -> Connector:
    class EssentialsConnector(Connector):
        def health(self, *, live: bool, check_schema: bool = False) -> Probe:
            if check_schema and not live:
                maturity, essentials, problem = _snapshot_pair()
                if problem:
                    return Probe(self.key, False, problem)
                drift = schema_drift(maturity, essentials)
                if drift:
                    return Probe(self.key, False, drift)
                return Probe(self.key, True, "schema ok")
            if not live:
                return Probe(self.key, True, "offline ok")
            text, cache, warning = _http(CHAPTERS["enterprise-it"], ttl=86400, skip_cache=True)
            if warning or not text:
                return Probe(self.key, False, warning or "Essentials page was not usable")
            if cache == "stale":
                return Probe(
                    self.key,
                    False,
                    "live fetch failed and only a stale cache was available",
                )
            if "essentials" not in text.lower() or "priority phase" not in text.lower():
                return Probe(self.key, False, "Essentials page no longer has the expected wording")
            catalog_url = (
                f"{RAW_ROOT}/{ISM_RELEASE}/ISM_E8_ML1-baseline-resolved-profile_catalog.json"
            )
            catalog, catalog_cache, catalog_warning = _http(catalog_url, ttl=86400, skip_cache=True)
            if catalog_warning or not catalog:
                detail = catalog_warning or "Essential Eight catalogue was not usable"
                return Probe(self.key, False, detail)
            if catalog_cache == "stale":
                return Probe(
                    self.key,
                    False,
                    "Essential Eight catalogue live fetch failed",
                )
            if '"catalog"' not in catalog and '"controls"' not in catalog:
                return Probe(
                    self.key,
                    False,
                    "Essential Eight catalogue no longer has the expected shape",
                )
            return Probe(self.key, True, "live ok")

    return EssentialsConnector(
        key="asd-essentials",
        server_name="e8",
        attribution=ATTRIBUTION,
        tools=[
            ToolSpec(
                "e8_requirements",
                "Essential Eight requirements for one strategy at one maturity level.",
                e8_requirements,
            ),
            ToolSpec(
                "essentials_chapter",
                "Principles, actions, domains and priority phases for one chapter.",
                essentials_chapter,
            ),
            ToolSpec(
                "essentials_transition",
                "ASD's quoted mapping from one Essential Eight strategy into Essentials.",
                essentials_transition,
            ),
        ],
    )


def schema_drift(maturity, essentials) -> str | None:
    if not isinstance(maturity, dict):
        return "E8 payload is not an object"
    controls = maturity.get("controls")
    if not isinstance(controls, list):
        return "E8 schema drift, missing controls"
    if controls:
        row = controls[0]
        if not isinstance(row, dict):
            return "E8 schema drift, control is not an object"
        for key in ("control_id", "strategy", "maturity_levels", "statement"):
            if key not in row:
                return f"E8 schema drift, missing {key}"
    if not isinstance(essentials, dict):
        return "Essentials payload is not an object"
    chapters = essentials.get("chapters")
    if not isinstance(chapters, dict):
        return "Essentials schema drift, missing chapters"
    page = chapters.get("enterprise-it")
    if not isinstance(page, dict):
        return "Essentials schema drift, missing enterprise-it"
    domains = page.get("domains")
    phases = page.get("priority_phases")
    if not isinstance(domains, list) or not isinstance(phases, list):
        return "Essentials schema drift, missing domains or priority_phases"
    return None


def strategies_for(section: str, statement: str) -> list[str]:
    """Assign a control using the ISM section title and the subject of its statement."""
    leaf = (section or "").split(" / ")[-1].strip().lower()
    text = statement or ""
    lowered = text.lower()
    if leaf == "office productivity suites":
        if "macro" in lowered or "trusted publisher" in lowered:
            return ["restrict_office_macros"]
        return ["user_application_hardening"]
    if leaf == "hardening operating system configurations":
        if "memory integrity" in lowered:
            return ["restrict_admin_privileges"]
        return ["user_application_hardening"]
    if leaf in _PATCH_SECTIONS:
        return _patch_strategies(text)
    mapped = _SECTION_STRATEGY.get(leaf)
    return [mapped] if mapped else []


def parse_chapter(html: str, chapter: str, url: str) -> dict:
    events = _parse_html(html)
    domains = _domain_table(events)
    phases = _priority_phases(events, [item["name"] for item in domains])
    actions, principles = _matrix(events)
    published = ""
    match = _PUBLISHED.search(html)
    if match:
        published = match.group(1)
    note = ""
    if not phases:
        note = (
            "This chapter does not state priority phase membership in text. "
            "A figure may show it. No phase order is inferred."
        )
    return {
        "chapter": chapter,
        "url": url,
        "published": published,
        "source_sha256": hashlib.sha256(html.encode()).hexdigest(),
        "domains": domains,
        "priority_phases": phases,
        "priority_phases_are_not_maturity_levels": True,
        "priority_phases_note": note,
        "principles": principles,
        "actions": actions,
    }


def parse_transition(html: str) -> dict:
    events = _parse_html(html)
    from_table = _transition_principles(events)
    from_heading = _heading_principles(events)
    mappings = _transition_mappings(events)
    strategies = {}
    for key, label in _STRATEGY_LABELS.items():
        table_principles = from_table.get(label.lower(), [])
        heading_principles = from_heading.get(label.lower(), [])
        if len(heading_principles) >= len(table_principles):
            principles = heading_principles
        else:
            principles = table_principles
        strategies[key] = {
            "label": label,
            "principles": principles,
            "mappings": mappings.get(label.lower(), []),
        }
    return {
        "url": TRANSITION_URL,
        "source_sha256": hashlib.sha256(html.encode()).hexdigest(),
        "strategies": strategies,
    }


def _span_count(value) -> int:
    try:
        count = int(value or 1)
    except (TypeError, ValueError):
        return 1
    return count if count > 0 else 1


def merge_control_rows(rows: list[dict]) -> list[dict]:
    """One row per control and strategy, with the union of maturity levels."""
    merged: dict[tuple[str, str], dict] = {}
    for row in rows:
        if not row.get("strategy"):
            continue
        key = (row["control_id"], row["strategy"])
        current = merged.get(key)
        if current is None:
            merged[key] = {**row, "maturity_levels": list(row.get("maturity_levels") or [])}
            continue
        for level in row.get("maturity_levels") or []:
            if level not in current["maturity_levels"]:
                current["maturity_levels"].append(level)
    return list(merged.values())


def merge_unassigned_rows(rows: list[dict]) -> list[dict]:
    """One row per control that the ISM does not place under a single strategy."""
    merged: dict[str, dict] = {}
    for row in rows:
        if row.get("strategy"):
            continue
        current = merged.get(row["control_id"])
        if current is None:
            merged[row["control_id"]] = {
                "control_id": row["control_id"],
                "section": row.get("section") or "",
                "statement": row.get("statement") or "",
                "updated": row.get("updated") or "",
                "maturity_levels": list(row.get("maturity_levels") or []),
            }
            continue
        for level in row.get("maturity_levels") or []:
            if level not in current["maturity_levels"]:
                current["maturity_levels"].append(level)
    return list(merged.values())


def parse_catalog(document: dict) -> list[dict]:
    found: list[dict] = []

    def walk(nodes, trail: list[str]) -> None:
        for node in nodes or []:
            if not isinstance(node, dict):
                continue
            title = str(node.get("title") or "")
            here = trail + ([title] if title else [])
            for control in node.get("controls") or []:
                if not isinstance(control, dict) or not control.get("id"):
                    continue
                statement = _statement(control)
                section = " / ".join(here)
                levels = _maturity_levels(control)
                assigned = strategies_for(section, statement)
                row = {
                    "control_id": control["id"],
                    "section": section,
                    "statement": statement,
                    "updated": _prop(control, "updated"),
                    "maturity_levels": levels,
                }
                if not assigned:
                    row["strategy"] = ""
                    found.append(row)
                    continue
                for strategy in assigned:
                    found.append({**row, "strategy": strategy})
            walk(node.get("groups") or [], here)

    catalog = document.get("catalog") if isinstance(document, dict) else None
    if not isinstance(catalog, dict):
        return []
    walk(catalog.get("groups") or [], [])
    return found


def chapter_problem(page: dict) -> str | None:
    if not page.get("domains"):
        return "Essentials page has no domain table"
    if not page.get("actions"):
        return "Essentials page has no principle and action table"
    return None


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.events: list[tuple] = []
        self.capture = 0
        self.skip = 0
        self.mode: str | None = None
        self.buf: list[str] = []
        self.row: list[str] = []
        self.col = 0
        self.spans: dict[int, list] = {}
        self.cell_rows = 1
        self.cell_cols = 1

    def handle_starttag(self, tag, attrs):
        css = dict(attrs).get("class", "")
        if "layout-content-sidebar__main" in css:
            self.capture += 1
        if not self.capture:
            return
        if tag in {"script", "style"}:
            self.skip += 1
            return
        if self.skip:
            return
        if tag == "table":
            self._flush_row()
            self.spans = {}
            self.events.append(("table-end",))
        elif tag in {"h1", "h2", "h3", "h4"}:
            self._flush_row()
            self.mode = tag
            self.buf = []
        elif tag == "tr":
            self._flush_heading()
            self.mode = "row"
            self.row = []
            self.col = 0
            self.buf = []
            self._fill_spans()
        elif tag in {"td", "th"} and self.mode in {"row", "cell"}:
            self._flush_cell()
            self._fill_spans()
            self.mode = "cell"
            self.buf = []
            values = dict(attrs)
            self.cell_rows = _span_count(values.get("rowspan"))
            self.cell_cols = _span_count(values.get("colspan"))
        elif tag == "p" and self.mode not in {"cell", "row"}:
            self._flush_heading()
            self.mode = "p"
            self.buf = []

    def handle_endtag(self, tag):
        if tag in {"script", "style"} and self.skip:
            self.skip -= 1
            return
        if not self.capture or self.skip:
            return
        if tag in {"td", "th"} and self.mode == "cell":
            self._flush_cell()
            self.mode = "row"
        elif tag == "table":
            self._flush_row()
            self.spans = {}
            self.events.append(("table-end",))
        elif tag == "tr":
            self._flush_row()
        elif tag in {"h1", "h2", "h3", "h4"} and self.mode == tag:
            self._flush_heading()
        elif tag == "p" and self.mode == "p":
            text = _clean(" ".join(self.buf))
            if text:
                self.events.append(("p", text))
            self.mode = None
            self.buf = []

    def handle_data(self, data):
        if self.capture and not self.skip and self.mode in {"h1", "h2", "h3", "h4", "p", "cell"}:
            self.buf.append(data)

    def close(self):
        super().close()
        self._flush_heading()
        self._flush_row()

    def _flush_heading(self) -> None:
        if self.mode in {"h1", "h2", "h3", "h4"}:
            text = _clean(" ".join(self.buf))
            if text:
                self.events.append((self.mode, text))
            self.mode = None
            self.buf = []

    def _flush_cell(self) -> None:
        if self.mode != "cell":
            return
        text = _clean_cell(" ".join(self.buf))
        self.row.append(text)
        if self.cell_rows > 1:
            self.spans[self.col] = [text, self.cell_rows - 1]
        self.col += 1
        for _extra in range(self.cell_cols - 1):
            self.row.append("")
            self.col += 1
        self.buf = []
        self.cell_rows = 1
        self.cell_cols = 1

    def _fill_spans(self) -> None:
        while self.col in self.spans:
            text, left = self.spans[self.col]
            self.row.append(text)
            left -= 1
            if left <= 0:
                del self.spans[self.col]
            else:
                self.spans[self.col][1] = left
            self.col += 1

    def _flush_row(self) -> None:
        self._flush_cell()
        if self.mode in {"row", "cell"}:
            self._fill_spans()
        if self.mode in {"row", "cell"} and any(self.row):
            self.events.append(("row", self.row))
        self.mode = None
        self.row = []
        self.buf = []
        self.col = 0


def _parse_html(html: str) -> list[tuple]:
    parser = _PageParser()
    parser.feed(html)
    parser.close()
    return parser.events


def _domain_table(events: list[tuple]) -> list[dict]:
    rows = _tables(events)
    for table in rows:
        header = [cell.lower() for cell in table[0]]
        if header[:3] != ["domain", "description", "risk context"]:
            continue
        domains = []
        for cells in table[1:]:
            name = cells[0] if cells else ""
            if not name or name.lower() == "domain":
                continue
            domains.append(
                {
                    "name": name,
                    "description": cells[1] if len(cells) > 1 else "",
                    "risk_context": cells[2] if len(cells) > 2 else "",
                }
            )
        return domains
    return []


def _priority_phases(events: list[tuple], domain_names: list[str]) -> list[dict]:
    phases = []
    pending: dict | None = None
    for event in events:
        kind = event[0]
        if kind in {"h2", "h3", "h4"}:
            if pending:
                phases.append(pending)
                pending = None
            if kind != "h4":
                continue
            match = _PHASE.match(event[1])
            if not match:
                continue
            domains, _rest = _consume_domains(match.group(2), domain_names)
            pending = {
                "phase": int(match.group(1)),
                "domains": domains,
                "summary": "",
                "sequencing_only": True,
                "not_a_maturity_level": True,
            }
        elif kind == "p" and pending and not pending["summary"]:
            pending["summary"] = event[1]
    if pending:
        phases.append(pending)
    return phases


def _matrix(events: list[tuple]) -> tuple[list[dict], list[dict]]:
    actions = []
    principles = []
    seen = set()
    seen_actions = set()
    for table in _tables(events):
        header = table[0]
        columns = _columns(header)
        if columns["principle"] is None or columns["action"] is None:
            continue
        previous = ""
        previous_name = ""
        for cells in table[1:]:
            padded = cells + [""] * (len(header) - len(cells))
            principle_cell = padded[columns["principle"]]
            action = padded[columns["action"]]
            if principle_cell.lower() == "principle" or not action:
                continue
            match = _PRINCIPLE.match(principle_cell)
            if match:
                previous = match.group(1)
                previous_name = match.group(2)
                if previous not in seen:
                    seen.add(previous)
                    principles.append({"id": previous, "name": previous_name})
            elif principle_cell:
                previous = ""
                previous_name = principle_cell
            principle_id = previous
            principle_name = previous_name
            identity = (principle_id, action)
            if identity in seen_actions:
                continue
            seen_actions.add(identity)
            domains = []
            for name, index in columns["domains"]:
                if index < len(padded) and _ticked(padded[index]):
                    domains.append(name)
            attack = ""
            if columns["attack"] is not None and columns["attack"] < len(padded):
                attack = padded[columns["attack"]]
            shared = {}
            for label, index in columns["shared"]:
                if index < len(padded) and padded[index]:
                    shared[label] = padded[index]
            actions.append(
                {
                    "principle_id": principle_id,
                    "principle": principle_name,
                    "action": action,
                    "domains": domains,
                    "attack": attack,
                    "shared_responsibility": shared,
                }
            )
    return actions, principles


def _heading_principles(events: list[tuple]) -> dict[str, list[str]]:
    current = ""
    found: dict[str, list[str]] = {}
    for event in events:
        if event[0] in {"h2", "h3"}:
            current = event[1].strip().lower()
        elif event[0] == "p" and event[1].lower().startswith("key mapped principles"):
            text = event[1].split(":", 1)[-1]
            keys = _strategy_heading_keys(current)
            for key in keys:
                found[key] = _known_principle_split(text)
    return found


def _strategy_heading_keys(heading: str) -> list[str]:
    if "patch applications" in heading and "operating systems" in heading:
        return ["patch applications", "patch operating systems"]
    return [heading] if heading else []


def _transition_principles(events: list[tuple]) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for table in _tables(events):
        header = [cell.lower() for cell in table[0]]
        if not header or "mitigation strategy" not in header[0]:
            continue
        for cells in table[1:]:
            if len(cells) < 2:
                continue
            label = cells[0].strip()
            if not label or label.lower().startswith("essential eight"):
                continue
            principles = _split_principles(cells[1])
            found[label.lower()] = principles
    return found


def _transition_mappings(events: list[tuple]) -> dict[str, list[dict]]:
    found: dict[str, list[dict]] = {}
    tables = _tables_with_context(events)
    for context, table in tables:
        header = [cell.lower() for cell in table[0]]
        if "action" not in header or "domain coverage" not in header:
            continue
        heading = context.lower()
        if "patch applications" in heading and "operating systems" in heading:
            keys = ["patch applications", "patch operating systems"]
        else:
            keys = [heading]
        principle_index = header.index("principle") if "principle" in header else 0
        action_index = header.index("action")
        coverage_index = header.index("domain coverage")
        if "existing e8 contribution" in header:
            contribution_index = header.index("existing e8 contribution")
        else:
            contribution_index = None
        previous = ""
        rows = []
        for cells in table[1:]:
            padded = cells + [""] * 4
            principle = padded[principle_index]
            action = padded[action_index]
            if principle.lower() == "principle" or not action:
                continue
            if principle:
                previous = principle
            rows.append(
                {
                    "principle": previous,
                    "action": action,
                    "domain_coverage": padded[coverage_index],
                    "existing_contribution": (
                        padded[contribution_index] if contribution_index is not None else ""
                    ),
                }
            )
        for key in keys:
            found.setdefault(key, []).extend(rows)
    return found


def _tables(events: list[tuple]) -> list[list[list[str]]]:
    return [table for _context, table in _tables_with_context(events)]


def _tables_with_context(events: list[tuple]) -> list[tuple[str, list[list[str]]]]:
    tables = []
    context = ""
    section = ""
    current: list[list[str]] = []
    for event in events:
        if event[0] in {"h1", "h2", "h3", "h4"}:
            if current:
                tables.append((context, current))
                current = []
            title = event[1]
            if event[0] in {"h2", "h3"}:
                section = title
            if title.lower().startswith("action mapping"):
                context = section
            else:
                context = title
        elif event[0] == "row":
            current.append(event[1])
        elif event[0] == "table-end" and current:
            tables.append((context, current))
            current = []
        elif event[0] == "p" and current:
            tables.append((context, current))
            current = []
    if current:
        tables.append((context, current))
    return tables


def _columns(header: list[str]) -> dict:
    columns = {"principle": None, "action": None, "attack": None, "domains": [], "shared": []}
    for index, cell in enumerate(header):
        label = cell.strip()
        lowered = label.lower()
        if lowered == "principle":
            columns["principle"] = index
        elif lowered in {"action", "cloud actions"}:
            columns["action"] = index
        elif "mitre" in lowered:
            columns["attack"] = index
        elif "shared responsibility" in lowered:
            columns["shared"].append((label, index))
        elif label:
            columns["domains"].append((label, index))
    return columns


def _consume_domains(text: str, domain_names: list[str]) -> tuple[list[str], str]:
    names = sorted(domain_names, key=len, reverse=True)
    found = []
    cursor = text.strip()
    while cursor:
        matched = next((name for name in names if cursor.lower().startswith(name.lower())), None)
        if matched is None:
            break
        found.append(matched)
        cursor = cursor[len(matched) :].strip()
        if cursor.lower().startswith("and "):
            cursor = cursor[4:].strip()
        elif cursor.startswith(","):
            cursor = cursor[1:].strip()
            if cursor.lower().startswith("and "):
                cursor = cursor[4:].strip()
        else:
            break
    return found, cursor


def _patch_strategies(statement: str) -> list[str]:
    text = statement.lower()
    if "asset discovery" in text or "vulnerability database" in text:
        return ["patch_applications", "patch_operating_systems"]
    operating = any(phrase in text for phrase in ("operating systems", "drivers", "firmware"))
    applications = any(
        phrase in text
        for phrase in (
            "online services",
            "office productivity",
            "applications other than",
            "web browsers",
            "email clients",
            "pdf applications",
            "security products",
            "adobe flash",
        )
    )
    chosen = []
    if applications:
        chosen.append("patch_applications")
    if operating:
        chosen.append("patch_operating_systems")
    return chosen


def _maturity_levels(control: dict) -> list[int]:
    levels = []
    for prop in control.get("props") or []:
        if prop.get("name") != "essential-eight-applicability":
            continue
        match = re.search(r"(\d)", str(prop.get("value") or ""))
        if match:
            number = int(match.group(1))
            if number not in levels:
                levels.append(number)
    return levels


def _statement(control: dict) -> str:
    parts: list[str] = []

    def walk(nodes) -> None:
        for part in nodes or []:
            prose = str(part.get("prose") or "").strip()
            if prose:
                parts.append(prose)
            walk(part.get("parts") or [])

    walk(control.get("parts") or [])
    return " ".join(parts)


def _prop(control: dict, name: str) -> str:
    for prop in control.get("props") or []:
        if prop.get("name") == name and prop.get("value"):
            return str(prop["value"])
    return ""


def _split_principles(text: str) -> list[str]:
    pieces = re.split(r"\s{2,}|(?<=[a-z)])\s+(?=[A-Z])", text.strip())
    # The published cell often separates principles with single spaces and capitals.
    if len(pieces) <= 1:
        pieces = _known_principle_split(text)
    return [piece.strip() for piece in pieces if piece.strip()]


def _known_principle_split(text: str) -> list[str]:
    """Split a transition-table cell on principle names that are already known labels."""
    labels = [
        "Trustworthy software",
        "Secure configuration management",
        "Vulnerability management",
        "Asset identification",
        "Legacy system management",
        "Identity, credential and access management",
        "Least privilege access",
        "Secure administration",
        "Network segmentation and segregation",
        "Content filtering",
        "Regular and proven backups",
    ]
    remaining = text.strip()
    found = []
    while remaining:
        if remaining.lower().startswith("and "):
            remaining = remaining[4:].strip()
        matched = next((label for label in labels if remaining.startswith(label)), None)
        if matched is None:
            break
        found.append(matched)
        remaining = remaining[len(matched) :].strip(" .,;:")
    return found


def _chapter_body(chapter: str, page: dict, *, actions: list[dict], domain: str | None) -> dict:
    phases = []
    for phase in page.get("priority_phases") or []:
        phases.append(
            {
                "phase": phase.get("phase"),
                "domains": list(phase.get("domains") or []),
                "summary": untrusted_text(phase.get("summary") or "", "e8"),
                "sequencing_only": True,
                "not_a_maturity_level": True,
            }
        )
    domains = []
    for item in page.get("domains") or []:
        if domain and not _domain_match(domain, item.get("name") or ""):
            continue
        domains.append(
            {
                "name": item.get("name") or "",
                "description": untrusted_text(item.get("description") or "", "e8"),
                "risk_context": untrusted_text(item.get("risk_context") or "", "e8"),
            }
        )
    return {
        "chapter": chapter,
        "url": page.get("url") or CHAPTERS.get(chapter, ""),
        "published": page.get("published") or "",
        "source_sha256": page.get("source_sha256") or "",
        "priority_phases_are_not_maturity_levels": True,
        "priority_phases_note": page.get("priority_phases_note") or "",
        "domains": domains,
        "priority_phases": phases,
        "principles": [
            {"id": item.get("id") or "", "name": _quote(item.get("name") or "")}
            for item in page.get("principles") or []
        ],
        "actions": actions,
    }


def _public_action(action: dict) -> dict:
    shared = {
        key: _quote(value) for key, value in (action.get("shared_responsibility") or {}).items()
    }
    return {
        "principle_id": action.get("principle_id") or "",
        "principle": _quote(action.get("principle") or ""),
        "action": _quote(action.get("action") or ""),
        "domains": list(action.get("domains") or []),
        "attack": _quote(action.get("attack") or ""),
        "shared_responsibility": shared,
    }


def _quote(value: str) -> str:
    text = value or ""
    if not text.strip():
        return ""
    return untrusted_text(text, "e8")


def _cross_cutting(maturity: dict, level: int) -> list[dict]:
    rows = []
    for control in maturity.get("unassigned_controls") or []:
        if level not in (control.get("maturity_levels") or []):
            continue
        rows.append(
            {
                "control_id": control.get("control_id") or "",
                "section": _quote(control.get("section") or ""),
                "statement": _quote(control.get("statement") or ""),
                "maturity_levels": list(control.get("maturity_levels") or []),
            }
        )
    return rows


def _matching_domains(query: str, names: list[str]) -> list[str]:
    return [name for name in names if name and _domain_match(query, name)]


def _action_in_domain(action: dict, names: list[str]) -> bool:
    labels = action.get("domains") or []
    for name in names:
        for label in labels:
            if _domain_match(name, label) or _domain_match(label, name):
                return True
    return False


def _domain_match(left: str, right: str) -> bool:
    if left.lower() == right.lower():
        return True
    left_word = left.split()[0].lower() if left.split() else ""
    right_word = right.split()[0].lower() if right.split() else ""
    return len(left_word) > 4 and left_word == right_word


def _ticked(value: str) -> bool:
    return value.strip().lower() in _TICKS or any(mark in value for mark in _TICK_MARKS)


def _strategy_key(value) -> str | None:
    if not isinstance(value, str):
        return None
    return _STRATEGY_ALIASES.get(value.strip().lower())


def _level(value) -> tuple[int | None, str]:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 3:
        return None, "maturity_level must be 1, 2 or 3"
    return value, ""


def _clean(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _clean_cell(value: str) -> str:
    text = _clean(value)
    leaked = text.find("Priority phases In each chapter")
    if leaked > 0:
        text = text[:leaked].strip()
    return text


def _visible_text(events: list[tuple]) -> str:
    return " ".join(event[1] for event in events if event[0] in {"h1", "p"})


def _maturity() -> tuple[dict | None, str, str]:
    maturity, _essentials_doc, problem = _snapshot_pair()
    if problem and maturity is None:
        return None, "snapshot", problem
    return maturity, "snapshot", ""


def _essentials() -> tuple[dict | None, str, str]:
    _maturity_doc, essentials, problem = _snapshot_pair()
    if problem and essentials is None:
        return None, "snapshot", problem
    return essentials, "snapshot", ""


def _snapshot_pair() -> tuple[dict | None, dict | None, str]:
    root = _root()
    maturity_path = _latest(root, "e8-maturity-*.json")
    essentials_path = _latest(root, "essentials-*.json")
    if maturity_path is None or essentials_path is None:
        return None, None, "Essential Eight snapshot is missing"
    maturity = _loads(maturity_path.read_text(encoding="utf-8"))
    essentials = _loads(essentials_path.read_text(encoding="utf-8"))
    if not isinstance(maturity, dict) or not isinstance(essentials, dict):
        return None, None, "Essential Eight snapshot was not usable"
    return maturity, essentials, ""


def _latest(root: Path, pattern: str) -> Path | None:
    found = sorted(root.glob(pattern))
    return found[-1] if found else None


def _root() -> Path:
    override = os.environ.get("CYBERAU_E8_SNAPSHOT")
    return Path(override) if override else _PACKAGE / "data"


def _loads(text: str):
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _http(url: str, *, ttl: int, skip_cache: bool) -> tuple[str | None, str, str]:
    if os.environ.get("CYBERAU_OFFLINE") == "1":
        return None, "snapshot", "offline"
    data_dir = _data_dir()
    client = HttpClient(
        "asd-essentials",
        policy=EgressPolicy(_allowlist(), "asd-essentials"),
        cache=HttpCache(data_dir / "http_cache.sqlite"),
        limiter=RateLimiter(data_dir / "rate_limit.sqlite", sleeper=_SLEEP),
        user_agent=USER_AGENT,
        rate=1 / 5,
        burst=2,
        window="rolling",
        timeout=60,
        retries=1,
        transport=_TRANSPORT,
        sleeper=_SLEEP,
    )
    try:
        response = client.get(url, ttl=ttl, stale_if_error=86400, skip_cache=skip_cache)
    except Exception as exc:
        return None, "snapshot", redact(str(exc))
    finally:
        client.close()
    if response.status == 403:
        return None, response.cache, "upstream status 403. asd-essentials has no API key."
    if response.status == 401:
        return None, response.cache, "upstream status 401. asd-essentials has no API key."
    if response.status == 429:
        return (
            None,
            response.cache,
            "upstream status 429. Retry-After was honoured until the limit remained.",
        )
    if response.status >= 400:
        return None, response.cache, f"upstream status {response.status}"
    try:
        text = response.body.decode("utf-8")
    except UnicodeDecodeError:
        return None, response.cache, "Essentials payload was not UTF-8"
    warning = "served from cache after the live fetch failed" if response.cache == "stale" else ""
    return text, response.cache, warning


def _envelope(data, cache: str, urls=None, data_as_of: str | None = None, warnings=()):
    if isinstance(urls, str):
        urls = [urls]
    return envelope(
        "asd-essentials",
        data,
        urls=list(urls or []),
        cache=cache,
        data_as_of=data_as_of,
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


def _data_dir() -> Path:
    path = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-e8"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def _allowlist() -> Path:
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


def rebuild_shipped_snapshot(destination: Path | None = None) -> dict:
    """Download the pinned public sources and write the shipped JSON snapshot."""
    destination = destination or (_PACKAGE / "data")
    destination.mkdir(parents=True, exist_ok=True)
    chapters = {}
    for key, url in CHAPTERS.items():
        text, _cache, warning = _http(url, ttl=86400, skip_cache=True)
        if not text or warning:
            raise RuntimeError(warning or f"{key} page was empty")
        page = parse_chapter(text, key, url)
        problem = chapter_problem(page)
        if problem:
            raise RuntimeError(f"{key}: {problem}")
        chapters[key] = page
    transition_html, _cache, warning = _http(TRANSITION_URL, ttl=86400, skip_cache=True)
    if not transition_html or warning:
        raise RuntimeError(warning or "transition page was empty")
    launch_html, _cache, launch_warning = _http(LAUNCH_URL, ttl=86400, skip_cache=True)
    controls = []
    unassigned_rows = []
    hashes = {}
    urls = []
    for level in (1, 2, 3):
        filename = f"ISM_E8_ML{level}-baseline-resolved-profile_catalog.json"
        url = f"{RAW_ROOT}/{ISM_RELEASE}/{filename}"
        urls.append(url)
        text, _cache, warning = _http(url, ttl=7 * 86400, skip_cache=True)
        if not text or warning:
            raise RuntimeError(warning or f"{filename} was empty")
        hashes[filename] = hashlib.sha256(text.encode()).hexdigest()
        document = _loads(text)
        if not isinstance(document, dict):
            raise RuntimeError(f"{filename} was not JSON")
        for row in parse_catalog(document):
            if not row["strategy"]:
                unassigned_rows.append(row)
                continue
            controls.append(row)
    controls = merge_control_rows(controls)
    unassigned = merge_unassigned_rows(unassigned_rows)
    essentials = {
        "retrieved_on": "2026-10-17",
        "chapters": chapters,
        "transition": parse_transition(transition_html),
        "launch_url": LAUNCH_URL,
        "launch_sha256": hashlib.sha256(launch_html.encode()).hexdigest() if launch_html else "",
        "launch_warning": launch_warning,
        "ot_url": CHAPTERS["ot"],
        "transition_url_confirmed": TRANSITION_URL,
    }
    maturity = {
        "retrieved_on": "2026-10-17",
        "ism_release": ISM_RELEASE,
        "source_urls": urls,
        "source_sha256": hashes,
        "controls": controls,
        "unassigned_controls": unassigned,
        "unassigned_control_ids": [row["control_id"] for row in unassigned],
        "classification": (
            "Each control is assigned from its ISM section title. "
            "Patching controls are split by the subject of the statement "
            "(applications and online services, or operating systems, drivers and firmware). "
            "Office macro statements stay with restrict_office_macros. "
            "Incident-reporting controls that the ISM does not place under one mitigation "
            "strategy are listed in unassigned_control_ids and are not copied onto every strategy."
        ),
    }
    (destination / "essentials-2026-10-17.json").write_text(
        json.dumps(essentials, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (destination / f"e8-maturity-{ISM_RELEASE}.json").write_text(
        json.dumps(maturity, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return {
        "chapters": {key: len(value["actions"]) for key, value in chapters.items()},
        "phases": {
            key: [item["phase"] for item in value["priority_phases"]]
            for key, value in chapters.items()
        },
        "controls": len(controls),
        "unassigned": unassigned,
    }


register_connector("asd-essentials", connector)
