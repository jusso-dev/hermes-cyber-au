"""Render a PSPF threat and risk assessment and security risk management plan.

The script does not use the network. It rates risks only from the likelihood
and consequence labels it is given, on the matrix it is given (or the labelled
default). A missing value stays missing. Nothing is sent and no one is notified.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

DOCUMENTS = ("tra", "srmp")
KINDS = {
    "entity": "Entity security plan (risk component)",
    "system": "System security risk management plan",
    "technology": "Technology Security Risk Management Plan",
    "facility": "Facility security risk management plan",
    "project": "Project security risk management plan",
}
OPTIONS = {
    "reduce": "Reduce (treat)",
    "avoid": "Avoid (terminate the activity)",
    "share": "Share (transfer or share with a partner)",
    "accept": "Accept (tolerate)",
}
DEFAULT_MATRIX = {
    "name": "hermes-cyber-au default 5 by 5 matrix",
    "likelihood": ["rare", "unlikely", "possible", "likely", "almost certain"],
    "consequence": ["insignificant", "minor", "moderate", "major", "severe"],
    "levels": ["low", "medium", "high", "extreme"],
}
PSPF_LIST = "Source: PSPF Release 2026 List of Requirements, July 2026, retrieved 2026-10-19"
PSPF_RELEASE = "Source: PSPF Release 2026, July 2026, retrieved 2026-10-19"
REQ = {
    "0019": "The Accountable Authority approves the entity's security plan.",
    "0020": (
        "The security plan is considered annually and reviewed at least every two years to "
        "confirm its adequacy and ability to adapt to shifts in the entity's risk, threat or "
        "operating environment."
    ),
    "0036": (
        "The Accountable Authority determines their entity's tolerance for security risks and "
        "documents in the security plan."
    ),
    "0037": (
        "A risk steward (or manager) is identified for each security risk or category of "
        "security risk, including shared risks."
    ),
    "0086": (
        "The Authorising Officer authorises each technology system to operate based on the "
        "acceptance of the residual security risks associated with its operation before that "
        "system processes, stores or communicates government information or data."
    ),
    "0211": (
        "A Technology Asset Stocktake and Technology Security Risk Management Plan is created to "
        "identify and manage the entity's internet-facing systems or services to ensure "
        "continuous visibility and monitoring of the entity's resource and technology estate."
    ),
}
ELEMENTS = (
    ("goals", "Security goals and objectives"),
    ("risk_environment", "Security risk environment"),
    ("tolerance", "Risk tolerance"),
    ("capability", "Security capability"),
    ("strategies", "Security risk management strategies"),
    ("implications", "Implications of risk decisions"),
    ("pspf_implementation", "PSPF implementation"),
    ("directions", "PSPF Directions"),
    ("critical_resources", "Critical people and resources"),
    ("threat_levels", "Threat levels"),
    ("incident_management", "Incident management plan"),
    ("monitoring", "Monitoring and improvement"),
    ("review", "Review"),
)
DISCLAIMER = (
    "This is a draft prepared with hermes-cyber-au from the information supplied and the "
    "sources cited. It is not an IRAP assessment, not an authorisation to operate, not a PSPF "
    "compliance finding and not legal advice. Each rating is for the risk steward to confirm. "
    "Nothing was sent and no one was notified."
)
REGISTER_COLUMNS = (
    "risk_id,risk,assets,threats,steward,likelihood,consequence,inherent,rated_by,treatment,"
    "actions,residual_likelihood,residual_consequence,residual,tolerance_status,acceptance"
)
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_URL = re.compile(r"\b(https?)://([^\s/]+)(\S*)", re.IGNORECASE)
_EMAIL = re.compile(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})\b")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN = re.compile(
    r"\b((?:[a-z0-9-]+\.)+(?:com|net|org|au|gov|edu|io|info|biz|xyz|top|ru|cn|uk|nz|co|ws|cc))\b",
)
_INSTRUCTION = re.compile(
    r"(?i)(?:ignore|disregard|forget)\s+(?:all\s+|any\s+|the\s+|your\s+)*"
    r"(?:previous|prior|above|earlier)"
    r"|\bmark\s+(?:every|all|each|the)\s+(?:risk|control)s?\s+(?:as\s+)?"
    r"(?:accepted|met|low|closed|treated)"
    r"|\b(?:post|send|email|upload|publish)\s+(?:the\s+|this\s+)?"
    r"(?:plan|assessment|srmp|tra|register)\b"
)
_FORMULA = ("=", "+", "-", "@", "\t", "\r")


@dataclass
class Rated:
    """One risk after the matrix has been applied."""

    rid: str
    statement: str
    assets: list[str]
    threats: list[str]
    steward: str
    likelihood: str
    consequence: str
    inherent: str
    rated_by: str
    option: str
    actions: list[dict]
    residual_likelihood: str
    residual_consequence: str
    residual: str
    residual_note: str
    tolerance_status: str
    acceptance: str
    raw: dict


@dataclass
class Context:
    as_of: str
    kind: str
    authority: str
    matrix: dict
    matrix_default: bool
    tolerance: str
    tolerance_line: str
    gaps: list[str] = field(default_factory=list)
    instructions: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Report:
    markdown: str
    tra: str
    srmp: str
    register: str


def defang_text(value: str) -> str:
    """Defang URLs, email addresses, IPv4 addresses and domains in free text, once."""

    def url_sub(match: re.Match[str]) -> str:
        scheme = "hxxps" if match.group(1).lower() == "https" else "hxxp"
        return f"{scheme}://{match.group(2).replace('.', '[.]')}{match.group(3)}"

    text = _URL.sub(url_sub, value)
    text = _EMAIL.sub(lambda m: f"{m.group(1)}[@]{m.group(2).replace('.', '[.]')}", text)
    text = _IPV4.sub(lambda m: m.group(0).replace(".", "[.]"), text)
    return _DOMAIN.sub(lambda m: m.group(1).replace(".", "[.]"), text)


def render(document: dict) -> Report:
    """Build the TRA, the SRMP and the risk register."""
    if not isinstance(document, dict):
        raise TypeError("risk input must be a JSON object")
    as_of = _day(document.get("as_of"))
    if not as_of:
        raise ValueError("as_of must be a YYYY-MM-DD date")
    documents = document.get("documents") or list(DOCUMENTS)
    if not isinstance(documents, list) or not set(documents) <= set(DOCUMENTS):
        raise ValueError("documents must be a list of tra and srmp")
    scope = _mapping(document.get("scope"))
    kind = str(scope.get("kind") or "entity")
    if kind not in KINDS:
        raise ValueError(f"scope.kind must be one of {', '.join(KINDS)}")
    authority = _text(scope.get("acceptance_authority")) or (
        "Authorising Officer" if kind in {"system", "technology"} else "Accountable Authority"
    )
    matrix, matrix_default = _matrix(document.get("matrix"))
    ctx = Context(as_of, kind, authority, matrix, matrix_default, "", "")
    _tolerance(document.get("tolerance"), ctx)
    for label in _strings(document.get("missing_sources")):
        ctx.gaps.append(f"Source missing: {label}. Nothing from it was assumed.")
    assets = [_mapping(item) for item in _list(document.get("assets"))]
    threats = [_mapping(item) for item in _list(document.get("threats"))]
    risks = [_rate(_mapping(item), ctx, assets, threats) for item in _list(document.get("risks"))]
    _scan(document, ctx)

    tra = _tra(document, scope, assets, threats, risks, ctx) if "tra" in documents else ""
    srmp = _srmp(document, scope, assets, threats, risks, ctx) if "srmp" in documents else ""
    register = _register(risks)
    markdown = "\n".join(part for part in (tra, srmp) if part)
    return Report(markdown, tra, srmp, register)


def _matrix(raw: object) -> tuple[dict, bool]:
    if not isinstance(raw, dict) or not raw:
        return DEFAULT_MATRIX, True
    likelihood = _strings(raw.get("likelihood"))
    consequence = _strings(raw.get("consequence"))
    levels = _strings(raw.get("levels"))
    grid = raw.get("grid")
    if not likelihood or not consequence or not levels:
        raise ValueError("matrix needs likelihood, consequence and levels lists")
    if not isinstance(grid, list) or len(grid) != len(likelihood):
        raise ValueError("matrix.grid needs one row for each likelihood label")
    for row in grid:
        if not isinstance(row, list) or len(row) != len(consequence):
            raise ValueError("each matrix.grid row needs one rating for each consequence label")
        if any(cell not in levels for cell in row):
            raise ValueError("every matrix.grid rating must be one of matrix.levels")
    name = _text(raw.get("name")) or "entity risk matrix"
    return {
        "name": name,
        "likelihood": likelihood,
        "consequence": consequence,
        "levels": levels,
        "grid": grid,
    }, False


def _rating(matrix: dict, likelihood: str, consequence: str) -> str:
    lik = [label.lower() for label in matrix["likelihood"]]
    con = [label.lower() for label in matrix["consequence"]]
    if likelihood.lower() not in lik or consequence.lower() not in con:
        return "unrated"
    li, ci = lik.index(likelihood.lower()), con.index(consequence.lower())
    if "grid" in matrix:
        return matrix["grid"][li][ci]
    score = (li + 1) * (ci + 1)
    levels = matrix["levels"]
    if score <= 3:
        return levels[0]
    if score <= 9:
        return levels[1]
    if score <= 15:
        return levels[2]
    return levels[3]


def _tolerance(raw: object, ctx: Context) -> None:
    data = _mapping(raw)
    level = _text(data.get("rating"))
    if not level:
        ctx.tolerance_line = (
            "Risk tolerance: missing. No tolerance was assumed, so no risk is evaluated "
            "against tolerance. PSPF Requirement 0036: " + REQ["0036"]
        )
        ctx.gaps.append("Risk tolerance missing (PSPF Requirement 0036).")
        return
    matches = [item for item in ctx.matrix["levels"] if item.lower() == level.lower()]
    if not matches:
        raise ValueError("tolerance.rating must be one of the matrix levels")
    level = matches[0]
    ctx.tolerance = level
    by = _text(data.get("approved_by"))
    when = _day(data.get("date"))
    if by and when:
        ctx.tolerance_line = (
            f"Risk tolerance: residual risk rated {level} or lower is within tolerance. "
            f"Determined by {_safe(by)} on {when}."
        )
    else:
        ctx.tolerance_line = (
            f"Risk tolerance: {level} or lower (supplied). Who determined it and when is "
            "missing. PSPF Requirement 0036: " + REQ["0036"]
        )
        ctx.gaps.append("Risk tolerance has no recorded Accountable Authority decision (0036).")


def _rate(raw: dict, ctx: Context, assets: list[dict], threats: list[dict]) -> Rated:
    rid = _text(raw.get("id")) or "missing"
    likelihood = _text(raw.get("likelihood")) or "missing"
    consequence = _text(raw.get("consequence")) or "missing"
    inherent = _rating(ctx.matrix, likelihood, consequence)
    if inherent == "unrated":
        ctx.gaps.append(
            f"{rid}: unrated. Likelihood {likelihood}, consequence {consequence}. "
            "No rating was substituted."
        )
    steward = _text(raw.get("steward"))
    if not steward:
        steward = "missing"
        ctx.gaps.append(f"{rid}: risk steward missing (PSPF Requirement 0037).")
    rated_by = _text(raw.get("rated_by")) or "missing"
    asset_ids = {_text(item.get("id")) for item in assets}
    for aid in _strings(raw.get("assets")):
        if assets and aid not in asset_ids:
            ctx.gaps.append(f"{rid}: asset {aid} is not in the asset list.")
    threat_ids = _strings(raw.get("threats"))
    known = {str(item.get("id")): item for item in threats}
    for tid in threat_ids:
        if tid not in known:
            ctx.gaps.append(f"{rid}: threat {tid} is not in the threat assessment.")
        elif not _evidence(known[tid]):
            ctx.gaps.append(f"{rid}: threat {tid} has no sourced evidence.")

    treatment = _mapping(raw.get("treatment"))
    option = _text(treatment.get("option"))
    if option and option not in OPTIONS:
        raise ValueError(f"{rid}: treatment.option must be one of {', '.join(OPTIONS)}")
    actions = [_mapping(item) for item in _list(treatment.get("actions"))]
    rl = _text(treatment.get("residual_likelihood"))
    rc = _text(treatment.get("residual_consequence"))
    if rl and rc:
        residual = _rating(ctx.matrix, rl, rc)
        residual_note = "target residual after the proposed treatment"
    else:
        rl, rc, residual = likelihood, consequence, inherent
        residual_note = "residual not assessed, so the inherent rating is carried"
    status = _against(ctx, residual)
    acceptance_raw = _mapping(raw.get("acceptance"))
    acc_by, acc_day = _text(acceptance_raw.get("by")), _day(acceptance_raw.get("date"))
    if acc_by and acc_day:
        acceptance = f"accepted by {_safe(acc_by)} on {acc_day}"
    else:
        acceptance = "not recorded"
    if status == "above tolerance" and not option:
        ctx.gaps.append(f"{rid}: above tolerance with no treatment option.")
    if status == "above tolerance" and option == "accept" and acceptance == "not recorded":
        ctx.gaps.append(f"{rid}: accepting a risk above tolerance needs the {ctx.authority}.")
    return Rated(
        rid=rid,
        statement=_text(raw.get("statement")) or "missing",
        assets=_strings(raw.get("assets")),
        threats=threat_ids,
        steward=steward,
        likelihood=likelihood,
        consequence=consequence,
        inherent=inherent,
        rated_by=rated_by,
        option=option or "missing",
        actions=actions,
        residual_likelihood=rl,
        residual_consequence=rc,
        residual=residual,
        residual_note=residual_note,
        tolerance_status=status,
        acceptance=acceptance,
        raw=raw,
    )


def _against(ctx: Context, rating: str) -> str:
    if rating == "unrated":
        return "not evaluated (unrated)"
    if not ctx.tolerance:
        return "not evaluated (tolerance missing)"
    levels = ctx.matrix["levels"]
    if levels.index(rating) <= levels.index(ctx.tolerance):
        return "within tolerance"
    return "above tolerance"


def _scan(value: object, ctx: Context, path: str = "input") -> None:
    """Record any embedded instruction as content. It is never carried out."""
    if isinstance(value, dict):
        for key, item in value.items():
            _scan(item, ctx, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _scan(item, ctx, f"{path}[{index}]")
    elif isinstance(value, str) and _INSTRUCTION.search(value):
        ctx.instructions.append(path)


def _tra(document, scope, assets, threats, risks, ctx: Context) -> str:
    out: list[str] = []
    subject = _safe(_text(scope.get("subject")) or "missing")
    out += [f"# Threat and risk assessment: {subject}", "", DISCLAIMER, ""]
    out += ["## Scope and context", ""]
    out += _scope_lines(scope, ctx)
    out += [
        "",
        "Method: PSPF security risk management process (5.2). Security risk assessment "
        "identifies, analyses and evaluates security risks. Treatment is drafted in the "
        "security risk management plan.",
        PSPF_RELEASE,
        "",
        "## Critical assets",
        "",
    ]
    out += _asset_table(assets)
    out += ["", "## Threat assessment", ""]
    out += _threat_env_lines(document, ctx.as_of)
    out += [""]
    if not threats:
        out += ["Threats: missing. No threat was assumed.", ""]
    for threat in threats:
        out += _threat_lines(threat, ctx.as_of)
    out += ["## Risk analysis", ""]
    out += _matrix_lines(ctx)
    out += [""]
    if risks:
        out += [
            "| id | risk | likelihood | consequence | inherent | rated by | steward |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
        for risk in risks:
            out.append(
                f"| {_cell(risk.rid)} | {_cell(risk.statement)} | {_cell(risk.likelihood)} | "
                f"{_cell(risk.consequence)} | {risk.inherent} | {_cell(_rated(risk))} | "
                f"{_cell(risk.steward)} |"
            )
        out.append("")
    else:
        out += ["Risks: missing. No risk was assumed.", ""]
    for risk in risks:
        out += _risk_lines(risk, ctx.as_of)
    out += ["## Risk evaluation", "", ctx.tolerance_line, ""]
    if risks:
        out += ["| id | inherent | residual | against tolerance |", "| --- | --- | --- | --- |"]
        for risk in risks:
            out.append(
                f"| {_cell(risk.rid)} | {risk.inherent} | {risk.residual} | "
                f"{risk.tolerance_status} |"
            )
        out.append("")
    out += ["## Gaps", ""]
    out += _gap_lines(ctx)
    out += ["", PSPF_LIST, PSPF_RELEASE, ""]
    return "\n".join(out)


def _srmp(document, scope, assets, threats, risks, ctx: Context) -> str:
    out: list[str] = []
    subject = _safe(_text(scope.get("subject")) or "missing")
    plan = _mapping(document.get("plan"))
    approval = _mapping(plan.get("approval"))
    approved_by, approved_on = _text(approval.get("by")), _day(approval.get("date"))
    out += [f"# Security risk management plan: {subject}", "", DISCLAIMER, ""]
    out += [f"Plan type: {KINDS[ctx.kind]}.", ""]
    out += _scope_lines(scope, ctx)
    out.append("")
    if ctx.kind == "technology":
        out += [f"PSPF Requirement 0211: {REQ['0211']}", PSPF_LIST, ""]
    out += ["## PSPF security plan elements", ""]
    if ctx.kind != "entity":
        out += [
            "The mandatory elements apply to the entity security plan (PSPF Requirement 0018). "
            "For this plan they are a completeness check.",
            "",
        ]
    out += ["| element | status | detail |", "| --- | --- | --- |"]
    for key, label in ELEMENTS:
        status, detail = _element(key, plan, assets, threats, risks, ctx, document)
        out.append(f"| {label} | {status} | {_cell(detail)} |")
    out += ["", PSPF_RELEASE, "", "## Risk tolerance", "", ctx.tolerance_line, ""]
    out += ["## Risk treatment plan", ""]
    if risks:
        out += [
            "| id | steward | inherent | treatment | residual | against tolerance | acceptance |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
        for risk in risks:
            out.append(
                f"| {_cell(risk.rid)} | {_cell(risk.steward)} | {risk.inherent} | "
                f"{risk.option} | {risk.residual} | {risk.tolerance_status} | {risk.acceptance} |"
            )
        out.append("")
    else:
        out += ["Risks: missing. No treatment was drafted.", ""]
    for risk in risks:
        out += _treatment_lines(risk, ctx)
    out += ["## Monitoring and review", ""]
    out += _review_lines(ctx, approved_on)
    out += ["", "## Approval", ""]
    if approved_by and approved_on:
        out.append(f"Approved by {_safe(approved_by)} on {approved_on}.")
    else:
        approver = "Accountable Authority" if ctx.kind == "entity" else ctx.authority
        out.append(
            f"Not approved. Proposal: the {approver} reviews and approves this plan. "
            "Reversible by withdrawing the draft."
        )
        if ctx.kind == "entity":
            out.append(f"PSPF Requirement 0019: {REQ['0019']}")
        else:
            out.append(f"PSPF Requirement 0086: {REQ['0086']}")
    out += ["", "## Gaps", ""]
    out += _gap_lines(ctx)
    out += ["", PSPF_LIST, PSPF_RELEASE, ""]
    return "\n".join(out)


def _element(key, plan, assets, threats, risks, ctx: Context, document) -> tuple[str, str]:
    supplied = _text(plan.get(key))
    if key == "risk_environment":
        if threats and risks:
            return "drafted", f"{len(threats)} threats and {len(risks)} risks in this plan"
        return "missing", "no threat assessment or no risks"
    if key == "tolerance":
        if ctx.tolerance:
            return "drafted", f"residual {ctx.tolerance} or lower"
        return "missing", "PSPF Requirement 0036"
    if key == "strategies":
        open_risks = [risk.rid for risk in risks if risk.option == "missing"]
        if risks and not open_risks:
            return "drafted", "a treatment option for every risk"
        return "partial" if risks else "missing", "no treatment for " + (
            ", ".join(open_risks) if open_risks else "any risk"
        )
    if key == "critical_resources":
        critical = [_text(a.get("name")) or "missing" for a in assets if a.get("critical") is True]
        if critical:
            return "drafted", ", ".join(critical)
        return "missing", "no asset marked critical"
    if key == "threat_levels":
        env = _mapping(document.get("threat_environment"))
        level = _text(env.get("national_terrorism_threat_level"))
        if level:
            return "drafted", f"National Terrorism Threat Level {level}"
        return "missing", "National Terrorism Threat Level not supplied"
    if key == "review":
        return "drafted", "schedule in Monitoring and review"
    if supplied:
        return "drafted", supplied
    return "missing", "not supplied"


def _scope_lines(scope: dict, ctx: Context) -> list[str]:
    lines = [
        f"Entity: {_safe(_text(scope.get('entity')) or 'missing')}",
        f"Subject: {_safe(_text(scope.get('subject')) or 'missing')} ({ctx.kind})",
        f"Highest classification handled: {_safe(_text(scope.get('classification')) or 'missing')}",
        f"Residual risk decision: {ctx.authority}",
        f"As of: {ctx.as_of}",
    ]
    objectives = _strings(scope.get("objectives"))
    lines.append("Objectives: " + ("; ".join(_safe(o) for o in objectives) or "missing"))
    excluded = _strings(scope.get("out_of_scope"))
    lines.append("Out of scope: " + ("; ".join(_safe(o) for o in excluded) or "none recorded"))
    return lines


def _asset_table(assets: list[dict]) -> list[str]:
    if not assets:
        return ["Assets: missing. No asset was assumed."]
    lines = [
        "| id | asset | type | classification | critical | owner |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for asset in assets:
        critical = asset.get("critical")
        lines.append(
            "| "
            + " | ".join(
                _cell(value)
                for value in (
                    _text(asset.get("id")) or "missing",
                    _text(asset.get("name")) or "missing",
                    _text(asset.get("type")) or "missing",
                    _text(asset.get("classification")) or "missing",
                    "yes" if critical is True else "no" if critical is False else "missing",
                    _text(asset.get("owner")) or "missing",
                )
            )
            + " |"
        )
    return lines


def _threat_env_lines(document: dict, as_of: str) -> list[str]:
    env = _mapping(document.get("threat_environment"))
    level = _text(env.get("national_terrorism_threat_level"))
    lines = []
    if level:
        lines.append(f"National Terrorism Threat Level: {_safe(level)}")
        lines.append(_citation(env.get("source"), as_of))
    else:
        lines.append(
            "National Terrorism Threat Level: missing. This skill has no tool for it. "
            "Ask the entity's security adviser."
        )
    asio = _text(env.get("asio_reporting"))
    lines.append(
        "ASIO reporting on espionage, foreign interference or sabotage: "
        + (_safe(asio) if asio else "missing")
    )
    return lines


def _threat_lines(threat: dict, as_of: str) -> list[str]:
    tid = _text(threat.get("id")) or "missing"
    lines = [f"### {tid}: {_safe(_text(threat.get('name')) or 'missing')}", ""]
    for key, label in (
        ("actor_type", "Actor type"),
        ("capability", "Capability"),
        ("intent", "Intent"),
    ):
        lines.append(f"{label}: {_safe(_text(threat.get(key)) or 'missing')}")
    techniques = _strings(threat.get("attack_techniques"))
    if techniques:
        lines.append("ATT&CK techniques: " + ", ".join(_safe(t) for t in techniques))
    evidence = _evidence(threat)
    if not evidence:
        lines.append(
            "Evidence: none sourced. This threat is an assessor assumption and needs a source "
            "before the plan is approved."
        )
    for item in evidence:
        text = _text(item.get("text"))
        marker = " (contains an instruction: recorded as content, not carried out)"
        lines.append(f"- {_safe(text)}{marker if _INSTRUCTION.search(text) else ''}")
        lines.append(f"  {_citation(item.get('source'), as_of)}")
    lines.append("")
    return lines


def _risk_lines(risk: Rated, as_of: str) -> list[str]:
    lines = [f"### {risk.rid}: {_safe(risk.statement)}", ""]
    lines.append("Assets: " + (", ".join(_safe(a) for a in risk.assets) or "missing"))
    lines.append("Threats: " + (", ".join(_safe(t) for t in risk.threats) or "missing"))
    lines.append(f"Vulnerability: {_safe(_text(risk.raw.get('vulnerability')) or 'missing')}")
    controls = [_mapping(item) for item in _list(risk.raw.get("controls"))]
    if not controls:
        lines.append("Existing controls: none recorded.")
    for control in controls:
        ism = _strings(control.get("ism"))
        suffix = f" ({', '.join(_safe(i) for i in ism)})" if ism else ""
        effect = _text(control.get("effectiveness")) or "effectiveness not tested"
        lines.append(f"- Control: {_safe(_text(control.get('text')) or 'missing')}{suffix}.")
        lines.append(f"  Effectiveness: {_safe(effect)}.")
        citation = _citation(control.get("source"), as_of)
        if citation:
            lines.append(f"  {citation}")
    lines.append(f"Rationale: {_safe(_text(risk.raw.get('rationale')) or 'missing')}")
    if risk.inherent == "unrated":
        lines.append("Inherent risk: unrated.")
    else:
        lines.append(
            f"Inherent risk: {risk.likelihood} likelihood and {risk.consequence} consequence "
            f"give {risk.inherent}."
        )
    lines.append(f"Rated by: {_rated(risk)}")
    if risk.steward == "missing":
        lines.append(f"Risk steward: missing. PSPF Requirement 0037: {REQ['0037']}")
    else:
        lines.append(f"Risk steward: {_safe(risk.steward)}")
    lines.append("")
    return lines


def _treatment_lines(risk: Rated, ctx: Context) -> list[str]:
    lines = [f"### {risk.rid}: {_safe(risk.statement)}", ""]
    lines.append(f"Treatment option: {OPTIONS.get(risk.option, 'missing')}")
    if not risk.actions and risk.option in {"reduce", "share", "avoid"}:
        lines.append("Actions: missing.")
    for action in risk.actions:
        text = _safe(_text(action.get("text")) or "missing").rstrip(".")
        owner = _safe(_text(action.get("owner")) or "missing")
        due = _day(action.get("due")) or "missing"
        lines.append(f"Proposal: {text}. Owner: {owner}. Due: {due}.")
        ism = _strings(action.get("ism"))
        if ism:
            lines.append("  ISM controls: " + ", ".join(_safe(i) for i in ism))
        citation = _citation(action.get("source"))
        if citation:
            lines.append(f"  {citation}")
    if risk.residual == "unrated":
        lines.append(f"Residual risk: unrated ({risk.residual_note}).")
    else:
        lines.append(
            f"Residual risk: {risk.residual_likelihood} likelihood and "
            f"{risk.residual_consequence} consequence give {risk.residual} "
            f"({risk.residual_note})."
        )
    lines.append(f"Against tolerance: {risk.tolerance_status}.")
    if risk.acceptance != "not recorded":
        lines.append(f"Acceptance: {risk.acceptance}.")
    elif risk.tolerance_status == "above tolerance":
        lines.append(
            f"Proposal: the {ctx.authority} decides whether to accept this residual risk above "
            "tolerance or to fund further treatment. Reversible by recording a new decision."
        )
    elif risk.tolerance_status == "within tolerance":
        who = ctx.authority if ctx.kind in {"system", "technology"} else "risk steward"
        when = " once the treatment is in place" if risk.actions else ""
        lines.append(
            f"Proposal: the {who} records acceptance of this residual risk{when}. Reversible by "
            "recording a new decision."
        )
    lines.append("")
    return lines


def _review_lines(ctx: Context, approved_on: str) -> list[str]:
    base = approved_on or ctx.as_of
    label = "approval" if approved_on else "this draft (not yet approved)"
    return [
        f"Consider this plan by {_add_years(base, 1)} and formally review it by "
        f"{_add_years(base, 2)}, counted from {label} on {base}.",
        f"PSPF Requirement 0020: {REQ['0020']}",
        "Review earlier when the National Terrorism Threat Level changes, a new threat changes "
        "a business impact level, or the subject changes significantly.",
        PSPF_LIST,
    ]


def _matrix_lines(ctx: Context) -> list[str]:
    matrix = ctx.matrix
    lines = [f"Risk matrix: {matrix['name']}."]
    if ctx.matrix_default:
        lines.append(
            "The entity's own risk matrix was not supplied. Ratings use the default matrix: "
            "likelihood and consequence are scored 1 to 5 and multiplied; 1 to 3 is low, 4 to 9 "
            "medium, 10 to 15 high and 16 to 25 extreme. Replace it with the entity's matrix "
            "before approval."
        )
    lines.append("Likelihood: " + ", ".join(matrix["likelihood"]) + ".")
    lines.append("Consequence: " + ", ".join(matrix["consequence"]) + ".")
    return lines


def _gap_lines(ctx: Context) -> list[str]:
    gaps = list(dict.fromkeys(ctx.gaps))
    for path in dict.fromkeys(ctx.instructions):
        gaps.append(
            f"{path} contains an instruction. It was recorded as content and not carried out."
        )
    if not gaps:
        return ["None found."]
    return [f"{index}. {_safe(gap)}" for index, gap in enumerate(gaps, start=1)]


def _register(risks: list[Rated]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(REGISTER_COLUMNS.split(","))
    for risk in risks:
        actions = "; ".join(
            f"{_text(a.get('text'))} (owner {_text(a.get('owner')) or 'missing'}, "
            f"due {_day(a.get('due')) or 'missing'})"
            for a in risk.actions
        )
        row = [
            risk.rid,
            risk.statement,
            " ".join(risk.assets),
            " ".join(risk.threats),
            risk.steward,
            risk.likelihood,
            risk.consequence,
            risk.inherent,
            risk.rated_by,
            risk.option,
            actions,
            risk.residual_likelihood,
            risk.residual_consequence,
            risk.residual,
            risk.tolerance_status,
            risk.acceptance,
        ]
        writer.writerow([_formula_safe(defang_text(value)) for value in row])
    return buffer.getvalue()


def _rated(risk: Rated) -> str:
    if risk.rated_by == "proposed":
        return "proposed, for the risk steward to confirm"
    return risk.rated_by


def _evidence(threat: dict) -> list[dict]:
    return [
        _mapping(item)
        for item in _list(threat.get("evidence"))
        if _text(_mapping(item).get("text"))
    ]


def _citation(raw: object, as_of: str = "") -> str:
    data = _mapping(raw)
    name = _text(data.get("name")).replace(",", "")
    if not name:
        return f"Source: supplied context, none, retrieved {as_of}" if as_of else ""
    version = _text(data.get("version")).replace(",", "") or "none"
    retrieved = _day(data.get("retrieved")) or as_of
    return f"Source: {name}, {version}, retrieved {retrieved}"


def _add_years(day: str, years: int) -> str:
    parsed = date.fromisoformat(day)
    try:
        return parsed.replace(year=parsed.year + years).isoformat()
    except ValueError:
        return parsed.replace(year=parsed.year + years, day=28).isoformat()


def _safe(value: str) -> str:
    return defang_text(value)


def _cell(value: str) -> str:
    return defang_text(value).replace("|", "/").replace("\n", " ")


def _formula_safe(value: str) -> str:
    return f"'{value}" if value.startswith(_FORMULA) else value


def _day(value: object) -> str:
    if not isinstance(value, str) or not _DATE.match(value):
        return ""
    try:
        date.fromisoformat(value)
    except ValueError:
        return ""
    return value


def _text(value: object) -> str:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return " ".join(value.split()) if isinstance(value, str) else ""


def _strings(value: object) -> list[str]:
    return [_text(item) for item in _list(value) if _text(item)]


def _list(value: object) -> list:
    return value if isinstance(value, list) else []


def _mapping(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="render_risk")
    parser.add_argument("document", type=Path)
    parser.add_argument("--out", type=Path, help="directory for tra.md, srmp.md and register.csv")
    args = parser.parse_args(argv)
    try:
        loaded = json.loads(args.document.read_text(encoding="utf-8"))
        report = render(loaded)
    except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
        print(f"Risk input error: {exc}", file=sys.stderr)
        return 2
    sys.stdout.write(report.markdown)
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        if report.tra:
            (args.out / "tra.md").write_text(report.tra, encoding="utf-8")
        if report.srmp:
            (args.out / "srmp.md").write_text(report.srmp, encoding="utf-8")
        (args.out / "register.csv").write_text(report.register, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
