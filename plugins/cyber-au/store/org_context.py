"""``cyberau-mcp org``: what the organisation profile means for a skill.

``cyberau-mcp org context --skill soci-reporting`` reads ``org.yaml``, the core profile rules
and the active sector packs, and prints the profile, the rules that apply to it for that
skill (each with its source and review date) and the pack's prompt additions. Skills run it
before their procedure so the answer is tailored from the first question.

Pure and local: it reads files on the profile and never uses the network. The output is the
organisation's own description plus reviewed reference rules. It is not a coverage decision
and it is not legal advice.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from .org import OrgFileError, OrgProfile, load_org, org_path
from .packs import (
    ActivePacks,
    Pack,
    PackError,
    Rule,
    active_packs,
    list_packs,
    load_core_rules,
    pack_roots,
)
from .paths import configured_data_dir

HEADER = (
    "Organisation profile from org.yaml. This is the organisation's own description, not a "
    "tool result and not a coverage decision. Guidance, not legal advice."
)
NO_PROFILE = (
    "Organisation profile: not set. Run hermes cyber-au setup to write org.yaml. Using a "
    "sector-neutral default, so ask the coverage questions."
)


@dataclass
class Context:
    profile: OrgProfile
    found: bool
    skill: str | None
    active: ActivePacks
    rules: list[tuple[Pack, Rule]] = field(default_factory=list)
    prompts: list[tuple[Pack, str]] = field(default_factory=list)
    connectors: list[tuple[Pack, dict]] = field(default_factory=list)
    today: date = field(default_factory=date.today)

    def to_dict(self) -> dict:
        return {
            "profile_found": self.found,
            "profile": self.profile.to_dict(),
            "warnings": list(self.profile.warnings) + self.active.problems,
            "skill": self.skill,
            "active_packs": [
                {"name": pack.name, "version": pack.version, "title": pack.title}
                for pack in self.active.packs
            ],
            "packs_reason": self.active.reason,
            "missing_packs": self.active.missing,
            "rules": [_rule_dict(pack, rule, self.today) for pack, rule in self.rules],
            "prompts": [{"pack": pack.name, "text": text} for pack, text in self.prompts],
            "connectors": [{"pack": pack.name, **item} for pack, item in self.connectors],
        }


def _rule_dict(pack: Pack, rule: Rule, today: date) -> dict:
    source = pack.sources[rule.source]
    return {
        "pack": pack.name,
        "id": rule.id,
        "kind": rule.kind,
        "title": rule.title,
        "section": rule.section,
        "summary": rule.summary,
        "citation": source.citation(),
        "url": source.url,
        "reviewed": rule.reviewed,
        "review_by": rule.review_by,
        "review_overdue": rule.stale(today),
    }


def build_context(
    profile: OrgProfile,
    *,
    found: bool = True,
    skill: str | None = None,
    root: str | Path | None = None,
    data_dir: str | Path | None = None,
    today: date | None = None,
) -> Context:
    """Collect the rules, prompts and connector hints that apply to ``profile``."""
    roots = pack_roots(root, data_dir)
    active = active_packs(profile, roots)
    sources: list[Pack] = []
    try:
        sources.append(load_core_rules())
    except PackError as exc:
        active.problems.append(str(exc))
    sources.extend(active.packs)
    context = Context(
        profile=profile, found=found, skill=skill, active=active, today=today or date.today()
    )
    for pack in sources:
        context.rules.extend((pack, rule) for rule in pack.rules_for(profile, skill))
        if skill is not None:
            context.prompts.extend((pack, text) for text in pack.prompts.get(skill, ()))
        context.connectors.extend((pack, item) for item in pack.connectors)
    return context


def _yes(value: bool) -> str:
    return "yes" if value else "no"


def _items(values: tuple[str, ...]) -> str:
    return ", ".join(values) if values else "none recorded"


def render_text(context: Context) -> str:
    profile = context.profile
    lines = [HEADER, ""]
    if not context.found:
        lines.extend([NO_PROFILE, ""])
    lines.append(
        "Profile: "
        f"sector {profile.sector}; size {profile.size}; turnover {profile.turnover}; "
        f"regulators {_items(profile.regulators)}; environments {_items(profile.environments)}; "
        f"critical infrastructure {_yes(profile.critical_infrastructure)}; "
        f"holds personal information {_yes(profile.holds_personal_information)}."
    )
    if context.active.packs:
        names = ", ".join(f"{pack.name} {pack.version}" for pack in context.active.packs)
        lines.append(f"Active sector packs: {names} ({context.active.reason}).")
    else:
        lines.append(f"Active sector packs: none ({context.active.reason}).")
    for name in context.active.missing:
        lines.append(f"Missing sector pack: {name} is named in org.yaml but is not installed.")
    label = f" for {context.skill}" if context.skill else ""
    lines.extend(["", f"Rules that apply to this profile{label}:"])
    if not context.rules:
        lines.append("- none")
    for pack, rule in context.rules:
        source = pack.sources[rule.source]
        lines.append(f"- [{rule.kind}] {rule.title} ({rule.section}). {rule.summary}")
        lines.append(f"  {source.citation()}")
        if rule.stale(context.today):
            lines.append(
                f"  Review overdue since {rule.review_by}: re-check the source before relying "
                "on this rule."
            )
    if context.prompts:
        lines.extend(["", f"Sector pack notes{label}:"])
        lines.extend(f"- {text}" for _pack, text in context.prompts)
    warnings = list(context.profile.warnings) + context.active.problems
    if warnings:
        lines.extend(["", "Warnings:"])
        lines.extend(f"- {item}" for item in warnings)
    return "\n".join(lines) + "\n"


def render_packs(roots: list[Path], profile: OrgProfile, today: date) -> dict:
    available, problems = list_packs(roots)
    active = {pack.name for pack in active_packs(profile, roots).packs}
    return {
        "packs": [
            {
                "name": pack.name,
                "version": pack.version,
                "title": pack.title,
                "sectors": list(pack.sectors),
                "active": pack.name in active,
                "rules": len(pack.rules),
                "stale_rules": [rule.id for rule in pack.stale_rules(today)],
                "path": str(pack.path),
            }
            for pack in available
        ],
        "problems": problems,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cyberau-mcp org",
        description="Show the organisation profile and the sector packs it switches on.",
    )
    parser.add_argument("--org", help="org.yaml path. Defaults to $CYBERAU_DATA_DIR/org.yaml")
    parser.add_argument("--root", help="Distribution root holding packs/. Defaults to this one")
    sub = parser.add_subparsers(dest="org_command", required=True)
    context = sub.add_parser("context", help="Profile, rules and pack notes for one skill")
    context.add_argument("--skill", help="Skill name, such as soci-reporting")
    context.add_argument("--json", action="store_true")
    show = sub.add_parser("show", help="Print the profile as JSON")
    show.set_defaults(json=True)
    packs = sub.add_parser("packs", help="List installed packs and which are active")
    packs.set_defaults(json=True)
    args = parser.parse_args(argv)

    try:
        target = org_path(args.org)
    except OrgFileError:
        target = None
    try:
        profile = load_org(target) if target is not None else OrgProfile()
    except OrgFileError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    found = target is not None and target.is_file()
    data_dir = target.parent if target is not None else configured_data_dir()
    today = date.today()

    if args.org_command == "show":
        payload = {"path": str(target) if target else None, "found": found}
        payload.update(profile.to_dict())
        payload["packs"] = list(profile.packs)
        payload["warnings"] = list(profile.warnings)
        print(json.dumps(payload, indent=2))
        return 0
    if args.org_command == "packs":
        report = render_packs(pack_roots(args.root, data_dir), profile, today)
        print(json.dumps(report, indent=2))
        return 1 if report["problems"] else 0
    built = build_context(
        profile, found=found, skill=args.skill, root=args.root, data_dir=data_dir, today=today
    )
    if args.json:
        print(json.dumps(built.to_dict(), indent=2))
    else:
        sys.stdout.write(render_text(built))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
