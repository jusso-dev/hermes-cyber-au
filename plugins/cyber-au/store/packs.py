"""Sector packs: extra sources, rules, skill prompts and connector suggestions for one sector.

A pack is a directory holding ``pack.yaml``. Shipped packs live in ``packs/<name>/`` at the
distribution root. Your own packs go in ``plugin-data/cyber-au/packs/<name>/`` on the
profile, which an update never touches; a local pack with a shipped name replaces it.

``org.yaml`` switches packs on. An explicit ``sector_packs`` list wins (``[none]`` turns
every pack off). Otherwise the pack named after the sector, and every pack whose
``sectors`` list names the sector, are active. Adding or removing a pack directory, or
editing ``org.yaml``, is enough: no core file changes.

Every rule names a source from the pack's ``sources`` list and carries its own ``reviewed``
and ``review_by`` dates, so a stale rule is visible in ``doctor``. Pack text is reference
data. It is not legal advice, and a pack cannot tell a skill to submit or send anything.

The same format holds the sector-neutral profile rules in ``org_rules.yaml`` next to this
module. Standard library plus PyYAML (loaded lazily), so ``doctor`` can import it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from .org import ENVIRONMENTS, REGULATORS, SECTORS, SIZES, TURNOVER, OrgProfile

MANIFEST = "pack.yaml"
CORE_RULES = Path(__file__).resolve().parent / "org_rules.yaml"
RULE_KINDS = ("obligation", "guidance")
_NAME = re.compile(r"^[a-z][a-z0-9-]{1,40}$")
_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
_VERSION = re.compile(r"^\d+\.\d+\.\d+$")
_SKILL = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_TOP_KEYS = {
    "name",
    "version",
    "title",
    "description",
    "sectors",
    "reviewed",
    "review_by",
    "sources",
    "connectors",
    "rules",
    "prompts",
    "playbooks",
}
_SOURCE_KEYS = {"id", "title", "version", "url", "retrieved", "note"}
_RULE_KEYS = {
    "id",
    "title",
    "kind",
    "applies_when",
    "skills",
    "summary",
    "source",
    "section",
    "reviewed",
    "review_by",
}
# applies_when keys and the values each may take. Booleans match exactly; a list matches
# when the profile value (or any profile list item) is in it.
_CONDITIONS: dict[str, tuple[str, ...] | None] = {
    "critical_infrastructure": None,
    "holds_personal_information": None,
    "sector": SECTORS,
    "size": SIZES,
    "turnover": TURNOVER,
    "regulators": REGULATORS,
    "environments": ENVIRONMENTS,
}
_LONG_TEXT = 2000
# A pack is data. It may describe an obligation, but it may not tell a skill to act.
_ACTION = re.compile(
    r"(?i)\b(submit|lodge|send|post|email|notify|publish)\b[^.]{0,40}"
    r"\b(automatically|now|for you|without (?:asking|approval))\b"
)
_EM_DASH = "\u2014"


class PackError(ValueError):
    """A pack manifest cannot be used. ``problems`` lists every reason."""

    def __init__(self, name: str, problems: list[str]):
        self.name = name
        self.problems = problems
        super().__init__(f"pack {name}: " + "; ".join(problems))


@dataclass(frozen=True)
class Source:
    id: str
    title: str
    version: str
    url: str
    retrieved: str
    note: str = ""

    def citation(self) -> str:
        return f"Source: {self.title}, {self.version}, retrieved {self.retrieved}"


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    kind: str
    summary: str
    source: str
    section: str
    reviewed: str
    review_by: str
    applies_when: dict = field(default_factory=dict)
    skills: tuple[str, ...] = ()

    def applies(self, profile: OrgProfile) -> bool:
        for key, wanted in self.applies_when.items():
            have = getattr(profile, key)
            if isinstance(wanted, bool):
                if bool(have) is not wanted:
                    return False
            elif isinstance(have, tuple):
                if not set(have) & set(wanted):
                    return False
            elif have not in wanted:
                return False
        return True

    def for_skill(self, skill: str | None) -> bool:
        return skill is None or not self.skills or skill in self.skills

    def stale(self, today: date) -> bool:
        return date.fromisoformat(self.review_by) < today


@dataclass(frozen=True)
class Pack:
    name: str
    version: str
    title: str
    description: str
    sectors: tuple[str, ...]
    reviewed: str
    review_by: str
    sources: dict[str, Source]
    connectors: tuple[dict, ...]
    rules: tuple[Rule, ...]
    prompts: dict[str, tuple[str, ...]]
    playbooks: tuple[str, ...]
    path: Path

    def stale_rules(self, today: date) -> list[Rule]:
        return [rule for rule in self.rules if rule.stale(today)]

    def rules_for(self, profile: OrgProfile, skill: str | None = None) -> list[Rule]:
        return [rule for rule in self.rules if rule.applies(profile) and rule.for_skill(skill)]


@dataclass
class ActivePacks:
    packs: list[Pack]
    missing: list[str]
    problems: list[str]
    reason: str


def shipped_root(root: str | Path | None = None) -> Path:
    """``<root>/packs``, or the packs directory of the distribution holding this plugin."""
    if root is not None:
        return Path(root) / "packs"
    # <root>/plugins/cyber-au/store/packs.py
    return Path(__file__).resolve().parents[3] / "packs"


def pack_roots(root: str | Path | None = None, data_dir: str | Path | None = None) -> list[Path]:
    """Shipped packs first, then local packs from the profile data directory."""
    roots = [shipped_root(root)]
    if data_dir is not None:
        roots.append(Path(data_dir) / "packs")
    return roots


def _date_text(value: object, label: str, problems: list[str]) -> str:
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, str):
        try:
            return date.fromisoformat(value.strip()).isoformat()
        except ValueError:
            pass
    problems.append(f"{label} must be a YYYY-MM-DD date")
    return "1970-01-01"


def _text(value: object, label: str, problems: list[str], *, required: bool = True) -> str:
    if value is None and not required:
        return ""
    if not isinstance(value, str) or (required and not value.strip()):
        problems.append(f"{label} must be a non-empty string")
        return ""
    text = " ".join(value.split())
    if len(text) > _LONG_TEXT:
        problems.append(f"{label} is longer than {_LONG_TEXT} characters")
    if _EM_DASH in text:
        problems.append(f"{label} contains an em dash")
    if _ACTION.search(text):
        problems.append(f"{label} must not tell a skill to submit or send")
    return text


def _str_list(value: object, label: str, problems: list[str]) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        problems.append(f"{label} must be a list of strings")
        return ()
    return tuple(item.strip() for item in value)


def _sources(raw: object, problems: list[str]) -> dict[str, Source]:
    if not isinstance(raw, list) or not raw:
        problems.append("sources must be a non-empty list")
        return {}
    out: dict[str, Source] = {}
    for index, item in enumerate(raw):
        label = f"sources[{index}]"
        if not isinstance(item, dict):
            problems.append(f"{label} must be a mapping")
            continue
        extra = sorted(set(item) - _SOURCE_KEYS)
        if extra:
            problems.append(f"{label} has unknown keys: {', '.join(extra)}")
        source_id = item.get("id")
        if not isinstance(source_id, str) or not _ID.match(source_id):
            problems.append(f"{label} id must be a lowercase token")
            continue
        if source_id in out:
            problems.append(f"{label} duplicates {source_id}")
            continue
        url = _text(item.get("url"), f"source {source_id} url", problems)
        if url and not url.startswith("https://"):
            problems.append(f"source {source_id} url must be https")
        out[source_id] = Source(
            id=source_id,
            title=_text(item.get("title"), f"source {source_id} title", problems),
            version=_text(item.get("version"), f"source {source_id} version", problems),
            url=url,
            retrieved=_date_text(item.get("retrieved"), f"source {source_id} retrieved", problems),
            note=_text(item.get("note"), f"source {source_id} note", problems, required=False),
        )
    return out


def _conditions(raw: object, label: str, problems: list[str]) -> dict:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        problems.append(f"{label} applies_when must be a mapping")
        return {}
    out: dict = {}
    for key, value in raw.items():
        if key not in _CONDITIONS:
            problems.append(f"{label} applies_when has unknown key {key}")
            continue
        allowed = _CONDITIONS[key]
        if allowed is None:
            if not isinstance(value, bool):
                problems.append(f"{label} applies_when.{key} must be true or false")
                continue
            out[key] = value
            continue
        values = [value] if isinstance(value, str) else value
        if not isinstance(values, list) or not values:
            problems.append(f"{label} applies_when.{key} must be a value or a list")
            continue
        bad = [item for item in values if item not in allowed]
        if bad:
            problems.append(f"{label} applies_when.{key} has unknown values: {bad}")
            continue
        out[key] = tuple(values)
    return out


def _rules(
    raw: object, sources: dict[str, Source], skills: set[str] | None, problems: list[str]
) -> tuple[Rule, ...]:
    if not isinstance(raw, list) or not raw:
        problems.append("rules must be a non-empty list")
        return ()
    out: list[Rule] = []
    seen: set[str] = set()
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            problems.append(f"rules[{index}] must be a mapping")
            continue
        rule_id = item.get("id")
        if not isinstance(rule_id, str) or not _ID.match(rule_id):
            problems.append(f"rules[{index}] id must be a lowercase token")
            continue
        label = f"rule {rule_id}"
        extra = sorted(set(item) - _RULE_KEYS)
        if extra:
            problems.append(f"{label} has unknown keys: {', '.join(extra)}")
        if rule_id in seen:
            problems.append(f"{label} is duplicated")
            continue
        seen.add(rule_id)
        kind = item.get("kind")
        if kind not in RULE_KINDS:
            problems.append(f"{label} kind must be one of {', '.join(RULE_KINDS)}")
        source = item.get("source")
        if source not in sources:
            problems.append(f"{label} source {source!r} is not in sources")
        rule_skills = _str_list(item.get("skills"), f"{label} skills", problems)
        for skill in rule_skills:
            if not _SKILL.match(skill) or (skills is not None and skill not in skills):
                problems.append(f"{label} names unknown skill {skill}")
        reviewed = _date_text(item.get("reviewed"), f"{label} reviewed", problems)
        review_by = _date_text(item.get("review_by"), f"{label} review_by", problems)
        if review_by <= reviewed:
            problems.append(f"{label} review_by must be after reviewed")
        out.append(
            Rule(
                id=rule_id,
                title=_text(item.get("title"), f"{label} title", problems),
                kind=str(kind),
                summary=_text(item.get("summary"), f"{label} summary", problems),
                source=str(source),
                section=_text(item.get("section"), f"{label} section", problems),
                reviewed=reviewed,
                review_by=review_by,
                applies_when=_conditions(item.get("applies_when"), label, problems),
                skills=rule_skills,
            )
        )
    return tuple(out)


def _connectors(raw: object, problems: list[str], servers: dict | None) -> tuple[dict, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        problems.append("connectors must be a list")
        return ()
    out = []
    for index, item in enumerate(raw):
        label = f"connectors[{index}]"
        if not isinstance(item, dict) or set(item) - {"key", "why"}:
            problems.append(f"{label} must be a mapping with key and why")
            continue
        key = item.get("key")
        if not isinstance(key, str) or not key:
            problems.append(f"{label} key must be a server name from mcp/servers.yaml")
            continue
        if servers is not None and key not in servers:
            problems.append(f"{label} key {key} is not in mcp/servers.yaml")
        out.append({"key": key, "why": _text(item.get("why"), f"{label} why", problems)})
    return tuple(out)


def _prompts(raw: object, skills: set[str] | None, problems: list[str]) -> dict:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        problems.append("prompts must map a skill name to a list of text")
        return {}
    out: dict[str, tuple[str, ...]] = {}
    for skill, texts in raw.items():
        if not isinstance(skill, str) or not _SKILL.match(skill):
            problems.append(f"prompts key {skill!r} must be a skill name")
            continue
        if skills is not None and skill not in skills:
            problems.append(f"prompts names unknown skill {skill}")
        items = [texts] if isinstance(texts, str) else texts
        if not isinstance(items, list) or not items:
            problems.append(f"prompts.{skill} must be a list of text")
            continue
        out[skill] = tuple(_text(text, f"prompts.{skill}", problems) for text in items)
    return out


def parse_pack(
    data: object,
    path: Path,
    *,
    name: str | None = None,
    servers: dict | None = None,
    skills: set[str] | None = None,
    playbooks_dir: Path | None = None,
) -> Pack:
    """Validate a parsed manifest. Raises PackError listing every problem.

    ``servers``, ``skills`` and ``playbooks_dir``, when given, are checked against the
    connector keys, skill names and playbook files the pack refers to.
    """
    name = name or path.name
    problems: list[str] = []
    if not isinstance(data, dict):
        raise PackError(name, ["pack.yaml must be a mapping"])
    extra = sorted(set(data) - _TOP_KEYS)
    if extra:
        problems.append(f"unknown keys: {', '.join(extra)}")
    if not _NAME.match(name):
        problems.append("pack name must be a lowercase token")
    if data.get("name") != name:
        problems.append(f"name must be {name}, the directory name")
    version = data.get("version")
    if not isinstance(version, str) or not _VERSION.match(version):
        problems.append("version must be MAJOR.MINOR.PATCH")
    sectors = _str_list(data.get("sectors"), "sectors", problems)
    for sector in sectors:
        if sector not in SECTORS:
            problems.append(f"sectors has unknown sector {sector}")
    sources = _sources(data.get("sources"), problems)
    rules = _rules(data.get("rules"), sources, skills, problems)
    unused = sorted(set(sources) - {rule.source for rule in rules})
    if unused:
        problems.append(f"sources not cited by any rule: {', '.join(unused)}")
    playbooks = _str_list(data.get("playbooks"), "playbooks", problems)
    if playbooks_dir is not None:
        for ref in playbooks:
            if ".." in Path(ref).parts or not (playbooks_dir / ref).is_file():
                problems.append(f"playbook {ref} is not a file under playbooks/")
    reviewed = _date_text(data.get("reviewed"), "reviewed", problems)
    review_by = _date_text(data.get("review_by"), "review_by", problems)
    if review_by <= reviewed:
        problems.append("review_by must be after reviewed")
    pack = Pack(
        name=name,
        version=str(version),
        title=_text(data.get("title"), "title", problems),
        description=_text(data.get("description"), "description", problems),
        sectors=sectors,
        reviewed=reviewed,
        review_by=review_by,
        sources=sources,
        connectors=_connectors(data.get("connectors"), problems, servers),
        rules=rules,
        prompts=_prompts(data.get("prompts"), skills, problems),
        playbooks=playbooks,
        path=path,
    )
    if problems:
        raise PackError(name, problems)
    return pack


def _read_yaml(path: Path, name: str) -> object:
    import yaml

    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise PackError(name, [f"{path.name} could not be read ({type(exc).__name__})"]) from exc


def load_pack(directory: Path, **context) -> Pack:
    manifest = directory / MANIFEST
    if not manifest.is_file():
        raise PackError(directory.name, [f"{MANIFEST} is missing"])
    return parse_pack(_read_yaml(manifest, directory.name), directory, **context)


def load_core_rules(path: Path = CORE_RULES, **context) -> Pack:
    """The sector-neutral profile rules shipped with the plugin."""
    return parse_pack(_read_yaml(path, "core"), path.parent, name="core", **context)


def list_packs(roots: list[Path] | None = None, **context) -> tuple[list[Pack], list[str]]:
    """Every valid pack under ``roots``, and one problem line for each pack that fails.

    A later root replaces a pack of the same name from an earlier root.
    """
    found: dict[str, Pack] = {}
    problems: list[str] = []
    for base in roots or pack_roots():
        if not base.is_dir():
            continue
        for child in sorted(base.iterdir()):
            if not child.is_dir() or child.name.startswith((".", "_")):
                continue
            try:
                found[child.name] = load_pack(child, **context)
            except PackError as exc:
                problems.append(str(exc))
    return [found[name] for name in sorted(found)], problems


def active_packs(profile: OrgProfile, roots: list[Path] | None = None) -> ActivePacks:
    """The packs this profile switches on, and why."""
    available, problems = list_packs(roots)
    by_name = {pack.name: pack for pack in available}
    if profile.sector_packs:
        wanted = list(profile.packs)
        reason = "sector_packs in org.yaml" if wanted else "sector_packs: none in org.yaml"
        missing = [name for name in wanted if name not in by_name]
    else:
        wanted = list(profile.packs)
        wanted += [pack.name for pack in available if profile.sector in pack.sectors]
        reason = f"sector {profile.sector}"
        # A sector default with no installed pack is not an error.
        missing = []
    chosen: list[Pack] = []
    for name in wanted:
        if name in by_name and by_name[name] not in chosen:
            chosen.append(by_name[name])
    return ActivePacks(packs=chosen, missing=missing, problems=problems, reason=reason)
