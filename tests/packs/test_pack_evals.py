"""Sector packs: shipped manifests validate, and the offline evals check tailoring.

Each eval case writes a synthetic org.yaml, renders the org context a skill reads, and checks
required and forbidden text. No network and no model.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest
import yaml
from store.org import load_org, parse_org, write_org
from store.org_context import build_context, render_text
from store.packs import (
    PackError,
    active_packs,
    list_packs,
    load_core_rules,
    pack_roots,
    parse_pack,
)

ROOT = Path(__file__).resolve().parents[2]
PACKS = ROOT / "packs"
EVALS = sorted(Path(__file__).resolve().parent.glob("*/evals.yaml"))
TODAY = date(2026, 11, 28)
EM_DASH = "\u2014"


def _servers() -> dict:
    return yaml.safe_load((ROOT / "mcp" / "servers.yaml").read_text(encoding="utf-8"))["servers"]


def _skills() -> set[str]:
    return {path.name for path in (ROOT / "skills").iterdir() if (path / "SKILL.md").is_file()}


def _strict() -> dict:
    return {"servers": _servers(), "skills": _skills(), "playbooks_dir": ROOT / "playbooks"}


def _cases() -> list:
    found = []
    for path in EVALS:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        for case in data["cases"]:
            found.append(pytest.param(data["pack"], case, id=f"{data['pack']}:{case['id']}"))
    return found


def test_every_shipped_pack_validates_against_connectors_skills_and_playbooks():
    packs, problems = list_packs([PACKS], **_strict())
    assert problems == []
    assert {pack.name for pack in packs} >= {"energy-water", "health"}
    load_core_rules(skills=_skills())


def test_every_shipped_pack_has_offline_evals():
    names = {path.parent.name for path in EVALS}
    shipped = {path.name for path in PACKS.iterdir() if (path / "pack.yaml").is_file()}
    assert shipped <= names


def test_every_rule_has_a_source_url_and_a_future_review_date():
    packs, _ = list_packs([PACKS])
    for pack in [*packs, load_core_rules()]:
        for rule in pack.rules:
            source = pack.sources[rule.source]
            assert source.url.startswith("https://"), rule.id
            assert rule.reviewed <= TODAY.isoformat() < rule.review_by, rule.id
            assert EM_DASH not in rule.summary


@pytest.mark.parametrize(("pack", "case"), _cases())
def test_pack_eval(pack: str, case: dict, tmp_path: Path):
    profile = parse_org(case["org"])
    write_org(profile, tmp_path / "org.yaml")
    loaded = load_org(tmp_path / "org.yaml")
    today = date.fromisoformat(str(case.get("today", TODAY)))
    context = build_context(loaded, skill=case["skill"], root=ROOT, data_dir=tmp_path, today=today)
    text = render_text(context)
    for fact in case["required_facts"]:
        assert fact in text, f"{pack}:{case['id']} missing {fact!r}\n{text}"
    for claim in case.get("forbidden_claims") or []:
        assert claim not in text, f"{pack}:{case['id']} has forbidden {claim!r}\n{text}"
    for line in text.splitlines():
        if "Source:" in line:
            assert line.strip().startswith("Source: ") and ", retrieved 20" in line
    assert EM_DASH not in text


def _minimal(**overrides) -> dict:
    data = {
        "name": "example-pack",
        "version": "0.1.0",
        "title": "Example",
        "description": "A synthetic pack for tests.",
        "sectors": ["retail"],
        "reviewed": "2026-11-28",
        "review_by": "2027-05-28",
        "sources": [
            {
                "id": "example",
                "title": "Example source",
                "version": "none",
                "url": "https://example.com/source",
                "retrieved": "2026-11-28",
            }
        ],
        "rules": [
            {
                "id": "example-rule",
                "title": "Example rule",
                "kind": "guidance",
                "summary": "Ask the analyst.",
                "source": "example",
                "section": "s 1",
                "reviewed": "2026-11-28",
                "review_by": "2027-05-28",
            }
        ],
    }
    data.update(overrides)
    return data


@pytest.mark.parametrize(
    ("override", "problem"),
    [
        ({"name": "other"}, "name must be example-pack"),
        ({"version": "1"}, "version must be"),
        ({"sectors": ["mining"]}, "unknown sector"),
        ({"extra": 1}, "unknown keys"),
        ({"review_by": "2026-01-01"}, "review_by must be after reviewed"),
        ({"sources": []}, "sources must be a non-empty list"),
        ({"connectors": [{"key": "nope", "why": "x"}]}, "not in mcp/servers.yaml"),
        ({"prompts": {"not-a-skill": ["x"]}}, "unknown skill"),
        ({"playbooks": ["../secret.md"]}, "not a file under playbooks/"),
        (
            {"prompts": {"incident-triage": ["Submit the report automatically."]}},
            "must not tell a skill to submit or send",
        ),
    ],
)
def test_parse_pack_rejects_bad_manifests(override: dict, problem: str, tmp_path: Path):
    with pytest.raises(PackError) as raised:
        parse_pack(_minimal(**override), tmp_path / "example-pack", **_strict())
    assert any(problem in item for item in raised.value.problems), raised.value.problems


def test_rule_needs_a_listed_source_and_dates(tmp_path: Path):
    rule = dict(_minimal()["rules"][0], source="missing", reviewed="soon")
    with pytest.raises(PackError) as raised:
        parse_pack(_minimal(rules=[rule]), tmp_path / "example-pack")
    text = " ".join(raised.value.problems)
    assert "source 'missing' is not in sources" in text
    assert "reviewed must be a YYYY-MM-DD date" in text


def test_local_pack_turns_on_without_touching_core_files(tmp_path: Path):
    data_dir = tmp_path / "data"
    local = data_dir / "packs" / "example-pack"
    local.mkdir(parents=True)
    (local / "pack.yaml").write_text(yaml.safe_dump(_minimal()), encoding="utf-8")
    profile = parse_org({"sector": "retail"})
    active = active_packs(profile, pack_roots(ROOT, data_dir))
    assert [pack.name for pack in active.packs] == ["example-pack"]

    off = parse_org({"sector": "retail", "sector_packs": ["none"]})
    assert active_packs(off, pack_roots(ROOT, data_dir)).packs == []


def test_a_broken_local_pack_is_reported_not_loaded(tmp_path: Path):
    broken = tmp_path / "packs" / "broken-pack"
    broken.mkdir(parents=True)
    (broken / "pack.yaml").write_text("name: broken-pack\nversion: x\n", encoding="utf-8")
    profile = parse_org({"sector": "energy-water"})
    active = active_packs(profile, pack_roots(ROOT, tmp_path))
    assert [pack.name for pack in active.packs] == ["energy-water"]
    assert any("broken-pack" in problem for problem in active.problems)


def test_named_pack_that_is_not_installed_is_missing():
    profile = parse_org({"sector": "retail", "sector_packs": ["no-such-pack"]})
    active = active_packs(profile, pack_roots(ROOT))
    assert active.packs == []
    assert active.missing == ["no-such-pack"]
