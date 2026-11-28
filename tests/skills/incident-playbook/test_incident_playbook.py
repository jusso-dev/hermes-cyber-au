"""Playbooks are well formed, the helper keeps an honest timeline, and the eval walks one."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE))

import build_evals  # noqa: E402
import walkthrough  # noqa: E402

pb = walkthrough.helper()
HARNESS = ROOT / "tests" / "skills" / "harness.py"
REQUIRED = {
    "business-email-compromise",
    "ransomware",
    "phishing",
    "lost-or-stolen-device",
    "suspected-data-breach",
    "compromised-cloud-admin",
    "third-party-breach",
}


def _harness():
    spec = importlib.util.spec_from_file_location("incident_playbook_harness", HARNESS)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_starter_set_has_at_least_seven_playbooks():
    ids = set(pb.playbook_ids())
    assert REQUIRED <= ids
    assert len(ids) >= 7


@pytest.mark.parametrize("playbook_id", sorted(REQUIRED))
def test_playbook_structure(playbook_id):
    book = pb.load(playbook_id)
    assert pb.problems(book) == []
    text = (ROOT / "playbooks" / f"{playbook_id}.md").read_text(encoding="utf-8")
    assert "The assistant proposes. A person acts." in text
    assert "not legal advice" in text
    assert "Last reviewed 2026-" in text
    assert "\u2014" not in text


def test_readme_lists_every_playbook():
    readme = (ROOT / "playbooks" / "README.md").read_text(encoding="utf-8")
    for playbook_id in pb.playbook_ids():
        assert f"({playbook_id}.md)" in readme


def test_playbooks_pass_the_house_style_check():
    completed = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "ci" / "style_check.py"), "--root", str(ROOT)],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert not [line for line in completed.stdout.splitlines() if line.startswith("playbooks/")]


def test_timeline_is_append_only_and_sorted_by_instant(tmp_path):
    path = tmp_path / "timeline.jsonl"
    late = pb.entry(
        playbook="phishing", phase=1, who="Analyst", event="later", at="2026-04-05T02:30:00+10:00"
    )
    early = pb.entry(
        playbook="phishing", phase=1, who="Analyst", event="earlier", at="2026-04-05T02:30:00+11:00"
    )
    pb.append(path, late)
    first = path.read_text(encoding="utf-8")
    pb.append(path, early)
    assert path.read_text(encoding="utf-8").startswith(first)
    table = pb.render_timeline(pb.read_timeline(path))
    assert table.index("earlier") < table.index("later")


def test_times_need_an_offset_in_a_dst_gap_or_overlap():
    with pytest.raises(pb.PlaybookError, match="does not exist"):
        pb.parse_moment("2026-10-04T02:30:00")
    with pytest.raises(pb.PlaybookError, match="ambiguous"):
        pb.parse_moment("2026-04-05T02:30:00")
    assert pb.parse_moment("2026-07-01T08:00:00").isoformat() == "2026-07-01T08:00:00+10:00"


def test_assistant_cannot_record_an_approval_and_input_is_checked():
    with pytest.raises(pb.PlaybookError, match="named person"):
        pb.entry(playbook="ransomware", phase=2, who="assistant", event="x", kind="approval")
    with pytest.raises(pb.PlaybookError, match="phase"):
        pb.entry(playbook="ransomware", phase=9, who="Lead", event="x")
    with pytest.raises(pb.PlaybookError, match="no playbook"):
        pb.load("not-a-playbook")
    with pytest.raises(pb.PlaybookError):
        pb.load("../README")


def test_pending_proposals_are_listed_until_approved(tmp_path):
    result = walkthrough.build(tmp_path / "timeline.jsonl")
    assert "Take the backup repository offline" in result["timeline"].split("no approval")[1]
    assert "Isolate FS01" not in result["timeline"].split("no approval")[1]


def test_walkthrough_covers_every_phase_and_uses_the_checker(tmp_path):
    result = walkthrough.build(tmp_path / "timeline.jsonl")
    phases = {row["phase"] for row in result["rows"]}
    assert phases == {p["number"] for p in result["book"]["phases"]}
    assert result["rows"][0]["at"] == walkthrough.AWARE
    ids = {item["id"] for item in result["obligations"]["applicable"]}
    assert "ndb.suspected_breach" in ids
    assert "ransomware_payment.payment" not in ids
    assert result["obligations"]["submitted"] is False


def test_cli_round_trip(tmp_path):
    script = [sys.executable, str(walkthrough.HELPER)]
    listed = subprocess.run([*script, "list"], capture_output=True, text=True, check=True)
    assert "ransomware: Ransomware" in listed.stdout
    shown = subprocess.run(
        [*script, "show", "ransomware", "--phase", "2"], capture_output=True, text=True, check=True
    )
    assert "Contain" in shown.stdout and "Decisions:" in shown.stdout
    timeline = tmp_path / "t.jsonl"
    logged = subprocess.run(
        [
            *script,
            "log",
            str(timeline),
            "--playbook",
            "phishing",
            "--phase",
            "1",
            "--who",
            "Analyst",
            "--event",
            "Reported",
            "--at",
            "2026-06-01T09:00:00+10:00",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(logged.stdout)["phase_name"] == "Detect and triage"
    printed = subprocess.run(
        [*script, "timeline", str(timeline)], capture_output=True, text=True, check=True
    )
    assert "2026-06-01T09:00:00+10:00" in printed.stdout
    refused = subprocess.run(
        [
            *script,
            "log",
            str(timeline),
            "--playbook",
            "phishing",
            "--phase",
            "1",
            "--who",
            "assistant",
            "--event",
            "x",
            "--kind",
            "approval",
        ],
        capture_output=True,
        text=True,
    )
    assert refused.returncode == 2


def test_eval_is_current_and_passes_offline():
    assert build_evals.main([]) == 0, "run build_evals.py --write"
    harness = _harness()
    eval_file = harness.load_eval_file(HERE / "evals.yaml")
    assert eval_file.skill == "incident-playbook"
    for case in eval_file.cases:
        assert harness.score_session(case, case.offline) == [], case.id
