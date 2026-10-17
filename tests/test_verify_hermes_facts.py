"""Tests for tools/ci/verify_hermes_facts.py. No network."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "ci" / "verify_hermes_facts.py"
NOTES = ROOT / "docs" / "research" / "hermes-structure.md"

SAMPLE = """\
# Notes

| Fact | Source |
|---|---|
| Heading in the English security doc. | `security.md` ("Context File Injection Protection") |
| Manifest class. | `hermes_cli/profile_distribution.py` (`DistributionManifest`) |
| Template constant. | `ENV_TEMPLATE_FILENAME` |
| Skills directory. | `optional-skills/security/` |
| Image file. | `Dockerfile` |
"""


def _load():
    spec = importlib.util.spec_from_file_location("verify_hermes_facts", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["verify_hermes_facts"] = module
    spec.loader.exec_module(module)
    return module


verify = _load()


def _checkout(tmp_path: Path) -> Path:
    root = tmp_path / "hermes"
    english = root / "website" / "docs" / "user-guide"
    english.mkdir(parents=True)
    (english / "security.md").write_text(
        "Context File Injection Protection\nCANARY-DO-NOT-COPY\n",
        encoding="utf-8",
    )
    translated = root / "website" / "i18n" / "zh-Hans" / "docs" / "user-guide"
    translated.mkdir(parents=True)
    (translated / "security.md").write_text("wrong copy\n", encoding="utf-8")
    package = root / "hermes_cli"
    package.mkdir()
    (package / "profile_distribution.py").write_text(
        "class DistributionManifest:\n    pass\nENV_TEMPLATE_FILENAME = '.env.EXAMPLE'\n",
        encoding="utf-8",
    )
    (root / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    skill = root / "optional-skills" / "security" / "sherlock"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("# sherlock\n", encoding="utf-8")
    return root


def _facts(tmp_path: Path, body: str = SAMPLE) -> Path:
    path = tmp_path / "facts.md"
    path.write_text(body, encoding="utf-8")
    return path


def test_real_notes_parse_into_the_three_check_kinds():
    facts = verify.parse_facts(NOTES.read_text(encoding="utf-8"))
    assert len(facts) == 48
    assert facts[0].checks == (
        verify.Check("file", "website/docs/getting-started/installation.md"),
    )
    assert "bash" in facts[0].summary
    assert any("stable|main" in fact.summary for fact in facts)
    kinds = {check.kind for fact in facts for check in fact.checks}
    assert kinds == {"file", "symbol", "string"}
    assert any(
        check.kind == "symbol"
        and check.target == "DistributionManifest"
        and check.bound is not None
        and check.bound.endswith("profile_distribution.py")
        for fact in facts
        for check in fact.checks
    )
    assert any(
        check.kind == "symbol"
        and check.target == "ENV_TEMPLATE_FILENAME"
        and check.bound is None
        for fact in facts
        for check in fact.checks
    )
    assert any(
        check.kind == "string" and check.target == "Context File Injection Protection"
        for fact in facts
        for check in fact.checks
    )
    assert any(
        check.kind == "file" and check.target == "optional-skills/security/"
        for fact in facts
        for check in fact.checks
    )
    assert any(
        check.kind == "file" and check.target == "Dockerfile"
        for fact in facts
        for check in fact.checks
    )
    for fact in facts:
        for check in fact.checks:
            assert ".." not in Path(check.target).parts
            if check.bound:
                assert ".." not in Path(check.bound).parts


def test_checkout_passes_and_does_not_copy_upstream_text(tmp_path: Path):
    checkout = _checkout(tmp_path)
    report = tmp_path / "report.md"
    code = verify.main(
        [
            "--checkout",
            str(checkout),
            "--facts",
            str(_facts(tmp_path)),
            "--report",
            str(report),
        ]
    )
    assert code == 0
    text = report.read_text(encoding="utf-8")
    assert "0 failed" in text
    assert "CANARY-DO-NOT-COPY" not in text
    assert "website/docs/user-guide/security.md" in text
    assert "i18n" not in text
    assert "hermes_cli/profile_distribution.py" in text


def test_missing_symbol_fails(tmp_path: Path):
    checkout = _checkout(tmp_path)
    (checkout / "hermes_cli" / "profile_distribution.py").write_text(
        "ENV_TEMPLATE_FILENAME = '.env.EXAMPLE'\n",
        encoding="utf-8",
    )
    report = tmp_path / "report.md"
    code = verify.main(
        [
            "--checkout",
            str(checkout),
            "--facts",
            str(_facts(tmp_path)),
            "--report",
            str(report),
        ]
    )
    assert code == 1
    text = report.read_text(encoding="utf-8")
    assert "fail fact" in text
    assert "DistributionManifest" in text
    assert "CANARY-DO-NOT-COPY" not in text


def test_missing_string_fails(tmp_path: Path):
    checkout = _checkout(tmp_path)
    (checkout / "website" / "docs" / "user-guide" / "security.md").write_text(
        "no heading here\nCANARY-DO-NOT-COPY\n",
        encoding="utf-8",
    )
    report = tmp_path / "report.md"
    code = verify.main(
        [
            "--checkout",
            str(checkout),
            "--facts",
            str(_facts(tmp_path)),
            "--report",
            str(report),
        ]
    )
    assert code == 1
    text = report.read_text(encoding="utf-8")
    assert 'string present: "Context File Injection Protection"' in text
    assert "CANARY-DO-NOT-COPY" not in text


def test_parent_citation_is_refused_without_reading_outside(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    outside = tmp_path / "secret.txt"
    outside.write_text("CANARY-OUTSIDE", encoding="utf-8")
    checkout = tmp_path / "hermes"
    checkout.mkdir()
    facts = _facts(
        tmp_path, "| Fact | Source |\n|---|---|\n| Escape. | `../secret.txt` |\n"
    )
    report = tmp_path / "report.md"
    code = verify.main(
        ["--checkout", str(checkout), "--facts", str(facts), "--report", str(report)]
    )
    assert code == 1
    captured = capsys.readouterr()
    assert "CANARY-OUTSIDE" not in captured.out
    assert "CANARY-OUTSIDE" not in captured.err
    assert "Refusing parent" in captured.err
    assert not report.exists()


def test_bad_tag_does_not_clone(monkeypatch: pytest.MonkeyPatch):
    def boom(*_args, **_kwargs):
        raise AssertionError("clone attempted")

    monkeypatch.setattr(verify.subprocess, "run", boom)
    with pytest.raises(verify.VerifyError, match="Refusing tag"):
        verify.checkout_tag("v1.2.3;touch /tmp/pwned")
    with pytest.raises(verify.VerifyError, match="Refusing tag"):
        verify.checkout_tag("../v0.22.2")


def test_clone_environment_drops_tokens(monkeypatch: pytest.MonkeyPatch):
    seen: dict[str, object] = {}

    def fake_run(args, **kwargs):
        seen["args"] = args
        seen["env"] = kwargs.get("env", {})

        class Proc:
            returncode = 1
            stderr = "clone failed"
            stdout = ""

        return Proc()

    monkeypatch.setenv("GH_TOKEN", "ghp_shouldnotpass")
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_shouldnotpass")
    monkeypatch.setattr(verify.subprocess, "run", fake_run)
    with pytest.raises(verify.VerifyError, match="Could not fetch"):
        verify.checkout_tag("v1.2.3")
    env = seen["env"]
    assert isinstance(env, dict)
    assert "GH_TOKEN" not in env
    assert "GITHUB_TOKEN" not in env
    assert "ghp_shouldnotpass" not in str(env)
    assert "https://github.com/NousResearch/hermes-agent.git" in seen["args"]
    joined = " ".join(seen["args"])
    assert "ghp_" not in joined
    assert "@" not in joined.split("https://", 1)[1]


def test_cli_help_lists_the_tag_and_checkout():
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert "--tag" in proc.stdout
    assert "--checkout" in proc.stdout
    assert "--report" in proc.stdout
