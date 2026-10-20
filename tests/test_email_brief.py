"""Morning briefing email: rendering, settings, sending and the cron script."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills" / "daily-briefing" / "scripts" / "email_brief.py"
KEY = "test-only-email-key-not-a-secret"


def _load():
    spec = importlib.util.spec_from_file_location("email_brief", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


email = _load()

BRIEF = {
    "window": "24 hours to 07:30 AEDT. Public sources only.",
    "headline": "Patch <script>alert(1)</script> today [1].",
    "act_today": {"intro": "", "items": [], "notes": []},
    "acsc": [
        {
            "feed": "alerts",
            "title": "Critical flaw",
            "published": "2026-10-20",
            "url": "javascript:alert(1)",
            "summary": "Read it.",
        }
    ],
    "coverage": [],
    "sources": [
        {"n": 1, "text": "ASD", "links": [{"label": "x", "url": "http://insecure.example"}]}
    ],
}
HITS = {
    "source": "intel-store",
    "untrusted": True,
    "data": {
        "hits": [
            {
                "id": "watch-1",
                "kind": "advisory watch",
                "value": "<<untrusted source=feed-x>> Defender <b>change</b> <<end untrusted>>",
                "seen": "2026-10-20T04:00:00Z",
                "watch": "Microsoft security changes",
                "source": "feed-azure-updates",
                "url": "https://updates.example/a",
                "published": "2026-10-19T08:00:00Z",
            },
            {"id": "watch-2", "kind": "ip_range", "value": "192.0.2.7", "seen": "x", "asset": "a"},
        ]
    },
}


def _files(tmp_path: Path) -> tuple[Path, Path]:
    brief = tmp_path / "out.txt"
    brief.write_text("session noise\n" + json.dumps(BRIEF) + "\ntrailing", encoding="utf-8")
    hits = tmp_path / "hits.json"
    hits.write_text(json.dumps(HITS), encoding="utf-8")
    return brief, hits


def _settings(tmp_path: Path, mode: int = 0o600) -> Path:
    (tmp_path / "secrets").mkdir(exist_ok=True)
    key = tmp_path / "secrets" / "email-api-key"
    key.write_text(KEY + "\n", encoding="utf-8")
    key.chmod(mode)
    config = tmp_path / "email.yaml"
    config.write_text(
        "api_url: https://mail.example/api/v1/emails\n"
        "from: Briefing <briefing@example.com>\n"
        "to: team@example.com\n",
        encoding="utf-8",
    )
    return config


def test_render_escapes_text_and_keeps_only_https_links(tmp_path):
    brief, hits = _files(tmp_path)
    html_out, text_out = tmp_path / "b.html", tmp_path / "b.txt"
    assert (
        email.main(
            [
                "render",
                str(brief),
                "--date-label",
                "Tuesday 20 October 2026",
                "--watches",
                str(hits),
                "--html",
                str(html_out),
                "--text",
                str(text_out),
            ]
        )
        == 0
    )
    page = html_out.read_text(encoding="utf-8")
    text = text_out.read_text(encoding="utf-8")
    assert "<script>" not in page
    assert "&lt;script&gt;" in page
    assert 'href="javascript' not in page
    assert 'href="http://insecure' not in page
    assert "MICROSOFT SECURITY CHANGES" in text
    assert "Defender <b>change</b> (Azure updates, 2026-10-19)" in text
    assert "<<untrusted" not in page
    assert 'href="https://updates.example/a"' in page
    # Only watch hits are shown in the watch section.
    assert "192.0.2.7" not in text


def test_watches_file_is_optional():
    assert email.load_watches(None) == []
    assert email.load_watches("/nonexistent/file.json") == []


def test_settings_validate_and_key_must_be_private(tmp_path):
    config = _settings(tmp_path)
    settings = email.load_settings(config)
    assert settings["to"] == ["team@example.com"]
    assert email.read_key(settings["key_file"]) == KEY
    settings["key_file"].chmod(0o644)
    with pytest.raises(ValueError, match="chmod 600"):
        email.read_key(settings["key_file"])
    bad = tmp_path / "bad.yaml"
    bad.write_text("api_url: http://mail.example\nfrom: a@example.com\nto: b@example.com\n")
    with pytest.raises(ValueError, match="https"):
        email.load_settings(bad)
    bad.write_text("api_url: https://mail.example\nfrom: a@example.com\nto: not-an-address\n")
    with pytest.raises(ValueError, match="email addresses"):
        email.load_settings(bad)
    bad.write_text("api_url: https://mail.example\n")
    with pytest.raises(ValueError, match="missing from, to"):
        email.load_settings(bad)


def test_send_posts_one_message_with_the_key_in_a_header(tmp_path):
    settings = email.load_settings(_settings(tmp_path))
    seen = {}

    def post(url, body, headers):
        seen.update(url=url, body=body, headers=headers)
        return 200, '{"id": "msg-1"}'

    ident = email.send(settings, "Subject", "<p>x</p>", "x", "cyberau-brief-2026-10-20-brief", post)
    assert ident == "msg-1"
    assert seen["url"] == "https://mail.example/api/v1/emails"
    assert seen["headers"]["Authorization"] == f"Bearer {KEY}"
    assert seen["headers"]["Idempotency-Key"] == "cyberau-brief-2026-10-20-brief"
    assert seen["body"]["to"] == ["team@example.com"]
    assert KEY not in json.dumps(seen["body"])


def test_send_error_never_echoes_the_key(tmp_path):
    settings = email.load_settings(_settings(tmp_path))
    with pytest.raises(RuntimeError) as caught:
        email.send(settings, "s", "h", "t", "id", lambda *_a: (401, f"bad key {KEY}"))
    assert KEY not in str(caught.value)
    assert "401" in str(caught.value)


def _profile(tmp_path: Path, hermes: str | None) -> tuple[Path, dict]:
    profile = tmp_path / "profile"
    (profile / "scripts").mkdir(parents=True)
    shutil.copy(ROOT / "scripts" / "cyberau_morning_email.sh", profile / "scripts")
    skill = profile / "skills" / "daily-briefing"
    (skill / "scripts").mkdir(parents=True)
    (skill / "references").mkdir(parents=True)
    shutil.copy(SCRIPT, skill / "scripts")
    shutil.copy(ROOT / "skills/daily-briefing/references/email-prompt.txt", skill / "references")
    venv = profile / "mcp" / ".venv" / "bin"
    venv.mkdir(parents=True)
    (venv / "python").symlink_to(sys.executable)
    cli = venv / "cyberau-mcp"
    cli.write_text("#!/bin/sh\nprintf '%s' '" + json.dumps(HITS) + "'\n", encoding="utf-8")
    cli.chmod(0o755)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    if hermes is not None:
        fake = bin_dir / "hermes"
        fake.write_text(hermes, encoding="utf-8")
        fake.chmod(0o755)
    data = tmp_path / "data"
    data.mkdir()
    env = {
        "PATH": f"{bin_dir}:/usr/bin:/bin",
        "HERMES_HOME": str(profile),
        "CYBERAU_DATA_DIR": str(data),
        "HOME": str(tmp_path),
    }
    return profile, env


def _run(profile: Path, env: dict) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(profile / "scripts" / "cyberau_morning_email.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


@pytest.mark.skipif(
    subprocess.run(["date", "-u", "-d", "-1 hours"], capture_output=True).returncode != 0,
    reason="needs GNU date, as in the Hermes container",
)
def test_script_reports_missing_settings_and_never_prints_the_key(tmp_path):
    profile, env = _profile(tmp_path, "#!/bin/sh\nprintf '%s' '" + json.dumps(BRIEF) + "'\n")
    result = _run(profile, env)
    assert result.returncode == 1
    assert result.stdout == "morning email failed: no email.yaml in the profile data directory\n"

    _settings(Path(env["CYBERAU_DATA_DIR"]), mode=0o644)
    result = _run(profile, env)
    assert result.returncode == 1
    assert result.stdout.startswith("morning email failed:")
    assert "chmod 600" in result.stdout
    assert KEY not in result.stdout + result.stderr


def test_script_needs_the_connector_venv(tmp_path):
    profile, env = _profile(tmp_path, None)
    os.remove(profile / "mcp" / ".venv" / "bin" / "cyberau-mcp")
    result = _run(profile, env)
    assert result.returncode == 1
    assert result.stdout == "morning email failed: mcp/.venv/bin/cyberau-mcp is not installed\n"


def test_dry_run_checks_the_key_but_does_not_send(tmp_path, capsys):
    brief, hits = _files(tmp_path)
    config = _settings(tmp_path)
    argv = ["send", str(brief), "--date-label", "d", "--day", "2026-10-20", "--config", str(config)]
    assert email.main([*argv, "--watches", str(hits), "--dry-run"]) == 0
    assert "not sent: dry run" in capsys.readouterr().out
    (tmp_path / "secrets" / "email-api-key").chmod(0o644)
    assert email.main([*argv, "--dry-run"]) == 1
    assert "chmod 600" in capsys.readouterr().out
