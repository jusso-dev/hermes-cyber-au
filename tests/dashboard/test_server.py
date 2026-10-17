"""Tests for dashboard/server.py. No network beyond loopback."""

from __future__ import annotations

import http.client
import importlib.util
import json
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load():
    path = ROOT / "dashboard" / "server.py"
    spec = importlib.util.spec_from_file_location("cyberau_dashboard_server", path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


server = _load()

REPORT = "2026-10-17_07-30-02.md"


def _write_jobs(profile: Path, jobs: list[dict]) -> None:
    (profile / "cron").mkdir(parents=True, exist_ok=True)
    (profile / "cron" / "jobs.json").write_text(json.dumps({"jobs": jobs}), encoding="utf-8")


def _write_report(profile: Path, job_id: str, name: str, text: str) -> Path:
    directory = profile / "cron" / "output" / job_id
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(text, encoding="utf-8")
    return path


def _get(profile: Path, target: str) -> tuple[int, str]:
    status, body = server.route(profile, target)
    return status, body.decode("utf-8")


@pytest.fixture
def profile(tmp_path: Path) -> Path:
    path = tmp_path / "cyber-au"
    path.mkdir()
    return path


def test_jobs_render_runtime_fields(profile: Path) -> None:
    _write_jobs(
        profile,
        [
            {
                "id": "cyberau-morning-brief",
                "name": "Morning cyber briefing (AU)",
                "schedule": {"kind": "cron", "expr": "30 7 * * *", "display": "30 7 * * *"},
                "deliver": "origin",
                "state": "paused",
                "last_status": "error",
                "last_error": "x" * 1000,
                "next_run_at": "2026-10-18T07:30:00+11:00",
            }
        ],
    )
    status, body = _get(profile, "/")
    assert status == 200
    assert "cyberau-morning-brief" in body
    assert "Morning cyber briefing (AU)" in body
    assert "30 7 * * *" in body
    assert "origin" in body
    assert "paused" in body
    assert "2026-10-18T07:30:00+11:00" in body
    assert "x" * 400 not in body  # truncated
    assert "x" * 300 in body
    assert "07:30 Australia/Sydney" in body
    assert "do nothing until" in body


def test_shipped_jobs_file_without_runtime_fields(profile: Path) -> None:
    shipped = json.loads((ROOT / "cron" / "jobs.json").read_text(encoding="utf-8"))
    (profile / "cron").mkdir()
    (profile / "cron" / "jobs.json").write_text(json.dumps(shipped), encoding="utf-8")
    status, body = _get(profile, "/")
    assert status == 200
    for job in shipped["jobs"]:
        assert job["id"] in body
        assert job["deliver"] in body
    assert "no run recorded" in body
    assert "succeeded" not in body.lower()


def test_html_in_report_is_escaped(profile: Path) -> None:
    _write_jobs(profile, [{"id": "daily", "name": "Daily"}])
    _write_report(
        profile,
        "daily",
        REPORT,
        "# Title <script>alert(1)</script>\n\nHello <img src=x onerror=alert(2)> & more\n\n"
        "- item <b>bold</b>\n\n```\n<iframe></iframe>\n```\n",
    )
    for target in (f"/reports/daily/{REPORT}", "/latest/daily"):
        status, body = _get(profile, target)
        assert status == 200
        assert "<script>" not in body
        assert "<img" not in body
        assert "<b>" not in body
        assert "<iframe>" not in body
        assert "&lt;script&gt;" in body
        assert "&lt;img src=x onerror=alert(2)&gt;" in body
        assert "<h2>Title" in body


def test_latest_report_is_newest(profile: Path) -> None:
    _write_jobs(profile, [{"id": "daily", "name": "Daily"}])
    _write_report(profile, "daily", "2026-10-16_07-30-00.md", "# Old")
    _write_report(profile, "daily", "2026-10-17_07-30-00.md", "# New")
    _write_report(profile, "daily", "notes.md", "# Ignored")
    status, body = _get(profile, "/latest/daily")
    assert status == 200
    assert "New" in body and "Old" not in body
    _, index = _get(profile, "/")
    assert "2026-10-17_07-30-00.md" in index


@pytest.mark.parametrize(
    "target",
    [
        f"/reports/daily/../secret/{REPORT}",
        f"/reports/..%2Fsecret/{REPORT}",
        "/reports/daily/..%2F..%2Fsecret.md",
        "/reports/daily/%2e%2e/%2e%2e/etc/passwd",
        f"/reports/Daily/{REPORT}",
        f"/reports/da_ily/{REPORT}",
        "/reports/daily/notes.md",
        "/reports/daily/2026-10-17_07-30-02.md.txt",
        "/reports/daily/2026-10-17_07-30-02.md%00.png",
        "/reports/daily/2026-10-17_07-30-02.md/",
        "/reports/daily",
        "/reports",
        "/latest/..",
        "/latest/Secret",
        "/nope",
    ],
)
def test_traversal_and_bad_names_are_404(profile: Path, target: str) -> None:
    _write_jobs(profile, [{"id": "daily", "name": "Daily"}])
    _write_report(profile, "daily", REPORT, "# fine")
    (profile / "cron" / "output" / "secret").mkdir()
    (profile / "secret.md").write_text("top secret", encoding="utf-8")
    status, body = _get(profile, target)
    assert status == 404
    assert "top secret" not in body


def test_symlink_out_of_output_directory_is_404(profile: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside.md"
    outside.write_text("top secret", encoding="utf-8")
    directory = profile / "cron" / "output" / "daily"
    directory.mkdir(parents=True)
    try:
        (directory / REPORT).symlink_to(outside)
    except OSError:
        pytest.skip("symlinks not available")
    status, body = _get(profile, f"/reports/daily/{REPORT}")
    assert status == 404
    assert "top secret" not in body
    status, _ = _get(profile, "/latest/daily")
    assert status == 404


def test_missing_profile_does_not_crash_index(tmp_path: Path) -> None:
    status, body = _get(tmp_path / "does-not-exist", "/")
    assert status == 200
    assert "does not exist" in body
    assert "There are no handoffs yet." in body
    assert "hermes -p cyber-au chat" in body


def test_broken_jobs_file_does_not_crash_index(profile: Path) -> None:
    (profile / "cron").mkdir()
    (profile / "cron" / "jobs.json").write_text("{not json", encoding="utf-8")
    status, body = _get(profile, "/")
    assert status == 200
    assert "not valid JSON" in body


def test_handoffs_absent_and_present(profile: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CYBERAU_DATA_DIR", raising=False)
    _, body = _get(profile, "/")
    assert "There are no handoffs yet." in body

    lines = [
        json.dumps(
            {
                "id": "h-1",
                "action": "escalate",
                "actor": "analyst",
                "tlp": "TLP:AMBER",
                "confidence": "high",
                "claim": "y" * 500 + "<script>",
            }
        ),
        "not json",
        json.dumps({"id": "h-2", "action": "note"}),
    ]
    (profile / "handoffs.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    _, body = _get(profile, "/")
    assert "h-1" in body and "h-2" in body
    assert "TLP:AMBER" in body and "analyst" in body
    assert "y" * 300 not in body
    assert "<script>" not in body
    assert "1 unreadable line" in body
    assert body.index("h-2") < body.index("h-1")  # newest first


def test_handoffs_from_data_dir(
    profile: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = tmp_path / "data"
    data.mkdir()
    (data / "handoffs.jsonl").write_text(json.dumps({"id": "from-data"}) + "\n", encoding="utf-8")
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(data))
    _, body = _get(profile, "/")
    assert "from-data" in body


def _write_session(profile: Path, session_id: str, messages: list[tuple], **session) -> None:
    import sqlite3

    profile.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(profile / "state.db")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS sessions ("
        "id TEXT, title TEXT, source TEXT, model TEXT, started_at REAL, "
        "last_activity_at REAL, message_count INT, profile_name TEXT, hidden INT)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS messages ("
        "id INT, session_id TEXT, role TEXT, content TEXT, tool_name TEXT, "
        "tool_calls TEXT, timestamp REAL, active INT)"
    )
    conn.execute(
        "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            session_id,
            session.get("title", "Untitled"),
            session.get("source", "cli"),
            session.get("model", "test-model"),
            session.get("started_at", 1_760_000_000),
            session.get("last_activity_at", 1_760_001_000),
            len(messages),
            profile.name,
            session.get("hidden", 0),
        ),
    )
    for index, message in enumerate(messages, start=1):
        role, content, tool = message
        conn.execute(
            "INSERT INTO messages VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (index, session_id, role, content, tool, "api_key=should-not-appear", index, 1),
        )
    conn.commit()
    conn.close()


def test_conversation_snapshot_escapes_and_hides_secrets(profile: Path) -> None:
    _write_session(
        profile,
        "sess1",
        [
            ("system", "SECRET SYSTEM PROMPT", None),
            ("user", "What is exposed?", None),
            ("assistant", "Two hosts <script>alert(1)</script>", None),
            ("tool", "api_key=supersecretvalue", "web"),
            ("assistant", "token=abc123secretvalue and then the finding", None),
        ],
        title="Morning look",
    )
    status, body = _get(profile, "/")
    assert status == 200
    assert "Conversation snapshots" in body
    assert "Morning look" in body
    assert "What is exposed?" in body
    assert "Two hosts" in body
    assert "<script>" not in body
    assert "&lt;script&gt;" in body
    assert "SECRET SYSTEM PROMPT" not in body
    assert "supersecretvalue" not in body
    assert "should-not-appear" not in body
    assert "abc123secretvalue" not in body
    assert "[redacted]" in body
    assert "Used web" in body

    status, page = _get(profile, "/conversations/cyber-au/sess1")
    assert status == 200
    assert "What is exposed?" in page
    assert "SECRET SYSTEM PROMPT" not in page
    assert "<script>" not in page


def test_hidden_session_and_bad_snapshot_path(profile: Path) -> None:
    _write_session(profile, "visible1", [("user", "shown turn", None)], hidden=0)
    _write_session(profile, "hidden1", [("user", "hidden turn", None)], hidden=1)
    _, body = _get(profile, "/")
    assert "shown turn" in body
    assert "hidden turn" not in body
    for target in (
        "/conversations/../state.db",
        "/conversations/%2e%2e/state.db",
        "/conversations/cyber-au/../sess1",
        "/conversations/not-a-profile/visible1",
    ):
        status, page = _get(profile, target)
        assert status == 404
        assert "shown turn" not in page
    status, page = _get(profile, "/conversations/cyber-au/visible1")
    assert status == 200
    assert "shown turn" in page


def test_sibling_role_snapshot(tmp_path: Path) -> None:
    home = tmp_path / "profiles"
    watcher = home / "watcher"
    marker = watcher / "plugin-data" / "cyber-au"
    marker.mkdir(parents=True)
    (marker / "profile-role").write_text("watcher\n", encoding="utf-8")
    _write_session(watcher, "w1", [("assistant", "Posted a new claim", None)], title="Watch")
    analyst = home / "analyst"
    _write_session(analyst, "a1", [("assistant", "Claimed the item", None)], title="Analysis")
    status, body = _get(watcher, "/")
    assert status == 200
    assert "Posted a new claim" in body
    assert "Claimed the item" in body
    assert ">watcher<" in body
    assert ">analyst<" in body


def test_no_session_store_says_so(profile: Path) -> None:
    _, body = _get(profile, "/")
    assert "No conversation has been recorded yet." in body


def test_sessions_message(profile: Path) -> None:
    _, body = _get(profile, "/")
    assert "No chat has been opened yet" in body
    (profile / "sessions").mkdir()
    _, body = _get(profile, "/")
    assert "No chat has been opened yet" in body
    (profile / "sessions" / "s1.json").write_text("{}", encoding="utf-8")
    _, body = _get(profile, "/")
    assert "No chat has been opened yet" not in body


def test_default_profile_resolution(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("CYBERAU_PROFILE_HOME", str(tmp_path / "x"))
    assert server.default_profile() == tmp_path / "x"
    monkeypatch.delenv("CYBERAU_PROFILE_HOME")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(server, "DOCKER_PROFILE", tmp_path / "absent")
    assert server.default_profile() == tmp_path / ".hermes" / "profiles" / "cyber-au"
    present = tmp_path / "present"
    present.mkdir()
    monkeypatch.setattr(server, "DOCKER_PROFILE", present)
    assert server.default_profile() == present


def test_live_server_serves_and_rejects_traversal(profile: Path) -> None:
    _write_jobs(profile, [{"id": "daily", "name": "Daily"}])
    _write_report(profile, "daily", REPORT, "# Hi")
    httpd = server.make_server(profile, "127.0.0.1", 0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        port = httpd.server_address[1]

        def request(method: str, target: str) -> tuple[int, dict[str, str], bytes]:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            try:
                conn.request(method, target)
                resp = conn.getresponse()
                return resp.status, dict(resp.getheaders()), resp.read()
            finally:
                conn.close()

        status, headers, body = request("GET", "/")
        assert status == 200
        assert b"daily" in body
        assert "default-src 'none'" in headers["Content-Security-Policy"]
        assert request("GET", f"/reports/daily/{REPORT}")[0] == 200
        assert request("GET", "/reports/daily/../../../etc/passwd")[0] == 404
        assert request("GET", "/reports/%2e%2e/daily/" + REPORT)[0] == 404
        assert request("POST", "/")[0] == 405
    finally:
        httpd.shutdown()
        httpd.server_close()
