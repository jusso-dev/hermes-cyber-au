"""Tamper-evident audit log tests. No network and no real credentials."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import logging
import os
from datetime import date, datetime, timedelta
from pathlib import Path

import pytest
from cyberau_common.audit import (
    GENESIS,
    AuditHooks,
    AuditLog,
    AuditUsageError,
    AuditVerifyError,
    AuditWriteError,
    canonical_json,
    chain_hash,
    default_audit_dir,
    main,
    register_cli,
    register_hooks,
    tool_writes,
)

ROOT = Path(__file__).resolve().parents[3]
SECRET = "fake-token-value-0123456789"


def _log(tmp_path: Path, **kwargs) -> AuditLog:
    return AuditLog(tmp_path / "audit", **kwargs)


def _clock(start: datetime):
    current = {"at": start}

    def read() -> datetime:
        return current["at"]

    def advance(delta: timedelta) -> None:
        current["at"] = current["at"] + delta

    read.advance = advance  # type: ignore[attr-defined]
    read.current = current  # type: ignore[attr-defined]
    return read


class TestChain:
    def test_hash_is_prev_plus_canonical_json(self, tmp_path: Path):
        log = _log(tmp_path)
        record = log.record("session_start", session_id="sess")
        body = {key: value for key, value in record.items() if key != "hash"}
        assert record["prev_hash"] == GENESIS
        assert record["seq"] == 1
        assert record["hash"] == chain_hash(GENESIS, body)
        assert record["hash"] == hashlib.sha256(
            (GENESIS + canonical_json(body)).encode("utf-8")
        ).hexdigest()
        assert log.verify() == 1

    def test_events_chain_across_days(self, tmp_path: Path):
        log = _log(tmp_path)
        clock = _clock(datetime(2026, 10, 17, 23, 30, tzinfo=log.zone))
        log._clock = clock
        hooks = AuditHooks(log)
        hooks.on_session_start("sess", model="local", platform="cli")
        hooks.post_tool_call("intel_search", {"q": "kev"}, '{"ok": true}', "task-1", 4)
        hooks.record_approval("intel_export_stix", {"id": "1"}, approved=True, task_id="task-1")
        hooks.record_block(
            "intel_add_observation", {"id": "1"}, task_id="task-1", reason="no"
        )
        hooks.record_export(
            "intel_export_stix",
            {"id": "1"},
            result="STIX-BUNDLE-BODY",
            task_id="task-1",
        )
        hooks.record_delivery(
            "brief_deliver", {"to": "queue"}, result="sent-body", task_id="task-1"
        )
        hooks.record_config_change("retention_days", 30, old_value=90, session_id="sess")
        clock.advance(timedelta(hours=2))
        hooks.on_session_end("sess", completed=True, platform="cli")
        assert log.verify() == 8
        days = sorted(path.name for path in (tmp_path / "audit").glob("*.jsonl"))
        assert days == ["2026-10-17.jsonl", "2026-10-18.jsonl"]
        text = "".join(
            path.read_text(encoding="utf-8") for path in (tmp_path / "audit").glob("*.jsonl")
        )
        assert "STIX-BUNDLE-BODY" not in text
        assert "sent-body" not in text
        events = [record["event"] for _path, _line, record in log.iter_records()]
        assert events == [
            "session_start",
            "tool_call",
            "approval",
            "tool_blocked",
            "export",
            "delivery",
            "config_change",
            "session_end",
        ]

    def test_post_tool_call_marks_export_and_approval(self, tmp_path: Path):
        log = _log(tmp_path)
        hooks = AuditHooks(log)
        hooks.post_tool_call(
            "intel_export_stix",
            {"id": "1"},
            "bundle-secret-body",
            "task",
            3,
            approved=True,
        )
        events = [record["event"] for _path, _line, record in log.iter_records()]
        assert events == ["approval", "export"]
        blob = "".join(
            path.read_text(encoding="utf-8") for path in (tmp_path / "audit").glob("*.jsonl")
        )
        assert "bundle-secret-body" not in blob

    def test_editing_a_line_fails_at_that_line(self, tmp_path: Path):
        log = _log(tmp_path)
        log.record("session_start", session_id="sess")
        log.record("tool_call", tool="intel_search", args={"q": "a"}, result="{}", duration_ms=1)
        log.record("session_end", session_id="sess")
        path = next((tmp_path / "audit").glob("*.jsonl"))
        lines = path.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[1])
        record["tool"] = "tampered"
        lines[1] = canonical_json(record)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with pytest.raises(AuditVerifyError) as caught:
            log.verify()
        assert caught.value.line_number == 2
        assert caught.value.path.name == path.name
        assert "hash" in caught.value.reason

    def test_whitespace_edit_fails_at_that_line(self, tmp_path: Path):
        log = _log(tmp_path)
        log.record("session_start", session_id="sess")
        log.record("session_end", session_id="sess")
        path = next((tmp_path / "audit").glob("*.jsonl"))
        lines = path.read_text(encoding="utf-8").splitlines()
        lines[0] = lines[0].replace(",", ", ")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with pytest.raises(AuditVerifyError) as caught:
            log.verify()
        assert caught.value.line_number == 1

    def test_deleting_a_middle_line_fails_at_that_line(self, tmp_path: Path):
        log = _log(tmp_path)
        for name in ("one", "two", "three"):
            log.record("session_start", session_id=name)
        path = next((tmp_path / "audit").glob("*.jsonl"))
        lines = path.read_text(encoding="utf-8").splitlines()
        del lines[1]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with pytest.raises(AuditVerifyError) as caught:
            log.verify()
        assert caught.value.line_number == 2

    def test_deleting_the_last_line_fails_at_that_line(self, tmp_path: Path):
        log = _log(tmp_path)
        log.record("session_start", session_id="one")
        log.record("session_end", session_id="one")
        path = next((tmp_path / "audit").glob("*.jsonl"))
        lines = path.read_text(encoding="utf-8").splitlines()
        path.write_text(lines[0] + "\n", encoding="utf-8")
        with pytest.raises(AuditVerifyError) as caught:
            log.verify()
        assert caught.value.line_number == 2

    def test_deleting_the_first_file_breaks_the_chain(self, tmp_path: Path):
        log = _log(tmp_path)
        clock = _clock(datetime(2026, 10, 17, 12, 0, tzinfo=log.zone))
        log._clock = clock
        log.record("session_start", session_id="sess")
        clock.advance(timedelta(days=1))
        log.record("session_end", session_id="sess")
        first = tmp_path / "audit" / "2026-10-17.jsonl"
        first.unlink()
        with pytest.raises(AuditVerifyError) as caught:
            log.verify()
        assert caught.value.line_number == 1
        assert caught.value.path.name == "2026-10-18.jsonl"

    def test_broken_chain_refuses_another_append(self, tmp_path: Path):
        log = _log(tmp_path)
        hooks = AuditHooks(log)
        log.record("session_start", session_id="sess")
        path = next((tmp_path / "audit").glob("*.jsonl"))
        lines = path.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[0])
        record["session_id"] = "changed"
        lines[0] = canonical_json(record)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with pytest.raises(AuditWriteError):
            log.record("session_end", session_id="sess")
        blocked = hooks.pre_tool_call("intel_export_stix", {}, "task")
        assert blocked["action"] == "block"


class TestRedaction:
    def test_secrets_are_not_written(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("OTX_API_KEY", SECRET)
        monkeypatch.setenv("NVD_API_KEY", "nvd-fake-key-0123456789")
        log = _log(tmp_path)
        record = log.record(
            "tool_call",
            tool="intel_search",
            task_id="task",
            args={
                "apiKey": SECRET,
                "Authorization": f"Bearer {SECRET}",
                "url": f"https://example.com/search?apiKey={SECRET}",
                "note": f"token {SECRET} in prose",
                "auth": {"X-OTX-API-KEY": SECRET, "keep": "visible"},
                "key": "nvd-fake-key-0123456789",
                "q": "open",
            },
            result=f"result {SECRET} must not be stored",
            duration_ms=2,
        )
        blob = next((tmp_path / "audit").glob("*.jsonl")).read_text(encoding="utf-8")
        assert SECRET not in blob
        assert "nvd-fake-key-0123456789" not in blob
        assert "result " not in blob
        redacted = record["args_redacted"]
        assert redacted["apiKey"] == "[REDACTED]"
        assert redacted["Authorization"] == "[REDACTED]"
        assert redacted["key"] == "[REDACTED]"
        assert redacted["auth"]["X-OTX-API-KEY"] == "[REDACTED]"
        assert redacted["auth"]["keep"] == "visible"
        assert redacted["q"] == "open"
        assert SECRET not in redacted["note"]
        assert SECRET not in redacted["url"]
        assert redacted["Authorization"] == "[REDACTED]"
        ready = {
            "apiKey": SECRET,
            "Authorization": f"Bearer {SECRET}",
            "url": f"https://example.com/search?apiKey={SECRET}",
            "note": f"token {SECRET} in prose",
            "auth": {"X-OTX-API-KEY": SECRET, "keep": "visible"},
            "key": "nvd-fake-key-0123456789",
            "q": "open",
        }
        digest = hashlib.sha256(canonical_json(ready).encode()).hexdigest()
        assert record["args_sha256"] == digest
        assert "result_sha256" in record
        assert "result" not in record

    def test_config_change_redacts_secret_values(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setenv("GREYNOISE_API_KEY", SECRET)
        log = _log(tmp_path)
        hooks = AuditHooks(log)
        record = hooks.record_config_change(
            "api_token", SECRET, old_value="old-fake-token-9876543210"
        )
        blob = next((tmp_path / "audit").glob("*.jsonl")).read_text(encoding="utf-8")
        assert SECRET not in blob
        assert record["args_redacted"]["new"] == "[REDACTED]"


class TestRetention:
    def test_default_retention_drops_old_days(self, tmp_path: Path):
        log = _log(tmp_path)
        clock = _clock(datetime(2026, 1, 1, 9, 0, tzinfo=log.zone))
        log._clock = clock
        log.record("session_start", session_id="old")
        log.record("tool_call", tool="intel_search", args={"q": "a"}, result="{}", duration_ms=1)
        clock.advance(timedelta(days=151))
        log.record("session_end", session_id="old")
        names = sorted(path.name for path in (tmp_path / "audit").glob("*.jsonl"))
        assert names == ["2026-06-01.jsonl"]
        assert (tmp_path / "audit" / "anchor").exists()
        assert log.verify() == 1

    def test_retention_window_is_configurable(self, tmp_path: Path):
        log = _log(tmp_path, retention_days=10)
        clock = _clock(datetime(2026, 5, 1, 9, 0, tzinfo=log.zone))
        log._clock = clock
        log.record("session_start", session_id="day0")
        clock.advance(timedelta(days=5))
        log.record("tool_call", tool="intel_get", args={}, result="{}", duration_ms=1)
        clock.advance(timedelta(days=7))
        log.record("session_end", session_id="day0")
        names = sorted(path.name for path in (tmp_path / "audit").glob("*.jsonl"))
        assert "2026-05-01.jsonl" not in names
        assert "2026-05-06.jsonl" in names
        assert "2026-05-13.jsonl" in names
        assert log.verify() == 2


class TestFailClosed:
    def test_write_tools_block_and_read_tools_warn(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ):
        audit = tmp_path / "audit"
        log = AuditLog(audit)
        hooks = AuditHooks(log)
        log.record("session_start", session_id="sess")
        for child in audit.iterdir():
            child.chmod(0o400)
        audit.chmod(0o500)
        try:
            with caplog.at_level(logging.WARNING, logger="cyberau.audit"):
                blocked = hooks.pre_tool_call("intel_export_stix", {"id": "1"}, "task")
                warned = hooks.pre_tool_call("intel_search", {"q": "a"}, "task")
                hooks.post_tool_call("intel_search", {"q": "a"}, "{}", "task", 1)
        finally:
            audit.chmod(0o700)
            for child in audit.iterdir():
                child.chmod(0o600)
        assert blocked == {
            "action": "block",
            "message": "audit log is not writable; write tools are blocked",
        }
        assert warned is None
        assert hooks.last_warning is not None
        assert "intel_search" in hooks.last_warning
        assert "not writable" in caplog.text

    def test_missing_directory_parent_blocks_writes(self, tmp_path: Path):
        blocked = tmp_path / "audit"
        blocked.write_text("not a directory", encoding="utf-8")
        hooks = AuditHooks(AuditLog(blocked))
        decision = hooks.pre_tool_call("evidence_import", {}, "task")
        assert decision["action"] == "block"
        assert hooks.pre_tool_call("intel_search", {}, "task") is None
        hooks.on_session_start("sess")
        assert hooks.last_warning is not None

    def test_explicit_block_is_recorded(self, tmp_path: Path):
        log = _log(tmp_path)
        hooks = AuditHooks(log)
        decision = hooks.pre_tool_call(
            "intel_add_observation",
            {"id": "1"},
            "task",
            blocked=True,
            block_message="needs approval",
        )
        assert decision["action"] == "block"
        events = [record["event"] for _path, _line, record in log.iter_records()]
        assert events == ["tool_blocked"]
        assert log.verify() == 1


class TestCommands:
    def test_verify_and_export(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture,
    ):
        monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
        monkeypatch.delenv("CYBERAU_AUDIT_LOG_PATH", raising=False)
        log = AuditLog()
        clock = _clock(datetime(2026, 10, 17, 8, 0, tzinfo=log.zone))
        log._clock = clock
        log.record("session_start", session_id="sess")
        log.record(
            "tool_call",
            tool="intel_search",
            args={"q": "a"},
            result="hidden-result",
            duration_ms=1,
        )
        clock.advance(timedelta(days=1))
        log.record(
            "export",
            tool="intel_export_stix",
            args={"id": "1"},
            result="hidden-export",
            duration_ms=2,
        )
        assert main(["audit", "verify"]) == 0
        assert "audit chain verified (3 records)" in capsys.readouterr().out
        assert main(["audit", "verify", "--from", "2026-10-18"]) == 0
        assert "verified (1 records)" in capsys.readouterr().out
        assert main(["audit", "export", "--since", "2026-10-18", "--format", "jsonl"]) == 0
        exported = capsys.readouterr().out
        assert "hidden-export" not in exported
        assert exported.count("\n") == 1
        assert json.loads(exported)["event"] == "export"
        assert main(["audit", "export", "--since", "2026-10-17", "--format", "csv"]) == 0
        csv_text = capsys.readouterr().out
        assert csv_text.startswith("ts,seq,")
        assert "intel_search" in csv_text
        assert "hidden-result" not in csv_text
        path = tmp_path / "audit" / "2026-10-17.jsonl"
        lines = path.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[1])
        record["tool"] = "tampered"
        lines[1] = canonical_json(record)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        assert main(["audit", "verify"]) == 1
        error = capsys.readouterr().err
        assert "line 2" in error
        assert "2026-10-17.jsonl" in error

    def test_usage_errors(self, tmp_path: Path, capsys: pytest.CaptureFixture):
        assert main([]) == 2
        capsys.readouterr()
        assert main(["audit", "export", "--since", "17-10-2026", "--format", "jsonl"]) == 2
        assert "YYYY-MM-DD" in capsys.readouterr().err
        with pytest.raises(AuditUsageError):
            AuditLog(tmp_path / "audit").export(date(2026, 1, 1), fmt="xml")

    def test_data_dir_resolution(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("CYBERAU_AUDIT_LOG_PATH", raising=False)
        monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "data"))
        assert default_audit_dir() == tmp_path / "data" / "audit"
        monkeypatch.setenv("CYBERAU_AUDIT_LOG_PATH", str(tmp_path / "custom"))
        assert default_audit_dir() == tmp_path / "custom"
        monkeypatch.delenv("CYBERAU_AUDIT_LOG_PATH")
        monkeypatch.delenv("CYBERAU_DATA_DIR")
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes"))
        assert default_audit_dir() == tmp_path / "hermes" / "plugin-data" / "cyber-au" / "audit"


class TestHooks:
    def test_tool_classification(self):
        assert tool_writes("intel_export_stix") is True
        assert tool_writes("intel_search") is False
        assert tool_writes("intel_add_observation") is True
        assert tool_writes("address_lookup") is False
        assert tool_writes("asset_get") is False
        assert tool_writes("unknown_tool") is True
        assert tool_writes("intel_export_stix", writes=False) is False
        assert tool_writes("intel_search", read_only=False) is True
        assert tool_writes("custom", readOnlyHint=True) is False

    def test_register_and_plugin_module(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        class Ctx:
            def __init__(self):
                self.hooks = {}
                self.cli = None

            def register_hook(self, name, fn):
                self.hooks[name] = fn

            def register_cli_command(self, **kwargs):
                self.cli = kwargs

        log = _log(tmp_path)
        hooks = AuditHooks(log)
        ctx = Ctx()
        register_hooks(ctx, hooks)
        register_cli(ctx)
        assert set(ctx.hooks) == {
            "pre_tool_call",
            "post_tool_call",
            "on_session_start",
            "on_session_end",
        }
        assert ctx.cli["name"] == "cyber-au"
        ctx.hooks["on_session_start"]("sess", model="local", platform="cli")
        ctx.hooks["post_tool_call"]("brief_deliver", {"to": "queue"}, "body", "task", 2)
        assert log.verify() == 2

        monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "plugin-data"))
        monkeypatch.delenv("CYBERAU_AUDIT_LOG_PATH", raising=False)
        module_path = ROOT / "plugins" / "cyber-au" / "hooks" / "audit.py"
        spec = importlib.util.spec_from_file_location("cyber_au_audit_hooks", module_path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assert module.pre_tool_call("intel_search", {"q": "a"}, task_id="t") is None
        module.post_tool_call("intel_search", {"q": "a"}, result="{}", task_id="t", duration_ms=1)
        module.on_session_start("plugin-sess", model="local", platform="cli")
        module.on_session_end("plugin-sess", completed=True, platform="cli")
        plugin_log = AuditLog()
        assert plugin_log.verify() == 3

    def test_hook_overhead_under_5ms(self, tmp_path: Path):
        log = _log(tmp_path)
        clock = _clock(datetime(2026, 10, 17, 9, 0, tzinfo=log.zone))
        log._clock = clock
        hooks = AuditHooks(log)
        hooks.on_session_start("sess", platform="cli")
        for _ in range(5):
            assert hooks.pre_tool_call("intel_search", {"q": "warm"}, "task") is None
            hooks.post_tool_call("intel_search", {"q": "warm"}, "{}", "task", 1)
        import time

        samples = []
        for index in range(30):
            started = time.perf_counter()
            assert hooks.pre_tool_call("intel_search", {"q": str(index)}, "task") is None
            hooks.post_tool_call("intel_search", {"q": str(index)}, "{}", "task", 1)
            samples.append((time.perf_counter() - started) * 1000)
        average = sum(samples) / len(samples)
        assert average < 5, f"mean hook time {average:.2f} ms"
        assert log.verify() == 36


def test_retention_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("CYBERAU_AUDIT_RETENTION_DAYS", "15")
    log = AuditLog(tmp_path / "audit")
    assert log.retention_days == 15
    monkeypatch.setenv("CYBERAU_AUDIT_RETENTION_DAYS", "nope")
    with pytest.raises(ValueError):
        AuditLog(tmp_path / "other")


def test_cli_verify_from_does_not_hide_a_later_edit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("CYBERAU_AUDIT_LOG_PATH", raising=False)
    log = AuditLog()
    clock = _clock(datetime(2026, 10, 17, 8, 0, tzinfo=log.zone))
    log._clock = clock
    log.record("session_start", session_id="sess")
    clock.advance(timedelta(days=1))
    log.record("session_end", session_id="sess")
    path = tmp_path / "audit" / "2026-10-18.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    record["session_id"] = "edited"
    lines[0] = canonical_json(record)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert main(["audit", "verify", "--from", "2026-10-18"]) == 1
    assert "line 1" in capsys.readouterr().err


def test_files_are_mode_0600(tmp_path: Path):
    log = _log(tmp_path)
    log.record("session_start", session_id="sess")
    path = next((tmp_path / "audit").glob("*.jsonl"))
    assert path.stat().st_mode & 0o777 == 0o600
    assert os.stat(tmp_path / "audit" / "HEAD").st_mode & 0o777 == 0o600


def test_unicode_line_separators_do_not_break_verify(tmp_path: Path):
    log = _log(tmp_path)
    log.record("tool_call", tool="intel_search", args={"q": "a b\u0085c d"})
    assert log.verify() == 1
    assert "a b" in log.export(date(2000, 1, 1), fmt="jsonl")


def test_carriage_return_edit_is_detected(tmp_path: Path):
    log = _log(tmp_path)
    log.record("session_start", session_id="s")
    path = next((tmp_path / "audit").glob("*.jsonl"))
    path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
    with pytest.raises(AuditVerifyError) as caught:
        log.verify()
    assert caught.value.line_number == 1


def test_unusual_hook_values_are_still_recorded(tmp_path: Path):
    log = _log(tmp_path)
    hooks = AuditHooks(log)
    hooks.post_tool_call("intel_post", json.loads('{"a": NaN, "b": Infinity}'), "ok", "t", 1)
    hooks.post_tool_call("intel_post", {"a": 1}, "ok", "t", 12.6)
    hooks.post_tool_call("intel_post", {"a": {1, 2}}, object(), "t", None)
    assert log.verify() == 3
    records = [record for _path, _line, record in log.iter_records()]
    assert records[1]["duration_ms"] == 13


def test_secret_shaped_names_and_values_are_redacted(tmp_path: Path):
    log = _log(tmp_path)
    fake = "abcd1234efgh5678ijkl"
    record = log.record(
        "tool_call",
        tool="intel_search",
        args={
            "aws_secret_access_key": fake,
            "ssh_key": fake,
            "passphrase": fake,
            "cookie": fake,
            "note": "sk-" + fake,
            "other": "ghp_" + fake,
            "url": f"https://user:{fake}@host.example/x",
        },
    )
    blob = json.dumps(record["args_redacted"])
    assert fake not in blob
    assert blob.count("[REDACTED]") >= 7
