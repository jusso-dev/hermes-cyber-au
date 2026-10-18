"""Unit tests for cyber-au doctor. No network and no reading of .env."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import json
import os
import shutil
import sqlite3
import stat
import sys
from datetime import date
from pathlib import Path

import jsonschema
import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
TODAY = date(2026, 10, 17)
SECRET = "doctor-seed-secret-7f3c9a"
LITERAL = "doctor-seed-literal-9aa1"
SCHEMA = {
    "type": "object",
    "properties": {
        "version": {"type": "string"},
        "checks": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "status": {"enum": ["ok", "warn", "fail"]},
                    "detail": {"type": "string"},
                    "fix": {"type": "string"},
                },
                "required": ["id", "status"],
            },
        },
    },
    "required": ["version", "checks"],
}


def _plugin():
    name = "cyber_au_plugin"
    loaded = sys.modules.get(name)
    if loaded is not None:
        return loaded
    directory = REPO / "plugins" / "cyber-au"
    spec = importlib.util.spec_from_file_location(
        name,
        directory / "__init__.py",
        submodule_search_locations=[str(directory)],
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cyber-au plugin could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


plugin = _plugin()
cli = importlib.import_module(f"{plugin.__name__}.cli")
doctor = importlib.import_module(f"{plugin.__name__}.doctor")


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _stamp(root: Path) -> None:
    lock = root / "mcp" / "uv.lock"
    _write(lock, "revision: test\n")
    venv = root / "mcp" / ".venv"
    venv.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(lock.read_bytes()).hexdigest()
    (venv / ".cyberau-lock-sha256").write_text(digest + "\n", encoding="utf-8")


def _store(path: Path, version: int = 1) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.executescript(
        f"""
        CREATE TABLE schema_version (version INTEGER NOT NULL);
        INSERT INTO schema_version (version) VALUES ({version});
        CREATE TABLE sources (id TEXT PRIMARY KEY, name TEXT);
        INSERT INTO sources (id, name) VALUES ('cisa-kev', 'KEV');
        CREATE TABLE indicators (id TEXT PRIMARY KEY);
        CREATE TABLE observations (
            id INTEGER PRIMARY KEY,
            source_id TEXT,
            observed_at TEXT
        );
        INSERT INTO observations (source_id, observed_at)
            VALUES ('cisa-kev', '2026-10-16T00:00:00Z');
        CREATE TABLE vulnerabilities (cve_id TEXT PRIMARY KEY);
        CREATE TABLE advisories (id TEXT PRIMARY KEY);
        """
    )
    connection.commit()
    connection.close()


def _plugin_tree(root: Path, declared: list[str], registered: list[str]) -> None:
    lines = ["name: cyber-au", 'version: "0.1.0"']
    if declared:
        lines.append("provides_tools:")
        lines.extend(f"  - {name}" for name in declared)
    _write(root / "plugins" / "cyber-au" / "plugin.yaml", "\n".join(lines) + "\n")
    body = ["def register(ctx):"]
    if registered:
        body.extend(f"    ctx.register_tool(name={name!r})" for name in registered)
    else:
        body.append("    return None")
    _write(root / "plugins" / "cyber-au" / "__init__.py", "\n".join(body) + "\n")


def healthy(tmp_path: Path) -> Path:
    root = tmp_path / "profile"
    _write(
        root / "distribution.yaml",
        'name: cyber-au\nversion: 0.1.0\nhermes_requires: ">=0.22.2"\n',
    )
    _write(
        root / "config.yaml",
        "timezone: Australia/Sydney\n"
        "security:\n"
        "  allow_private_urls: false\n"
        "plugins:\n"
        "  enabled:\n"
        "    - cyber-au\n"
        "mcp_servers: {}\n",
    )
    _write(
        root / "mcp" / "servers.yaml",
        "servers:\n"
        "  kev:\n"
        "    connector: cisa-kev\n"
        "    args: [serve, cisa-kev]\n"
        "    env: []\n"
        "    enabled_by_default: true\n"
        "    required_env: []\n",
    )
    _write(
        root / "mcp" / "cisa-kev" / "pyproject.toml",
        "[project]\nname = 'cyberau-cisa-kev'\nversion = '0.1.0'\n",
    )
    _write(
        root / "mcp" / "cisa-kev" / "data" / "kev.json",
        json.dumps(
            {
                "catalogVersion": "2026.10.16",
                "dateReleased": "2026-10-16T00:00:00.000Z",
                "vulnerabilities": [],
            }
        ),
    )
    _write(
        root / "mcp" / "asd-ism" / "pyproject.toml",
        "[project]\nname = 'cyberau-asd-ism'\nversion = '0.1.0'\n",
    )
    _write(
        root / "mcp" / "asd-ism" / "data" / "releases.json",
        json.dumps(
            {"releases": [{"tag_name": "v2026.10.16", "published_at": "2026-10-16T00:00:00Z"}]}
        ),
    )
    _write(
        root / "mcp" / "egress-allowlist.yaml",
        "connectors:\n  cisa-kev:\n    hosts: [www.cisa.gov]\n",
    )
    _write(
        root / "cron" / "jobs.json",
        json.dumps({"jobs": [{"id": "cyberau-morning-brief", "paused": True}]}),
    )
    _plugin_tree(root, ["intel_search"], ["intel_search"])
    _stamp(root)
    _store(root / "plugin-data" / "cyber-au" / "intel.sqlite")
    (root / "plugin-data" / "cyber-au" / "audit").mkdir(parents=True, exist_ok=True)
    env = root / ".env"
    env.write_text("# no values\n", encoding="utf-8")
    os.chmod(env, 0o600)
    return root


def run(root: Path, **kwargs):
    health = kwargs.pop("health", None) or (lambda _name, _live: (0, "ok"))
    return doctor.execute(
        root=root,
        home=kwargs.pop("home", root),
        offline=kwargs.pop("offline", True),
        fix=kwargs.pop("fix", False),
        today=kwargs.pop("today", TODAY),
        environ=kwargs.pop("environ", {}),
        hermes_version=kwargs.pop("hermes_version", lambda: "hermes 0.22.2"),
        health=health,
    )


def ids(report) -> dict:
    return {item.id: item for item in report.checks}


def rendered(report) -> str:
    return doctor.format_text(report) + doctor.format_json(report)


def _raw(path: Path) -> bytes:
    handle = os.open(path, os.O_RDONLY)
    try:
        chunks = []
        while True:
            block = os.read(handle, 65536)
            if not block:
                return b"".join(chunks)
            chunks.append(block)
    finally:
        os.close(handle)


def test_healthy_profile_exits_zero_and_matches_schema(tmp_path: Path):
    report = run(healthy(tmp_path))
    jsonschema.validate(report.to_dict(), SCHEMA)
    assert report.version == "0.1.0"
    assert report.exit_code() == 0
    found = ids(report)
    assert found["hermes.version"].status == "ok"
    assert found["plugin.enabled"].status == "ok"
    assert found["plugin.tools"].status == "ok"
    assert found["mcp.venv"].status == "ok"
    assert found["connector.kev"].status == "ok"
    assert "offline probe passed" in found["connector.kev"].detail
    assert "live probe skipped" in found["connector.kev"].detail
    assert found["store.schema"].detail == "schema version 1"
    assert "observations 1" in found["store.rows"].detail
    assert "cisa-kev 2026-10-16T00:00:00Z" in found["store.ingest"].detail
    assert found["store.wal"].detail == "WAL is 0 bytes"
    assert "v2026.10.16" in found["snapshot.ism"].detail
    assert found["snapshot.ism"].status == "ok"
    assert "2026.10.16" in found["snapshot.kev"].detail
    assert found["snapshot.e8"].detail == "not installed"
    assert found["snapshot.e8"].status == "warn"
    assert found["snapshot.attack"].detail == "not installed"
    assert found["cron.jobs"].status == "ok"
    assert "paused" in found["cron.jobs"].detail
    assert found["security.private_urls"].status == "ok"
    assert found["security.audit_log"].status == "ok"
    assert found["security.egress"].status == "ok"
    assert found["security.env_mode"].detail == ".env mode is 600"
    assert "\u2014" not in rendered(report)


def test_failures_set_exit_code_and_each_check(tmp_path: Path):
    root = healthy(tmp_path)
    report = run(root, hermes_version=lambda: "hermes 0.1.0")
    assert ids(report)["hermes.version"].status == "fail"
    assert report.exit_code() == 1

    report = run(root, hermes_version=lambda: "not hermes")
    assert "not available" in ids(report)["hermes.version"].detail

    config = (root / "config.yaml").read_text(encoding="utf-8")
    (root / "config.yaml").write_text(
        config.replace("    - cyber-au\n", ""),
        encoding="utf-8",
    )
    assert ids(run(root))["plugin.enabled"].status == "fail"

    _plugin_tree(root, ["intel_search"], [])
    mismatch = ids(run(root))["plugin.tools"]
    assert mismatch.status == "fail"
    assert "intel_search" in mismatch.detail
    assert mismatch.fix

    (root / "mcp" / ".venv" / ".cyberau-lock-sha256").write_text("0" * 64 + "\n", encoding="utf-8")
    assert ids(run(root))["mcp.venv"].status == "fail"
    shutil.rmtree(root / "mcp" / ".venv")
    assert "not present" in ids(run(root))["mcp.venv"].detail

    _write(
        root / "mcp" / "servers.yaml",
        "servers:\n"
        "  attack:\n"
        "    connector: attack\n"
        "    args: [serve, attack]\n"
        "    enabled_by_default: true\n"
        "    required_env: []\n"
        "  kev:\n"
        "    connector: cisa-kev\n"
        "    args: [serve, cisa-kev]\n"
        '    env: ["NVD_API_KEY=${NVD_API_KEY}"]\n'
        "    enabled_by_default: true\n"
        "    required_env: [NVD_API_KEY]\n",
    )
    missing = ids(run(root))
    assert missing["connector.attack"].detail == "not installed"
    assert missing["connector.attack"].status == "fail"
    assert missing["connector.kev"].status == "fail"
    assert "NVD_API_KEY is not set" in missing["connector.kev"].detail
    assert SECRET not in rendered(run(root, environ={"NVD_API_KEY": SECRET}))

    calls: list[bool] = []

    def health(_name, live):
        calls.append(live)
        if live:
            return 1, "live down"
        return 0, "ok"

    _write(
        root / "mcp" / "servers.yaml",
        "servers:\n"
        "  kev:\n"
        "    connector: cisa-kev\n"
        "    args: [serve, cisa-kev]\n"
        "    env: []\n"
        "    enabled_by_default: true\n"
        "    required_env: []\n",
    )
    live = ids(run(root, offline=False, health=health))["connector.kev"]
    assert live.status == "fail"
    assert "live probe failed" in live.detail
    assert calls == [False, True]

    calls.clear()
    run(root, offline=True, health=health)
    assert calls == [False]


def test_literal_env_value_is_not_printed(tmp_path: Path):
    root = healthy(tmp_path)
    _write(
        root / "mcp" / "servers.yaml",
        "servers:\n"
        "  kev:\n"
        "    connector: cisa-kev\n"
        "    args: [serve, cisa-kev]\n"
        "    env:\n"
        f"      NVD_API_KEY: {LITERAL}\n"
        "    enabled_by_default: true\n"
        "    required_env: []\n",
    )
    report = run(root)
    item = ids(report)["connector.kev"]
    assert item.status == "fail"
    assert "literal" in item.detail
    assert LITERAL not in rendered(report)


def test_store_cron_security_and_snapshot_age(tmp_path: Path):
    root = healthy(tmp_path)
    db = root / "plugin-data" / "cyber-au" / "intel.sqlite"
    db.unlink()
    report = run(root)
    assert ids(report)["store.schema"].status == "fail"
    assert "store.rows" not in ids(report)

    _store(db)
    migrations = root / "plugins" / "cyber-au" / "store" / "migrations"
    migrations.mkdir(parents=True)
    (migrations / "0002_next.sql").write_text("-- next\n", encoding="utf-8")
    assert "expected 2" in ids(run(root))["store.schema"].detail

    _write(
        root / "mcp" / "asd-ism" / "data" / "releases.json",
        json.dumps(
            {"releases": [{"tag_name": "v2026.09.03", "published_at": "2026-09-03T00:00:00Z"}]}
        ),
    )
    stale = ids(run(root))["snapshot.ism"]
    assert stale.status == "warn"
    assert "days old" in stale.detail
    assert stale.fix

    _write(root / "cron" / "jobs.json", json.dumps({"jobs": []}))
    assert ids(run(root))["cron.jobs"].status == "warn"
    _write(
        root / "cron" / "jobs.json",
        json.dumps(
            {"jobs": [{"id": "cyberau-kev-watch", "enabled": True, "last_status": "failed"}]}
        ),
    )
    failed = ids(run(root))["cron.jobs"]
    assert failed.status == "fail"
    assert "cyberau-kev-watch" in failed.detail

    config = (root / "config.yaml").read_text(encoding="utf-8")
    (root / "config.yaml").write_text(
        config.replace("allow_private_urls: false", "allow_private_urls: true"),
        encoding="utf-8",
    )
    assert ids(run(root))["security.private_urls"].status == "fail"
    _write(root / "mcp" / "egress-allowlist.yaml", "connectors: {}\n")
    assert ids(run(root))["security.egress"].status == "fail"


def test_env_is_stat_only_and_fix_does_not_read_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = healthy(tmp_path)
    env = root / ".env"
    env.write_text(f"NVD_API_KEY={SECRET}\nGITHUB_TOKEN={SECRET}\n", encoding="utf-8")
    os.chmod(env, 0o644)
    before = env.read_bytes()
    (root / "plugin-data" / "cyber-au" / "audit").rmdir()

    real_open = Path.open
    real_read_text = Path.read_text
    real_read_bytes = Path.read_bytes

    def guard_open(self: Path, *args, **kwargs):
        if self.name == ".env":
            raise AssertionError("opened .env")
        return real_open(self, *args, **kwargs)

    def guard_text(self: Path, *args, **kwargs):
        if self.name == ".env":
            raise AssertionError("read .env")
        return real_read_text(self, *args, **kwargs)

    def guard_bytes(self: Path, *args, **kwargs):
        if self.name == ".env":
            raise AssertionError("read .env")
        return real_read_bytes(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guard_open)
    monkeypatch.setattr(Path, "read_text", guard_text)
    monkeypatch.setattr(Path, "read_bytes", guard_bytes)

    report = run(root)
    assert ids(report)["security.env_mode"].detail == ".env mode is 644"
    assert ids(report)["security.audit_log"].status == "fail"
    assert SECRET not in rendered(report)
    assert _raw(env) == before

    fixed = run(root, fix=True)
    assert "chmod 600 .env" in fixed.actions
    assert "created the audit log directory" in fixed.actions
    assert stat.S_IMODE(os.lstat(env).st_mode) == 0o600
    assert _raw(env) == before
    assert SECRET not in rendered(fixed)
    assert ids(fixed)["security.env_mode"].status == "ok"
    assert ids(fixed)["security.audit_log"].status == "ok"


def test_env_symlink_is_not_followed(tmp_path: Path):
    root = healthy(tmp_path)
    target = root / "secret-target"
    target.write_text(f"NVD_API_KEY={SECRET}\n", encoding="utf-8")
    env = root / ".env"
    env.unlink()
    env.symlink_to(target)
    report = run(root)
    assert ids(report)["security.env_mode"].status == "fail"
    assert "symlink" in ids(report)["security.env_mode"].detail
    assert SECRET not in rendered(report)


def test_fix_reruns_bootstrap_only(tmp_path: Path):
    root = healthy(tmp_path)
    shutil.rmtree(root / "mcp" / ".venv")
    _write(
        root / "install" / "bootstrap.sh",
        "#!/bin/sh\n"
        "set -eu\n"
        "mkdir -p mcp/.venv\n"
        "python3 -c 'import hashlib, pathlib; "
        'p=pathlib.Path("mcp/uv.lock"); '
        'out=pathlib.Path("mcp/.venv/.cyberau-lock-sha256"); '
        'out.write_text(hashlib.sha256(p.read_bytes()).hexdigest()+"\\n")\'\n'
        "printf '%s\\n' \"$*\" > bootstrap-args.txt\n",
    )
    report = run(root, fix=True, offline=True)
    assert "re-ran install/bootstrap.sh" in report.actions
    args = (root / "bootstrap-args.txt").read_text(encoding="utf-8")
    assert "--offline" in args
    assert "--non-interactive" in args
    assert "--profile cyber-au" in args
    assert ids(report)["mcp.venv"].status == "ok"
    assert report.exit_code() == 0

    again = run(root, fix=True)
    assert "re-ran install/bootstrap.sh" not in again.actions


def test_probe_output_redacts_environment_values(tmp_path: Path):
    root = healthy(tmp_path)

    def health(_name, _live):
        return 1, f"probe saw {SECRET}"

    report = run(root, health=health, environ={"NVD_API_KEY": SECRET})
    text = rendered(report)
    assert SECRET not in text
    assert "[redacted]" in text


def test_checkout_reports_only_installed_connectors_and_named_gaps(tmp_path: Path):
    catalogue = yaml.safe_load((REPO / "mcp" / "servers.yaml").read_text(encoding="utf-8"))
    servers = catalogue["servers"]
    ctx = doctor.Context(
        root=REPO,
        home=tmp_path,
        environ={},
        offline=True,
        today=TODAY,
        hermes_version=lambda: "hermes 0.22.2",
        health=lambda _name, _live: (0, "ok"),
    )
    checks = doctor.check_connectors(ctx)
    assert {item.id for item in checks} == {f"connector.{name}" for name in servers}
    for item in checks:
        name = item.id.split(".", 1)[1]
        spec = servers[name]
        key = spec.get("connector") or name
        installed = (REPO / "mcp" / key / "pyproject.toml").is_file() or key == "stub"
        if doctor._is_external(spec):
            assert "external server" in item.detail
        elif installed:
            assert item.detail != "not installed"
        else:
            assert item.detail == "not installed"

    snapshots = {item.id: item for item in doctor.check_snapshots(ctx)}
    for name in ("e8", "attack"):
        installed = (REPO / "mcp" / servers[name]["connector"] / "pyproject.toml").is_file()
        if installed:
            assert snapshots[f"snapshot.{name}"].detail != "not installed"
        else:
            assert snapshots[f"snapshot.{name}"].detail == "not installed"
    releases = json.loads((REPO / "mcp" / "asd-ism" / "data" / "releases.json").read_text())
    newest = max(releases["releases"], key=lambda row: row["published_at"])
    assert newest["tag_name"] in snapshots["snapshot.ism"].detail
    for name in ("kev", "attack"):
        assert snapshots[f"snapshot.{name}"].status == "warn"
        assert "no local snapshot" in snapshots[f"snapshot.{name}"].detail
    tools = doctor.check_plugin_tools(ctx)
    assert tools.status == "ok", tools.detail


def test_offline_health_command_stays_local(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    runner = doctor.default_health(REPO, {"CYBERAU_DATA_DIR": str(tmp_path)})
    code, output = runner("cisa-kev", False)
    assert code == 0, output
    assert "ok" in output.lower()
    assert SECRET not in output


def test_cli_and_slash_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    root = healthy(tmp_path)
    monkeypatch.setenv("CYBERAU_ROOT", str(root))
    monkeypatch.setenv("HERMES_HOME", str(root))
    monkeypatch.delenv("CYBERAU_DATA_DIR", raising=False)
    monkeypatch.setattr(doctor, "default_hermes_version", lambda: "hermes 0.22.2")

    def _health(_root, _env):
        return lambda _name, _live: (0, "ok")

    monkeypatch.setattr(doctor, "default_health", _health)

    top = argparse.ArgumentParser()
    subs = top.add_subparsers(dest="command")
    plugin_parser = subs.add_parser("cyber-au")
    cli.setup_parser(plugin_parser)
    plugin_parser.set_defaults(func=cli.handle)
    args = top.parse_args(["cyber-au", "doctor", "--offline", "--json"])
    code = args.func(args)
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    jsonschema.validate(payload, SCHEMA)
    assert code == 0
    assert payload["version"] == "0.1.0"
    assert SECRET not in captured.out

    class Capture:
        def register_cli_command(self, **kwargs):
            self.cli_name = kwargs["name"]

        def register_command(self, name, handler, **kwargs):
            self.slash_name = name
            self.slash = handler

        def __getattr__(self, _name):
            return lambda *_args, **_kwargs: None

    capture = Capture()
    plugin.register(capture)
    assert capture.cli_name == "cyber-au"
    assert capture.slash_name == "cyber-au"
    text = capture.slash("doctor --offline --json")
    body = json.loads(text)
    assert body["version"] == "0.1.0"
    assert "not installed" in text
    assert capture.slash("help") == "Usage: /cyber-au doctor [--offline] [--json] [--fix]"


def test_redaction_keeps_plain_settings_readable():
    environ = {
        "HERMES_PROFILE": "cyber-au",
        "CYBERAU_DATA_DIR": "plugin-data",
        "NVD_API_KEY": SECRET,
    }
    text = doctor.redact(f"plugin cyber-au in plugin-data saw {SECRET}", environ)
    assert text == "plugin cyber-au in plugin-data saw [redacted]"


def test_live_probe_gets_only_the_connectors_declared_variables(tmp_path: Path):
    root = healthy(tmp_path)
    _write(
        root / "mcp" / "servers.yaml",
        "servers:\n"
        "  kev:\n"
        "    connector: cisa-kev\n"
        "    args: [serve, cisa-kev]\n"
        "    env:\n"
        "      - FEED_TOKEN=${KEV_FEED_TOKEN}\n"
        "    enabled_by_default: true\n"
        "    required_env: []\n"
        "  other:\n"
        "    connector: other\n"
        "    args: [serve, other]\n"
        "    env:\n"
        "      - OTHER_API_KEY=${OTHER_API_KEY}\n"
        "    required_env: []\n",
    )
    environ = {
        "KEV_FEED_TOKEN": SECRET,
        "OTHER_API_KEY": "other-seed-secret-1b2c3d",
        "AWS_SESSION_TOKEN": "unrelated-seed-secret-4e5f6a",
        "CYBERAU_DATA_DIR": str(tmp_path),
    }
    declared = doctor._server_env(root, root, environ, "cisa-kev")
    assert declared == {"FEED_TOKEN": SECRET}
    child = doctor._probe_env(environ, declared)
    assert child["FEED_TOKEN"] == SECRET
    assert child["CYBERAU_DATA_DIR"] == str(tmp_path)
    assert "OTHER_API_KEY" not in child
    assert "AWS_SESSION_TOKEN" not in child
    assert "KEV_FEED_TOKEN" not in child
    assert "OTHER_API_KEY" not in doctor._probe_env(environ, {})


def test_unreadable_lock_stamp_is_reported_not_raised(tmp_path: Path):
    root = healthy(tmp_path)
    (root / "mcp" / ".venv" / ".cyberau-lock-sha256").write_bytes(b"\xff\xfe\x00bad")
    report = run(root)
    assert ids(report)["mcp.venv"].status == "fail"
    assert "does not match" in ids(report)["mcp.venv"].detail
    assert doctor._venv_needs_bootstrap(
        doctor.Context(
            root=root,
            home=root,
            environ={},
            offline=True,
            today=TODAY,
            hermes_version=lambda: "hermes 0.22.2",
            health=lambda _name, _live: (0, "ok"),
        )
    )


def test_native_connector_with_wrap_metadata_is_probed(tmp_path: Path):
    root = healthy(tmp_path)
    catalogue = root / "mcp" / "servers.yaml"
    content = yaml.safe_load(catalogue.read_text())
    content["servers"]["kev"]["wrap"] = {"upstream": "https://example.com/mcp"}
    catalogue.write_text(yaml.safe_dump(content))
    probes = []

    def health(name, live):
        probes.append((name, live))
        return 1, "probe failed"

    report = run(root, health=health)
    assert ("cisa-kev", False) in probes
    assert ids(report)["connector.kev"].status == "fail"


def test_doctor_uses_the_profile_selected_by_hermes(tmp_path: Path, monkeypatch):
    from types import SimpleNamespace

    selected = tmp_path / "profiles" / "selected"
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setitem(
        sys.modules, "hermes_constants", SimpleNamespace(get_hermes_home=lambda: selected)
    )
    assert doctor.profile_home(tmp_path) == selected


def test_connector_packages_follow_cyberau_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # hermes plugins doctor loads a copy of the plugin from a scratch directory,
    # so CYBERAU_HOME names the profile whose mcp/.venv holds the connectors.
    packages = tmp_path / "mcp" / ".venv" / "lib" / "python3.99" / "site-packages"
    _write(packages / "cyberau_doctor_probe_pkg" / "__init__.py", "VALUE = 7\n")
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.delitem(sys.modules, "cyberau_doctor_probe_pkg", raising=False)
    monkeypatch.setenv("CYBERAU_HOME", str(tmp_path))
    assert plugin._profile_homes()[0] == tmp_path
    plugin._connector_packages()
    assert str(packages) in sys.path
    import cyberau_doctor_probe_pkg

    assert cyberau_doctor_probe_pkg.VALUE == 7
    monkeypatch.delitem(sys.modules, "cyberau_doctor_probe_pkg")


def test_plugin_imports_without_pyyaml(tmp_path: Path):
    # On a native install PyYAML is only importable after register() adds the
    # profile venv, so importing the package itself must not need it.
    import subprocess

    script = (
        "import importlib.util, sys\n"
        "sys.modules['yaml'] = None\n"
        "d = sys.argv[1]\n"
        "spec = importlib.util.spec_from_file_location(\n"
        "    'cyberau_noyaml', d + '/__init__.py', submodule_search_locations=[d])\n"
        "module = importlib.util.module_from_spec(spec)\n"
        "sys.modules[spec.name] = module\n"
        "spec.loader.exec_module(module)\n"
        "assert callable(module.register) and callable(module.main)\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", script, str(REPO / "plugins" / "cyber-au")],
        capture_output=True,
        text=True,
        check=False,
        cwd=tmp_path,
    )
    assert proc.returncode == 0, proc.stderr


@pytest.mark.parametrize(
    "name,connector,filename",
    [
        ("kev", "cisa-kev", "kev.json"),
        ("attack", "mitre-attack", "index.json"),
    ],
)
@pytest.mark.parametrize("content", [None, "{", "{}"])
def test_live_only_snapshot_absence_warns_but_corruption_fails(
    tmp_path, name, connector, filename, content
):
    root = healthy(tmp_path)
    directory = root / "mcp" / connector
    _write(directory / "pyproject.toml", "[project]\n")
    path = directory / "data" / filename
    path.unlink(missing_ok=True)
    if content is not None:
        _write(path, content)
    item = ids(run(root))[f"snapshot.{name}"]
    assert item.status == ("warn" if content is None else "fail")
    if content is None:
        assert "no local snapshot" in item.detail
