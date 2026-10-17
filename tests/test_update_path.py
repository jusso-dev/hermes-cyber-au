"""Update path: keep operator data, pause new cron jobs, roll back schema safely."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ENV_TEXT = "CYBERAU_PROFILE_NOTE=local\n"
MEMORY_TEXT = "The desk prefers plain language.\n"
USER_CONFIG = "timezone: Australia/Perth\nmodel: desk-choice\n"
SHIPPED_CONFIG = "timezone: Australia/Sydney\nsecurity:\n  allow_private_urls: false\n"
NOTE_SQL = "ALTER TABLE indicators ADD COLUMN note TEXT;\n"
BAD_SQL = (
    "INSERT INTO indicators (id, value) VALUES (1001, 'should-not-stick');\n"
    "INSERT INTO no_such_table (id) VALUES (1);\n"
)


def _load():
    path = ROOT / "plugins" / "cyber-au" / "update_path.py"
    spec = importlib.util.spec_from_file_location("cyberau_update_path", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _manifest(version: str) -> str:
    owned = [
        "distribution.yaml",
        "SOUL.md",
        "config.yaml",
        ".env.template",
        "skills",
        "cron/jobs.json",
        "scripts",
        "plugins/cyber-au",
        ".env",
        "memories",
        "backups",
        "plugin-data",
    ]
    lines = [
        "name: cyber-au",
        f"version: {version}",
        'hermes_requires: ">=0.22.2"',
        "distribution_owned:",
        *[f"  - {item}" for item in owned],
        "",
    ]
    return "\n".join(lines)


def _write_dist(
    path: Path,
    *,
    version: str,
    soul: str,
    jobs: list[dict],
    extra_sql: str | None,
) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / "distribution.yaml").write_text(_manifest(version), encoding="utf-8")
    (path / "SOUL.md").write_text(soul, encoding="utf-8")
    (path / "config.yaml").write_text(SHIPPED_CONFIG, encoding="utf-8")
    (path / ".env.template").write_text("# names only\nNVD_API_KEY=\n", encoding="utf-8")
    (path / ".env").write_text("CYBERAU_PROFILE_NOTE=shipped\n", encoding="utf-8")
    (path / "memories").mkdir()
    (path / "memories" / "MEMORY.md").write_text("shipped memory\n", encoding="utf-8")
    (path / "backups").mkdir()
    (path / "backups" / "note.txt").write_text("shipped backup\n", encoding="utf-8")
    shipped_store = path / "plugin-data" / "cyber-au"
    shipped_store.mkdir(parents=True)
    conn = sqlite3.connect(shipped_store / "intel.sqlite")
    conn.execute("CREATE TABLE indicators (id INTEGER PRIMARY KEY, value TEXT)")
    conn.execute("INSERT INTO indicators (id, value) VALUES (1, 'shipped')")
    conn.commit()
    conn.close()
    (path / "skills" / "shipped").mkdir(parents=True)
    (path / "skills" / "shipped" / "SKILL.md").write_text(f"shipped {version}\n", encoding="utf-8")
    (path / "scripts").mkdir()
    (path / "scripts" / "ping.txt").write_text(version + "\n", encoding="utf-8")
    (path / "cron").mkdir()
    (path / "cron" / "jobs.json").write_text(
        json.dumps({"jobs": jobs}, indent=2) + "\n", encoding="utf-8"
    )
    migrations = path / "plugins" / "cyber-au" / "store" / "migrations"
    migrations.mkdir(parents=True)
    origin = ROOT / "plugins" / "cyber-au" / "store" / "migrations" / "0001_schema.sql"
    shutil.copy(origin, migrations)
    if extra_sql is not None:
        (migrations / "0002_note.sql").write_text(extra_sql, encoding="utf-8")
    (path / "plugins" / "cyber-au" / "MARKER").write_text(version + "\n", encoding="utf-8")


def _seed_store(profile: Path) -> None:
    store = profile / "plugin-data" / "cyber-au" / "intel.sqlite"
    store.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(store)
    conn.execute("CREATE TABLE indicators (id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
    conn.executemany(
        "INSERT INTO indicators (id, value) VALUES (?, ?)",
        [(i, f"row-{i}") for i in range(1000)],
    )
    conn.commit()
    conn.close()


def _prepare_profile(profile: Path) -> None:
    profile.mkdir()
    (profile / ".env").write_text(ENV_TEXT, encoding="utf-8")
    (profile / "config.yaml").write_text(USER_CONFIG, encoding="utf-8")
    (profile / "memories").mkdir()
    (profile / "memories" / "MEMORY.md").write_text(MEMORY_TEXT, encoding="utf-8")
    (profile / "backups").mkdir()
    (profile / "backups" / "note.txt").write_text("mine\n", encoding="utf-8")
    (profile / "SOUL.md").write_text("version zero\n", encoding="utf-8")
    (profile / "skills" / "local-only").mkdir(parents=True)
    (profile / "skills" / "local-only" / "SKILL.md").write_text("local skill\n", encoding="utf-8")
    (profile / "cron").mkdir()
    jobs = [
        {
            "id": "daily-brief",
            "name": "daily-brief",
            "prompt": "Old prompt",
            "schedule": "30 7 * * *",
            "enabled": True,
            "state": "scheduled",
        },
        {
            "id": "my-note",
            "name": "my-note",
            "prompt": "Personal",
            "schedule": "0 9 * * *",
            "enabled": True,
            "state": "scheduled",
        },
    ]
    (profile / "cron" / "jobs.json").write_text(
        json.dumps({"jobs": jobs}, indent=2) + "\n", encoding="utf-8"
    )
    _seed_store(profile)


def _jobs(profile: Path) -> dict[str, dict]:
    data = json.loads((profile / "cron" / "jobs.json").read_text(encoding="utf-8"))
    return {job["id"]: job for job in data["jobs"]}


def _stats(profile: Path) -> tuple[int, int]:
    conn = sqlite3.connect(profile / "plugin-data" / "cyber-au" / "intel.sqlite")
    try:
        count, total = conn.execute(
            "SELECT count(*), coalesce(sum(id), 0) FROM indicators"
        ).fetchone()
        return int(count), int(total)
    finally:
        conn.close()


def _update(mod, profile: Path, source: Path, **kwargs) -> int:
    calls: list[list[str]] = []

    def hermes(args: list[str]) -> int:
        calls.append(args)
        raise AssertionError(args)

    kwargs.setdefault("hermes_runner", hermes)
    kwargs.setdefault("bootstrap_runner", lambda home, name: _migrate(mod, home))
    kwargs.setdefault("doctor_runner", lambda name: 0)
    code = mod.run_update(profile_home=profile, profile="cyber-au", source=source, **kwargs)
    assert calls == []
    return code


def _migrate(mod, home: Path) -> int:
    mod.migrate(home)
    return 0


def test_update_from_v010_to_v011_keeps_operator_data(tmp_path: Path) -> None:
    mod = _load()
    profile = tmp_path / "profile"
    _prepare_profile(profile)
    source = tmp_path / "v0.1.1"
    _write_dist(
        source,
        version="0.1.1",
        soul="version one\n",
        jobs=[
            {
                "id": "daily-brief",
                "name": "daily-brief",
                "prompt": "New prompt",
                "schedule": "30 7 * * *",
                "enabled": False,
            },
            {
                "id": "kev-watch",
                "name": "kev-watch",
                "prompt": "Check KEV",
                "schedule": "0 8 * * *",
                "enabled": True,
            },
        ],
        extra_sql=NOTE_SQL,
    )

    assert _update(mod, profile, source) == 0

    assert (profile / ".env").read_text(encoding="utf-8") == ENV_TEXT
    assert (profile / "config.yaml").read_text(encoding="utf-8") == USER_CONFIG
    assert (profile / "memories" / "MEMORY.md").read_text(encoding="utf-8") == MEMORY_TEXT
    assert (profile / "backups" / "note.txt").read_text(encoding="utf-8") == "mine\n"
    assert (profile / "SOUL.md").read_text(encoding="utf-8") == "version one\n"
    assert (profile / "plugins" / "cyber-au" / "MARKER").read_text(encoding="utf-8") == "0.1.1\n"
    assert (profile / "scripts" / "ping.txt").read_text(encoding="utf-8") == "0.1.1\n"
    local_skill = (profile / "skills" / "local-only" / "SKILL.md").read_text(encoding="utf-8")
    shipped_skill = (profile / "skills" / "shipped" / "SKILL.md").read_text(encoding="utf-8")
    assert local_skill == "local skill\n"
    assert shipped_skill == "shipped 0.1.1\n"
    assert "NVD_API_KEY=" in (profile / ".env.EXAMPLE").read_text(encoding="utf-8")
    assert _stats(profile) == (1000, 499500)
    conn = sqlite3.connect(profile / "plugin-data" / "cyber-au" / "intel.sqlite")
    columns = [row[1] for row in conn.execute("PRAGMA table_info(indicators)")]
    versions = [row[0] for row in conn.execute("SELECT version FROM schema_migrations ORDER BY 1")]
    conn.close()
    assert "note" in columns
    assert versions == ["0001_schema.sql", "0002_note.sql"]

    jobs = _jobs(profile)
    assert set(jobs) == {"daily-brief", "my-note", "kev-watch"}
    assert jobs["daily-brief"]["enabled"] is True
    assert jobs["daily-brief"]["prompt"] == "New prompt"
    assert jobs["my-note"]["enabled"] is True
    assert jobs["kev-watch"]["enabled"] is False
    assert jobs["kev-watch"]["state"] == "paused"
    assert jobs["kev-watch"]["paused_reason"]

    jobs["kev-watch"]["enabled"] = True
    jobs["kev-watch"]["state"] = "scheduled"
    (profile / "cron" / "jobs.json").write_text(
        json.dumps({"jobs": list(jobs.values())}, indent=2) + "\n", encoding="utf-8"
    )
    assert _update(mod, profile, source) == 0
    again = _jobs(profile)
    assert again["kev-watch"]["enabled"] is True
    assert again["daily-brief"]["enabled"] is True
    assert _stats(profile) == (1000, 499500)
    assert (profile / ".env").read_text(encoding="utf-8") == ENV_TEXT


def test_force_config_replaces_config_and_keeps_env(tmp_path: Path) -> None:
    mod = _load()
    profile = tmp_path / "profile"
    _prepare_profile(profile)
    source = tmp_path / "dist"
    _write_dist(source, version="0.1.1", soul="version one\n", jobs=[], extra_sql=None)
    assert _update(mod, profile, source, force_config=True) == 0
    text = (profile / "config.yaml").read_text(encoding="utf-8")
    assert "desk-choice" not in text
    assert "Australia/Sydney" in text
    assert (profile / ".env").read_text(encoding="utf-8") == ENV_TEXT


def test_failed_migration_restores_store_and_prints_backup(tmp_path: Path, capsys) -> None:
    mod = _load()
    profile = tmp_path / "profile"
    _prepare_profile(profile)
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    origin = ROOT / "plugins" / "cyber-au" / "store" / "migrations" / "0001_schema.sql"
    shutil.copy(origin, migrations)
    (migrations / "0002_bad.sql").write_text(BAD_SQL, encoding="utf-8")

    with pytest.raises(mod.MigrationFailure) as caught:
        mod.migrate(profile, migrations)
    printed = capsys.readouterr().out
    assert "The intel store was left unchanged." in printed
    assert f"Backup: {caught.value.backup}" in printed
    assert caught.value.backup.is_file()
    assert "plugin-data/cyber-au/backups" in str(caught.value.backup)
    assert "CYBERAU_PROFILE_NOTE" not in printed
    assert (profile / ".env").read_text(encoding="utf-8") == ENV_TEXT
    assert (profile / "backups" / "note.txt").read_text(encoding="utf-8") == "mine\n"
    assert not (profile / "backups" / "note.txt").samefile(caught.value.backup)
    assert _stats(profile) == (1000, 499500)
    conn = sqlite3.connect(profile / "plugin-data" / "cyber-au" / "intel.sqlite")
    stuck = conn.execute(
        "SELECT count(*) FROM indicators WHERE value = 'should-not-stick'"
    ).fetchone()[0]
    tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
    conn.close()
    assert stuck == 0
    assert "schema_migrations" not in tables


def test_cli_migrate_failure_keeps_env(tmp_path: Path) -> None:
    profile = tmp_path / "profile"
    _prepare_profile(profile)
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    (migrations / "0002_bad.sql").write_text(BAD_SQL, encoding="utf-8")
    # 0001 is already the only way to record versions. Apply a failing file alone
    # after the bookkeeping table exists, so the failure is the new statement.
    mod = _load()
    mod.migrate(profile, ROOT / "plugins" / "cyber-au" / "store" / "migrations")
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "plugins" / "cyber-au" / "cli.py"),
            "migrate",
            "--profile-home",
            str(profile),
            "--migrations",
            str(migrations),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "Backup:" in result.stdout
    assert "left unchanged" in result.stdout
    assert "CYBERAU_PROFILE_NOTE" not in result.stdout
    assert "CYBERAU_PROFILE_NOTE" not in result.stderr
    assert (profile / ".env").is_file()
    assert (profile / ".env").read_text(encoding="utf-8") == ENV_TEXT
    assert _stats(profile) == (1000, 499500)


def test_downgrade_refuses_and_leaves_the_profile(tmp_path: Path) -> None:
    mod = _load()
    repo = _git_distribution(tmp_path / "repo")
    profile = tmp_path / "profile"
    _prepare_profile(profile)
    exported = tmp_path / "exported-new"
    mod.export_git_tag(repo, "v0.1.1", exported)
    assert _update(mod, profile, exported) == 0
    assert "0002_note.sql" in _versions(profile)
    soul = (profile / "SOUL.md").read_text(encoding="utf-8")
    boot_calls: list[Path] = []

    def boot(home: Path, name: str) -> int:
        boot_calls.append(home)
        return 0

    with pytest.raises(mod.UpdateError, match="Refusing to downgrade"):
        mod.run_update(
            profile_home=profile,
            profile="cyber-au",
            source=repo,
            to_tag="v0.1.0",
            bootstrap_runner=boot,
            doctor_runner=lambda name: 0,
            hermes_runner=lambda args: 0,
        )
    assert boot_calls == []
    assert (profile / "SOUL.md").read_text(encoding="utf-8") == soul
    assert (profile / ".env").read_text(encoding="utf-8") == ENV_TEXT
    assert _stats(profile) == (1000, 499500)
    assert "0002_note.sql" in _versions(profile)


def test_rollback_to_older_tag_when_schema_matches(tmp_path: Path) -> None:
    mod = _load()
    repo = _git_distribution(tmp_path / "repo")
    profile = tmp_path / "profile"
    _prepare_profile(profile)
    exported = tmp_path / "exported-new"
    mod.export_git_tag(repo, "v0.1.1", exported)
    mod.apply_distribution(exported, profile)
    only_first = tmp_path / "only-0001"
    only_first.mkdir()
    shutil.copy(
        ROOT / "plugins" / "cyber-au" / "store" / "migrations" / "0001_schema.sql",
        only_first,
    )
    mod.migrate(profile, only_first)
    assert _update(mod, profile, repo, to_tag="v0.1.0") == 0
    assert (profile / "SOUL.md").read_text(encoding="utf-8") == "version zero\n"
    assert (profile / ".env").read_text(encoding="utf-8") == ENV_TEXT
    assert (profile / "config.yaml").read_text(encoding="utf-8") == USER_CONFIG
    assert _stats(profile) == (1000, 499500)
    assert _versions(profile) == ["0001_schema.sql"]


def test_cli_runs_profile_update_then_bootstrap_then_doctor(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "hermes.log"
    fake = bin_dir / "hermes"
    fake.write_text(
        '#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$HERMES_LOG"\nexit 0\n',
        encoding="utf-8",
    )
    fake.chmod(0o755)
    profile = tmp_path / "profile"
    profile.mkdir()
    (profile / ".env").write_text(ENV_TEXT, encoding="utf-8")
    env = os.environ.copy()
    env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")
    env["HERMES_LOG"] = str(log)
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "plugins" / "cyber-au" / "cli.py"),
            "update",
            "--profile",
            "cyber-au",
            "--profile-home",
            str(profile),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    assert log.read_text(encoding="utf-8").splitlines() == [
        "profile update cyber-au --yes",
        "-p cyber-au cyber-au doctor",
    ]
    assert (profile / ".env").read_text(encoding="utf-8") == ENV_TEXT
    assert (profile / "plugin-data" / "cyber-au" / "intel.sqlite").is_file()


def test_failed_hermes_update_does_not_bootstrap(tmp_path: Path) -> None:
    mod = _load()
    called: list[str] = []
    code = mod.run_update(
        profile_home=tmp_path / "profile",
        profile="cyber-au",
        hermes_runner=lambda args: 3,
        bootstrap_runner=lambda home, name: called.append("boot") or 0,
        doctor_runner=lambda name: called.append("doctor") or 0,
    )
    assert code == 3
    assert called == []
    assert not (tmp_path / "profile" / ".env").exists()


def test_docs_and_manifest_state_the_version_policy() -> None:
    mod = _load()
    text = (ROOT / "docs" / "operations" / "updating.md").read_text(encoding="utf-8")
    assert "hermes_requires" in text
    assert "weekly bump" in text
    assert "deps-and-hermes-bump" in text
    assert "--force-config" in text
    assert "arrives paused" in text
    assert "\u2014" not in text
    manifest = mod.read_manifest(ROOT / "distribution.yaml")
    assert manifest.hermes_requires == ">=0.22.2"
    assert "install/bootstrap.sh" in manifest.distribution_owned
    assert "cron/jobs.json" in manifest.distribution_owned


def test_bootstrap_script_migrates_and_keeps_env(tmp_path: Path) -> None:
    profile = tmp_path / "profile"
    profile.mkdir()
    (profile / ".env").write_text(ENV_TEXT, encoding="utf-8")
    result = subprocess.run(
        [
            "sh",
            str(ROOT / "install" / "bootstrap.sh"),
            "--profile",
            "cyber-au",
            "--profile-home",
            str(profile),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert (profile / ".env").read_text(encoding="utf-8") == ENV_TEXT
    assert _versions(profile) == ["0001_schema.sql"]


def test_plugin_registers_update_command() -> None:
    path = ROOT / "plugins" / "cyber-au" / "cli.py"
    spec = importlib.util.spec_from_file_location("cyberau_cli", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.path.insert(0, str(path.parent))
    spec.loader.exec_module(module)

    class Ctx:
        def register_cli_command(self, **kwargs) -> None:
            self.kwargs = kwargs

    ctx = Ctx()
    module.register(ctx)
    assert ctx.kwargs["name"] == "cyber-au"
    assert "update" in ctx.kwargs["help"].casefold()


def _versions(profile: Path) -> list[str]:
    conn = sqlite3.connect(profile / "plugin-data" / "cyber-au" / "intel.sqlite")
    try:
        return [
            row[0] for row in conn.execute("SELECT version FROM schema_migrations ORDER BY version")
        ]
    finally:
        conn.close()


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=cyber-au test",
            "-c",
            "user.email=cyber-au-test@example.com",
            "-c",
            "commit.gpgsign=false",
            "-c",
            f"core.hooksPath={repo}/.no-hooks",
            *args,
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def _git_distribution(repo: Path) -> Path:
    repo.mkdir()
    (repo / ".no-hooks").mkdir()
    _write_dist(repo, version="0.1.0", soul="version zero\n", jobs=[], extra_sql=None)
    _git(repo, "init")
    _git(repo, "add", "-f", "--", ".")
    _git(repo, "commit", "-m", "v0.1.0")
    _git(repo, "tag", "v0.1.0")
    (repo / "SOUL.md").write_text("version one\n", encoding="utf-8")
    (repo / "distribution.yaml").write_text(_manifest("0.1.1"), encoding="utf-8")
    migrations = repo / "plugins" / "cyber-au" / "store" / "migrations"
    (migrations / "0002_note.sql").write_text(NOTE_SQL, encoding="utf-8")
    (repo / "plugins" / "cyber-au" / "MARKER").write_text("0.1.1\n", encoding="utf-8")
    _git(repo, "add", "-f", "--", ".")
    _git(repo, "commit", "-m", "v0.1.1")
    _git(repo, "tag", "v0.1.1")
    return repo


def test_migration_splitter_keeps_triggers_and_comment_semicolons() -> None:
    mod = _load()
    script = (
        "/* note; with a semicolon */\n"
        "CREATE TABLE audit (id INTEGER);\n"
        "CREATE TRIGGER audit_row AFTER INSERT ON audit BEGIN\n"
        "  INSERT INTO audit VALUES (1);\n"
        "END;\n"
        "INSERT INTO audit VALUES ('a;b'); -- trailing; note\n"
    )
    statements = mod._split_sql(script)
    assert len(statements) == 3
    assert statements[1].rstrip().endswith("END;")
    conn = sqlite3.connect(":memory:")
    for statement in statements:
        conn.execute(statement)
    conn.close()


def test_migration_splitter_rejects_transactions_behind_comments() -> None:
    mod = _load()
    with pytest.raises(mod.UpdateError, match="must not manage transactions"):
        mod._split_sql("-- start\nBEGIN;\nCREATE TABLE t (a);")


def test_unreadable_migration_restores_the_store(tmp_path: Path, capsys) -> None:
    mod = _load()
    profile = tmp_path / "profile"
    _prepare_profile(profile)
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    shutil.copy(
        ROOT / "plugins" / "cyber-au" / "store" / "migrations" / "0001_schema.sql", migrations
    )
    (migrations / "0002_bytes.sql").write_bytes(b"CREATE TABLE t (a); -- \xff\xfe\n")

    with pytest.raises(mod.MigrationFailure) as caught:
        mod.migrate(profile, migrations)
    assert "0002_bytes.sql" in str(caught.value)
    assert f"Backup: {caught.value.backup}" in capsys.readouterr().out
    assert _stats(profile) == (1000, 499500)
    conn = sqlite3.connect(profile / "plugin-data" / "cyber-au" / "intel.sqlite")
    tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
    conn.close()
    assert "schema_migrations" not in tables


def test_source_older_than_the_store_is_refused(tmp_path: Path) -> None:
    mod = _load()
    repo = _git_distribution(tmp_path / "repo")
    profile = tmp_path / "profile"
    _prepare_profile(profile)
    newer = tmp_path / "exported-new"
    mod.export_git_tag(repo, "v0.1.1", newer)
    assert _update(mod, profile, newer) == 0
    older = tmp_path / "exported-old"
    mod.export_git_tag(repo, "v0.1.0", older)
    soul = (profile / "SOUL.md").read_text(encoding="utf-8")

    with pytest.raises(mod.UpdateError, match="Refusing to downgrade"):
        _update(mod, profile, older)
    assert (profile / "SOUL.md").read_text(encoding="utf-8") == soul
    assert "0002_note.sql" in _versions(profile)


def test_bootstrap_refuses_python_older_than_3_11(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "python3"
    fake.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    fake.chmod(0o755)
    profile = tmp_path / "profile"
    profile.mkdir()
    result = subprocess.run(
        ["/bin/sh", str(ROOT / "install" / "bootstrap.sh"), "--profile-home", str(profile)],
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": str(bin_dir)},
    )
    assert result.returncode == 1
    assert "Python 3.11 or newer" in result.stderr
    assert not (profile / "plugin-data").exists()
