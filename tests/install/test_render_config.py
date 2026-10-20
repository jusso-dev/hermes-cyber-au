"""Golden tests for install/render_config.py. No network and no secret values."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
RENDER = ROOT / "install" / "render_config.py"
SERVERS = ROOT / "mcp" / "servers.yaml"
MARKER = "test-only-not-a-secret"


def _run(
    home: Path, servers: Path, config: Path, env_file: Path
) -> subprocess.CompletedProcess[str]:
    managed = home / "plugin-data" / "cyber-au" / "managed-servers.json"
    status = home / "plugin-data" / "cyber-au" / "bootstrap-status.json"
    return subprocess.run(
        [
            sys.executable,
            str(RENDER),
            "--profile-home",
            str(home),
            "--servers",
            str(servers),
            "--config",
            str(config),
            "--env-file",
            str(env_file),
            "--managed",
            str(managed),
            "--status",
            str(status),
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_empty_config_renders_keyless_and_disables_keyed(tmp_path: Path) -> None:
    home = tmp_path / "profile"
    config = home / "config.yaml"
    env_file = home / ".env"
    proc = _run(home, SERVERS, config, env_file)
    assert proc.returncode == 0, proc.stderr
    loaded = yaml.safe_load(config.read_text(encoding="utf-8"))
    assert loaded["timezone"] == "Australia/Sydney"
    kev = loaded["mcp_servers"]["kev"]
    assert kev["args"] == ["serve", "cisa-kev"]
    assert kev["trust"] == "untrusted"
    assert kev["lazy"] is True
    assert kev["x-cyber-au-managed"] is True
    assert "enabled" not in kev
    assert kev["command"] == str(home.resolve() / "mcp" / ".venv" / "bin" / "cyberau-mcp")
    assert kev["env"]["CYBERAU_DATA_DIR"] == str(home.resolve() / "plugin-data" / "cyber-au")
    assert kev["env"]["CYBERAU_EGRESS_ALLOWLIST"] == str(
        home.resolve() / "mcp" / "egress-allowlist.yaml"
    )
    nvd = loaded["mcp_servers"]["nvd"]
    assert nvd.get("enabled", True) is True
    assert nvd["env"]["NVD_API_KEY"] == "${NVD_API_KEY}"
    assert loaded["mcp_servers"]["ism"]["env"]["GITHUB_TOKEN"] == "${GITHUB_TOKEN}"
    assert "enabled" not in loaded["mcp_servers"]["ism"]
    assert "NVD_API_KEY is unset" not in proc.stdout
    assert "stub" not in loaded["mcp_servers"]
    for name in ("internetdb", "ghsa", "threatsieve"):
        assert loaded["mcp_servers"][name]["enabled"] is False
    assert MARKER not in config.read_text(encoding="utf-8")


def test_second_render_is_byte_identical(tmp_path: Path) -> None:
    home = tmp_path / "profile"
    config = home / "config.yaml"
    env_file = home / ".env"
    first = _run(home, SERVERS, config, env_file)
    assert first.returncode == 0, first.stderr
    before = {
        "config": config.read_bytes(),
        "managed": (home / "plugin-data" / "cyber-au" / "managed-servers.json").read_bytes(),
        "status": (home / "plugin-data" / "cyber-au" / "bootstrap-status.json").read_bytes(),
    }
    second = _run(home, SERVERS, config, env_file)
    assert second.returncode == 0, second.stderr
    assert config.read_bytes() == before["config"]
    assert (home / "plugin-data" / "cyber-au" / "managed-servers.json").read_bytes() == before[
        "managed"
    ]
    assert (home / "plugin-data" / "cyber-au" / "bootstrap-status.json").read_bytes() == before[
        "status"
    ]


def test_user_edits_survive_and_a_key_enables_abusech(tmp_path: Path) -> None:
    home = tmp_path / "profile"
    servers = tmp_path / "servers.yaml"
    config = home / "config.yaml"
    env_file = home / ".env"
    _write(
        servers,
        """
servers:
  kev:
    args: [serve, kev]
    env: []
    trust: untrusted
    lazy: true
    timeout: 120
    enabled_by_default: true
    required_env: []
  abusech:
    args: [serve, abusech]
    env:
      - ABUSECH_AUTH_KEY=${ABUSECH_AUTH_KEY}
    trust: untrusted
    lazy: true
    timeout: 120
    enabled_by_default: true
    required_env:
      - ABUSECH_AUTH_KEY
  paid:
    args: [serve, paid]
    env:
      - PAID_TOKEN=${PAID_TOKEN}
    trust: untrusted
    enabled_by_default: false
    required_env:
      - PAID_TOKEN
""",
    )
    _write(
        config,
        """
model:
  name: my-analyst-model
timezone: Pacific/Auckland
security:
  allow_private_urls: false
  analyst_note: keep this
mcp_servers:
  custom:
    command: /usr/bin/true
    args: [stay]
    trust: trusted
""",
    )
    disabled = _run(home, servers, config, env_file)
    assert disabled.returncode == 0, disabled.stderr
    loaded = yaml.safe_load(config.read_text(encoding="utf-8"))
    assert loaded["model"]["name"] == "my-analyst-model"
    assert loaded["timezone"] == "Pacific/Auckland"
    assert loaded["security"]["analyst_note"] == "keep this"
    assert loaded["security"]["allow_private_urls"] is False
    assert loaded["mcp_servers"]["custom"]["command"] == "/usr/bin/true"
    assert loaded["mcp_servers"]["custom"]["args"] == ["stay"]
    assert loaded["mcp_servers"]["abusech"]["enabled"] is False
    assert loaded["mcp_servers"]["abusech"]["env"]["ABUSECH_AUTH_KEY"] == "${ABUSECH_AUTH_KEY}"
    assert "ABUSECH_AUTH_KEY is unset" in disabled.stdout

    _write(env_file, f"ABUSECH_AUTH_KEY={MARKER}\nPAID_TOKEN={MARKER}\n")
    enabled = _run(home, servers, config, env_file)
    assert enabled.returncode == 0, enabled.stderr
    loaded = yaml.safe_load(config.read_text(encoding="utf-8"))
    text = config.read_text(encoding="utf-8")
    assert loaded["mcp_servers"]["abusech"]["enabled"] is True
    assert loaded["mcp_servers"]["paid"]["enabled"] is False
    assert loaded["model"]["name"] == "my-analyst-model"
    assert loaded["timezone"] == "Pacific/Auckland"
    assert loaded["security"]["analyst_note"] == "keep this"
    assert loaded["mcp_servers"]["custom"]["args"] == ["stay"]
    assert MARKER not in text
    assert MARKER not in enabled.stdout
    assert MARKER not in enabled.stderr
    status = json.loads((home / "plugin-data" / "cyber-au" / "bootstrap-status.json").read_text())
    assert MARKER not in json.dumps(status)
    assert status["present_env"] == ["ABUSECH_AUTH_KEY", "PAID_TOKEN"]


def test_partially_managed_config_keeps_user_servers_and_extra_fields(
    tmp_path: Path,
) -> None:
    home = tmp_path / "profile"
    servers = tmp_path / "servers.yaml"
    config = home / "config.yaml"
    env_file = home / ".env"
    _write(
        servers,
        """
servers:
  kev:
    args: [serve, cisa-kev]
    env: []
    trust: untrusted
    lazy: true
    timeout: 120
    tools:
      include: [kev_lookup]
  epss:
    args: [serve, first-epss]
    env: []
    trust: untrusted
    lazy: true
""",
    )
    _write(
        config,
        """
timezone: Australia/Sydney
mcp_servers:
  kev:
    command: /old
    x-cyber-au-managed: true
    supports_parallel_tool_calls: false
    enabled: false
  custom:
    command: /usr/bin/true
    trust: trusted
  retired:
    command: /gone
    x-cyber-au-managed: true
""",
    )
    proc = _run(home, servers, config, env_file)
    assert proc.returncode == 0, proc.stderr
    loaded = yaml.safe_load(config.read_text(encoding="utf-8"))
    servers_out = loaded["mcp_servers"]
    assert servers_out["kev"]["command"] == str(
        home.resolve() / "mcp" / ".venv" / "bin" / "cyberau-mcp"
    )
    assert servers_out["kev"]["supports_parallel_tool_calls"] is False
    assert servers_out["kev"]["enabled"] is False
    assert servers_out["kev"]["tools"]["include"] == ["kev_lookup"]
    assert servers_out["custom"]["command"] == "/usr/bin/true"
    assert "x-cyber-au-managed" not in servers_out["custom"]
    assert "retired" not in servers_out
    assert "epss" in servers_out
    names = json.loads(
        (home / "plugin-data" / "cyber-au" / "managed-servers.json").read_text(encoding="utf-8")
    )["servers"]
    assert names == ["epss", "kev"]
    again = _run(home, servers, config, env_file)
    assert again.returncode == 0
    assert yaml.safe_load(config.read_text(encoding="utf-8"))["mcp_servers"]["custom"][
        "command"
    ] == ("/usr/bin/true")


def test_literal_env_value_is_refused_without_echoing_it(tmp_path: Path) -> None:
    home = tmp_path / "profile"
    servers = tmp_path / "servers.yaml"
    leaked = "literal-must-not-leak"
    _write(
        servers,
        f"""
servers:
  abusech:
    args: [serve, abusech]
    env:
      - ABUSECH_AUTH_KEY={leaked}
    required_env: []
""",
    )
    proc = _run(home, servers, home / "config.yaml", home / ".env")
    assert proc.returncode != 0
    assert leaked not in proc.stdout
    assert leaked not in proc.stderr
    assert "ABUSECH_AUTH_KEY" in proc.stderr


_TWO_SERVERS = """
servers:
  kev:
    args: [serve, kev]
    env: []
    trust: untrusted
    enabled_by_default: true
    required_env: []
  abusech:
    args: [serve, abusech]
    env:
      - ABUSECH_AUTH_KEY=${ABUSECH_AUTH_KEY}
    trust: untrusted
    enabled_by_default: true
    required_env:
      - ABUSECH_AUTH_KEY
"""


def test_comments_and_a_same_named_user_server_survive(tmp_path: Path) -> None:
    home = tmp_path / "profile"
    servers = tmp_path / "servers.yaml"
    config = home / "config.yaml"
    env_file = home / ".env"
    _write(servers, _TWO_SERVERS)
    _write(
        config,
        "# kept note\n"
        "timezone: Australia/Perth  # mine\n"
        "model:\n"
        "  default: foo  # chosen\n"
        "mcp_servers:\n"
        "  kev:\n"
        "    command: /usr/local/bin/my-kev\n"
        "\n"
        "# after note\n"
        "other: 1\n",
    )
    first = _run(home, servers, config, env_file)
    assert first.returncode == 0, first.stderr
    text = config.read_text(encoding="utf-8")
    for kept in ("# kept note", "# mine", "# chosen", "# after note", "other: 1"):
        assert kept in text
    loaded = yaml.safe_load(text)
    assert loaded["timezone"] == "Australia/Perth"
    assert loaded["mcp_servers"]["kev"] == {"command": "/usr/local/bin/my-kev"}
    assert loaded["mcp_servers"]["abusech"]["enabled"] is False
    assert "Server kev" in first.stdout
    before = config.read_bytes()
    assert _run(home, servers, config, env_file).returncode == 0
    assert config.read_bytes() == before


def test_a_commented_blank_key_is_still_unset(tmp_path: Path) -> None:
    home = tmp_path / "profile"
    servers = tmp_path / "servers.yaml"
    config = home / "config.yaml"
    env_file = home / ".env"
    _write(servers, _TWO_SERVERS)
    _write(env_file, "ABUSECH_AUTH_KEY=   # todo\n")
    assert _run(home, servers, config, env_file).returncode == 0
    loaded = yaml.safe_load(config.read_text(encoding="utf-8"))
    assert loaded["mcp_servers"]["abusech"]["enabled"] is False
    _write(env_file, f"ABUSECH_AUTH_KEY={MARKER} # note\n")
    assert _run(home, servers, config, env_file).returncode == 0
    loaded = yaml.safe_load(config.read_text(encoding="utf-8"))
    assert loaded["mcp_servers"]["abusech"]["enabled"] is True


def test_remote_wrap_uses_a_bearer_placeholder_once_its_token_is_set(tmp_path: Path) -> None:
    home = tmp_path / "profile"
    config = home / "config.yaml"
    env_file = home / ".env"
    proc = _run(home, SERVERS, config, env_file)
    assert proc.returncode == 0, proc.stderr
    radar = yaml.safe_load(config.read_text(encoding="utf-8"))["mcp_servers"]["cloudflare_radar"]
    assert radar["url"] == "https://mcp.cloudflare.com/mcp?codemode=false"
    assert radar["auth"] == "oauth"
    assert "headers" not in radar and "command" not in radar
    assert radar["tools"] == {"include": ["*_radar_*"]}
    assert radar["enabled"] is False

    # The person switches it on, then adds the token. Neither render turns it off.
    text = config.read_text(encoding="utf-8")
    on = text.replace('"*_radar_*"\n    enabled: false', '"*_radar_*"\n    enabled: true')
    assert on != text
    _write(config, on)
    _write(env_file, f"CLOUDFLARE_RADAR_API_TOKEN={MARKER}\n")
    proc = _run(home, SERVERS, config, env_file)
    assert proc.returncode == 0, proc.stderr
    text = config.read_text(encoding="utf-8")
    radar = yaml.safe_load(text)["mcp_servers"]["cloudflare_radar"]
    assert radar["headers"] == {"Authorization": "Bearer ${CLOUDFLARE_RADAR_API_TOKEN}"}
    assert "auth" not in radar
    assert radar["enabled"] is True
    assert MARKER not in text


def test_an_old_stdio_render_of_a_remote_wrap_is_replaced(tmp_path: Path) -> None:
    home = tmp_path / "profile"
    config = home / "config.yaml"
    _write(
        config,
        """
mcp_servers:
  cloudflare_radar:
    command: /old/cyberau-mcp
    args: [serve, cloudflare-radar]
    env:
      CYBERAU_DATA_DIR: /old
    enabled: true
    x-cyber-au-managed: true
""",
    )
    proc = _run(home, SERVERS, config, home / ".env")
    assert proc.returncode == 0, proc.stderr
    radar = yaml.safe_load(config.read_text(encoding="utf-8"))["mcp_servers"]["cloudflare_radar"]
    assert not {"command", "args", "env"} & set(radar)
    assert radar["url"].startswith("https://mcp.cloudflare.com/")
    assert radar["enabled"] is True
