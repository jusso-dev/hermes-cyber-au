"""The shipped allowlist stays aligned with the connector inventory."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools" / "ci" / "check_allowlist.py"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_repo_allowlist_matches_inventory():
    result = _run()
    assert result.returncode == 0, result.stderr


def test_missing_host_fails(tmp_path: Path):
    source = (ROOT / "mcp" / "egress-allowlist.yaml").read_text(encoding="utf-8")
    drifted = tmp_path / "allow.yaml"
    drifted.write_text(source.replace("      - www.cisa.gov\n", ""), encoding="utf-8")
    result = _run("--allowlist", str(drifted))
    assert result.returncode != 0
    assert "cisa-kev" in result.stderr


def test_shorter_floor_fails(tmp_path: Path):
    source = (ROOT / "mcp" / "egress-allowlist.yaml").read_text(encoding="utf-8")
    drifted = tmp_path / "allow.yaml"
    drifted.write_text(source.replace("  - 100.64.0.0/10\n", ""), encoding="utf-8")
    result = _run("--allowlist", str(drifted))
    assert result.returncode != 0
    assert "100.64.0.0/10" in result.stderr


def test_print_hosts_includes_catalogue_and_skips_loopback():
    result = _run("--print-hosts")
    assert result.returncode == 0, result.stderr
    hosts = set(result.stdout.split())
    assert "www.cisa.gov" in hosts
    assert "services.nvd.nist.gov" in hosts
    assert "127.0.0.1" not in hosts
    assert "localhost" not in hosts
    assert "example.com" not in hosts
