"""Checks for the pinned, read-only VirusTotal wrap. No network and no vendor install."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml
from cyberau_common.ratelimit import RateLimited, RateLimiter

PACKAGE = Path(__file__).resolve().parents[1]
MCP = PACKAGE.parent
ROOT = MCP.parent
FIXTURES = PACKAGE / "tests" / "fixtures"
EXPECTED = ["get_file_report", "get_url_report", "get_domain_report", "get_ip_report"]
WRITE_WORDS = re.compile(r"(?i)submit|reanaly[sz]e|rescan|upload|comment|vote")
SECRET = re.compile(
    r"(?i)(authorization|x-apikey|x-api-key|vtai_token)[\"']?\s*[:=]\s*(?![\"']?\$\{)[\"']?\S+"
)


def _yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _entry() -> dict:
    return _yaml(MCP / "servers.yaml")["servers"]["virustotal"]


def _recorded_tools() -> list[dict]:
    return json.loads((FIXTURES / "tools_list.json").read_text(encoding="utf-8"))


def _registered(include: list[str]) -> list[str]:
    """The tools a client sees once `tools.include` filters the recorded `tools/list`."""
    return [tool["name"] for tool in _recorded_tools() if tool["name"] in include]


def test_expected_tools_are_frozen_and_present_in_the_recorded_release():
    frozen = (PACKAGE / "expected_tools.txt").read_text(encoding="utf-8").split()
    assert frozen == EXPECTED
    assert set(frozen) <= {tool["name"] for tool in _recorded_tools()}


def test_include_list_matches_the_frozen_names():
    entry = _entry()
    assert entry["tools"]["include"] == EXPECTED
    assert (MCP / entry["expected_tools"]).is_file()


def test_filter_registers_only_the_four_report_tools():
    registered = _registered(_entry()["tools"]["include"])
    assert sorted(registered) == sorted(EXPECTED)
    assert len(_recorded_tools()) > len(registered)


def test_no_write_tool_is_registered():
    by_name = {tool["name"]: tool for tool in _recorded_tools()}
    for name in _registered(_entry()["tools"]["include"]):
        assert not WRITE_WORDS.search(name), name
        annotations = by_name[name]["annotations"]
        assert annotations["readOnlyHint"] is True
        assert annotations["destructiveHint"] is False


def test_every_excluded_upstream_tool_is_a_write_or_a_follow_up_read():
    included = set(_entry()["tools"]["include"])
    for tool in _recorded_tools():
        if tool["name"] in included:
            continue
        writes = tool["annotations"]["readOnlyHint"] is False
        assert writes or tool["name"] in {"get_analysis", "get_submission"}, tool["name"]


def test_lock_pins_a_release_with_checksums():
    lock = _yaml(MCP / "vendor" / "virustotal-mcp.lock")
    assert re.fullmatch(r"v\d+\.\d+\.\d+", lock["version"])
    assert lock["package"] == f"vt-mcp=={lock['version'].lstrip('v')}"
    assert re.fullmatch(r"[0-9a-f]{40}", lock["commit"])
    for key in ("sdist", "wheel"):
        assert re.fullmatch(r"[0-9a-f]{64}", lock[key]["sha256"])
        assert lock["version"] in lock[key]["url"]
    assert (MCP / _entry()["lock"]).is_file()


def test_ships_disabled_with_a_placeholder_key_and_untrusted_output():
    entry = _entry()
    assert entry["wrap"] is True
    assert entry["enabled_by_default"] is False
    assert entry["trust"] == "untrusted"
    assert entry["lazy"] is True
    assert entry["timeout"] == 60
    assert entry["env"] == ["VTAI_TOKEN=${VTAI_TOKEN}"]
    assert entry["required_env"] == ["VTAI_TOKEN"]
    assert entry["command"].startswith("<PROFILE_HOME>/mcp/vendor/virustotal-mcp/")


def test_egress_hosts_are_listed():
    hosts = _yaml(MCP / "egress-allowlist.yaml")["connectors"]["virustotal"]
    assert set(hosts["hosts"]) == {"ai.virustotal.com", "www.virustotal.com"}
    assert hosts["allow_ip_literals"] is False
    assert hosts["allow_http_loopback"] is False


@pytest.mark.parametrize(
    "text",
    [
        '{"x-apikey": "abc123"}',
        '{"Authorization": "Bearer abc123"}',
        "x-apikey: abc123",
        "VTAI_TOKEN=abc123",
    ],
)
def test_secret_pattern_catches_json_and_header_forms(text: str):
    assert SECRET.search(text)


@pytest.mark.parametrize("text", ["VTAI_TOKEN=${VTAI_TOKEN}", '"vtai_token": "${VTAI_TOKEN}"'])
def test_secret_pattern_allows_placeholders(text: str):
    assert not SECRET.search(text)


def test_fixtures_hold_no_credential():
    for path in FIXTURES.glob("*"):
        assert not SECRET.search(path.read_text(encoding="utf-8")), path.name


def test_report_fixtures_carry_counts_date_and_permalink():
    for name in ("file_report_known_bad", "domain_report_clean"):
        report = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
        assert report["status"] == "found"
        assert report["analysis_date"]
        assert report["report_url"].startswith("https://www.virustotal.com/gui/")
        stats = report["data"]["last_analysis_stats"]
        assert all(isinstance(count, int) and count >= 0 for count in stats.values())
    bad = json.loads((FIXTURES / "file_report_known_bad.json").read_text(encoding="utf-8"))
    clean = json.loads((FIXTURES / "domain_report_clean.json").read_text(encoding="utf-8"))
    assert bad["data"]["last_analysis_stats"]["malicious"] > 0
    assert clean["data"]["last_analysis_stats"]["malicious"] == 0


def test_error_fixtures_have_the_upstream_error_shape():
    denied = json.loads((FIXTURES / "vt_401.json").read_text(encoding="utf-8"))["error"]
    assert denied["http_status"] == 401
    assert denied["code"] == "access_denied"
    assert denied["retryable"] is False
    limited = json.loads((FIXTURES / "vt_429_quota.json").read_text(encoding="utf-8"))["error"]
    assert limited["http_status"] == 429
    assert limited["retryable"] is True
    assert isinstance(limited["retry_after_seconds"], int)


def test_budget_refuses_the_fifth_call_inside_a_minute(tmp_path: Path):
    budget = _entry()["rate_limit"]
    assert budget == {"per_minute": 4, "per_day": 500}
    now = [0.0]
    limiter = RateLimiter(tmp_path / "limit.sqlite", clock=lambda: now[0], sleeper=lambda s: None)
    rate = budget["per_minute"] / 60
    for _ in range(budget["per_minute"]):
        limiter.acquire("virustotal", rate=rate, burst=budget["per_minute"], timeout=0)
        now[0] += 1
    with pytest.raises(RateLimited):
        limiter.acquire("virustotal", rate=rate, burst=budget["per_minute"], timeout=0)


def test_docs_page_states_terms_and_is_linked_from_the_readme():
    page = (ROOT / "docs" / "connectors" / "virustotal.md").read_text(encoding="utf-8")
    assert "must not be used in commercial products" in page
    assert "enabled: true" in page
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    row = next(line for line in readme.splitlines() if "`virustotal`" in line)
    assert "docs/connectors/virustotal.md" in row
    assert "off:" in row


def test_skill_states_terms_before_use_and_excludes_writes():
    skill = (ROOT / "skills" / "virustotal" / "SKILL.md").read_text(encoding="utf-8")
    assert "must not be used in commercial products" in skill
    assert skill.index("## Terms") < skill.index("## Procedure")
    for name in EXPECTED:
        assert f"mcp__virustotal__{name}" in skill
    assert "Upload, rescan, comment and vote tools are not available" in skill


def test_prose_has_no_em_dash():
    paths = [
        PACKAGE / "SOURCE.md",
        ROOT / "docs" / "connectors" / "virustotal.md",
        ROOT / "skills" / "virustotal" / "SKILL.md",
    ]
    for path in paths:
        assert "—" not in path.read_text(encoding="utf-8"), path.name
