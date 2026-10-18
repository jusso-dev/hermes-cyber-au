"""Offline checks for the threat-hunting helpers. No model and no network."""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]
SKILL = ROOT / "skills" / "threat-hunting"
EVALS = ROOT / "tests" / "skills" / "threat-hunting" / "evals.yaml"
SCRIPTS = SKILL / "scripts"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


harness = _load(ROOT / "tests" / "skills" / "harness.py", "threat_hunting_harness")


check_kql = _load(SCRIPTS / "check_kql.py", "threat_hunting_check_kql")
sigma_lint = _load(SCRIPTS / "sigma_lint.py", "threat_hunting_sigma_lint")


POWERSHELL = """
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine contains "-enc"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
"""

WEB_SHELL = """
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath contains "wwwroot"
| where FileName endswith ".aspx"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine
"""

SENTINEL = """
SecurityEvent
| where TimeGenerated > ago(1d)
| where CommandLine contains "-enc"
| project TimeGenerated, AccountName, CommandLine
"""

ENCODED_RULE = """
title: Encoded PowerShell command
id: 11111111-1111-4111-8111-111111111111
status: experimental
author: hermes-cyber-au
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: '-enc'
  condition: selection
level: medium
"""

OFFSET_RULE = """
title: Encoded command with an unconfirmed modifier
id: 33333333-3333-4333-8333-333333333333
author: hermes-cyber-au
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|base64offset|contains: powershell
  condition: selection
"""


def test_skill_passes_the_structural_check():
    assert harness.check_skill(SKILL) == []


def test_offline_eval_passes_without_a_provider_key(monkeypatch: pytest.MonkeyPatch):
    for name in harness.PROVIDER_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("CYBERAU_EVAL_MODELS", raising=False)
    result = harness.run_eval_file(EVALS, live=False)
    assert result["model_matrix"]["ran"] is False
    assert result["ok"], result


def test_helpers_do_not_use_the_network():
    banned = ("urllib", "httpx", "requests", "socket")
    for path in SCRIPTS.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        for name in banned:
            assert name not in text, path.name


def test_powershell_and_file_and_sentinel_queries_are_ready():
    schemas = check_kql.load_schemas(check_kql.schema_dir())
    for query in (POWERSHELL, WEB_SHELL, SENTINEL):
        result = check_kql.check_query(query, schemas)
        assert result["ready"], result["errors"]
        assert result["citations"]


def test_unknown_column_is_not_confirmed_and_not_ready():
    schemas = check_kql.load_schemas(check_kql.schema_dir())
    result = check_kql.check_query(
        "DeviceProcessEvents | where Timestamp > ago(1d) | where EncodedCommand contains 'x'",
        schemas,
    )
    assert result["ready"] is False
    assert any("not confirmed" in item and "EncodedCommand" in item for item in result["errors"])


def test_unknown_table_and_management_commands_are_not_ready():
    schemas = check_kql.load_schemas(check_kql.schema_dir())
    missing = check_kql.check_query("Foo | where Timestamp > ago(1d)", schemas)
    assert missing["ready"] is False
    assert any("no bundled table" in item for item in missing["errors"])
    created = check_kql.check_query(".create table Foo (x:string)", schemas)
    assert created["ready"] is False
    assert any(".create" in item for item in created["errors"])
    external = check_kql.check_query(
        "DeviceProcessEvents | where Timestamp > ago(1d) | join kind=inner "
        'externaldata(x:string)["https://example.com/a"] on x',
        schemas,
    )
    assert external["ready"] is False
    assert any("externaldata" in item for item in external["errors"])


def test_url_in_a_string_does_not_hide_externaldata():
    schemas = check_kql.load_schemas(check_kql.schema_dir())
    result = check_kql.check_query(
        "DeviceProcessEvents\n| where Timestamp > ago(1d)\n"
        '| where ProcessCommandLine has "http://a"'
        ' | join kind=inner externaldata(x:string)["https://example.com/a"] on x',
        schemas,
    )
    assert result["ready"] is False
    assert any("externaldata" in item for item in result["errors"])


@pytest.mark.parametrize(
    "query",
    [
        ".append DeviceProcessEvents <| DeviceProcessEvents | where Timestamp > ago(1d)",
        ".alter table DeviceProcessEvents (Timestamp:datetime)",
        ".purge table DeviceProcessEvents records",
        "DeviceProcessEvents | where Timestamp > ago(1d) | evaluate http_request('https://example.com')",
    ],
)
def test_other_management_commands_and_outbound_plugins_are_not_ready(query: str):
    schemas = check_kql.load_schemas(check_kql.schema_dir())
    result = check_kql.check_query(query, schemas)
    assert result["ready"] is False
    assert any("is not a hunt" in item for item in result["errors"])


def test_column_used_only_as_a_function_argument_is_checked():
    schemas = check_kql.load_schemas(check_kql.schema_dir())
    result = check_kql.check_query(
        "DeviceProcessEvents | where Timestamp > ago(1d) | where isnotempty(FakeColumn)",
        schemas,
    )
    assert result["ready"] is False
    assert any("FakeColumn" in item for item in result["errors"])


def test_aliases_summarize_and_comments_are_not_false_positives():
    schemas = check_kql.load_schemas(check_kql.schema_dir())
    query = """
let lookback = 7d;
DeviceProcessEvents
| where Timestamp >= ago(lookback) // see http://example.com
| where FileName in~ ("powershell.exe", "pwsh.exe")
| extend Short = substring(ProcessCommandLine, 0, 40)
| summarize Hits = count(), Last = max(Timestamp) by DeviceName, bin(Timestamp, 1h)
| project-rename Host = DeviceName
| top 10 by Hits desc
"""
    result = check_kql.check_query(query, schemas)
    assert result["ready"], result["errors"]


def test_query_without_a_time_bound_is_not_ready():
    schemas = check_kql.load_schemas(check_kql.schema_dir())
    result = check_kql.check_query(
        'DeviceProcessEvents | where ProcessCommandLine contains "-enc"',
        schemas,
    )
    assert result["ready"] is False
    assert any("Timestamp" in item for item in result["errors"])


def test_sigma_template_and_encoded_rule_pass_lint():
    support = sigma_lint.load_support(sigma_lint.support_path())
    template = (SKILL / "templates" / "sigma-rule.yml").read_text(encoding="utf-8")
    for text in (template, ENCODED_RULE):
        result = sigma_lint.lint_text(text, support)
        assert result["ok"], result["errors"]
        assert result["kql"] is None
        assert result["conversion"] == "not performed"


def test_base64offset_is_a_graceful_unsupported_modifier():
    support = sigma_lint.load_support(sigma_lint.support_path())
    result = sigma_lint.lint_text(OFFSET_RULE, support)
    assert result["ok"] is False
    assert result["kql"] is None
    assert "base64offset" in result["unsupported"]
    assert any("unsupported" in item and "No KQL was produced" in item for item in result["errors"])
    assert any("not ready" in item for item in result["errors"])


def test_condition_list_is_accepted_and_still_checks_modifiers():
    support = sigma_lint.load_support(sigma_lint.support_path())
    text = OFFSET_RULE.replace("condition: selection", "condition:\n    - selection")
    result = sigma_lint.lint_text(text, support)
    assert not any("condition" in item for item in result["errors"])
    assert "base64offset" in result["unsupported"]


def test_malformed_sigma_yaml_does_not_raise():
    support = sigma_lint.load_support(sigma_lint.support_path())
    result = sigma_lint.lint_text("[\n", support)
    assert result["ok"] is False
    assert result["kql"] is None
    assert any("could not be parsed" in item for item in result["errors"])


def test_rule_without_an_author_is_not_ready():
    support = sigma_lint.load_support(sigma_lint.support_path())
    text = OFFSET_RULE.replace("author: hermes-cyber-au\n", "")
    text = text.replace("CommandLine|base64offset|contains", "CommandLine|contains")
    result = sigma_lint.lint_text(text, support)
    assert result["ok"] is False
    assert any("author" in item for item in result["errors"])


def test_cli_prints_json_and_no_traceback():
    completed = subprocess.run(
        [sys.executable, str(SCRIPTS / "sigma_lint.py")],
        input="[\n",
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 1
    assert "Traceback" not in completed.stderr
    assert "Traceback" not in completed.stdout
    payload = json.loads(completed.stdout)
    assert payload["ok"] is False
    assert payload["kql"] is None


def test_eval_queries_match_the_checker_and_linter():
    schemas = check_kql.load_schemas(check_kql.schema_dir())
    support = sigma_lint.load_support(sigma_lint.support_path())
    loaded = yaml.safe_load(EVALS.read_text(encoding="utf-8"))
    for case in loaded["cases"]:
        message = case["offline"]["message"]
        for query in re.findall(r"```kusto\n(.*?)```", message, re.DOTALL):
            result = check_kql.check_query(query, schemas)
            assert result["ready"], (case["id"], result["errors"])
        for rule in re.findall(r"```yaml\n(.*?)```", message, re.DOTALL):
            result = sigma_lint.lint_text(rule, support)
            assert result["ok"], (case["id"], result["errors"])
        if case["id"] == "unsupported-modifier":
            assert "```kusto" not in message
            assert "base64offset" in message


def test_eval_file_forbids_create_and_run_tools():
    loaded = yaml.safe_load(EVALS.read_text(encoding="utf-8"))
    refused = next(case for case in loaded["cases"] if case["id"] == "refuse-create-or-run")
    assert "mcp__junction__sentinel_create_analytics_rule" in refused["forbid_tools"]
    assert "mcp__junction__sentinel_run_hunt" in refused["forbid_tools"]
    web = next(case for case in loaded["cases"] if case["id"] == "asd-web-shell")
    assert web["replay"][0]["connector"] == "asd-acsc"
    for name in ("mcp__attack__attack_technique", "mcp__sigma__sigma_search"):
        assert name in web["expect_tools"]
        assert name in [call["name"] for call in web["offline"]["tool_calls"]]
    modifier = next(case for case in loaded["cases"] if case["id"] == "unsupported-modifier")
    assert "mcp__sigma__sigma_convert" in modifier["forbid_tools"]
    assert modifier["offline"]["tool_calls"] == []
    assert "untrusted" in web["offline"]["message"]


@pytest.mark.parametrize(
    ("raw", "defanged"),
    [
        ("203.0.113.10", "203[.]0[.]113[.]10"),
        (
            "https://web.example.com/shell.aspx",
            "hxxps://web[.]example[.]com/shell.aspx",
        ),
        ("web.example.com", "web[.]example[.]com"),
    ],
)
def test_defang_examples_match_the_harness(raw: str, defanged: str):
    assert harness.defang_observable(raw) == defanged
