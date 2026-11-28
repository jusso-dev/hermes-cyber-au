"""Offline evals for hunt query drafts (issue #169). No model, no network, no SIEM.

Sample advisories in fixtures/hunt/ are synthetic. Each generated query must cite
its source, be marked as an untested draft, and pass the offline syntax checks:
Sigma through pySigma parsing and conversion, KQL and SPL through structural checks
and the bundled schemas.
"""

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
SCRIPTS = ROOT / "skills" / "threat-hunting" / "scripts"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "hunt"
SAMPLES = ("advisory-web-shell.yaml", "cve-loader.yaml")


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


hunt = _load(SCRIPTS / "hunt_queries.py", "threat_hunting_hunt_queries")
checker = _load(SCRIPTS / "check_hunt_pack.py", "threat_hunting_check_hunt_pack")


def _request(name: str) -> dict:
    return yaml.safe_load((FIXTURES / name).read_text(encoding="utf-8"))


def _pack(name: str) -> dict:
    request = _request(name)
    return hunt.generate(
        request["source"],
        iocs=request.get("iocs"),
        techniques=request.get("techniques"),
        lookback=request.get("lookback", "30d"),
    )


@pytest.mark.parametrize("sample", SAMPLES)
def test_sample_advisory_queries_are_valid_and_cited(sample: str):
    pack = _pack(sample)
    assert pack["status"] == "untested draft"
    assert pack["executed"] is False
    assert pack["queries"]
    report = checker.check_pack(pack)
    failures = {item["id"]: item["errors"] for item in report["queries"] if not item["ok"]}
    assert report["ok"], failures or report["problems"]


@pytest.mark.parametrize("sample", SAMPLES)
def test_every_language_is_covered(sample: str):
    languages = {query["language"] for query in _pack(sample)["queries"]}
    assert languages == {"kql_defender", "kql_sentinel", "spl", "sigma"}


def test_every_query_cites_its_origin():
    pack = _pack("advisory-web-shell.yaml")
    advisory = "Source: ASD ACSC advisory 2026-SYN-0042, none, retrieved 2026-11-28"
    for query in pack["queries"]:
        assert query["status"] == "untested draft"
        assert advisory in query["citations"], query["id"]
        assert query["data_sources"] and query["false_positives"]
        for technique in query["based_on"].get("techniques", []):
            assert any(f"MITRE ATT&CK {technique}, v20.1" in line for line in query["citations"])
    cve = _pack("cve-loader.yaml")
    for query in cve["queries"]:
        assert "Source: CVE Program CVE-2026-0001, none, retrieved 2026-11-28" in query["citations"]


def test_kql_queries_cite_the_bundled_schema():
    pack = _pack("advisory-web-shell.yaml")
    for query in pack["queries"]:
        if query["language"].startswith("kql"):
            assert any(line.startswith("Source: Microsoft Learn ") for line in query["citations"])
        if query["language"] == "spl":
            assert any(
                "Splunk Common Information Model, 6.2" in line for line in query["citations"]
            )


def test_sigma_converts_through_pysigma_and_carries_references():
    pack = _pack("advisory-web-shell.yaml")
    rules = [q for q in pack["queries"] if q["language"] == "sigma"]
    assert rules
    for query in rules:
        errors, conversions = checker.check_sigma_rule(query["query"])
        assert not errors, errors
        assert set(conversions) == {"kusto", "splunk"}
        rule = yaml.safe_load(query["query"])
        assert rule["references"] == [
            "https://www.cyber.gov.au/about-us/view-all-content/advisories/synthetic-web-shell-fixture"
        ]
        assert rule["status"] == "experimental"
        assert "draft" in rule["author"]


def test_sigma_rule_ids_are_stable():
    first = [q["query"] for q in _pack("cve-loader.yaml")["queries"] if q["language"] == "sigma"]
    second = [q["query"] for q in _pack("cve-loader.yaml")["queries"] if q["language"] == "sigma"]
    assert first == second


def test_defanged_input_is_refanged_once():
    pack = _pack("advisory-web-shell.yaml")
    text = "\n".join(query["query"] for query in pack["queries"])
    assert '"203.0.113.10"' in text
    assert '"updates.example.com"' in text
    assert "https://web.example.com/shell.aspx?cmd=whoami" in text
    assert "0f343b0931126a20f133d67c2b018a3b5d7e0c7a0e0f1c2d3e4f5a6b7c8d9e0f" in text
    assert "[.]" not in text and "hxxp" not in text
    cve = "\n".join(query["query"] for query in _pack("cve-loader.yaml")["queries"])
    assert '"billing@example.net"' in cve and "[@]" not in cve


def test_hostile_feed_values_never_reach_a_query():
    pack = _pack("hostile-feed.yaml")
    assert pack["queries"] == []
    assert len(pack["rejected"]) == 17
    assert all(item["untrusted"] is True for item in pack["rejected"])
    assert len(pack["invalid_techniques"]) == 2
    assert any("No usable IOC" in warning for warning in pack["warnings"])
    # Rejected values are shown to a person, so they are defanged and stripped of newlines.
    for item in pack["rejected"]:
        assert "\n" not in item["value"]


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("ip", '198.51.100.7") | evaluate http_request("x'),
        ("domain", 'evil.example.com" or 1==1 //'),
        ("domain", "evil.example.com\n| where 1==1"),
        ("url", 'https://x.example.com/a"|delete'),
        ("url", "https://x.example.com/'||'"),
        ("sha256", "a" * 63 + '"'),
        ("email", 'a"b@example.com'),
    ],
)
def test_injection_values_are_refused(kind: str, value: str):
    clean, reason = hunt.normalise_ioc(kind, value)
    assert clean is None
    assert reason


def test_escaping_is_safe_for_any_text():
    nasty = 'a"b\\c'
    assert hunt.kql_string(nasty) == '"a\\"b\\\\c"'
    assert hunt.spl_string(nasty) == '"a\\"b\\\\c"'
    assert hunt.sigma_value("a*b?c\\d") == "a\\*b\\?c\\\\d"
    with pytest.raises(ValueError):
        hunt.spl_string("a*b")
    with pytest.raises(ValueError):
        hunt.kql_string("a\nb")
    # An escaped literal stays one string token for the KQL checker.
    query = (
        "DeviceNetworkEvents\n| where Timestamp > ago(1d)\n"
        f"| where RemoteUrl contains {hunt.kql_string(nasty)}\n| project Timestamp"
    )
    schemas = checker.check_kql.load_schemas(checker.check_kql.schema_dir())
    assert checker.check_kql_query(query, schemas) == []


def test_url_query_characters_survive_escaping_in_every_language():
    pack = hunt.generate(
        {"id": "CVE-2026-0002", "retrieved": "2026-11-28"},
        iocs={"url": ["https://x.example.com/p?q=1&r=(2)"]},
    )
    report = checker.check_pack(pack)
    assert report["ok"], report
    sigma = next(q for q in pack["queries"] if q["language"] == "sigma")
    assert "https://x.example.com/p\\?q=1&r=(2)" in sigma["query"]


def test_checker_rejects_tampered_queries():
    pack = _pack("advisory-web-shell.yaml")
    schemas = checker.check_kql.load_schemas(checker.check_kql.schema_dir())
    cim = yaml.safe_load(
        (ROOT / "skills/threat-hunting/references/splunk-cim.yaml").read_text("utf-8")
    )
    spl = next(q for q in pack["queries"] if q["language"] == "spl")["query"]
    kql = next(q for q in pack["queries"] if q["language"] == "kql_defender")["query"]
    assert checker.check_spl_query(spl + " | outputlookup x.csv", cim)
    assert checker.check_spl_query(spl + ' | sendemail to="a@example.com"', cim)
    assert checker.check_spl_query(spl.replace('"203.0.113.10"', '"203.0.113.10', 1), cim)
    assert checker.check_spl_query(spl.replace("All_Traffic.dest_port", "All_Traffic.bogus"), cim)
    assert checker.check_spl_query(spl.replace("earliest=-30d", ""), cim)
    assert checker.check_kql_query(kql + "\n| evaluate http_request('x')", schemas)
    assert checker.check_kql_query(kql.replace("(", "", 1), schemas)
    assert checker.check_kql_query(kql.replace("DeviceNetworkEvents", "MadeUpTable"), schemas)
    errors, _ = checker.check_sigma_rule("title: x\nlogsource: {}\ndetection: {condition: sel}\n")
    assert errors
    entry = dict(pack["queries"][0])
    entry["citations"] = [
        "Source: Microsoft Learn DeviceNetworkEvents table, none, retrieved 2026-11-28"
    ]
    assert any("does not cite" in e for e in checker.check_entry(entry, schemas, cim)["errors"])
    entry["citations"] = []
    assert checker.check_entry(entry, schemas, cim)["errors"]
    entry = dict(pack["queries"][0])
    entry["status"] = "ready"
    assert checker.check_entry(entry, schemas, cim)["errors"]


def test_templates_reference_only_bundled_tables_and_known_techniques():
    library = hunt.load_templates()
    known = set(library["attack"]["techniques"])
    tables = set(checker.check_kql.load_schemas(checker.check_kql.schema_dir()))
    for template in library["templates"]:
        assert set(template.get("techniques", [])) <= known, template["id"]
        assert bool(template.get("ioc")) != bool(template.get("techniques")), template["id"]
        for language in ("kql_defender", "kql_sentinel"):
            block = template.get(language)
            if block:
                first = re.split(r"[\s,]", block["query"].strip().removeprefix("union "))[0]
                assert first in tables, (template["id"], first)
        for language in hunt.LANGUAGES:
            assert template.get(language) or template.get(f"{language}_unavailable"), (
                template["id"],
                language,
            )
    covered = {template["ioc"] for template in library["templates"] if template.get("ioc")}
    assert covered == set(hunt.IOC_TYPES)


def test_parent_technique_selects_its_sub_techniques_and_unknown_ones_are_listed():
    pack = hunt.generate(
        {"id": "CVE-2026-0003", "retrieved": "2026-11-28"}, techniques=["t1003", "T1999"]
    )
    assert {q["template"] for q in pack["queries"]} == {"lsass-minidump-comsvcs"}
    assert pack["unmapped_techniques"] == ["T1999"]


@pytest.mark.parametrize(
    "source",
    [
        None,
        {},
        {"id": ""},
        {"id": "a b c"},
        {"id": "CVE-2026-0001", "url": "http://x.example.com"},
        {"id": "CVE-2026-0001", "retrieved": "28/11/2026"},
    ],
)
def test_bad_source_is_refused(source):
    with pytest.raises(hunt.HuntInputError):
        hunt.generate(source)


@pytest.mark.parametrize("lookback", ["0d", "366d", "30m", "1d | take 1", 30])
def test_bad_lookback_is_refused(lookback):
    with pytest.raises(hunt.HuntInputError):
        hunt.generate({"id": "CVE-2026-0001", "retrieved": "2026-11-28"}, lookback=lookback)


def test_cli_markdown_and_json(tmp_path: Path):
    script = SCRIPTS / "hunt_queries.py"
    sample = FIXTURES / "advisory-web-shell.yaml"
    text = subprocess.run(
        [sys.executable, str(script), str(sample), "--format", "markdown"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert "Status: untested draft" in text
    assert "Proposal:" in text
    assert "\u2014" not in text
    for line in text.splitlines():
        if "Source:" in line:
            assert re.fullmatch(r"Source: [^,]+, [^,]+, retrieved \d{4}-\d{2}-\d{2}", line), line
    pack_path = tmp_path / "pack.json"
    pack_path.write_text(
        subprocess.run(
            [sys.executable, str(script), str(sample)], check=True, capture_output=True, text=True
        ).stdout,
        encoding="utf-8",
    )
    checked = subprocess.run(
        [sys.executable, str(SCRIPTS / "check_hunt_pack.py"), str(pack_path)],
        capture_output=True,
        text=True,
    )
    assert checked.returncode == 0, checked.stdout
    bad = tmp_path / "bad.yaml"
    bad.write_text("source: {id: 'not valid id!'}\n", encoding="utf-8")
    failed = subprocess.run([sys.executable, str(script), str(bad)], capture_output=True, text=True)
    assert failed.returncode == 2
    assert json.loads(failed.stdout)["queries"] == []


def test_generator_and_checker_never_reach_a_siem():
    for name in ("hunt_queries.py", "check_hunt_pack.py"):
        text = (SCRIPTS / name).read_text(encoding="utf-8")
        for banned in ("subprocess", "urlopen", "http.client", "requests", "httpx", "socket"):
            assert banned not in text, (name, banned)
