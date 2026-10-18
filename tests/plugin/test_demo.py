"""Demo mode: synthetic data that is labelled and never mixed with real intel."""

from __future__ import annotations

import argparse
import importlib.util
import io
import ipaddress
import json
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
PLUGIN_DIR = ROOT / "plugins" / "cyber-au"
EXAMPLES = ROOT / "examples"
FIRST_HOUR = ROOT / "docs" / "getting-started" / "first-hour.md"
README = ROOT / "README.md"
DOC_NETS = [
    ipaddress.ip_network(net) for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
]
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|au)\b", re.IGNORECASE)


def _load_demo():
    if str(PLUGIN_DIR) not in sys.path:
        sys.path.insert(0, str(PLUGIN_DIR))
    name = "cyberau_demo_under_test"
    spec = importlib.util.spec_from_file_location(
        name,
        PLUGIN_DIR / "demo" / "__init__.py",
        submodule_search_locations=[str(PLUGIN_DIR / "demo")],
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


demo = _load_demo()


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    real = tmp_path / "plugin-data" / "cyber-au"
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(real))
    monkeypatch.delenv("HERMES_HOME", raising=False)
    return real


def _run(argv: list[str]) -> tuple[int, str, str]:
    parser = argparse.ArgumentParser(prog="cyber-au")
    demo.add_parser(parser.add_subparsers(dest="command", required=True))
    args = parser.parse_args(["demo", *argv])
    out, err = io.StringIO(), io.StringIO()
    code = demo.dispatch(args, out=out, err=err)
    return code, out.getvalue(), err.getvalue()


# The data is obviously fake


def test_dataset_is_marked_demo_everywhere():
    data = demo.load_dataset()
    assert data["demo"] is True
    assert "DEMO" in data["label"] and "DEMO" in data["source"]["name"]
    for row in data["indicators"]:
        assert "demo" in row["tags"]
        assert row["note"].startswith("DEMO:")
    for row in data["advisories"]:
        assert row["title"].startswith("DEMO")
        assert row["summary"].startswith("DEMO:")
        assert row["url"].startswith("https://example.com/")


def test_dataset_values_are_documentation_values():
    for row in demo.load_dataset()["indicators"]:
        if row["type"] == "ipv4":
            address = ipaddress.ip_address(row["value"])
            assert any(address in net for net in DOC_NETS), row["value"]
        if row["type"] == "domain":
            assert re.search(r"(^|\.)example\.(com|net|org)$", row["value"]), row["value"]


@pytest.mark.parametrize(
    "name",
    ["edr-alert.json", "phishing-email.eml", "iocs.txt", "assets.csv", "incident-timeline.md"],
)
def test_example_files_are_labelled_and_use_reserved_values(name):
    text = (EXAMPLES / name).read_text(encoding="utf-8")
    assert "DEMO DATA" in text
    for value in IPV4.findall(text):
        address = ipaddress.ip_address(value)
        assert any(address in net for net in DOC_NETS), f"{name}: {value}"
    for value in DOMAIN.findall(text):
        host = value.lower()
        assert re.search(r"(^|\.)example\.(com|net|org)$", host), f"{name}: {host}"


def test_examples_ship_with_the_profile():
    manifest = yaml.safe_load((ROOT / "distribution.yaml").read_text(encoding="utf-8"))
    assert "examples" in manifest["distribution_owned"]


# Triage


def test_triage_sample_alert():
    record = demo.triage()
    assert record["demo"] is True
    assert record["severity"] == "P1"
    hostile = {m["value"] for m in record["matches"] if m["verdict"] == "malicious"}
    assert hostile == {
        "203.0.113.45",
        "update.example.net",
        "80a67057fca09654d9e3c87207428bea1ef73ffd9ecd6ffddaf8964ecccc28b7",
    }
    assert [item["id"] for item in record["attack"]] == ["T1071.001"]
    assert record["asset"]["hostname"] == "WS-DEMO-042"


def test_triage_text_is_labelled_demo_first_and_last():
    code, out, err = _run(["triage"])
    assert code == 0, err
    lines = out.strip().splitlines()
    assert lines[0] == demo.BANNER
    assert lines[-1] == demo.FOOTER
    assert "203[.]0[.]113[.]45" in out
    assert "203.0.113.45" not in out
    assert "Source: cyber-au DEMO dataset (synthetic, not real intelligence)" in out
    assert "Proposal:" in out
    for line in lines:
        if line.startswith("Source:") and "DEMO" not in line:
            assert "hermes-cyber-au incident-triage" in line


def test_triage_json_is_marked_demo():
    code, out, _ = _run(["triage", "--json"])
    assert code == 0
    record = json.loads(out)
    assert record["demo"] is True
    assert record["label"].startswith("DEMO DATA")


def test_triage_refuses_a_real_alert(tmp_path):
    real = json.loads((EXAMPLES / "edr-alert.json").read_text(encoding="utf-8"))
    real.pop("demo")
    path = tmp_path / "alert.json"
    path.write_text(json.dumps(real), encoding="utf-8")
    code, out, err = _run(["triage", "--alert", str(path)])
    assert code == 1
    assert out == ""
    assert "not marked" in err and "incident-triage" in err


def test_triage_without_hostile_matches_is_p4(tmp_path):
    alert = {
        "demo": True,
        "alert_id": "DEMO-EDR-0002",
        "category": "scan",
        "host": {"hostname": "WS-DEMO-999"},
        "network": [{"dst_ip": "198.51.100.200", "dst_port": 22}],
    }
    path = tmp_path / "alert.json"
    path.write_text(json.dumps(alert), encoding="utf-8")
    record = demo.triage(path, assets_path=None)
    assert record["severity"] == "P4"
    assert record["matches"] == []
    assert record["attack"] == []


def test_triage_never_touches_a_store(data_dir):
    demo.triage()
    assert not data_dir.exists()


# Separate demo store


def test_load_writes_only_the_demo_store(data_dir):
    summary = demo.load()
    db = Path(summary["path"])
    assert db.name == "intel-demo.sqlite"
    assert db.parent == (data_dir / "demo").resolve()
    assert (db.parent / demo.MARKER_NAME).is_file()
    assert not (data_dir / "intel.sqlite").exists()
    conn = sqlite3.connect(db)
    try:
        sources = {row[0] for row in conn.execute("SELECT id FROM sources")}
        count = conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
    finally:
        conn.close()
    assert sources == {"cyber-au-demo"}
    assert count == len(demo.load_dataset()["indicators"])


def test_load_leaves_an_existing_real_store_alone(data_dir):
    data_dir.mkdir(parents=True)
    real = data_dir / "intel.sqlite"
    real.write_bytes(b"real store placeholder")
    demo.load()
    assert real.read_bytes() == b"real store placeholder"


@pytest.mark.parametrize("where", ["real", "real-store-dir", "unmarked"])
def test_load_refuses_unsafe_targets(data_dir, tmp_path, where):
    if where == "real":
        target = data_dir
    elif where == "real-store-dir":
        target = tmp_path / "other"
        target.mkdir()
        (target / "intel.sqlite").write_bytes(b"")
    else:
        target = tmp_path / "unmarked"
        target.mkdir()
        (target / "notes.txt").write_text("mine", encoding="utf-8")
    code, out, err = _run(["load", "--data-dir", str(target)])
    assert code == 1
    assert out == ""
    assert err


def test_clear_removes_only_a_marked_demo_dir(data_dir, tmp_path):
    demo.load()
    assert demo.clear() is True
    assert not (data_dir / "demo").exists()
    assert demo.clear() is False
    other = tmp_path / "other"
    other.mkdir()
    (other / "keep.txt").write_text("keep", encoding="utf-8")
    with pytest.raises(demo.DemoError):
        demo.clear(other)
    assert (other / "keep.txt").is_file()


# Entry points and prompts


def test_runs_from_a_checkout_with_plain_python():
    result = subprocess.run(
        [sys.executable, "-I", str(PLUGIN_DIR / "demo"), "triage"],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith(demo.BANNER)


def test_plugin_cli_has_demo_command():
    source = (PLUGIN_DIR / "cli.py").read_text(encoding="utf-8")
    assert "demo.add_parser(subs)" in source
    assert 'command == "demo"' in source


def test_prompts_name_real_skills_and_match_the_docs():
    prompts = demo.load_prompts()
    assert len(prompts) == 10
    docs = FIRST_HOUR.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")
    in_readme = 0
    for item in prompts:
        assert (ROOT / "skills" / item["skill"] / "SKILL.md").is_file(), item["skill"]
        assert item["keys"] == "none"
        assert item["prompt"] in docs, item["prompt"]
        assert f"`{item['skill']}`" in docs
        in_readme += item["prompt"] in readme
    assert in_readme >= 5
