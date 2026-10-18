"""Org exposure watchlist, mocked skill cases, and the paused routine."""

from __future__ import annotations

import importlib.util
import ipaddress
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import httpx
import pytest
import yaml
from cyberau_org_exposure.abn import checksum_ok, data_dir, lookup_names, normalise_abn
from cyberau_org_exposure.cli import main
from cyberau_org_exposure.findings import stored_values
from cyberau_org_exposure.service import (
    Quota,
    clear_registry,
    merge_shipped_jobs,
    register_premium_connector,
    register_ransom_matcher,
    run_exposure_watch,
    run_tool,
    verify_audit,
)
from cyberau_org_exposure.tool import SCHEMA, handle
from cyberau_org_exposure.watchlist import WatchlistError, default_watchlist_path, load_profile

ROOT = Path(__file__).resolve().parents[3]
EVALS = ROOT / "tests" / "skills" / "au-org-exposure" / "evals.yaml"
DOMAIN = "example.com.au"
NOW = datetime(2026, 10, 17, 9, tzinfo=ZoneInfo("Australia/Sydney"))


class Source:
    def __init__(self, vendor, rows, quota=None, enabled=True):
        self.vendor = vendor
        self.rows = rows
        self.quota = quota if quota is not None else Quota()
        self.enabled = enabled
        self.seen = []

    def exposure_for(self, watchlist, since):
        self.seen.append((watchlist, since))
        return self.rows


class Ransom:
    def __init__(self, rows):
        self.rows = rows
        self.seen = []

    def __call__(self, watchlist, days):
        self.seen.append((watchlist, days))
        return self.rows


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("ABR_GUID", raising=False)
    monkeypatch.delenv("HERMES_HOME", raising=False)
    monkeypatch.delenv("CYBERAU_ORG_WATCHLIST", raising=False)
    clear_registry()
    yield tmp_path
    clear_registry()
    # _use() sets this directly, so it would leak into the next test.
    os.environ.pop("CYBERAU_ORG_WATCHLIST", None)


def test_checksum_accepts_only_a_generated_number():
    number = _first_valid_abn()
    assert checksum_ok(number)
    last = "0" if number[-1] != "0" else "1"
    assert not checksum_ok(number[:-1] + last)
    assert not checksum_ok("00000000000")


def test_empty_duplicate_and_bad_abn_do_not_query(env):
    source = Source("fixture", [_infostealer()])
    register_premium_connector(source)
    empty = env / "empty.yaml"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(WatchlistError) as caught:
        load_profile(empty)
    assert caught.value.code == "empty"
    _write(env / "dup.yaml", domains=[DOMAIN, DOMAIN])
    with pytest.raises(WatchlistError) as caught:
        load_profile(env / "dup.yaml")
    assert caught.value.code == "duplicate_domain"
    _write(env / "bad.yaml", abns=["00000000000"])
    with pytest.raises(WatchlistError) as caught:
        load_profile(env / "bad.yaml")
    assert caught.value.code == "abn_checksum"
    _use(env / "bad.yaml")
    result = run_tool({})
    assert source.seen == []
    assert result["data"]["calls"] == 0
    assert result["data"]["sent"] is False


def test_init_does_not_ship_an_organisation(env):
    target = env / "org-exposure.yaml"
    assert main(["watchlist", "init", "--org", "--path", str(target)]) == 0
    text = target.read_text(encoding="utf-8")
    assert not re.search(r"\d{11}", text)
    assert "example." not in text
    assert ".com" not in text
    with pytest.raises(WatchlistError) as caught:
        load_profile(target)
    assert caught.value.code == "empty"
    assert main(["watchlist", "init", "--org", "--path", str(target)]) == 1
    assert main(["watchlist", "init", "--path", str(env / "other.yaml")]) == 2


def test_eval_cases(env, monkeypatch):
    document = yaml.safe_load(EVALS.read_text(encoding="utf-8"))
    ids = [case["id"] for case in document["cases"]]
    assert ids == [
        "no-findings",
        "one-infostealer",
        "excluded-lookalike-leak",
        "third-party",
    ]
    runners = {
        "no-findings": _eval_no_findings,
        "one-infostealer": _eval_infostealer,
        "excluded-lookalike-leak": _eval_lookalike,
        "third-party": _eval_third_party,
    }
    for case in document["cases"]:
        clear_registry()
        runners[case["id"]](env, monkeypatch, case["required"])


def test_leak_claim_is_labelled_unconfirmed_and_not_alerted(env):
    _write(env / "org.yaml", domains=[], brands=["Harbour"])
    _use(env / "org.yaml")
    row = _finding(
        "leak_site_claim",
        "brand",
        "Harbour",
        confidence="unverified_claim",
        actor="Fixture Group",
        observed_at="2026-10-01T01:00:00Z",
        first_seen="2026-10-01T01:00:00Z",
    )
    register_premium_connector(Source("fixture", [row]))
    result = run_tool({"since": "2026-10-01"}, now=NOW)
    line = result["data"]["groups"][0]["findings"][0]["line"]
    assert line == "claimed by Fixture Group on 2026-10-01, not confirmed"
    watched = run_exposure_watch(since="2026-10-01", now=NOW)
    assert watched["new_findings_count"] == 0
    assert watched["quiet"] is True
    assert stored_values() == ["harbour"] or stored_values() == ["Harbour"]


def test_personal_information_adds_the_ndb_note(env):
    _write(env / "org.yaml")
    _use(env / "org.yaml")
    row = _infostealer()
    row["contains_personal_information"] = True
    register_premium_connector(Source("fixture", [row]))
    result = run_tool({}, now=NOW)
    note = result["data"]["ndb"]["note"]
    assert result["data"]["ndb"]["applies"] is True
    assert "Notifiable Data Breaches" in note
    assert "ndb-breach-notification" in note
    assert "not legal advice" in note.lower()
    rendered = json.dumps(result)
    assert "I have notified" not in rendered
    assert "hunter2" not in rendered


def test_outside_watchlist_is_not_stored(env):
    _write(env / "org.yaml", exclude=["example.com"])
    _use(env / "org.yaml")
    outsider = _finding("leak_site_claim", "domain", "example.com", confidence="unverified_claim")
    register_premium_connector(Source("fixture", [_infostealer(), outsider]))
    result = run_tool({}, now=NOW)
    assert stored_values() == [DOMAIN]
    assert result["data"]["dropped_outside_watchlist"] == 1
    values = [group["subject"]["value"] for group in result["data"]["groups"]]
    assert values == [DOMAIN]


def test_secrets_are_not_returned(env):
    _write(env / "org.yaml")
    _use(env / "org.yaml")
    row = _infostealer()
    row["source_ref"] = "password=hunter2"
    register_premium_connector(Source("fixture", [row]))
    result = run_tool({}, now=NOW)
    rendered = json.dumps(result)
    assert "hunter2" not in rendered
    blob = b"".join(path.read_bytes() for path in env.rglob("*") if path.is_file())
    assert b"hunter2" not in blob


def test_session_only_is_not_stored(env):
    _write(env / "org.yaml")
    _use(env / "org.yaml")
    row = _infostealer()
    row["licence_scope"] = "session_only"
    register_premium_connector(Source("fixture", [row]))
    result = run_tool({}, now=NOW)
    assert result["data"]["groups"]
    assert stored_values() == []


def test_abn_expands_to_names_and_digits_are_not_sent(env, monkeypatch):
    number = _first_valid_abn()
    _write(env / "org.yaml", abns=[number], brands=[])
    _use(env / "org.yaml")
    source = Source("fixture", [])
    register_premium_connector(source)

    def lookup(abn):
        assert abn == number
        return ["Registered Fixture", "Fixture Trading"]

    run_tool({}, lookup_fn=lookup, now=NOW)
    watchlist, _since = source.seen[0]
    sent = " ".join((*watchlist.domains, *watchlist.email_domains, *watchlist.brands))
    assert number not in sent
    assert "Registered Fixture" in watchlist.brands
    assert "Fixture Trading" in watchlist.brands
    assert not hasattr(watchlist, "abns")


def test_abr_lookup_uses_the_json_service_and_hides_the_guid(env, monkeypatch):
    number = _first_valid_abn()
    guid = "00000000-0000-0000-0000-000000000000"
    monkeypatch.setenv("ABR_GUID", guid)
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["host"] = request.url.host
        seen["abn"] = request.url.params.get("abn")
        seen["guid_sent"] = request.url.params.get("guid") == guid
        body = (
            'callback({"EntityName":"Registered Fixture","BusinessName":["Fixture Trading"],'
            '"Message":""})'
        )
        return httpx.Response(200, text=body)

    names = lookup_names(
        number,
        transport=httpx.MockTransport(handler),
        resolver=lambda _host: [ipaddress.ip_address("1.1.1.1")],
    )
    assert names == ["Registered Fixture", "Fixture Trading"]
    assert seen["host"] == "abr.business.gov.au"
    assert seen["abn"] == number
    assert seen["guid_sent"] is True
    blob = b"".join(path.read_bytes() for path in env.rglob("*") if path.is_file())
    assert guid.encode() not in blob

    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(str(request.url))

    with pytest.raises(Exception) as caught:
        lookup_names(
            number,
            transport=httpx.MockTransport(fail),
            resolver=lambda _host: [ipaddress.ip_address("1.1.1.1")],
        )
    assert guid not in str(caught.value)


def test_routine_budget_share_blocks_the_second_call(env):
    _write(env / "org.yaml")
    _use(env / "org.yaml")
    source = Source("fixture", [_infostealer()], quota=Quota(calls_per_day=2))
    register_premium_connector(source)
    first = run_exposure_watch(since="2026-10-01", now=NOW)
    second = run_exposure_watch(since="2026-10-01", now=NOW)
    assert len(source.seen) == 1
    assert first["new_findings_count"] == 1
    assert any("calls_per_day" in warning for warning in second["query"]["warnings"])


def test_approval_threshold_skips_the_call(env):
    _write(env / "org.yaml")
    _use(env / "org.yaml")
    source = Source(
        "fixture",
        [_infostealer()],
        quota=Quota(approval_above_units=0.5, cost_units_per_call=1),
    )
    register_premium_connector(source)
    result = run_tool({}, now=NOW)
    assert source.seen == []
    assert any("approval_above_units" in warning for warning in result["warnings"])


def test_routine_alerts_once_and_writes_the_audit_record(env, capsys):
    _write(env / "org.yaml")
    _use(env / "org.yaml")
    register_premium_connector(Source("fixture", [_infostealer()]))
    register_ransom_matcher(Ransom([]))
    (env / "delivery.yaml").write_text("owner: owner-channel\n", encoding="utf-8")
    assert main(["exposure-watch", "--since", "2026-10-01"]) == 0
    first = json.loads(capsys.readouterr().out)
    assert main(["exposure-watch", "--since", "2026-10-01"]) == 0
    second = json.loads(capsys.readouterr().out)
    assert first["new_findings_count"] == 1
    assert first["quiet"] is False
    assert first["deliver_to"] == "owner-channel"
    assert second["new_findings_count"] == 0
    assert second["quiet"] is True
    assert second["deliver_to"] is None
    assert stored_values() == [DOMAIN]
    audit = next((env / "audit").glob("*.jsonl"))
    verify_audit(audit)
    lines = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
    assert [line["new_findings_count"] for line in lines] == [1, 0]
    assert lines[0]["tool"] == "premium-exposure-watch"
    assert "fixture" in lines[0]["vendors_queried"]
    assert "calls" in lines[0]
    assert "cost_units" in lines[0]
    tampered = audit.read_text(encoding="utf-8").replace("fixture", "other", 1)
    audit.write_text(tampered, encoding="utf-8")
    with pytest.raises(ValueError):
        verify_audit(audit)


def test_routine_watchlist_domains_and_brands_are_shared(env):
    _write(env / "org.yaml", brands=["Harbour"])
    _use(env / "org.yaml")
    (env / "watchlists.yaml").write_text(
        "domains:\n  - example.au\nbrands:\n  - Extra Fixture\n",
        encoding="utf-8",
    )
    source = Source("fixture", [])
    register_premium_connector(source)
    run_tool({}, now=NOW)
    watchlist, _since = source.seen[0]
    assert DOMAIN in watchlist.domains
    assert "example.au" in watchlist.domains
    assert "Harbour" in watchlist.brands
    assert "Extra Fixture" in watchlist.brands


def test_shipped_job_arrives_paused_and_a_resume_survives_update():
    shipped = json.loads((ROOT / "cron" / "jobs.json").read_text(encoding="utf-8"))["jobs"]
    job = next(item for item in shipped if item["id"] == "premium-exposure-watch")
    assert job["schedule"] == "every 6h"
    assert job["skills"] == ["au-org-exposure"]
    assert job["deliver"] == "origin"
    assert "Australia/Sydney" in job["prompt"]
    assert "NOTHING" in job["prompt"]
    assert "enabled" not in job
    fresh = merge_shipped_jobs([], shipped, now="2026-10-17T09:00:00+11:00")
    assert fresh[0]["enabled"] is False
    assert fresh[0]["state"] == "paused"
    # A local-only job: its id must not be one the distribution ships.
    assert all(item["id"] != "desk-local-note" for item in shipped)
    existing = [
        {"id": "desk-local-note", "enabled": True, "state": "scheduled", "prompt": "keep"},
        {"id": "premium-exposure-watch", "enabled": True, "state": "scheduled", "prompt": "old"},
    ]
    # The exposure job is already known, so drop it from this local list and add it as new.
    only_other = [existing[0]]
    added = merge_shipped_jobs(only_other, shipped, now="2026-10-17T09:00:00+11:00")
    exposure = next(item for item in added if item["id"] == "premium-exposure-watch")
    other = next(item for item in added if item["id"] == "desk-local-note")
    assert exposure["state"] == "paused"
    assert exposure["enabled"] is False
    assert other["enabled"] is True
    assert other["prompt"] == "keep"
    resumed = merge_shipped_jobs([existing[1]], shipped, now="2026-10-17T09:00:00+11:00")
    assert resumed[0]["enabled"] is True
    assert resumed[0]["state"] == "scheduled"
    assert resumed[0]["prompt"] == job["prompt"]


def test_plugin_registers_the_schema(env):
    # Load the plugin as a package, as Hermes does, under a name no other test uses.
    name = "cyberau_plugin_org_exposure_test"
    plugin_dir = ROOT / "plugins" / "cyber-au"
    spec = importlib.util.spec_from_file_location(
        name, plugin_dir / "__init__.py", submodule_search_locations=[str(plugin_dir)]
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)

        class Ctx:
            """Records tools and ignores the plugin's other registrations."""

            def __init__(self):
                self.tools = {}

            def register_tool(self, name=None, **kwargs):
                self.tools[name] = kwargs

            def __getattr__(self, _attr):
                return lambda *args, **kwargs: None

        ctx = Ctx()
        module.register(ctx)
    finally:
        for loaded in [key for key in sys.modules if key == name or key.startswith(name + ".")]:
            del sys.modules[loaded]
    registered = ctx.tools["cyber_au_org_exposure"]
    assert registered["schema"] is SCHEMA
    # Hermes calls a tool handler with the arguments as one dict plus host keywords.
    payload = json.loads(registered["handler"]({"subject": "example.com.au"}, task_id="t"))
    assert payload["untrusted"] is True
    assert payload["data"]["calls"] == 0
    assert SCHEMA["parameters"]["additionalProperties"] is False
    assert SCHEMA["parameters"]["required"] == []
    assert set(SCHEMA["parameters"]["properties"]) == {"subject", "since", "kinds", "vendors"}
    assert SCHEMA["parameters"]["properties"]["since"]["format"] == "date"


def test_handle_reports_a_missing_watchlist(env):
    payload = json.loads(handle(subject="example.com.au"))
    assert payload["untrusted"] is True
    assert payload["data"]["calls"] == 0


def test_skill_and_shipped_files_omit_the_illustration_abn():
    skill = (ROOT / "skills" / "au-org-exposure" / "SKILL.md").read_text(encoding="utf-8")
    front, body = skill.split("---", 2)[1:]
    meta = yaml.safe_load(front)
    assert meta["metadata"]["hermes"]["related_skills"] == [
        "incident-triage",
        "ndb-breach-notification",
        "executive-briefing",
    ]
    for heading in ("When to Use", "Quick Reference", "Procedure", "Pitfalls", "Verification"):
        assert f"## {heading}" in body
    assert "organisation" in body
    assert "organization" not in body.lower()
    assert "\u2014" not in skill
    assert "\u2013" not in skill
    assert "example.com.au" not in skill
    assert not re.search(r"\d{11}", skill)
    package = ROOT / "mcp" / "org-exposure" / "src"
    for path in package.rglob("*"):
        if path.suffix not in {".py", ".toml", ".yaml", ".json", ".md"}:
            continue
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"\d{11}", text)
        assert "\u2014" not in text


def _eval_no_findings(env, monkeypatch, required):
    source, result = _run_case(env, monkeypatch, _watchlist(), [])
    assert required["vendor_called"] is True
    assert len(source.seen) == 1
    assert result["data"]["calls"] >= 1
    assert len(result["data"]["groups"]) == required["groups"]
    assert stored_values() == []
    rendered = json.dumps(result).lower()
    assert "password" not in rendered


def _eval_infostealer(env, monkeypatch, required):
    source, result = _run_case(env, monkeypatch, _watchlist(), [_infostealer()])
    assert len(source.seen) == 1
    assert len(result["data"]["groups"]) == required["groups"]
    assert result["data"]["groups"][0]["kind"] == required["kind"]
    assert stored_values() == [DOMAIN]
    row = result["data"]["groups"][0]["findings"][0]
    assert row["vendor"] == "fixture"
    assert row["confidence"] == "vendor_reported"
    assert "first seen 2026-10-15" in row["line"]


def _eval_lookalike(env, monkeypatch, required):
    profile = _watchlist(domains=[], brands=["Harbour"], exclude=["Harbour Logistics"])
    row = _finding(
        "leak_site_claim",
        "brand",
        "Harbour Logistics",
        confidence="unverified_claim",
        actor="Fixture Group",
    )
    source, result = _run_case(env, monkeypatch, profile, [row])
    assert len(source.seen) == 1
    sent = source.seen[0][0]
    assert "Harbour Logistics" not in sent.brands
    assert result["data"]["groups"] == []
    assert stored_values() == []
    assert "Harbour Logistics" not in json.dumps(result["data"]["groups"])
    assert required["absent_lookalike"] is True


def _eval_third_party(env, monkeypatch, required):
    source = Source("fixture", [_infostealer()])
    ransom = Ransom([_infostealer()])
    register_premium_connector(source)
    register_ransom_matcher(ransom)
    path = env / "third.yaml"
    _write(path, **_watchlist())
    monkeypatch.setenv("CYBERAU_ORG_WATCHLIST", str(path))
    result = run_tool({"subject": "Other Fixture Org"}, now=NOW)
    assert source.seen == []
    assert ransom.seen == []
    assert result["data"]["sent"] is required["sent"]
    assert result["data"]["confirmation_required"] is required["confirmation_required"]
    assert result["data"]["calls"] == 0
    assert result["data"]["would_send"][0]["vendor"] == "fixture"
    assert "Other Fixture Org" in result["data"]["would_send"][0]["names"]
    assert "Nothing was sent" in result["data"]["message"]
    assert required["discloses_vendor"] is True
    assert stored_values() == []


def test_checksum_rejects_non_ascii_digits():
    number = _first_valid_abn()
    arabic = "".join(chr(0x0660 + int(char)) for char in number)
    fullwidth = "".join(chr(0xFF10 + int(char)) for char in number)
    assert not checksum_ok(arabic)
    assert not checksum_ok(fullwidth)
    assert normalise_abn(arabic) == ""


def test_a_mail_domain_may_repeat_a_web_domain(env):
    _write(env / "org.yaml", domains=[DOMAIN], email_domains=[DOMAIN])
    profile = load_profile(env / "org.yaml")
    assert profile.domains == (DOMAIN,)
    assert profile.email_domains == (DOMAIN,)
    _write(env / "dup.yaml", email_domains=[DOMAIN, DOMAIN])
    with pytest.raises(WatchlistError) as caught:
        load_profile(env / "dup.yaml")
    assert caught.value.code == "duplicate_domain"
    _write(
        env / "sub.yaml",
        subsidiaries=[{"name": "Fixture Services", "domains": [DOMAIN]}],
    )
    with pytest.raises(WatchlistError) as caught:
        load_profile(env / "sub.yaml")
    assert caught.value.code == "duplicate_domain"


def test_state_directory_is_stable_across_processes(monkeypatch, tmp_path):
    monkeypatch.delenv("CYBERAU_DATA_DIR", raising=False)
    monkeypatch.delenv("CYBERAU_ORG_WATCHLIST", raising=False)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    assert data_dir() == tmp_path / "plugin-data" / "cyber-au"
    assert default_watchlist_path() == tmp_path / "watchlists" / "org-exposure.yaml"
    monkeypatch.delenv("HERMES_HOME")
    monkeypatch.setattr(os, "getpid", lambda: 1)
    first = data_dir()
    monkeypatch.setattr(os, "getpid", lambda: 2)
    assert data_dir() == first


def test_a_finding_under_an_abn_registered_name_is_kept(env):
    number = _first_valid_abn()
    _write(env / "org.yaml", abns=[number], domains=[], brands=["Harbour"], exclude=["Skip Me"])
    _use(env / "org.yaml")
    row = _finding("data_leak_disclosure", "brand", "REGISTERED FIXTURE PTY LTD")
    lookalike = _finding("data_leak_disclosure", "brand", "Skip Me", source_ref="fixture-2")
    register_premium_connector(Source("fixture", [row, lookalike]))
    result = run_tool({}, lookup_fn=lambda _abn: ["Registered Fixture Pty Ltd", "Skip Me"], now=NOW)
    groups = result["data"]["groups"]
    assert [group["subject"]["value"] for group in groups] == ["Registered Fixture Pty Ltd"]
    assert result["data"]["dropped_outside_watchlist"] == 1
    assert stored_values() == ["Registered Fixture Pty Ltd"]


def test_the_window_does_not_move_past_a_skipped_or_failed_vendor(env):
    _write(env / "org.yaml")
    _use(env / "org.yaml")
    state = env / "routine_state" / "premium-exposure-watch.json"

    class Broken(Source):
        def exposure_for(self, watchlist, since):
            raise RuntimeError("down")

    register_premium_connector(Broken("broken", []))
    result = run_exposure_watch(now=NOW)
    assert result["query"]["data"]["incomplete"] == ["broken"]
    assert json.loads(state.read_text(encoding="utf-8"))["last_run"] is None
    clear_registry()
    register_premium_connector(Source("fixture", [], quota=Quota(calls_per_day=1)))
    run_exposure_watch(now=NOW)
    assert json.loads(state.read_text(encoding="utf-8"))["last_run"] is None
    clear_registry()
    register_premium_connector(Source("fixture", []))
    run_exposure_watch(now=NOW)
    assert json.loads(state.read_text(encoding="utf-8"))["last_run"] == "2026-10-17"
    _use(env / "missing.yaml")
    later = datetime(2026, 10, 18, 9, tzinfo=ZoneInfo("Australia/Sydney"))
    run_exposure_watch(now=later)
    assert json.loads(state.read_text(encoding="utf-8"))["last_run"] == "2026-10-17"


def _run_case(env, monkeypatch, profile, rows):
    data = env / f"case-{len(list(env.iterdir()))}"
    data.mkdir()
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(data))
    source = Source("fixture", rows)
    register_premium_connector(source)
    register_ransom_matcher(Ransom([]))
    path = data / "case.yaml"
    _write(path, **profile)
    monkeypatch.setenv("CYBERAU_ORG_WATCHLIST", str(path))
    return source, run_tool({"since": "2026-10-01"}, now=NOW)


def _watchlist(**overrides):
    data = {
        "organisation": "Fixture Holder",
        "abns": [],
        "domains": [DOMAIN],
        "email_domains": [],
        "brands": [],
        "subsidiaries": [],
        "exclude": [],
    }
    data.update(overrides)
    return data


def _write(path: Path, **overrides):
    path.write_text(yaml.safe_dump(_watchlist(**overrides)), encoding="utf-8")


def _use(path: Path):
    import os

    os.environ["CYBERAU_ORG_WATCHLIST"] = str(path)


def _infostealer():
    return _finding("infostealer_credential", "domain", DOMAIN)


def _finding(kind, subject_type, value, **extra):
    row = {
        "kind": kind,
        "subject": {"type": subject_type, "value": value},
        "observed_at": extra.pop("observed_at", "2026-10-16T01:00:00Z"),
        "first_seen": extra.pop("first_seen", "2026-10-15T01:00:00Z"),
        "confidence": extra.pop("confidence", "vendor_reported"),
        "licence_scope": extra.pop("licence_scope", "store_metadata"),
        "source_ref": extra.pop("source_ref", "fixture-1"),
        "contains_personal_information": extra.pop("contains_personal_information", False),
    }
    row.update(extra)
    return row


def _first_valid_abn() -> str:
    for number in range(10_000_000_000, 10_000_002_000):
        text = f"{number:011d}"
        if checksum_ok(text):
            return text
    raise AssertionError("no checksum in range")
