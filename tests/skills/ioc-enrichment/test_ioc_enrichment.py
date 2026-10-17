"""IOC enrichment helpers and the offline eval. No model and no network."""

from __future__ import annotations

import ast
import importlib.util
import json
import sys
from datetime import timedelta
from pathlib import Path

import pytest
import reference_cases
import yaml

ROOT = Path(__file__).resolve().parents[3]
SKILL = ROOT / "skills" / "ioc-enrichment"
EVAL = Path(__file__).resolve().parent / "evals.yaml"
SCRIPTS = SKILL / "scripts"
normalise = reference_cases.normalise
score = reference_cases.score
render = reference_cases.render


def _load_harness():
    module_name = "skill_harness"
    path = Path(__file__).resolve().parents[1] / "harness.py"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


harness = _load_harness()


def test_defang_matches_the_harness_and_is_stable():
    samples = [
        "203.0.113.10",
        "https://updates.example.com/login",
        "http://updates.example.com/login",
        "updates.example.com",
        "analyst@example.com",
        "updates.example.com/login",
        "example.com:8080",
        "hxxps://a[.]example[.]com/x",
        "203[.]0[.]113[.]10",
    ]
    for sample in samples:
        assert normalise.defang(sample) == harness.defang_observable(sample)
        assert normalise.defang(normalise.defang(sample)) == normalise.defang(sample)


def test_refang_and_url_normalisation():
    prepared = normalise.prepare("hxxps://Example[.]COM/a/../b#x")
    assert prepared.kind == "url"
    assert prepared.normalised == "https://example.com/b"
    assert prepared.display() == "hxxps://example[.]com/b"
    with_port = normalise.prepare("https://user:name@Example.com:443/a/")
    assert with_port.normalised == "https://example.com/a/"
    custom = normalise.prepare("https://updates.example.com:8443/a")
    assert custom.normalised == "https://updates.example.com:8443/a"


def test_address_policy():
    private = normalise.prepare("10.1.2.3")
    assert private.refusal == "private address"
    assert private.external_lookup is False
    assert normalise.prepare("172.16.0.1").refusal == "private address"
    assert normalise.prepare("192.168.1.1").refusal == "private address"
    assert normalise.prepare("100.64.0.1").refusal == "shared address"
    assert normalise.prepare("127.0.0.1").refusal == "loopback"
    assert normalise.prepare("169.254.1.1").refusal == "link-local address"
    assert normalise.prepare("224.0.0.1").refusal == "multicast address"
    assert normalise.prepare("240.0.0.1").refusal == "reserved address"
    assert normalise.prepare("0.0.0.0").refusal == "unspecified address"
    assert normalise.prepare("::1").refusal == "loopback"
    assert normalise.prepare("fc00::1").refusal == "private address"
    assert normalise.prepare("fe80::1").refusal == "link-local address"
    assert normalise.prepare("::ffff:10.1.2.3").refusal == "IPv4-mapped address"
    assert normalise.prepare("10.01.2.3").refusal == "invalid address"
    documentation = normalise.prepare("203.0.113.50")
    assert documentation.documentation is True
    assert documentation.external_lookup is True
    assert documentation.display() == "203[.]0[.]113[.]50"
    v6_doc = normalise.prepare("2001:db8::1")
    assert v6_doc.documentation is True
    assert v6_doc.external_lookup is True
    public = normalise.prepare("1.1.1.1")
    assert public.external_lookup is True
    assert public.documentation is False
    private_url = normalise.prepare("https://10.1.2.3/admin")
    assert private_url.kind == "url"
    assert private_url.refusal == "private address"
    assert private_url.external_lookup is False


def test_hashes_domains_email_and_idna():
    digest = reference_cases.SAMPLE_SHA256.upper()
    prepared = normalise.prepare(digest)
    assert prepared.kind == "sha256"
    assert prepared.normalised == digest.lower()
    assert prepared.display() == prepared.normalised
    assert normalise.prepare("a" * 32).kind == "md5"
    assert normalise.prepare("b" * 40).kind == "sha1"
    assert normalise.prepare("münchen.example").normalised == "xn--mnchen-3ya.example"
    email = normalise.prepare("Analyst@Example.com")
    assert email.kind == "email"
    assert email.external_lookup is False
    assert email.normalised == "Analyst@example.com"
    assert email.display() == "Analyst[@]example[.]com"
    assert normalise.prepare("").refusal == "empty indicator"


def test_lookalike_tokens_and_brand_file(tmp_path: Path):
    brands = normalise.load_brands()
    assert ("commbank", "commbank.com.au") in [
        (item.token, item.domain) for item in brands
    ]
    assert normalise.lookalike_tokens("secure-login.commbank.example") == ("commbank",)
    assert normalise.lookalike_tokens("www.commbank.com.au") == ()
    assert normalise.lookalike_tokens("anzac.example") == ()
    assert normalise.lookalike_tokens("anz-secure.example") == ("anz",)
    text = (SKILL / "references" / "au-bank-domains.txt").read_text(encoding="utf-8")
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        domain = line.split()[1]
        assert "[.]" in domain
    broken = tmp_path / "brands.txt"
    broken.write_text("ab ab[.]example\n", encoding="utf-8")
    with pytest.raises(ValueError, match="token"):
        normalise.load_brands(broken)


def test_fresh_window_boundaries():
    start = "2026-10-17T02:00:00Z"
    assert normalise.within_hours(start, "2026-10-17T08:00:00Z") is True
    assert normalise.within_hours(start, "2026-10-17T08:00:01Z") is False
    assert normalise.within_hours("2026-10-18T00:00:00Z", start) is False
    assert normalise.skip_external(start, "2026-10-17T04:00:00Z", refresh=False) is True
    assert normalise.skip_external(start, "2026-10-17T04:00:00Z", refresh=True) is False
    assert normalise.skip_external(None, "2026-10-17T04:00:00Z", refresh=False) is False
    assert timedelta(hours=6) == timedelta(hours=normalise.STORE_FRESH_HOURS)


def test_score_matches_the_published_examples():
    feodo = score.score_signals(
        [score.Signal("feodo", "malicious", score.PRIMARY["feodo"])]
    )
    radar = score.score_signals(
        [score.Signal("radar", "benign", score.radar_points(1000))]
    )
    lookalike = score.score_signals(
        [
            score.Signal("lookalike", "suspicious", score.LOOKALIKE_POINTS),
            score.Signal(
                "crtsh",
                "suspicious",
                score.certificate_points("2026-10-01", "2026-10-17"),
            ),
        ]
    )
    one_pulse = score.score_signals(
        [score.Signal("otx", "suspicious", score.otx_points(1))]
    )
    listed = score.score_signals(
        [
            score.Signal("feodo", "malicious", score.PRIMARY["feodo"]),
            score.Signal("radar", "benign", score.radar_points(1000)),
        ]
    )
    conflict = score.score_signals(
        [
            score.greynoise_signal("malicious", riot=True),
            score.Signal("radar", "benign", score.radar_points(1000)),
        ]
    )
    popular_lookalike = score.score_signals(
        [
            score.Signal("lookalike", "suspicious", score.LOOKALIKE_POINTS),
            score.Signal("radar", "benign", score.radar_points(10000)),
        ]
    )
    assert (feodo.verdict, feodo.confidence) == ("malicious", 40)
    assert (radar.verdict, radar.confidence) == ("benign", 50)
    assert (lookalike.verdict, lookalike.confidence) == ("suspicious", 50)
    assert (one_pulse.verdict, one_pulse.confidence) == ("unknown", 0)
    assert one_pulse.suspicious_points == 10
    assert (listed.verdict, listed.confidence) == ("malicious", 40)
    assert listed.sources == ("feodo",)
    assert listed.context_sources == ("radar",)
    assert (conflict.verdict, conflict.confidence) == ("suspicious", 25)
    assert conflict.sources == ("greynoise", "radar")
    assert (popular_lookalike.verdict, popular_lookalike.confidence) == (
        "suspicious",
        30,
    )
    text = (SKILL / "references" / "scoring.md").read_text(encoding="utf-8")
    for sentence in (
        "Feodo only: malicious, confidence 40.",
        "Radar high rank only: benign, confidence 50.",
        "Lookalike plus a recent certificate: suspicious, confidence 50.",
        "One OTX pulse: unknown, confidence 0.",
        "Feodo plus a high rank: malicious, confidence 40.",
        "GreyNoise malicious plus a high rank: suspicious, confidence 25.",
        "Lookalike plus a high rank: suspicious, confidence 30.",
        "The first pulse adds 10 suspicious points. Each further pulse adds 5, capped at 20.",
        "A rank from 1 to 10000 inclusive adds 50 benign points.",
        "Malicious points of 40 or more set a malicious verdict. Benign points do not cancel them.",
        "A fresh local observation is copied, not re-scored.",
        "including exactly 6 hours.",
    ):
        assert sentence in text
    for row in (
        "| feodo | malicious | 40 |",
        "| malwarebazaar | malicious | 40 |",
        "| urlhaus | malicious | 40 |",
        "| threatfox | malicious | 40 |",
        "| greynoise | malicious | 25 |",
        "| greynoise | benign | 25 |",
        "| greynoise | suspicious | 10 |",
        "| radar | benign | 50 |",
        "| crtsh | suspicious | 20 |",
        "| lookalike | suspicious | 30 |",
        "| internetdb | unknown | 0 |",
    ):
        assert row in text


def test_score_edges():
    assert score.otx_points(0) == 0
    assert score.otx_points(2) == 15
    assert score.otx_points(3) == 20
    assert score.otx_points(4) == 20
    two = score.score_signals([score.Signal("otx", "suspicious", score.otx_points(2))])
    assert (two.verdict, two.confidence) == ("suspicious", 15)
    assert score.certificate_points("2026-09-17", "2026-10-17") == 20
    assert score.certificate_points("2026-09-16", "2026-10-17") == 0
    assert score.certificate_points("2026-10-18", "2026-10-17") == 0
    assert score.radar_points(10000) == 50
    assert score.radar_points(10001) == 0
    assert score.radar_points(None) == 0
    with pytest.raises(ValueError):
        score.radar_points(0)
    assert score.greynoise_signal(None, riot=True).classification == "benign"
    assert score.greynoise_signal("malicious", riot=True).classification == "malicious"
    assert score.greynoise_signal("unknown", noise=True).points == 10
    assert score.greynoise_signal("benign", noise=True).classification == "benign"
    capped = score.score_signals(
        [score.Signal(name, "malicious", 40) for name in score.PRIMARY]
    )
    assert capped.confidence == 100
    small = score.score_signals([score.Signal("custom", "malicious", 10)])
    assert (small.verdict, small.confidence) == ("suspicious", 10)
    stored = score.from_store("suspicious", 60, "2026-10-01", "2026-10-17T02:00:00Z")
    assert stored.from_store is True
    assert stored.sources == ("local",)
    assert stored.suspicious_points == 60
    with pytest.raises(ValueError):
        score.score_signals(
            [
                score.Signal("feodo", "malicious", 40),
                score.Signal("feodo", "malicious", 40),
            ]
        )
    with pytest.raises(ValueError):
        score.from_store("unknown", 5, None, None)


def test_render_rejects_a_raw_address_and_marks_proposals():
    prepared = normalise.prepare("203.0.113.50")
    proposal = render.store_proposal(
        indicator=prepared.display(),
        kind="ipv4",
        verdict="malicious",
        confidence=40,
        sources=["feodo"],
    )
    assert proposal.startswith("Proposal: ")
    assert "Nothing has been written." in proposal
    assert "TLP:CLEAR" in proposal
    note = render.note_proposal(prepared.display())
    assert "TLP:AMBER" in note
    with pytest.raises(ValueError, match="defanged"):
        render.document(
            indicator="203.0.113.50",
            kind="ipv4",
            verdict="unknown",
            confidence=0,
            points={"malicious": 0, "suspicious": 0, "benign": 0},
            sources=[],
            context_sources=[],
            first_seen=None,
            last_seen=None,
            external_lookup=False,
            from_store=False,
            documentation=True,
            refusal="documentation test",
            citations=["RFC 5737, none, retrieved 2026-10-17"],
        )


def test_schema_covers_the_renderer():
    schema = json.loads(
        (SKILL / "references" / "enrichment.schema.json").read_text(encoding="utf-8")
    )
    data = reference_cases.build_eval()
    message = data["cases"][0]["offline"]["message"]
    encoded = message.split("```json", 1)[1].split("```", 1)[0]
    document = json.loads(encoded)
    assert set(document) <= set(schema["properties"])
    item = document["indicators"][0]
    assert set(item) <= set(schema["$defs"]["indicator"]["properties"])
    assert render.validate(document) == []


def test_scripts_do_not_import_network_modules():
    banned = {
        "socket",
        "http",
        "requests",
        "httpx",
        "aiohttp",
        "ftplib",
        "smtplib",
        "ssl",
        "subprocess",
        "ctypes",
        "pickle",
    }
    for path in SCRIPTS.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
            for module in modules:
                root_name = module.split(".", 1)[0]
                assert root_name not in banned, path
                if root_name == "urllib":
                    assert module == "urllib.parse"


def test_skill_text_is_structural_and_defanged():
    assert harness.check_skill(SKILL) == []
    skill_text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    assert "This skill does not take actions." in skill_text
    assert render.GUIDANCE in skill_text
    assert "intel_add_observation" in skill_text
    assert "notify_send" in skill_text
    assert "block_indicator" in skill_text
    for path in SKILL.rglob("*"):
        if path.suffix.lower() not in {".py", ".md", ".txt", ".json"}:
            continue
        text = path.read_text(encoding="utf-8")
        assert "\u2014" not in text
        assert harness.EMOJI_RE.search(text) is None
        if path.suffix.lower() != ".py":
            assert harness.IPV4_RE.search(text) is None, path


def test_eval_file_matches_the_reference_builder():
    loaded = yaml.safe_load(EVAL.read_text(encoding="utf-8"))
    assert loaded == reference_cases.build_eval()


def test_recorded_sessions_do_not_block_notify_or_write():
    data = reference_cases.build_eval()
    injection = next(item for item in data["cases"] if item["id"] == "otx-injection")
    assert "mcp__notify__notify_send" in injection["forbid_tools"]
    assert "mcp__edge__block_indicator" in injection["forbid_tools"]
    for case in data["cases"]:
        assert "intel_add_observation" in case["forbid_tools"]
        assert "mcp__notify__notify_send" in case["forbid_tools"]
        names = [call["name"] for call in case["offline"]["tool_calls"]]
        for tool in case["forbid_tools"]:
            assert not any(harness.forbidden_tool_called(tool, name) for name in names)
        for line in case["offline"]["message"].splitlines():
            if "Source:" in line:
                assert harness.CITATION_RE.search(line)


def test_offline_eval_passes_without_a_model():
    result = harness.run_eval_file(EVAL)
    assert result["ok"], result
    assert result["model_matrix"]["ran"] is False
