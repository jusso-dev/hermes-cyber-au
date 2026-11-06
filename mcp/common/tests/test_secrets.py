"""Secrets stay out of logs, envelopes, cassettes, exports, and rendered config."""

from __future__ import annotations

import io
import json
import logging
import os
import re
from pathlib import Path

import pytest
import yaml
from cyberau_common.audit import redact_text
from cyberau_common.cli import main
from cyberau_common.envelope import envelope
from cyberau_common.http import HttpError
from cyberau_common.secrets import (
    FILTER_HEADERS,
    RedactFilter,
    cassette_findings,
    check_env_mode,
    install_cassette_scrubber,
    redact,
    redact_data,
    redact_headers,
    scrub_cassette,
    secret_values,
)
from cyberau_common.server import Connector, ToolSpec, invoke_tool

ROOT = Path(__file__).resolve().parents[3]
SEEDED = "seeded-fake-key-value"
TICKET_HEADERS = ("Auth-Key", "apiKey", "Authorization", "X-OTX-API-KEY", "key")


def test_redact_covers_ticket_header_names():
    for name in TICKET_HEADERS:
        assert SEEDED not in redact(f"{name}: {SEEDED}")
        assert redact_headers({name: SEEDED})[name] == "[REDACTED]"
    for name in TICKET_HEADERS:
        assert name in FILTER_HEADERS or name.lower() in {item.lower() for item in FILTER_HEADERS}


def test_vcr_filter_headers_match_any_casing(vcr_config):
    from vcr.filters import replace_headers
    from vcr.request import Request

    # Every secret header a connector sends, in the casing it sends it.
    sent = ("X-RFToken", "X-API-KEY", "Api-Key", "api-key", "x-apikey")
    headers = {name: SEEDED for name in TICKET_HEADERS + sent}
    request = Request("GET", "https://example.com/", b"", headers)
    replacements = [(name, None) for name in vcr_config["filter_headers"]]
    assert dict(replace_headers(request, replacements).headers) == {}


def test_envelopes_redact_what_the_audit_log_redacts(monkeypatch, tmp_path):
    empty = tmp_path / "distribution.yaml"
    empty.write_text("env_requires: []\n", encoding="utf-8")
    monkeypatch.setenv("CYBERAU_DISTRIBUTION", str(empty))
    monkeypatch.setenv("UNDECLARED_VENDOR_PASSWORD", SEEDED)
    monkeypatch.setenv("SOME_SERVICE_URL", "https://plain.example/value")
    assert SEEDED in secret_values()
    assert "https://plain.example/value" not in secret_values()
    assert SEEDED not in redact(f"upstream said {SEEDED}")
    assert redact_text(f"upstream said {SEEDED}") == redact(f"upstream said {SEEDED}")


def test_distribution_env_values_are_redacted(monkeypatch):
    monkeypatch.setenv("CYBERAU_DISTRIBUTION", str(ROOT / "distribution.yaml"))
    monkeypatch.setenv("OTX_API_KEY", SEEDED)
    assert SEEDED not in redact(f"upstream said {SEEDED}")


def test_seeded_fake_key_never_leaks(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CYBERAU_DISTRIBUTION", str(ROOT / "distribution.yaml"))
    for name in (
        "ABUSECH_AUTH_KEY",
        "NVD_API_KEY",
        "OTX_API_KEY",
        "CLOUDFLARE_RADAR_API_TOKEN",
        "GREYNOISE_API_KEY",
    ):
        monkeypatch.setenv(name, SEEDED)
    audit = tmp_path / "audit.jsonl"
    monkeypatch.setenv("CYBERAU_AUDIT_LOG", str(audit))

    assert SEEDED not in redact(f"bare {SEEDED} Auth-Key: {SEEDED} ?key={SEEDED}")
    item = envelope(
        "nvd",
        {"apiKey": SEEDED, "note": f"Authorization: Bearer {SEEDED}"},
        cache="miss",
        warnings=(f"X-OTX-API-KEY: {SEEDED}",),
        urls=[f"https://example.com/a?apiKey={SEEDED}"],
    )
    assert SEEDED not in json.dumps(item)

    try:
        raise HttpError(f"key: {SEEDED}")
    except HttpError as exc:
        assert SEEDED not in str(exc)
        assert SEEDED not in repr(exc)

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.addFilter(RedactFilter())
    logger = logging.getLogger("cyberau-secrets-seeded")
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.INFO)
    try:
        raise RuntimeError(f"Authorization: Bearer {SEEDED}")
    except RuntimeError:
        logger.exception("failed")
    logger.info("landed %s", SEEDED)
    assert SEEDED not in stream.getvalue()

    def leak(apiKey: str = ""):
        raise RuntimeError(f"apiKey: {apiKey}")

    result = invoke_tool(
        Connector(key="demo", server_name="demo", attribution="demo", tools=[]),
        ToolSpec("demo_read", "Read.", leak),
        apiKey=SEEDED,
    )
    assert SEEDED not in json.dumps(result)
    stored = audit.read_text(encoding="utf-8")
    assert SEEDED not in stored
    assert audit.stat().st_mode & 0o777 == 0o600

    captured = capsys.readouterr()
    assert SEEDED not in captured.out
    assert SEEDED not in captured.err


def test_doctor_warns_when_env_is_not_mode_600(tmp_path, capsys):
    env = tmp_path / ".env"
    env.write_text(f"NVD_API_KEY={SEEDED}\n", encoding="utf-8")
    os.chmod(env, 0o644)
    warned = check_env_mode(env)
    assert warned["status"] == "warn"
    assert "600" in warned["fix"]
    assert SEEDED not in warned["detail"]
    code = main(["doctor", "--env", str(env)])
    captured = capsys.readouterr()
    assert code == 0
    assert "warn" in captured.out
    assert SEEDED not in captured.out
    assert SEEDED not in captured.err

    os.chmod(env, 0o600)
    assert check_env_mode(env)["status"] == "ok"
    code = main(["doctor", "--env", str(env)])
    captured = capsys.readouterr()
    assert code == 0
    assert "ok" in captured.out
    assert SEEDED not in captured.out
    assert SEEDED not in captured.err


def test_missing_env_file_is_ok(tmp_path):
    assert check_env_mode(tmp_path / ".env")["status"] == "ok"


def test_cassettes_have_placeholder_headers_only():
    assert cassette_findings(ROOT) == []


def test_scrub_leaves_clean_cassette_unchanged(tmp_path):
    source = Path(__file__).parent / "fixtures" / "sample.yaml"
    path = tmp_path / "sample.yaml"
    path.write_bytes(source.read_bytes())
    assert scrub_cassette(path) is False
    assert path.read_bytes() == source.read_bytes()


def test_post_record_scrubber_rewrites_headers(tmp_path):
    cassette = tmp_path / "dirty.yaml"
    dirty = (
        "interactions:\n"
        "- request:\n"
        "    method: GET\n"
        f"    uri: https://example.com/a?apiKey={SEEDED}\n"
        "    headers:\n"
        f"      Authorization: {SEEDED}\n"
        "      Accept: application/json\n"
        "  response:\n"
        "    status:\n"
        "      code: 200\n"
        "    headers:\n"
        "      X-OTX-API-KEY:\n"
        f"      - {SEEDED}\n"
        f"      Auth-Key: {SEEDED}\n"
        f"      key: {SEEDED}\n"
    )

    class _Dummy:
        def use_cassette(self, path, *args, **kwargs):
            class _Manager:
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    Path(path).write_text(dirty, encoding="utf-8")
                    return False

            return _Manager()

    vcr = _Dummy()
    install_cassette_scrubber(vcr)
    with vcr.use_cassette(cassette):
        pass
    text = cassette.read_text(encoding="utf-8")
    assert SEEDED not in text
    loaded = yaml.safe_load(text)
    request = loaded["interactions"][0]["request"]
    assert request["headers"]["Authorization"] == "[REDACTED]"
    assert request["headers"]["Accept"] == "application/json"
    assert "apiKey=[REDACTED]" in request["uri"]
    response_headers = loaded["interactions"][0]["response"]["headers"]
    assert response_headers["X-OTX-API-KEY"] == ["[REDACTED]"]
    assert response_headers["Auth-Key"] == "[REDACTED]"
    assert response_headers["key"] == "[REDACTED]"


@pytest.mark.parametrize(
    "text",
    [
        f"Authorization: Basic {SEEDED}",
        f"Authorization: Token {SEEDED}",
        f"{{'Authorization': 'Bearer {SEEDED}'}}",
        f'{{"apiKey": "{SEEDED}"}}',
        f"{{'X-OTX-API-KEY': '{SEEDED}', 'Accept': 'x'}}",
        f"headers={{'Auth-Key': '{SEEDED}'}}",
        f"GET /a?apiKey={SEEDED} HTTP/1.1",
    ],
)
def test_redact_covers_quoted_and_scheme_forms(text):
    assert SEEDED not in redact(text)


def test_redact_keeps_query_separator():
    assert redact(f"/a?apiKey={SEEDED}&x=1") == "/a?apiKey=[REDACTED]&x=1"


def test_redaction_reaches_child_logger_on_any_handler():
    from cyberau_common.secrets import install_log_redaction

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    root = logging.getLogger()
    root.addHandler(handler)
    install_log_redaction()
    try:
        logging.getLogger("httpx").warning("sent Authorization: Basic %s", SEEDED)
        try:
            raise RuntimeError(f"Auth-Key: {SEEDED}")
        except RuntimeError:
            logging.getLogger("httpx").exception("failed")
    finally:
        root.removeHandler(handler)
    assert SEEDED not in stream.getvalue()


def test_redact_data_keeps_plain_value_types():
    import datetime
    import decimal

    stamp = datetime.datetime(2026, 1, 2, 3, 4, 5)
    cleaned = redact_data({"at": stamp, "n": decimal.Decimal("1.5"), "tags": {"a"}})
    assert cleaned["at"] is stamp
    assert cleaned["n"] == decimal.Decimal("1.5")
    assert cleaned["tags"] == ["a"]


def test_github_token_value_is_redacted(monkeypatch):
    monkeypatch.setenv("CYBERAU_DISTRIBUTION", str(ROOT / "distribution.yaml"))
    monkeypatch.setenv("GITHUB_TOKEN", SEEDED)
    assert SEEDED not in redact(f"GitHub said {SEEDED}")


def test_cassette_scan_covers_cassettes_directories(tmp_path):
    folder = tmp_path / "mcp" / "demo" / "tests" / "cassettes"
    folder.mkdir(parents=True)
    (folder / "dirty.yaml").write_text(
        "interactions:\n- request:\n    headers:\n      Authorization:\n"
        f"      - {SEEDED}\n  response:\n    headers: {{}}\n",
        encoding="utf-8",
    )
    assert cassette_findings(tmp_path)


_PLACEHOLDER = re.compile(r"^\$\{(?:env:)?[A-Za-z_][A-Za-z0-9_]*\}$")
_SECRET_ASSIGN = re.compile(
    r"(?i)\b("
    r"[A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD)"
    r"|authorization|auth-key|x-otx-api-key|x-api-key|x-apikey|x-rftoken|api[_-]?key"
    r")\b\s*[:=]\s*[\"']?(?:(?:bearer|basic|token)\s+)?([^\"'\s#]+)"
)
_TOKEN_SHAPE = re.compile(
    r"AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}|sk-(?:live|test|proj)-[A-Za-z0-9]{10,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
)


def _literal_credentials(text: str) -> list[str]:
    """Line numbers and names of credential assignments that are not ${VAR} placeholders."""
    findings = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        code = raw.split("#", 1)[0]
        if _TOKEN_SHAPE.search(code):
            findings.append(f"{lineno}: token-shaped literal")
        for match in _SECRET_ASSIGN.finditer(code):
            if not _PLACEHOLDER.fullmatch(match.group(2).strip().strip("'\"")):
                findings.append(f"{lineno}: {match.group(1)}")
    return findings


def test_shipped_config_holds_placeholders_only():
    for rel in ("mcp/servers.yaml", "config.yaml"):
        assert _literal_credentials((ROOT / rel).read_text(encoding="utf-8")) == [], rel
    assert _literal_credentials('headers:\n  Authorization: "Bearer ${GITHUB_TOKEN}"\n') == []
    assert _literal_credentials(f"headers:\n  Authorization: Bearer {SEEDED}\n")
    assert _literal_credentials(f"env:\n  NVD_API_KEY: {SEEDED}\n")
