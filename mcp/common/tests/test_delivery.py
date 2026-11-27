"""Briefing delivery: off unless configured, draft first, mock webhook and SMTP stub."""

from __future__ import annotations

import ipaddress
import json
import smtplib
from datetime import datetime
from zoneinfo import ZoneInfo

import httpx
import pytest
from cyberau_common import delivery
from cyberau_common.delivery import DeliveryError, load_destinations, run
from cyberau_common.egress import EgressDenied

NOW = datetime(2026, 10, 20, 7, 31, tzinfo=ZoneInfo("Australia/Sydney"))
SLACK_URL = "https://hooks.slack.com/services/TFAKE0000/BFAKE0000/fakefakefakefakefake"
TEAMS_URL = (
    "https://prod-00.australiaeast.logic.azure.com/workflows/fake/triggers/manual?sig=fakesig"
)
PASSWORD = "fake-smtp-password-not-real"
BRIEFING_OWNER = """# Daily Australian cyber briefing

Window: 24 hours ending 2026-10-20T07:30:00+11:00.
Detail: brief.
Channel: owner.

## Headline

Tuesday 20 October 2026: 1 item needs action today, led by CVE-2099-0101.

## Act today

- CVE-2099-0101 (KEV, added 2026-10-19), rule kev-vendor-product, matches North gateway.

## Sources

- CISA KEV, retrieved 2026-10-20T07:25:00+11:00.

Missing connectors: none.
"""
BRIEFING_EXTERNAL = BRIEFING_OWNER.replace("Channel: owner.", "Channel: external.").replace(
    "matches North gateway.", "matches 1 asset (1 internet-facing)."
)
CONFIG = """owner: origin
destinations:
  - name: soc-slack
    type: slack
    url_env: CYBERAU_SLACK_WEBHOOK
    owner: true
    approved: true
  - name: leaders-teams
    type: teams
    url_env: CYBERAU_TEAMS_WEBHOOK
    approved: false
  - name: soc-email
    type: smtp
    host: smtp.example.com
    port: 587
    from: briefing@example.com
    to: [soc@example.com]
    username_env: CYBERAU_SMTP_USERNAME
    password_env: CYBERAU_SMTP_PASSWORD
    owner: true
    approved: true
"""


def _public(_host):
    return [ipaddress.ip_address("93.184.216.34")]


class FakeSMTP:
    """A local SMTP stub. It records what would be sent and never opens a socket."""

    instances: list[FakeSMTP] = []

    def __init__(self, host, port, *, context):
        self.host = host
        self.port = port
        self.logins = []
        self.messages = []
        self.closed = False
        FakeSMTP.instances.append(self)

    def login(self, username, password):
        self.logins.append((username, password))

    def send_message(self, message):
        self.messages.append(message)

    def quit(self):
        self.closed = True


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CYBERAU_SLACK_WEBHOOK", SLACK_URL)
    monkeypatch.setenv("CYBERAU_TEAMS_WEBHOOK", TEAMS_URL)
    monkeypatch.setenv("CYBERAU_SMTP_USERNAME", "briefing-user")
    monkeypatch.setenv("CYBERAU_SMTP_PASSWORD", PASSWORD)
    (tmp_path / "delivery.yaml").write_text(CONFIG, encoding="utf-8")
    FakeSMTP.instances.clear()
    return tmp_path


def _recorder():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, text="ok")

    return seen, httpx.MockTransport(handler)


def test_delivery_is_off_without_a_file(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    assert load_destinations() == []
    briefing = tmp_path / "brief.md"
    briefing.write_text(BRIEFING_OWNER, encoding="utf-8")
    assert delivery.main([str(briefing), "--send"]) == 0
    out = capsys.readouterr().out
    assert "Delivery is off" in out
    assert not (tmp_path / "delivery").exists()


def test_delivery_is_off_with_no_destinations(tmp_path):
    path = tmp_path / "delivery.yaml"
    path.write_text("owner: origin\n", encoding="utf-8")
    assert load_destinations(path) == []


@pytest.mark.parametrize(
    "body, message",
    [
        ("destinations:\n  - {name: a, type: slack, url: https://hooks.slack.com/x}\n", "url"),
        ("destinations:\n  - {name: a, type: slack, url_env: 'https://x'}\n", "url_env"),
        ("destinations:\n  - {name: a, type: fax, url_env: A_URL}\n", "type"),
        (
            "destinations:\n  - {name: a, type: smtp, host: smtp.example.com, "
            "from: a@example.com, to: b@example.com, password: hunter2hunter2}\n",
            "password",
        ),
        (
            "destinations:\n  - {name: a, type: smtp, host: smtp.example.com, port: 25, "
            "from: a@example.com, to: b@example.com}\n",
            "port",
        ),
        ("destinations:\n  - {name: a, type: slack, url_env: A_URL, approved: 'yes'}\n", "true"),
        (
            "destinations:\n  - {name: a, type: slack, url_env: A_URL}\n"
            "  - {name: a, type: slack, url_env: B_URL}\n",
            "twice",
        ),
    ],
)
def test_bad_config_is_refused(tmp_path, body, message):
    path = tmp_path / "delivery.yaml"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(DeliveryError) as caught:
        load_destinations(path)
    assert message in str(caught.value)
    assert "hunter2" not in str(caught.value)
    assert "hooks.slack.com/x" not in str(caught.value)


def test_dry_run_shows_full_message_and_destination_and_sends_nothing(env, capsys):
    briefing = env / "brief.md"
    briefing.write_text(BRIEFING_OWNER, encoding="utf-8")
    seen, _transport = _recorder()
    assert delivery.main([str(briefing), "--only", "soc-slack", "--only", "soc-email"]) == 0
    out = capsys.readouterr().out
    assert "Destination: soc-slack (slack, https://hooks.slack.com/... from " in out
    assert "CYBERAU_SLACK_WEBHOOK" in out
    assert (
        "Destination: soc-email (smtp, smtp smtp.example.com:587, from briefing@example.com" in out
    )
    assert "to soc@example.com" in out
    assert "Result: draft, dry run, nothing sent." in out
    assert "Dry run. Nothing was sent." in out
    # The whole briefing is shown, with its sources and the untrusted-content note.
    assert BRIEFING_OWNER.strip() in out
    assert "## Sources" in out
    assert "Untrusted content:" in out
    assert "TFAKE0000" not in out
    assert PASSWORD not in out
    assert seen == []
    assert FakeSMTP.instances == []
    drafts = sorted((env / "delivery" / "drafts").glob("*.txt"))
    assert len(drafts) == 2
    for path in drafts:
        assert oct(path.stat().st_mode & 0o777) == "0o600"
        assert "TFAKE0000" not in path.read_text(encoding="utf-8")
    assert not (env / "delivery" / "log.jsonl").exists()


def test_send_posts_only_to_approved_destinations(env):
    seen, transport = _recorder()
    destinations = load_destinations()
    outcomes = run(
        BRIEFING_OWNER,
        destinations,
        send=True,
        now=NOW,
        transport=transport,
        smtp_factory=FakeSMTP,
        resolver=_public,
    )
    status = {item.destination: item.status for item in outcomes}
    # leaders-teams is not an owner channel and the briefing is the owner rendering.
    assert status == {"soc-slack": "sent", "leaders-teams": "blocked", "soc-email": "sent"}
    assert len(seen) == 1
    request = seen[0]
    assert str(request.url) == SLACK_URL
    payload = json.loads(request.content)
    assert "CVE-2099-0101" in payload["text"]
    assert "Untrusted content:" in payload["text"]
    assert payload["unfurl_links"] is False
    stub = FakeSMTP.instances[0]
    assert (stub.host, stub.port) == ("smtp.example.com", 587)
    assert stub.logins == [("briefing-user", PASSWORD)]
    assert stub.closed
    sent = stub.messages[0]
    assert sent["To"] == "soc@example.com"
    assert sent["Subject"] == "Daily Australian cyber briefing, 2026-10-20"
    assert "## Sources" in sent.get_content()
    log = (env / "delivery" / "log.jsonl").read_text(encoding="utf-8")
    assert "TFAKE0000" not in log
    assert PASSWORD not in log
    assert "soc@example.com" not in log
    assert '"host": "hooks.slack.com"' in log


def test_unapproved_destination_is_skipped(env):
    seen, transport = _recorder()
    teams = [item for item in load_destinations() if item.name == "leaders-teams"]
    outcomes = run(BRIEFING_EXTERNAL, teams, send=True, now=NOW, transport=transport)
    assert outcomes[0].status == "skipped"
    assert "approved: true" in outcomes[0].detail
    assert seen == []


def test_external_rendering_goes_to_an_approved_non_owner_teams_target(env, tmp_path):
    path = tmp_path / "teams.yaml"
    path.write_text(
        "destinations:\n  - name: leaders-teams\n    type: teams\n"
        "    url_env: CYBERAU_TEAMS_WEBHOOK\n    approved: true\n",
        encoding="utf-8",
    )
    seen, transport = _recorder()
    outcomes = run(
        BRIEFING_EXTERNAL, load_destinations(path), send=True, now=NOW, transport=transport
    )
    assert outcomes[0].status == "sent"
    card = json.loads(seen[0].content)
    assert card["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"
    text = card["attachments"][0]["content"]["body"][0]["text"]
    assert "matches 1 asset (1 internet-facing)." in text
    assert "North gateway" not in text


def test_webhook_failure_does_not_leak_the_url(env):
    def handler(request):
        raise httpx.ConnectError(f"cannot reach {request.url}")

    slack = [item for item in load_destinations() if item.name == "soc-slack"]
    outcomes = run(
        BRIEFING_OWNER, slack, send=True, now=NOW, transport=httpx.MockTransport(handler)
    )
    assert outcomes[0].status == "failed"
    assert "ConnectError" in outcomes[0].detail
    assert "TFAKE0000" not in outcomes[0].detail
    text = delivery.format_outcomes(outcomes, slack, True)
    assert "TFAKE0000" not in text


def test_webhook_error_status_is_a_failure(env):
    slack = [item for item in load_destinations() if item.name == "soc-slack"]
    transport = httpx.MockTransport(lambda request: httpx.Response(403, text="no"))
    outcomes = run(BRIEFING_OWNER, slack, send=True, now=NOW, transport=transport)
    assert outcomes[0].status == "failed"
    assert outcomes[0].detail == "slack webhook answered 403"


@pytest.mark.parametrize(
    "url, kind",
    [
        ("http://hooks.slack.com/services/x", "slack"),
        ("https://evil.example.com/services/x", "slack"),
        ("https://user:pw@hooks.slack.com/services/x", "slack"),
        ("https://hooks.slack.com/services/x", "teams"),
        ("https://192.0.2.10/workflows/x", "teams"),
        ("https://logic.azure.com.example.com/x", "teams"),
    ],
)
def test_webhook_host_must_pass_egress_rules(env, url, kind):
    with pytest.raises(EgressDenied):
        delivery.webhook_policy(url, kind)


def test_webhook_host_resolving_to_a_private_address_is_refused(env):
    policy = delivery.webhook_policy(
        SLACK_URL, "slack", resolver=lambda host: [ipaddress.ip_address("10.0.0.5")]
    )
    with pytest.raises(EgressDenied):
        policy.connect_addresses("hooks.slack.com")


def test_wrong_host_in_env_is_refused_before_any_request(env, monkeypatch):
    monkeypatch.setenv("CYBERAU_SLACK_WEBHOOK", "https://evil.example.com/hook/secretpath1")
    seen, transport = _recorder()
    slack = [item for item in load_destinations() if item.name == "soc-slack"]
    outcomes = run(BRIEFING_OWNER, slack, send=True, now=NOW, transport=transport)
    assert outcomes[0].status == "failed"
    assert "egress refused" in outcomes[0].detail
    assert "secretpath1" not in outcomes[0].detail
    assert seen == []


def test_smtp_host_on_a_private_address_is_refused(env):
    smtp = [item for item in load_destinations() if item.name == "soc-email"]
    outcomes = run(
        BRIEFING_OWNER,
        smtp,
        send=True,
        now=NOW,
        smtp_factory=FakeSMTP,
        resolver=lambda host: [ipaddress.ip_address("192.168.1.10")],
    )
    assert outcomes[0].status == "failed"
    assert "egress refused" in outcomes[0].detail
    assert FakeSMTP.instances == []


def test_smtp_errors_do_not_leak_the_password(env):
    class Refusing(FakeSMTP):
        def login(self, username, password):
            raise smtplib.SMTPAuthenticationError(535, f"bad password {password}".encode())

    smtp = [item for item in load_destinations() if item.name == "soc-email"]
    outcomes = run(
        BRIEFING_OWNER, smtp, send=True, now=NOW, smtp_factory=Refusing, resolver=_public
    )
    assert outcomes[0].status == "failed"
    assert PASSWORD not in outcomes[0].detail
    assert Refusing.instances[-1].closed


def test_smtp_client_uses_starttls_on_587(monkeypatch):
    calls = []

    class Plain:
        def __init__(self, host, port, timeout):
            calls.append(("open", host, port))

        def ehlo(self):
            calls.append(("ehlo",))

        def starttls(self, context):
            calls.append(("starttls", context is not None))

    monkeypatch.setattr(delivery.smtplib, "SMTP", Plain)
    delivery.smtp_client("smtp.example.com", 587, context=object())
    assert ("starttls", True) in calls
    assert calls[0] == ("open", "smtp.example.com", 587)


def test_secret_shaped_text_in_the_briefing_is_redacted(env):
    leaked = BRIEFING_OWNER.replace("Missing connectors", f"Note {SLACK_URL}\n\nMissing connectors")
    slack = [item for item in load_destinations() if item.name == "soc-slack"]
    outcomes = run(leaked, slack, now=NOW)
    assert "TFAKE0000" not in outcomes[0].message
    assert "[REDACTED]" in outcomes[0].message


def test_briefing_without_sources_is_not_delivered(env):
    slack = [item for item in load_destinations() if item.name == "soc-slack"]
    with pytest.raises(DeliveryError):
        run("# Something else\n\nChannel: owner.\n", slack, now=NOW)


def test_slack_text_escapes_mentions():
    payload = delivery.slack_payload("<!channel> & <https://example.com|x>")
    assert payload["text"] == "&lt;!channel&gt; &amp; &lt;https://example.com|x&gt;"


def test_cli_routes_deliver(env, capsys):
    from cyberau_common.cli import main

    briefing = env / "brief.md"
    briefing.write_text(BRIEFING_OWNER, encoding="utf-8")
    assert main(["deliver", str(briefing), "--only", "soc-slack"]) == 0
    assert "Dry run. Nothing was sent." in capsys.readouterr().out
