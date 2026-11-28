"""Opt-in delivery of the daily briefing to Teams, Slack or email. Draft first.

Destinations live in ``delivery.yaml`` in the profile data directory
(``plugin-data/cyber-au/delivery.yaml``). That file names environment
variables. It never holds a webhook URL, a password or a recipient secret.
With no file, or no ``destinations``, delivery is off.

The default run writes a draft for each destination and prints the full
message and where it would go. Nothing is sent. ``--send`` posts only to a
destination marked ``approved: true``. A destination that is not an owner
channel only takes a briefing rendered with ``--channel external``.

Webhook URLs carry their secret in the path. They are read from the
environment at send time, checked against the egress rules, and never
printed, logged or written. Output names the scheme and host only.
"""

from __future__ import annotations

import hashlib
import json
import re
import smtplib
import ssl
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from email.message import EmailMessage
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

import httpx
import yaml

from cyberau_common import runtime
from cyberau_common.egress import EgressDenied, EgressPolicy, normalise_host
from cyberau_common.secrets import lookup, redact

SYDNEY = ZoneInfo("Australia/Sydney")
FILE_NAME = "delivery.yaml"
KINDS = ("teams", "slack", "smtp")
EGRESS_KEY = "delivery"
# Hosts a webhook may point at, by type. Slack incoming webhooks use one host.
# Teams incoming webhooks are Power Automate workflow URLs (or the older Office
# 365 connector host), which differ per tenant, so they are matched by suffix.
SLACK_HOSTS = frozenset({"hooks.slack.com"})
TEAMS_SUFFIXES = (".logic.azure.com", ".api.powerplatform.com", ".webhook.office.com")
SLACK_LIMIT = 39000
TEAMS_LIMIT = 25000
SMTP_PORTS = (465, 587)
TIMEOUT = 30.0

_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,40}$")
_ENV = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
_HOST = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_CHANNEL = re.compile(r"^Channel: (owner|external)\.$", re.MULTILINE)
_WEBHOOK_KEYS = {"name", "type", "url_env", "approved", "owner"}
_SMTP_KEYS = {
    "name",
    "type",
    "host",
    "port",
    "from",
    "to",
    "username_env",
    "password_env",
    "approved",
    "owner",
}
_TOP_KEYS = {"owner", "destinations"}


class DeliveryError(ValueError):
    """delivery.yaml is unusable, or a destination refused the message. No secrets."""


@dataclass(frozen=True)
class Destination:
    name: str
    kind: str
    approved: bool = False
    owner: bool = False
    url_env: str | None = None
    host: str | None = None
    port: int = 587
    sender: str | None = None
    recipients: tuple[str, ...] = ()
    username_env: str | None = None
    password_env: str | None = None

    def describe(self) -> str:
        where = self.target()
        owner = "yes" if self.owner else "no"
        approved = "yes" if self.approved else "no"
        return f"{self.name} ({self.kind}, {where}, owner channel: {owner}, approved: {approved})"

    def target(self) -> str:
        if self.kind == "smtp":
            to = ", ".join(self.recipients)
            return f"smtp {self.host}:{self.port}, from {self.sender}, to {to}"
        url = lookup(self.url_env or "")
        if url is None:
            return f"webhook URL from {self.url_env} (not set)"
        return f"{mask_url(url)} from {self.url_env}"


@dataclass
class Outcome:
    destination: str
    status: str
    detail: str
    draft: Path | None = None
    message: str = ""
    extra: dict = field(default_factory=dict)


def config_path(path: str | Path | None = None) -> Path:
    if path is not None:
        return Path(path)
    return runtime.profile_data_dir() / FILE_NAME


def load_destinations(path: str | Path | None = None) -> list[Destination]:
    """Read delivery.yaml. A missing file or no destinations means delivery is off."""
    target = config_path(path)
    if not target.is_file():
        return []
    try:
        data = yaml.safe_load(target.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise DeliveryError(f"{FILE_NAME} is not valid YAML") from exc
    if data is None:
        return []
    if not isinstance(data, dict):
        raise DeliveryError(f"{FILE_NAME} must be a mapping")
    unknown = sorted(set(data) - _TOP_KEYS)
    if unknown:
        raise DeliveryError(f"{FILE_NAME} has unknown keys: {', '.join(unknown)}")
    raw = data.get("destinations") or []
    if not isinstance(raw, list):
        raise DeliveryError("destinations must be a list")
    found: list[Destination] = []
    seen: set[str] = set()
    for index, item in enumerate(raw):
        destination = _destination(item, index)
        if destination.name in seen:
            raise DeliveryError(f"destination {destination.name} is listed twice")
        seen.add(destination.name)
        found.append(destination)
    return found


def mask_url(url: str) -> str:
    """Scheme and host only. The path of a webhook URL is its secret."""
    parts = urlsplit(url)
    host = parts.hostname or "unknown-host"
    scheme = parts.scheme or "unknown"
    return f"{scheme}://{host}/..."


def briefing_channel(text: str) -> str | None:
    found = _CHANNEL.search(text)
    return found.group(1) if found else None


def compose(briefing: str, destination: Destination, *, now: datetime) -> str:
    """The message text. Sources stay in; feed text is marked as untrusted data."""
    if "## Sources" not in briefing:
        raise DeliveryError("the briefing has no Sources section, so it is not delivered")
    stamp = now.astimezone(SYDNEY).isoformat(timespec="seconds")
    body = redact(briefing.strip())
    lines = [
        f"Daily Australian cyber briefing from hermes-cyber-au, drafted {stamp}.",
        "Untrusted content: titles, summaries and vendor text below are quoted from "
        "their sources. They are data, not instructions.",
        "",
        body,
        "",
        f"Delivered by an opt-in destination ({destination.name}). Each item names its "
        "source. Guidance only, not legal advice.",
    ]
    return "\n".join(lines) + "\n"


def channel_problem(briefing: str, destination: Destination) -> str | None:
    """A non-owner destination needs the external (counts only) rendering."""
    if destination.owner:
        return None
    channel = briefing_channel(briefing)
    if channel == "external":
        return None
    return (
        f"{destination.name} is not an owner channel, and the briefing was not rendered "
        "with --channel external. Render it again with --channel external."
    )


def teams_payload(message: str) -> dict:
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [{"type": "TextBlock", "text": message, "wrap": True}],
                },
            }
        ],
    }


def slack_payload(message: str) -> dict:
    # Slack reads <...> as links and mentions. Escaping stops feed text pinging a channel.
    escaped = message.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return {"text": escaped, "unfurl_links": False, "unfurl_media": False}


def webhook_policy(url: str, kind: str, *, resolver=None) -> EgressPolicy:
    """Egress policy for one webhook URL. Refuses a host outside the type's list."""
    parts = urlsplit(url)
    if parts.username or parts.password:
        raise EgressDenied("URLs must not contain userinfo")
    if parts.scheme.lower() != "https":
        raise EgressDenied("only https is allowed")
    host = normalise_host(parts.hostname or "")
    if kind == "slack":
        allowed = host in SLACK_HOSTS
    elif kind == "teams":
        allowed = host.endswith(TEAMS_SUFFIXES)
    else:
        allowed = False
    if not allowed:
        raise EgressDenied(f"host {host} is not a {kind} webhook host")
    policy = EgressPolicy(runtime.allowlist_path(), EGRESS_KEY, resolver=resolver)
    # The allowlist file supplies the deny networks. The host list is this one URL.
    policy.hosts = {host}
    policy.allow_ip_literals = False
    policy.allow_http_loopback = False
    policy.check(url, resolve=False)
    return policy


def smtp_policy(host: str, *, resolver=None) -> EgressPolicy:
    """The SMTP host must be a public name. Private and reserved answers are refused."""
    policy = EgressPolicy(runtime.allowlist_path(), EGRESS_KEY, resolver=resolver)
    policy.hosts = {normalise_host(host)}
    policy.allow_ip_literals = False
    policy.allow_http_loopback = False
    policy.check(f"https://{host}/", resolve=True)
    return policy


def post_webhook(destination: Destination, message: str, *, transport=None, resolver=None) -> int:
    url = lookup(destination.url_env or "")
    if url is None:
        raise DeliveryError(f"{destination.url_env} is not set in the profile .env")
    if destination.kind == "slack":
        payload = slack_payload(message)
        if len(payload["text"]) > SLACK_LIMIT:
            raise DeliveryError("message is too long for Slack; render with --detail brief")
    else:
        payload = teams_payload(message)
        if len(json.dumps(payload).encode()) > TEAMS_LIMIT:
            raise DeliveryError("message is too long for Teams; render with --detail brief")
    try:
        policy = webhook_policy(url, destination.kind, resolver=resolver)
    except EgressDenied as exc:
        raise DeliveryError(f"egress refused: {exc}") from None
    mounts = None
    if transport is None:
        from cyberau_common.http import _proxy_mounts, egress_transport

        transport = egress_transport(policy)
        mounts = _proxy_mounts()
    try:
        with httpx.Client(
            transport=transport, mounts=mounts, follow_redirects=False, timeout=TIMEOUT
        ) as client:
            response = client.post(url, json=payload)
    except (httpx.HTTPError, EgressDenied) as exc:
        # The exception text can include the URL. Name the type only.
        raise DeliveryError(f"{destination.kind} post failed ({type(exc).__name__})") from None
    if not 200 <= response.status_code < 300:
        raise DeliveryError(f"{destination.kind} webhook answered {response.status_code}")
    return response.status_code


def smtp_client(host: str, port: int, *, context: ssl.SSLContext):
    """Open an SMTP connection with TLS. Port 465 is implicit TLS; 587 needs STARTTLS."""
    if port == 465:
        return smtplib.SMTP_SSL(host, port, context=context, timeout=TIMEOUT)
    client = smtplib.SMTP(host, port, timeout=TIMEOUT)
    client.ehlo()
    client.starttls(context=context)
    client.ehlo()
    return client


def send_email(
    destination: Destination,
    message: str,
    *,
    subject: str,
    factory: Callable | None = None,
    resolver=None,
) -> str:
    try:
        smtp_policy(destination.host or "", resolver=resolver)
    except EgressDenied as exc:
        raise DeliveryError(f"egress refused: {exc}") from None
    email = EmailMessage()
    email["Subject"] = subject
    email["From"] = destination.sender or ""
    email["To"] = ", ".join(destination.recipients)
    email.set_content(message)
    username = lookup(destination.username_env) if destination.username_env else None
    password = lookup(destination.password_env) if destination.password_env else None
    if destination.username_env and username is None:
        raise DeliveryError(f"{destination.username_env} is not set in the profile .env")
    if destination.password_env and password is None:
        raise DeliveryError(f"{destination.password_env} is not set in the profile .env")
    opener = factory or smtp_client
    context = ssl.create_default_context()
    try:
        client = opener(destination.host, destination.port, context=context)
        try:
            if username is not None and password is not None:
                client.login(username, password)
            client.send_message(email)
        finally:
            client.quit()
    except (smtplib.SMTPException, OSError) as exc:
        raise DeliveryError(f"smtp send failed ({type(exc).__name__})") from None
    return "accepted"


def run(
    briefing: str,
    destinations: list[Destination],
    *,
    send: bool = False,
    only: list[str] | None = None,
    now: datetime | None = None,
    draft_dir: Path | None = None,
    transport=None,
    smtp_factory: Callable | None = None,
    resolver=None,
) -> list[Outcome]:
    """Draft every chosen destination. With ``send``, deliver to the approved ones."""
    moment = now or datetime.now(SYDNEY)
    chosen = destinations
    if only:
        names = {item.name for item in destinations}
        unknown = sorted(set(only) - names)
        if unknown:
            raise DeliveryError(f"unknown destination: {', '.join(unknown)}")
        chosen = [item for item in destinations if item.name in set(only)]
    folder = draft_dir or (runtime.profile_data_dir() / "delivery" / "drafts")
    secrets = _configured_secrets(destinations)
    outcomes: list[Outcome] = []
    for destination in chosen:
        message = _scrub(compose(briefing, destination, now=moment), secrets)
        draft = _write_draft(folder, destination, message, moment)
        problem = channel_problem(briefing, destination)
        if problem:
            outcomes.append(Outcome(destination.name, "blocked", problem, draft, message))
            continue
        if not send:
            outcomes.append(
                Outcome(destination.name, "draft", "dry run, nothing sent", draft, message)
            )
            continue
        if not destination.approved:
            detail = "not approved; set approved: true for it in delivery.yaml"
            outcomes.append(Outcome(destination.name, "skipped", detail, draft, message))
            continue
        try:
            if destination.kind == "smtp":
                detail = send_email(
                    destination,
                    message,
                    subject=_subject(moment),
                    factory=smtp_factory,
                    resolver=resolver,
                )
            else:
                code = post_webhook(destination, message, transport=transport, resolver=resolver)
                detail = f"status {code}"
        except DeliveryError as exc:
            reason = _scrub(str(exc), secrets)
            outcomes.append(Outcome(destination.name, "failed", reason, draft, message))
            _log(folder.parent, destination, "failed", message, moment)
            continue
        outcomes.append(Outcome(destination.name, "sent", detail, draft, message))
        _log(folder.parent, destination, "sent", message, moment)
    return outcomes


def format_outcomes(outcomes: list[Outcome], destinations: list[Destination], send: bool) -> str:
    by_name = {item.name: item for item in destinations}
    lines: list[str] = []
    for outcome in outcomes:
        destination = by_name[outcome.destination]
        lines.append(f"Destination: {destination.describe()}")
        lines.append(f"Result: {outcome.status}, {outcome.detail}.")
        if outcome.draft is not None:
            lines.append(f"Draft: {outcome.draft}")
        if not send or outcome.status != "sent":
            lines.append("----- message -----")
            lines.append(outcome.message.rstrip("\n"))
            lines.append("----- end -----")
        lines.append("")
    if not send:
        lines.append("Dry run. Nothing was sent. Add --send to deliver to approved destinations.")
    return "\n".join(lines).rstrip("\n") + "\n"


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="cyberau-mcp deliver",
        description="Draft the daily briefing for each destination in delivery.yaml. "
        "Nothing is sent without --send and approved: true.",
    )
    parser.add_argument("briefing", help="Rendered briefing file, or - for stdin")
    parser.add_argument("--config", help="delivery.yaml path (default: profile data dir)")
    parser.add_argument("--only", action="append", help="Limit to this destination name")
    parser.add_argument("--send", action="store_true", help="Send to approved destinations")
    args = parser.parse_args(argv)
    try:
        destinations = load_destinations(args.config)
    except DeliveryError as exc:
        print(f"delivery failed: {exc}", file=sys.stderr)
        return 2
    if not destinations:
        print(f"Delivery is off: no destinations in {config_path(args.config)}. Nothing sent.")
        return 0
    try:
        text = (
            sys.stdin.read()
            if args.briefing == "-"
            else Path(args.briefing).read_text(encoding="utf-8")
        )
        outcomes = run(text, destinations, send=args.send, only=args.only)
    except (OSError, DeliveryError) as exc:
        print(f"delivery failed: {redact(str(exc))}", file=sys.stderr)
        return 2
    sys.stdout.write(format_outcomes(outcomes, destinations, args.send))
    if args.send and any(item.status in {"failed", "blocked"} for item in outcomes):
        return 1
    return 0


def _destination(item, index: int) -> Destination:
    where = f"destinations[{index}]"
    if not isinstance(item, dict):
        raise DeliveryError(f"{where} must be a mapping")
    kind = item.get("type")
    if kind not in KINDS:
        raise DeliveryError(f"{where} type must be teams, slack or smtp")
    allowed = _SMTP_KEYS if kind == "smtp" else _WEBHOOK_KEYS
    unknown = sorted(set(item) - allowed)
    if unknown:
        # A literal url, password or token key is refused here, so it cannot sit in the file.
        raise DeliveryError(f"{where} has unknown keys: {', '.join(unknown)}")
    name = item.get("name")
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise DeliveryError(f"{where} name must be lower case letters, digits, - or _")
    approved = item.get("approved", False)
    owner = item.get("owner", False)
    if not isinstance(approved, bool) or not isinstance(owner, bool):
        raise DeliveryError(f"{where} approved and owner must be true or false")
    if kind != "smtp":
        return Destination(
            name=name,
            kind=kind,
            approved=approved,
            owner=owner,
            url_env=_env_name(item.get("url_env"), f"{where} url_env", required=True),
        )
    host = item.get("host")
    if not isinstance(host, str) or not _HOST.fullmatch(host):
        raise DeliveryError(f"{where} host must be a host name")
    port = item.get("port", 587)
    if port not in SMTP_PORTS or isinstance(port, bool):
        raise DeliveryError(f"{where} port must be 465 (TLS) or 587 (STARTTLS)")
    sender = _address(item.get("from"), f"{where} from")
    raw_to = item.get("to")
    recipients = [raw_to] if isinstance(raw_to, str) else raw_to
    if not isinstance(recipients, list) or not recipients:
        raise DeliveryError(f"{where} to must be an address or a list of addresses")
    to = tuple(_address(value, f"{where} to") for value in recipients)
    username_env = _env_name(item.get("username_env"), f"{where} username_env", required=False)
    password_env = _env_name(item.get("password_env"), f"{where} password_env", required=False)
    if bool(username_env) != bool(password_env):
        raise DeliveryError(f"{where} needs both username_env and password_env, or neither")
    return Destination(
        name=name,
        kind=kind,
        approved=approved,
        owner=owner,
        host=host,
        port=int(port),
        sender=sender,
        recipients=to,
        username_env=username_env,
        password_env=password_env,
    )


def _env_name(value, where: str, *, required: bool) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or not _ENV.fullmatch(value):
        raise DeliveryError(f"{where} must name an environment variable, not hold a value")
    return value


def _address(value, where: str) -> str:
    if not isinstance(value, str):
        raise DeliveryError(f"{where} must be an email address")
    _, address = parseaddr(value)
    if not address or "@" not in address or any(ch.isspace() for ch in address):
        raise DeliveryError(f"{where} must be an email address")
    return value.strip()


def _configured_secrets(destinations: list[Destination]) -> list[str]:
    """Values of the webhook URL and password variables. A URL name ending in _URL is not
    treated as a secret by the shared redactor, so delivery scrubs these itself."""
    found = []
    for item in destinations:
        for name in (item.url_env, item.password_env):
            value = lookup(name) if name else None
            if value and len(value) >= 8:
                found.append(value)
    return sorted(found, key=len, reverse=True)


def _scrub(text: str, secrets: list[str]) -> str:
    for value in secrets:
        text = text.replace(value, "[REDACTED]")
    return text


def _subject(moment: datetime) -> str:
    local = moment.astimezone(SYDNEY)
    return f"Daily Australian cyber briefing, {local.date().isoformat()}"


def _write_draft(folder: Path, destination: Destination, message: str, moment: datetime) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    stamp = moment.astimezone(SYDNEY).strftime("%Y%m%dT%H%M%S")
    path = folder / f"{stamp}-{destination.name}.txt"
    path.write_text(message, encoding="utf-8")
    path.chmod(0o600)
    return path


def _log(folder: Path, destination: Destination, status: str, message: str, moment) -> None:
    """One line per send attempt: no URL path, no address, no secret."""
    folder.mkdir(parents=True, exist_ok=True)
    host = destination.host
    if destination.kind != "smtp":
        url = lookup(destination.url_env or "") or ""
        host = urlsplit(url).hostname or ""
    record = {
        "at": moment.astimezone(SYDNEY).isoformat(timespec="seconds"),
        "destination": destination.name,
        "type": destination.kind,
        "host": host,
        "status": status,
        "sha256": hashlib.sha256(message.encode()).hexdigest(),
    }
    with (folder / "log.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
