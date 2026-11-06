"""Environment lookup and redaction. Secret values are never logged or exported."""

from __future__ import annotations

import datetime
import decimal
import json
import logging
import os
import re
import uuid
from pathlib import Path

import yaml

# Header names the secrets ticket requires, plus the spellings connectors send.
SECRET_HEADER_NAMES = frozenset(
    {
        "authorization",
        "auth-key",
        "x-otx-api-key",
        "x-api-key",
        "x-apikey",
        "api-key",
        "apikey",
        "api_key",
        "key",
        "x-rftoken",
    }
)

# vcrpy matches filter_headers against a case-insensitive header map.
FILTER_HEADERS = tuple(sorted(SECRET_HEADER_NAMES))
_HEADER_NAMES = "|".join(
    re.escape(name) for name in sorted(SECRET_HEADER_NAMES, key=len, reverse=True)
)

_PLACEHOLDER = re.compile(r"^\$\{(?:env:)?[A-Za-z_][A-Za-z0-9_]*\}$")
_QUERY_RE = re.compile(r"(?i)([?&](?:api[_-]?key|token|auth|key|access_token)=)([^&\s]+)")
_BEARER_RE = re.compile(r"(?i)\bBearer\s+\S+")
_HEADER_RE = re.compile(
    r"(?i)(?<![?&])(?P<head>[\"']?\b"
    rf"(?P<name>{_HEADER_NAMES})"
    r"\b[\"']?\s*[:=]\s*[\"']?)"
    r"(?P<value>(?:(?:bearer|basic|token|digest)\s+)?[^\"'\s,}&]+)"
)
# An environment variable with one of these in its name holds a credential,
# whether or not distribution.yaml declares it.
_SECRET_ENV = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|PASSWD)", re.IGNORECASE)
_NAME_CACHE: tuple[str, float, tuple[str, ...]] | None = None
_VALUE_CACHE: tuple[tuple, tuple[str, ...]] | None = None
# Values shorter than this collide with ordinary words, so they are not
# substituted globally. Header patterns still cover them.
_MIN_SECRET_LEN = 8
_PLAIN_TYPES = (datetime.date, datetime.time, decimal.Decimal, uuid.UUID)
_PLACEHOLDER_VALUES = {"", "[REDACTED]", "XXXX"}


def lookup(name: str) -> str | None:
    """Return an environment value, or None when it is missing or blank."""
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return None
    return value


# Names in distribution.yaml that configure a connector but carry no credential.
# Their values are ordinary identifiers and addresses, so they must reach tool
# answers. Redacting them would blank the collection id, or any other row field
# that happens to match.
_PLAIN_CONFIG_SUFFIXES = ("_URL", "_BASE_URL", "_API_ROOT", "_COLLECTION_ID")


def is_plain_config_name(name: str) -> bool:
    """True for a distribution env name that holds configuration, not a secret."""
    return name.upper().endswith(_PLAIN_CONFIG_SUFFIXES)


def distribution_env_names(path: Path | None = None) -> tuple[str, ...]:
    """Names declared in distribution.yaml. Values are not read."""
    global _NAME_CACHE
    found = path or _distribution_path()
    if found is None:
        return ()
    try:
        mtime = found.stat().st_mtime
        if _NAME_CACHE and _NAME_CACHE[0] == str(found) and _NAME_CACHE[1] == mtime:
            return _NAME_CACHE[2]
        data = yaml.safe_load(found.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return ()
    names: list[str] = []
    for item in (data.get("env_requires") if isinstance(data, dict) else None) or []:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if isinstance(name, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            names.append(name)
    loaded = tuple(names)
    _NAME_CACHE = (str(found), mtime, loaded)
    return loaded


def secret_values() -> tuple[str, ...]:
    """Environment values that must never be logged, returned or exported, longest first.

    A value counts when its name is declared in distribution.yaml (other than a
    plain configuration name such as a URL) or looks like a credential name.
    """
    global _VALUE_CACHE
    declared = distribution_env_names()
    environ = tuple(os.environ.items())
    if _VALUE_CACHE is not None and _VALUE_CACHE[0] == (declared, environ):
        return _VALUE_CACHE[1]
    found: set[str] = set()
    for name, value in environ:
        credential = _SECRET_ENV.search(name) is not None
        if not credential and (name not in declared or is_plain_config_name(name)):
            continue
        if len(value) < _MIN_SECRET_LEN or value in _PLACEHOLDER_VALUES:
            continue
        if value.startswith("${") and value.endswith("}"):
            continue
        found.add(value)
    values = tuple(sorted(found, key=len, reverse=True))
    _VALUE_CACHE = ((declared, environ), values)
    return values


def redact(text: str) -> str:
    """Replace secret-shaped header, query, and known env values with a marker."""
    rendered = text if isinstance(text, str) else str(text)
    for secret in secret_values():
        if secret in rendered:
            rendered = rendered.replace(secret, "[REDACTED]")
    rendered = _QUERY_RE.sub(_query_sub, rendered)
    rendered = _HEADER_RE.sub(_header_sub, rendered)
    rendered = _BEARER_RE.sub("Bearer [REDACTED]", rendered)
    return rendered


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    cleaned: dict[str, str] = {}
    for key, value in headers.items():
        if str(key).lower() in SECRET_HEADER_NAMES:
            cleaned[key] = "[REDACTED]"
        else:
            cleaned[key] = value
    return cleaned


def redact_data(value):
    """Walk envelopes and audit records. Secret field names lose their values."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            # A number or flag under a secret-looking field name is a count or a
            # switch (for example a tally of "authorization" rows), not a credential.
            if (
                isinstance(key, str)
                and key.lower() in SECRET_HEADER_NAMES
                and not isinstance(item, (int, float, bool, type(None)))
            ):
                cleaned[key] = "[REDACTED]"
            else:
                cleaned[key] = redact_data(item)
        return cleaned
    if isinstance(value, list | tuple):
        return [redact_data(item) for item in value]
    if isinstance(value, set | frozenset):
        return [redact_data(item) for item in value]
    if isinstance(value, bytes | bytearray):
        return redact(bytes(value).decode("utf-8", "replace"))
    if value is None or isinstance(value, (int, float, bool, *_PLAIN_TYPES)):
        return value
    return redact(repr(value))


def _scrub_record(record: logging.LogRecord) -> None:
    try:
        record.msg = redact(record.getMessage())
        record.args = ()
    except (TypeError, ValueError):
        # Bad format arguments: keep the error for the handler, but not the secret.
        record.msg = redact(str(record.msg))
        record.args = (
            redact_data(record.args)
            if isinstance(record.args, dict)
            else tuple(redact_data(item) for item in record.args or ())
        )
    if record.exc_info:
        record.exc_text = redact(logging.Formatter().formatException(record.exc_info))
        record.exc_info = None
    elif record.exc_text:
        record.exc_text = redact(record.exc_text)


class RedactFilter(logging.Filter):
    """Logging filter that rewrites the rendered message and traceback."""

    def filter(self, record: logging.LogRecord) -> bool:
        _scrub_record(record)
        return True


def install_log_redaction() -> None:
    """Redact every log record, whichever logger or handler emits it.

    A filter on the root logger only sees records logged on the root itself, so
    the scrub also runs when the record is created.
    """
    root = logging.getLogger()
    if not any(isinstance(existing, RedactFilter) for existing in root.filters):
        root.addFilter(RedactFilter())
    factory = logging.getLogRecordFactory()
    if getattr(factory, "_cyberau_redacting", False):
        return

    def make_record(*args, **kwargs):
        record = factory(*args, **kwargs)
        _scrub_record(record)
        return record

    make_record._cyberau_redacting = True
    logging.setLogRecordFactory(make_record)


def append_audit(path: Path, record: dict) -> None:
    """Append one redacted audit record. The file is created mode 600."""
    redacted = redact_data(record)
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(redacted, sort_keys=True, separators=(",", ":")) + "\n"
    descriptor = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        os.write(descriptor, line.encode("utf-8"))
    finally:
        os.close(descriptor)
    try:
        os.chmod(path, 0o600)
    except OSError:
        return


def record_tool_audit(tool: str, args: tuple, kwargs: dict, error: str | None) -> None:
    """Write a redacted tool event when CYBERAU_AUDIT_LOG is set."""
    dest = os.environ.get("CYBERAU_AUDIT_LOG")
    if not dest:
        return
    append_audit(
        Path(dest),
        {
            "event": "tool_error" if error else "tool_call",
            "tool": tool,
            "args_redacted": {"args": list(args), "kwargs": kwargs},
            "error": error,
        },
    )


def check_env_mode(path: Path) -> dict[str, str]:
    """Warn when .env is not mode 600. The file contents are never read."""
    if not path.exists():
        return {"id": "env_mode", "status": "ok", "detail": "no .env file", "fix": ""}
    if not path.is_file():
        return {
            "id": "env_mode",
            "status": "warn",
            "detail": ".env is not a file",
            "fix": "chmod 600 .env",
        }
    mode = path.stat().st_mode & 0o777
    if mode == 0o600:
        return {"id": "env_mode", "status": "ok", "detail": ".env is mode 600", "fix": ""}
    return {
        "id": "env_mode",
        "status": "warn",
        "detail": f".env permissions are {mode:03o}",
        "fix": "chmod 600 .env",
    }


def format_doctor(result: dict[str, str]) -> str:
    lines = [f"{result['id']} {result['status']} {result['detail']}"]
    if result.get("fix"):
        lines.append(f"fix: {result['fix']}")
    return "\n".join(lines)


def scrub_uri(uri: str) -> str:
    def replace(match: re.Match[str]) -> str:
        value = match.group(2)
        if _is_placeholder_header(value):
            return match.group(0)
        return match.group(1) + "[REDACTED]"

    return _QUERY_RE.sub(replace, uri)


def scrub_cassette(path: Path) -> bool:
    """Rewrite a recorded cassette so secret headers are placeholders.

    Clean cassettes are left untouched. Returns True when the file changed.
    """
    if not path.is_file():
        return False
    original = path.read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(original)
    except yaml.YAMLError:
        return False
    if not isinstance(data, dict) or not isinstance(data.get("interactions"), list):
        return False
    changed = False
    for interaction in data["interactions"]:
        if not isinstance(interaction, dict):
            continue
        for side in ("request", "response"):
            block = interaction.get(side)
            if isinstance(block, dict) and _scrub_block(block):
                changed = True
    if not changed:
        return False
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return True


def cassette_findings(root: Path) -> list[str]:
    """List cassette headers whose values are not placeholders."""
    findings: list[str] = []
    base = root / "mcp"
    paths = list(base.rglob("*.yaml")) + list(base.rglob("*.yml"))
    for path in sorted(paths):
        if ".venv" in path.parts or not {"fixtures", "cassettes"} & set(path.parts):
            continue
        findings.extend(_cassette_file_findings(path))
    return findings


def install_cassette_scrubber(vcr) -> None:
    """Scrub secret headers before a cassette is written, and again after."""
    if getattr(vcr, "_cyberau_scrubber", False):
        return
    vcr._cyberau_scrubber = True
    previous_request = getattr(vcr, "before_record_request", None)
    previous_response = getattr(vcr, "before_record_response", None)

    def before_record_request(request):
        if previous_request:
            request = previous_request(request)
        headers = getattr(request, "headers", None)
        if headers is not None:
            for name in list(headers):
                if str(name).lower() in SECRET_HEADER_NAMES:
                    headers[name] = "[REDACTED]"
        uri = getattr(request, "uri", None)
        if isinstance(uri, str):
            request.uri = scrub_uri(uri)
        return request

    def before_record_response(response):
        if previous_response:
            response = previous_response(response)
        if isinstance(response, dict) and isinstance(response.get("headers"), dict):
            _scrub_header_map(response["headers"])
        return response

    vcr.before_record_request = before_record_request
    vcr.before_record_response = before_record_response
    original = vcr.use_cassette

    def use_cassette(path, *args, **kwargs):
        manager = original(path, *args, **kwargs)

        class _Scrubbing:
            def __enter__(self):
                return manager.__enter__()

            def __exit__(self, exc_type, exc, traceback):
                result = manager.__exit__(exc_type, exc, traceback)
                try:
                    scrub_cassette(Path(str(path)))
                except OSError:
                    return result
                return result

        return _Scrubbing()

    vcr.use_cassette = use_cassette


def _distribution_path() -> Path | None:
    override = os.environ.get("CYBERAU_DISTRIBUTION")
    if override:
        path = Path(override)
        return path if path.is_file() else None
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "distribution.yaml"
        if candidate.is_file():
            return candidate
    return None


def _query_sub(match: re.Match[str]) -> str:
    if _is_placeholder_header(match.group(2)):
        return match.group(0)
    return match.group(1) + "[REDACTED]"


def _header_sub(match: re.Match[str]) -> str:
    head = match.group("head")
    value = match.group("value")
    if match.group("name").lower() == "key" and len(value) < _MIN_SECRET_LEN:
        return match.group(0)
    if value == "[REDACTED]":
        return match.group(0)
    return f"{head}[REDACTED]"


def _is_placeholder_header(value: object) -> bool:
    if value is None:
        return True
    text = str(value).strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        text = text[1:-1]
    if text in _PLACEHOLDER_VALUES:
        return True
    return _PLACEHOLDER.fullmatch(text) is not None


def _header_items(value: object) -> list:
    if isinstance(value, list):
        return list(value)
    return [value]


def _scrub_header_map(headers: dict) -> bool:
    changed = False
    for name, value in list(headers.items()):
        if str(name).lower() not in SECRET_HEADER_NAMES:
            continue
        if isinstance(value, list):
            scrubbed = [
                "[REDACTED]" if not _is_placeholder_header(item) else item for item in value
            ]
        elif _is_placeholder_header(value):
            continue
        else:
            scrubbed = "[REDACTED]"
        if scrubbed != value:
            headers[name] = scrubbed
            changed = True
    return changed


def _scrub_block(block: dict) -> bool:
    changed = False
    for field in ("uri", "url"):
        uri = block.get(field)
        if isinstance(uri, str):
            scrubbed = scrub_uri(uri)
            if scrubbed != uri:
                block[field] = scrubbed
                changed = True
    headers = block.get("headers")
    if isinstance(headers, dict) and _scrub_header_map(headers):
        changed = True
    return changed


def _cassette_file_findings(path: Path) -> list[str]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError:
        # Fixture folders also hold other YAML, such as multi-document rule files.
        # Only a file that claims to be a cassette has to parse.
        text = path.read_text(encoding="utf-8")
        if re.search(r"(?m)^interactions:", text) is None:
            return []
        return [f"{path}: cassette is not valid YAML"]
    if not isinstance(data, dict):
        return []
    interactions = data.get("interactions")
    if not isinstance(interactions, list):
        return []
    findings: list[str] = []
    for index, interaction in enumerate(interactions):
        if not isinstance(interaction, dict):
            continue
        for side in ("request", "response"):
            block = interaction.get(side)
            if not isinstance(block, dict):
                continue
            for field in ("uri", "url"):
                uri = block.get(field)
                if isinstance(uri, str) and scrub_uri(uri) != uri:
                    findings.append(f"{path}:{index}:{side}:{field}")
            headers = block.get("headers")
            if not isinstance(headers, dict):
                continue
            for name, value in headers.items():
                if str(name).lower() not in SECRET_HEADER_NAMES:
                    continue
                for item in _header_items(value):
                    if not _is_placeholder_header(item):
                        findings.append(f"{path}:{index}:{side}:{name}")
                        break
    return findings
