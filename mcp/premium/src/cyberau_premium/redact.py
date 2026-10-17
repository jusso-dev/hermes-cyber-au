"""Replace credentials and personal information with a type and a short hash."""

from __future__ import annotations

import hashlib
import re

_SECRET_KEY = re.compile(
    r"(?i)(password|passwd|pwd|passphrase|cookie|token|secret|api_?key|apikey|"
    r"session_?id|sessionid|authorization|credential|private_?key)"
)
_SECRET_KEY_PARTS = {"sid", "auth", "pass", "session"}
_COUNT_SAFE = re.compile(r"(?i)(?:^|_)(?:count|total|num|limit)(?:$|_)")

# A value is a quoted string, or an unquoted run. Quoted values may hold spaces.
_VALUE = r"""(?:"([^"]*)"|'([^']*)'|([^\s"'`,;}]+))"""
_LINE_VALUE = r"""(?:"([^"]*)"|'([^']*)'|([^\r\n]+))"""

_PASSWORD = re.compile(
    rf"""(?i)(["']?)\b([\w-]*?(?:password|passwd|pwd|passphrase)s?)\1\s*(?:is|=|:)\s*{_VALUE}"""
)
# A cookie header holds several pairs, so a header value runs to the end of the line.
# The inline form (cookie=a=1;b=2) runs to the next space.
_COOKIE = re.compile(rf"""(?i)(["']?)\b(set-cookie|cookie)\1\s*:\s*{_LINE_VALUE}""")
_COOKIE_INLINE = re.compile(
    r"""(?i)(["']?)\b(set-cookie|cookie)\1\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'`,}]+))"""
)
_AUTH_HEADER = re.compile(
    r"(?i)\b(authorization)\s*[:=]\s*(?:basic|digest|negotiate|token)\s+[^\s,;]+"
)
_TOKEN = re.compile(
    rf"""(?i)(["']?)\b([\w-]*?(?:token|api[_-]?key|apikey|secret|bearer|private[_-]?key)s?)\1\s*[:=]\s*{_VALUE}"""
)
_BEARER = re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._\-+/=]+)")
_SESSION = re.compile(r"(?i)\b(session(?:id)?|sid)\s*=\s*([^\s;]+)")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
_PREFIXED = re.compile(
    r"\b(?:(?:sk|pk|rk)-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|"
    r"xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b"
)
_URL_CREDENTIAL = re.compile(r"(?i)(://)([^/\s:@]+):([^/\s@]+)@")
_EMAIL_TEXT = r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}"
# Infostealer and combolist lines: email:password, email;password, email|password.
_COMBO = re.compile(rf"(?i)\b({_EMAIL_TEXT})[:;|]([^\s,]+)")
_EMAIL = re.compile(rf"(?i)\b({_EMAIL_TEXT})\b")
_PHONE_AU = re.compile(r"(?<![\w.])(?:\+61|0061|0)\s?[2-478](?:[\s-]?\d){8}(?!\d)")
_PHONE_INTL = re.compile(r"(?<![\w.])\+\d{1,3}[\s-]?(?:\d[\s-]?){7,12}\d(?!\d)")
_ID_NUMBER = re.compile(
    r"(?i)\b(tfn|tax file number|medicare(?: number| card| no\.?)?|"
    r"passport(?: number| no\.?)?|driver'?s? licen[cs]e(?: number| no\.?)?|"
    r"licen[cs]e(?: number| no\.?))\s*[:=#]?\s*"
    r"(\d(?:[ -]?\d){6,13}|[A-Z]{1,2}\d{6,9})\b"
)
_BIRTH = re.compile(
    r"(?i)\b(dob|date of birth|born)\s*[:=]?\s*"
    r"(\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}|\d{4}-\d{2}-\d{2})\b"
)


def short_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:8]


def _mark(kind: str, value: str) -> str:
    return f"{kind}:{short_hash(value)}"


def _first(match: re.Match[str], *groups: int) -> str:
    for index in groups:
        value = match.group(index)
        if value is not None:
            return value
    return ""


def redact_text(text: str) -> str:
    """Redact credential-shaped and personal text. The original value is not kept."""

    def password(match: re.Match[str]) -> str:
        return _mark("password", _first(match, 3, 4, 5))

    def cookie(match: re.Match[str]) -> str:
        return _mark("cookie", _first(match, 3, 4, 5))

    def token(match: re.Match[str]) -> str:
        return _mark("token", _first(match, 3, 4, 5))

    text = _AUTH_HEADER.sub(lambda match: _mark("token", match.group(0)), text)
    text = _URL_CREDENTIAL.sub(
        lambda match: (
            f"{match.group(1)}{_mark('user', match.group(2))}:{_mark('password', match.group(3))}@"
        ),
        text,
    )
    text = _COMBO.sub(
        lambda match: f"{_mark('email', match.group(1))}:{_mark('password', match.group(2))}",
        text,
    )
    text = _PASSWORD.sub(password, text)
    text = _COOKIE.sub(cookie, text)
    text = _COOKIE_INLINE.sub(cookie, text)
    text = _TOKEN.sub(token, text)
    text = _BEARER.sub(lambda match: _mark("token", match.group(1)), text)
    text = _JWT.sub(lambda match: _mark("token", match.group(0)), text)
    text = _PREFIXED.sub(lambda match: _mark("token", match.group(0)), text)
    text = _SESSION.sub(lambda match: _mark("cookie", match.group(2)), text)
    text = _EMAIL.sub(lambda match: _mark("email", match.group(1)), text)
    text = _ID_NUMBER.sub(lambda match: _mark("id", match.group(2)), text)
    text = _BIRTH.sub(lambda match: _mark("dob", match.group(2)), text)
    text = _PHONE_AU.sub(lambda match: _mark("phone", match.group(0)), text)
    text = _PHONE_INTL.sub(lambda match: _mark("phone", match.group(0)), text)
    return text


def _is_secret_key(key: str) -> bool:
    normalised = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key).lower().replace("-", "_")
    if _COUNT_SAFE.search(normalised):
        return False
    if _SECRET_KEY.search(normalised):
        return True
    return any(part in _SECRET_KEY_PARTS for part in normalised.split("_"))


def _kind_for_key(key: str) -> str:
    normalised = key.lower().replace("-", "_")
    if "cookie" in normalised or normalised.startswith("session") or normalised == "sid":
        return "cookie"
    if re.search(r"password|passwd|pwd|passphrase|(^|_)pass($|_)", normalised):
        return "password"
    return "token"


def redact_obj(value, key: str | None = None):
    """Redact a nested value. Every leaf under a secret-named key is replaced."""
    return _redact(value, key, secret_key=None)


def _redact(value, key: str | None, secret_key: str | None):
    if key is not None and secret_key is None and _is_secret_key(key):
        secret_key = key
    if isinstance(value, dict):
        return {name: _redact(item, str(name), secret_key) for name, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item, key, secret_key) for item in value]
    if (
        secret_key is not None
        and isinstance(value, (str, int, float))
        and not isinstance(value, bool)
    ):
        return _mark(_kind_for_key(secret_key), str(value))
    if isinstance(value, str):
        return redact_text(value)
    return value
