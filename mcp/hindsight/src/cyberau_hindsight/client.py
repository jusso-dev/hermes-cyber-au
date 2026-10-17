"""Hindsight retain and recall. Reflect is not part of this slice.

The client stays off until HINDSIGHT_BASE_URL is set. The API key, when there
is one, is HINDSIGHT_API_KEY from the environment. No host and no key are
built into this package.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx
from cyberau_common import USER_AGENT
from cyberau_common.envelope import untrusted_text
from cyberau_common.secrets import lookup, redact

from cyberau_hindsight.constants import BANKS

_LOOPBACK = {"127.0.0.1", "localhost", "::1"}
_TRUE = {"1", "true", "yes", "on"}


class HindsightError(Exception):
    """The Hindsight call did not complete."""


@dataclass
class HindsightClient:
    base_url: str | None
    api_key: str | None
    read_only: bool
    transport: httpx.BaseTransport | None = None
    timeout: float = 30.0

    def __post_init__(self) -> None:
        if self.base_url:
            self.base_url = _check_base(self.base_url)

    @classmethod
    def from_env(cls, transport: httpx.BaseTransport | None = None) -> HindsightClient:
        raw = lookup("HINDSIGHT_BASE_URL")
        base = _check_base(raw) if raw else None
        flag = (lookup("HINDSIGHT_READ_ONLY") or "").lower()
        return cls(
            base_url=base,
            api_key=lookup("HINDSIGHT_API_KEY"),
            read_only=flag in _TRUE,
            transport=transport,
        )

    @property
    def enabled(self) -> bool:
        return self.base_url is not None

    def retain(
        self,
        bank: str,
        content: str,
        *,
        context: str | None = None,
        document_id: str | None = None,
        metadata: dict | None = None,
        tags: list[str] | None = None,
        confirmed: bool | None = None,
    ) -> dict:
        _bank(bank)
        if not self.enabled:
            return _off()
        if self.read_only:
            return {
                "enabled": True,
                "read_only": True,
                "bank": bank,
                "retained": 0,
                "detail": "Hindsight retain is off because this profile is read-only.",
            }
        text = _plain(content, "content", 100_000)
        item: dict = {"content": text}
        if context:
            item["context"] = _plain(context, "context", 2_000)
        if document_id:
            item["document_id"] = _plain(document_id, "document_id", 200)
        meta = _metadata(metadata, confirmed)
        if meta:
            item["metadata"] = meta
        if tags:
            item["tags"] = [_plain(tag, "tag", 80) for tag in tags]
        payload = self._post(f"/v1/default/banks/{bank}/memories", {"items": [item]})
        return {
            "enabled": True,
            "read_only": False,
            "bank": bank,
            "retained": int(payload.get("items_count") or 1),
            "detail": "retained",
        }

    def recall(self, bank: str, query: str, *, limit: int = 10) -> dict:
        _bank(bank)
        bounded = _limit(limit)
        if not self.enabled:
            return _off()
        text = _plain(query, "query", 1_000)
        payload = self._post(
            f"/v1/default/banks/{bank}/memories/recall",
            {"query": text, "budget": "mid", "max_tokens": 2048},
        )
        rows = payload.get("results")
        if not isinstance(rows, list):
            rows = []
        records = [_present(bank, row) for row in rows if isinstance(row, dict)]
        return {
            "enabled": True,
            "read_only": self.read_only,
            "bank": bank,
            "records": records[:bounded],
        }

    def _post(self, path: str, body: dict) -> dict:
        if path.endswith("/reflect") or "/reflect/" in path:
            raise HindsightError("reflect is not implemented")
        if not self.base_url:
            raise HindsightError("Hindsight is off until HINDSIGHT_BASE_URL is set")
        url = self.base_url + path
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "user-agent": USER_AGENT,
        }
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        try:
            with httpx.Client(
                transport=self.transport,
                follow_redirects=False,
                timeout=self.timeout,
            ) as http:
                response = http.post(url, json=body, headers=headers)
        except Exception as exc:
            raise HindsightError(self._safe(exc)) from None
        if response.status_code in {301, 302, 303, 307, 308}:
            raise HindsightError("Hindsight redirect was refused")
        if response.status_code >= 400:
            raise HindsightError(f"Hindsight returned HTTP {response.status_code}")
        try:
            payload = response.json()
        except ValueError as exc:
            raise HindsightError(self._safe(exc)) from None
        if not isinstance(payload, dict):
            raise HindsightError("Hindsight returned an unexpected payload")
        return payload

    def _safe(self, exc: Exception) -> str:
        text = redact(str(exc))
        if self.api_key:
            text = text.replace(self.api_key, "[REDACTED]")
        return text or "Hindsight request failed"


def _off() -> dict:
    return {
        "enabled": False,
        "read_only": False,
        "bank": None,
        "records": [],
        "retained": 0,
        "detail": "Hindsight is off until HINDSIGHT_BASE_URL is set.",
    }


def _bank(bank: str) -> None:
    if bank not in BANKS:
        raise HindsightError("bank must be org, intel, or lessons")


def _limit(limit: int) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise HindsightError("limit must be an integer from 1 to 50")
    if limit < 1 or limit > 50:
        raise HindsightError("limit must be an integer from 1 to 50")
    return limit


def _plain(value: str, label: str, limit: int) -> str:
    if not isinstance(value, str):
        raise HindsightError(f"{label} must be text")
    cleaned = " ".join(value.split()).strip()
    if not cleaned:
        raise HindsightError(f"{label} is empty")
    if len(cleaned) > limit:
        raise HindsightError(f"{label} is too long")
    return cleaned


def _metadata(metadata: dict | None, confirmed: bool | None) -> dict | None:
    clean: dict[str, str] = {}
    for key, value in (metadata or {}).items():
        if not isinstance(key, str) or not key.strip():
            raise HindsightError("metadata keys must be text")
        if isinstance(value, (dict, list)):
            raise HindsightError("metadata values must be plain text")
        clean[key.strip()[:40]] = str(value)[:200]
    if confirmed is True:
        clean["confirmed"] = "true"
    elif confirmed is False:
        clean["confirmed"] = "false"
    return clean or None


def _confirmed(row: dict) -> bool:
    meta = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
    flag = meta.get("confirmed")
    if flag is True or str(flag or "").strip().lower() in _TRUE:
        return True
    if str(meta.get("status") or "").strip().lower() == "confirmed":
        return True
    tags = row.get("tags") if isinstance(row.get("tags"), list) else []
    return any(str(tag).strip().lower() == "confirmed" for tag in tags)


def _present(bank: str, row: dict) -> dict:
    confirmed = _confirmed(row)
    trusted = bank == "org" and confirmed
    raw = row.get("text")
    if not isinstance(raw, str):
        raw = row.get("content") if isinstance(row.get("content"), str) else ""
    text = raw if trusted else untrusted_text(raw, source=f"hindsight:{bank}")
    return {
        "id": row.get("id"),
        "text": text,
        "untrusted": not trusted,
        "confirmed": confirmed,
        "type": row.get("type"),
    }


def _check_base(url: str) -> str:
    parts = urlsplit(url.strip())
    if parts.username or parts.password:
        raise HindsightError("Hindsight URL must not contain userinfo")
    if parts.query or parts.fragment or parts.path not in {"", "/"}:
        raise HindsightError("HINDSIGHT_BASE_URL must be the server origin, without a path")
    host = parts.hostname
    if not host:
        raise HindsightError("Hindsight URL has no host")
    scheme = parts.scheme.lower()
    if scheme == "http" and host in _LOOPBACK:
        return url.strip().rstrip("/")
    if scheme == "https":
        return url.strip().rstrip("/")
    raise HindsightError("Hindsight URL must be https, or http on a loopback host")
