"""Defang one observable for a triage record.

Tool arguments stay raw. This helper does not use the network.
A value that is already defanged is left unchanged.
"""

from __future__ import annotations

import re

URL_RE = re.compile(r"\b(https?)://([^\s/]+)(\S*)", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOST_RE = re.compile(r"(?i)^((?:[a-z0-9-]+\.)+[a-z]{2,})((?::\d+)?(?:[/?#].*)?)$")


def defang_observable(value: str) -> str:
    """Defang one observable for display. Tool arguments stay raw."""
    text = value.strip()
    bare = HOST_RE.fullmatch(text)
    if bare:
        return bare.group(1).replace(".", "[.]") + bare.group(2)

    def url_sub(match: re.Match[str]) -> str:
        scheme = "hxxps" if match.group(1).lower() == "https" else "hxxp"
        host = match.group(2).replace(".", "[.]")
        return f"{scheme}://{host}{match.group(3)}"

    text = URL_RE.sub(url_sub, text)

    def email_sub(match: re.Match[str]) -> str:
        return f"{match.group(1)}[@]{match.group(2).replace('.', '[.]')}"

    text = EMAIL_RE.sub(email_sub, text)
    return IPV4_RE.sub(lambda match: match.group(0).replace(".", "[.]"), text)
