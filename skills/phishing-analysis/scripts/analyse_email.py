"""Parse a reported email for phishing analysis.

Stdlib only. This helper does not open links, write files, or contact anyone.
Tool arguments are refanged. Display fields are defanged once.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

_SKILL_ROOT = Path(__file__).resolve().parents[1]
_BRANDS_PATH = _SKILL_ROOT / "references" / "au-brands.json"
_SHORTENERS_PATH = _SKILL_ROOT / "references" / "shorteners.json"

_MULTI_SUFFIXES = frozenset(
    {
        "com.au",
        "net.au",
        "org.au",
        "gov.au",
        "edu.au",
        "asn.au",
        "id.au",
        "co.nz",
        "net.nz",
        "org.nz",
        "govt.nz",
        "co.uk",
        "org.uk",
    }
)

# Working subset of confusables. Not the Unicode confusables catalogue.
_CONFUSABLES = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "і": "i",
    "ї": "i",
    "ј": "j",
    "ѕ": "s",
    "һ": "h",
    "ԁ": "d",
    "ɡ": "g",
    "ο": "o",
    "α": "a",
    "ε": "e",
    "ι": "i",
    "ν": "v",
    "ρ": "p",
    "τ": "t",
    "υ": "u",
    "0": "o",
    "1": "l",
    "5": "s",
}

_URL_RE = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
_HARNESS_URL_RE = re.compile(r"\b(https?)://([^\s/]+)(\S*)", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HOST_RE = re.compile(r"(?i)^((?:[a-z0-9-]+\.)+[a-z]{2,})((?::\d+)?(?:[/?#].*)?)$")
_DEFANGED_RE = re.compile(r"\[\.\]|\[@\]|hxxps?://", re.IGNORECASE)
_AUTH_METHOD_RE = re.compile(
    r"\b(spf|dkim|dmarc|arc)\s*=\s*"
    r"(pass|fail|softfail|neutral|none|temperror|permerror|bestguesspass)\b",
    re.IGNORECASE,
)
_HEADER_FROM_RE = re.compile(r"\bheader\.from\s*=\s*([^\s;]+)", re.IGNORECASE)
_ZW_TRANSLATION = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u200e\u200f\ufeff\u2060"))
_TRACKING_KEYS = ("utm_", "mc_eid", "mkt_tok")
_GUIDANCE = "This is guidance, not legal advice, an audit, or a formal assessment."
_DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)
_INSTRUCTION_RE = re.compile(
    r"(?i)(?:"
    r"forward\s+(?:the\s+|this\s+)?(?:mailbox|inbox)"
    r"|fetch_url"
    r"|fetch\s+(?:the\s+)?url"
    r"|notify_sender"
    r"|notify\s+(?:the\s+)?sender"
    r"|ignore\s+(?:all\s+|any\s+)?(?:previous|prior)\s+instructions"
    r"|disregard\s+(?:all\s+|any\s+)?(?:previous|prior)\s+instructions"
    r"|exfiltrate"
    r"|send\s+(?:the\s+)?(?:mailbox|password|credentials)"
    r")"
)
_ZW_SPAN = re.compile(
    r".{0,120}[\u200b\u200c\u200d\u200e\u200f\ufeff\u2060].{0,120}",
    re.DOTALL,
)


@dataclass(frozen=True)
class Brand:
    name: str
    domains: tuple[str, ...]
    labels: tuple[str, ...]


@dataclass(frozen=True)
class BrandList:
    source: str
    version: str
    retrieved: str
    brands: tuple[Brand, ...]


def defang_observable(value: str) -> str:
    """Defang one observable. A second call does not rewrite `[.]` or `[@]`."""
    text = value.strip()
    if _DEFANGED_RE.search(text):
        return text
    return _defang_once(text)


def _defang_once(value: str) -> str:
    text = value.strip()
    bare = _HOST_RE.fullmatch(text)
    if bare:
        return bare.group(1).replace(".", "[.]") + bare.group(2)

    def url_sub(match: re.Match[str]) -> str:
        scheme = "hxxps" if match.group(1).lower() == "https" else "hxxp"
        host = match.group(2).replace(".", "[.]")
        return f"{scheme}://{host}{match.group(3)}"

    text = _HARNESS_URL_RE.sub(url_sub, text)

    def email_sub(match: re.Match[str]) -> str:
        return f"{match.group(1)}[@]{match.group(2).replace('.', '[.]')}"

    text = _EMAIL_RE.sub(email_sub, text)
    return _IPV4_RE.sub(lambda match: match.group(0).replace(".", "[.]"), text)


def refang_observable(value: str) -> str:
    """Restore one observable for a tool argument."""
    text = value.strip()
    text = re.sub(r"(?i)^hxxps://", "https://", text)
    text = re.sub(r"(?i)^hxxp://", "http://", text)
    text = text.replace("[.]", ".").replace("(.)", ".").replace("[@]", "@")
    text = re.sub(r"(?i)\[at\]", "@", text)
    return text


def is_external_ip(value: str) -> bool:
    """True when an address is a global unicast target for an external lookup.

    Documentation ranges are excluded on every supported Python, including
    runtimes whose ``is_global`` still treats them as public.
    """
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if any(address in network for network in _DOCUMENTATION_NETWORKS):
        return False
    return bool(address.is_global)


def _is_instruction(text: str) -> bool:
    """True when hidden text asks for an action. The text is not followed."""
    return bool(_INSTRUCTION_RE.search(text))


def registrable_domain(host: str) -> str:
    labels = [part for part in host.lower().rstrip(".").split(".") if part]
    if len(labels) < 2:
        return ".".join(labels)
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _is_under(host: str, domain: str) -> bool:
    host = host.lower().rstrip(".")
    domain = domain.lower().rstrip(".")
    return bool(host) and (host == domain or host.endswith("." + domain))


def _fold_label(label: str) -> str:
    folded = label.lower()
    if folded.startswith("xn--"):
        try:
            folded = folded.encode("ascii").decode("idna").lower()
        except UnicodeError:
            pass
    return "".join(_CONFUSABLES.get(char, char) for char in folded)


def fold_host(host: str) -> str:
    labels = [_fold_label(part) for part in host.lower().rstrip(".").split(".") if part]
    return ".".join(labels)


def _tokens(host: str) -> set[str]:
    found: set[str] = set()
    for label in host.split("."):
        found.update(part for part in label.split("-") if part)
    return found


def _edit_limit(length: int) -> int | None:
    if length < 5:
        return None
    if length < 8:
        return 1
    return 2


def _levenshtein(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for index, left_char in enumerate(left, start=1):
        current = [index]
        for right_index, right_char in enumerate(right, start=1):
            insert = current[right_index - 1] + 1
            delete = previous[right_index] + 1
            substitute = previous[right_index - 1] + (left_char != right_char)
            current.append(min(insert, delete, substitute))
        previous = current
    return previous[-1]


def load_brands(path: Path | None = None) -> BrandList:
    payload = json.loads((path or _BRANDS_PATH).read_text(encoding="utf-8"))
    brands: list[Brand] = []
    for item in payload["brands"]:
        labels = tuple(label.lower() for label in item["labels"] if len(label) >= 3)
        domains = tuple(domain.lower().rstrip(".") for domain in item["domains"])
        brands.append(Brand(item["name"], domains, labels))
    return BrandList(
        source=str(payload["source"]),
        version=str(payload["version"]),
        retrieved=str(payload["retrieved"]),
        brands=tuple(brands),
    )


def load_shorteners(path: Path | None = None) -> set[str]:
    payload = json.loads((path or _SHORTENERS_PATH).read_text(encoding="utf-8"))
    return {host.lower().rstrip(".") for host in payload["hosts"]}


def _own_brands(own: list[str]) -> list[Brand]:
    brands: list[Brand] = []
    for domain in own:
        raw = domain.lower().rstrip(".")
        if not raw or _IPV4_RE.fullmatch(raw):
            continue
        label = registrable_domain(raw).split(".")[0]
        labels = (label,) if len(label) >= 3 else ()
        brands.append(Brand(f"own domain {raw}", (raw,), labels))
    return brands


def assess_host(host: str, brands: BrandList, own: list[str] | None = None) -> dict:
    """Compare one hostname with the shipped brands and the caller's own domains."""
    raw = host.lower().rstrip(".").split(":")[0].strip(".")
    empty = {
        "host": raw,
        "lookalike": False,
        "official": False,
        "owned": False,
        "brand": None,
        "rules": [],
        "detail": "no brand or own-domain lookalike rule matched",
    }
    if not raw or _IPV4_RE.fullmatch(raw):
        return empty
    own_domains = [item.lower().rstrip(".") for item in (own or []) if item.strip()]
    if any(_is_under(raw, domain) for domain in own_domains):
        return {
            **empty,
            "owned": True,
            "detail": "host is under a supplied own domain",
        }
    for brand in brands.brands:
        if any(_is_under(raw, domain) for domain in brand.domains):
            return {
                **empty,
                "official": True,
                "brand": brand.name,
                "detail": f"official domain for {brand.name}",
            }

    folded = fold_host(raw)
    folded_tokens = _tokens(folded)
    raw_tokens = _tokens(raw)
    matches: list[tuple[int, str, str, str]] = []
    for brand in list(brands.brands) + _own_brands(own_domains):
        for domain in brand.domains:
            if _is_under(folded, domain) and not _is_under(raw, domain):
                matches.append((0, "homoglyph", brand.name, f"homoglyph of {domain}"))
        for label in brand.labels:
            if label in folded_tokens:
                matches.append((1, "token", brand.name, f"token {label} matches {brand.name}"))
            for token in raw_tokens:
                if token.startswith(label) and token[len(label) :].isdigit():
                    matches.append(
                        (2, "digit-suffix", brand.name, f"digit suffix on {label} ({brand.name})")
                    )
            if len(label) >= 5:
                for token in folded_tokens:
                    longer = len(token) > len(label)
                    if longer and (token.startswith(label) or token.endswith(label)):
                        matches.append(
                            (4, "prefix", brand.name, f"prefix or suffix {label} ({brand.name})")
                        )
            left_raw = registrable_domain(raw).split(".")[0]
            left_folded = _fold_label(left_raw)
            squashed = left_folded.replace("-", "")
            if "-" in left_folded and squashed == label:
                matches.append(
                    (3, "hyphen-join", brand.name, f"hyphen join equals {label} ({brand.name})")
                )
            limit = _edit_limit(len(label))
            if limit is None:
                continue
            if abs(len(squashed) - len(label)) > limit:
                continue
            distance = _levenshtein(squashed, label)
            if 0 < distance <= limit:
                matches.append(
                    (
                        5,
                        "edit-distance",
                        brand.name,
                        f"edit distance {distance} from {label} ({brand.name})",
                    )
                )
    if not matches:
        return empty
    matches.sort(key=lambda item: item[0])
    _priority, rule, brand_name, detail = matches[0]
    rules = []
    for item in matches:
        if item[1] not in rules and item[2] == brand_name:
            rules.append(item[1])
    return {
        "host": raw,
        "lookalike": True,
        "official": False,
        "owned": False,
        "brand": brand_name,
        "rules": rules,
        "detail": detail,
    }


def extract_urls(text: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for match in _URL_RE.finditer(text):
        url = match.group(0).rstrip(".,;:)>]\"'")
        if url not in seen:
            seen.add(url)
            found.append(url)
    return found


def _style_reason(style: str) -> str | None:
    compact = re.sub(r"\s+", "", style.lower())
    if re.search(r"display:none(?:;|$|!)", compact):
        return "display:none"
    if re.search(r"visibility:hidden(?:;|$|!)", compact):
        return "visibility:hidden"
    if re.search(r"font-size:0(?:px|pt|em|%)?(?:;|$|!)", compact):
        return "font-size:0"
    if re.search(r"opacity:0(?:\.0+)?(?:;|$|!)", compact):
        return "opacity:0"
    if re.search(r"color:#ffffff(?:;|$|!)", compact):
        return "white-text"
    if re.search(r"color:#fff(?:;|$|!)", compact):
        return "white-text"
    if re.search(r"color:white(?:;|$|!)", compact):
        return "white-text"
    if re.search(r"color:rgb\(255,255,255\)(?:;|$|!)", compact):
        return "white-text"
    return None


class _HiddenHTML(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.found: list[dict] = []
        self.visible: list[str] = []
        self._depth = 0
        self._reason = ""
        self._buf: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {key.lower(): (value or "") for key, value in attrs}
        reason = None
        if "hidden" in attr:
            reason = "hidden-attribute"
        else:
            reason = _style_reason(attr.get("style", ""))
        if self._depth:
            self._depth += 1
            return
        if reason:
            self._depth = 1
            self._reason = reason
            self._buf = []

    def handle_endtag(self, tag: str) -> None:
        if not self._depth:
            return
        self._depth -= 1
        if self._depth == 0:
            text = "".join(self._buf).strip()
            self._buf = []
            if text:
                self.found.append({"kind": self._reason, "text": text[:2000], "untrusted": True})

    def handle_data(self, data: str) -> None:
        if self._depth:
            self._buf.append(data)
        else:
            self.visible.append(data)

    def handle_comment(self, data: str) -> None:
        text = data.strip()
        if text:
            self.found.append({"kind": "comment", "text": text[:2000], "untrusted": True})

    def close(self) -> None:
        super().close()
        if self._depth and self._buf:
            text = "".join(self._buf).strip()
            if text:
                self.found.append({"kind": self._reason, "text": text[:2000], "untrusted": True})


def _hidden_from_html(html: str) -> tuple[list[dict], str]:
    parser = _HiddenHTML()
    parser.feed(html)
    parser.close()
    return parser.found[:20], "".join(parser.visible)


def _auth_from_header(value: str) -> dict[str, str | None]:
    found: dict[str, str | None] = {"spf": None, "dkim": None, "dmarc": None, "arc": None}
    for match in _AUTH_METHOD_RE.finditer(value):
        method = match.group(1).lower()
        if found[method] is None:
            found[method] = match.group(2).lower()
    header_from = _HEADER_FROM_RE.search(value)
    found["header_from"] = header_from.group(1).lower() if header_from else None
    return found


def _authentication(message) -> dict:
    headers = message.get_all("Authentication-Results") or []
    arc_headers = message.get_all("ARC-Authentication-Results") or []
    parsed = (
        _auth_from_header(headers[0])
        if headers
        else {
            "spf": None,
            "dkim": None,
            "dmarc": None,
            "arc": None,
            "header_from": None,
        }
    )
    if parsed["arc"] is None and arc_headers:
        parsed["arc"] = _auth_from_header(arc_headers[0])["arc"]
    dmarc = parsed["dmarc"]
    if dmarc == "pass":
        aligned: bool | None = True
    elif dmarc == "fail":
        aligned = False
    else:
        aligned = None
    parsed["aligned"] = aligned
    parsed["present"] = bool(headers)
    return parsed


def _display_claims(display: str, brands: BrandList) -> list[str]:
    words = set(re.findall(r"[a-z0-9]+", display.casefold()))
    text = display.casefold()
    hits: list[str] = []
    for brand in brands.brands:
        name = brand.name.casefold()
        named = (len(name) >= 5 and name in text) or name in words
        by_label = any(label in words for label in brand.labels)
        if named or by_label:
            hits.append(brand.name)
    return hits


def _is_shortener(host: str, shorteners: set[str]) -> bool:
    return any(host == item or host.endswith("." + item) for item in shorteners)


def _tracking(url: str) -> bool:
    query = urlparse(url).query.lower()
    return any(key in query for key in _TRACKING_KEYS)


def _url_record(
    raw_url: str,
    *,
    brands: BrandList,
    own: list[str],
    shorteners: set[str],
    hidden: bool,
) -> dict | None:
    refanged = refang_observable(raw_url)
    parsed = urlparse(refanged)
    host = (parsed.hostname or "").lower()
    if not host:
        return None
    lookalike = assess_host(host, brands, own)
    return {
        "raw": refanged,
        "defanged": defang_observable(refanged),
        "host": host,
        "defanged_host": defang_observable(host),
        "shortener": _is_shortener(host, shorteners),
        "expanded": False,
        "tracking": _tracking(refanged),
        "hidden": hidden,
        "lookalike": lookalike,
    }


def _attachment_record(part) -> dict:
    payload = part.get_payload(decode=True) or b""
    filename = part.get_filename() or "unnamed"
    return {
        "filename": filename,
        "content_type": part.get_content_type(),
        "size": len(payload),
        "md5": hashlib.md5(payload, usedforsecurity=False).hexdigest(),
        "sha1": hashlib.sha1(payload, usedforsecurity=False).hexdigest(),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def _part_text(part) -> str:
    try:
        content = part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")
    if isinstance(content, str):
        return content
    return ""


def _zero_width_snippets(text: str) -> list[str]:
    """Fold zero-width characters and keep a short window of the revealed text."""
    snippets: list[str] = []
    for match in _ZW_SPAN.finditer(text):
        folded = " ".join(match.group(0).translate(_ZW_TRANSLATION).split())
        if folded and folded not in snippets:
            snippets.append(folded[:500])
        if len(snippets) == 10:
            break
    return snippets


def analyse(
    raw: bytes,
    *,
    brands: BrandList | None = None,
    shorteners: set[str] | None = None,
    own: list[str] | None = None,
) -> dict:
    """Return a JSON-ready reading. The message and this object are untrusted data."""
    brand_list = brands or load_brands()
    shortener_hosts = shorteners if shorteners is not None else load_shorteners()
    own_domains = [item.strip().lower() for item in (own or []) if item.strip()]
    message = BytesParser(policy=policy.default).parsebytes(raw)
    warnings: list[str] = []
    if not own_domains:
        warnings.append("Own domains were not supplied. Only the shipped brand list was used.")

    display, address = parseaddr(message.get("From", ""))
    claims = _display_claims(display, brand_list)
    from_host = address.split("@", 1)[1].lower() if "@" in address else ""
    if (
        claims
        and from_host
        and not any(
            _is_under(from_host, domain)
            for brand in brand_list.brands
            if brand.name in claims
            for domain in brand.domains
        )
    ):
        warnings.append(
            "The display name claims a shipped brand and the address domain is not that brand."
        )

    authentication = _authentication(message)
    if not authentication["present"]:
        warnings.append("Authentication-Results is not in this copy. Do not infer a pass.")

    received = [_defang_once(value)[:500] for value in (message.get_all("Received") or [])[:20]]
    ips: list[str] = []
    for value in message.get_all("Received") or []:
        for match in _IPV4_RE.finditer(value):
            candidate = match.group(0)
            if candidate not in ips:
                ips.append(candidate)
    external_ips = [item for item in ips if is_external_ip(item)]

    html_chunks: list[str] = []
    plain_chunks: list[str] = []
    attachments: list[dict] = []
    parts = message.walk() if message.is_multipart() else [message]
    for part in parts:
        if part.get_content_maintype() == "multipart":
            continue
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        if filename or disposition == "attachment":
            attachments.append(_attachment_record(part))
            continue
        content_type = part.get_content_type()
        if content_type == "text/html":
            html_chunks.append(_part_text(part))
        elif content_type.startswith("text/"):
            plain_chunks.append(_part_text(part))

    hidden: list[dict] = []
    visible_html: list[str] = []
    for chunk in html_chunks:
        found, visible = _hidden_from_html(chunk)
        hidden.extend(found)
        visible_html.append(visible)
    body_text = "\n".join(plain_chunks + visible_html)
    combined_body = "\n".join(plain_chunks + html_chunks)
    for snippet in _zero_width_snippets(combined_body):
        hidden.append({"kind": "zero-width", "text": snippet, "untrusted": True})
    for item in hidden:
        item["instruction"] = _is_instruction(item["text"])

    hidden_urls: set[str] = set()
    for item in hidden:
        hidden_urls.update(extract_urls(refang_observable(item["text"])))
        hidden_urls.update(extract_urls(item["text"]))
    folded_body = combined_body.translate(_ZW_TRANSLATION)
    hidden_urls.update(
        url for url in extract_urls(folded_body) if url not in extract_urls(combined_body)
    )
    for item in hidden:
        item["text"] = _defang_once(item["text"])

    seen_urls: set[str] = set()
    url_records: list[dict] = []
    search_text = folded_body if folded_body != combined_body else combined_body
    for url in extract_urls(search_text):
        refanged = refang_observable(url)
        if refanged in seen_urls:
            continue
        seen_urls.add(refanged)
        record = _url_record(
            refanged,
            brands=brand_list,
            own=own_domains,
            shorteners=shortener_hosts,
            hidden=refanged in {refang_observable(item) for item in hidden_urls},
        )
        if record:
            url_records.append(record)
            if record["shortener"]:
                warnings.append(
                    "Shortener not expanded. HEAD expansion is opt-in and this helper "
                    "does not use the network."
                )

    signals: list[dict] = []
    if authentication["dmarc"]:
        signals.append({"kind": "dmarc", "value": authentication["dmarc"]})
    for claim in claims:
        signals.append({"kind": "display-name", "brand": claim})
    for record in url_records:
        if record["lookalike"]["lookalike"]:
            signals.append(
                {
                    "kind": "lookalike",
                    "host": record["defanged_host"],
                    "brand": record["lookalike"]["brand"],
                    "rules": record["lookalike"]["rules"],
                }
            )
        if record["tracking"]:
            signals.append({"kind": "tracking", "host": record["defanged_host"]})
        if record["shortener"]:
            signals.append({"kind": "shortener", "host": record["defanged_host"]})
    if hidden:
        signals.append({"kind": "hidden", "count": len(hidden)})
    instruction_count = sum(1 for item in hidden if item.get("instruction"))
    if instruction_count:
        signals.append({"kind": "hidden-instruction", "count": instruction_count})
    if attachments:
        signals.append({"kind": "attachment", "count": len(attachments)})

    preview = _defang_once(body_text)[:2000]
    return {
        "untrusted": True,
        "network": False,
        "writes": False,
        "guidance": _GUIDANCE,
        "brand_list": {
            "source": brand_list.source,
            "version": brand_list.version,
            "retrieved": brand_list.retrieved,
        },
        "subject": message.get("Subject"),
        "from": {
            "display": display,
            "address": address,
            "defanged": defang_observable(address) if address else "",
            "display_claims": claims,
        },
        "authentication": authentication,
        "received": received,
        "urls": url_records,
        "attachments": attachments,
        "hidden": hidden,
        "signals": signals,
        "warnings": warnings,
        "body_preview": preview,
        "tool_arguments": {
            "urls": [record["raw"] for record in url_records],
            "domains": sorted({record["host"] for record in url_records}),
            "emails": [address] if address else [],
            "ips": external_ips,
            "hashes": [
                {"sha256": item["sha256"], "sha1": item["sha1"], "md5": item["md5"]}
                for item in attachments
            ],
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Parse a reported email. No network and no store writes."
    )
    parser.add_argument("path", nargs="?", help="Path to a .eml file. Reads stdin if omitted.")
    parser.add_argument("--own", default="", help="Comma-separated own domains.")
    parser.add_argument("--brands", type=Path, default=None)
    parser.add_argument("--shorteners", type=Path, default=None)
    args = parser.parse_args(argv)
    if args.path:
        path = Path(args.path)
        if not path.is_file():
            print(f"File not found: {path}", file=sys.stderr)
            return 2
        raw = path.read_bytes()
    else:
        raw = sys.stdin.buffer.read()
    own = [item.strip() for item in args.own.split(",") if item.strip()]
    try:
        brands = load_brands(args.brands)
        shorteners = load_shorteners(args.shorteners)
        result = analyse(raw, brands=brands, shorteners=shorteners, own=own)
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        print(f"Could not analyse the message: {exc}", file=sys.stderr)
        return 2
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
